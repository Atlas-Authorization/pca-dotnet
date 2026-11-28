using System.Globalization;
using System.Net;
using System.Net.Sockets;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// TEST-ONLY network adversary: a transparent TCP proxy that misbehaves once, after <c>AfterBytes</c> bytes, in one direction (drop / delay /
/// truncate / bitflip / duplicate / reorder at the byte level). TLS 1.3 record authentication rejects tampering, so the expected outcome is an
/// attributable-to-the-link disconnect, never a silently corrupted value.
/// </summary>
public sealed class FaultProxy
{
    public enum Kind { None, Drop, Delay, Truncate, Bitflip, Duplicate, Reorder }

    public enum Dir { C2S, S2C }

    /// <param name="Kind">the misbehaviour.</param>
    /// <param name="Dir">the direction it applies to.</param>
    /// <param name="AfterBytes">the fault starts after this many bytes passed in that direction (skips the TLS handshake).</param>
    /// <param name="Ms">delay (kind Delay), default 1000.</param>
    public sealed record WireFault(Kind Kind, Dir Dir, long AfterBytes, long? Ms = null);

    /// <summary>The destination side of one pipe.</summary>
    public interface ISink
    {
        void Write(byte[] b);

        /// <summary>Half-close: nothing more will be written.</summary>
        void End();

        void Destroy();

        bool Destroyed();
    }

    /// <summary>
    /// One direction of the proxy. Callers feed it <see cref="Data"/>, <see cref="End"/> (source half-closed) and <see cref="Close"/> (source gone);
    /// a delay is scheduled on the clock. A closed side tears down the other one only after that direction's delayed bytes are delivered: a real
    /// network delays data, it does not drop what the sender wrote before it closed.
    /// </summary>
    public sealed class Pipe
    {
        readonly WireFault _f;
        readonly bool _active;
        readonly string _dirName;
        readonly ISink _to;
        readonly IMeshClock _clock;
        readonly List<string> _log;
        readonly object _gate = new();
        long _seen;
        bool _fired, _done, _ended, _closed;
        byte[]? _held;
        int _pending; // delayed writes in flight: a half-close must not overtake them

        public Pipe(WireFault f, Dir dir, ISink to, IMeshClock clock, List<string> log)
        {
            _f = f;
            _active = f.Kind != Kind.None && f.Dir == dir;
            _dirName = dir == Dir.C2S ? "c2s" : "s2c";
            _to = to;
            _clock = clock;
            _log = log;
        }

        public void Data(byte[] chunk)
        {
            lock (_gate)
            {
                long before = _seen;
                _seen += chunk.Length;
                if (!_active || _done || before + chunk.Length <= _f.AfterBytes)
                {
                    if (_active && _f.Kind == Kind.Drop && _fired) return; // black hole stays black
                    _to.Write(chunk);
                    return;
                }
                if (!_fired)
                {
                    _fired = true;
                    lock (_log) _log.Add("fault " + _f.Kind.ToString().ToLowerInvariant() + " " + _dirName + " after " + _f.AfterBytes.ToString(CultureInfo.InvariantCulture) + "B");
                }
                switch (_f.Kind)
                {
                    case Kind.Drop:
                        return;
                    case Kind.Delay:
                        _pending++;
                        _clock.SetTimer(() => Delivered(chunk), _f.Ms ?? 1000);
                        return;
                    case Kind.Truncate:
                        _done = true;
                        _to.Write(chunk[..(chunk.Length / 2)]);
                        _to.End();
                        return;
                    case Kind.Bitflip:
                    {
                        _done = true;
                        var b = (byte[])chunk.Clone();
                        b[b.Length / 2] ^= 0x01;
                        _to.Write(b);
                        return;
                    }
                    case Kind.Duplicate:
                        _done = true;
                        _to.Write(chunk);
                        _to.Write(chunk);
                        return;
                    case Kind.Reorder:
                        if (_held == null)
                        {
                            _held = chunk;
                        }
                        else
                        {
                            _done = true;
                            _to.Write(chunk);
                            _to.Write(_held);
                            _held = null;
                        }
                        return;
                    default:
                        _to.Write(chunk);
                        return;
                }
            }
        }

        void Delivered(byte[] chunk)
        {
            lock (_gate)
            {
                if (!_to.Destroyed()) _to.Write(chunk);
                _pending--;
                if (_pending == 0 && _closed)
                {
                    _to.End();
                    _to.Destroy();
                }
                else if (_pending == 0 && _ended)
                {
                    _to.End();
                }
            }
        }

        public void End()
        {
            lock (_gate)
            {
                if (_held != null) _to.Write(_held);
                _ended = true;
                if (_pending == 0) _to.End();
            }
        }

        public void Close()
        {
            lock (_gate)
            {
                _closed = true;
                if (_pending == 0) _to.Destroy();
            }
        }
    }

    sealed class SocketSink : ISink
    {
        readonly TcpClient _c;
        readonly NetworkStream _out;
        volatile bool _dead;

        public SocketSink(TcpClient c) { _c = c; _out = c.GetStream(); }

        public void Write(byte[] b)
        {
            try { _out.Write(b, 0, b.Length); _out.Flush(); }
            catch (Exception) { Destroy(); }
        }

        public void End()
        {
            try { if (!_dead) _c.Client.Shutdown(SocketShutdown.Send); }
            catch (Exception) { Destroy(); }
        }

        public void Destroy()
        {
            _dead = true;
            try { _c.Close(); } catch (Exception) { /* already gone */ }
        }

        public bool Destroyed() => _dead;
    }

    readonly int _listenPort;
    readonly string _targetHost;
    readonly int _targetPort;
    readonly WireFault _fault;
    readonly IMeshClock _clock;
    TcpListener? _server;
    public readonly List<string> Log = new();

    public FaultProxy(int listenPort, string targetHost, int targetPort, WireFault fault, IMeshClock? clock = null)
    {
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;
        _fault = fault;
        _clock = clock ?? MeshClock.Wall;
    }

    /// <summary>A snapshot of the log (thread-safe).</summary>
    public List<string> LogSnapshot() { lock (Log) return new List<string>(Log); }

    /// <summary>Bind to loopback only; throws if the port is taken.</summary>
    public void Listen()
    {
        var s = new TcpListener(IPAddress.Loopback, _listenPort);
        s.Start(50);
        _server = s;
        new Thread(AcceptLoop) { IsBackground = true, Name = "fault-proxy-accept" }.Start();
    }

    public int Port() => _server == null ? -1 : ((IPEndPoint)_server.LocalEndpoint).Port;

    public void Close()
    {
        try { _server?.Stop(); } catch (Exception) { /* closing */ }
    }

    void AcceptLoop()
    {
        for (;;)
        {
            TcpClient c;
            try { c = _server!.AcceptTcpClient(); }
            catch (Exception) { return; }
            new Thread(() => OnClient(c)) { IsBackground = true, Name = "fault-proxy-conn" }.Start();
        }
    }

    void OnClient(TcpClient c)
    {
        var up = new TcpClient();
        try
        {
            c.NoDelay = true;
            if (!up.ConnectAsync(_targetHost, _targetPort).Wait(5000)) throw new IOException("upstream connect timeout");
            up.NoDelay = true;
            var c2s = new Pipe(_fault, Dir.C2S, new SocketSink(up), _clock, Log);
            var s2c = new Pipe(_fault, Dir.S2C, new SocketSink(c), _clock, Log);
            new Thread(() => Pump(c, up, c2s)) { IsBackground = true, Name = "fault-proxy-c2s" }.Start();
            Pump(up, c, s2c);
        }
        catch (Exception)
        {
            CloseQuietly(c);
            CloseQuietly(up);
        }
    }

    /// <summary>Read <paramref name="from"/> until it ends, feeding <paramref name="pipe"/>; an I/O error destroys both sides at once.</summary>
    static void Pump(TcpClient from, TcpClient other, Pipe pipe)
    {
        var buf = new byte[16 * 1024];
        try
        {
            var inp = from.GetStream();
            int n;
            while ((n = inp.Read(buf, 0, buf.Length)) > 0) pipe.Data(buf[..n]);
            pipe.End();
            pipe.Close();
        }
        catch (Exception)
        {
            CloseQuietly(from);
            CloseQuietly(other);
        }
    }

    static void CloseQuietly(TcpClient s)
    {
        try { s.Close(); } catch (Exception) { /* already gone */ }
    }
}

/// <summary>TEST-ONLY frame tamperer: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer. The bytes still travel inside valid TLS.</summary>
public static class FrameFaults
{
    /// <summary>Kinds: duplicate, reorder, skip-seq, garbage, truncate, bitflip, wrong-round, wrong-session, oversize, drop, silent-from, extra-field, false-accuse.</summary>
    public sealed record FrameFault(string Kind, string Round, int? To = null, int? Accuse = null);

    static byte[] Raw(D body)
    {
        var json = new System.Text.UTF8Encoding(false).GetBytes(NetWire.Stringify(body));
        var o = new byte[4 + json.Length];
        o[0] = (byte)(json.Length >> 24);
        o[1] = (byte)(json.Length >> 16);
        o[2] = (byte)(json.Length >> 8);
        o[3] = (byte)json.Length;
        Buffer.BlockCopy(json, 0, o, 4, json.Length);
        return o;
    }

    static D Body(NetWire.Frame f) => new() { ["v"] = f.V, ["ty"] = f.Ty, ["sid"] = f.Sid, ["seq"] = f.Seq, ["rd"] = f.Rd, ["d"] = f.D };

    static object? SeqPlusOne(object? seq) =>
        seq is Num n ? new Num((long.Parse(n.Raw, CultureInfo.InvariantCulture) + 1).ToString(CultureInfo.InvariantCulture)) : Convert.ToInt64(seq, CultureInfo.InvariantCulture) + 1;

    public static Func<Mesh.TamperEvent, List<byte[]>> TamperFor(FrameFault spec)
    {
        var stash = new Dictionary<int, byte[]>();
        bool silent = false;
        return ev =>
        {
            if (silent) return new List<byte[]>();
            bool hit = ev.Frame.Rd == spec.Round && (spec.To == null || spec.To == ev.To);
            if (spec.Kind == "reorder")
            {
                if (stash.Remove(ev.To, out var held)) return new List<byte[]> { ev.Raw, held }; // later frame first, then the held-back one
                if (hit)
                {
                    stash[ev.To] = ev.Raw;
                    return new List<byte[]>();
                }
                return new List<byte[]> { ev.Raw };
            }
            if (!hit) return new List<byte[]> { ev.Raw };
            switch (spec.Kind)
            {
                case "duplicate": return new List<byte[]> { ev.Raw, ev.Raw };
                case "skip-seq": { var b = Body(ev.Frame); b["seq"] = SeqPlusOne(ev.Frame.Seq); return new List<byte[]> { Raw(b) }; }
                case "garbage":
                {
                    var g = new byte[ev.Raw.Length];
                    Array.Fill(g, (byte)0x5a);
                    int len = ev.Raw.Length - 4;
                    g[0] = (byte)(len >> 24); g[1] = (byte)(len >> 16); g[2] = (byte)(len >> 8); g[3] = (byte)len;
                    return new List<byte[]> { g };
                }
                case "truncate": return new List<byte[]> { ev.Raw[..Math.Max(5, ev.Raw.Length / 2)] };
                case "bitflip":
                {
                    var b = (byte[])ev.Raw.Clone();
                    int i = (int)Math.Floor(b.Length * 0.6);
                    b[i] ^= 0x04;
                    return new List<byte[]> { b };
                }
                case "wrong-round": { var b = Body(ev.Frame); b["rd"] = "zzz-" + ev.Frame.Rd; return new List<byte[]> { Raw(b) }; }
                case "wrong-session": { var b = Body(ev.Frame); b["sid"] = "not-this-session"; return new List<byte[]> { Raw(b) }; }
                case "oversize": return new List<byte[]> { new byte[] { 0x7f, 0xff, 0xff, 0xff } };
                case "drop": return new List<byte[]>();
                case "silent-from": silent = true; return new List<byte[]>();
                case "false-accuse":
                {
                    var b = Body(ev.Frame);
                    b["ty"] = "abort";
                    b["rd"] = "abort";
                    b["d"] = new D { ["kind"] = "timeout", ["blamed"] = spec.Accuse ?? 0, ["detail"] = "forged accusation" };
                    return new List<byte[]> { Raw(b) };
                }
                case "extra-field": { var b = Body(ev.Frame); b["x"] = 1; return new List<byte[]> { Raw(b) }; }
                default: throw new ArgumentException("unknown frame fault " + spec.Kind);
            }
        };
    }
}
