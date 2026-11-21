using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3.
/// MUTUAL TLS with PINNED self-signed certificates (<see cref="Certs"/>): a peer is identified by the SHA-256 fingerprint of its
/// certificate, never by anything it claims, and the id in its hello frame must agree with the pinned fingerprint. Strict framing and
/// per-link sequence numbers: a malformed frame, a replayed or skipped one, a frame for the wrong round or session, or an oversize
/// length prefix aborts the whole run with a NetAbort naming the sender. Every receive has a timeout (no hangs). ABORT PROPAGATION:
/// the first failure poisons the mesh, wakes every pending receive, best-effort sends an abort frame to every peer, then closes the
/// sockets. A node dials every lower-numbered link target and accepts from the higher-numbered ones.
/// </summary>
public sealed class Mesh
{
    /// <summary>A node of the session: its address and PUBLIC certificate (the pinned trust anchor and identity).</summary>
    public sealed record NodeAddr(int Id, string Host, int Port, string CertPem);

    /// <summary>TEST HOOK input: a frame about to be sent and its honest encoding.</summary>
    public sealed record TamperEvent(int To, NetWire.Frame Frame, byte[] Raw);

    public sealed record LinkStats(int Peer, long AppBytesOut, long AppBytesIn, long FramesOut, long FramesIn);

    public sealed class Config
    {
        public int SelfId { get; set; }
        /// <summary>Every node of the session, including self.</summary>
        public List<NodeAddr>? Nodes { get; set; }
        /// <summary>Node ids this node keeps a link to (default: all others).</summary>
        public List<int>? LinkTo { get; set; }
        public string? KeyPem { get; set; }
        public string? CertPem { get; set; }
        public string? SessionId { get; set; }
        public string ListenHost { get; set; } = "0.0.0.0";
        public long ConnectTimeoutMs { get; set; } = 30_000;
        public long RecvTimeoutMs { get; set; } = 20_000;
        /// <summary>Time source for deadlines (default: real time).</summary>
        public IMeshClock? Clock { get; set; } = MeshClock.Wall;
        /// <summary>TEST HOOK: a (malicious) sender rewriting its own outgoing frames; refused unless <see cref="UnsafeTestHooks"/>.</summary>
        public Func<TamperEvent, List<byte[]>>? Tamper { get; set; }
        public bool UnsafeTestHooks { get; set; }
        public int MaxInboxFrames { get; set; } = 1024;
        public long MaxInboxBytes { get; set; } = 32L * 1024 * 1024;
    }

    public const int MAX_MESH_EVENTS = 64;

    private sealed class Item
    {
        public readonly string Rd;
        public readonly object? D;
        public readonly int Size;
        public readonly NetWire.NetAbort? Abort;
        public Item(string rd, object? d, int size, NetWire.NetAbort? abort) { Rd = rd; D = d; Size = size; Abort = abort; }
    }

    private sealed class Link
    {
        public readonly int Id;
        public readonly NetWire.FrameSplitter Splitter = new();
        public readonly Queue<Item> Inbox = new();
        public TcpClient? Tcp;
        public SslStream? Ssl;
        public long InboxBytes;
        public bool Paused;
        public long SendSeq;
        public long RecvSeq;
        public volatile bool Closed;
        public volatile bool SockClosed;
        public volatile bool HelloSeen;
        public long BytesIn, BytesOut, FramesIn, FramesOut;
        public Link(int id) { Id = id; }
    }

    public readonly int SelfId;
    private readonly Config cfg;
    private readonly IMeshClock clock;
    private readonly SortedDictionary<int, Link> links = new();
    private readonly Dictionary<string, int> pinned = new();
    private readonly Dictionary<int, NodeAddr> nodeById = new();
    private readonly Dictionary<int, X509Certificate2> nodeCert = new();
    private readonly ECDsa privateKey;
    private readonly object gate = new();
    private readonly object signLock = new();
    private readonly List<string> events = new();
    private long eventsDropped;
    private volatile NetWire.NetAbort? failure;
    private volatile bool finished;
    private volatile bool closing;
    private volatile bool deferAborts;
    private X509Certificate2? tlsCert;
    private TcpListener? server;

    public Mesh(Config cfg)
    {
        this.cfg = cfg ?? throw new ArgumentException("mesh: incomplete config");
        clock = cfg.Clock ?? MeshClock.Wall;
        SelfId = cfg.SelfId;
        if (cfg.Tamper != null && !cfg.UnsafeTestHooks) throw new ArgumentException("mesh: the tamper test hook requires unsafeTestHooks (test-only)");
        if (cfg.Nodes == null || cfg.SessionId == null || cfg.KeyPem == null || cfg.CertPem == null) throw new ArgumentException("mesh: incomplete config");
        privateKey = Certs.ParseKey(cfg.KeyPem);
        string selfFp = Certs.FingerprintOf(cfg.CertPem);
        bool selfSeen = false;
        foreach (NodeAddr n in cfg.Nodes)
        {
            if (nodeById.ContainsKey(n.Id)) throw new ArgumentException("mesh: duplicate node id " + n.Id);
            nodeById[n.Id] = n;
            X509Certificate2 nc = Certs.ParseCert(n.CertPem);
            nodeCert[n.Id] = nc;
            string fp = Certs.Fingerprint(nc);
            if (n.Id == SelfId)
            {
                selfSeen = true;
                if (fp != selfFp) throw new ArgumentException("mesh: own certificate differs from the one listed for this node");
            }
            else
            {
                if (pinned.ContainsKey(fp) || fp == selfFp) throw new ArgumentException("mesh: two nodes share one certificate");
                pinned[fp] = n.Id;
            }
        }
        if (!selfSeen) throw new ArgumentException("mesh: self not in nodes");
        var want = new List<int>();
        if (cfg.LinkTo != null) want.AddRange(cfg.LinkTo);
        else foreach (NodeAddr n in cfg.Nodes) if (n.Id != SelfId) want.Add(n.Id);
        foreach (int id in want)
        {
            if (!nodeById.ContainsKey(id) || id == SelfId) throw new ArgumentException("mesh: unknown link target " + id);
            links[id] = new Link(id);
        }
    }

    private void Note(string msg)
    {
        lock (events)
        {
            if (events.Count < MAX_MESH_EVENTS) { events.Add(msg); return; }
        }
        Interlocked.Increment(ref eventsDropped);
    }

    public List<string> Events() { lock (events) return new List<string>(events); }
    public long EventsDropped() => Interlocked.Read(ref eventsDropped);
    public string SessionId() => cfg.SessionId!;
    public NetWire.NetAbort? Failed() => failure;
    public List<int> Peers() => new(links.Keys);

    // ------------------------------------------------------------------ connect

    /// <summary>Pin-only validation: accept iff the presented certificate is currently valid and its SHA-256 is one of the pinned fingerprints.
    /// Chain building, hostnames and the platform trust store play no part (policy errors are expected for a self-signed certificate).</summary>
    private bool PinCheck(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (cert == null) return false;
        try
        {
            using var c2 = new X509Certificate2(cert);
            DateTime now = DateTime.Now;
            if (now < c2.NotBefore || now > c2.NotAfter) return false;
            return pinned.ContainsKey(Certs.Fingerprint(c2));
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static IPAddress ResolveHost(string host)
    {
        if (IPAddress.TryParse(host, out IPAddress? ip)) return ip;
        IPAddress[] all = Dns.GetHostAddresses(host);
        if (all.Length == 0) throw new InvalidOperationException("no address for " + host);
        return all[0];
    }

    /// <summary>Port the TLS server is bound to (useful when the configured port was 0).</summary>
    public int BoundPort() => server == null ? -1 : ((IPEndPoint)server.LocalEndpoint).Port;

    private static int ClampMs(long ms) => (int)Math.Max(1L, Math.Min(int.MaxValue, ms));

    /// <summary>Listen, dial every lower-numbered link target, and wait until all links are authenticated.</summary>
    public void Connect()
    {
        NodeAddr self = nodeById[SelfId];
        long deadline = clock.Now() + cfg.ConnectTimeoutMs;
        try
        {
            tlsCert = Certs.WithKey(cfg.CertPem!, cfg.KeyPem!);
            server = new TcpListener(ResolveHost(cfg.ListenHost), self.Port);
            server.Start(128);
        }
        catch (Exception e)
        {
            throw new InvalidOperationException("mesh: cannot listen: " + e.Message, e);
        }
        Daemon("mesh-accept-" + SelfId, AcceptLoop).Start();
        foreach (int id in Peers())
        {
            if (id < SelfId)
            {
                int target = id;
                Daemon("mesh-dial-" + SelfId + "-" + id, () => Dial(target, deadline)).Start();
            }
        }
        NetWire.NetAbort toFail;
        lock (gate)
        {
            for (;;)
            {
                NetWire.NetAbort? cur = failure;
                if (cur != null) throw cur;
                var missing = new List<int>();
                foreach (Link l in links.Values) if (!l.HelloSeen) missing.Add(l.Id);
                if (missing.Count == 0) return;
                long left = deadline - clock.Now();
                if (left <= 0)
                {
                    toFail = new NetWire.NetAbort("timeout", missing[0], SelfId, "connect: no authenticated link from [" + string.Join(", ", missing) + "]");
                    break;
                }
                try
                {
                    Monitor.Wait(gate, 20); // a poll interval, not a decision: real time
                }
                catch (ThreadInterruptedException)
                {
                    toFail = new NetWire.NetAbort("local", null, SelfId, "connect interrupted");
                    break;
                }
            }
        }
        Fail(toFail, null);
        throw toFail;
    }

    private void WakeAll()
    {
        lock (gate) Monitor.PulseAll(gate);
    }

    private static Thread Daemon(string name, ThreadStart r) => new(r) { Name = name, IsBackground = true };

    private void AcceptLoop()
    {
        while (!closing && failure == null)
        {
            TcpClient tcp;
            try
            {
                tcp = server!.AcceptTcpClient();
            }
            catch (Exception e)
            {
                if (!closing) Note("server error: " + e.Message);
                return;
            }
            Daemon("mesh-in-" + SelfId, () => OnIncoming(tcp)).Start();
        }
    }

    private void Dial(int id, long deadline)
    {
        NodeAddr node = nodeById[id];
        while (failure == null && !closing && clock.Now() < deadline)
        {
            TcpClient? tcp = null;
            SslStream? ssl = null;
            try
            {
                tcp = new TcpClient { NoDelay = true };
                Task connectTask = tcp.ConnectAsync(node.Host, node.Port);
                if (!connectTask.Wait(3000))
                {
                    connectTask.ContinueWith(t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                    throw new IOException("connect timed out");
                }
                NetworkStream ns = tcp.GetStream();
                ns.ReadTimeout = ClampMs(deadline - clock.Now());
                ssl = new SslStream(ns, false);
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = node.Host,
                    ClientCertificates = new X509CertificateCollection { tlsCert! },
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    RemoteCertificateValidationCallback = PinCheck,
                });
                ns.ReadTimeout = Timeout.Infinite;
                // We pin by certificate (not hostname): the peer must be exactly the pinned identity of node `id`.
                string? fp = ssl.RemoteCertificate == null ? null : Certs.Fingerprint(ssl.RemoteCertificate);
                if (fp == null || !pinned.TryGetValue(fp, out int got) || got != id)
                {
                    CloseQuietly(tcp, ssl);
                    Fail(new NetWire.NetAbort("identity", id, SelfId, "dial: peer certificate is not the pinned identity of node " + id), null);
                    return;
                }
                Attach(id, tcp, ssl);
                return;
            }
            catch (Exception)
            {
                CloseQuietly(tcp, ssl);
            }
            try
            {
                Thread.Sleep(150); // retry pacing, not a decision
            }
            catch (ThreadInterruptedException)
            {
                return;
            }
        }
    }

    private void OnIncoming(TcpClient tcp)
    {
        SslStream? ssl = null;
        try
        {
            tcp.NoDelay = true;
            NetworkStream ns = tcp.GetStream();
            ns.ReadTimeout = (int)Math.Min(int.MaxValue, Math.Max(1L, cfg.ConnectTimeoutMs));
            ssl = new SslStream(ns, false);
            ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
            {
                ServerCertificate = tlsCert,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = PinCheck,
            });
            ns.ReadTimeout = Timeout.Infinite;
            int? id = null;
            if (ssl.RemoteCertificate != null && pinned.TryGetValue(Certs.Fingerprint(ssl.RemoteCertificate), out int found)) id = found;
            if (id == null || !links.ContainsKey(id.Value) || id.Value < SelfId)
            {
                Note("rejected incoming connection (peer " + (id == null ? "null" : id.Value.ToString(CultureInfo.InvariantCulture)) + ")");
                CloseQuietly(tcp, ssl);
                return;
            }
            Attach(id.Value, tcp, ssl);
        }
        catch (Exception e)
        {
            Note("tlsClientError: " + Sanitize(e.Message ?? "", 120));
            CloseQuietly(tcp, ssl);
        }
    }

    private static void CloseQuietly(TcpClient? tcp, SslStream? ssl)
    {
        try { ssl?.Dispose(); } catch (Exception) { /* already gone */ }
        try { tcp?.Dispose(); } catch (Exception) { /* already gone */ }
    }

    private static void CloseLink(Link l)
    {
        l.SockClosed = true;
        CloseQuietly(l.Tcp, l.Ssl);
    }

    private void Attach(int id, TcpClient tcp, SslStream ssl)
    {
        Link l = links[id];
        lock (gate)
        {
            if (l.Ssl != null)
            {
                Note("duplicate connection from node " + id);
                CloseQuietly(tcp, ssl);
                return;
            }
            l.Tcp = tcp;
            l.Ssl = ssl;
        }
        // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin. Sent before the reader starts, so
        // no caller data can overtake it.
        var d = new JD { ["id"] = SelfId };
        SendFrame(l, "hello", "hello", d);
        Daemon("mesh-rd-" + SelfId + "-" + id, () => ReadLoop(l, ssl)).Start();
    }

    // ------------------------------------------------------------------ receive path

    private void ReadLoop(Link l, SslStream input)
    {
        var buf = new byte[64 * 1024];
        for (;;)
        {
            int n;
            try
            {
                n = input.Read(buf, 0, buf.Length);
            }
            catch (Exception e)
            {
                OnClosed(l, "socket error: " + e.Message);
                return;
            }
            if (n <= 0) { OnClosed(l, "peer ended"); return; }
            var chunk = new byte[n];
            Buffer.BlockCopy(buf, 0, chunk, 0, n);
            try
            {
                OnData(l, chunk);
            }
            catch (Exception)
            {
                Fail(new NetWire.NetAbort("malformed", l.Id, SelfId, "frame handling error"), null);
                return;
            }
            if (failure != null) return;
            lock (gate)
            {
                while (l.Paused && failure == null && !l.Closed) Monitor.Wait(gate);
            }
        }
    }

    private static double ToDouble(object? o)
    {
        switch (o)
        {
            case AtlasPca.Num n:
                return double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double v) ? v : double.NaN;
            case int i: return i;
            case long lg: return lg;
            default: return double.NaN;
        }
    }

    private static int? AsInt(object? o)
    {
        double d = ToDouble(o);
        if (double.IsNaN(d) || double.IsInfinity(d) || d != Math.Round(d) || Math.Abs(d) > 1e9 || (d == 0 && double.IsNegative(d))) return null;
        return (int)d;
    }

    private void OnData(Link l, byte[] chunk)
    {
        if (failure != null) return;
        Interlocked.Add(ref l.BytesIn, chunk.Length);
        List<byte[]> bodies;
        try
        {
            bodies = l.Splitter.Push(chunk);
        }
        catch (InvalidOperationException)
        {
            Fail(new NetWire.NetAbort("oversize", l.Id, SelfId, "length prefix above MAX_FRAME_BYTES"), null);
            return;
        }
        foreach (byte[] b in bodies)
        {
            JD? f = NetWire.ParseFrame(b);
            if (f == null)
            {
                long? pv = NetWire.VersionMismatch(b);
                if (pv != null)
                    Fail(new NetWire.NetAbort("version", l.Id, SelfId, "peer " + l.Id + " speaks wire version " + pv.Value.ToString(CultureInfo.InvariantCulture) + ", this node speaks " + NetWire.WIRE_VERSION + "; upgrade both peers"), null);
                else
                    Fail(new NetWire.NetAbort("malformed", l.Id, SelfId, "undecodable or ill-shaped frame"), null);
                return;
            }
            string ty = (string)f["ty"]!;
            string rd = (string)f["rd"]!;
            if (!(f.TryGetValue("sid", out object? sid) && sid is string ss && ss == cfg.SessionId))
            {
                Fail(new NetWire.NetAbort("wrong-session", l.Id, SelfId, "frame from another session"), null);
                return;
            }
            if (ty == "abort")
            {
                // An abort frame is only a CLAIM by the peer that sent it: we blame that peer, never the party it names.
                JD d = f["d"] as JD ?? new JD();
                bool relayed = d.TryGetValue("relayed", out object? rl) && rl is bool rb && rb;
                string? claimedKind = d.TryGetValue("kind", out object? ck) && ck is string cks && NetWire.ABORT_KINDS.Contains(cks) ? cks : null;
                int maxId = 0;
                foreach (NodeAddr x in cfg.Nodes!) maxId = Math.Max(maxId, x.Id);
                int? cb = d.TryGetValue("blamed", out object? bl) ? AsInt(bl) : null;
                int? claimedBlame = cb != null && cb >= 0 && cb <= maxId ? cb : null;
                string detail = d.TryGetValue("detail", out object? dt) && dt is string dts ? Sanitize(dts, 120) : "";
                var claim = new NetWire.NetAbort("peer-abort", relayed ? null : l.Id, SelfId,
                    "peer " + l.Id + " " + (relayed ? "relayed" : "reported") + " an abort (" + (claimedKind ?? "unspecified") + ", accuses "
                        + (claimedBlame == null ? "no one" : claimedBlame.Value.ToString(CultureInfo.InvariantCulture)) + ", unverified) " + detail,
                    claimedKind, claimedBlame,
                    relayed ? "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence" : null, null, null);
                if (deferAborts)
                {
                    // Order-preserving: takes effect when READ, i.e. after every frame this peer sent before it.
                    lock (gate) l.Inbox.Enqueue(new Item(rd, null, b.Length, claim));
                    continue;
                }
                Fail(claim, l.Id);
                return;
            }
            long seq = (long)ToDouble(f["seq"]);
            if (seq != l.RecvSeq)
            {
                string kind = seq < l.RecvSeq ? "duplicate" : "out-of-order";
                Fail(new NetWire.NetAbort(kind, l.Id, SelfId, "expected seq " + l.RecvSeq + ", got " + seq + " (round " + rd + ")"), null);
                return;
            }
            l.RecvSeq++;
            Interlocked.Increment(ref l.FramesIn);
            if (ty == "hello")
            {
                int? hid = f["d"] is JD hd && hd.TryGetValue("id", out object? hv) ? AsInt(hv) : null;
                if (l.HelloSeen || hid == null || hid.Value != l.Id)
                {
                    Fail(new NetWire.NetAbort("identity", l.Id, SelfId, "hello claims id " + (hid == null ? "?" : hid.Value.ToString(CultureInfo.InvariantCulture)) + " on the link pinned to " + l.Id), null);
                    return;
                }
                lock (gate) { l.HelloSeen = true; Monitor.PulseAll(gate); }
            }
            else
            {
                if (!l.HelloSeen)
                {
                    Fail(new NetWire.NetAbort("malformed", l.Id, SelfId, "data before hello"), null);
                    return;
                }
                bool flood;
                lock (gate)
                {
                    l.Inbox.Enqueue(new Item(rd, f["d"], b.Length, null));
                    l.InboxBytes += b.Length;
                    flood = l.Inbox.Count > cfg.MaxInboxFrames || l.InboxBytes > cfg.MaxInboxBytes;
                    if (!flood && !l.Paused && (l.Inbox.Count > cfg.MaxInboxFrames / 2 || l.InboxBytes > cfg.MaxInboxBytes / 2)) l.Paused = true;
                }
                if (flood)
                {
                    Fail(new NetWire.NetAbort("flood", l.Id, SelfId, "peer " + l.Id + " queued more than the inbox cap allows"), null);
                    return;
                }
            }
        }
        WakeAll();
    }

    private void OnClosed(Link l, string why)
    {
        if (l.Closed) return;
        l.Closed = true;
        if (!finished && failure == null && !l.HelloSeen) Note("link " + l.Id + " closed before hello: " + why);
        WakeAll();
    }

    // ------------------------------------------------------------------ send path

    private void SendFrame(Link l, string ty, string rd, object? d)
    {
        lock (l)
        {
            var frame = new NetWire.Frame(NetWire.WIRE_VERSION, ty, cfg.SessionId!, l.SendSeq++, rd, d);
            byte[] raw = NetWire.EncodeFrame(frame);
            List<byte[]> outs = cfg.Tamper != null && ty != "hello" ? cfg.Tamper(new TamperEvent(l.Id, frame, raw)) : new List<byte[]> { raw };
            WriteAll(l, outs);
            Interlocked.Increment(ref l.FramesOut);
        }
    }

    private static void WriteAll(Link l, List<byte[]> outs)
    {
        foreach (byte[] b in outs)
        {
            SslStream? s = l.Ssl;
            if (s != null && !l.SockClosed)
            {
                try
                {
                    s.Write(b, 0, b.Length);
                    s.Flush();
                    Interlocked.Add(ref l.BytesOut, b.Length);
                }
                catch (Exception)
                {
                    // the dead link surfaces as a disconnect on the read side
                }
            }
        }
    }

    /// <summary>Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed).</summary>
    public void Send(int to, string round, object? payload)
    {
        NetWire.NetAbort? f = failure;
        if (f != null) throw f;
        if (!links.TryGetValue(to, out Link? l)) throw new ArgumentException("mesh: no link to " + to);
        SendFrame(l, "msg", round, payload);
    }

    public void Broadcast(string round, object? payload) => Broadcast(round, payload, Peers());

    public void Broadcast(string round, object? payload, List<int> to) { foreach (int p in to) Send(p, round, payload); }

    /// <summary>ECDSA-P256/SHA-256 (DER) signature over <paramref name="data"/> with this node's TLS identity key.</summary>
    public byte[] Sign(byte[] data)
    {
        try
        {
            lock (signLock) return privateKey.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception e)
        {
            throw new InvalidOperationException("mesh: sign failed", e);
        }
    }

    /// <summary>Verify <paramref name="sig"/> over <paramref name="data"/> against the PINNED certificate of node <paramref name="peer"/>. False on any failure.</summary>
    public bool Verify(int peer, byte[] data, byte[] sig)
    {
        if (!nodeCert.TryGetValue(peer, out X509Certificate2? n) || peer == SelfId) return false;
        try
        {
            using ECDsa? pub = n.GetECDsaPublicKey();
            return pub != null && pub.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Receive the next message from <paramref name="from"/>, which must belong to <paramref name="round"/>. Times out; never hangs.</summary>
    public object? Recv(int from, string round) => Recv(from, round, cfg.RecvTimeoutMs);

    public object? Recv(int from, string round, long timeoutMs)
    {
        if (!links.TryGetValue(from, out Link? l)) throw new ArgumentException("mesh: no link to " + from);
        long deadline = clock.Now() + timeoutMs;
        NetWire.NetAbort toFail;
        int? skip = null;
        lock (gate)
        {
            for (;;)
            {
                NetWire.NetAbort? cur = failure;
                if (cur != null) throw cur;
                if (l.Inbox.Count > 0)
                {
                    Item it = l.Inbox.Dequeue();
                    if (it.Abort != null) { toFail = it.Abort; skip = from; break; }
                    l.InboxBytes -= it.Size;
                    if (l.Paused && l.Inbox.Count <= cfg.MaxInboxFrames / 2 && l.InboxBytes <= cfg.MaxInboxBytes / 2)
                    {
                        l.Paused = false;
                        Monitor.PulseAll(gate);
                    }
                    if (it.Rd != round)
                    {
                        toFail = new NetWire.NetAbort("wrong-round", from, SelfId, "expected round '" + round + "', got '" + it.Rd + "'");
                        break;
                    }
                    return it.D;
                }
                if (l.Closed)
                {
                    toFail = new NetWire.NetAbort("disconnect", from, SelfId, "link to " + from + " closed while awaiting '" + round + "'");
                    break;
                }
                long left = deadline - clock.Now();
                if (left <= 0)
                {
                    toFail = new NetWire.NetAbort("timeout", from, SelfId, "no '" + round + "' message from " + from + " within " + timeoutMs + "ms (deadline " + timeoutMs
                        + "ms; a silent peer is blamed on this local observation only)", null, null, null, null, (int)Math.Min(int.MaxValue, timeoutMs));
                    break;
                }
                object? timer = null;
                try
                {
                    timer = clock.SetTimer(WakeAll, left);
                    Monitor.Wait(gate);
                }
                catch (ThreadInterruptedException)
                {
                    toFail = new NetWire.NetAbort("local", null, SelfId, "receive interrupted");
                    break;
                }
                finally
                {
                    if (timer != null) clock.ClearTimer(timer);
                }
            }
        }
        Fail(toFail, skip);
        throw toFail;
    }

    /// <summary>
    /// While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and
    /// only takes effect when a receive from that peer reaches it (used for the blame round).
    /// </summary>
    public void SetDeferAborts(bool on) { deferAborts = on; }

    /// <summary>Receive <paramref name="round"/> from every peer in <paramref name="from"/> concurrently; a failure on any link throws.</summary>
    public SortedDictionary<int, object?> Collect(string round, List<int> from, long? timeoutMs)
    {
        long t = timeoutMs ?? cfg.RecvTimeoutMs;
        var outp = new SortedDictionary<int, object?>();
        Exception? err = null;
        var ts = new List<Thread>();
        foreach (int p in from)
        {
            int peer = p;
            Thread th = Daemon("mesh-collect-" + peer, () =>
            {
                try
                {
                    object? v = Recv(peer, round, t);
                    lock (outp) outp[peer] = v;
                }
                catch (Exception e)
                {
                    lock (outp) { err ??= e; }
                }
            });
            ts.Add(th);
            th.Start();
        }
        foreach (Thread th in ts) th.Join();
        lock (outp)
        {
            if (err != null) throw err;
        }
        return outp;
    }

    public SortedDictionary<int, object?> Collect(string round) => Collect(round, Peers(), null);

    // ------------------------------------------------------------------ failure / shutdown

    /// <summary>
    /// Poison the mesh: record the first failure, tell EVERY peer except <paramref name="skipPeer"/> (a forwarded accusation stays a claim,
    /// so an innocent bystander is never blamed for merely closing), close all.
    /// </summary>
    public void Fail(NetWire.NetAbort err, int? skipPeer)
    {
        lock (gate)
        {
            if (failure != null) return;
            failure = err;
            Monitor.PulseAll(gate);
        }
        bool fwd = err.Kind == "peer-abort";
        string kind = fwd ? (err.ClaimedKind ?? "peer-abort") : err.Kind;
        int? blamed = fwd ? err.ClaimedBlame : err.Blamed;
        foreach (Link l in links.Values)
        {
            if (skipPeer != null && l.Id == skipPeer.Value) continue;
            if (l.Ssl != null && !l.SockClosed && !l.Closed)
            {
                var d = new JD { ["kind"] = kind, ["blamed"] = (object?)blamed, ["detail"] = Sanitize(err.Message, 200) };
                if (fwd) d["relayed"] = true;
                try
                {
                    lock (l)
                    {
                        var frame = new NetWire.Frame(NetWire.WIRE_VERSION, "abort", cfg.SessionId!, l.SendSeq++, "abort", d);
                        WriteAll(l, new List<byte[]> { NetWire.EncodeFrame(frame) });
                    }
                }
                catch (Exception)
                {
                    // best effort
                }
            }
        }
        Daemon("mesh-fail-close", () =>
        {
            try { Thread.Sleep(50); } catch (ThreadInterruptedException) { /* closing anyway */ }
            CloseAll();
        }).Start();
    }

    /// <summary>Normal completion: flush and close. Peers that are still reading see EOF only after our data.</summary>
    public void Finish()
    {
        finished = true;
        try { Thread.Sleep(100); } catch (ThreadInterruptedException) { /* closing anyway */ }
        CloseAll();
    }

    /// <summary>Abrupt shutdown with no abort frames (a crashed node; also the way a launcher stops a straggler).</summary>
    public void Kill() { CloseAll(); }

    private void CloseAll()
    {
        closing = true;
        foreach (Link l in links.Values) CloseLink(l);
        try { server?.Stop(); } catch (Exception) { /* already closed */ }
    }

    public List<LinkStats> Stats()
    {
        var outp = new List<LinkStats>();
        foreach (Link l in links.Values)
            outp.Add(new LinkStats(l.Id, Interlocked.Read(ref l.BytesOut), Interlocked.Read(ref l.BytesIn), Interlocked.Read(ref l.FramesOut), Interlocked.Read(ref l.FramesIn)));
        return outp;
    }

    /// <summary>Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging).</summary>
    internal static string Sanitize(string x, int max)
    {
        var sb = new System.Text.StringBuilder();
        foreach (char c in x) sb.Append(c >= 0x20 && c <= 0x7e ? c : '?');
        return sb.Length > max ? sb.ToString(0, max) : sb.ToString();
    }
}
