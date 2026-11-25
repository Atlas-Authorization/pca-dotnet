// The reference mutual-TLS channel for the FROST DKG: one TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate. Each side trusts exactly the other
// participants' certificates, and the peer's SHA-256 certificate fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the handshake and never from
// message content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a second connection for an already linked
// identity and a connection from a party that should have been dialled are all refused before any DKG byte is read. Frames are a 4-byte big-endian length then the message; the length is checked
// against the message cap before any allocation. Certificate issuance, rotation and revocation are the deployer's. The TLS stack is the platform's (SslStream): TLS 1.3 needs a platform whose
// TLS library supports it (OpenSSL 1.1.1 or later on Linux; Windows 11 or Server 2022).
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>The pinned certificate of one OTHER participant (certificate only, PEM).</summary>
public sealed record TlsDkgPeerCert(long Id, string CertPem);

/// <summary>Where to dial one lower-numbered peer.</summary>
public sealed record TlsDkgAddress(long Id, string Host, int Port);

/// <summary>The options of <see cref="FrostDkgTls.StartTlsDkgNode"/>.</summary>
public sealed class TlsDkgNodeOpts
{
    public long Self;
    public byte[] SessionId = [];
    /// <summary>This node's PEM private key and certificate.</summary>
    public string KeyPem = "", CertPem = "";
    /// <summary>The pinned identities of every OTHER participant.</summary>
    public IReadOnlyList<TlsDkgPeerCert> PeerCerts = [];
    /// <summary>The port to listen on (0 = ephemeral; read <see cref="TlsDkgNode.Port"/>).</summary>
    public int ListenPort;
    public string ListenHost = "127.0.0.1";
}

public static class FrostDkgTls
{
    /// <summary>Starts one participant's TLS node: the listener for the higher-numbered peers. Throws when the peer certificates are not distinct, one is this node's, or a PEM does not parse.</summary>
    public static TlsDkgNode StartTlsDkgNode(TlsDkgNodeOpts opts) => new(opts);
}

/// <summary>One participant's listener and authenticated links.</summary>
public sealed class TlsDkgNode : IAsyncDisposable
{
    const int HandshakeMs = 10_000;

    readonly TlsDkgNodeOpts _opts;
    readonly Dictionary<string, long> _pinned = new(StringComparer.Ordinal);
    readonly List<long> _peers;
    readonly DkgInbox _inbox;
    readonly X509Certificate2 _own;
    readonly TcpListener _listener;
    readonly CancellationTokenSource _stop = new();
    readonly Dictionary<long, Link> _links = new();
    readonly HashSet<IDisposable> _conns = new();
    readonly List<TaskCompletionSource> _waiters = new();
    readonly object _lock = new();
    readonly Task _accept;
    bool _closed;

    sealed class Link(SslStream stream)
    {
        public SslStream Stream { get; } = stream;
        public SemaphoreSlim Write { get; } = new(1, 1);
    }

    public int Port { get; }

    internal TlsDkgNode(TlsDkgNodeOpts o)
    {
        _opts = o;
        foreach (var p in o.PeerCerts) _pinned[Fingerprint(X509Certificate2.CreateFromPem(p.CertPem).RawData)] = p.Id;
        if (_pinned.Count != o.PeerCerts.Count || o.PeerCerts.Any(p => p.Id == o.Self))
            throw new ArgumentException("startTlsDkgNode: peer certificates must be distinct and none may be this node");
        _peers = o.PeerCerts.Select(p => p.Id).OrderBy(x => x).ToList();
        _inbox = new DkgInbox(o.SessionId, _peers);
        // an ephemeral key does not survive SslStream on every platform: round-trip it through PKCS#12
        using (var pem = X509Certificate2.CreateFromPem(o.CertPem, o.KeyPem)) _own = new X509Certificate2(pem.Export(X509ContentType.Pkcs12));
        _listener = new TcpListener(IPAddress.Parse(o.ListenHost), o.ListenPort);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _accept = Task.Run(AcceptLoop);
    }

    static string Fingerprint(byte[] der) => Convert.ToHexString(SHA256.HashData(der));

    /// <summary>The certificate verification: a handshake whose peer certificate is one of the pinned ones and is inside its validity (pinned by certificate, not by chain or host name).</summary>
    bool PinCheck(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (cert == null) return false;
        try
        {
            if (!_pinned.ContainsKey(Fingerprint(cert.GetRawCertData()))) return false;
            using var c = new X509Certificate2(cert);
            var now = DateTime.Now;
            return now >= c.NotBefore && now <= c.NotAfter;
        }
        catch (Exception) { return false; }
    }

    bool Track(IDisposable c)
    {
        lock (_lock)
        {
            if (_closed) return false;
            _conns.Add(c);
            return true;
        }
    }

    long? IdOf(SslStream s) => s.RemoteCertificate is { } c && _pinned.TryGetValue(Fingerprint(c.GetRawCertData()), out var id) ? id : null;

    async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false); }
            catch (Exception) { return; }
            _ = Task.Run(() => Serve(c));
        }
    }

    async Task Serve(TcpClient c)
    {
        SslStream? s = null;
        try
        {
            if (!Track(c)) { c.Dispose(); return; }
            c.NoDelay = true;
            s = new SslStream(c.GetStream(), false, PinCheck);
            if (!Track(s)) { c.Dispose(); return; }
            using var hs = new CancellationTokenSource(HandshakeMs);
            await s.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _own, ClientCertificateRequired = true, EnabledSslProtocols = SslProtocols.Tls13, RemoteCertificateValidationCallback = PinCheck,
            }, hs.Token).ConfigureAwait(false);
            // only a pinned, authorized peer that is supposed to dial us (a higher id), once
            if (IdOf(s) is not long id || id < _opts.Self) { s.Dispose(); c.Dispose(); return; }
            if (!Attach(id, s)) { s.Dispose(); c.Dispose(); }
        }
        catch (Exception)
        {
            s?.Dispose();
            c.Dispose();
        }
    }

    bool Attach(long id, SslStream s)
    {
        Link link;
        List<TaskCompletionSource> ws;
        lock (_lock)
        {
            if (_closed || _links.ContainsKey(id)) return false;
            link = new Link(s);
            _links[id] = link;
            ws = [.. _waiters];
            _waiters.Clear();
        }
        foreach (var w in ws) w.TrySetResult();
        _ = Task.Run(() => ReadLoop(id, link));
        return true;
    }

    async Task ReadLoop(long id, Link link)
    {
        var dec = new FrostDkgChannel.FrameDecoder();
        var buf = new byte[32 * 1024];
        try
        {
            for (; ; )
            {
                int n = await link.Stream.ReadAsync(buf, _stop.Token).ConfigureAwait(false);
                if (n == 0) break;
                dec.Feed(buf.AsSpan(0, n).ToArray());
                foreach (var f in dec.Accepted) _inbox.Accept(id, f);
                dec.Accepted.Clear();
                if (dec.Error != null)
                {
                    _inbox.Fail(id, new DkgChannelError("oversize", id, "frame exceeds the cap"));
                    link.Stream.Dispose();
                    break;
                }
            }
        }
        catch (Exception) { /* the link ended */ }
        lock (_lock)
            if (_links.TryGetValue(id, out var cur) && ReferenceEquals(cur, link)) _links.Remove(id);
        _inbox.PeerGone(id);
    }

    async Task Dial(TlsDkgAddress a, Func<bool> stopped)
    {
        while (!stopped() && !IsClosed)
        {
            TcpClient? c = null;
            SslStream? s = null;
            try
            {
                c = new TcpClient { NoDelay = true };
                if (!Track(c)) { c.Dispose(); return; }
                using var hs = new CancellationTokenSource(HandshakeMs);
                await c.ConnectAsync(a.Host, a.Port, hs.Token).ConfigureAwait(false);
                s = new SslStream(c.GetStream(), false, PinCheck);
                if (!Track(s)) { c.Dispose(); return; }
                await s.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = a.Host, ClientCertificates = new X509CertificateCollection { _own }, EnabledSslProtocols = SslProtocols.Tls13, RemoteCertificateValidationCallback = PinCheck,
                }, hs.Token).ConfigureAwait(false);
                if (IdOf(s) == a.Id && Attach(a.Id, s)) return;
            }
            catch (Exception) { /* not reachable yet, or not the pinned peer: try again */ }
            s?.Dispose();
            c?.Dispose();
            try { await Task.Delay(50, _stop.Token).ConfigureAwait(false); } catch (OperationCanceledException) { return; }
        }
    }

    bool IsClosed { get { lock (_lock) return _closed; } }

    /// <summary>Dials the lower-numbered peers, waits for the higher-numbered ones and returns the channel once every link is authenticated. On the deadline the node closes and the error
    /// is <c>timeout</c>.</summary>
    public async Task<IDkgChannel> ConnectAsync(IReadOnlyList<TlsDkgAddress> addresses, double connectTimeoutMs = 15_000)
    {
        bool stop = false;
        foreach (var a in addresses)
        {
            if (!_peers.Contains(a.Id)) throw new DkgChannelError("identity", a.Id, "address for a participant that is not a pinned peer");
            if (a.Id < _opts.Self) _ = Dial(a, () => stop);
        }
        var deadline = DateTime.UtcNow.AddMilliseconds(connectTimeoutMs);
        for (; ; )
        {
            TaskCompletionSource w;
            List<long> missing;
            lock (_lock)
            {
                missing = _peers.Where(p => !_links.ContainsKey(p)).ToList();
                if (missing.Count == 0) break;
                w = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters.Add(w);
            }
            var left = (deadline - DateTime.UtcNow).TotalMilliseconds;
            if (left <= 0 || await Task.WhenAny(w.Task, Task.Delay(TimeSpan.FromMilliseconds(left))).ConfigureAwait(false) != w.Task)
            {
                stop = true;
                await CloseAsync().ConfigureAwait(false);
                throw new DkgChannelError("timeout", missing[0], $"no authenticated link to {string.Join(",", missing)}");
            }
        }
        stop = true;
        return new Channel(this);
    }

    /// <summary>Ends every link and the listener.</summary>
    public async Task CloseAsync()
    {
        List<IDisposable> conns;
        lock (_lock)
        {
            if (_closed) return;
            _closed = true;
            conns = [.. _conns];
        }
        _stop.Cancel();
        _inbox.Close();
        foreach (var c in conns) { try { c.Dispose(); } catch (Exception) { /* already gone */ } }
        _listener.Stop();
        try { await _accept.ConfigureAwait(false); } catch (Exception) { /* ends by cancellation */ }
    }

    public ValueTask DisposeAsync() => new(CloseAsync());

    sealed class Channel(TlsDkgNode n) : IDkgChannel
    {
        public long Self => n._opts.Self;
        public IReadOnlyList<long> Peers => n._peers;

        async Task Write(long to, string kind, object? body)
        {
            Link? link;
            lock (n._lock) n._links.TryGetValue(to, out link);
            if (link == null) throw new DkgChannelError("closed", to, "no authenticated link");
            var frame = FrostDkgChannel.EncodeFrame(FrostDkgChannel.EncodeMessage(n._opts.SessionId, kind, body));
            await link.Write.WaitAsync().ConfigureAwait(false);
            try
            {
                await link.Stream.WriteAsync(frame).ConfigureAwait(false);
                await link.Stream.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception) { throw new DkgChannelError("closed", to, "write failed"); }
            finally { link.Write.Release(); }
        }

        public Task Broadcast(string kind, object? body) => Task.WhenAll(n._peers.Select(p => Write(p, kind, body)));
        public Task Send(long to, string kind, object? body) => n._peers.Contains(to) ? Write(to, kind, body) : Task.FromException(new DkgChannelError("identity", to, "not a connected peer"));
        public Task<Dictionary<long, object?>> Collect(string kind, IReadOnlyList<long> from, double timeoutMs) => n._inbox.Collect(kind, from, timeoutMs);
        public Task Close() => n.CloseAsync();
    }
}
