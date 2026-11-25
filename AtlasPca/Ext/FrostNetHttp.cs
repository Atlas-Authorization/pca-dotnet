// JSON over loopback HTTP for the networked FROST signer: a server for one GuardianSignerService (POST /round1, POST /round2) and the client transport the
// coordinator uses against it. All bytes are base64url inside the JSON tree, exactly the request and response objects of the in-process transport.
using System.Net;
using System.Net.Sockets;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>An HTTP server for one signer service. Routes: <c>POST /round1</c>, <c>POST /round2</c>. It binds 127.0.0.1 and, by default, an ephemeral port. JSON in, JSON out; a handler
/// error is a refusal response (400 with <c>refused: true</c>), never a stack or a share. A request body over 1 MiB is refused. There is no TLS and no authentication here: the signer's own
/// checks (allow token, proof of possession, equivocation guard) are the authority; expose it only on a loopback or an otherwise protected link.</summary>
public sealed class SignerHttpServer : IDisposable
{
    const int BodyLimit = 1 << 20, DrainLimit = 4 << 20, HeaderLimit = 64 * 1024, ReadTimeoutMs = 10_000;

    readonly GuardianSignerService _service;
    readonly TcpListener _listener;
    readonly CancellationTokenSource _stop = new();
    readonly HashSet<TcpClient> _live = new();
    readonly Task _loop;

    /// <summary>The base URL, e.g. <c>http://127.0.0.1:43211</c>.</summary>
    public string Url { get; }
    public int Port { get; }

    SignerHttpServer(GuardianSignerService service, string host, int port)
    {
        _service = service;
        var ip = IPAddress.Parse(host);
        _listener = new TcpListener(ip, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Url = $"http://{host}:{Port}";
        _loop = Task.Run(AcceptLoop);
    }

    /// <summary>Starts the server. <paramref name="port"/> 0 takes an ephemeral port; <paramref name="host"/> must be an IP literal (default 127.0.0.1).</summary>
    public static SignerHttpServer Start(GuardianSignerService service, int port = 0, string host = "127.0.0.1") => new(service, host, port);

    async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false); }
            catch (Exception) { return; }
            lock (_live) _live.Add(c);
            _ = Task.Run(() => Serve(c));
        }
    }

    async Task Serve(TcpClient c)
    {
        try
        {
            c.ReceiveTimeout = c.SendTimeout = ReadTimeoutMs;
            using var s = c.GetStream();
            var (code, body) = await Handle(s).ConfigureAwait(false);
            if (code == 0) return;
            var payload = Encoding.UTF8.GetBytes(Pca.Canonicalize(body));
            var head = Encoding.ASCII.GetBytes($"HTTP/1.1 {code} {Reason(code)}\r\ncontent-type: application/json\r\ncontent-length: {payload.Length}\r\nconnection: close\r\n\r\n");
            await s.WriteAsync(head).ConfigureAwait(false);
            await s.WriteAsync(payload).ConfigureAwait(false);
            await s.FlushAsync().ConfigureAwait(false);
        }
        catch (Exception) { /* a broken or timed-out connection: nothing to answer */ }
        finally
        {
            lock (_live) _live.Remove(c);
            c.Dispose();
        }
    }

    static string Reason(int code) => code switch { 200 => "OK", 400 => "Bad Request", 404 => "Not Found", 405 => "Method Not Allowed", _ => "Error" };

    D Refusal(string reason) => new() { ["ok"] = false, ["identifier"] = _service.Identifier, ["refused"] = true, ["reason"] = reason };

    async Task<(int Code, D Body)> Handle(NetworkStream s)
    {
        var buf = new List<byte>();
        var tmp = new byte[4096];
        int end;
        while ((end = FindHeaderEnd(buf)) < 0)
        {
            if (buf.Count > HeaderLimit) return (400, Refusal("request headers too large"));
            int n = await s.ReadAsync(tmp).ConfigureAwait(false);
            if (n == 0) return (0, new D());
            buf.AddRange(tmp.AsSpan(0, n).ToArray());
        }
        var lines = Encoding.ASCII.GetString(buf.GetRange(0, end).ToArray()).Split("\r\n");
        var parts = lines[0].Split(' ');
        if (parts.Length < 2) return (400, Refusal("bad request"));
        long length = 0;
        foreach (var l in lines.Skip(1))
        {
            var i = l.IndexOf(':');
            if (i > 0 && l[..i].Trim().Equals("content-length", StringComparison.OrdinalIgnoreCase) && !long.TryParse(l[(i + 1)..].Trim(), out length)) return (400, Refusal("bad request"));
        }
        if (parts[0] != "POST") return (405, new D { ["ok"] = false, ["reason"] = "method not allowed" });
        if (parts[1] != "/round1" && parts[1] != "/round2") return (404, new D { ["ok"] = false, ["reason"] = "not found" });
        try
        {
            // a body over the limit is read (up to a bound) before it is refused, so the refusal reaches a client that is still sending
            if (length < 0 || length > DrainLimit) throw new InvalidOperationException("request body too large");
            var body = buf.GetRange(end + 4, buf.Count - end - 4);
            while (body.Count < length)
            {
                int n = await s.ReadAsync(tmp).ConfigureAwait(false);
                if (n == 0) throw new InvalidOperationException("request body truncated");
                body.AddRange(tmp.AsSpan(0, n).ToArray());
            }
            if (length > BodyLimit) throw new InvalidOperationException("request body too large");
            var raw = Encoding.UTF8.GetString(body.GetRange(0, (int)length).ToArray());
            object? req = raw.Length > 0 ? Pca.ParseJson(raw) : new D();
            return (200, parts[1] == "/round1" ? _service.Round1(req) : _service.Round2(req));
        }
        catch (Exception e) { return (400, Refusal(e.Message)); }
    }

    static int FindHeaderEnd(List<byte> b)
    {
        for (int i = 0; i + 3 < b.Count; i++)
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i;
        return -1;
    }

    /// <summary>Stops listening and drops every open connection.</summary>
    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        lock (_live) foreach (var c in _live) c.Dispose();
        try { _loop.Wait(2000); } catch (Exception) { /* the loop ends by its cancellation */ }
        _stop.Dispose();
    }
}

/// <summary>The coordinator's transport to a signer HTTP server: one instance per remote signer. A transport failure or a timeout is an exception (the coordinator counts that signer as unavailable).</summary>
public sealed class HttpSignerTransport : ISignerTransport, IDisposable
{
    readonly string _base;
    readonly TimeSpan _timeout;
    readonly HttpClient _http;
    readonly bool _own;

    /// <param name="baseUrl">The server's base URL (no trailing slash).</param>
    /// <param name="identifier">The signer's participant identifier.</param>
    /// <param name="timeoutMs">Per-request timeout (default 10 s).</param>
    /// <param name="http">An HTTP client to use (default: one this transport owns).</param>
    public HttpSignerTransport(string baseUrl, long identifier, int timeoutMs = 10_000, HttpClient? http = null)
    {
        _base = baseUrl.TrimEnd('/');
        Identifier = identifier;
        _timeout = TimeSpan.FromMilliseconds(timeoutMs);
        _own = http == null;
        _http = http ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    }

    public long Identifier { get; }
    public Task<D> Round1Async(D request) => Post("/round1", request);
    public Task<D> Round2Async(D request) => Post("/round2", request);

    async Task<D> Post(string path, D body)
    {
        using var cts = new CancellationTokenSource(_timeout);
        using var content = new StringContent(Pca.Canonicalize(body), Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync(_base + path, content, cts.Token).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
        return Pca.ParseJson(text) as D ?? throw new InvalidOperationException("the signer answered with something other than a JSON object");
    }

    public void Dispose() { if (_own) _http.Dispose(); }
}
