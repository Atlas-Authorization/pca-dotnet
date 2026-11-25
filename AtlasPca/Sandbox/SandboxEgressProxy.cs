// The egress proxy: a forward proxy for non-WASM tools (the reference createEgressProxy). Set it as the tool's only route out (HTTP(S)_PROXY, a
// network namespace, or the generated OS profile that permits connecting only to this proxy). Every request is claimed against the admissions of an
// EgressPolicy (default deny); refusals answer 403 and are receipted. The upstream address is resolved through a guard that refuses private
// addresses unless AllowPrivate, and the connection is made to the address that passed the guard, so an admitted hostname cannot be re-pointed at an
// internal service between the check and the connect.
//
// HTTP/1.1 only, one request per connection (connection: close). A request body is read whole (Content-Length or chunked) up to MaxBodyBytes.
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Sandbox;

public sealed class EgressProxyOptions
{
    /// <summary>REQUIRED: the admissions (default deny).</summary>
    public PcaSandbox.EgressPolicy? Policy { get; set; }
    /// <summary>REQUIRED: where every decision is receipted.</summary>
    public PcaSandbox.ReceiptLog? Log { get; set; }
    /// <summary>The runtime class the receipts claim. Default egress_default_deny.</summary>
    public string RuntimeClass { get; set; } = "egress_default_deny";
    /// <summary>Permit upstreams that resolve to private or loopback addresses (tests, internal APIs). Default false (SSRF guard).</summary>
    public bool AllowPrivate { get; set; }
    public int MaxBodyBytes { get; set; } = 1 << 20;
    public int UpstreamTimeoutMs { get; set; } = 10_000;
}

public static partial class PcaSandbox
{
    /// <summary>Build the forward proxy (call <see cref="EgressProxy.Start"/> to listen).</summary>
    public static EgressProxy CreateEgressProxy(EgressProxyOptions o) => new(o);
}

public sealed class EgressProxy : IDisposable
{
    static readonly HashSet<string> Hop = new(StringComparer.Ordinal)
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host",
    };

    const int MaxHeaderBytes = 65_536;
    readonly PcaSandbox.EgressPolicy _policy;
    readonly PcaSandbox.ReceiptLog _log;
    readonly string _cls;
    readonly bool _allowPrivate;
    readonly int _maxBody, _timeoutMs;
    readonly HttpClient _http;
    readonly CancellationTokenSource _stop = new();
    TcpListener? _listener;

    internal EgressProxy(EgressProxyOptions o)
    {
        _policy = o?.Policy ?? throw new ArgumentException("an egress policy is required");
        _log = o.Log ?? throw new ArgumentException("a receipt log is required");
        _cls = o.RuntimeClass;
        _allowPrivate = o.AllowPrivate;
        _maxBody = o.MaxBodyBytes;
        _timeoutMs = o.UpstreamTimeoutMs;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromMilliseconds(_timeoutMs), ConnectCallback = GuardedConnect,
        };
        _http = new HttpClient(handler, true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>The port the proxy listens on (after <see cref="Start"/>).</summary>
    public int Port => ((IPEndPoint?)_listener?.LocalEndpoint)?.Port ?? 0;

    /// <summary>Listen on <paramref name="address"/> (loopback by default) and <paramref name="port"/> (0 = any free port); returns the port.</summary>
    public int Start(int port = 0, string address = "127.0.0.1")
    {
        if (_listener != null) throw new InvalidOperationException("already started");
        _listener = new TcpListener(IPAddress.Parse(address), port);
        _listener.Start();
        _ = Task.Run(AcceptLoop);
        return Port;
    }

    public void Dispose()
    {
        _stop.Cancel();
        try { _listener?.Stop(); } catch (Exception) { /* already closed */ }
        _http.Dispose();
    }

    async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await _listener!.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false); }
            catch (Exception) { return; }
            _ = Task.Run(() => Handle(c));
        }
    }

    // ---- the guard ----
    static bool IsPrivateIfLiteral(string host)
    {
        var h = host.Length > 1 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        return IPAddress.TryParse(h, out var ip) && PcaSandbox.IsPrivateAddress(ip.ToString());
    }

    async Task<IPAddress[]> ResolveGuarded(string host, CancellationToken ct)
    {
        var h = host.Length > 1 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        var list = IPAddress.TryParse(h, out var lit) ? new[] { lit } : await Dns.GetHostAddressesAsync(h, ct).ConfigureAwait(false);
        if (list.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        if (!_allowPrivate && list.Any(a => PcaSandbox.IsPrivateAddress(a.ToString()))) throw new SocketException((int)SocketError.AccessDenied);
        return list;
    }

    async Task<Socket> ConnectTo(string host, int port, CancellationToken ct)
    {
        var list = await ResolveGuarded(host, ct).ConfigureAwait(false);
        Exception? last = null;
        foreach (var a in list)
        {
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await s.ConnectAsync(new IPEndPoint(a, port), ct).ConfigureAwait(false);
                return s;
            }
            catch (Exception e)
            {
                s.Dispose();
                last = e;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    async ValueTask<Stream> GuardedConnect(SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        var s = await ConnectTo(ctx.DnsEndPoint.Host, ctx.DnsEndPoint.Port, ct).ConfigureAwait(false);
        return new NetworkStream(s, true);
    }

    static string ErrCode(Exception e)
    {
        for (var x = e; x != null; x = x.InnerException!)
        {
            if (x is SocketException se)
                return se.SocketErrorCode switch
                {
                    SocketError.AccessDenied => "EACCES", SocketError.ConnectionRefused => "ECONNREFUSED", SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData => "ENOTFOUND",
                    SocketError.TimedOut => "ETIMEDOUT", SocketError.ConnectionReset => "ECONNRESET", SocketError.NetworkUnreachable => "ENETUNREACH", _ => se.SocketErrorCode.ToString(),
                };
            if (x is OperationCanceledException) return "timeout";
            if (x.InnerException == null) break;
        }
        return e.Message;
    }

    // ---- receipts ----
    void Receipt(string method, string url, D? admitted, string outcome, string reason)
    {
        var sub = new D
        {
            ["op_id"] = admitted != null ? admitted["op_id"] : "",
            ["verb"] = admitted != null ? ((D)admitted["admission"]!)["verb"] : "",
            ["resource"] = admitted != null ? ((D)admitted["admission"]!)["resource"] : Clip256(method + " " + url),
            ["params_digest"] = admitted != null ? ((D)admitted["admission"]!)["params_digest"] : "",
        };
        _log.Append(_cls, new D { ["kind"] = "egress", ["subject"] = sub, ["outcome"] = outcome, ["reason"] = reason });
    }

    static string Clip256(string s) => s.Length <= 256 ? s : s[..256];

    // ---- wire ----
    sealed record Req(string Method, string Target, Dictionary<string, List<string>> Headers, byte[] Leftover);

    static async Task<Req?> ReadRequest(Stream st, CancellationToken ct)
    {
        var buf = new byte[MaxHeaderBytes];
        var n = 0;
        var end = -1;
        while (end < 0)
        {
            if (n == buf.Length) return null;
            var r = await st.ReadAsync(buf.AsMemory(n), ct).ConfigureAwait(false);
            if (r == 0) return null;
            n += r;
            for (var i = Math.Max(0, n - r - 3); i + 3 < n; i++)
                if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') { end = i; break; }
        }
        var head = Encoding.Latin1.GetString(buf, 0, end);
        var lines = head.Split("\r\n");
        var rl = lines[0].Split(' ');
        if (rl.Length != 3 || rl[0].Length == 0 || rl[1].Length == 0 || !rl[2].StartsWith("HTTP/1.", StringComparison.Ordinal)) return null;
        var headers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        for (var i = 1; i < lines.Length; i++)
        {
            var ln = lines[i];
            var c = ln.IndexOf(':');
            if (c < 1 || ln[0] == ' ' || ln[0] == '\t') return null; // no obsolete line folding, no header without a name
            var name = ln[..c].ToLowerInvariant();
            if (name.Any(ch => ch <= ' ' || ch == 127)) return null;
            if (!headers.TryGetValue(name, out var l)) headers[name] = l = new List<string>();
            l.Add(ln[(c + 1)..].Trim(' ', '\t'));
        }
        var left = new byte[n - (end + 4)];
        Array.Copy(buf, end + 4, left, 0, left.Length);
        return new Req(rl[0], rl[1], headers, left);
    }

    /// <summary>The whole request body, or null for a malformed framing; <paramref name="tooBig"/> when it exceeds the cap.</summary>
    async Task<byte[]?> ReadBody(Stream st, Req req, CancellationToken ct, Action<bool> tooBig)
    {
        var te = req.Headers.GetValueOrDefault("transfer-encoding");
        var cl = req.Headers.GetValueOrDefault("content-length");
        if (te != null && cl != null) return null; // request smuggling shape
        var carry = new MemoryStream(req.Leftover);
        async Task<int> Read(byte[] b, int off, int len)
        {
            var got = carry.Read(b, off, len);
            return got > 0 ? got : await st.ReadAsync(b.AsMemory(off, len), ct).ConfigureAwait(false);
        }
        async Task<byte[]?> Exactly(int count)
        {
            var b = new byte[count];
            for (var o = 0; o < count;)
            {
                var r = await Read(b, o, count - o).ConfigureAwait(false);
                if (r == 0) return null;
                o += r;
            }
            return b;
        }
        async Task<string?> Line()
        {
            var sb = new StringBuilder();
            var one = new byte[1];
            while (sb.Length < 1024)
            {
                if (await Read(one, 0, 1).ConfigureAwait(false) == 0) return null;
                if (one[0] == '\n') return sb.ToString().TrimEnd('\r');
                sb.Append((char)one[0]);
            }
            return null;
        }
        if (te != null)
        {
            if (te.Count != 1 || !te[0].Equals("chunked", StringComparison.OrdinalIgnoreCase)) return null;
            var all = new MemoryStream();
            for (; ; )
            {
                var size = await Line().ConfigureAwait(false);
                if (size == null) return null;
                var semi = size.IndexOf(';');
                if (semi >= 0) size = size[..semi];
                if (size.Length == 0 || size.Length > 8 || !int.TryParse(size, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var len) || len < 0) return null;
                if (len == 0)
                {
                    for (string? t; (t = await Line().ConfigureAwait(false)) != "";) if (t == null) return null; // trailers are dropped
                    return all.ToArray();
                }
                if (all.Length + len > _maxBody) { tooBig(true); return null; }
                var chunk = await Exactly(len).ConfigureAwait(false);
                if (chunk == null || await Line().ConfigureAwait(false) != "") return null;
                all.Write(chunk, 0, chunk.Length);
            }
        }
        if (cl == null) return Array.Empty<byte>();
        if (cl.Count != 1 || cl[0].Length == 0 || cl[0].Length > 12 || !cl[0].All(char.IsAsciiDigit)) return null;
        var want = long.Parse(cl[0], CultureInfo.InvariantCulture);
        if (want > _maxBody) { tooBig(true); return null; }
        return want == 0 ? Array.Empty<byte>() : await Exactly((int)want).ConfigureAwait(false);
    }

    static async Task Respond(Stream st, int status, string reason, string? json = null)
    {
        var body = json == null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(json);
        var h = "HTTP/1.1 " + status.ToString(CultureInfo.InvariantCulture) + " " + reason + "\r\n" + (json != null ? "content-type: application/json\r\n" : "")
            + "content-length: " + body.Length.ToString(CultureInfo.InvariantCulture) + "\r\nconnection: close\r\n\r\n";
        var hb = Encoding.Latin1.GetBytes(h);
        await st.WriteAsync(hb).ConfigureAwait(false);
        if (body.Length > 0) await st.WriteAsync(body).ConfigureAwait(false);
        await st.FlushAsync().ConfigureAwait(false);
    }

    async Task Deny(Stream st, string method, string url, string reason, int status = 403)
    {
        Receipt(method, url, null, "refused", reason);
        await Respond(st, status, status == 413 ? "Payload Too Large" : "Forbidden", JsJson.Stringify(new D { ["error"] = "egress_denied", ["reason"] = reason })).ConfigureAwait(false);
    }

    async Task Handle(TcpClient client)
    {
        using var _c = client;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            cts.CancelAfter(Math.Max(_timeoutMs, 1000) * 3);
            var st = client.GetStream();
            var req = await ReadRequest(st, cts.Token).ConfigureAwait(false);
            if (req == null) { await Respond(st, 400, "Bad Request").ConfigureAwait(false); return; }
            if (req.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase)) await Connect(client, st, req).ConfigureAwait(false);
            else await Forward(st, req, cts.Token).ConfigureAwait(false);
        }
        catch (Exception) { /* the client went away or timed out: nothing more to say to it */ }
    }

    async Task Connect(TcpClient client, Stream st, Req req)
    {
        var target = req.Target;
        var d = _policy.Claim("CONNECT", target);
        if (d.GetValueOrDefault("allow") is not true)
        {
            Receipt("CONNECT", target, null, "refused", (string)d["reason"]!);
            await st.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n")).ConfigureAwait(false);
            return;
        }
        var colon = target.LastIndexOf(':');
        var host = target[..colon];
        if (host.Length > 1 && host[0] == '[' && host[^1] == ']') host = host[1..^1];
        var port = int.Parse(target[(colon + 1)..], CultureInfo.InvariantCulture);
        if (!_allowPrivate && IsPrivateIfLiteral(host))
        {
            Receipt("CONNECT", target, d, "error", "upstream:EACCES");
            await st.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")).ConfigureAwait(false);
            return;
        }
        Socket up;
        try
        {
            using var cts = new CancellationTokenSource(_timeoutMs);
            up = await ConnectTo(host, port, cts.Token).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Receipt("CONNECT", target, d, "error", Clip64("upstream:" + ErrCode(e)));
            await st.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")).ConfigureAwait(false);
            return;
        }
        using var upstream = up;
        using var us = new NetworkStream(up, false);
        Receipt("CONNECT", target, d, "ok", "tunnel");
        await st.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n")).ConfigureAwait(false);
        if (req.Leftover.Length > 0) await us.WriteAsync(req.Leftover).ConfigureAwait(false);
        var a = st.CopyToAsync(us, _stop.Token);
        var b = us.CopyToAsync(st, _stop.Token);
        await Task.WhenAny(a, b).ConfigureAwait(false);
        try { up.Shutdown(SocketShutdown.Both); } catch (Exception) { /* already closed */ }
        client.Close();
    }

    static string Clip64(string s) => s.Length <= 64 ? s : s[..64];

    async Task Forward(Stream st, Req req, CancellationToken ct)
    {
        var big = false;
        var body = await ReadBody(st, req, ct, b => big = b).ConfigureAwait(false);
        if (big) { await Deny(st, req.Method, req.Target, "body_too_large", 413).ConfigureAwait(false); return; }
        if (body == null) { await Respond(st, 400, "Bad Request").ConfigureAwait(false); return; }
        var url = req.Target;
        var d = _policy.Claim(req.Method, url, body);
        if (d.GetValueOrDefault("allow") is not true) { await Deny(st, req.Method, url, (string)d["reason"]!).ConfigureAwait(false); return; }
        // the policy matched the WHATWG parse of the URL: forward exactly that parse
        var u = EgressUrl.Parse(url)!;
        var host = u.Host.Length > 1 && u.Host[0] == '[' && u.Host[^1] == ']' ? u.Host[1..^1] : u.Host;
        // an IP literal never reaches the resolver, so the private-address guard runs here too
        if (!_allowPrivate && IsPrivateIfLiteral(host))
        {
            Receipt(req.Method, url, d, "error", "upstream:EACCES");
            await Respond(st, 502, "Bad Gateway").ConfigureAwait(false);
            return;
        }
        var port = u.Port >= 0 ? u.Port : u.Scheme == "http" ? 80 : 443;
        var netHost = host.Contains(':') ? "[" + host + "]" : host;
        var uri = new Uri(u.Scheme + "://" + netHost + ":" + port.ToString(CultureInfo.InvariantCulture) + u.Path + (u.Query.Length > 0 ? "?" + u.Query : ""));
        using var msg = new HttpRequestMessage(new HttpMethod(req.Method.ToUpperInvariant()), uri);
        ByteArrayContent? content = body.Length > 0 || req.Method.ToUpperInvariant() is "POST" or "PUT" or "PATCH" ? new ByteArrayContent(body) : null;
        if (content != null) msg.Content = content;
        foreach (var (name, vals) in req.Headers)
        {
            if (Hop.Contains(name) || name == "content-length") continue;
            foreach (var v in vals)
                if (!msg.Headers.TryAddWithoutValidation(name, v)) content?.Headers.TryAddWithoutValidation(name, v);
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeoutMs);
        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false); }
        catch (Exception e)
        {
            Receipt(req.Method, url, d, "error", Clip64("upstream:" + ErrCode(e)));
            await Respond(st, 502, "Bad Gateway").ConfigureAwait(false);
            return;
        }
        using (resp)
        {
            var sb = new StringBuilder();
            sb.Append("HTTP/1.1 ").Append(((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture)).Append(' ').Append(resp.ReasonPhrase ?? "").Append("\r\n");
            foreach (var h in resp.Headers.Concat(resp.Content.Headers))
            {
                var name = h.Key.ToLowerInvariant();
                if (Hop.Contains(name)) continue;
                foreach (var v in h.Value) sb.Append(name).Append(": ").Append(v.Replace("\r", "").Replace("\n", "")).Append("\r\n");
            }
            sb.Append("connection: close\r\n\r\n");
            await st.WriteAsync(Encoding.Latin1.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
            try
            {
                using var bs = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                var buf = new byte[16_384];
                for (; ; )
                {
                    cts.CancelAfter(_timeoutMs); // an idle timeout, like the socket timeout of the reference
                    var r = await bs.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                    if (r == 0) break;
                    await st.WriteAsync(buf.AsMemory(0, r), ct).ConfigureAwait(false);
                }
                await st.FlushAsync(ct).ConfigureAwait(false);
                Receipt(req.Method, url, d, "ok", "status:" + ((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture));
            }
            catch (Exception e)
            {
                Receipt(req.Method, url, d, "error", Clip64("upstream:" + ErrCode(e)));
            }
        }
    }
}
