using System.Net;
using System.Net.Sockets;
using System.Text;
using AtlasPca.Sandbox;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using S = AtlasPca.Sandbox.PcaSandbox;

namespace AtlasPca.Corpus.Tests;

// The egress proxy (S.CreateEgressProxy): a request matching an admitted template is forwarded, everything else answers 403 and is receipted,
// a private upstream is refused (502) unless AllowPrivate, a body over the cap answers 413, and a CONNECT is tunnelled only to an admitted host:port.
public class SandboxEgressProxyTests
{
    static AuthorizeResult Bound(string verb, string resource) => new()
    {
        Allow = true, Status = 200,
        Operation = new AuthorizedOperation(verb, resource, Pca.HashCanonical(new D()), "op-1"),
    };

    /// <summary>A one-shot fake upstream: records the request text and answers a fixed 200 body.</summary>
    sealed class Upstream : IDisposable
    {
        readonly TcpListener _l = new(IPAddress.Loopback, 0);
        public readonly List<string> Seen = new();
        public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;

        public Upstream()
        {
            _l.Start();
            _ = Task.Run(async () =>
            {
                for (; ; )
                {
                    TcpClient c;
                    try { c = await _l.AcceptTcpClientAsync(); } catch (Exception) { return; }
                    _ = Task.Run(async () =>
                    {
                        using var _c = c;
                        var s = c.GetStream();
                        var buf = new byte[8192];
                        var n = await s.ReadAsync(buf);
                        lock (Seen) Seen.Add(Encoding.Latin1.GetString(buf, 0, n));
                        await s.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-up: 1\r\nconnection: close\r\n\r\nhello"));
                    });
                }
            });
        }

        public void Dispose() => _l.Stop();
    }

    static async Task<string> Raw(int proxyPort, string request)
    {
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, proxyPort);
        var s = c.GetStream();
        await s.WriteAsync(Encoding.Latin1.GetBytes(request));
        var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        return Encoding.Latin1.GetString(ms.ToArray());
    }

    static (EgressProxy Proxy, S.EgressPolicy Policy, S.ReceiptLog Log) Rig(bool allowPrivate = true, int maxBody = 1 << 20)
    {
        var policy = new S.EgressPolicy();
        var log = new S.ReceiptLog();
        var proxy = S.CreateEgressProxy(new EgressProxyOptions { Policy = policy, Log = log, AllowPrivate = allowPrivate, MaxBodyBytes = maxBody });
        proxy.Start();
        return (proxy, policy, log);
    }

    static D Tpl(int port, string path = "/ok", string method = "GET") => new() { ["method"] = method, ["scheme"] = "http", ["host"] = "127.0.0.1", ["port"] = (long)port, ["path"] = path };

    [Fact]
    public async Task AnAdmittedRequestIsForwardedAndReceipted()
    {
        using var up = new Upstream();
        var (proxy, policy, log) = Rig();
        using var _p = proxy;
        policy.Admit(Bound("net.get", "api"), new Operation("net.get", "api", new D()), _ => Tpl(up.Port));
        var res = await Raw(proxy.Port, $"GET http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\nhost: 127.0.0.1\r\nx-keep: 1\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 200", res);
        Assert.EndsWith("hello", res);
        Assert.Contains("x-up: 1", res);
        Assert.Contains("x-keep: 1", up.Seen[0]);
        await Task.Delay(100);
        var r = log.Entries.Last();
        Assert.Equal("egress", r["kind"]);
        Assert.Equal("ok", r["outcome"]);
        Assert.Equal("status:200", r["reason"]);
        Assert.Equal("net.get", ((D)r["subject"]!)["verb"]);
        // the single use is spent: the same request is now refused
        var again = await Raw(proxy.Port, $"GET http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 403", again);
        Assert.Contains("spent", again);
    }

    [Fact]
    public async Task AnUnadmittedRequestIsRefusedAndReceiptedAndNeverReachesTheUpstream()
    {
        using var up = new Upstream();
        var (proxy, policy, log) = Rig();
        using var _p = proxy;
        policy.Admit(Bound("net.get", "api"), new Operation("net.get", "api", new D()), _ => Tpl(up.Port));
        var res = await Raw(proxy.Port, $"GET http://127.0.0.1:{up.Port}/other HTTP/1.1\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 403", res);
        Assert.Contains("egress_denied", res);
        Assert.Empty(up.Seen);
        Assert.Equal("refused", log.Entries.Last()["outcome"]);
        Assert.StartsWith("HTTP/1.1 403", await Raw(proxy.Port, "GET /relative HTTP/1.1\r\n\r\n"));
        Assert.StartsWith("HTTP/1.1 400", await Raw(proxy.Port, "garbage\r\n\r\n"));
    }

    [Fact]
    public async Task APrivateUpstreamIsRefusedUnlessAllowed()
    {
        using var up = new Upstream();
        var (proxy, policy, log) = Rig(allowPrivate: false);
        using var _p = proxy;
        policy.Admit(Bound("net.get", "api"), new Operation("net.get", "api", new D()), _ => Tpl(up.Port));
        var res = await Raw(proxy.Port, $"GET http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 502", res);
        Assert.Empty(up.Seen);
        Assert.Equal("upstream:EACCES", log.Entries.Last()["reason"]);
    }

    [Fact]
    public async Task ABodyOverTheCapAnswers413AndAnUnboundBodyIsRefused()
    {
        using var up = new Upstream();
        var (proxy, policy, _) = Rig(maxBody: 8);
        using var _p = proxy;
        policy.Admit(Bound("net.post", "api"), new Operation("net.post", "api", new D()), _ => Tpl(up.Port, "/ok", "POST"));
        var big = await Raw(proxy.Port, $"POST http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\ncontent-length: 9\r\n\r\n123456789");
        Assert.StartsWith("HTTP/1.1 413", big);
        // a body the template does not hash is refused
        var small = await Raw(proxy.Port, $"POST http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\ncontent-length: 3\r\n\r\nabc");
        Assert.StartsWith("HTTP/1.1 403", small);
        Assert.Contains("body_mismatch", small);
        Assert.Empty(up.Seen);
        // content-length and transfer-encoding together is a smuggling shape
        Assert.StartsWith("HTTP/1.1 400", await Raw(proxy.Port, $"POST http://127.0.0.1:{up.Port}/ok HTTP/1.1\r\ncontent-length: 3\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"));
    }

    [Fact]
    public async Task AConnectIsTunnelledOnlyToAnAdmittedHostAndPort()
    {
        using var up = new Upstream();
        var (proxy, policy, log) = Rig();
        using var _p = proxy;
        var denied = await Raw(proxy.Port, $"CONNECT 127.0.0.1:{up.Port} HTTP/1.1\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 403", denied);
        policy.Admit(Bound("net.tunnel", "api"), new Operation("net.tunnel", "api", new D()), _ => new D { ["method"] = "CONNECT", ["scheme"] = "https", ["host"] = "127.0.0.1", ["port"] = (long)up.Port, ["path"] = "/", ["tunnel"] = true });
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, proxy.Port);
        var s = c.GetStream();
        await s.WriteAsync(Encoding.Latin1.GetBytes($"CONNECT 127.0.0.1:{up.Port} HTTP/1.1\r\n\r\nping"));
        var buf = new byte[512];
        var got = new StringBuilder();
        while (!got.ToString().EndsWith("hello"))
        {
            var n = await s.ReadAsync(buf);
            if (n == 0) break;
            got.Append(Encoding.Latin1.GetString(buf, 0, n));
        }
        Assert.StartsWith("HTTP/1.1 200 Connection Established", got.ToString());
        Assert.Contains("hello", got.ToString());
        Assert.Equal("tunnel", log.Entries.First(e => (string)e["outcome"]! == "ok")["reason"]);
    }
}
