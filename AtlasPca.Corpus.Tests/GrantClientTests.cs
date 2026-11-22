using System.Net;
using System.Text;
using AtlasPca;
using AtlasPca.Grants;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class GrantClientTests
{
    sealed class Stub(Func<HttpRequestMessage, string?, HttpResponseMessage> fn) : HttpMessageHandler
    {
        public readonly List<(HttpMethod Method, string Url, string? Body, string? Fresh)> Seen = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            var body = r.Content == null ? null : await r.Content.ReadAsStringAsync(ct);
            Seen.Add((r.Method, r.RequestUri!.AbsoluteUri, body, r.Headers.TryGetValues("pca-fresh-at", out var f) ? f.First() : null));
            return fn(r, body);
        }
    }

    static HttpResponseMessage Json(HttpStatusCode c, string body, string? fresh = null)
    {
        var m = new HttpResponseMessage(c) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (fresh != null) m.Headers.TryAddWithoutValidation("pca-fresh-at", fresh);
        return m;
    }

    static string Tok(long epoch) => $"{{\"revocation_epoch\":{epoch},\"policy_revision\":1,\"ledger_tree_size\":1,\"budget_version\":1}}";

    [Fact]
    public async Task RoutesAndEncodesPaths()
    {
        var h = new Stub((_, _) => Json(HttpStatusCode.OK, "{\"ok\":true}"));
        var c = new GrantClient("https://as.example/", new HttpClient(h));
        await c.Inspect("a/b c");
        await c.Revoke("g1", "agent", "SIG");
        await c.Revoke("g2");
        await c.List(new Dictionary<string, string?> { ["principal"] = "p q", ["limit"] = null });
        Assert.Equal("https://as.example/pca/grants/a%2Fb%20c", h.Seen[0].Url);
        Assert.Equal(HttpMethod.Delete, h.Seen[1].Method);
        Assert.Equal("https://as.example/pca/grants/g1?scope=agent", h.Seen[1].Url);
        Assert.Equal("{\"sig\":\"SIG\"}", h.Seen[1].Body);
        Assert.Null(h.Seen[2].Body);
        Assert.EndsWith("?scope=grant", h.Seen[2].Url);
        Assert.EndsWith("/pca/grants?principal=p%20q", h.Seen[3].Url);
    }

    [Fact]
    public async Task ErrorBodiesBecomeTypedErrors()
    {
        var c = new GrantClient("https://as.example", new HttpClient(new Stub((_, _) => Json(HttpStatusCode.Conflict, "{\"error\":\"conflict\",\"message\":\"stale\"}"))));
        var e = await Assert.ThrowsAsync<GrantApiException>(() => c.Inspect("g"));
        Assert.Equal((409, "conflict", "stale"), (e.Status, e.Code, e.Message));
    }

    [Fact]
    public async Task FreshTokenIsMonotoneAndResent()
    {
        var toks = new Queue<string>(new[] { Tok(5), Tok(3), Tok(9) });
        var h = new Stub((_, _) => Json(HttpStatusCode.OK, "{}", toks.Dequeue()));
        var c = new GrantClient("https://as.example", new HttpClient(h));
        await c.Inspect("a");
        await c.Inspect("b");
        Assert.Equal(5, (long)IntentJs.NumOf(c.FreshAt!["revocation_epoch"])!.Value);
        await c.Inspect("c");
        Assert.Equal(9, (long)IntentJs.NumOf(c.FreshAt!["revocation_epoch"])!.Value);
        Assert.Null(h.Seen[0].Fresh);
        Assert.Contains("\"revocation_epoch\":5", h.Seen[1].Fresh);
    }

    [Fact]
    public async Task AnUnverifiedTokenIsIgnoredWhenASignerIsPinned()
    {
        var c = new GrantClient("https://as.example", new HttpClient(new Stub((_, _) => Json(HttpStatusCode.OK, "{}", Tok(5)))), freshSigner: "pinned");
        await c.Inspect("a");
        Assert.Null(c.FreshAt);
    }

    [Fact]
    public void TheInMemoryLeaseStorePassesTheConformanceKit()
    {
        var passed = LeaseStoreConformance.Run(new LeaseStoreKit(() => new MemoryAtomicKv(), kv => kv));
        Assert.Equal(7, passed.Count);
    }
}
