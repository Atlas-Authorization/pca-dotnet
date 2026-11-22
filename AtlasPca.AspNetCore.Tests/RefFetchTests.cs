using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AtlasPca.AspNetCore;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.AspNetCore.Tests;

/// <summary>Replays the reference Web Fetch guard corpus (construction guards and pre-verification refusals) against <see cref="PcaFetchHandler"/>.</summary>
public class RefFetchTests
{
    const string Aud = "rs_fetch";

    static JsonElement Cases()
    {
        using var s = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "test-data", "ref-fetch.json.gz")), CompressionMode.Decompress);
        using var r = new StreamReader(s, new UTF8Encoding(false));
        return JsonDocument.Parse(r.ReadToEnd()).RootElement.GetProperty("cases").Clone();
    }

    sealed class Inner : HttpMessageHandler
    {
        public bool Ran;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken ct)
        {
            Ran = true;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"ok\":true}") });
        }
    }

    static PcaOptions Opts(string kind, bool resolveThrows) => new()
    {
        Audience = kind == "noaudience" ? "" : Aud,
        GrantResolver = _ => resolveThrows ? throw new InvalidOperationException("store down") : Task.FromResult<JD?>(null),
        SignatureOnly = kind != "nooperation",
    };

    [Fact]
    public async Task Corpus()
    {
        int n = 0;
        foreach (var c in Cases().EnumerateArray())
        {
            var fn = c.GetProperty("fn").GetString();
            var name = c.GetProperty("name").GetString();
            var args = c.GetProperty("args")[0];
            var want = c.GetProperty("out");
            n++;
            if (fn == "constructScenario")
            {
                var kind = args.GetString()!;
                if (want.TryGetProperty("$throws", out _))
                    Assert.Throws<InvalidOperationException>(() => new PcaFetchHandler(Opts(kind, false), new Inner()));
                else Assert.NotNull(new PcaFetchHandler(Opts(kind, false), new Inner()));
                continue;
            }
            var inner = new Inner();
            var client = new HttpClient(new PcaFetchHandler(Opts("ok", args.GetProperty("resolve").GetString() == "throws"), inner));
            var req = new HttpRequestMessage(HttpMethod.Post, "http://localhost/refunds");
            if (args.TryGetProperty("headers", out var hs))
                foreach (var h in hs.EnumerateObject()) req.Headers.TryAddWithoutValidation(h.Name, h.Value.GetString());
            if (args.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String)
                req.Content = new StringContent(b.GetString()!, Encoding.UTF8, "application/json");
            var res = await client.SendAsync(req);
            var text = await res.Content.ReadAsStringAsync();
            JsonElement? body = null;
            try { var e = JsonDocument.Parse(text).RootElement; if (e.ValueKind == JsonValueKind.Object) body = e; } catch (JsonException) { }
            var status = (int)res.StatusCode;
            Assert.True(want.GetProperty("status").GetInt32() == status, name + " status " + status);
            Assert.True(want.GetProperty("handlerRan").GetBoolean() == inner.Ran, name + " handlerRan");
            Assert.Equal("application/json", res.Content.Headers.ContentType?.MediaType);
            Assert.Equal(want.GetProperty("decision").GetString(), body?.GetProperty("decision").GetString());
            var keys = body!.Value.EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray();
            Assert.Equal(want.GetProperty("bodyKeys").EnumerateArray().Select(x => x.GetString()!).ToArray(), keys);
            Assert.Equal(JsonValueKind.String, body.Value.GetProperty("error").ValueKind);
            if (status == 401)
                Assert.True(res.Headers.TryGetValues("WWW-Authenticate", out var www) && www.First().StartsWith("PCA realm=\"", StringComparison.Ordinal), name + " challenge");
        }
        Assert.Equal(59, n);
    }
}
