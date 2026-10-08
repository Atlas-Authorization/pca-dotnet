using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AtlasPca.AspNetCore.Tests;

// Mirrors the Conformance runner's style: load packages/pca/conformance/vectors.json with the SDK's own
// JSON parser, and drive the middleware with a genuinely-signed valid PCActn vector over a DefaultHttpContext.
public class PcaMiddlewareTests
{
    const string ValidVector = "valid-raw-json-format-insensitive"; // allow=true, carries raw signed pcactn_json

    static readonly Dictionary<string, object?> Doc =
        (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(FindVectors()))!;

    static string FindVectors()
    {
        var dir = new DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "packages", "pca", "conformance", "vectors.json");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("conformance vectors.json not found by climbing from " + System.AppContext.BaseDirectory);
    }

    static Dictionary<string, object?> Vector(string name) =>
        ((List<object?>)Doc["vectors"]!)
        .Cast<Dictionary<string, object?>>()
        .First(v => (string)v["name"]! == name);

    sealed record Fixture(string Json, Dictionary<string, object?> Grant, string GrantRef, long Now, string Aud);

    static Fixture LoadValid()
    {
        var v = Vector(ValidVector);
        var json = (string)v["pcactn_json"]!;
        var grant = (Dictionary<string, object?>)v["grant"]!;
        var cctx = (Dictionary<string, object?>)v["context"]!;
        long now = long.Parse(((Num)cctx["now"]!).Raw, CultureInfo.InvariantCulture);
        string aud = (string)cctx["aud"]!;
        string grantRef = (string)grant["id"]!; // grant_ref == the grant's cap hash (its id)
        return new Fixture(json, grant, grantRef, now, aud);
    }

    static PcaOptions OptionsFor(Fixture f, string? audienceOverride = null,
        System.Func<string, Task<Dictionary<string, object?>?>>? resolverOverride = null) => new()
        {
            Audience = audienceOverride ?? f.Aud,
            Clock = () => f.Now,
            GrantResolver = resolverOverride
                ?? (r => Task.FromResult<Dictionary<string, object?>?>(r == f.GrantRef ? f.Grant : null)),
        };

    static DefaultHttpContext NewContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream(); // capture the challenge body
        return ctx;
    }

    static string HeaderFor(string json) => Pca.B64u(Encoding.UTF8.GetBytes(json)); // base64url, no padding

    static string ReadBody(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body).ReadToEnd();
    }

    [Fact]
    public async Task ValidHeader_RunsNext_AndSetsItems()
    {
        var f = LoadValid();
        bool nextRan = false;
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));

        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = HeaderFor(f.Json);

        await mw.InvokeAsync(ctx);

        Assert.True(nextRan, "next middleware should have run");
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        var result = Assert.IsType<PcaAuthResult>(ctx.Items["pca"]);
        Assert.True(result.Verdict.Allow);
        Assert.All(result.Verdict.Checks.Values, Assert.True);
    }

    [Fact]
    public async Task ValidBody_RunsNext_AndSetsItems()
    {
        var f = LoadValid();
        bool nextRan = false;
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));

        var ctx = NewContext();
        var envelope = "{\"pcactn\":" + f.Json + "}";
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(envelope));
        ctx.Request.ContentType = "application/json";

        await mw.InvokeAsync(ctx);

        Assert.True(nextRan, "next middleware should have run");
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.IsType<PcaAuthResult>(ctx.Items["pca"]);
        // body is rewound for downstream
        Assert.Equal(0, ctx.Request.Body.Position);
    }

    [Fact]
    public async Task NoHeader_Returns401_WithChallenge()
    {
        var f = LoadValid();
        bool nextRan = false;
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));

        var ctx = NewContext();
        await mw.InvokeAsync(ctx);

        Assert.False(nextRan);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Null(ctx.Items["pca"]);
        var www = ctx.Response.Headers["WWW-Authenticate"].ToString();
        Assert.StartsWith("PCA realm=\"pca\"", www);
        Assert.Contains("error=\"invalid_request\"", www);
        Assert.Contains("\"error\":\"invalid_request\"", ReadBody(ctx));
    }

    [Fact]
    public async Task UnknownGrant_Returns401()
    {
        var f = LoadValid();
        bool nextRan = false;
        // resolver never finds the grant
        var options = OptionsFor(f, resolverOverride: _ => Task.FromResult<Dictionary<string, object?>?>(null));
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, options);

        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = HeaderFor(f.Json);

        await mw.InvokeAsync(ctx);

        Assert.False(nextRan);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Null(ctx.Items["pca"]);
        Assert.Contains("error=\"invalid_grant\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
    }

    [Fact]
    public async Task WrongAudience_Returns403()
    {
        var f = LoadValid();
        bool nextRan = false;
        var options = OptionsFor(f, audienceOverride: "rs-not-this-one");
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, options);

        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = HeaderFor(f.Json);

        await mw.InvokeAsync(ctx);

        Assert.False(nextRan);
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Null(ctx.Items["pca"]);
        var www = ctx.Response.Headers["WWW-Authenticate"].ToString();
        Assert.Contains("error=\"access_denied\"", www);
        Assert.Contains("audience", ReadBody(ctx)); // the denying reason names the failed audience check
    }
}
