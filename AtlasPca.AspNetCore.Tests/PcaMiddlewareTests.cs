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
            SignatureOnly = true,
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

    // R6-01 PoC: body mode parsed the {"pcactn":...} envelope leniently, so a duplicate key collapsed last-wins
    // BEFORE verification ("dup-aud-first-evil": a leading "aud":"evil" was dropped and the request allowed), while
    // the rewound body still carried the first value for a first-wins downstream parser. Body mode must use the
    // same strict profile as header mode: duplicate keys at any depth are refused.
    static async Task<(bool NextRan, int Status)> RunBody(Fixture f, string envelope)
    {
        bool nextRan = false;
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));
        var ctx = NewContext();
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(envelope));
        ctx.Request.ContentType = "application/json";
        await mw.InvokeAsync(ctx);
        return (nextRan, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Body_DuplicateAudFirstEvil_IsDenied()
    {
        var f = LoadValid();
        Assert.StartsWith("{", f.Json);
        var evil = "{\"aud\":\"evil\"," + f.Json.Substring(1);
        var (nextRan, status) = await RunBody(f, "{\"pcactn\":" + evil + "}");
        Assert.False(nextRan, "a PCActn with a duplicate 'aud' must not be verified (last-wins) and allowed");
        Assert.Equal(StatusCodes.Status401Unauthorized, status);
    }

    [Fact]
    public async Task Body_DuplicateCounterFirst_IsDenied()
    {
        var f = LoadValid();
        var evil = "{\"counter\":999," + f.Json.Substring(1);
        var (nextRan, _) = await RunBody(f, "{\"pcactn\":" + evil + "}");
        Assert.False(nextRan);
    }

    [Fact]
    public async Task Body_DuplicateEnvelopeKey_IsDenied()
    {
        var f = LoadValid();
        var (nextRan, status) = await RunBody(f, "{\"pcactn\":{},\"pcactn\":" + f.Json + "}");
        Assert.False(nextRan, "a duplicate 'pcactn' envelope key must be refused, not resolved last-wins");
        Assert.Equal(StatusCodes.Status401Unauthorized, status);
    }

    [Fact]
    public async Task Body_DuplicateNestedKey_IsDenied()
    {
        var f = LoadValid();
        // duplicate inside a nested object of the PCActn (action.verb)
        var m = System.Text.RegularExpressions.Regex.Match(f.Json, "\"action\"\\s*:\\s*\\{");
        Assert.True(m.Success);
        var at = m.Index + m.Length;
        var evil = f.Json.Substring(0, at) + "\"verb\":\"delete\"," + f.Json.Substring(at);
        var (nextRan, _) = await RunBody(f, "{\"pcactn\":" + evil + "}");
        Assert.False(nextRan);
    }

    // 0.4.1: the PCA-Action header is STRICT unpadded base64url of well-formed UTF-8 (primitives.pca_header). Every invalid
    // value is the 401 "not canonical base64url" path; invalid UTF-8 used to be replaced with U+FFFD and reach the JSON parser.
    [Fact]
    public async Task Header_StrictBase64UrlAndUtf8_PcaHeaderVectors()
    {
        var f = LoadValid();
        var prim = (Dictionary<string, object?>)Doc["primitives"]!;
        int ran = 0;
        foreach (var x in (List<object?>)prim["pca_header"]!)
        {
            var e = (Dictionary<string, object?>)x!;
            var input = (string)e["input"]!;
            if (input.Length == 0) continue; // an empty header is "no header" (body mode)
            bool nextRan = false;
            var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));
            var ctx = NewContext();
            ctx.Request.Headers["PCA-Action"] = input;
            await mw.InvokeAsync(ctx);
            var challenge = ReadBody(ctx);
            bool refusedAsB64 = ctx.Response.StatusCode == StatusCodes.Status401Unauthorized && challenge.Contains("is not canonical base64url");
            Assert.False(nextRan, (string)e["name"]!);
            Assert.True((bool)e["valid"]! ? !refusedAsB64 : refusedAsB64, $"{e["name"]}: {ctx.Response.StatusCode} {challenge}");
            ran++;
        }
        Assert.True(ran >= 26, $"ran {ran}");
    }

    [Fact]
    public async Task Header_InvalidUtf8InsideAString_IsRefusedAsUndecodable()
    {
        var f = LoadValid();
        // the genuine PCActn with an overlong-encoded byte pair spliced into its "aud" string: lenient decoding turned it into
        // U+FFFD U+FFFD (valid JSON, a 403 from the verifier); strict decoding refuses the header itself.
        var bytes = Encoding.UTF8.GetBytes(f.Json).ToList();
        int at = f.Json.IndexOf("\"" + f.Aud + "\"", System.StringComparison.Ordinal) + 1; // inside the (ASCII) aud string
        Assert.True(at > 0);
        bytes.InsertRange(at, new byte[] { 0xC0, 0xAF });
        var mw = new PcaMiddleware(_ => Task.CompletedTask, OptionsFor(f));
        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(bytes.ToArray());
        await mw.InvokeAsync(ctx);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Contains("is not canonical base64url", ReadBody(ctx));
    }

    [Theory]
    [InlineData("   ")]
    [InlineData(" {0}")]
    [InlineData("{0} ")]
    [InlineData("{0}=")]
    public async Task Header_WhitespaceOrPadding_Returns401(string template)
    {
        var f = LoadValid();
        bool nextRan = false;
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, OptionsFor(f));
        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = template.Replace("{0}", HeaderFor(f.Json));
        await mw.InvokeAsync(ctx);
        Assert.False(nextRan);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Contains("is not canonical base64url", ReadBody(ctx));
    }

    // 0.4.2 audit: the denial reason (request-derived text) never reaches the WWW-Authenticate header; only realm + code.
    [Fact]
    public async Task Challenge_CarriesNoDescription()
    {
        var f = LoadValid();
        var mw = new PcaMiddleware(_ => Task.CompletedTask, OptionsFor(f, audienceOverride: "rs-not-this-one"));
        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = HeaderFor(f.Json);
        await mw.InvokeAsync(ctx);
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Equal("PCA realm=\"pca\", error=\"access_denied\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
        Assert.Contains("audience", ReadBody(ctx));
    }

    // 0.4.2 audit: a throwing grant resolver fails closed (403), never an unhandled exception (500).
    [Fact]
    public async Task ThrowingResolver_FailsClosed403()
    {
        var f = LoadValid();
        bool nextRan = false;
        var options = OptionsFor(f, resolverOverride: _ => throw new System.InvalidOperationException("db down"));
        var mw = new PcaMiddleware(_ => { nextRan = true; return Task.CompletedTask; }, options);
        var ctx = NewContext();
        ctx.Request.Headers["PCA-Action"] = HeaderFor(f.Json);
        await mw.InvokeAsync(ctx);
        Assert.False(nextRan);
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Contains("grant resolution failed", ReadBody(ctx));
    }

    // 0.4.2 audit: invalid UTF-8 in the body is REJECTED (strict decoder, as the header path), never replaced by U+FFFD.
    [Fact]
    public async Task Body_InvalidUtf8_IsRefused401()
    {
        var f = LoadValid();
        string? seen = null;
        var options = OptionsFor(f, resolverOverride: r => { seen = r; return Task.FromResult<Dictionary<string, object?>?>(null); });
        var mw = new PcaMiddleware(_ => Task.CompletedTask, options);
        var ctx = NewContext();
        var bytes = Encoding.UTF8.GetBytes("{\"pcactn\":{\"grant_ref\":\"__\"}}");
        bytes[24] = 0xFF; bytes[25] = 0xFE;
        ctx.Request.Body = new MemoryStream(bytes);
        ctx.Request.ContentType = "application/json";
        await mw.InvokeAsync(ctx);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Contains("not valid UTF-8", ReadBody(ctx));
        Assert.Null(seen);
    }
}

public class PcaMiddlewareDeepNestingTests
{
    static string ReadBodyOf(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body).ReadToEnd();
    }

    // PoC: an attacker POSTs a deeply nested body. The envelope parse must reject it BEFORE recursing; run on a tiny stack so a
    // regression (unbounded or 4096-deep recursion) kills the test host instead of passing by luck on an 8 MB stack.
    [Fact]
    public void DeeplyNestedBody_IsRejectedWithoutStackOverflow()
    {
        int status = 0;
        var t = new System.Threading.Thread(() =>
        {
            var ctx = new DefaultHttpContext();
            ctx.Response.Body = new MemoryStream();
            var body = "{\"pcactn\":" + new string('[', 3000) + new string(']', 3000) + "}";
            ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
            ctx.Request.ContentType = "application/json";
            var mw = new PcaMiddleware(_ => Task.CompletedTask, new PcaOptions { Audience = "a", Clock = () => 0, GrantResolver = _ => Task.FromResult<Dictionary<string, object?>?>(null) });
            mw.InvokeAsync(ctx).GetAwaiter().GetResult();
            status = ctx.Response.StatusCode;
        }, 256 * 1024);
        t.Start();
        t.Join();
        Assert.Equal(StatusCodes.Status401Unauthorized, status);
    }

    // Parity with the TS reference (require-pca.ts defaultExtract: strictParse of the WHOLE body, MAX_JSON_DEPTH = 32) and the
    // Go / Python middleware: the envelope's own object counts, so an envelope of total depth 33 is refused at parse time and
    // one of total depth 32 gets past the parse (and is then refused only because [[...]] is not a PCActn object).
    [Theory]
    [InlineData(32, "PCActn must be a JSON object.")]
    [InlineData(33, "The request body is not valid JSON: strict JSON: nesting too deep")]
    public async Task BodyEnvelope_DepthCapCountsTheEnvelope(int totalDepth, string expected)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        var inner = totalDepth - 1;
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"pcactn\":" + new string('[', inner) + new string(']', inner) + "}"));
        ctx.Request.ContentType = "application/json";
        var mw = new PcaMiddleware(_ => Task.CompletedTask, new PcaOptions { Audience = "a", Clock = () => 0, GrantResolver = _ => Task.FromResult<Dictionary<string, object?>?>(null) });
        await mw.InvokeAsync(ctx);
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Contains("\"error_description\":\"" + expected, ReadBodyOf(ctx));
    }
}
