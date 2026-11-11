using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

/// <summary>Kills of the Stryker survivors in the ASP.NET Core project. The strings pinned here are the native wire convention (the same as
/// sdks/go-pca/middleware.go and sdks/php-pca/src/PcaMiddleware.php): <c>WWW-Authenticate: PCA realm="...", error="code"</c> with no
/// reason in it, on 401 and 403 only, and the reason in the JSON body.</summary>
public class PcaMiddlewareKillTests
{
    static readonly string FixText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json"));
    static JD Fix => (JD)Pca.ParseJson(FixText)!;
    static readonly string Aud = System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("audience").GetString()!;
    static readonly long Now = long.Parse(System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("now").GetRawText(), CultureInfo.InvariantCulture);
    static JD Case => ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static JD Grant => (JD)Case["grant"]!;
    static JD Step => (JD)((JL)Case["steps"]!)[0]!;
    static JD Pcactn => (JD)Step["pcactn"]!;
    static Operation Op => new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    static string RecordId => Pca.HashCanonical(Pcactn);
    static readonly string[] Unrecorded = { "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive" };
    const int Max = Pca.MaxArtifactBytes;
    const int Cap = 2 * Pca.MaxArtifactBytes;
    const string G = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw";
    const string P = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo";

    static Task<JD?> Resolve(string r) => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null);
    static string B64(string text) => Pca.B64u(Encoding.UTF8.GetBytes(text));
    static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
    static byte[] WithBom(string text) => new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Utf8(text)).ToArray();
    static string Spaced(string json, int total) => new string(' ', total - json.Length) + json;

    static PcaOptions Core(Action<PcaOptions>? tweak = null)
    {
        var o = new PcaOptions { Audience = Aud, Clock = () => Now, SignatureOnly = true, InsecureSkipPlanRootCheck = true, GrantResolver = Resolve };
        tweak?.Invoke(o);
        return o;
    }

    static PcaOptions Full(Action<PcaAuthorizeOptions>? tweak = null, Action<PcaOptions>? tweakOptions = null)
    {
        var az = new PcaAuthorizeOptions { Plan = "single-step", StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options };
        tweak?.Invoke(az);
        var o = new PcaOptions { Audience = Aud, Clock = () => Now, GrantResolver = Resolve, Authorize = az };
        tweakOptions?.Invoke(o);
        return o;
    }

    static void ProofInHeader(DefaultHttpContext c) => c.Request.Headers["PCA-Action"] = B64(Pca.Canonicalize(Pcactn));
    static void BundleInHeader(DefaultHttpContext c) => c.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
    static void Both(DefaultHttpContext c) { ProofInHeader(c); BundleInHeader(c); }

    static async Task<(DefaultHttpContext Ctx, int Ran)> Run(PcaOptions o, Action<DefaultHttpContext> arrange, RequestDelegate? next = null)
    {
        int ran = 0;
        var mw = new PcaMiddleware(c => { ran++; return next?.Invoke(c) ?? Task.CompletedTask; }, o);
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        arrange(ctx);
        await mw.InvokeAsync(ctx);
        return (ctx, ran);
    }

    static string Text(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body).ReadToEnd();
    }

    static JsonElement Json(HttpContext ctx) => JsonDocument.Parse(Text(ctx)).RootElement;
    static string? Reason(HttpContext ctx) => Json(ctx).GetProperty("error_description").GetString();
    static string? Decision(HttpContext ctx) => Json(ctx).GetProperty("decision").GetString();

    /// <summary>The whole refusal: status, challenge (only on 401 / 403, with no reason in it), content type, error and reason. The body parses as ONE JSON value.</summary>
    static void Refused(HttpContext ctx, int status, string error, string reason, string realm = "pca")
    {
        Assert.Equal(status, ctx.Response.StatusCode);
        if (status is 401 or 403) Assert.Equal($"PCA realm=\"{realm}\", error=\"{error}\", hint=\"send PCA-Action: <base64url PCActn> or JSON body {{pcactn}}\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
        else Assert.False(ctx.Response.Headers.ContainsKey("WWW-Authenticate"));
        Assert.Equal("application/json; charset=utf-8", ctx.Response.ContentType);
        var b = Json(ctx);
        Assert.Equal(error, b.GetProperty("error").GetString());
        Assert.Equal(reason, b.GetProperty("error_description").GetString());
    }

    /// <summary>A body stream that cannot seek (what a real server hands the middleware).</summary>
    sealed class NoSeek : Stream
    {
        readonly MemoryStream _m;
        public NoSeek(byte[] b) { _m = new MemoryStream(b); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _m.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Counts how often a reader rewinds the body: a reader that never ran leaves it at zero.</summary>
    sealed class RewindCounter : MemoryStream
    {
        public int Rewinds;
        public RewindCounter(byte[] b) : base(b) { }
        public override long Position { get => base.Position; set { Rewinds++; base.Position = value; } }
    }

    static RequestDelegate ExpectBody(string text) => async c =>
    {
        c.Request.Body.Position = 0;
        Assert.Equal(text, await new StreamReader(c.Request.Body).ReadToEndAsync());
    };

    // ---------------------------------------------------------------- the PCActn readers

    [Fact]
    public async Task ANonObjectPcactnIsInvalidRequest()
    {
        var (ctx, ran) = await Run(Core(), c => c.Request.Body = new MemoryStream(Utf8("{\"pcactn\":[1]}")));
        Assert.Equal(0, ran);
        Refused(ctx, 401, "invalid_pcactn", "PCActn must be a JSON object.");
    }

    [Theory]
    [InlineData("{\"x\":1}")]
    [InlineData("{\"grant_ref\":1}")]
    [InlineData("{\"grant_ref\":\"\"}")]
    public async Task AGrantRefMustBeANonEmptyString(string json)
    {
        var (ctx, ran) = await Run(Core(), c => c.Request.Headers["PCA-Action"] = B64(json));
        Assert.Equal(0, ran);
        Refused(ctx, 401, "invalid_pcactn", "PCActn is missing a string 'grant_ref'.");
    }

    [Fact]
    public async Task AThrowingResolverIsAccessDenied()
    {
        var (ctx, ran) = await Run(Core(o => o.GrantResolver = _ => throw new InvalidOperationException("down")), ProofInHeader);
        Assert.Equal(0, ran);
        Refused(ctx, 403, "access_denied", "grant resolution failed (fail closed).");
    }

    [Fact]
    public async Task AnUnknownGrantIsInvalidGrant()
    {
        var (ctx, ran) = await Run(Core(o => o.GrantResolver = _ => Task.FromResult<JD?>(null)), ProofInHeader);
        Assert.Equal(0, ran);
        Refused(ctx, 401, "unknown_grant", "No grant is known for this grant_ref.");
    }

    [Fact]
    public async Task AHeaderThatIsNotBase64UrlIsInvalidRequest()
    {
        var (ctx, _) = await Run(Core(o => o.HeaderName = "X-Proof"), c => c.Request.Headers["X-Proof"] = "!!!");
        Refused(ctx, 401, "invalid_pcactn", "The X-Proof header is not canonical base64url.");
    }

    [Fact]
    public async Task TheHeaderSizeBoundIsExact()
    {
        // grant_ref padded to exactly the cap: it parses, and the resolver answers "unknown"
        var at = "{\"grant_ref\":\"" + new string('x', Max - 16) + "\"}";
        Assert.Equal(Max, at.Length);
        var (ok, _) = await Run(Core(), c => c.Request.Headers["PCA-Action"] = B64(at));
        Refused(ok, 401, "unknown_grant", "No grant is known for this grant_ref.");
        var over = "{\"grant_ref\":\"" + new string('x', Max - 15) + "\"}";
        var (big, _) = await Run(Core(), c => c.Request.Headers["PCA-Action"] = B64(over));
        Refused(big, 401, "invalid_pcactn", "The PCA-Action header is not a decodable PCActn: " + Pca.ArtifactSizeReason);
    }

    [Fact]
    public async Task AnUndecodableHeaderNeverFallsBackToTheBody()
    {
        var (ctx, ran) = await Run(Core(), c =>
        {
            c.Request.Headers["PCA-Action"] = B64("{bad");
            c.Request.Body = new MemoryStream(Utf8("{\"pcactn\":" + Pca.Canonicalize(Pcactn) + "}"));
        });
        Assert.Equal(0, ran);
        Assert.Equal(401, ctx.Response.StatusCode);
        Assert.Equal("invalid_pcactn", Json(ctx).GetProperty("error").GetString());
        Assert.StartsWith("The PCA-Action header is not a decodable PCActn: ", Reason(ctx));
    }

    [Fact]
    public async Task ANonSeekableBodyIsBufferedForDownstream()
    {
        var env = "{\"pcactn\":" + Pca.Canonicalize(Pcactn) + "}";
        var (ctx, ran) = await Run(Core(), c => c.Request.Body = new NoSeek(Utf8(env)), ExpectBody(env));
        Assert.Equal(1, ran);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task AByteOrderMarkInTheBodyIsNotJson()
    {
        // both the reader's detectEncodingFromByteOrderMarks and the encoding's preamble would skip it
        var (ctx, ran) = await Run(Core(), c => c.Request.Body = new MemoryStream(WithBom("{\"pcactn\":" + Pca.Canonicalize(Pcactn) + "}")));
        Assert.Equal(0, ran);
        Assert.Equal(401, ctx.Response.StatusCode);
        Assert.Equal("invalid_request", Json(ctx).GetProperty("error").GetString());
        Assert.StartsWith("The request body is not valid JSON: ", Reason(ctx));
    }

    [Fact]
    public async Task InvalidUtf8RewindsAndIsInvalidRequest()
    {
        var (ctx, _) = await Run(Core(), c => c.Request.Body = new MemoryStream(new byte[] { (byte)'{', 0xFF, 0xFE, (byte)'}' }));
        Refused(ctx, 401, "invalid_request", "The request body is not valid UTF-8.");
        Assert.Equal(0, ctx.Request.Body.Position);
    }

    [Fact]
    public async Task ABodyWithoutAPcactnEnvelope()
    {
        var (empty, _) = await Run(Core(), _ => { });
        Refused(empty, 401, "missing_pcactn", "No PCActn: set the PCA-Action header or POST a JSON body {\"pcactn\":...}.");
        foreach (var body in new[] { "{\"a\":1}", "[1]" })
        {
            var (ctx, _) = await Run(Core(), c => c.Request.Body = new MemoryStream(Utf8(body)));
            Refused(ctx, 401, "missing_pcactn", "The request body must be a JSON object {\"pcactn\":...}.");
        }
        var (bad, _) = await Run(Core(), c => c.Request.Body = new MemoryStream(Utf8("{bad")));
        Assert.Equal("invalid_request", Json(bad).GetProperty("error").GetString());
        Assert.StartsWith("The request body is not valid JSON: ", Reason(bad));
    }

    // ---------------------------------------------------------------- the per-request hooks

    [Fact]
    public async Task AThrowingFreshAtPolicyIsAccessDenied()
    {
        var (ctx, ran) = await Run(Core(o => o.FreshAt = (_, _) => throw new InvalidOperationException("x")), ProofInHeader);
        Assert.Equal(0, ran);
        Refused(ctx, 403, "access_denied", "fresh_at_policy_error: the consistency-token policy could not be resolved (fail closed).");
    }

    [Fact]
    public async Task AThrowingIntentV2ContextIsAccessDenied()
    {
        var (ctx, ran) = await Run(Core(o => o.IntentV2 = (_, _) => throw new InvalidOperationException("x")), ProofInHeader);
        Assert.Equal(0, ran);
        Refused(ctx, 403, "access_denied", "intent_v2_context_error: the Intent Layer v2 verifier state could not be resolved (fail closed).");
    }

    [Fact]
    public async Task TheIntentV2ContextIsAskedOncePerRequestInBothModes()
    {
        foreach (var core in new[] { true, false })
        {
            int asked = 0;
            HttpContext? seen = null;
            Func<HttpContext, JD, Task<IntentV2Context?>> hook = (c, _) => { asked++; seen = c; return Task.FromResult<IntentV2Context?>(null); };
            var options = core ? Core(o => o.IntentV2 = hook) : Full(null, o => o.IntentV2 = hook);
            var (ctx, ran) = await Run(options, Both);
            Assert.Equal((1, 1), (asked, ran));
            Assert.Same(ctx, seen);
        }
    }

    // require-pca.ts:786-793: a present header, empty included, is read as a token, and an unparseable token is a bad token. The port
    // treated an empty header as no header, and the request went through.
    [Fact]
    public async Task AnEmptySideCarriedHeaderIsABadTokenNotAMissingOne()
    {
        var signer = EdKey.FromSeed(Enumerable.Repeat((byte)9, 32).ToArray()).Id;
        var options = Full(null, o => o.FreshAt = (_, _) => Task.FromResult<FreshAtPolicy?>(new FreshAtPolicy(signer, "inst_1", new FreshAtState(5, 10, 1, 1, "pd"))));
        var (ctx, ran) = await Run(options, c => { Both(c); c.Request.Headers["pca-fresh-at"] = ""; });
        Assert.Equal(0, ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("fresh_at", Reason(ctx));
    }

    [Fact]
    public async Task AThrowingOperationMappingDenies()
    {
        var (ctx, ran) = await Run(Full(a => a.Operation = _ => throw new InvalidOperationException("x")), Both);
        Assert.Equal(0, ran);
        Assert.Equal(403, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task TheK1CallbackIsAsked()
    {
        int asked = 0;
        var (_, ran) = await Run(Full(a => a.K1 = (_, _) => { asked++; return new K1Input(); }), Both);
        Assert.Equal((1, 1), (asked, ran));
    }

    [Fact]
    public async Task AnAuthorizeRefusalMapsItsStatusToTheErrorCode()
    {
        var (unknown, _) = await Run(Full(null, o => o.GrantResolver = _ => Task.FromResult<JD?>(null)), Both);
        Refused(unknown, 401, "invalid_pcactn", "grant_ref: does not resolve to a known grant");
        var (revoked, _) = await Run(Full(a => a.IsRevoked = (_, _) => true), Both);
        Assert.Equal(403, revoked.Response.StatusCode);
        Assert.Equal("PCA realm=\"pca\", error=\"access_denied\", hint=\"send PCA-Action: <base64url PCActn> or JSON body {pcactn}\"", revoked.Response.Headers["WWW-Authenticate"].ToString());
    }

    // ---------------------------------------------------------------- revocation staleness

    static readonly byte[] GuardianSeed = Enumerable.Repeat((byte)11, 32).ToArray();
    static JD Epoch() => RevocationFreshness.SignEpoch(GuardianSeed, new RevocationEpochBody("i", (string)Pcactn["grant_ref"]!, 0, 0, IntentRevocation.RevsetRoot(Array.Empty<string>()), Now - 1_000, Now + 300_000));
    static string FirstCap => (string)((JD)((JL)Pcactn["cap_chain"]!)[0]!)["id"]!;

    static void Staleness(PcaAuthorizeOptions a)
    {
        a.RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 300_000);
        a.RevocationState = (_, _, _) => new RevocationState(Epoch: Epoch());
        a.GuardianPublic = (string)Epoch()["guardian"]!;
    }

    [Fact]
    public async Task NoStateSourceIsAMissingComponent()
    {
        var (ctx, _) = await Run(Full(a => { Staleness(a); a.RevocationState = null; }), Both);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("RevocationState (required by RevocationStaleness)", Reason(ctx));
    }

    [Fact]
    public async Task NoIdSourceMeansTheChainAndNoProofSourceDenies()
    {
        var (ctx, ran) = await Run(Full(Staleness), Both);
        Assert.Equal(0, ran);
        Assert.Equal("freshness: no non-membership proof for " + FirstCap, Reason(ctx));
    }

    [Fact]
    public async Task TheIdAndProofCallbacksAreUsed()
    {
        var (fresh, ran) = await Run(Full(a => { Staleness(a); a.RevocationIds = (_, _) => Array.Empty<string>(); }), Both);
        Assert.Equal((1, 200), (ran, fresh.Response.StatusCode));
        var (proved, ranProved) = await Run(Full(a => { Staleness(a); a.RevocationProofFor = (_, _, _) => new JD { ["size"] = IntentJs.OfLong(0) }; }), Both);
        Assert.Equal((1, 200), (ranProved, proved.Response.StatusCode));
    }

    // ---------------------------------------------------------------- the executor

    static OperationRecord Seeded(string state, string? error = null, object? result = null) =>
        new(RecordId, state, Op.Verb, Op.Resource, Pca.ParamsDigest(Op.Params), "irreversible", Now) { Error = error, Result = result };

    static PcaOptions Executing(IOperationStore ops, Action<PcaOptions>? tweak = null) =>
        Full(null, o => { o.Executor = new PcaExecutorOptions { Operations = ops }; tweak?.Invoke(o); });

    static MemoryOperationStore StoreWith(OperationRecord rec)
    {
        var ops = new MemoryOperationStore();
        ops.Create(rec);
        return ops;
    }

    [Fact]
    public async Task HopByHopHeadersAreNeverRecordedAndAnEmptyValueIsKeptEmpty()
    {
        var ops = new MemoryOperationStore();
        RequestDelegate app = async c =>
        {
            foreach (var h in Unrecorded) c.Response.Headers[h] = "7";
            c.Response.Headers["X-Keep"] = "k";
            c.Response.Headers["X-Null"] = new StringValues(new string?[] { null, "x" });
            c.Response.StatusCode = 201;
            await c.Response.WriteAsync("created");
        };
        var mw = new PcaMiddleware(app, Executing(ops));
        var first = new DefaultHttpContext();
        first.Response.Body = new MemoryStream();
        Both(first);
        await mw.InvokeAsync(first);
        Assert.Equal(201, first.Response.StatusCode);
        var recorded = (JD)((JD)ops.Get(RecordId)!.Result!)["headers"]!;
        foreach (var h in Unrecorded) Assert.False(recorded.ContainsKey(h), h);
        Assert.Equal(new object?[] { "", "x" }, (JL)recorded["X-Null"]!);

        var again = new DefaultHttpContext();
        again.Response.Body = new MemoryStream();
        Both(again);
        await mw.InvokeAsync(again);
        foreach (var h in Unrecorded) Assert.False(again.Response.Headers.ContainsKey(h), h);
        Assert.Equal("k", again.Response.Headers["X-Keep"].ToString());
        Assert.Equal(new[] { "", "x" }, again.Response.Headers["X-Null"].ToArray());
        Assert.Equal("true", again.Response.Headers["PCA-Replayed"].ToString());
    }

    [Fact]
    public async Task ARecordedResponseIsRebuiltFromTheRecord()
    {
        var result = new JD
        {
            ["status"] = new Num("202"), ["body"] = Convert.ToBase64String(Utf8("hi")),
            ["headers"] = new JD { ["X-A"] = new JL { new Num("5"), "s" }, ["X-Skip"] = "not a list", ["Connection"] = new JL { "close" } },
        };
        var (ctx, ran) = await Run(Executing(StoreWith(Seeded(OperationStates.Committed, null, result))), Both);
        Assert.Equal(0, ran);
        Assert.Equal(202, ctx.Response.StatusCode);
        Assert.Equal("hi", Text(ctx));
        Assert.Equal(new[] { "", "s" }, ctx.Response.Headers["X-A"].ToArray());
        Assert.False(ctx.Response.Headers.ContainsKey("X-Skip"));
        Assert.False(ctx.Response.Headers.ContainsKey("Connection"));
    }

    public static IEnumerable<object[]> UnreadableResults()
    {
        yield return new object[] { "not an object" };
        yield return new object[] { new JD { ["status"] = "200", ["headers"] = new JD(), ["body"] = "" } };
        yield return new object[] { new JD { ["status"] = new Num("-1"), ["headers"] = new JD(), ["body"] = "" } };
        yield return new object[] { new JD { ["status"] = new Num("200"), ["headers"] = new JD(), ["body"] = "!" } };
    }

    [Theory]
    [MemberData(nameof(UnreadableResults))]
    public async Task AnUnreadableRecordIsUncertain(object result)
    {
        var (ctx, ran) = await Run(Executing(StoreWith(Seeded(OperationStates.Committed, null, result))), Both);
        Assert.Equal(0, ran);
        Refused(ctx, 409, "operation_uncertain", "the recorded result is unreadable");
    }

    [Fact]
    public async Task TheExecutorOutcomesAndTheirReasons()
    {
        var (failed, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Failed, "secret detail"))), Both);
        Refused(failed, 500, "operation_failed", "the operation failed");
        var (aborted, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Aborted, "why"))), Both);
        Refused(aborted, 403, "operation_aborted", "why");
        var (abortedPlain, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Aborted))), Both);
        Refused(abortedPlain, 403, "operation_aborted", "aborted");
        var (pending, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Executing) with { ExecutingAt = Now })), Both);
        Refused(pending, 409, "operation_in_progress", "another execution of this operation is in flight");
        var (uncertain, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Uncertain, "why"))), Both);
        Refused(uncertain, 409, "operation_uncertain", "why");
        var (uncertainPlain, _) = await Run(Executing(StoreWith(Seeded(OperationStates.Uncertain))), Both);
        Refused(uncertainPlain, 409, "operation_uncertain", "outcome unknown");
    }

    [Fact]
    public async Task ARefusedExecutionIsAccessDeniedWithItsReason()
    {
        // the second clock read is inside the executor, whose catch turns the failure into a refusal
        int reads = 0;
        var (ctx, ran) = await Run(Executing(new MemoryOperationStore(), o => o.Clock = () => ++reads == 1 ? Now : throw new InvalidOperationException("boom")), Both);
        Assert.Equal(0, ran);
        Refused(ctx, 403, "access_denied", "executeAuthorized: error (fail closed): boom");
    }

    // ---------------------------------------------------------------- the escalation answer

    static EdKey Principal => EdKey.FromSeed(Enumerable.Repeat((byte)0x71, 32).ToArray());

    static string Answer()
    {
        var body = new JD
        {
            ["v"] = IntentJs.OfLong(1), ["kind"] = "pca-escalation-answer", ["principal"] = Principal.Id, ["policy_digest"] = Escalation.PolicyDigest(Grant),
            ["action_digest"] = Escalation.ActionDigest(Pcactn), ["history_head"] = Escalation.HistoryHead(null), ["decision"] = "allow",
            ["iat"] = IntentJs.OfLong(Now - 1_000), ["expires_at"] = IntentJs.OfLong(Now + 600_000), ["nonce"] = "CQkJCQkJCQkJCQkJCQkJCQ",
        };
        var sig = Pca.B64u(Principal.Sign(IntentJs.Message(Escalation.AnswerDomain, body)));
        body["sig"] = sig;
        return Pca.Canonicalize(body);
    }

    sealed class Unhook : IDisposable { public void Dispose() => Pca.CoreHook = null; }

    /// <summary>An escalate-class failure of the core (as in EscalationTests): only a principal's answer admits the request.</summary>
    static IDisposable Escalating()
    {
        Pca.CoreHook = core =>
        {
            core.Checks["provenance"] = false;
            core.Allow = false;
            core.Reason = "provenance: intent_required: a question is required";
        };
        return new Unhook();
    }

    static PcaOptions Answering() => Full(a => { a.EscalationPrincipals = new PinnedSigner[] { Principal.Id }; a.InsecureUnboundApproval = true; });

    [Fact]
    public async Task TheAnswerHeaderSizeBoundIsExact()
    {
        using var _ = Escalating();
        var (ok, ran) = await Run(Answering(), c => { Both(c); c.Request.Headers["PCA-Escalation-Answer"] = B64(Spaced(Answer(), Max)); });
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
        var (big, ranBig) = await Run(Answering(), c => { Both(c); c.Request.Headers["PCA-Escalation-Answer"] = B64(Spaced(Answer(), Max + 1)); });
        Assert.Equal(0, ranBig);
        Assert.Equal("escalate", Decision(big));
    }

    [Fact]
    public async Task TheBodyAnswerRewindsAndRefusesAByteOrderMark()
    {
        using var _ = Escalating();
        var env = "{\"escalation_answer\":" + Answer() + "}";
        var (ok, ran) = await Run(Answering(), c => { Both(c); c.Request.Body = new MemoryStream(Utf8(env)); }, ExpectBody(env));
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
        var (bom, ranBom) = await Run(Answering(), c => { Both(c); c.Request.Body = new MemoryStream(WithBom(env)); });
        Assert.Equal(0, ranBom);
        Assert.Equal("escalate", Decision(bom));
    }

    [Fact]
    public async Task TheAnswerIsReadOnlyWhenAPrincipalIsPinned()
    {
        async Task<int> Rewinds(IReadOnlyList<PinnedSigner>? principals)
        {
            var body = new RewindCounter(Utf8("{}"));
            await Run(Full(a => a.EscalationPrincipals = principals), c => { Both(c); c.Request.Body = body; });
            return body.Rewinds;
        }
        Assert.Equal(0, await Rewinds(null));
        Assert.Equal(0, await Rewinds(Array.Empty<PinnedSigner>()));
        Assert.True(await Rewinds(new PinnedSigner[] { Principal.Id }) > 0);
    }

    // ---------------------------------------------------------------- the provenance bundle

    static string BundleJson => Pca.Canonicalize(ProvHarness.Bundle(Op));
    static string BundleEnvelope => "{\"" + ArgProvenance.BodyMember + "\":" + BundleJson + "}";

    [Fact]
    public async Task TheBundleHeaderSizeBoundIsExact()
    {
        // base64url of 786432 bytes is exactly twice the artifact cap; two more characters are over it
        var at = B64(Spaced(BundleJson, 786432));
        Assert.Equal(Cap, at.Length);
        var (ok, ran) = await Run(Full(), c => { ProofInHeader(c); c.Request.Headers[ArgProvenance.Header] = at; });
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
        var (big, ranBig) = await Run(Full(), c => { ProofInHeader(c); c.Request.Headers[ArgProvenance.Header] = B64(Spaced(BundleJson, 786433)); });
        Assert.Equal(0, ranBig);
        Assert.Equal("deny", Decision(big));
        Assert.Equal("provenance_flow: the provenance bundle is unreadable (fail closed)", Reason(big));
    }

    static async Task<(DefaultHttpContext Ctx, int Ran)> BodyBundle(byte[] body, long? contentLength = null, RequestDelegate? next = null) =>
        await Run(Full(), c =>
        {
            ProofInHeader(c);
            c.Request.Body = new MemoryStream(body);
            c.Request.ContentLength = contentLength;
        }, next);

    [Fact]
    public async Task TheBodyBundleIsReadUpToTheDeclaredLengthCap()
    {
        var body = Utf8(BundleEnvelope);
        Assert.Equal(1, (await BodyBundle(body, body.Length)).Ran);
        Assert.Equal(1, (await BodyBundle(body, Cap)).Ran);
        var (over, ran) = await BodyBundle(body, Cap + 1);
        Assert.Equal(0, ran);
        Assert.Equal("escalate", Decision(over)); // no bundle, not an unreadable one
    }

    [Fact]
    public async Task ABodyOfExactlyTheCapIsReadWhole()
    {
        // the padding leads, so a reader that stops one character short breaks the JSON
        var (ok, ran) = await BodyBundle(Utf8(Spaced(BundleEnvelope, Cap)));
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
    }

    [Fact]
    public async Task ANonSeekableBodyIsBufferedForTheBundle()
    {
        var env = BundleEnvelope;
        var (ok, ran) = await Run(Full(), c => { ProofInHeader(c); c.Request.Body = new NoSeek(Utf8(env)); }, ExpectBody(env));
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
    }

    [Fact]
    public async Task TheBodyBundleReaderLeavesTheBodyOpen()
    {
        var env = BundleEnvelope;
        var (_, ran) = await BodyBundle(Utf8(env), null, ExpectBody(env));
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task AnUnreadableBodyPresentsNoBundleRatherThanABadOne()
    {
        var (bom, ran) = await BodyBundle(WithBom(BundleEnvelope));
        Assert.Equal(0, ran);
        Assert.Equal("escalate", Decision(bom));
        var (utf8, ranUtf8) = await BodyBundle(new byte[] { (byte)'{', 0xFF, (byte)'}' });
        Assert.Equal(0, ranUtf8);
        Assert.Equal("escalate", Decision(utf8));
    }

    // ---------------------------------------------------------------- the workflow step

    static JD Wf => WorkflowAuthorizeTests.Load(); // a missing fixture fails these tests, not the whole class; parsed per access so no mutant's failure is cached
    static JD WfStep(string name) => (JD)((JL)((JL)Wf["cases"]!).Cast<JD>().First(c => (string)c["name"]! == name)["steps"]!)[0]!;
    static Operation WfOp(JD step)
    {
        var op = (JD)step["operation"]!;
        return new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]);
    }

    static PcaOptions WfOptions(JD step, Action<PcaAuthorizeOptions>? tweak = null)
    {
        var wf = Wf;
        var grant = (JD)wf["grant"]!;
        var wfNow = long.Parse(((Num)wf["now"]!).Raw, CultureInfo.InvariantCulture);
        var az = new PcaAuthorizeOptions
        {
            StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = null,
            Operation = _ => Task.FromResult<Operation?>(WfOp(step)),
            Context = (_, _) => new JD { ["plan"] = wf["plan"], ["plan_authorized"] = true },
            Workflow = new WorkflowGate((string)wf["principal"]!, (string)wf["rs_signer"]!),
            ProvenanceFlow = ProvHarness.Options,
        };
        tweak?.Invoke(az);
        return new PcaOptions
        {
            Audience = (string)wf["audience"]!, Clock = () => wfNow,
            GrantResolver = r => Task.FromResult<JD?>(r == (string)grant["id"]! ? grant : null), Authorize = az,
        };
    }

    static void WfBundleInHeader(DefaultHttpContext c, JD step) => c.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(WfOp(step));

    static byte[] WfEnvelope(JD step, object? workflow) =>
        Utf8(Pca.Canonicalize(new JD { ["pcactn"] = step["pcactn"], ["workflow"] = workflow }));

    [Fact]
    public async Task AThrowingWorkflowReaderIsAnEmptyCallWhichTheOptionalGateDenies()
    {
        var step = WfStep("workflow-optional-and-absent");
        var (ctx, ran) = await Run(WfOptions(step, a => a.WorkflowCall = (_, _) => throw new InvalidOperationException("x")), c =>
        {
            c.Request.Headers["PCA-Action"] = B64(Pca.Canonicalize(step["pcactn"]));
            WfBundleInHeader(c, step);
        });
        Assert.Equal(0, ran);
        Assert.StartsWith("workflow: ", Reason(ctx));
    }

    [Fact]
    public async Task HeaderModeReadsNoWorkflowFromTheBody()
    {
        var step = WfStep("workflow-optional-and-absent");
        var (ctx, ran) = await Run(WfOptions(step), c =>
        {
            c.Request.Headers["PCA-Action"] = B64(Pca.Canonicalize(step["pcactn"]));
            WfBundleInHeader(c, step);
            c.Request.Body = new MemoryStream(Utf8("{\"workflow\":5}"));
        });
        Assert.Equal(1, ran);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    public static IEnumerable<object[]> AbsentHeaders()
    {
        yield return new object[] { "" };
        yield return new object[] { new string?[] { null } };
    }

    [Theory]
    [MemberData(nameof(AbsentHeaders))]
    public async Task AnEmptyProofHeaderIsBodyModeSoTheWorkflowIsRead(object header)
    {
        var step = WfStep("workflow-optional-and-absent");
        var (ctx, ran) = await Run(WfOptions(step), c =>
        {
            c.Request.Headers["PCA-Action"] = header is string s ? new StringValues(s) : new StringValues((string?[])header);
            WfBundleInHeader(c, step);
            c.Request.Body = new MemoryStream(WfEnvelope(step, IntentJs.OfLong(5)));
        });
        Assert.Equal(0, ran);
        Assert.StartsWith("workflow: ", Reason(ctx));
    }

    [Fact]
    public async Task TheWorkflowBodyReaderRefusesAByteOrderMark()
    {
        // the proof passed its own reader; a host hook then swaps the body, which is what reaches the workflow reader
        var step = WfStep("workflow-optional-and-absent");
        var (ctx, ran) = await Run(WfOptions(step, a => a.Operation = c =>
        {
            c.Request.Body = new MemoryStream(WithBom("{}"));
            return Task.FromResult<Operation?>(WfOp(step));
        }), c =>
        {
            WfBundleInHeader(c, step);
            c.Request.Body = new MemoryStream(Utf8(Pca.Canonicalize(new JD { ["pcactn"] = step["pcactn"] })));
        });
        Assert.Equal(0, ran);
        Assert.StartsWith("workflow: ", Reason(ctx));
    }

    [Fact]
    public async Task TheWorkflowMembersUnitsAndGoalDigestAreRead()
    {
        var step = WfStep("pay-after-quote");
        var wf = (JD)step["workflow"]!;
        async Task<(DefaultHttpContext Ctx, int Ran)> With(string member, object? value)
        {
            var edited = new JD(wf) { [member] = value };
            return await Run(WfOptions(step), c =>
            {
                WfBundleInHeader(c, step);
                c.Request.Body = new MemoryStream(WfEnvelope(step, edited));
            });
        }
        var (same, ranSame) = await With("units", wf["units"]);
        Assert.Equal((1, 200), (ranSame, same.Response.StatusCode));
        var (goal, ranGoal) = await With("goal_digest", Pca.B64u(new byte[32]));
        Assert.Equal(0, ranGoal);
        Assert.Equal("workflow: goal_mismatch (step quote)", Reason(goal));
        var (units, ranUnits) = await With("units", IntentJs.OfLong(5));
        Assert.Equal(0, ranUnits);
        Assert.Equal(403, units.Response.StatusCode);
    }

    // ---------------------------------------------------------------- presented K1 headers

    [Fact]
    public void PresentedK1SkipsEmptyHeadersAndReadsANullValueAsEmpty()
    {
        var empty = new DefaultHttpContext();
        empty.Request.Headers.Add("X-Empty", StringValues.Empty);
        Assert.True(PcaMiddleware.PresentedFrom(empty).Ok);

        var nullValue = new DefaultHttpContext();
        nullValue.Request.Headers["PCA-Discharges"] = new StringValues(new string?[] { null });
        var p = PcaMiddleware.PresentedFrom(nullValue);
        Assert.True(p.Ok);
        Assert.Null(p.Discharges);
    }

    // ---------------------------------------------------------------- the challenge

    [Fact]
    public async Task TheRealmIsEscapedForAQuotedString()
    {
        var (ctx, _) = await Run(Core(o => o.Realm = "a\\b\"c\rd\ne"), _ => { });
        Assert.Equal("PCA realm=\"a\\\\b\\\"c d e\", error=\"missing_pcactn\", hint=\"send PCA-Action: <base64url PCActn> or JSON body {pcactn}\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
    }

    // ---------------------------------------------------------------- PcaOptions

    static void Rejected(string message, Action<PcaOptions> tweak)
    {
        var o = Core();
        tweak(o);
        Assert.Equal(message, Assert.Throws<InvalidOperationException>(o.Validate).Message);
    }

    sealed class BareStore : IStateStore
    {
        public ClaimResult? Claim(string key, long counter) => throw new InvalidOperationException("not used");
    }

    [Fact]
    public void TheDefaultOptionsHaveNoAudience() =>
        Assert.Equal("PcaOptions.Audience must be set.", Assert.Throws<InvalidOperationException>(new PcaOptions().Validate).Message);

    [Fact]
    public void ValidateNamesEveryMissingComponent()
    {
        Core().Validate();
        Rejected("PcaOptions.Audience must be set.", o => o.Audience = "");
        Rejected("PcaOptions.GrantResolver must be set.", o => o.GrantResolver = null!);
        Rejected("PcaOptions.Clock must be set.", o => o.Clock = null!);
        Rejected("PcaOptions.HeaderName must be set.", o => o.HeaderName = "");
    }

    [Fact]
    public void ValidateRefusesConflictingOptions()
    {
        Rejected("PcaOptions: IntentPolicy.ApprovedGoal and ApprovedGoal name different goals.", o =>
        {
            o.IntentPolicy = new IntentPolicy(ApprovedGoal: new ApprovedGoalRef(G, P));
            o.ApprovedGoal = new ApprovedGoalRef(P, G);
        });
        Rejected("PcaOptions: Executor needs the authorize path (not SignatureOnly).", o => o.Executor = new PcaExecutorOptions { Operations = new MemoryOperationStore() });
        void Exec(PcaOptions o, PcaExecutorOptions e) { o.SignatureOnly = false; o.Executor = e; }
        Rejected("PcaOptions: Executor.Operations (an IOperationStore) is required.", o => Exec(o, new PcaExecutorOptions()));
        Rejected("PcaOptions: Executor.RecheckFor must be \"irreversible\" or \"always\".", o => Exec(o, new PcaExecutorOptions { Operations = new MemoryOperationStore(), RecheckFor = "sometimes" }));
        foreach (var ok in new[] { null, "irreversible", "always" })
        {
            var o = Core();
            Exec(o, new PcaExecutorOptions { Operations = new MemoryOperationStore(), RecheckFor = ok });
            o.Validate();
        }
    }

    [Fact]
    public void PinnedEscalationPrincipalsNeedAStoreThatKnowsTheHistoryHead()
    {
        PcaOptions With(IReadOnlyList<PinnedSigner> pins, IStateStore store)
        {
            var o = Core();
            o.SignatureOnly = false;
            o.Authorize = new PcaAuthorizeOptions { Plan = "single-step", EscalationPrincipals = pins, StateStore = store };
            return o;
        }
        PinnedSigner[] one = { Principal.Id };
        With(Array.Empty<PinnedSigner>(), new BareStore()).Validate();
        With(one, new MemoryStateStore()).Validate();
        Assert.Equal("PcaOptions: Authorize.EscalationPrincipals needs a StateStore that implements ILastStore (an escalation answer is bound to the holder's history head).",
            Assert.Throws<InvalidOperationException>(With(one, new BareStore()).Validate).Message);
    }

    [Fact]
    public void AnApprovedGoalKeepsTheFloorsOfTheIntentPolicy()
    {
        // internal to the package, whose test assembly has no InternalsVisibleTo: its only other observer needs a real intent-bound PCActn
        var effective = typeof(PcaOptions).GetProperty("EffectiveIntentPolicy", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var goal = new ApprovedGoalRef(G, P);
        var merged = (IntentPolicy)effective.GetValue(new PcaOptions { IntentPolicy = new IntentPolicy(MinFidelityPpm: 5), ApprovedGoal = goal })!;
        Assert.Equal(5, merged.MinFidelityPpm);
        Assert.Equal(goal, merged.ApprovedGoal);
        Assert.Equal(goal, ((IntentPolicy)effective.GetValue(new PcaOptions { ApprovedGoal = goal })!).ApprovedGoal);
    }

    // ---------------------------------------------------------------- registration

    static void Valid(PcaOptions o) { o.Audience = "a"; o.SignatureOnly = true; o.InsecureSkipPlanRootCheck = true; }

    [Fact]
    public void AddPcaConfiguresValidatesAndRegisters()
    {
        var services = new ServiceCollection();
        Assert.Equal("configure", Assert.Throws<ArgumentNullException>(() => services.AddPca(null!)).ParamName);
        Assert.Throws<InvalidOperationException>(() => services.AddPca(_ => { }));
        Assert.Empty(services);
        Assert.Same(services, services.AddPca(Valid));
        Assert.Equal("a", services.BuildServiceProvider().GetRequiredService<PcaOptions>().Audience);
    }

    static ApplicationBuilder App() => new(new ServiceCollection().BuildServiceProvider());

    static async Task<int> StatusOf(IApplicationBuilder app)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        await app.Build()(ctx);
        return ctx.Response.StatusCode;
    }

    [Fact]
    public async Task UsePcaWithAConfigureCallback()
    {
        Assert.Equal("configure", Assert.Throws<ArgumentNullException>(() => App().UsePca((Action<PcaOptions>)null!)).ParamName);
        Assert.Throws<InvalidOperationException>(() => App().UsePca(_ => { })); // at registration, not when the pipeline is built
        var app = App();
        app.UsePca(Valid);
        Assert.Equal(401, await StatusOf(app));
    }

    [Fact]
    public async Task UsePcaWithPrebuiltOptions()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => App().UsePca((PcaOptions)null!)).ParamName);
        Assert.Throws<InvalidOperationException>(() => App().UsePca(new PcaOptions())); // at registration, not when the pipeline is built
        var options = new PcaOptions();
        Valid(options);
        var app = App();
        app.UsePca(options);
        Assert.Equal(401, await StatusOf(app));
    }

    // ---------------------------------------------------------------- PcaProtect

    static Task<JD?> NoGrant(string _) => Task.FromResult<JD?>(null);
    static Task<Operation?> NoOp(HttpContext _) => Task.FromResult<Operation?>(null);

    [Fact]
    public void ProtectChecksItsArguments()
    {
        Assert.Equal("resolveGrant", Assert.Throws<ArgumentNullException>(() => PcaProtect.Create("a", (Func<string, Task<JD?>>)null!, NoOp)).ParamName);
        Assert.Equal("operation", Assert.Throws<ArgumentNullException>(() => PcaProtect.Create("a", (Func<string, Task<JD?>>)NoGrant, null!)).ParamName);
        Assert.Equal("PcaOptions.Audience must be set.", Assert.Throws<InvalidOperationException>(() => PcaProtect.Create("", (Func<string, Task<JD?>>)NoGrant, NoOp)).Message);
    }
}
