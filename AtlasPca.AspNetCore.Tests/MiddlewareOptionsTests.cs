using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// PcaMiddleware with the 0.5 native-parity options: ApprovedGoal (goal binding v3), and the authorize members RevocationStaleness,
// RequireAssurance and Plans, plus Executor (operation records). Exact-outcome tests with the guard semantics of the other natives.
public class MiddlewareOptionsTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    const string G = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw";
    const string P = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo";

    static PcaOptions Options(Action<PcaAuthorizeOptions>? tweak = null, Action<PcaOptions>? tweakOptions = null)
    {
        var az = new PcaAuthorizeOptions { StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options };
        tweak?.Invoke(az);
        var o = new PcaOptions
        {
            Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null), Authorize = az,
        };
        tweakOptions?.Invoke(o);
        return o;
    }

    static DefaultHttpContext Ctx()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        return ctx;
    }

    static JsonElement BodyOf(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return JsonDocument.Parse(new StreamReader(ctx.Response.Body).ReadToEnd()).RootElement;
    }

    static string Text(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body).ReadToEnd();
    }

    static async Task<(DefaultHttpContext Ctx, int Ran)> Run(PcaOptions o, RequestDelegate? next = null)
    {
        int ran = 0;
        var mw = new PcaMiddleware(c => { ran++; return next?.Invoke(c) ?? Task.CompletedTask; }, o);
        var ctx = Ctx();
        await mw.InvokeAsync(ctx);
        return (ctx, ran);
    }

    // ---- goal binding v3

    [Fact]
    public async Task ApprovedGoalRefusesAPcactnWithoutABoundIntent()
    {
        var (ctx, ran) = await Run(Options(null, o => o.ApprovedGoal = new ApprovedGoalRef(G, P)));
        Assert.Equal(0, ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("requires an intent binding", BodyOf(ctx).GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task AMalformedApprovedGoalIsAFailClosedMisconfiguration()
    {
        foreach (var bad in new[] { new ApprovedGoalRef(G, "AAAA"), new ApprovedGoalRef("", P) })
        {
            var (ctx, ran) = await Run(Options(null, o => o.IntentPolicy = new IntentPolicy(ApprovedGoal: bad)));
            Assert.Equal((0, 403), (ran, ctx.Response.StatusCode));
            Assert.Contains("approved_goal digests must be canonical base64url", BodyOf(ctx).GetProperty("error_description").GetString());
        }
        Assert.Throws<InvalidOperationException>(() => new PcaMiddleware(_ => Task.CompletedTask,
            Options(null, o => { o.IntentPolicy = new IntentPolicy(ApprovedGoal: new ApprovedGoalRef(G, P)); o.ApprovedGoal = new ApprovedGoalRef(P, G); })));
    }

    // ---- staleness, assurance, plans

    [Fact]
    public async Task RevocationStalenessFailsTheFreshnessCheck()
    {
        var pol = new RevocationStalenessPolicy(Staleness: new StalenessWindows(Irreversible: 10_000), AllowUnsignedRootForIrreversible: true);
        PcaOptions With(long issuedAgo) => Options(a => { a.RevocationStaleness = pol; a.RevocationIds = (_, _) => Array.Empty<string>(); a.RevocationState = (_, _, _) => new RevocationState(Root: "r", RootIssuedAt: Now - issuedAgo); });
        var (stale, ranStale) = await Run(With(10_001));
        Assert.Equal((0, 403), (ranStale, stale.Response.StatusCode));
        Assert.StartsWith("freshness: revocation root is 10001 ms old", BodyOf(stale).GetProperty("error_description").GetString());
        var (fresh, ran) = await Run(With(10_000));
        Assert.Equal((1, 200), (ran, fresh.Response.StatusCode));
    }

    [Fact]
    public async Task RequireAssuranceGatesTheRequest()
    {
        var (denied, ran) = await Run(Options(a => a.RequireAssurance = new AssuranceRequirement(Signature: "pq")));
        Assert.Equal((0, 403), (ran, denied.Response.StatusCode));
        Assert.Equal("assurance: post-quantum signatures required but leaf_signature is ed25519", BodyOf(denied).GetProperty("error_description").GetString());
        Assert.Equal(1, (await Run(Options(a => a.RequireAssurance = new AssuranceRequirement()))).Ran);
    }

    static JD PlanNodeOf(JD p)
    {
        var action = (JD)p["action"]!; var pl = (JD)p["plan"]!;
        return new JD { ["id"] = pl["node_id"], ["verb"] = action["verb"], ["resource"] = action["resource"], ["params_digest"] = action["params_digest"], ["reversibility_class"] = action["reversibility_class"] };
    }

    [Fact]
    public async Task APlanRegistryFeedsThePlanChecks()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => Now });
        PcaOptions With() => Options(a => { a.Plans = reg; a.Plan = null; a.StateStore = new MemoryStateStore(); });
        // an unregistered plan is not executable
        var (unknown, ranUnknown) = await Run(With());
        Assert.Equal((0, 403), (ranUnknown, unknown.Response.StatusCode));
        Assert.StartsWith("plan_state: ", BodyOf(unknown).GetProperty("error_description").GetString());
        var grantRef = (string)Pcactn["grant_ref"]!;
        var root = reg.Draft(grantRef, new List<JD> { PlanNodeOf(Pcactn) }).Record!.Root;
        reg.Validate(grantRef, root); reg.Commit(grantRef, root);
        Assert.Equal(0, (await Run(With())).Ran); // committed, not authorized by the principal
        reg.Authorize(grantRef, root, new PlanApproval("principal"));
        var (ok, ran) = await Run(With());
        Assert.Equal((1, 200), (ran, ok.Response.StatusCode));
    }

    // ---- the executor

    static PcaOptions Executing(IOperationStore ops, Action<PcaAuthorizeOptions>? tweak = null, Action<PcaExecutorOptions>? tweakExec = null) =>
        Options(tweak, o => { o.Executor = new PcaExecutorOptions { Operations = ops }; tweakExec?.Invoke(o.Executor); });

    [Fact]
    public async Task TheExecutorRunsTheAppOnceAndAnswersARetryFromTheRecord()
    {
        var ops = new MemoryOperationStore();
        var mw = new PcaMiddleware(async c =>
        {
            Interlocked.Increment(ref _calls);
            c.Response.StatusCode = 201;
            c.Response.Headers["X-Key"] = ((PcaAuthResult)c.Items["pca"]!).IdempotencyKey;
            await c.Response.WriteAsync("created");
        }, Executing(ops, a => a.StateStore = new MemoryStateStore()));
        _calls = 0;
        var first = Ctx();
        await mw.InvokeAsync(first);
        Assert.Equal(201, first.Response.StatusCode);
        Assert.Equal("created", Text(first));
        Assert.Equal(Pca.HashCanonical(Pcactn), first.Response.Headers["X-Key"].ToString());
        Assert.False(first.Response.Headers.ContainsKey("PCA-Replayed"));
        var again = Ctx();
        await mw.InvokeAsync(again);
        Assert.Equal((201, "created", "true"), (again.Response.StatusCode, Text(again), again.Response.Headers["PCA-Replayed"].ToString()));
        Assert.Equal(Pca.HashCanonical(Pcactn), again.Response.Headers["X-Key"].ToString());
        Assert.Equal(1, _calls);
    }

    static int _calls;

    [Fact]
    public async Task TheExecutorRecordsAnAppFailureAndNeverReRunsIt()
    {
        var ops = new MemoryOperationStore();
        _calls = 0;
        var mw = new PcaMiddleware(_ => { Interlocked.Increment(ref _calls); throw new InvalidOperationException("downstream down"); }, Executing(ops));
        for (int i = 0; i < 2; i++)
        {
            var ctx = Ctx();
            await mw.InvokeAsync(ctx);
            Assert.Equal(500, ctx.Response.StatusCode);
            var text = Text(ctx);
            Assert.Contains("\"error\":\"operation_failed\"", text);
            Assert.DoesNotContain("downstream down", text);
            Assert.False(ctx.Response.Headers.ContainsKey("WWW-Authenticate"));
        }
        Assert.Equal(1, _calls);
    }

    [Fact]
    public async Task AFailingRecheckAbortsBeforeTheAppRuns()
    {
        int seen = 0;
        var (ctx, ran) = await Run(Executing(new MemoryOperationStore(), a => a.IsRevoked = (_, _) => ++seen > 1)); // the authorization pass sees "not revoked"
        Assert.Equal(0, ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        var b = BodyOf(ctx);
        Assert.Equal("operation_aborted", b.GetProperty("error").GetString());
        Assert.Equal("recheck: the grant has been revoked", b.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task ARecordStillInFlightIsA409()
    {
        var ops = new MemoryOperationStore();
        ops.Create(new OperationRecord(Pca.HashCanonical(Pcactn), OperationStates.Executing, Op.Verb, Op.Resource, "d", "irreversible", Now) { ExecutingAt = Now });
        var (ctx, ran) = await Run(Executing(ops));
        Assert.Equal((0, 409), (ran, ctx.Response.StatusCode));
        Assert.Equal("operation_in_progress", BodyOf(ctx).GetProperty("error").GetString());
        Assert.False(ctx.Response.Headers.ContainsKey("WWW-Authenticate"));
    }

    [Fact]
    public async Task ExecutorDenialsKeepTheGuardSemantics()
    {
        var (ctx, ran) = await Run(Executing(new MemoryOperationStore(), a => a.IsRevoked = (_, _) => true));
        Assert.Equal((0, 403), (ran, ctx.Response.StatusCode));
        var b = BodyOf(ctx);
        Assert.Equal("access_denied", b.GetProperty("error").GetString());
        Assert.Equal("deny", b.GetProperty("decision").GetString());
        Assert.StartsWith("PCA realm=\"pca\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
    }

    [Fact]
    public void ExecutorConfigurationErrorsThrowAtConstruction()
    {
        PcaMiddleware Build(PcaOptions o) => new(_ => Task.CompletedTask, o);
        Assert.Throws<InvalidOperationException>(() => Build(Options(null, o => { o.SignatureOnly = true; o.Authorize = null; o.Executor = new PcaExecutorOptions { Operations = new MemoryOperationStore() }; })));
        Assert.Throws<InvalidOperationException>(() => Build(Options(null, o => o.Executor = new PcaExecutorOptions())));
        Assert.Throws<InvalidOperationException>(() => Build(Executing(new MemoryOperationStore(), null, e => e.RecheckFor = "sometimes")));
    }

    [Fact]
    public void BothPackagesDeclareStableMaturity()
    {
        Assert.Equal("stable", Pca.Maturity);
        foreach (var asm in new[] { typeof(Pca).Assembly, typeof(PcaMiddleware).Assembly })
            Assert.Equal("stable", asm.GetCustomAttributes(typeof(System.Reflection.AssemblyMetadataAttribute), false)
                .Cast<System.Reflection.AssemblyMetadataAttribute>().Single(a => a.Key == "maturity").Value);
    }
}
