using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Kills for IntentV2.cs against the reference: packages/pca/src/intent-v2.ts (context shape, allowSidePredicates, modelRules),
/// decision.ts (decideTighten) and server/verify.ts (needsModelRules, the params / env defaults).</summary>
public partial class IntentV2KillTests
{
    /// <summary>A grant whose envelope ReadEnvelope accepts (it needs a valid risk_policy), with members set or added.</summary>
    static D EnvGrant(params object?[] over)
    {
        var env = M("type", "envelope", "goal_commit", "x", "predicates", Li(), "caveats", Li(), "agent_binding", M(),
            "risk_policy", Pca.ParseJson("""{"weights":{"alpha":0,"beta":0,"gamma":1,"delta":0,"epsilon":0,"zeta":0},"theta1":1,"theta2":1,"kappa":100,"lambda":0,"rho":0.5,"bMax":1000000}"""));
        foreach (var (k, v) in M(over)) env[k] = v;
        return M("id", B64Seed("v2/env-grant"), "issuer", Pub(PRINCIPAL), "caveats", Li(env));
    }
    static L ReadsPath(string path) => Li(M("verb", "*", "where", Li(M("field", path, "op", "eq", "value", "a"))));
    static string Rule21Why(string path) => $"a grant's where reads model-derived path(s) {path}: a model may only tighten (move them into tighten[]) (rule 21)";
    static string? CtxErr(params object?[] kv) => IntentV2.ContextError(IntentV2Context.FromJson(M(kv)));
    static D NoSession() => Build(G0, "salt0", MAP0, null, Params(), REF);

    [Fact]
    public void WithDefaultsKeepsThePresentParamsAndFillsMissingOrNull()
    {
        object? Defaulted(D ctx) => IntentV2Context.FromJson(ctx).WithDefaults(M("a", "op"), null).Get("params");
        Assert.Equal("host", IntentJs.Get(Defaulted(M("params", M("a", "host"))), "a") as string);
        Assert.Equal("op", IntentJs.Get(Defaulted(M()), "a") as string);
        Assert.Equal("op", IntentJs.Get(Defaulted(M("params", null)), "a") as string);
    }

    [Fact]
    public void ReviewersShapeReadsOnlyTheReviewersMember()
    {
        const string Bad = "reviewers must be {keys: [...]}";
        Assert.Null(CtxErr("", 1L)); // a member named by the empty string is not reviewers
        Assert.Null(CtxErr("reviewers", M("keys", Li())));
        Assert.Equal(Bad, CtxErr("reviewers", "x"));
        Assert.Equal(Bad, CtxErr("reviewers", M()));
        Assert.Equal(Bad, CtxErr("reviewers", M("keys", "x")));
    }

    [Fact]
    public void CallContextRefusesAnyNonStringEntry()
    {
        const string Bad = "call_context must be an array of strings";
        Assert.Equal(Bad, CtxErr("call_context", Li("a", 1L))); // one bad entry among good ones
        Assert.Equal(Bad, CtxErr("call_context", Li(1L)));
        Assert.Null(CtxErr("call_context", Li()));
        Assert.Null(CtxErr("call_context", Li("a", "b")));
    }

    [Theory]
    [InlineData("org")]
    [InlineData("site")]
    [InlineData("std")]
    public void EveryCeilingIsAnAllowSideListOfRule21(string layer)
    {
        var d = Decide(G0, NoSession(), IntentV2Context.FromJson(Ctx("layers", M(layer, M("predicates", ReadsPath("env.class.x"))))));
        Assert.Equal(Rule21Why("env.class.x"), ReasonOf(d, "tighten"));
    }

    [Fact]
    public void AGrantPredicateIsAnAllowSideListOfRule21()
    {
        var d = Decide(EnvGrant("predicates", ReadsPath("env.class.x")), NoSession(), IntentV2Context.FromJson(Ctx()));
        Assert.Equal(Rule21Why("env.class.x"), ReasonOf(d, "tighten"));
    }

    [Fact]
    public void ASingleSourceWorldIsModelDerivedForRule21()
    {
        var body = M("v", 1L, "kind", "pca-fact", "name", "fx", "subject", "skyair.example/bookings", "value", 1L, "t_obs", NOW, "oracle", "o1");
        var fact = new D(body) { ["sig"] = Sign("wb/o1", IntentJs.Message(OracleFacts.FactDomain, body)) };
        var world = M("name", "fx", "subject_path", "action.resource", "freshness_ms", 60_000L, "min_oracles", 1L, "max_faulty", 0L,
            "oracles", Li(M("kid", "o1", "pk", Pub("wb/o1")), M("kid", "o2", "pk", Pub("wb/o2")), M("kid", "o3", "pk", Pub("wb/o3"))));
        var p = Build(G0, "salt0", MAP0, Is0("facts", Li(OracleFacts.FactRef((D)IntentJs.Normalize(fact)!))), Params(), REF);
        var d = Decide(G0, p, IntentV2Context.FromJson(Ctx(
            "wb", M("artifacts", M("facts", Li(fact)), "policy", M("world", M("worlds", Li(world)))),
            "layers", M("site", M("predicates", ReadsPath("env.world.fx"))))));
        Assert.True(d.Checks.Single(c => c.Name == "facts").Ok);
        Assert.Equal(new List<string> { "fx" }, d.SingleSource);
        Assert.Equal(Rule21Why("env.world.fx"), ReasonOf(d, "tighten"));
    }

    [Fact]
    public void TightenRulesSeeTheActionAndTheHostEnv()
    {
        D Rule(string field, string value) => EnvGrant("tighten", Li(M("id", "a", "when", M("field", field, "op", "eq", "value", value), "signal", "deny")));
        const string Denied = "denied by tighten rule 'a'";
        Assert.Equal(Denied, ReasonOf(Decide(Rule("action.verb", "air.book"), NoSession(), IntentV2Context.FromJson(Ctx())), "tighten"));
        Assert.Equal(Denied, ReasonOf(Decide(Rule("env.risk", "high"), NoSession(), IntentV2Context.FromJson(Ctx("env", M("risk", "high")))), "tighten"));
        var other = Decide(Rule("env.risk", "high"), NoSession(), IntentV2Context.FromJson(Ctx("env", M("risk", "low"))));
        Assert.True(other.Checks.Single(c => c.Name == "tighten").Ok);
    }

    [Fact]
    public void UnitsCompareTheVerbDeclaredParams()
    {
        D Tagged(string currency) => EnvGrant("units", M("action.params.total", M("kind", "money", "currency", currency, "exponent", 2L)));
        var same = Decide(Tagged("USD"), NoSession(), IntentV2Context.FromJson(Ctx())).Checks.Single(c => c.Name == "units");
        Assert.True(same.Ok, same.Reason);
        Assert.Equal("'action.params.total' is declared as money/USD/e2 by the action schema but the policy term is tagged money/EUR/e2 (unit confusion)",
            ReasonOf(Decide(Tagged("EUR"), NoSession(), IntentV2Context.FromJson(Ctx())), "units"));
    }

    [Fact]
    public void NeedsModelRulesIsFalseWithoutAReadableEnvelope()
    {
        Assert.False(IntentV2.NeedsModelRules(M("id", "g")));
        Assert.False(IntentV2.NeedsModelRules(G0)); // an envelope with no risk_policy reads as none
    }

    [Theory]
    [InlineData("actions")]
    [InlineData("units")]
    [InlineData("tighten")]
    [InlineData("model_polarity")]
    public void NeedsModelRulesForEachSignedEnvelopeMember(string member) => Assert.True(IntentV2.NeedsModelRules(EnvGrant(member, Li())));

    [Fact]
    public void NeedsModelRulesFollowsModelDerivedGrantReads()
    {
        Assert.False(IntentV2.NeedsModelRules(EnvGrant()));
        Assert.False(IntentV2.NeedsModelRules(EnvGrant("predicates", ReadsPath("action.params.total"))));
        Assert.False(IntentV2.NeedsModelRules(EnvGrant("predicates", ReadsPath("env.world.fx")))); // no single-source set before W-B runs
        Assert.True(IntentV2.NeedsModelRules(EnvGrant("predicates", ReadsPath("env.class.x"))));
    }
}
