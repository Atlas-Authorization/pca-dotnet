using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>F2: the risk score, trust budget and threshold step-up (Risk.cs and the Authorize decision), ported from the reference risk.ts and policy VM.</summary>
public class K05F2Tests
{
    static readonly RiskPolicy Pol = new(0.25, 0.2, 0.2, 0.2, 0.1, 0.05, 0.25, 0.6, 1, 0.0005, 0.5, 1);
    static RiskInputs In(double sd = 0, double rev = 1, double bl = 0, double taint = 0, double conf = 1, double age = 0) => new(sd, rev, bl, taint, conf, age);

    // ================= kernel =================

    [Fact]
    public void ScoreIsTheWeightedSumClampedAndFailsClosedOnNonFinite()
    {
        Assert.Equal(0, Risk.Score(In(), Pol));
        Assert.Equal(1, Risk.Score(Risk.Worst, Pol), 12);
        Assert.Equal(0.25, Risk.Score(In(sd: 1), Pol), 12);
        Assert.Equal(0.2, Risk.Score(In(rev: 0), Pol), 12);
        Assert.Equal(0.2, Risk.Score(In(bl: 1), Pol), 12);
        Assert.Equal(0.2, Risk.Score(In(taint: 1), Pol), 12);
        Assert.Equal(0.1, Risk.Score(In(conf: 0), Pol), 12);
        Assert.Equal(0.05, Risk.Score(In(age: 1), Pol), 12);
        // out of range clamps; NaN is the worst case of that input; a negative weight counts as zero
        Assert.Equal(0.25, Risk.Score(In(sd: 7), Pol), 12);
        Assert.Equal(0, Risk.Score(In(sd: -3), Pol), 12);
        Assert.Equal(0.25, Risk.Score(In(sd: double.NaN), Pol), 12);
        Assert.Equal(0.2, Risk.Score(In(rev: double.NaN), Pol), 12);
        Assert.Equal(0.1, Risk.Score(In(conf: double.PositiveInfinity), Pol), 12);
        Assert.Equal(0, Risk.Score(In(sd: 1), Pol with { Alpha = -5 }), 12);
        Assert.Equal(1, Risk.Score(Risk.Worst, Pol with { Alpha = 9 }), 12);
    }

    [Fact]
    public void RequiredThresholdBandsAndEscalationNeverLower()
    {
        Assert.Equal(new RequiredThreshold(1, "claim", true), Risk.Required(0.25, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(1, "claim", false), Risk.Required(0, 0.25, 0.6, irreversible: true));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(0.2500001, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(0.6, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Required(0.61, 0.25, 0.6));
        Assert.Equal(3, Risk.Required(double.NaN, 0.25, 0.6).T);
        var one = Risk.Required(0, 0.25, 0.6);
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(one, 3));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Escalate(one, 2));
        Assert.Equal(one, Risk.Escalate(one, 1));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(new RequiredThreshold(3, "strong", false), 1));
        Assert.Equal("strong", Risk.Escalate(new RequiredThreshold(2, "strong", false), 2).Proof);
    }

    [Fact]
    public void BudgetLeaksDebitsRechargesAndAges()
    {
        var b = new TrustBudget(1, 0, 0);
        var l = Risk.Leak(b, 10_000, 0.0005);
        Assert.Equal(0.995, l.B, 12);
        Assert.Equal(10_000, l.AsOf);
        Assert.Equal(l, Risk.Leak(l, 10_000, 0.0005)); // idempotent at the same now
        Assert.Equal(0, Risk.Leak(b, 10_000_000, 0.0005).B);
        Assert.Equal(1, Risk.Leak(b, 5, -1).B); // a negative rate does not recharge
        Assert.Equal(0.5, Risk.Debit(b, 0.5).B);
        Assert.Equal(0, Risk.Debit(b, 7).B);
        Assert.Equal(1, Risk.Debit(b, -1).B);
        Assert.Equal(new TrustBudget(0.75, 99, 99), Risk.Recharge(new TrustBudget(0.25, 1), 0.5, 1, 99));
        Assert.Equal(1, Risk.Recharge(new TrustBudget(0.9, 1), 0.5, 1, 99).B);
        Assert.Equal(new TrustBudget(1, 5, 5), Risk.RechargeFull(1, 5));
        Assert.Equal(0.5, Risk.AgeSinceTouch(new TrustBudget(1, 0), 1_800_000), 12);
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, 0), 9_000_000));
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, 0), 100, 0));
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, double.NaN), 100));
        Assert.Equal(0.2, Risk.Cost(0.2, 1), 12);
        Assert.Equal(1, Risk.Cost(double.NaN, 1));
        Assert.Equal(0, Risk.Cost(0.5, -3));
    }

    [Fact]
    public void AdmissionAndTheReleaseDecision()
    {
        Assert.Equal(new Admission(true, false, 1, true), Risk.AdmitOf(1, true));
        Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(1, false));
        Assert.Equal(new Admission(false, true, 2, true), Risk.AdmitOf(2, true));
        Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(2, false));
        Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(3, true));
        Assert.Equal(new Admission(true, false, 1, true), Risk.Admit(0.2, new TrustBudget(0.2, 0), Pol));
        Assert.Equal(new Admission(false, true, 3, false), Risk.Admit(0.2, new TrustBudget(0.19, 0), Pol));
        var rt = Risk.Required(0, 0.25, 0.6);
        var d = Risk.DecideCore(true, true, true, true, rt, Risk.AdmitOf(1, true));
        Assert.Equal(new CoreDecision(true, true, false, rt, true), d);
        var d2 = Risk.DecideCore(true, true, true, true, rt, Risk.AdmitOf(2, true));
        Assert.True(d2.Release && !d2.Admit && d2.NeedStepUp && d2.Debit && d2.Threshold.T == 2);
        foreach (var bad in new[] { (false, true, true, true), (true, false, true, true), (true, true, false, true), (true, true, true, false) })
        {
            var x = Risk.DecideCore(bad.Item1, bad.Item2, bad.Item3, bad.Item4, rt, Risk.AdmitOf(1, true));
            Assert.True(!x.Release && !x.Admit && x.NeedStepUp && !x.Debit);
        }
        Assert.Equal(1, Risk.SafetyBound(1, 1));
        Assert.Equal(0, Risk.SafetyBound(1, 0));
        Assert.Equal(5, Risk.SafetyBound(10, 2));
    }

    [Fact]
    public void SubBudgetsAndConsolidatedDebits()
    {
        var parent = new TrustBudget(1, 3, 4);
        Assert.Equal(new TrustBudget(0.5, 3, 4), Risk.SubBudget(parent, 0.5).Nodes![0]);
        Assert.Equal("allocation must be finite and >= 0", Risk.SubBudget(parent, -1).Reason);
        Assert.Equal("allocation must be finite and >= 0", Risk.SubBudget(parent, double.NaN).Reason);
        Assert.Equal("allocation exceeds parent remaining budget", Risk.SubBudget(parent, 1.5).Reason);
        Assert.Equal("sub-agent budget insufficient", Risk.DebitConsolidated(parent, new TrustBudget(0.1, 0), 0.2).Reason);
        Assert.Equal("parent budget insufficient", Risk.DebitConsolidated(new TrustBudget(0.1, 0), new TrustBudget(1, 0), 0.2).Reason);
        var ok = Risk.DebitConsolidated(parent, new TrustBudget(0.5, 0), 0.25);
        Assert.Equal(new[] { 0.75, 0.25 }, ok.Nodes!.Select(n => n.B).ToArray());
        Assert.Equal("budget node at depth 1 insufficient (need 0.6, have 0.5)", Risk.DebitConsolidatedPath(new[] { parent, new TrustBudget(0.5, 0) }, 0.6).Reason);
        Assert.Equal(new[] { 0.5, 0.25 }, Risk.DebitConsolidatedPath(new[] { parent, new TrustBudget(0.75, 0) }, 0.5).Nodes!.Select(n => n.B).ToArray());
    }

    [Fact]
    public void PlanGeodesicFollowsTheCommittedEdges()
    {
        JL Plan(params (string id, object? pre, object? post)[] ns) => ns.Select(n => (object?)new JD { ["id"] = n.id, ["pre"] = n.pre, ["post"] = n.post }).ToList();
        var chain = Plan(("a", null, null), ("b", "a", null), ("c", new JL { "b" }, null), ("d", null, null));
        Assert.Equal(0, Risk.PlanGeodesic(chain, "b", "b"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(chain, "a", "b"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(chain, "a", "c"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(chain, "c", "a"), 12); // undirected
        Assert.Equal(1, Risk.PlanGeodesic(chain, "a", "d")); // unreachable
        Assert.Equal(1, Risk.PlanGeodesic(chain, "a", "zzz"));
        Assert.Equal(1, Risk.PlanGeodesic(chain, null, "a"));
        Assert.Equal(1, Risk.PlanGeodesic("nope", "a", "b"));
        var bare = Plan(("a", null, null), ("b", null, null), ("c", null, null));
        Assert.Equal(1.0, Risk.PlanGeodesic(bare, "a", "c"), 12);
        Assert.Equal(0.5, Risk.PlanGeodesic(bare, "a", "b"), 12);
        var post = Plan(("a", null, new JD { ["before"] = "b" }), ("b", null, null));
        Assert.Equal(1, Risk.PlanGeodesic(post, "a", "b"));
    }

    [Fact]
    public void ToFixed3RoundsLikeJavaScript()
    {
        Assert.Equal("0.063", Risk.ToFixed3(0.0625));
        Assert.Equal("0.500", Risk.ToFixed3(0.5));
        Assert.Equal("1.000", Risk.ToFixed3(1));
        Assert.Equal("0.700", Risk.ToFixed3(0.7000000000000001));
    }

    // ================= through Authorize =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_f2";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x51, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x52, 32).ToArray()));
    static JD Amt() => new() { ["amount"] = 5L };
    static JD Grant() => Issue.MintGrant(P, Me.Id!, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "f2").Grant;
    static JD Act(JD grant, JD? slots = null) => new Agent(Me, Aud, grant, null, 0) { Clock = () => Now }.Act("pay", "inv/1", Amt(), slots);

    static AuthorizeResult Run(JD grant, JD pcactn, Action<AuthorizeInput>? cfg = null, IStateStore? store = null)
    {
        var g = Issue.NormJ(grant);
        var i = new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step",
        };
        cfg?.Invoke(i);
        i.ServerRisk ??= new Dictionary<string, double>(); // no server risk: every input is its worst case (WithProv would otherwise fill in the low-risk harness)
        return Pca.Authorize(Issue.Encode(pcactn), i.WithProv());
    }

    static Action<AuthorizeInput> Risky(params (string k, double v)[] over) => i => i.ServerRisk = ProvHarness.LowRisk.ToDictionary(kv => kv.Key, kv => kv.Value).Also(d => { foreach (var (k, v) in over) d[k] = v; });

    [Fact]
    public void ALowRiskActionIsAdmittedAndTheBudgetIsPersistedOnlyOnAnAllow()
    {
        var g = Grant();
        var store = new MemoryStateStore();
        var r = Run(g, Act(g), i => i.ServerRisk = ProvHarness.LowRisk, store);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal(0, r.RiskScore);
        Assert.Equal(1, r.RequiredThreshold!.T);
        Assert.Equal("pass", r.Checks["budget"]);
        Assert.Equal("not-enforced", r.Checks["threshold"]);
        var key = $"aud:{Aud}:{(string)g["id"]!}:{Me.Id}:budget";
        Assert.Equal(new TrustBudget(1, Now, Now), store.Budget(key));
        // a denied call leaves the stored budget alone
        var g2 = Grant();
        var s2 = new MemoryStateStore();
        var denied = Run(g2, Act(g2), null, s2);
        Assert.False(denied.Allow);
        Assert.Null(s2.Budget($"aud:{Aud}:{(string)g2["id"]!}:{Me.Id}:budget"));
    }

    [Fact]
    public void MissingServerRiskIsTheWorstCaseAndStepsUpToT3()
    {
        var g = Grant();
        var r = Run(g, Act(g));
        Assert.False(r.Allow);
        Assert.Equal(3, r.RequiredThreshold!.T);
        Assert.Equal("fail", r.Checks["threshold"]);
        Assert.Contains("policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence", r.Reasons);
        Assert.Contains("policy: risk 0.700 exceeds auto threshold: step-up to t=3", r.Reasons);
        Assert.Contains("threshold: t=3 (strong) required but no threshold verifier is enforced", r.Reasons);
        Assert.Equal(0.7, r.RiskScore!.Value, 9);
    }

    [Fact]
    public void TheThresholdHookMustEnforceAtLeastTheServerDerivedT()
    {
        var g = Grant();
        var pc = Act(g);
        ThresholdHookResult? Hook(double? t, bool ok = true, bool enforced = true) => new(enforced, ok, t, ok ? null : "nope");
        var good = Run(g, pc, i => i.ThresholdHook = (_, _) => Hook(3));
        Assert.True(good.Allow, good.Reason);
        Assert.Equal("pass", good.Checks["threshold"]);
        var g2 = Grant();
        var low = Run(g2, Act(g2), i => i.ThresholdHook = (_, _) => Hook(2));
        Assert.False(low.Allow);
        Assert.Contains("threshold: threshold hook enforced t=2 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)", low.Reasons);
        var g3 = Grant();
        var silent = Run(g3, Act(g3), i => i.ThresholdHook = (_, _) => Hook(null));
        Assert.Contains("threshold: threshold hook enforced t=unreported but the server requires t=3 (below the server-derived threshold; derive t from server-held data)", silent.Reasons);
        var g4 = Grant();
        var rej = Run(g4, Act(g4), i => i.ThresholdHook = (_, _) => Hook(3, ok: false));
        Assert.False(rej.Allow);
        Assert.Contains("threshold: nope", rej.Reasons);
        Assert.Contains("threshold: t=3 required and the threshold proof was rejected", rej.Reasons);
        var g4b = Grant();
        var fractional = Run(g4b, Act(g4b), i => i.ThresholdHook = (_, _) => Hook(1.9));
        Assert.Contains("threshold: threshold hook enforced t=1.9 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)", fractional.Reasons);
        var g4c = Grant();
        var nan = Run(g4c, Act(g4c), i => i.ThresholdHook = (_, _) => Hook(double.NaN));
        Assert.False(nan.Allow);
        Assert.Contains("threshold: threshold hook enforced t=NaN but the server requires t=3 (below the server-derived threshold; derive t from server-held data)", nan.Reasons);
        var g4d = Grant();
        var bare = Run(g4d, Act(g4d), i => i.ThresholdHook = (_, _) => new ThresholdHookResult(true, false));
        Assert.Contains("threshold: rejected", bare.Reasons);
        var g5 = Grant();
        var thrown = Run(g5, Act(g5), i => i.ThresholdHook = (_, _) => throw new InvalidOperationException("x"));
        Assert.False(thrown.Allow);
        Assert.Contains("threshold: threshold hook error (fail closed)", thrown.Reasons);
        var g6 = Grant();
        var notEnforced = Run(g6, Act(g6), i => i.ThresholdHook = (_, _) => Hook(3, enforced: false));
        Assert.False(notEnforced.Allow);
        Assert.Equal("fail", notEnforced.Checks["threshold"]);
    }

    [Fact]
    public void AMidRiskActionNeedsT2AndAnExhaustedBudgetStepsUpToT3()
    {
        var g = Grant();
        var mid = Run(g, Act(g), Risky(("taint", 1), ("blastRadius", 1)));
        Assert.False(mid.Allow);
        Assert.Equal(2, mid.RequiredThreshold!.T);
        Assert.Contains("threshold: t=2 (standard) required but no threshold verifier is enforced", mid.Reasons);
        var g2 = Grant();
        var ok2 = Run(g2, Act(g2), i => { Risky(("taint", 1), ("blastRadius", 1))(i); i.ThresholdHook = (_, _) => new ThresholdHookResult(true, true, 2); });
        Assert.True(ok2.Allow, ok2.Reason);
        Assert.Equal(0.6, ok2.Budget!.B, 9); // t=2 is metered: kappa * r = 0.4 debited from 1
        var g3 = Grant();
        var depleted = Run(g3, Act(g3), i =>
        {
            Risky(("taint", 1))(i);
            i.Context = _ => new JD { ["budget"] = new JD { ["B"] = 0.1, ["tau"] = Now, ["asOf"] = Now } };
        });
        Assert.False(depleted.Allow);
        Assert.Contains("policy: trust budget depleted: human recharge required", depleted.Reasons);
        Assert.Equal(3, depleted.RequiredThreshold!.T);
    }

    [Fact]
    public void ASignedCautionCanOnlyRaiseTheRisk()
    {
        var g = Grant();
        var plain = Run(g, Act(g), i => i.ServerRisk = ProvHarness.LowRisk);
        Assert.True(plain.Allow);
        var g2 = Grant();
        var raised = Run(g2, Act(g2, new JD { ["caution"] = new Num("0.9") }), i => i.ServerRisk = ProvHarness.LowRisk);
        Assert.False(raised.Allow);
        Assert.Equal(0.9, raised.RiskScore!.Value, 9);
        Assert.Equal(3, raised.RequiredThreshold!.T);
    }

    [Fact]
    public void RequiredRiskInputsAndTheAdaptivePolicy()
    {
        var g = Grant();
        var lacking = Run(g, Act(g), i => { i.ServerRisk = new Dictionary<string, double> { ["semanticDistance"] = 0 }; i.RequireRiskInputs = new[] { "taint", "blastRadius" }; });
        Assert.Equal("fail", lacking.Checks["risk_inputs"]);
        Assert.Contains("risk_inputs: required risk input(s) not supplied by the server: taint, blastRadius", lacking.Reasons);
        var g2 = Grant();
        var supplied = Run(g2, Act(g2), i => { i.ServerRisk = ProvHarness.LowRisk; i.RequireRiskInputs = new[] { "taint", "blastRadius", "age" }; });
        Assert.Equal("pass", supplied.Checks["risk_inputs"]);
        var g3 = Grant();
        var plan = Run(g3, Act(g3), i => { i.ServerRisk = new Dictionary<string, double>(); i.RequireRiskInputs = new[] { "semanticDistance" }; });
        Assert.Equal("pass", plan.Checks["risk_inputs"]); // the committed plan supplies the distance
        var g4 = Grant();
        var tight = Run(g4, Act(g4), i => { Risky(("reversibility", 0.5))(i); i.Adaptive = Pol with { Theta1 = 0, Theta2 = 0 }; });
        Assert.False(tight.Allow);
        Assert.Contains("adaptive: tightened policy requires threshold t=3 (grant policy: t=1)", tight.Reasons);
        var g5 = Grant();
        Assert.True(Run(g5, Act(g5), i => { i.ServerRisk = ProvHarness.LowRisk; i.Adaptive = Pol; }).Allow);
    }

    [Fact]
    public void TheAdaptivePolicyDelegateTakesTheTimeAndIsValidated()
    {
        long seen = 0;
        var g = Grant();
        var tight = Run(g, Act(g), i => { Risky(("reversibility", 0.5))(i); i.AdaptivePolicy = t => { seen = t; return Pol with { Theta1 = 0, Theta2 = 0 }; }; });
        Assert.Equal(Now, seen);
        Assert.Contains("adaptive: tightened policy requires threshold t=3 (grant policy: t=1)", tight.Reasons);
        var g2 = Grant();
        var json = Run(g2, Act(g2), i => { i.ServerRisk = ProvHarness.LowRisk; i.AdaptivePolicy = _ => new JD { ["weights"] = new JD(), ["theta1"] = 0L }; });
        Assert.Contains("adaptive: invalid policy (risk_policy.weights.alpha must be finite and >= 0)", json.Reasons);
        Assert.False(json.Allow);
        var g3 = Grant();
        Assert.True(Run(g3, Act(g3), i => { i.ServerRisk = ProvHarness.LowRisk; i.AdaptivePolicy = _ => null; }).Allow);
        var g4 = Grant();
        var thrown = Run(g4, Act(g4), i => { i.ServerRisk = ProvHarness.LowRisk; i.AdaptivePolicy = _ => throw new InvalidOperationException("x"); });
        Assert.False(thrown.Allow);
        Assert.Contains("authorize: error (fail closed): x", thrown.Reasons);
    }

    [Fact]
    public void AFailingBudgetStoreDeniesAfterTheClaim()
    {
        var g = Grant();
        var r = Run(g, Act(g), i => i.ServerRisk = ProvHarness.LowRisk, new RefusingBudget());
        Assert.False(r.Allow);
        Assert.Equal("budget: the budget store refused the update (changed concurrently or failed): fail closed", r.Reason);
    }

    sealed class RefusingBudget : IStateStore, IBudgetStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
        public TrustBudget? Budget(string key) => null;
        public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new) => false;
    }
}
