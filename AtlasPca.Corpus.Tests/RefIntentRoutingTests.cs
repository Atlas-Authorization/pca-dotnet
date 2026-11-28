using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of bond sizing, the semantic judge threshold, routing and the intent-conformance attestation against the TypeScript
/// reference (test-data/ref-intent-routing.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentRoutingTests
{
    const string M = "ref-intent-routing";

    static object? Inf(double x) => double.IsFinite(x) ? N(x) : "inf";

    static IntentLearner Make(L a)
    {
        var l = IntentMapKit.CreateLearner(OmegaFromJson(a[0]), IntentMapKit.MapLearnerOptions.FromJson(a[1]));
        foreach (var xo in (L)a[2]!)
        {
            var x = (D)xo!;
            l.Observe(OutcomeFromJson(x), (int)Dbl(x["y"]), (string)x["source"]!, null);
        }
        return l;
    }

    [Fact] public void BondAmountFn() => Base.Check(M, "bondAmount", a => N(IntentBond.BondAmount(IntentBond.BondPolicy.FromJson(a[0]), Dbl(a[1]))));
    [Fact] public void QuantizeScoreFn() => Base.Check(M, "quantizeScore", a => N(IntentSemantic.QuantizeScore(Dbl(a[0]))));

    [Fact]
    public void VerifyJudgeVerdictFn() => Base.Check(M, "verifyJudgeVerdict", a =>
    {
        var e = (D)a[1]!;
        var pins = a[2] is D o ? o.GetValueOrDefault("pqPins") as D : null;
        return IntentSemantic.VerifyJudgeVerdict(a[0], e.GetValueOrDefault("actionDigest") as string, e.GetValueOrDefault("goalCommitment") as string, pins);
    });

    [Fact] public void ConformalThresholdFn() => Base.Check(M, "conformalThreshold", a => Inf(IntentSemantic.ConformalThreshold(a[0])));
    [Fact] public void EmpiricalFalseAllowRateFn() => Base.Check(M, "empiricalFalseAllowRate", a => N(IntentSemantic.EmpiricalFalseAllowRate(a[0], Dbl(a[1]))));

    [Fact]
    public void VerifySemanticThresholdFn() => Base.Check(M, "verifySemanticThreshold", a =>
    {
        var t = IntentSemantic.VerifySemanticThreshold(a[0], (D)a[1]!);
        var r = t.ToJson();
        if (t.Cutoff != null) r["cutoff"] = Inf(t.Cutoff.Value);
        return r;
    });

    static object? Route(L a, bool veto)
    {
        var l = Make(a);
        var ro = IntentRouting.RouteOptions.FromJson(a[4]);
        if (veto) foreach (var x in (L)a[3]!) l.Observe(OutcomeFromJson(x), 0, "runtime", null);
        return ((L)a[3]!).Select(x => (object?)IntentRouting.RouteAction(l, OutcomeFromJson(x), ro)).ToList();
    }

    [Fact] public void RouteScenarioFn() => Base.Check(M, "routeScenario", a => Route(a, false));
    [Fact] public void RouteVetoScenarioFn() => Base.Check(M, "routeVetoScenario", a => Route(a, true));

    static void Add(D m, string key, double d) => m[key] = new Num(((long)(Dbl(m[key]) + d)).ToString(System.Globalization.CultureInfo.InvariantCulture));

    static readonly List<Action<D>> Muts = new()
    {
        m => { },
        m => m["ok"] = !(bool)m["ok"]!,
        m => Add(m, "aggregate_score_ppm", 1),
        m => { var d = (L)m["verdict_digests"]!; if (d.Count > 0) d.RemoveAt(d.Count - 1); },
        m => Add(m, "k", 1),
        m => m["reason"] = "x",
    };

    [Fact]
    public void ConformanceScenarioFn() => Base.Check(M, "conformanceScenario", a =>
    {
        var l = Make(a);
        var input = IntentRouting.JudgeInputOf(l, OutcomeFromJson(a[3]), (D)a[4]!);
        var verdicts = (L)a[5]!;
        var copts = (D)a[6]!;
        var att = IntentRouting.IntentConformanceAttestation(input, verdicts, copts);
        var tampered = new L();
        foreach (var f in Muts)
        {
            var copy = (D)IntentJs.Normalize(att)!;
            f(copy);
            tampered.Add(IntentRouting.VerifyIcAtt(copy, input, verdicts, copts));
        }
        tampered.Add(IntentRouting.VerifyIcAtt(att, input, verdicts.Skip(Math.Min(1, verdicts.Count)).ToList(), copts));
        return new D
        {
            ["input"] = input, ["att"] = att, ["digest"] = IntentRuntime.IcAttDigest(att), ["verify"] = IntentRouting.VerifyIcAtt(att, input, verdicts, copts),
            ["tampered"] = tampered, ["check"] = IntentRouting.CheckIntentConformance(_ => verdicts, input, copts),
        };
    });

    [Fact]
    public void JitScenarioFn() => Base.Check(M, "jitScenario", a =>
    {
        var l = Make(a);
        var oc = OutcomeFromJson(a[3]);
        var c = (D)a[5]!;
        var req = IntentRouting.JitConsentRequest(l, oc, c.GetValueOrDefault("intentRef") as string, c.GetValueOrDefault("mapDigest") as string);
        return new D
        {
            ["req"] = req, ["digest"] = IntentRuntime.JitConsentDigest(req), ["result"] = IntentRouting.RecordJitDecision(l, req, a[4] as string),
            ["metrics"] = RefIntentLearnerTests.Met(l.Metrics()), ["route"] = IntentRouting.RouteAction(l, oc, new IntentRouting.RouteOptions()),
        };
    });

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "bondAmount", "quantizeScore", "verifyJudgeVerdict", "conformalThreshold", "empiricalFalseAllowRate", "verifySemanticThreshold",
        "routeScenario", "routeVetoScenario", "conformanceScenario", "jitScenario",
    }); Assert.Equal(849, Base.Total(M)); }
}
