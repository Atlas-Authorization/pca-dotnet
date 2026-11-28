// Checking an executed action's effect against its postconditions and feeding a violation back, and the Monte Carlo form of the residual-risk estimate.
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentOutcome
{
    /// <summary>Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the action's cell; ok and
    /// pending change nothing. pcs null = the default postconditions. Returns {report, divergence?}.</summary>
    public static D VerifyOutcome(IntentLearner l, Outcome o, D effect, IEnumerable<object?>? pcs = null)
    {
        var vs = l.Omega.Verbs.Find(v => v.Verb == o.Verb) ?? throw new ArgumentException("verifyOutcome: no verb " + o.Verb + " in Ω");
        var report = IntentEffects.CheckPostconditions(vs, o, effect, pcs);
        var r = new D { ["report"] = report };
        if ((report["status"] as string) == "violated") r["divergence"] = IntentMapKit.ApplyDivergence(l, o, 0);
        return r;
    }

    /// <summary>The Monte Carlo residual-risk estimate of the learner's grant over samples draws (default 20000) with the seeded generator (default 7).</summary>
    public static double EstimateResidualRiskMC(IntentLearner l, int? samples = null, double? seed = null)
    {
        int m = samples ?? 20_000;
        var rand = Rng(seed ?? 7);
        var syn = l.Synthesize();
        var grant = new D { ["predicates"] = syn.Predicates.Select(x => (object?)x).ToList(), ["caveats"] = syn.Caveats.Select(x => (object?)x).ToList() };
        var g = IntentPolicyKit.MakeAdmitter(grant);
        double r = 0;
        for (int i = 0; i < m; i++)
        {
            var s = SampleOutcome(l.Omega, rand);
            if (g.Admits(s.Vs, s.O)) r += (1 - l.Acceptance(s.O)) * HarmOf(s.Vs, s.O, l.Harm);
        }
        return r / m;
    }
}
