using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the policy debugger over test-data/ref-policy-debug.json.gz: the risk decomposition, the decision explanation, the counterfactual edits and the audit of a
/// PCActn (the verifier's per-check table beside the explanation). A non-finite number is {"$num": text} in the corpus and a double here.</summary>
public class RefPolicyDebugTests
{
    const string M = "ref-policy-debug";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? Out(object? v) => v switch
    {
        double d when double.IsNaN(d) => new D { ["$num"] = "NaN" },
        double d when double.IsPositiveInfinity(d) => new D { ["$num"] = "Infinity" },
        double d when double.IsNegativeInfinity(d) => new D { ["$num"] = "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Out(e.Value)),
        L l => l.Select(Out).ToList(),
        _ => v,
    };

    [Fact] public void ExplainRisk() => Base.Check(M, "explainRisk", a => Out(PolicyDebug.ExplainRisk(Nums(a[0]), Nums(a[1]), a.Count > 2 ? Nums(a[2]) : null)), min: 315);
    [Fact] public void ExplainDecision() => Base.Check(M, "explainDecision", a => Out(PolicyDebug.ExplainDecision(Nums(a[0]))), min: 140);
    [Fact] public void ApplyDelta() => Base.Check(M, "applyDelta", a => Out(PolicyDebug.ApplyDelta(Nums(a[0]), Nums(a[1]))), min: 63);
    [Fact] public void Counterfactual() => Base.Check(M, "counterfactual", a => Out(PolicyDebug.Counterfactual(Nums(a[0]), Nums(a[1]))), min: 26);

    // the options the corpus uses: grant, nowEpoch, audience (null = the explicit opt-out, absent = none given), insecureSkipPlanRootCheck
    static PcaCore.Options Options(D j)
    {
        Assert.True(j.Keys.All(k => k is "grant" or "nowEpoch" or "audience" or "insecureSkipPlanRootCheck"), "unexpected audit option: " + string.Join(",", j.Keys));
        var o = new PcaCore.Options((D)j["grant"]!);
        if (j.ContainsKey("nowEpoch")) o.NowEpoch = IntentJs.Lng(j["nowEpoch"]);
        if (j.ContainsKey("audience")) { if (j["audience"] == null) o.AudienceAny(); else o.WithAudience((string)j["audience"]!); }
        o.PlanRoots = new PlanRootPolicy(null, j.GetValueOrDefault("insecureSkipPlanRootCheck") is true);
        return o;
    }

    [Fact]
    public void AuditPCActn() => Base.Check(M, "auditPCActn", a =>
    {
        var audit = PolicyDebug.AuditPCActn(a[0], Nums(a[1]), Options((D)a[2]!));
        var v = new D { ["allow"] = audit.Verify.Allow, ["checks"] = audit.Verify.Checks.ToDictionary(kv => kv.Key, kv => (object?)kv.Value) };
        if (audit.Verify.Reason != null) v["reason"] = audit.Verify.Reason;
        return new D { ["verify"] = v, ["explanation"] = Out(audit.Explanation) };
    }, min: 9);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "explainRisk", "explainDecision", "applyDelta", "counterfactual", "auditPCActn" });
        Assert.Equal(553, Base.Total(M));
    }
}
