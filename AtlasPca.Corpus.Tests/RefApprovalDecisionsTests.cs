using AtlasPca.InteropJs;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Standing class approvals, decision records and the human co-sign budget effect, replayed against the reference.</summary>
public class RefApprovalDecisionsTests
{
    const string M = "ref-core-approvals-decisions-dotnet";

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("expected number");

    [Fact]
    public void ApproveClass() => Base.Check(M, "approveClass", a =>
    {
        var o = (D)a[1]!;
        return Approvals.ApproveClass(((L)a[0]!).Select(v => (string)v!).ToList(), Dbl(o["ttlMs"]), (string)o["by"]!, Dbl(o["now"]), o.GetValueOrDefault("resource") as string);
    });

    [Fact] public void RecordDecision() => Base.Check(M, "recordDecision", a => Approvals.RecordDecision((D)a[0]!, (string)a[1]!, (string)a[2]!, Dbl(a[3])));

    [Fact]
    public void ApplyCosign() => Base.Check(M, "applyCosign", a =>
    {
        var b = (D)a[0]!; var p = (D)a[1]!;
        var bud = new TrustBudget(Dbl(b["B"]), Dbl(b["tau"]), b.ContainsKey("asOf") ? Dbl(b["asOf"]) : null);
        var pol = new RiskPolicy(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, Dbl(p["rho"]), Dbl(p["bMax"]));
        var r = Approvals.ApplyCosign(bud, pol, Dbl(a[2]), ((D)a[3]!).GetValueOrDefault("full") is true);
        return new D { ["B"] = JsX.Number(r.B), ["tau"] = JsX.Number(r.Tau), ["asOf"] = JsX.Number(r.AsOf!.Value) };
    });

    [Fact] public void EveryFn() { Base.Covers(M, new[] { "approveClass", "recordDecision", "applyCosign" }); Assert.Equal(68, Base.Total(M)); }
}
