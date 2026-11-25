using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of provenance banners, the friction floor and within-grant regret against the TypeScript reference
/// (test-data/ref-intent-provenance.json.gz). The admission and utility functions are named in the case and bound here.</summary>
public class RefIntentProvenanceTests
{
    const string M = "ref-intent-provenance";
    const string A = "action.params.";

    static double Amt(Outcome x) => x.Values.TryGetValue(A + "amount", out var v) && v is double d ? d : 0;

    static IntentProvenance.RegretCase Bind(object? o)
    {
        var c = (D)o!;
        Func<Outcome, bool> admits = (string)c["admits"]! switch
        {
            "all" => _ => true,
            "none" => _ => false,
            "amountLe50" => x => Amt(x) <= 50,
            "verbRefund" => x => x.Verb == "stripe.refund",
            var n => throw new InvalidOperationException("unknown admits " + n),
        };
        Func<Outcome, double> utility = (string)c["utility"]! switch
        {
            "amount" => x => Amt(x),
            "negAmount" => x => -Amt(x),
            "zero" => _ => 0,
            "nan" => _ => double.NaN,
            "amountPlusPrefer" => x => Amt(x) + (x.Values.TryGetValue(A + "recipient", out var r) && r is "bob" ? 1000 : 0),
            var n => throw new InvalidOperationException("unknown utility " + n),
        };
        return new IntentProvenance.RegretCase(((L)c["feasible"]!).Select(OutcomeFromJson).ToList(), OutcomeFromJson(c["chosen"]), admits, utility);
    }

    [Fact] public void ProvenanceBannerFn() => Base.Check(M, "provenanceBanner", a => IntentProvenance.ProvenanceBanner((string)a[0]!, a.Count > 1 ? (string?)a[1] : null));
    [Fact] public void IsTaintedFn() => Base.Check(M, "isTainted", a => IntentProvenance.IsTainted((string)a[0]!));
    [Fact] public void ProvenanceFrictionFn() => Base.Check(M, "provenanceFriction", a => IntentProvenance.ProvenanceFriction((string)a[0]!, (string)a[1]!, (string)a[2]!));

    [Fact]
    public void RegretFn() => Base.Check(M, "regret", a => IntentProvenance.WithinGrantRegret(Bind(a[0])));

    [Fact]
    public void ReportFn() => Base.Check(M, "report", a => IntentProvenance.RegretReport(((L)a[0]!).Select(Bind).ToList(), a.Count > 1 ? Dbl(a[1]) : 1));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "provenanceBanner", "isTainted", "provenanceFriction", "regret", "report" }); Assert.Equal(267, Base.Total(M)); }
}
