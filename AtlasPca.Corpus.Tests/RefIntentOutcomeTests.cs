using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of outcome verification and the Monte Carlo residual-risk estimate against the TypeScript reference
/// (test-data/ref-intent-outcome.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentOutcomeTests
{
    const string M = "ref-intent-outcome";

    [Fact]
    public void VerifyScenarioFn() => Base.Check(M, "verifyScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var result = IntentOutcome.VerifyOutcome(l, OutcomeFromJson(a[3]), (D)a[4]!, a.Count > 5 ? (L)a[5]! : null);
        return new D { ["result"] = result, ["metrics"] = RefIntentLearnerTests.Met(l.Metrics()) };
    });

    [Fact]
    public void McScenarioFn() => Base.Check(M, "mcScenario", a => N(IntentOutcome.EstimateResidualRiskMC(RefIntentRampTests.Make(a[0], a[1], a[2]), (int)Dbl(a[3]), Dbl(a[4]))));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "verifyScenario", "mcScenario" }); Assert.Equal(79, Base.Total(M)); }
}
