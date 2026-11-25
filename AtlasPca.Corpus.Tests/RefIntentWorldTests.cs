using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the intent world / provenance / classifier dimensions against the TypeScript reference (test-data/ref-intent-world.json.gz).</summary>
public class RefIntentWorldTests
{
    const string M = "ref-intent-world";

    static IEnumerable<double> Nums(object? o) => ((L)o!).Select(Dbl);

    [Fact]
    public void WorldDimFn() => Base.Check(M, "worldDim", a =>
    {
        var s = (D)a[1]!;
        return DimToJson(IntentWorld.WorldDim((string)a[0]!, Dbl(s["lo"]), Dbl(s["hi"]), s.TryGetValue("cuts", out var c) ? Nums(c) : null, s.GetValueOrDefault("dist") as string));
    });

    [Fact] public void ExcessDimFn() => Base.Check(M, "excessDim", a => DimToJson(IntentWorld.ExcessDim((string)a[0]!, Dbl(a[1]), Nums(a[2]))));
    [Fact] public void OptimalityConditionFn() => Base.Check(M, "optimalityCondition", a => IntentWorld.OptimalityCondition((string)a[0]!, a.Count > 1 ? Dbl(a[1]) : 0));
    [Fact] public void ProvenanceDimFn() => Base.Check(M, "provenanceDim", a => DimToJson(IntentWorld.ProvenanceDim((string)a[0]!)));
    [Fact] public void ClassifierDimFn() => Base.Check(M, "classifierDim", a => DimToJson(IntentWorld.ClassifierDim((string)a[0]!, ((L)a[1]!).Select(x => (string)x!))));
    [Fact] public void WithDimsFn() => Base.Check(M, "withDims", a => OmegaToJson(IntentWorld.WithDims(OmegaFromJson(a[0]), (string)a[1]!, ((L)a[2]!).Select(DimFromJson).ToList())));
    [Fact] public void LiftOutcomeFn() => Base.Check(M, "liftOutcome", a => OutcomeToJson(IntentWorld.LiftOutcome(OutcomeFromJson(a[0]), (D)a[1]!, ((L)a[2]!).Select(x => (string)x!))));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "worldDim", "excessDim", "optimalityCondition", "provenanceDim", "classifierDim", "withDims", "liftOutcome" }); Assert.Equal(52, Base.Total(M)); }
}
