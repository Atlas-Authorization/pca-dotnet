using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of trajectory intent (augmented space, lift, step rule, default accumulators, fact lines) against the TypeScript reference
/// (test-data/ref-intent-trajectory.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentTrajectoryTests
{
    const string M = "ref-intent-trajectory";

    static object? SchemaOf(L a, int i) => a.Count > i ? a[i] : null;

    [Fact] public void DimKindOfFn() => Base.Check(M, "dimKindOf", a => IntentTrajectory.DimKindOf((string)a[0]!));
    [Fact] public void AccDimPathFn() => Base.Check(M, "accDimPath", a => IntentTrajectory.AccDimPath((string)a[0]!));
    [Fact] public void MonDimPathFn() => Base.Check(M, "monDimPath", a => IntentTrajectory.MonDimPath((string)a[0]!));
    [Fact] public void TrajectoryHarmRangeFn() => Base.Check(M, "trajectoryHarmRange", a => N(IntentTrajectory.TrajectoryHarmRange(Dbl(a[0]), Dbl(a[1]))));

    [Fact]
    public void AugmentFn() => Base.Check(M, "augment", a => IntentOmega.OmegaToJson(IntentTrajectory.AugmentOmega(OmegaFromJson(a[0]), (D)a[1]!, a.Count > 2 ? (D)a[2]! : null)));

    [Fact]
    public void LiftScenarioFn() => Base.Check(M, "liftScenario", a =>
    {
        var tilde = IntentTrajectory.AugmentOmega(OmegaFromJson(a[0]), (D)a[1]!, (D)a[2]!);
        var lifted = IntentTrajectory.LiftAction(tilde, (D)a[1]!, (L)a[3]!, (D)a[4]!, SchemaOf(a, 5));
        var c = lifted == null ? null : IntentTrajectory.LiftedCellOf(tilde, lifted);
        return new D
        {
            ["lifted"] = lifted == null ? null : OutcomeToJson(lifted),
            ["cell"] = c == null ? null : new D { ["verb"] = c.Vs.Verb, ["cell"] = RefIntentLearnerTests.Ints(c.Cell) },
        };
    });

    static Func<string, int[], bool> Grant(string g) => g switch
    {
        "all" => (v, c) => true,
        "none" => (v, c) => false,
        "cell0" => (v, c) => c.All(x => x == 0),
        _ => (v, c) => c[0] <= 1,
    };

    [Fact]
    public void StepScenarioFn() => Base.Check(M, "stepScenario", a =>
    {
        var tilde = IntentTrajectory.AugmentOmega(OmegaFromJson(a[0]), (D)a[1]!, (D)a[2]!);
        var s = IntentTrajectory.StepTrajectory(tilde, (D)a[1]!, (L)a[3]!, (D)a[4]!, Grant((string)a[5]!), SchemaOf(a, 6));
        return new D { ["admitted"] = s.Admitted, ["history"] = s.History, ["lifted"] = s.Lifted == null ? null : OutcomeToJson(s.Lifted) };
    });

    [Fact]
    public void DefaultAccumulatorsFn() => Base.Check(M, "defaultAccumulators", a =>
    {
        var o = (D)a[1]!;
        return IntentTrajectory.DefaultAccumulators(a[0], Dbl(o["spendDomainMax"]), o.GetValueOrDefault("questionCap") == null ? null : Dbl(o["questionCap"]), o.GetValueOrDefault("holder") as D);
    });

    [Fact]
    public void DescribeAccCellFn() => Base.Check(M, "describeAccCell", a =>
    {
        Func<double, string>? fmt = (a[4] as string) == "bracket" ? x => "[" + ((Num)N(x)!).Raw + "]" : null;
        return IntentTrajectory.DescribeAccCell((NumDim)DimFromJson(a[0]), (int)Dbl(a[1]), (string)a[2]!, a[3] == null ? null : Dbl(a[3]), fmt);
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "dimKindOf", "accDimPath", "monDimPath", "trajectoryHarmRange", "augment", "liftScenario", "stepScenario", "defaultAccumulators", "describeAccCell" }); Assert.Equal(356, Base.Total(M)); }
}
