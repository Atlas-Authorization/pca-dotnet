using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of decision cells, boundary examples, goal tests and the policy pin.</summary>
public class RefGoalExamplesTests
{
    const string M = "ref-goal-examples";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static List<D>? Maps(object? o) => o == null ? null : A(o).Select(x => (D)x!).ToList();
    static List<string>? Strs(object? o) => o == null ? null : A(o).Select(x => (string)x!).ToList();
    static byte[] Seed(object? o) => Pca.B64uDecode(o) ?? throw new InvalidDataException("seed");
    static int Int(object? o) => int.Parse(o is Num n ? n.Raw : o!.ToString()!);
    static GoalExamples.Space Sp(L a) => GoalExamples.BuildSpace(Maps(a[0])!, Strs(a[1])!);

    [Fact] public void BuildSpace() => Base.Check(M, "buildSpace", a => Sp(a).toJson());
    [Fact] public void Cells() => Base.Check(M, "cells", a => GoalExamples.Cells(Sp(a), Strs(a[2])));
    [Fact] public void CellKey() => Base.Check(M, "cellKey", a => GoalExamples.CellKey(Sp(a), O(a[2])));
    [Fact] public void DecideCase() => Base.Check(M, "decideCase", a => GoalExamples.DecideCase(O(a[0]), O(a[1]), O(a[2])));
    [Fact] public void Replay() => Base.Check(M, "replay", a => GoalExamples.Replay(O(a[0]), O(a[1]), A(a[2]), A(a[3])));
    [Fact]
    public void AllowWitness() => Base.Check(M, "allowWitness", a =>
    {
        var g = O(a[0]);
        return GoalExamples.AllowWitness(g, (D)A(g["grants"])[Int(a[1])]!, O(a[2]));
    });
    [Fact] public void BoundaryExamples() => Base.Check(M, "boundaryExamples", a => GoalExamples.BoundaryExamples(O(a[0]), O(a[1]), Maps(a[2]), Strs(a[3])));
    [Fact] public void ReviewSet() => Base.Check(M, "reviewSet", a => GoalExamples.ReviewSet(A(a[0]), Int(a[1])));
    [Fact] public void TestsDigest() => Base.Check(M, "testsDigest", a => GoalExamples.TestsDigest(A(a[0])));
    [Fact] public void MakeGoalTests() => Base.Check(M, "makeGoalTests", a => GoalExamples.MakeGoalTests(O(a[0]), A(a[1])));
    [Fact] public void SignGoalTestsSeed() => Base.Check(M, "signGoalTestsSeed", a => GoalExamples.SignGoalTests(O(a[0]), Seed(a[1])));
    [Fact]
    public void CheckGoalTests() => Base.Check(M, "checkGoalTests", a =>
    {
        var mode = S(a[2]);
        D g = O(a[3]), ont = O(a[4]);
        return GoalExamples.CheckGoalTests(a[0] as D, A(a[1]), t => mode == "ref" ? (string)GoalExamples.DecideCase(g, ont, t)["decision"]! : mode == "allow" ? "allow" : mode == "deny" ? "deny" : "escalate");
    });
    [Fact] public void SignPinSeed() => Base.Check(M, "signPinSeed", a => GoalExamples.SignPin(O(a[0]), Seed(a[1])));
    [Fact] public void CheckPin() => Base.Check(M, "checkPin", a => GoalExamples.CheckPin(a[0] as D, A(a[1]), O(a[2])));

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "buildSpace", "cells", "cellKey", "decideCase", "replay", "allowWitness", "boundaryExamples", "reviewSet", "testsDigest", "makeGoalTests",
        "signGoalTestsSeed", "checkGoalTests", "signPinSeed", "checkPin",
    }); Assert.Equal(132, Base.Total(M)); }
}
