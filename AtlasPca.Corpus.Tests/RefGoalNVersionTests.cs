using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the goal N-version meet and active disambiguation.</summary>
public class RefGoalNVersionTests
{
    const string M = "ref-goal-nversion";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static List<D> Maps(object? o) { var r = new List<D>(); foreach (var x in A(o)) r.Add(O(x)); return r; }
    static double? Dbl(L a) => a.Count > 2 && a[2] != null ? double.Parse(((Num)a[2]!).Raw, System.Globalization.CultureInfo.InvariantCulture) : null;

    [Fact] public void Meet() => Base.Check(M, "meet", a => GoalNVersion.Meet(Maps(a[0])));
    [Fact] public void MeetGrants() => Base.Check(M, "meetGrants", a => GoalNVersion.MeetGrants(A(a[0]), A(a[1])));
    [Fact] public void CheckPanel() => Base.Check(M, "checkPanel", a => GoalNVersion.CheckPanel(Maps(a[0])));
    [Fact] public void DisagreementMass() => Base.Check(M, "disagreementMass", a => GoalDisambiguate.DisagreementMass(Maps(a[0]), O(a[1])));
    [Fact] public void Questions() => Base.Check(M, "questions", a => GoalDisambiguate.Questions(Maps(a[0]), new GoalDisambiguate.Opts(O(a[1]))));
    [Fact] public void NVersion() => Base.Check(M, "nVersion", a => GoalNVersion.NVersion(Maps(a[0]), new GoalDisambiguate.Opts(O(a[1])), Dbl(a)));
    [Fact] public void AllowsWitness() => Base.Check(M, "allowsWitness", a => GoalDisambiguate.AllowsWitness(O(a[0]), O(a[1]), O(a[2])));

    [Fact]
    public void Disambiguate() => Base.Check(M, "disambiguate", a =>
    {
        var readings = Maps(a[0]);
        var ont = O(a[1]);
        var mode = (string)a[2]!;
        var opts = new GoalDisambiguate.Opts(ont);
        if (a[3] != null) opts.Budget = int.Parse(((Num)a[3]!).Raw, System.Globalization.CultureInfo.InvariantCulture);
        return GoalDisambiguate.Disambiguate(readings, q => mode == "allow" ? "allow" : mode == "deny" ? "deny"
            : GoalDisambiguate.AllowsWitness(O(readings[int.Parse(mode.Substring(6), System.Globalization.CultureInfo.InvariantCulture)]["goal"]), ont, q) ? "allow" : "deny", opts);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "meet", "meetGrants", "checkPanel", "disagreementMass", "questions", "nVersion", "allowsWitness", "disambiguate" }); Assert.Equal(93, Base.Total(M)); }
}
