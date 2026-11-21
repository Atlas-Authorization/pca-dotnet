using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of liftLegacy: the facade's permissions and limits lifted to a Goal and an IR ontology (default catalog).</summary>
public class RefGoalLegacyTests
{
    const string M = "ref-goal-legacy";
    static long? Lng(object? o) => o == null ? null : long.Parse(((Num)o).Raw, CultureInfo.InvariantCulture);

    [Fact]
    public void LiftLegacy() => Base.Check(M, "liftLegacy", a =>
    {
        if (a[0] is not D perms) throw new ArgumentException("permissions must be an object");
        return GoalLegacy.LiftLegacy(perms, a[1] as D, null, (string)a[2]!, Lng(a[3]), Lng(a[4]), a[5] as string);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "liftLegacy" }); Assert.Equal(125, Base.Total(M)); }
}
