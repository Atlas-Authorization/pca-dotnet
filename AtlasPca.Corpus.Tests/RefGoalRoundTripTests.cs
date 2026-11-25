using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the card tape round trip, widening mutations and the explainer / comparator detector.</summary>
public class RefGoalRoundTripTests
{
    const string M = "ref-goal-roundtrip";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;

    static Func<List<string>, string> Explainer(string mode) => lines =>
    {
        if (mode == "throw") throw new InvalidOperationException("boom");
        return GoalRoundTrip.DeterministicExplain(lines);
    };
    static Func<string, string, D> Comparator(string mode) => (text, e) =>
    {
        if (mode == "throw") throw new InvalidOperationException("boom");
        if (mode == "ok") return new D { ["equivalent"] = true };
        if (mode == "no") return new D { ["equivalent"] = false };
        return new D { ["equivalent"] = e.Contains(mode.Substring(9), StringComparison.Ordinal) };
    };

    [Fact] public void CardRoundTrips() => Base.Check(M, "cardRoundTrips", a => GoalRoundTrip.CardRoundTrips(O(a[0])));
    [Fact] public void MutateGoal() => Base.Check(M, "mutateGoal", a => GoalRoundTrip.MutateGoal(O(a[0]), S(a[1]), O(a[2])));
    [Fact] public void RoundTrip() => Base.Check(M, "roundTrip", a => GoalRoundTrip.RoundTrip(O(a[0]), S(a[1]), Explainer(S(a[2])), Comparator(S(a[3]))));
    [Fact] public void MeasureDetection() => Base.Check(M, "measureDetection", a => GoalRoundTrip.MeasureDetection(A(a[0]), O(a[1]), Explainer(S(a[2])), Comparator(S(a[3]))));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "cardRoundTrips", "mutateGoal", "roundTrip", "measureDetection" }); Assert.Equal(78, Base.Total(M)); }
}
