using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of session histories (test-data/base-intenthistory.json.gz, TS reference
/// packages/pca/src/intent-history.ts). AccPreState / AccPost return null where the reference throws (mapped to Refused); a
/// reference inWindow that falls off its switch (undefined, out null) is false. A null argument is passed through as null.</summary>
public class BaseIntentHistoryDiffTests
{
    const string M = "intenthistory";

    [Fact]
    public void InWindow() => Base.Check(M, "inWindow", a => IntentHistory.InWindow((a[0] as D)!, a[1], a[2]),
        eq: (c, have) => Base.Eq(c["out"] ?? false, have), min: 1660);

    [Fact] public void AccKeyOf() => Base.Check(M, "accKeyOf", a => IntentHistory.AccKeyOf((D)a[0]!, a[1] as D), min: 93);

    [Fact]
    public void AccPreState() => Base.Check(M, "accPreState", a =>
    {
        var cand = (D)a[2]!;
        return (object?)IntentHistory.AccPreState((D)a[0]!, a[1] as L, cand.GetValueOrDefault("params") as D, cand.GetValueOrDefault("t"), a[3]) ?? Base.Refused;
    }, min: 10200);

    [Fact]
    public void AccPost() => Base.Check(M, "accPost", a =>
    {
        var cand = (D)a[2]!;
        return (object?)IntentHistory.AccPost((D)a[0]!, a[1] as L, (string)cand["verb"]!, (D)cand["params"]!, cand.GetValueOrDefault("t"), a[3]) ?? Base.Refused;
    }, min: 13300);

    [Fact] public void MonitorStep() => Base.Check(M, "monitorStep", a => IntentHistory.MonitorStep((D)a[0]!, (string)a[1]!, (a[2] as D)!), min: 900);
    [Fact] public void MonitorState() => Base.Check(M, "monitorState", a => IntentHistory.MonitorState((D)a[0]!, a[1] as L), min: 90);

    [Fact]
    public void StatusConstants()
    {
        Assert.Equal(new[] { "reserved", "committed", "released", "reverted" }, IntentHistory.EventStatuses);
        Assert.Equal(new[] { "reserved", "committed" }, IntentHistory.CountedStatuses);
        Assert.All(IntentHistory.EventStatuses, st => Assert.Equal(IntentHistory.CountedStatuses.Contains(st), IntentHistory.IsCounted(st)));
    }

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "inWindow", "accKeyOf", "accPreState", "accPost", "monitorStep", "monitorState" }); Assert.Equal(29179, Base.Total(M)); }
}
