using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of session histories (test-data/k05-intenthistory.json.gz, TS reference
/// packages/pca/src/intent-history.ts). AccPreState / AccPost return null where the reference throws (mapped to Refused); a
/// reference inWindow that falls off its switch (undefined, out null) is false. A null argument is passed through as null.</summary>
public class K05IntentHistoryDiffTests
{
    const string M = "intenthistory";

    [Fact]
    public void InWindow() => K05.Check(M, "inWindow", a => IntentHistory.InWindow((a[0] as D)!, a[1], a[2]),
        eq: (c, have) => K05.Eq(c["out"] ?? false, have), min: 1660);

    [Fact] public void AccKeyOf() => K05.Check(M, "accKeyOf", a => IntentHistory.AccKeyOf((D)a[0]!, a[1] as D), min: 93);

    [Fact]
    public void AccPreState() => K05.Check(M, "accPreState", a =>
    {
        var cand = (D)a[2]!;
        return (object?)IntentHistory.AccPreState((D)a[0]!, a[1] as L, cand.GetValueOrDefault("params") as D, cand.GetValueOrDefault("t"), a[3]) ?? K05.Refused;
    }, min: 10200);

    [Fact]
    public void AccPost() => K05.Check(M, "accPost", a =>
    {
        var cand = (D)a[2]!;
        return (object?)IntentHistory.AccPost((D)a[0]!, a[1] as L, (string)cand["verb"]!, (D)cand["params"]!, cand.GetValueOrDefault("t"), a[3]) ?? K05.Refused;
    }, min: 13300);

    [Fact] public void MonitorStep() => K05.Check(M, "monitorStep", a => IntentHistory.MonitorStep((D)a[0]!, (string)a[1]!, (a[2] as D)!), min: 900);
    [Fact] public void MonitorState() => K05.Check(M, "monitorState", a => IntentHistory.MonitorState((D)a[0]!, a[1] as L), min: 90);

    [Fact]
    public void EveryFn() => K05.Covers(M, new[] { "inWindow", "accKeyOf", "accPreState", "accPost", "monitorStep", "monitorState" });
}
