using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of frame and side-effect constraints against the TypeScript reference (test-data/ref-intent-frames.json.gz).
/// A reference throw requires the native to throw.</summary>
public class RefIntentFramesTests
{
    const string M = "ref-intent-frames";

    [Fact] public void StateDigestFn() => Base.Check(M, "stateDigest", a => IntentFrames.StateDigest(a[0]));
    [Fact] public void SnapshotStateFn() => Base.Check(M, "snapshotState", a => IntentFrames.SnapshotState((D)a[0]!, a.Count < 2 || a[1] is not false));
    [Fact] public void CheckFrameFn() => Base.Check(M, "checkFrame", a => IntentFrames.CheckFrame(a[0], a[1], a[2], a[3], a[4] as D));

    [Fact]
    public void ApplyScenarioFn() => Base.Check(M, "applyScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        return new D
        {
            ["result"] = IntentFrames.ApplyFrameReport(l, OutcomeFromJson(a[3]), a[4]),
            ["metrics"] = RefIntentLearnerTests.Met(l.Metrics()),
        };
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "stateDigest", "snapshotState", "checkFrame", "applyScenario" }); Assert.Equal(88, Base.Total(M)); }
}
