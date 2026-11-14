using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// The pca-goal vectors (goal corpus and selector corpus): goal digest, lowered policy digest, decision + witness for every probe, the
// helper vectors, and the native expansion of trait selectors. The semantics are the shared runner
// (packages/pca-conformance/runners/goal/dotnet/run.cs; GoalRunner.cs is its generated copy): every language replays one reference.
public class GoalVectorTests
{
    [Fact]
    public void EveryGoalVectorAgreesWithTheReference()
    {
        var (n, probes, bad) = GoalRunner.Replay(GoalDir());
        Assert.True(n >= 240, $"only {n} goal vectors");
        Assert.True(probes > 6000, $"only {probes} probes");
        Assert.Empty(bad.Take(20));
    }

    [Fact]
    public void EverySelectorVectorAgreesWithTheReference()
    {
        var sel = Path.Combine(Path.GetDirectoryName(GoalDir())!, "goal-select");
        Assert.True(Directory.Exists(sel), "the selector vectors are missing (a vector directory is never skipped): " + sel);
        var (n, probes, bad) = GoalRunner.Replay(sel);
        Assert.True(n >= 48, $"only {n} selector vectors");
        Assert.True(probes > 1000, $"only {probes} probes");
        Assert.Empty(bad.Take(20));
    }

    [Fact]
    public void MeetIsTheLowerDecisionAndNeverRaises()
    {
        Assert.Equal("deny", GoalRunner.Meet("allow", "deny"));
        Assert.Equal("escalate", GoalRunner.Meet("allow", "escalate"));
        Assert.Equal("allow", GoalRunner.Meet("allow", "ok"));
        Assert.Equal("deny", GoalRunner.Meet("deny", "escalate"));
    }
}
