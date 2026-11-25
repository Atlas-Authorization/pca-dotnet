using AtlasPca.ControlEvals;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The example blue control protocol (with data-flow governance and the behavioral immune system) against the reference's own recorded episodes and
/// evaluations: the native protocol decides every action of every recorded run exactly as the TypeScript stack did, so the whole transcript and the
/// aggregated report compare equal.</summary>
public class RefControlEvalsExampleTests
{
    const string M = "ref-control-evals";

    static double Dbl(object? o) => AtlasPca.Analyzer.Jx.ToNumber(o);

    [Fact]
    public void EpisodesAreDecidedLikeTheReference()
    {
        var agent = ControlEvalsExample.BuildExampleAgent();
        Base.Check(M, "runEpisode", a =>
        {
            var spec = (D)a[0]!;
            var blue = ControlEvalsExample.ExampleBlue(agent);
            return PcaControlEvals.RunEpisode(RefControlEvalsTests.Reds[(string)spec["red"]!], RefControlEvalsTests.EnvOf((string)spec["env"]!), blue.NewEpisode(0, 0), Dbl(spec["seed"]), blue.StartMs, blue.StepMs);
        });
    }

    [Fact]
    public void EvaluationsAreScoredLikeTheReference()
    {
        var agent = ControlEvalsExample.BuildExampleAgent();
        Base.Check(M, "controlEval", a =>
        {
            var spec = (D)a[0]!;
            IReadOnlyList<RedPolicy>? reds = spec["reds"] is L rl ? rl.Select(x => RefControlEvalsTests.Reds[(string)x!]).ToList() : null;
            double? episodes = spec["episodes"] is Num en ? Dbl(en) : null;
            double? seed = spec["seed"] is Num sn ? Dbl(sn) : null;
            return PcaControlEvals.ControlEval(reds, ControlEvalsExample.ExampleBlue(agent), RefControlEvalsTests.EnvOf((string)spec["env"]!), episodes, seed);
        });
    }

    [Fact]
    public void ExampleControlEvalIsDeterministicAndScoresEveryStrategy()
    {
        var r = ControlEvalsExample.ExampleControlEval();
        Assert.Equal(8.0 * PcaControlEvals.ExampleRedPolicies.Count, Dbl(r["episodes"]));
        Assert.Equal(PcaControlEvals.ExampleRedPolicies.Count, ((D)r["byStrategy"]!).Count);
        Assert.Equal(Base.Show(r), Base.Show(ControlEvalsExample.ExampleControlEval()));
        Assert.ThrowsAny<Exception>(() => ControlEvalsExample.ExampleControlEval(0));
    }
}
