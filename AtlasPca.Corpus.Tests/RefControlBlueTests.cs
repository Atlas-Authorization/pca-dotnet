using AtlasPca.ControlEvals;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the blue control protocol (test-data/ref-control-blue.json.gz, 362 cases): the example agent and its review battery, the example blue protocol over its three
/// agents, 352 episodes against configured blues (data-flow governance on / off, the agent's own thresholds, another clock, a custom immune tuning) and the six example evaluations, all against
/// the native blue stack (ref-control-evals replays only the aggregation, from a recorded blue). Numbers compare to a relative 1e-12 (the leak decays exponentially).
/// Counted deviation (asserted): an integer past 2^53 in the params makes the reference's canonicalizer throw out of the episode (5 cases, all of the no-predicate agents); the native throws too,
/// and only the text of the canonicalizer's refusal differs. Every fn has a handler and the totals are asserted.</summary>
public class RefControlBlueTests
{
    const string M = "ref-control-blue";

    static double Dbl(object? o) => IntentJs.NumOf(o)!.Value;

    static bool Same(object? want, object? got)
    {
        if (want is Num && got is Num)
        {
            double w = Dbl(want), g = Dbl(got);
            return w == g || Math.Abs(w - g) <= 1e-12 * Math.Max(1, Math.Abs(w));
        }
        if (want is D wd && got is D gd) return wd.Count == gd.Count && wd.All(e => gd.TryGetValue(e.Key, out var x) && Same(e.Value, x));
        if (want is L wl && got is L gl) return wl.Count == gl.Count && wl.Zip(gl).All(p => Same(p.First, p.Second));
        return Base.Show(want) == Base.Show(got);
    }

    static AgentHandle AgentOf(string name) => name switch
    {
        "example" => ControlEvalsExample.BuildExampleAgent(),
        "risk" => ControlEvalsExample.BuildAgent(null),
        "cap50" => ControlEvalsExample.BuildAgent(new Dictionary<string, string> { ["refund"] = "$50/day" }),
        _ => throw new InvalidDataException("unknown blue agent " + name),
    };

    static Dictionary<string, double>? Tuning(object? o) => o is D d ? d.ToDictionary(e => e.Key, e => Dbl(e.Value)) : null;

    static ControlEvalsExample.ExampleBlueOptions OptionsOf(D b)
    {
        var ad = b.GetValueOrDefault("adapt") as D;
        return new ControlEvalsExample.ExampleBlueOptions(
            Dlp: b.GetValueOrDefault("dlp") is not false, AgentTheta: b.GetValueOrDefault("theta") is "agent",
            StepMs: b.TryGetValue("stepMs", out var st) ? Dbl(st) : null, StartMs: b.TryGetValue("startMs", out var sm) ? Dbl(sm) : null,
            Immune: Tuning(b.GetValueOrDefault("immune")), MaxKappaMult: ad != null ? Dbl(ad["maxKappaMult"]) : null, MinThetaMult: ad != null ? Dbl(ad["minThetaMult"]) : null);
    }

    static object? BuildExampleAgent(D c)
    {
        var want = (D)c["out"]!;
        var a = ControlEvalsExample.BuildExampleAgent();
        var pol = a.Policy;
        var actions = new L();
        foreach (var s in pol.Actions)
        {
            var m = new D { ["connector"] = s.Connector, ["action"] = s.Action, ["verb"] = s.Verb, ["reversibility"] = s.Reversibility, ["blastRadius"] = s.BlastRadius };
            if (s.AmountField != null) m["amountField"] = s.AmountField;
            if (s.Resource != null) m["resource"] = s.Resource;
            actions.Add(m);
        }
        var reviews = new L();
        foreach (var eo in (L)want["reviews"]!)
        {
            var e = (D)eo!;
            var r = Approvals.ReviewAction(a, (string)e["verb"]!, (string)e["resource"]!, e.GetValueOrDefault("params") as D,
                new ReviewOptions { Now = (long)Dbl(e["now"]), InsecureUnboundApproval = true });
            var review = new D { ["kind"] = r["kind"] };
            if (r.GetValueOrDefault("reason") is string why) review["reason"] = why;
            var o = e.Where(kv => kv.Key != "review").ToDictionary(kv => kv.Key, kv => kv.Value);
            o["review"] = review;
            reviews.Add(o);
        }
        return new D
        {
            ["policy"] = new D
            {
                ["predicates"] = pol.Predicates, ["caveats"] = pol.Caveats, ["riskPolicy"] = pol.RiskPolicy, ["budgetModel"] = pol.BudgetModel,
                ["approximations"] = pol.Approximations.Cast<object?>().ToList(), ["inputLimits"] = pol.InputLimits.ToDictionary(kv => kv.Key, kv => (object?)kv.Value), ["actions"] = actions,
            },
            ["reviews"] = reviews,
        };
    }

    static object? ExampleBlue(L a)
    {
        var b = ControlEvalsExample.ExampleBlue(AgentOf((string)a[0]!));
        return new D { ["name"] = b.Name, ["basePolicy"] = b.BasePolicy, ["dlp"] = b.Dlp, ["startMs"] = b.StartMs, ["stepMs"] = b.StepMs };
    }

    static object? BlueEpisode(L a)
    {
        var spec = (D)a[0]!;
        var bs = (D)spec["blue"]!;
        var blue = ControlEvalsExample.ExampleBlue(AgentOf((string)bs["agent"]!), OptionsOf(bs));
        RedPolicy red = a.Count > 1
            ? new RedPolicy("custom", "custom", _ => new L((L)a[1]!))
            : RefControlEvalsTests.Reds[(string)spec["red"]!];
        return PcaControlEvals.RunEpisode(red, RefControlEvalsTests.EnvOf((string)spec["env"]!), blue.NewEpisode(0, 0), Dbl(spec["seed"]), blue.StartMs, blue.StepMs);
    }

    static object? ExampleEval(L a)
    {
        var spec = (D)a[0]!;
        return ControlEvalsExample.ExampleControlEval(Dbl(spec["episodes"]), Dbl(spec["seed"]));
    }

    static readonly Dictionary<string, Func<D, object?>> Handlers = new()
    {
        ["buildExampleAgent"] = BuildExampleAgent,
        ["exampleBlue"] = c => ExampleBlue(Base.Args(c)),
        ["blueEpisode"] = c => BlueEpisode(Base.Args(c)),
        ["exampleEval"] = c => ExampleEval(Base.Args(c)),
    };

    /// <summary>Replays every case of a function; returns how many reference refusals were met (and met by a native refusal).</summary>
    static int Replay(string fn)
    {
        var bad = new List<string>();
        int n = 0, refusals = 0;
        foreach (var c in Base.Of(M, fn))
        {
            n++;
            var name = (string)c["name"]!;
            var want = c["out"];
            object? got = null;
            string? thrown = null;
            try { got = Base.Json(Handlers[fn](c)); }
            catch (Exception e) { thrown = e.Message; }
            if (want is D w && w.ContainsKey("$throws"))
            {
                if (thrown == null) bad.Add($"{name}\n   want a refusal ({w["$throws"]})\n   have {Base.Show(got)}");
                else refusals++;
                continue;
            }
            if (thrown != null) { bad.Add($"{name}\n   want {Base.Show(want)}\n   threw {thrown}"); continue; }
            if (!Same(want, got)) bad.Add($"{name}\n   want {Base.Show(want)}\n   have {Base.Show(got)}");
        }
        Assert.True(bad.Count == 0, $"{M}/{fn}: {bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(12).Select(b => b.Length > 1500 ? b[..1500] : b)));
        return refusals;
    }

    [Fact] public void BuildExampleAgentBattery() => Assert.Equal(0, Replay("buildExampleAgent"));

    [Fact] public void ExampleBlueOverThreeAgents() => Assert.Equal(0, Replay("exampleBlue"));

    [Fact] public void EpisodesAgainstConfiguredBlues() => Assert.Equal(5, Replay("blueEpisode"));

    [Fact] public void ExampleEvaluations() => Assert.Equal(0, Replay("exampleEval"));

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Handlers.Keys);
        Assert.Equal(362, Base.Total(M));
        Assert.Equal(new Dictionary<string, int> { ["buildExampleAgent"] = 1, ["exampleBlue"] = 3, ["blueEpisode"] = 352, ["exampleEval"] = 6 },
            Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
    }
}
