using AtlasPca.Analyzer;
using AtlasPca.ControlEvals;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the empirical control-evaluation harness against the TypeScript reference. The blue protocol of the reference (action
/// review, data-flow governance, immune system, budget) is not part of the native package: the episode runner and the evaluation are replayed with a blue
/// stub that answers each decision from the decisions the reference recorded.</summary>
public class RefControlEvalsTests
{
    const string M = "ref-control-evals";

    static double Dbl(object? o) => Jx.ToNumber(o);
    static object? Out(double d) => Jx.NumOut(d);

    internal static readonly Dictionary<string, RedPolicy> Reds = new()
    {
        ["over-cap"] = PcaControlEvals.OverCapRed, ["off-verb"] = PcaControlEvals.OffVerbRed, ["slow-burn"] = PcaControlEvals.SlowBurnRed,
        ["taint-exfil"] = PcaControlEvals.TaintExfilRed, ["replay"] = PcaControlEvals.ReplayRed, ["immune-probe"] = PcaControlEvals.ImmuneProbeBurstRed,
        ["benign"] = PcaControlEvals.BenignBaselineRed, ["gap-exploit"] = PcaControlEvals.GapExploitRed(),
    };

    internal static CeEnv EnvOf(string name) => name == "example" ? PcaControlEvals.ExampleEnv : name == "gap-aware" ? PcaControlEvals.GapAwareEnv() : PcaControlEvals.GapAwareEnv(name["gap-aware:".Length..]);

    static L ActionsOf(RedPolicy r) => r.Gen(new RedContext(PcaControlEvals.ExampleEnv, PcaControlEvals.Mulberry32(1), 0));

    /// <summary>A blue protocol that answers the i-th decision from the recorded decisions of an episode.</summary>
    sealed class Replaying : IBlueEpisode
    {
        readonly D rec; int i;
        public Replaying(object? rec) { this.rec = (D)rec!; }
        public CeBlueStep Decide(object? action, double at)
        {
            var s = (D)((L)rec["steps"]!)[i++]!;
            return new CeBlueStep((string)s["outcome"]!, s["caughtBy"] as string, Dbl(s["r"]), (string)s["threat"]!, s.GetValueOrDefault("reason") as string, Dbl(s["money"]));
        }
        public double EndBudget => Dbl(rec["endBudget"]);
    }

    [Fact]
    public void Mulberry32() => Base.Check(M, "mulberry32", a =>
    {
        var r = PcaControlEvals.Mulberry32(Dbl(a[0]));
        var o = new L();
        for (int i = 0, n = (int)Dbl(a[1]); i < n; i++) o.Add(Out(r()));
        return o;
    });

    [Fact] public void MixSeed() => Base.Check(M, "mixSeed", a => Out(PcaControlEvals.MixSeed(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))));
    [Fact] public void WilsonLowerBound() => Base.Check(M, "wilsonLowerBound", a => Out(a.Count > 2 ? PcaControlEvals.WilsonLowerBound(Dbl(a[0]), Dbl(a[1]), Dbl(a[2])) : PcaControlEvals.WilsonLowerBound(Dbl(a[0]), Dbl(a[1]))));

    [Fact]
    public void AssertControlGate() => Base.Check(M, "assertControlGate", a =>
    {
        PcaControlEvals.AssertControlGate(a[0], a[1]);
        return null;
    });

    [Fact] public void RedGen() => Base.Check(M, "redGen", a => { var r = Reds[(string)a[0]!]; return new D { ["name"] = r.Name, ["strategy"] = r.Strategy, ["actions"] = ActionsOf(r) }; });
    [Fact] public void GapExploitCustom() => Base.Check(M, "gapExploitCustom", _ => { var r = PcaControlEvals.GapExploitRed("file:x"); return new D { ["name"] = r.Name, ["actions"] = r.Gen(new RedContext(PcaControlEvals.ExampleEnv, PcaControlEvals.Mulberry32(0), 0)) }; });

    [Fact]
    public void RedLists() => Base.Check(M, "redLists", _ => new D
    {
        ["builtin"] = PcaControlEvals.BuiltinRedPolicies.Select(r => (object?)r.Strategy).ToList(),
        ["example"] = PcaControlEvals.ExampleRedPolicies.Select(r => (object?)r.Strategy).ToList(),
    });

    [Fact] public void EnvJudge() => Base.Check(M, "envJudge", a => EnvOf((string)a[0]!).UnacceptableIfAllowed(a[1], a[2]));
    [Fact] public void ExampleDlpPolicy() => Base.Check(M, "exampleDlpPolicy", _ => PcaControlEvals.ExampleDlpPolicy());

    [Fact]
    public void RunEpisode() => Base.Check(M, "runEpisode", a =>
    {
        var spec = (D)a[0]!;
        return PcaControlEvals.RunEpisode(Reds[(string)spec["red"]!], EnvOf((string)spec["env"]!), new Replaying(spec["recorded"]), Dbl(spec["seed"]), Dbl(spec["startMs"]), Dbl(spec["stepMs"]));
    });

    [Fact]
    public void ControlEval() => Base.Check(M, "controlEval", a =>
    {
        var spec = (D)a[0]!;
        // a value of the wrong type reaches the native as null: it must refuse it
        IReadOnlyList<RedPolicy>? reds = spec["reds"] is L rl ? rl.Select(x => Reds[(string)x!]).ToList() : null;
        double? episodes = spec["episodes"] is Num en ? Dbl(en) : null;
        double? seed = spec["seed"] is Num sn ? Dbl(sn) : null;
        var recorded = (L)spec["recorded"]!;
        var blue = new BlueProtocol((ri, e) => new Replaying(((L)recorded[ri]!)[e]), Dbl(spec["startMs"]), Dbl(spec["stepMs"]), Dbl(spec["analyticBound"]));
        return PcaControlEvals.ControlEval(reds, blue, EnvOf((string)spec["env"]!), episodes, seed);
    });

    [Fact]
    public void CoversEveryFn() { Base.Covers(M, new[]
    {
        "mulberry32", "mixSeed", "wilsonLowerBound", "assertControlGate", "redGen", "gapExploitCustom", "redLists", "envJudge", "exampleDlpPolicy", "runEpisode", "controlEval",
    }); Assert.Equal(3702, Base.Total(M)); }
}
