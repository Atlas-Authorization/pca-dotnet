using AtlasPca;
using AtlasPca.IntentPkg;
using AtlasPca.Wallet;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the wallet over an intent learner: the grant view of a learner (acceptance, vetoes, ceilings, confirmed cells)
/// and the mass a population prior admits beyond the base prior (test-data/ref-wallet-learner-py.json.gz).</summary>
public class RefWalletLearnerTests
{
    const string M = "ref-wallet-learner-py";

    static D Dd(object? o) => (D)o!;
    static int[] Idx(object? o) => ((L)o!).Select(x => (int)Dbl(x)).ToArray();
    static IntentLearner.Observation Obs(Omega omega, object? o)
    {
        var m = Dd(o);
        var oc = OutcomeFromJson(new D { ["verb"] = m["verb"], ["values"] = m["values"] });
        var vs = VerbSpaceOf(omega, oc.Verb)!;
        return new IntentLearner.Observation(oc.Verb, oc.Values, CellOf(vs, oc)!, (int)Dbl(m["y"]), (string)m["source"]!, null);
    }

    [Fact]
    public void ViewScenarioFn() => Base.Check(M, "viewScenario", a =>
    {
        var omega = OmegaFromJson(a[0]);
        var l = IntentMapKit.CreateLearner(omega, IntentMapKit.MapLearnerOptions.FromJson(a[1]));
        foreach (var x in (L)a[2]!) { var ob = Obs(omega, x); l.Observe(new Outcome(ob.Verb, ob.Values), ob.Y, ob.Source, null); }
        Func<string, int[], bool>? inside = (string)a[3]! switch { "all" => (_, _) => true, "idx0" => (_, idx) => idx[0] == 0, "never" => (_, _) => false, _ => null };
        var view = new LearnerView(l, inside);
        var probes = ((L)a[4]!).Select(p => (object?)new L { N(view.P((string)Dd(p)["verb"]!, Idx(Dd(p)["idx"]))), view.Vetoed((string)Dd(p)["verb"]!, Idx(Dd(p)["idx"])), view.OutsideCeiling((string)Dd(p)["verb"]!, Idx(Dd(p)["idx"])) }).ToList();
        var confirmed = view.Confirmed().Select(c => (object?)new D { ["verb"] = c.Verb, ["idx"] = c.Idx.Select(i => N(i)).ToList() }).ToList();
        return new D { ["probes"] = probes, ["confirmed"] = confirmed };
    });

    [Fact]
    public void ViewUnknownVerbFn() => Base.Check(M, "viewUnknownVerb", a =>
        new LearnerView(IntentMapKit.CreateLearner(OmegaFromJson(a[0]), IntentMapKit.MapLearnerOptions.FromJson(new D()))).P((string)a[1]!, Idx(a[2])));

    [Fact]
    public void PriorScenarioFn() => Base.Check(M, "priorScenario", a =>
    {
        var omega = OmegaFromJson(a[0]);
        var schema = (string)a[4]!;
        double qOf = Dbl(a[5]);
        bool hi = a.Count > 6 && a[6] is true;
        var cells = new D();
        foreach (var vs in omega.Verbs)
            for (int c = 0; c < (long)VerbCellCount(vs); c++)
            {
                double q = Math.Min(0.98, Math.Max(0.02, hi ? 0.98 - 0.04 * (c % qOf) : 0.05 + 0.04 * (c % qOf)));
                cells[WalletPopulation.PopulationCellKey(schema, vs, DecodeCell(vs, c))] = new D { ["q"] = N(q), ["n"] = N(50) };
            }
        var rel = new D { ["v"] = N(1), ["kind"] = "pca-intent-population-prior", ["schema"] = schema, ["period"] = N(1), ["epsilon"] = N(0.9), ["delta"] = N(1e-5), ["sigma"] = N(1), ["sensitivity"] = N(8), ["cells"] = cells };
        var mix = WalletPopulation.PopulationPrior(rel, Dbl(a[3]));
        var obs = ((L)a[2]!).Select(x => Obs(omega, x)).ToList();
        return N(WalletPopulation.PriorAdmittedPpm(omega, IntentLearner.LearnerOptions.FromJson(a[1]), obs, mix));
    });

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[] { "viewScenario", "viewUnknownVerb", "priorScenario" }); Assert.Equal(239, Base.Total(M)); }

    static bool Close(object? a, object? b)
    {
        if (a is Num x && b is Num y)
        {
            double p = IntentJs.NumOf(x)!.Value, q = IntentJs.NumOf(y)!.Value;
            return p == q || Math.Abs(p - q) <= 1e-12 * Math.Max(Math.Abs(p), Math.Abs(q));
        }
        if (a is D da && b is D db) return da.Count == db.Count && da.All(e => db.TryGetValue(e.Key, out var v) && Close(e.Value, v));
        if (a is L la && b is L lb) return la.Count == lb.Count && la.Zip(lb).All(t => Close(t.First, t.Second));
        return Base.Show(a) == Base.Show(b);
    }
}
