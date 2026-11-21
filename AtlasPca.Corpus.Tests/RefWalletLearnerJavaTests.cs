using AtlasPca;
using AtlasPca.IntentPkg;
using AtlasPca.Wallet;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the second wallet-over-learner corpus (test-data/ref-wallet-learner-java.json.gz): the grant view of a default learner over every cell
/// (acceptance, veto, ceiling, confirmed cells), a single-cell probe, and the mass a signed population prior admits beyond the base prior. Acceptance
/// values compare to 1e-12 relative, everything else exactly.</summary>
public class RefWalletLearnerJavaTests
{
    const string M = "ref-wallet-learner-java";

    static Outcome OutcomeOf(object? o) => OutcomeFromJson(new D { ["verb"] = ((D)o!)["verb"], ["values"] = ((D)o!)["values"] });
    static L Ints(int[] a) => a.Select(i => N(i)).ToList();

    [Fact]
    public void View() => Base.Check(M, "view", a =>
    {
        var omega = OmegaFromJson(a[0]);
        var l = new IntentLearner(omega);
        foreach (var x in (L)a[1]!) l.Observe(OutcomeOf(x), (int)Dbl(((D)x!)["y"]));
        // the ceiling, when given, admits the cells whose first index is at most it
        var view = a[2] == null ? new LearnerView(l) : new LearnerView(l, (_, idx) => idx[0] <= Dbl(a[2]));
        var cells = new L();
        foreach (var vs in omega.Verbs)
            for (int f = 0; f < (long)VerbCellCount(vs); f++)
            {
                var idx = DecodeCell(vs, f);
                cells.Add(new L { vs.Verb, Ints(idx), N(view.P(vs.Verb, idx)), view.Vetoed(vs.Verb, idx), view.OutsideCeiling(vs.Verb, idx) });
            }
        var confirmed = view.Confirmed().Select(c => (object?)new D { ["verb"] = c.Verb, ["idx"] = Ints(c.Idx.ToArray()) }).ToList();
        return new D { ["cells"] = cells, ["confirmed"] = confirmed };
    }, (c, have) => Close(c["out"], Base.Json(have)), min: 36);

    [Fact]
    public void Probe() => Base.Check(M, "probe", a => N(new LearnerView(new IntentLearner(OmegaFromJson(a[0]))).P((string)a[1]!, new[] { 0, 0 })),
        (c, have) => Close(c["out"], Base.Json(have)), min: 2);

    [Fact]
    public void PriorAdmittedPpm() => Base.Check(M, "ppm", a =>
    {
        var omega = OmegaFromJson(a[0]);
        var obs = ((L)a[2]!).Select(x =>
        {
            var oc = OutcomeOf(x);
            return new IntentLearner.Observation(oc.Verb, oc.Values, CellOf(VerbSpaceOf(omega, oc.Verb)!, oc)!, (int)Dbl(((D)x!)["y"]), "elicitation", null);
        }).ToList();
        return N(WalletPopulation.PriorAdmittedPpm(omega, IntentLearner.LearnerOptions.FromJson(a[1]), obs, WalletPopulation.PopulationPrior((D)a[3]!, Dbl(a[4]))));
    }, min: 301);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "view", "probe", "ppm" });
        Assert.Equal(339, Base.Cases(M).Count);
    }

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
