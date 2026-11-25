using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the learner feedback glue (test-data/ref-intent-glue-py.json.gz): outcome verification (a violated postcondition vetoes the cell, and
/// the veto holds after a later "yes"), frame reports, and org layers learned from the maps of several principals. Every scenario also returns the
/// learner's vetoed cells, metrics and observations.</summary>
public class RefIntentGluePyTests
{
    const string M = "ref-intent-glue-py";

    static void Tail(D o, IntentLearner l)
    {
        o["vetoed"] = l.VetoedCells().Cast<object?>().ToList();
        o["metrics"] = RefIntentLearnerTests.Met(l.Metrics());
        o["observations"] = l.Observations.Select(x => (object?)x.ToJson()).ToList();
    }

    [Fact]
    public void VerifyScenario() => Base.Check(M, "verifyScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var oc = OutcomeFromJson(a[3]);
        var o = new D();
        if (a.Count == 5)
        {
            // the variant that answers "yes" after the violation: the veto must hold
            o["r"] = IntentOutcome.VerifyOutcome(l, oc, (D)a[4]!);
            l.Observe(oc, 1, "elicitation", null);
            Tail(o, l);
            o["again"] = l.AdmitsOutcome(oc);
            return o;
        }
        o["result"] = IntentOutcome.VerifyOutcome(l, oc, (D)a[4]!, a[5] as L);
        Tail(o, l);
        return o;
    }, min: 87);

    [Fact]
    public void FrameScenario() => Base.Check(M, "frameScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var o = new D { ["result"] = IntentFrames.ApplyFrameReport(l, OutcomeFromJson(a[3]), a[4]) };
        Tail(o, l);
        return o;
    }, min: 46);

    [Fact]
    public void OrgScenario() => Base.Check(M, "orgScenario", a =>
    {
        var maps = ((L)a[1]!).Select(p => (object?)IntentMapKit.EmitIntentMap(RefIntentRampTests.Make(a[0], a[3], ((D)p!)["observations"]), ((D)p!)["ref"] as string)).ToList();
        return IntentLattice.OrgLayerFromMaps(maps, (D)a[2]!);
    }, min: 13);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "verifyScenario", "frameScenario", "orgScenario" });
        Assert.Equal(146, Base.Cases(M).Count);
    }
}
