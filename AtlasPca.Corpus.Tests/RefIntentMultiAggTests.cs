using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of multi-principal aggregation, cross-organisation lifting and the layered lattice against the TypeScript reference
/// (test-data/ref-intent-multi-agg.json.gz, test-data/ref-intent-lattice.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentMultiAggTests
{
    const string M = "ref-intent-multi-agg";
    const string ML = "ref-intent-lattice";

    static D BuildMap(object? omega, object? mapOpts, object? observations, object? reference)
    {
        var l = IntentMapKit.CreateLearner(OmegaFromJson(omega), IntentMapKit.MapLearnerOptions.FromJson(mapOpts));
        foreach (var xo in (L)observations!)
        {
            var x = (D)xo!;
            l.Observe(OutcomeFromJson(x), (int)Dbl(x["y"]), (string)x["source"]!, null);
        }
        return IntentMapKit.EmitIntentMap(l, reference as string);
    }

    static L Maps(object? omega, object? principals, object? mapOpts)
    {
        var o = new L();
        foreach (var p in (L)principals!) o.Add(BuildMap(omega, mapOpts, ((D)p!)["observations"], ((D)p)["ref"]));
        return o;
    }

    static void Add(D m, string key, double d) => m[key] = new Num(((long)(Dbl(m[key]) + d)).ToString(System.Globalization.CultureInfo.InvariantCulture));

    static readonly List<Action<D>> Muts = new()
    {
        m => { },
        m => Add((D)m["metrics"]!, "residual_risk_ppm", 7),
        m => { var c = (D)((L)m["cells"]!)[0]!; c["in_grant"] = !(bool)c["in_grant"]!; },
        m => m["aggregation"] = null,
        m => { var a = (D)m["aggregation"]!; a["rule"] = "quorum"; a["k"] = new Num("1"); },
        m => ((D)m["aggregation"]!)["vetoers"] = new L(),
    };

    // the oracle hands its plain {ref: org} map to the reference as the options object, whose members are not refs: no organisation is ever attached
    static D OrgsOf(object? o) => o is D opts && opts.GetValueOrDefault("orgs") is D orgs ? orgs : new D();

    [Fact]
    public void AggregateScenarioFn() => Base.Check(M, "aggregateScenario", a =>
    {
        var ms = Maps(a[0], a[1], a[4]);
        var rule = (D)a[2]!;
        var orgs = OrgsOf(a[3]);
        var agg = IntentMultiAgg.AggregateIntentMaps(ms, rule, orgs);
        var tampered = new L();
        foreach (var f in Muts)
        {
            var copy = (D)IntentJs.Normalize(agg)!;
            f(copy);
            tampered.Add(IntentMultiAgg.VerifyAggregate(copy, ms, orgs));
        }
        return new D
        {
            ["aggregate"] = agg,
            ["digest"] = IntentMapKit.IntentMapDigest(agg),
            ["rule"] = IntentMultiAgg.RuleOf(agg),
            ["verify"] = IntentMultiAgg.VerifyAggregate(agg, ms, orgs),
            ["tampered"] = tampered,
            ["wrongInputs"] = IntentMultiAgg.VerifyAggregate(agg, ms.Take(Math.Max(0, ms.Count - 1)).ToList(), orgs),
            ["combined"] = (rule.GetValueOrDefault("kind") as string) == "unanimity" && !rule.ContainsKey("vetoers") ? IntentMultiAgg.CombineIntentMaps(ms, orgs) : null,
        };
    });

    [Fact]
    public void AggregateTwoOmegasFn() => Base.Check(M, "aggregateTwoOmegas", a =>
    {
        var ps = (L)a[2]!;
        var ms = new L
        {
            BuildMap(a[0], null, ((D)ps[0]!)["observations"], ((D)ps[0]!)["ref"]),
            BuildMap(a[1], null, new L(), ((D)ps[1]!)["ref"]),
        };
        return IntentMultiAgg.AggregateIntentMaps(ms, (D)a[3]!, null);
    });

    [Fact]
    public void AggregateOfAggregateFn() => Base.Check(M, "aggregateOfAggregate", a =>
    {
        var ms = Maps(a[0], a[1], null);
        var agg = IntentMultiAgg.AggregateIntentMaps(ms, (D)a[2]!, null);
        return IntentMultiAgg.AggregateIntentMaps(new L { agg, ms[0] }, (D)a[2]!, null);
    });

    [Fact]
    public void LiftOfAggregateFn() => Base.Check(M, "liftOfAggregate", a =>
    {
        var ms = Maps(a[0], a[1], null);
        var agg = IntentMultiAgg.AggregateIntentMaps(ms.Take(1).ToList(), (D)a[2]!, null);
        return IntentMultiAgg.LiftIntentMap(agg, OmegaFromJson(a[0]));
    });

    [Fact]
    public void CrossScenarioFn() => Base.Check(M, "crossScenario", a =>
    {
        var ms = new L();
        foreach (var s in (L)a[0]!)
        {
            var sp = (D)s!;
            ms.Add(BuildMap(sp["omega"], sp.GetValueOrDefault("mapOpts"), sp["observations"], sp["ref"]));
        }
        var rule = (D)a[1]!;
        var orgs = OrgsOf(a[2]);
        var r = IntentMultiAgg.CrossOrgAggregate(ms, rule, orgs);
        var tampered = new L();
        foreach (var f in Muts)
        {
            var copy = (D)IntentJs.Normalize(r.Aggregate)!;
            f(copy);
            tampered.Add(IntentMultiAgg.VerifyCrossOrgAggregate(copy, ms, orgs));
        }
        return new D
        {
            ["aggregate"] = r.Aggregate, ["lifted"] = r.Lifted, ["omega"] = IntentOmega.OmegaToJson(r.Omega), ["digest"] = IntentMapKit.IntentMapDigest(r.Aggregate),
            ["verify"] = IntentMultiAgg.VerifyCrossOrgAggregate(r.Aggregate, ms, orgs), ["tampered"] = tampered,
            ["wrong"] = IntentMultiAgg.VerifyCrossOrgAggregate(r.Aggregate, ms.Skip(Math.Min(1, ms.Count)).ToList(), orgs),
        };
    });

    [Fact]
    public void LiftScenarioFn() => Base.Check(M, "liftScenario", a => IntentMultiAgg.LiftIntentMap(BuildMap(a[0], a[1], a[2], a[3]), OmegaFromJson(a[4])));

    [Fact] public void OmegaKeyFn() => Base.Check(M, "omegaKey", a => IntentMultiAgg.OmegaKey(OmegaFromJson(a[0])));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "aggregateScenario", "aggregateTwoOmegas", "aggregateOfAggregate", "liftOfAggregate", "crossScenario", "liftScenario", "omegaKey" }); Assert.Equal(76, Base.Total(M)); }

    [Fact]
    public void LatticeScenarioFn() => Base.Check(ML, "latticeScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var c = IntentLayers.MakeCeilingAdmitters((D)a[3]!);
        var decisions = ((L)a[4]!).Select(o => (object?)IntentLattice.DecideOutcomeLayers(l, c, OutcomeFromJson(o))).ToList();
        return new D { ["view"] = IntentLattice.LatticeView(l, c), ["decisions"] = decisions };
    });

    [Fact] public void OrgScenarioFn() => Base.Check(ML, "orgScenario", a => IntentLattice.OrgLayerFromMaps((L)a[0]!, (D)a[1]!));

    [Fact] public void LatticeAllFnsHandled() { Base.Covers(ML, new[] { "latticeScenario", "orgScenario" }); Assert.Equal(88, Base.Total(ML)); }
}
