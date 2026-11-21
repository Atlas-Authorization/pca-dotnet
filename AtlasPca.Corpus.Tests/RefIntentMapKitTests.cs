using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the Intent Map (emit, verify, digests, committed form, divergence) against the TypeScript reference
/// (test-data/ref-intent-map.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentMapKitTests
{
    const string M = "ref-intent-map";

    static byte[] Secret(int seed) => Enumerable.Range(0, 32).Select(i => (byte)((seed + 7 * i) & 255)).ToArray();

    static void Add(D m, string key, double d) => m[key] = new Num(((long)(Dbl(m[key]) + d)).ToString(System.Globalization.CultureInfo.InvariantCulture));

    static D Cell0(D m) => (D)((L)m["cells"]!)[0]!;

    static readonly List<Action<D>> Muts = new()
    {
        m => { },
        m => Add((D)m["metrics"]!, "residual_risk_ppm", 5),
        m => Add(Cell0(m), "p_ppm", 3),
        m => { var c = Cell0(m); c["in_grant"] = !(bool)c["in_grant"]!; },
        m => m["grant_digest"] = "AAAA",
        m => { var o = (L)m["observations"]!; if (o.Count > 0) o.RemoveAt(o.Count - 1); },
        m => m["kind"] = "x",
        m => m["principals"] = new L { "a", "b" },
        m => m["aggregation"] = new D { ["rule"] = "unanimity" },
        m => ((D)m["metrics"]!).Remove("log2_vs_mbits"),
        m => Add((D)m["learner"]!, "eta_ppm", 100000),
        m => Add((D)m["metrics"]!, "questions", 1),
        m => { var c = (L)m["cells"]!; c.RemoveAt(c.Count - 1); },
        m => ((D)((L)((D)m["omega"]!)["verbs"]!)[0]!)["w"] = new Num("5"),
        m => ((D)m["metrics"]!)["log2_vs_mbits"] = null,
        m => Add(Cell0(m), "p_ppm", 2),
        m => Add(Cell0(m), "p_ppm", 1),
    };

    static IntentLearner Build(L a)
    {
        var l = IntentMapKit.CreateLearner(OmegaFromJson(a[0]), IntentMapKit.MapLearnerOptions.FromJson(a[1]));
        foreach (var xo in (L)a[2]!)
        {
            var x = (D)xo!;
            l.Observe(OutcomeFromJson(x), (int)Dbl(x["y"]), (string)x["source"]!, null);
        }
        return l;
    }

    static object? Scenario(L a)
    {
        var omega = OmegaFromJson(a[0]);
        var l = Build(a);
        var reference = a[3] as string;
        int seed = (int)Dbl(a[4]);
        var map = IntentMapKit.EmitIntentMap(l, reference);
        var tampered = new L();
        foreach (var f in Muts)
        {
            var copy = (D)IntentJs.Normalize(map)!;
            f(copy);
            tampered.Add(IntentMapKit.VerifyIntentMap(copy));
        }
        tampered.Add(IntentMapKit.VerifyIntentMap(null));
        tampered.Add(IntentMapKit.VerifyIntentMap(new D { ["v"] = new Num("2") }));
        var output = new D
        {
            ["map"] = map,
            ["digest"] = IntentMapKit.IntentMapDigest(map),
            ["grantDigest"] = IntentMapKit.GrantDigest(map["grant"]),
            ["verify"] = IntentMapKit.VerifyIntentMap(map),
            ["tampered"] = tampered,
            ["options"] = IntentMapKit.MapLearnerOptionsOf(map).ToJson(),
            ["omegaRoundtrip"] = IntentMapKit.OmegaToJson(IntentMapKit.OmegaFromJson(map["omega"])),
        };
        var commit = new D();
        try
        {
            var cm = IntentMapKit.CommitIntentMap(map, Secret(seed));
            commit["map_commit"] = cm.MapCommit;
            commit["size"] = N(cm.Size);
            commit["leaves"] = cm.LeavesJson();
            var ds = new L();
            foreach (var vs in omega.Verbs)
            {
                double t = VerbCellCount(vs);
                foreach (double f in new[] { 0, Math.Floor(t / 2), t - 1 })
                {
                    var oc = CellRep(vs, DecodeCell(vs, f));
                    var ps = new D();
                    object? resource = null;
                    foreach (var e in oc.Values)
                    {
                        if (e.Key == "action.resource") resource = e.Value;
                        else ps[e.Key.Substring("action.params.".Length)] = e.Value;
                    }
                    ds.Add(cm.Disclose(vs.Verb, resource, ps));
                }
            }
            commit["disclosures"] = ds;
        }
        catch (Exception)
        {
            commit.Clear();
            commit["error"] = true;
        }
        output["commit"] = commit;
        return output;
    }

    [Fact] public void MapScenarios() => Base.Check(M, "mapScenario", Scenario);

    [Fact]
    public void CommitIntentMapFn() => Base.Check(M, "commitIntentMap", a =>
    {
        var cm = IntentMapKit.CommitIntentMap(a[0], Secret(3));
        return new D { ["map_commit"] = cm.MapCommit, ["size"] = N(cm.Size), ["leaves"] = cm.LeavesJson() };
    });

    [Fact] public void CommitRejectsShortSecret() => Assert.Throws<ArgumentException>(() => IntentMapCommitKit.CommitMap(new List<D>(), new Dictionary<string, List<D>>(), new D(), "x", new byte[31]));

    [Fact] public void GrantDigestFn() => Base.Check(M, "grantDigest", a => IntentMapKit.GrantDigest(a[0]));
    [Fact] public void IntentMapDigestFn() => Base.Check(M, "intentMapDigest", a => IntentMapKit.IntentMapDigest(a[0]));
    [Fact] public void OmegaToJsonFn() => Base.Check(M, "omegaToJSON", a => IntentMapKit.OmegaToJson(OmegaFromJson(a[0])));
    [Fact] public void OmegaFromJsonFn() => Base.Check(M, "omegaFromJSON", a => IntentOmega.OmegaToJson(IntentMapKit.OmegaFromJson(a[0])));

    [Fact]
    public void DivergenceFn() => Base.Check(M, "divergence", a =>
    {
        var l = Build(a);
        var output = new L();
        foreach (var d in (L)a[3]!)
        {
            var dm = (D)d!;
            output.Add(IntentMapKit.ApplyDivergence(l, OutcomeFromJson(dm["outcome"]), (int)Dbl(dm["y"])));
        }
        return output;
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "mapScenario", "commitIntentMap", "grantDigest", "intentMapDigest", "omegaToJSON", "omegaFromJSON", "divergence" }); Assert.Equal(183, Base.Total(M)); }
}
