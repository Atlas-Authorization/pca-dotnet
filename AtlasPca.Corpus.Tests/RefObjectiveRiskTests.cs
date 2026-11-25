using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the objective risk functional over test-data/ref-objective-risk.json.gz: the canonical action, the inverse registry and reversibility, the resource graph and blast radius, the native
/// and customer-model embedders, the goal commitment and distance, calibration, the harm currency, the composition and the dispute-game oracle. A non-finite number is {"$num": text} in the corpus and a double
/// here. Specs: a registry {trusted, entries: [[verb, entry]...]}; a graph {nodes, edges}; an embedder {scheme: native, config} | {scheme: byo, descriptor, claimedModelId?, infer} (infer: {vector} | {throws} |
/// {notArray} | {byLen}) | {scheme: fixed, modelId, dims, config, vector} (returns the vector verbatim); a context as the generator documents. A reason that starts with the engine text "Cannot read properties" is
/// compared as "some reason" (that text is the JavaScript engine's).</summary>
public class RefObjectiveRiskTests
{
    const string M = "ref-objective-risk";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? Out(object? v) => v switch
    {
        double d when double.IsNaN(d) => new D { ["$num"] = "NaN" },
        double d when double.IsPositiveInfinity(d) => new D { ["$num"] = "Infinity" },
        double d when double.IsNegativeInfinity(d) => new D { ["$num"] = "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Out(e.Value)),
        L l => l.Select(Out).ToList(),
        _ => v,
    };

    sealed class FixedEmbedder : IEmbedder
    {
        readonly object? _vector;
        public FixedEmbedder(string id, object? config, double dims, object? vector) { ModelId = id; Config = config; Dims = dims; _vector = vector; }
        public string ModelId { get; }
        public object? Config { get; }
        public double Dims { get; }
        public object? Embed(D canonicalAction) => _vector;
    }

    static InMemoryInverseRegistry Registry(object? spec)
    {
        var s = (D)Nums(spec)!;
        var r = new InMemoryInverseRegistry(((L?)s.GetValueOrDefault("trusted") ?? new L()).Cast<string>());
        foreach (var e in (L?)s.GetValueOrDefault("entries") ?? new L()) r.Register((string)((L)e!)[0]!, (D)((L)e!)[1]!);
        return r;
    }

    static ResourceGraph Graph(object? spec)
    {
        var s = (D)Nums(spec)!;
        var g = new ResourceGraph();
        foreach (var n in (L?)s.GetValueOrDefault("nodes") ?? new L()) g.AddNode((D)n!);
        foreach (var e in (L?)s.GetValueOrDefault("edges") ?? new L()) g.AddEdge((D)e!);
        return g;
    }

    static Func<string, object?> Infer(object? spec, object? descriptor)
    {
        var i = (D)Nums(spec)!;
        return json =>
        {
            if (i.GetValueOrDefault("throws") is true) throw new InvalidOperationException("infer boom");
            if (i.GetValueOrDefault("notArray") is true) return "x";
            if (i.GetValueOrDefault("byLen") is true)
            {
                var dims = (int)IntentJs.NumOf(((D)descriptor!)["dims"])!.Value;
                return new L(Enumerable.Range(0, dims).Select(k => (object?)IntentJs.OfLong(json.Length + k)));
            }
            return i["vector"];
        };
    }

    static IEmbedder Embedder(object? spec)
    {
        var s = (D)Nums(spec)!;
        switch (s["scheme"] as string)
        {
            case "native": return ObjectiveRisk.NativeEmbedder(s["config"]);
            case "fixed": return new FixedEmbedder((string)s["modelId"]!, s["config"], IntentJs.NumOf(s["dims"])!.Value, s["vector"]);
            default: return ObjectiveRisk.ByoEmbedder(s["descriptor"], Infer(s["infer"], s["descriptor"]), s.GetValueOrDefault("claimedModelId") as string);
        }
    }

    static ObjectiveRiskContext Context(object? spec)
    {
        var c = (D)spec!;
        var ctx = new ObjectiveRiskContext
        {
            Registry = Registry(c["registry"]), AuthorizedKinds = ((L)c["authorizedKinds"]!).Cast<string>().ToHashSet(StringComparer.Ordinal), Graph = Graph(c["graph"]),
            Embedder = Embedder(c["embedder"]), Goal = c["goal"], Commitments = c["commitments"], Denominations = (L)c["denominations"]!, Weights = c["weights"],
            Taint = c.GetValueOrDefault("taint"), Age = c.GetValueOrDefault("age"),
        };
        if (c.GetValueOrDefault("scope") is D sc) ctx.Scope = sc;
        if (c.TryGetValue("attestedUncertainty", out var au)) ctx.AttestedUncertainty = au;
        if (c.GetValueOrDefault("calibration") is L cal) ctx.Calibration = cal;
        return ctx;
    }

    static object? Opt(L a, int i) => a.Count > i && a[i] != null ? Nums(a[i]) : null;

    static bool EngineText(object? s) => s is string t && t.StartsWith("Cannot read properties", StringComparison.Ordinal);

    // a reason that is the JavaScript engine's own text matches any reason
    static bool SameOrEngineReason(D c, object? have)
    {
        var want = c["out"];
        if (EngineText(want)) return have is string;
        if (want is D w && EngineText(w.GetValueOrDefault("reason"))) return have is D h && h.GetValueOrDefault("ok") is false && h.GetValueOrDefault("reason") is string;
        return Base.Eq(want, have);
    }

    [Fact] public void Constants() => Base.Check(M, "constants", _ => Out(ObjectiveRisk.Constants()));
    [Fact] public void CanonicalAction() => Base.Check(M, "canonicalAction", a => Out(ObjectiveRisk.CanonicalAction(Nums(a[0]))), min: 39);
    [Fact] public void CanonicalActionJson() => Base.Check(M, "canonicalActionJson", a => ObjectiveRisk.CanonicalActionJson(Nums(a[0])), min: 23);
    [Fact] public void CanonicalActionDigest() => Base.Check(M, "canonicalActionDigest", a => ObjectiveRisk.CanonicalActionDigest(Nums(a[0])), min: 23);
    [Fact] public void RegistryDigest() => Base.Check(M, "registryDigest", a => Registry(a[0]).Digest(), min: 8);

    [Fact]
    public void RegistryOps() => Base.Check(M, "registryOps", a =>
    {
        var r = new InMemoryInverseRegistry(((L)a[0]!).Cast<string>());
        var res = new L();
        foreach (var oo in (L)a[1]!)
        {
            var op = (L)oo!;
            switch ((string)op[0]!)
            {
                case "register": r.Register((string)op[1]!, (D)op[2]!); res.Add(null); break;
                case "lookup": res.Add(r.Lookup((string)op[1]!)); break;
                case "trustedVerifiers": res.Add(new L(r.TrustedVerifiers().Cast<object?>())); break;
                default: res.Add(r.Digest()); break;
            }
        }
        return res;
    }, min: 3);

    [Fact] public void Reversibility() => Base.Check(M, "reversibility", a => Out(ObjectiveRisk.Reversibility(Nums(a[0]), Registry(a[1]), ((L)a[2]!).Cast<string>().ToHashSet(StringComparer.Ordinal))), min: 224);

    [Fact]
    public void GraphBuild() => Base.Check(M, "graphBuild", a =>
    {
        var g = Graph(a[0]);
        return new D { ["size"] = (long)g.Size, ["digest"] = g.Digest() };
    }, min: 17);

    [Fact] public void GraphReachable() => Base.Check(M, "graphReachable", a => new L(Graph(a[0]).Reachable((string)a[1]!, Opt(a, 2)).Cast<object?>()), min: 1190);
    [Fact] public void GraphNode() => Base.Check(M, "graphNode", a => Out(Graph(a[0]).Node((string)a[1]!)), min: 102);
    [Fact] public void BlastRadius() => Base.Check(M, "blastRadius", a => Out(ObjectiveRisk.BlastRadius(Nums(a[0]), Graph(a[1]), Opt(a, 2))), min: 1190);

    [Fact]
    public void NativeEmbed() => Base.Check(M, "nativeEmbed", a =>
    {
        var e = ObjectiveRisk.NativeEmbedder(Nums(a[0]));
        var vector = e.Embed((D)Nums(a[1])!);
        return new D { ["modelId"] = e.ModelId, ["dims"] = e.Dims, ["config"] = e.Config, ["vector"] = vector };
    }, min: 98);

    [Fact] public void ByoModelId() => Base.Check(M, "byoModelId", a => ObjectiveRisk.ByoModelId(Nums(a[0])), min: 18);

    [Fact]
    public void ByoEmbed() => Base.Check(M, "byoEmbed", a =>
    {
        var d = Nums(a[0]);
        var e = ObjectiveRisk.ByoEmbedder(d, Infer(a[2], d), a[1] as string);
        return new D { ["modelId"] = e.ModelId, ["dims"] = e.Dims, ["vector"] = e.Embed((D)Nums(a[3])!) };
    }, min: 39);

    [Fact] public void ValidateVector() => Base.Check(M, "validateVector", a => ObjectiveRisk.ValidateVector(Nums(a[0]), IntentJs.NumOf(a[1])!.Value), min: 17);
    [Fact] public void ConformanceCheck() => Base.Check(M, "conformanceCheck", a => ObjectiveRisk.ConformanceCheck(Embedder(a[0]), (L)Nums(a[1])!), min: 10);
    [Fact] public void CommitGoal() => Base.Check(M, "commitGoal", a => Out(ObjectiveRisk.CommitGoal(Embedder(a[0]), Nums(a[1]), Opt(a, 2))), min: 36);
    [Fact] public void VerifyGoalCommitment() => Base.Check(M, "verifyGoalCommitment", a => ObjectiveRisk.VerifyGoalCommitment(Nums(a[0]), Embedder(a[1])), eq: SameOrEngineReason, min: 88);
    [Fact] public void VectorDistance() => Base.Check(M, "vectorDistance", a => ObjectiveRisk.VectorDistance((L)Nums(a[0])!, (L)Nums(a[1])!, a[2] == null ? ObjectiveRisk.DefaultEpsilon : IntentJs.NumOf(a[2])!.Value), min: 168);
    [Fact] public void CommittedDistanceChecked() => Base.Check(M, "committedDistanceChecked", a => Out(ObjectiveRisk.CommittedDistanceChecked((D)Nums(a[0])!, Nums(a[1]), Embedder(a[2]))), eq: SameOrEngineReason, min: 40);
    [Fact] public void CommittedDistance() => Base.Check(M, "committedDistance", a => ObjectiveRisk.CommittedDistance(Nums(a[0]), Nums(a[1]), Embedder(a[2])), min: 40);
    [Fact] public void Calibrate() => Base.Check(M, "calibrate", a => ObjectiveRisk.Calibrate(Nums(a[0]), (L)Nums(a[1])!), min: 154);
    [Fact] public void ConformalThreshold() => Base.Check(M, "conformalThreshold", a => Out(ObjectiveRisk.ConformalThreshold((L)Nums(a[0])!, Nums(a[1]))), min: 121);
    [Fact] public void CalibrationDigest() => Base.Check(M, "calibrationDigest", a => ObjectiveRisk.CalibrationDigest((L)Nums(a[0])!), min: 13);
    [Fact] public void HarmReport() => Base.Check(M, "harmReport", a => Out(ObjectiveRisk.HarmReport(Nums(a[0]), (L)Nums(a[1])!)), min: 108);
    [Fact] public void ObjectiveRiskCases() => Base.Check(M, "objectiveRisk", a => Out(ObjectiveRisk.Evaluate(Nums(a[0]), Context(Nums(a[1])))), min: 178);
    [Fact] public void ObjectiveRiskOracle() => Base.Check(M, "objectiveRiskOracle", a => Out(ObjectiveRisk.ResolveOracle(Context(Nums(a[0])), a[1], a[2])), min: 104);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "canonicalAction", "canonicalActionJson", "canonicalActionDigest", "registryDigest", "registryOps", "reversibility", "graphBuild", "graphNode", "graphReachable", "blastRadius",
            "nativeEmbed", "byoModelId", "byoEmbed", "validateVector", "commitGoal", "verifyGoalCommitment", "vectorDistance", "committedDistanceChecked", "committedDistance", "conformanceCheck",
            "calibrate", "conformalThreshold", "calibrationDigest", "harmReport", "objectiveRisk", "objectiveRiskOracle",
        });
        Assert.Equal(4052, Base.Total(M));
    }
}
