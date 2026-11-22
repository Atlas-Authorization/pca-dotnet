using AtlasPca.Invariants;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the deterministic exports of the invariants package (seeded keys, the legal-chain builder, worsen, the registry
/// constants). The property functions and the property-based runner are not generated (no property-testing library in the native SDK).</summary>
public class RefInvariantsTests
{
    const string M = "ref-invariants";

    static double N(D d, string k) => JsJson.ToJsNumber(d[k]);
    static RiskAxes Axes(object? o) { var d = (D)o!; return new RiskAxes(N(d, "semanticDistance"), N(d, "blastRadius"), N(d, "taint"), N(d, "age"), N(d, "reversibility"), N(d, "confidence")); }
    static RiskDeltas Deltas(object? o) { var d = (D)o!; return new RiskDeltas(N(d, "dSem"), N(d, "dBlast"), N(d, "dTaint"), N(d, "dAge"), N(d, "dRev"), N(d, "dConf")); }

    [Fact]
    public void KeyPairFromSeed() => Base.Check(M, "keyPairFromSeed", a =>
    {
        var k = PcaInvariants.KeyPairFromSeed(Base.Bytes(a[0]));
        return new D { ["secretKey"] = k.SecretKey, ["publicKey"] = k.PublicKey, ["pub"] = k.Pub };
    });

    [Fact]
    public void BuildChain() => Base.Check(M, "buildChain", a =>
    {
        var m = (D)a[0]!;
        var hops = ((L)m["hops"]!).Cast<D>().Select(h => new HopModel(Base.Bytes(h["holderSeed"]), ((L)h["addedSpecs"]!).Cast<D>().ToList())).ToList();
        var model = new ChainModel(Base.Bytes(m["principalSeed"]), Base.Bytes(m["holder0Seed"]), ((L)m["rootSpecs"]!).Cast<D>().ToList(), hops, m["predicates"]);
        return PcaInvariants.BuildChain(model).ToTree();
    });

    [Fact] public void Worsen() => Base.Check(M, "worsen", a => PcaInvariants.Worsen(Axes(a[0]), Deltas(a[1])).ToTree());

    [Fact]
    public void Consts() => Base.Check(M, "consts", _ => new D
    {
        ["DEFAULT_SEED"] = PcaInvariants.DefaultSeed,
        ["DEFAULT_NUM_RUNS"] = PcaInvariants.DefaultNumRuns,
        ["INVARIANT_NAMES"] = PcaInvariants.InvariantNames.Cast<object?>().ToList(),
    });

    [Fact] public void EveryFnHasATest() { Base.Covers(M, new[] { "keyPairFromSeed", "buildChain", "worsen", "consts" }); Assert.Equal(312, Base.Total(M)); }
}
