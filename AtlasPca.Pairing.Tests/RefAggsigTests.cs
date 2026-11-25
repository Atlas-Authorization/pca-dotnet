using AtlasPca.Aggsig;
using AtlasPca.Corpus.Tests;
using Xunit;
using Ag = AtlasPca.Aggsig.Aggsig;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Pairing.Tests;

/// <summary>Replays the reference corpus (test-data/ref-aggsig.json.gz) through the native port.</summary>
public class RefAggsigTests
{
    const string M = "ref-aggsig";

    static D Map(object? o) => (D)o!;

    static List<byte[]> BytesList(object? o) => ((L)o!).Select(Base.Bytes).ToList();

    /// <summary>Register every {pk, pop}; null when any refuses (the reference reports {registerFailed: true}).</summary>
    static List<RegisteredKey?>? Reg(object? keys)
    {
        var out_ = new List<RegisteredKey?>();
        foreach (var k in (L)keys!)
        {
            var r = Ag.RegisterKey(Base.Bytes(Map(k)["pk"]), Base.Bytes(Map(k)["pop"]));
            if (!r.Ok) return null;
            out_.Add(r.Key);
        }
        return out_;
    }

    static KeyRegistry Registry(object? keys)
    {
        var r = new KeyRegistry();
        foreach (var k in (L)keys!)
            if (!r.Register(Base.Bytes(Map(k)["pk"]), Base.Bytes(Map(k)["pop"])).Ok) return r;
        return r;
    }

    static D Failed() => new() { ["registerFailed"] = true };

    [Fact] public void PublicKeyOf() => Base.Check(M, "publicKeyOf", a => Ag.PublicKeyOf(Base.Bytes(a[0])));
    [Fact] public void Sign() => Base.Check(M, "sign", a => Ag.Sign(Base.Bytes(a[0]), Base.Bytes(a[1])));
    [Fact] public void PopProve() => Base.Check(M, "popProve", a => Ag.PopProve(Base.Bytes(a[0])));
    [Fact] public void Verify() => Base.Check(M, "verify", a => Ag.Verify(Base.Bytes(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2])));
    [Fact] public void KeyValidate() => Base.Check(M, "keyValidate", a => Ag.KeyValidate(Base.Bytes(a[0])));

    [Fact]
    public void RegisterKey() => Base.Check(M, "registerKey", a =>
    {
        var r = Ag.RegisterKey(Base.Bytes(a[0]), Base.Bytes(a[1]));
        var o = new D { ["ok"] = r.Ok };
        if (!r.Ok) o["reason"] = r.Reason;
        return o;
    });

    [Fact] public void Aggregate() => Base.Check(M, "aggregate", a => Ag.Aggregate(BytesList(a[0])));

    [Fact]
    public void AggregateVerify() => Base.Check(M, "aggregateVerify", a =>
    {
        var ks = Reg(a[0]);
        if (ks == null) return Failed();
        return Ag.AggregateVerify(ks, BytesList(a[1]), Base.Bytes(a[2]));
    });

    [Fact]
    public void FastAggregateVerify() => Base.Check(M, "fastAggregateVerify", a =>
    {
        var ks = Reg(a[0]);
        if (ks == null) return Failed();
        return Ag.FastAggregateVerify(ks, Base.Bytes(a[1]), Base.Bytes(a[2]));
    });

    [Fact]
    public void MintBlsRoot() => Base.Check(M, "mintBlsRoot", a =>
        AggsigChain.MintBlsRoot(Base.Bytes(a[0]), (string)a[1]!, (string)a[2]!, (L)a[3]!));

    [Fact]
    public void ChainDelegate() => Base.Check(M, "chainDelegate", a =>
        AggsigChain.BlsDelegate(Map(a[0]), (string)a[1]!, (L)a[2]!, Base.Bytes(a[3])));

    [Fact]
    public void ChainAttenuate() => Base.Check(M, "chainAttenuate", a =>
        AggsigChain.BlsAttenuate(Map(a[0]), (L)a[1]!, Base.Bytes(a[2])));

    [Fact] public void CapHash() => Base.Check(M, "capHash", a => AggsigChain.CapHash(Map(a[0])));

    [Fact]
    public void AggregateChainSignatures() => Base.Check(M, "aggregateChainSignatures", a => AggsigChain.AggregateChainSignatures((L)a[0]!));

    [Fact]
    public void VerifyAggregatedChain() => Base.Check(M, "verifyAggregatedChain", a =>
        AggsigChain.VerifyAggregatedChain((L)a[0]!, Base.Bytes(a[1]), Registry(a[2]), a[3] as string));

    [Fact] public void CosignTreeHead() => Base.Check(M, "cosignTreeHead", a => AggsigWitness.CosignTreeHead(Map(a[0]), Base.Bytes(a[1])));
    [Fact] public void VerifyWitnessCosignature() => Base.Check(M, "verifyWitnessCosignature", a => AggsigWitness.VerifyWitnessCosignature(Map(a[0]), Map(a[1])));

    [Fact]
    public void AggregateWitnessCosignatures() => Base.Check(M, "aggregateWitnessCosignatures", a =>
        AggsigWitness.AggregateWitnessCosignatures(((L)a[0]!).Select(Map).ToList()));

    [Fact]
    public void VerifyAggregatedWitnessCosignatures() => Base.Check(M, "verifyAggregatedWitnessCosignatures", a =>
    {
        var ks = Reg(a[1]);
        if (ks == null) return Failed();
        return AggsigWitness.VerifyAggregatedWitnessCosignatures(Map(a[0]), ks, Base.Bytes(a[2]));
    });

    [Fact]
    public void EveryFnIsCovered() { Base.Covers(M, new[]
    {
        "publicKeyOf", "sign", "popProve", "verify", "keyValidate", "registerKey", "aggregate", "aggregateVerify", "fastAggregateVerify",
        "mintBlsRoot", "chainDelegate", "chainAttenuate", "capHash", "aggregateChainSignatures", "verifyAggregatedChain",
        "cosignTreeHead", "verifyWitnessCosignature", "aggregateWitnessCosignatures", "verifyAggregatedWitnessCosignatures",
    }); Assert.Equal(552, Base.Total(M)); }
}
