using System.Numerics;
using AtlasPca.Abe;
using AtlasPca.Pairing;
using AbeLib = AtlasPca.Abe.Abe; // the class shares its name with its namespace
using static supranational.blst;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the TypeScript-reference corpus (test-data/ref-abe.json.gz) through the native FAME port.</summary>
public class RefAbeTests
{
    const string M = "ref-abe";

    static BigInteger Unhex(object? s) => Bls12.Os2ip(Convert.FromHexString((string)s!));
    static BigInteger[] Scalars(object? l) => ((L)l!).Select(Unhex).ToArray();
    static List<string> Strings(object? l) => ((L)l!).Select(x => (string)x!).ToList();
    static List<byte[]> BytesList(object? o) => ((L)o!).Select(Base.Bytes).ToList();
    static L G1s(P1[] p) => p.Select(x => (object?)x.compress()).ToList();
    static L G2s(P2[] p) => p.Select(x => (object?)x.compress()).ToList();

    [Fact] public void GenCorpusIsPresent() => Base.RequireGenCorpus(M);
    [Fact]
    public void Fame() => Base.Check(M, "fame", a =>
    {
        var n = AbePolicy.Normalize(a[0]);
        if (!n.Ok) throw new ArgumentException(n.Reason);
        var attrs = Strings(a[1]);
        var s = (D)a[2]!;
        var ms = AtlasPca.Abe.Fame.Setup(Scalars(s["a"]), Scalars(s["b"]), Scalars(s["d"]));
        var sg = Scalars(s["sigma"]).ToList();
        var key = AtlasPca.Abe.Fame.Keygen(ms.Msk, attrs, Scalars(s["r"]), sg, Unhex(s["sigmaPrime"]));
        var e = AtlasPca.Abe.Fame.Encrypt(ms.Mpk, n.Tree!, Scalars(s["s"]));
        var dec = AtlasPca.Abe.Fame.Decrypt(key, n.Tree!, e.Ct);
        var ka = new D();
        foreach (var en in key.Attrs) ka[en.Key] = G1s(en.Value);
        var rows = new L();
        foreach (var r in e.Ct.Rows) rows.Add(G1s(r));
        return new D
        {
            ["h"] = new L { ms.Mpk.H1.compress(), ms.Mpk.H2.compress() },
            ["t"] = new L { ms.Mpk.T1, ms.Mpk.T2 },
            ["mskg"] = G1s(ms.Msk.G),
            ["k0"] = G2s(key.K0),
            ["kp"] = G1s(key.Kp),
            ["key"] = ka,
            ["ct0"] = G2s(e.Ct.Ct0),
            ["rows"] = rows,
            ["k"] = e.K,
            ["dec"] = dec,
        };
    });

    [Fact] public void GtIsElement() => Base.Check(M, "gtIsElement", a => Gt.IsElement(Base.Bytes(a[0])));
    [Fact] public void GtPow() => Base.Check(M, "gtPow", a => Gt.Pow(Base.Bytes(a[0]), Unhex(a[1])));
    [Fact] public void GtMul() => Base.Check(M, "gtMul", a => Gt.Mul(Base.Bytes(a[0]), Base.Bytes(a[1])));

    [Fact]
    public void PairingProduct() => Base.Check(M, "pairingProduct", a =>
    {
        var p = BytesList(a[0]).Select(Bls12.DecodeG1).ToList();
        var q = BytesList(a[1]).Select(Bls12.DecodeG2).ToList();
        return Gt.PairingProduct(p, q);
    });

    [Fact] public void NormalizePolicy() => Base.Check(M, "normalizePolicy", a => AbePolicy.Normalize(a[0]).ToJson());
    [Fact] public void Satisfies() => Base.Check(M, "satisfies", a => AbePolicy.Satisfies((D)a[0]!, new HashSet<string>(Strings(a[1]))));
    [Fact] public void PolicyAttributes() => Base.Check(M, "policyAttributes", a => AbePolicy.PolicyAttributes((D)a[0]!));
    [Fact] public void ParseCiphertext() => Base.Check(M, "parseCiphertext", a => AbeLib.ParseCiphertext(a[0]));
    [Fact] public void Decrypt() => Base.Check(M, "decrypt", a => AbeLib.Decrypt(a[0], a[1]));
    [Fact] public void DecryptText() => Base.Check(M, "decryptText", a => AbeLib.DecryptText(a[0], a[1]));
    [Fact] public void DecryptWithCapability() => Base.Check(M, "decryptWithCapability", a => AbeLib.DecryptWithCapability(a[0], a[1]));

    [Fact]
    public void EncryptAccepts() => Base.Check(M, "encryptAccepts", a =>
    {
        AbeLib.EncryptForPolicy(a[0], a[1], "x");
        return true;
    });

    [Fact]
    public void KeygenForAttributes() => Base.Check(M, "keygenForAttributes", a =>
        ((D)AbeLib.KeygenForAttributes(a[0], Strings(a[1]))["attrs"]!).Keys.Select(k => (object?)k).ToList());

    [Fact]
    public void KeygenForCapability() => Base.Check(M, "keygenForCapability", a =>
    {
        var k = AbeLib.KeygenForCapability(a[0], (D)a[1]!, Strings(a[2]), (D)a[3]!);
        return new D
        {
            ["holder"] = k.GetValueOrDefault("holder"),
            ["attrs"] = ((D)k["attrs"]!).Keys.Select(x => (object?)x).ToList(),
        };
    });

    [Fact]
    public void CapabilityAttributes() => Base.Check(M, "capabilityAttributes", a =>
        AbeLib.CapabilityAttributes((D)a[0]!, (D)a[1]!).Select(x => (object?)x).ToList());

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "fame", "gtIsElement", "gtPow", "gtMul", "pairingProduct", "normalizePolicy", "satisfies", "policyAttributes", "parseCiphertext",
        "decrypt", "decryptText", "decryptWithCapability", "encryptAccepts", "keygenForAttributes", "keygenForCapability", "capabilityAttributes",
    }); Assert.Equal(254, Base.Total(M)); }
}
