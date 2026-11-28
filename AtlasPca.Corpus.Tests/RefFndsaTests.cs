using AtlasPca;
using Xunit;
using F = AtlasPca.Fndsa.Fndsa;
using AtlasPca.Fndsa;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the FN-DSA suite registry, leaf framing and hybrid composition (test-data/ref-fndsa.json.gz, TS reference
/// packages/pca-fndsa). Every case runs through the deterministic mock backend or an explicit stub backend (the reference ships no Falcon math).</summary>
// serialised with the suites that need the backend ABSENT (ProducerVectorTests): the registered backend is process-wide, every case resets it in finally
[Collection("fndsa-global-backend")]
public class RefFndsaTests
{
    const string M = "ref-fndsa";

    static byte[]? B(object? a) => Base.IsBytes(a) ? Base.Bytes(a) : null;
    static D? Rec(object? a) => a as D;

    static void Install(string kind)
    {
        F.ResetFalconBackend();
        var mock = F.RegisterTestBackend();
        switch (kind)
        {
            case "mock": return;
            case "none": F.ResetFalconBackend(); return;
            case "verify-only": F.SetFalconBackend(new FalconBackend { Verify = mock.Verify }); return;
            case "short-sig": F.SetFalconBackend(new FalconBackend { Verify = mock.Verify, Sign = (_, _) => new byte[10] }); return;
            case "all-true": F.SetFalconBackend(new FalconBackend { Verify = (_, _, _) => true, Sign = mock.Sign }); return;
            case "throws": F.SetFalconBackend(new FalconBackend { Verify = (_, _, _) => throw new InvalidOperationException("backend exploded"), Sign = mock.Sign }); return;
            default: throw new InvalidOperationException("kind " + kind);
        }
    }

    static T With<T>(string kind, Func<T> f)
    {
        try { Install(kind); return f(); } finally { F.ResetFalconBackend(); }
    }

    static List<FalconKat> Kats(object? a) =>
        ((L)a!).Select(v => { var d = (D)v!; return new FalconKat(Base.Bytes(d["pk"]), Base.Bytes(d["msg"]), Base.Bytes(d["sig"])); }).ToList();

    static D Pair(FalconKeyPair k) => new() { ["pk"] = k.Pk, ["sk"] = k.Sk };

    [Fact] public void ResolveFnDsaAlg() => Base.Check(M, "resolveFnDsaAlg", a => F.ResolveFnDsaAlg(a[0])?.ToJson());
    [Fact] public void IsKnownFnDsaAlg() => Base.Check(M, "isKnownFnDsaAlg", a => F.IsKnownFnDsaAlg(a[0]));
    [Fact] public void IsFnDsaVariant() => Base.Check(M, "isFnDsaVariant", a => F.IsFnDsaVariant(a[0]));
    [Fact] public void HashKat() => Base.Check(M, "hashKat", a => F.HashKat(Base.Bytes(a[0]), (int)Base.Long(a[1])));

    [Fact]
    public void MockKeypair() => Base.Check(M, "mockKeypair", a =>
        Pair(F.MockKeypair(a[0] as string ?? "", a.Count > 1 ? (Base.IsBytes(a[1]) ? Base.Bytes(a[1]) : a[1]) : null)));

    [Fact] public void LeafMessage() => Base.Check(M, "fndsaLeafMessage", a => F.FndsaLeafMessage((D)a[0]!, (string)a[1]!, (string)a[2]!));

    [Fact]
    public void SignWith() => Base.Check(M, "fndsaSignWith", a => With((string)a[0]!, () => F.FndsaSign((string)a[1]!, B(a[2]), B(a[3]))));

    [Fact]
    public void VerifyWith() => Base.Check(M, "fndsaVerifyWith", a => With((string)a[0]!, () => F.FndsaVerify(a[1], B(a[2]), B(a[3]), B(a[4]))));

    [Fact]
    public void VerifyKat() => Base.Check(M, "fndsaVerifyKat", a =>
    {
        F.ResetFalconBackend();
        F.RegisterTestBackend(Kats(a[4]));
        try { return F.FndsaVerify(a[0], B(a[1]), B(a[2]), B(a[3])); } finally { F.ResetFalconBackend(); }
    });

    [Fact]
    public void SignKat() => Base.Check(M, "fndsaSignKat", a =>
    {
        var vs = Kats(a[0]);
        var variant = vs[0].Pk.Length == F.FnDsa512PublicKeyBytes ? "fn-dsa-512" : "fn-dsa-1024";
        var kp = F.MockKeypair(variant, "ref");
        F.ResetFalconBackend();
        F.RegisterTestBackend(vs);
        try { return F.FndsaSign(variant, kp.Sk, System.Text.Encoding.UTF8.GetBytes("m")); } finally { F.ResetFalconBackend(); }
    });

    static object? SignPca(D x)
    {
        FalconKeyPair? kp = x.GetValueOrDefault("fnDsa") is D f ? new FalconKeyPair(B(f.GetValueOrDefault("pk"))!, B(f.GetValueOrDefault("sk"))!) : null;
        return With("mock", () => F.SignPcaWithFndsa(x.GetValueOrDefault("alg"), (D)x["leaf"]!, kp, B(x.GetValueOrDefault("edSecret"))));
    }

    static bool VerifyPca(string kind, D x) => With(kind, () => F.VerifyPcaFndsa(x.GetValueOrDefault("alg"), (D)x["leaf"]!, x.GetValueOrDefault("holder"), x.GetValueOrDefault("pq_pk"), x.GetValueOrDefault("sig"), x.GetValueOrDefault("pq_sig")));

    [Fact] public void SignPcaWithFndsa() => Base.Check(M, "signPcaWithFndsa", a => SignPca((D)a[0]!));
    [Fact] public void VerifyPcaFndsa() => Base.Check(M, "verifyPcaFndsa", a => VerifyPca("mock", (D)a[0]!));
    [Fact] public void VerifyPcaFndsaNone() => Base.Check(M, "verifyPcaFndsaNone", a => VerifyPca("none", (D)a[0]!));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "resolveFnDsaAlg", "isKnownFnDsaAlg", "isFnDsaVariant", "hashKat", "mockKeypair", "fndsaLeafMessage", "fndsaSignWith", "fndsaVerifyWith",
        "fndsaVerifyKat", "fndsaSignKat", "signPcaWithFndsa", "verifyPcaFndsa", "verifyPcaFndsaNone",
    }); Assert.Equal(480, Base.Total(M)); }
}
