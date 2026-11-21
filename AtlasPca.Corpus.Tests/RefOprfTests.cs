using System.Numerics;
using AtlasPca;
using Xunit;
using O = AtlasPca.Oprf.Oprf;
using OP = AtlasPca.Oprf.OprfPca;
using AtlasPca.Oprf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 and the PCA private-membership layer
/// (test-data/ref-oprf.json.gz, TS reference packages/pca-oprf). Keys derive from fixed seeds and every randomised step is pinned.</summary>
public class RefOprfTests
{
    const string M = "ref-oprf";

    static byte[]? B(object? a) => Base.IsBytes(a) ? Base.Bytes(a) : null;
    static string Md(object? a) => a as string ?? "";
    static object? Opt(L a, int i) => a.Count > i ? a[i] : null;
    static D Bl(BlindResult r) => new() { ["blind"] = r.Blind, ["blindedElement"] = r.BlindedElement };
    static D Ev(EvaluateResult r)
    {
        var d = new D { ["evaluatedElement"] = r.EvaluatedElement };
        if (r.Proof != null) d["proof"] = r.Proof;
        return d;
    }

    [Fact] public void GenCorpusIsPresent() => Base.RequireGenCorpus(M);
    [Fact]
    public void DeriveKeyPair() => Base.Check(M, "deriveKeyPair", a =>
    {
        var k = O.DeriveKeyPair(B(a[0])!, B(a[1])!, Md(a[2]));
        return new D { ["secretKey"] = k.SecretKey, ["publicKey"] = k.PublicKey };
    });

    [Fact] public void PublicKeyFor() => Base.Check(M, "publicKeyFor", a => O.PublicKeyFor(B(a[0])!));
    [Fact] public void DeserializeScalar() => Base.Check(M, "deserializeScalar", a => O.DeserializeScalar(B(a[0])).ToString());
    [Fact] public void SerializeScalar() => Base.Check(M, "serializeScalar", a => O.SerializeScalar(BigInteger.Parse((string)a[0]!, System.Globalization.CultureInfo.InvariantCulture)));
    [Fact] public void HashToGroup() => Base.Check(M, "hashToGroup", a => O.HashToGroup(B(a[0])!, Md(a[1])));
    [Fact] public void DeserializeElement() => Base.Check(M, "deserializeElement", a => O.ReserializeElement(B(a[0])!));

    [Fact] public void Blind() => Base.Check(M, "blind", a => Bl(O.Blind(B(a[0])!, Md(a[1]), B(Opt(a, 2)))));

    [Fact]
    public void BlindEvaluate() => Base.Check(M, "blindEvaluate", a =>
    {
        // the reference treats an explicit null public key as present (and refuses it); only an absent argument means "derive it"
        if (a.Count > 3 && a[3] == null) return Base.Refused;
        return Ev(O.BlindEvaluate(B(a[0])!, B(a[1])!, Md(a[2]), B(Opt(a, 3)), B(Opt(a, 4))));
    });

    [Fact]
    public void FinalizeFn() => Base.Check(M, "finalize", a =>
    {
        var o = Opt(a, 4) as D;
        return O.Finalize(B(a[0])!, B(a[1])!, B(a[2])!, Md(a[3]), B(o?.GetValueOrDefault("proof")), B(o?.GetValueOrDefault("publicKey")), B(o?.GetValueOrDefault("blindedElement")));
    });

    [Fact] public void Evaluate() => Base.Check(M, "evaluate", a => O.Evaluate(B(a[0])!, B(a[1])!, Md(a[2])));

    [Fact]
    public void BlindPoprf() => Base.Check(M, "blindPoprf", a =>
    {
        var r = O.BlindPoprf(B(a[0])!, B(a[1])!, B(a[2])!, B(Opt(a, 3)));
        return new D { ["blind"] = r.Blind, ["blindedElement"] = r.BlindedElement, ["tweakedKey"] = r.TweakedKey };
    });

    [Fact] public void BlindEvaluatePoprf() => Base.Check(M, "blindEvaluatePoprf", a => Ev(O.BlindEvaluatePoprf(B(a[0])!, B(a[1])!, B(a[2])!, B(Opt(a, 3)))));

    [Fact]
    public void FinalizePoprf() => Base.Check(M, "finalizePoprf", a =>
    {
        var o = (D)a[4]!;
        return O.FinalizePoprf(B(a[0])!, B(a[1])!, B(a[2])!, B(a[3])!, B(o.GetValueOrDefault("proof")), B(o.GetValueOrDefault("blindedElement")), B(o.GetValueOrDefault("tweakedKey")));
    });

    [Fact] public void EvaluatePoprf() => Base.Check(M, "evaluatePoprf", a => O.EvaluatePoprf(B(a[0])!, B(a[1])!, B(a[2])!));
    [Fact] public void ToHex() => Base.Check(M, "toHex", a => O.ToHex(B(a[0])!));
    [Fact] public void BytesEqual() => Base.Check(M, "bytesEqual", a => O.BytesEqual(B(a[0])!, B(a[1])!));

    [Fact]
    public void BuildRevocationSet() => Base.Check(M, "buildRevocationSet", a =>
    {
        var s = OP.BuildRevocationSet(B(a[0])!, ((L)a[1]!).Select(x => (string)x!), Md(a[2]));
        var d = new D { ["outputs"] = s.Outputs.OrderBy(x => x, StringComparer.Ordinal).Cast<object?>().ToList(), ["mode"] = s.Mode };
        if (s.PublicKey != null) d["publicKey"] = s.PublicKey;
        return d;
    }, eq: (c, have) =>
    {
        // the reference wrapper of the duplicate-id case omits the public key
        var h = (D)have!;
        if (((string)c["name"]!).EndsWith("-dups", StringComparison.Ordinal)) h = h.Where(e => e.Key != "publicKey").ToDictionary(e => e.Key, e => e.Value);
        return Base.Eq(c["out"], h);
    });

    static readonly byte[] OtherKey = O.DeriveKeyPair(Enumerable.Repeat((byte)0x55, 32).ToArray(), new byte[] { 1 }, "poprf").SecretKey;

    [Fact]
    public void IsRevokedPrivate() => Base.Check(M, "isRevokedPrivate", a =>
    {
        var op = (D)a[1]!;
        var sk = B(op["sk"])!;
        var mode = Md(op["mode"]);
        var set = OP.BuildRevocationSet(sk, ((L)op["revoked"]!).Select(x => (string)x!), mode);
        var lie = op.GetValueOrDefault("lie") as string;
        var real = OP.MakeRevocationEvaluator(lie == "wrong-key" ? OtherKey : sk, mode);
        Func<byte[], EvaluateResult> eval = lie == "no-proof" ? (b => new EvaluateResult(real(b).EvaluatedElement)) : real;
        return OP.IsRevokedPrivate(a[0] as string, eval, set);
    });

    [Fact] public void RateToken() => Base.Check(M, "rateToken", a => OP.RateToken(B(a[0])!, a[1] as string, a[2] as string));
    [Fact] public void RateTokenHex() => Base.Check(M, "rateTokenHex", a => OP.RateTokenHex(B(a[0])!, a[1] as string, a[2] as string));

    [Fact]
    public void PrivateRateToken() => Base.Check(M, "privateRateToken", a =>
    {
        var op = (D)a[2]!;
        var sk = B(op["sk"])!;
        var pk = op.TryGetValue("pk", out var p) && p != null ? B(p)! : O.PublicKeyFor(sk);
        return OP.PrivateRateToken(a[0] as string, a[1] as string, OP.MakeRateEvaluator(sk), pk);
    });

    [Fact]
    public void RateCounter() => Base.Check(M, "rateCounter", a =>
    {
        var c = new RateWindowCounter(IntentJs.NumOf(a[0]) ?? throw new ArgumentException("limit must be a number"));
        var res = new L();
        foreach (var st in (L)a[1]!)
        {
            var s = (L)st!;
            switch ((string)s[0]!)
            {
                case "hit": var h = c.Hit(B(s[1])!); res.Add(new D { ["count"] = h.Count, ["allowed"] = h.Allowed }); break;
                case "count": res.Add(c.Count(B(s[1])!)); break;
                default: c.Reset(); res.Add(null); break;
            }
        }
        return res;
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "deriveKeyPair", "publicKeyFor", "deserializeScalar", "serializeScalar", "hashToGroup", "deserializeElement", "blind", "blindEvaluate", "evaluate", "finalize",
        "blindPoprf", "blindEvaluatePoprf", "finalizePoprf", "evaluatePoprf", "toHex", "bytesEqual", "buildRevocationSet", "isRevokedPrivate", "rateToken",
        "rateTokenHex", "privateRateToken", "rateCounter",
    }); Assert.Equal(508, Base.Total(M)); }
}
