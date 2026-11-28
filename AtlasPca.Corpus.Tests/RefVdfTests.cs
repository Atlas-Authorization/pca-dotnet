using System.Numerics;
using AtlasPca;
using Xunit;
using V = AtlasPca.Vdf.Vdf;
using TL = AtlasPca.Vdf.Timelock;
using AtlasPca.Vdf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the Wesolowski VDF and the PCA timelock (test-data/ref-vdf.json.gz, TS reference packages/pca-vdf).
/// Big integers cross as decimal strings, step counts as JSON numbers.</summary>
public class RefVdfTests
{
    const string M = "ref-vdf";

    static BigInteger Bi(object? a) => a is string s ? BigInteger.Parse(s, System.Globalization.CultureInfo.InvariantCulture) : throw new InvalidDataException("bigint arg");
    static double Dbl(object? a) => IntentJs.NumOf(a) ?? throw new InvalidDataException("number arg");
    static string S(BigInteger b) => b.ToString(System.Globalization.CultureInfo.InvariantCulture);
    static D Pf(VdfProof p) => new() { ["y"] = S(p.Y), ["pi"] = S(p.Pi) };
    static D Vd(VdfVerdict v) => v.Ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = v.Reason };

    [Fact] public void IsProbablePrime() => Base.Check(M, "isProbablePrime", a => V.IsProbablePrime(Bi(a[0])));
    [Fact] public void IsMillerRabinProbablePrime() => Base.Check(M, "isMillerRabinProbablePrime", a => V.IsMillerRabinProbablePrime(Bi(a[0])));
    [Fact] public void IsStrongLucasProbablePrime() => Base.Check(M, "isStrongLucasProbablePrime", a => V.IsStrongLucasProbablePrime(Bi(a[0])));
    [Fact] public void Modpow() => Base.Check(M, "modpow", a => S(V.Modpow(Bi(a[0]), Bi(a[1]), Bi(a[2]))));
    [Fact] public void Gcd() => Base.Check(M, "gcd", a => S(V.Gcd(Bi(a[0]), Bi(a[1]))));
    [Fact] public void CanonicalVdfOutput() => Base.Check(M, "canonicalVdfOutput", a => S(V.CanonicalVdfOutput(Bi(a[0]), Bi(a[1]))));
    [Fact] public void BigIntToBytes() => Base.Check(M, "bigIntToBytes", a => V.BigIntToBytes(Bi(a[0])));
    [Fact] public void BytesRoundTrip() => Base.Check(M, "bytesRoundTrip", a => V.BigIntToBytes(V.BytesToBigInt(Pca.B64uDecode(a[0]) ?? throw new InvalidDataException("b64u"))));

    static object? HashToPrimeOf(L a) =>
        S(a.Count > 4 ? V.HashToPrime(Bi(a[0]), Bi(a[1]), Dbl(a[2]), Bi(a[3]), Dbl(a[4])) : V.HashToPrime(Bi(a[0]), Bi(a[1]), Dbl(a[2]), Bi(a[3])));
    static bool Bits8192(D c) => Base.Args(c) is var a && a.Count > 4 && IntentJs.NumOf(a[4]) == 8192;

    [Fact]
    public void HashToPrime() => Base.Check(M, "hashToPrime", HashToPrimeOf, skip: c => Bits8192(c) ? "the 8192-bit search: HashToPrime8192Bits" : null);

    /// <summary>The 8192-bit case alone: its prime search is hundreds of 8192-bit Miller-Rabin rounds (~7 minutes, half of the whole
    /// suite), so it is Category=Huge, outside the mutation oracle (every survivor is re-run against the full suite). The bits limit it
    /// pins is kept killed there by <see cref="TheBitsLimitIncludes8192"/>.</summary>
    [Fact, Trait("Category", "Huge")]
    public void HashToPrime8192Bits() => Base.Check(M, "hashToPrime", HashToPrimeOf, skip: c => Bits8192(c) ? null : "below 8192 bits: HashToPrime");

    /// <summary>8192 bits passes the bits check (the steps check right after it refuses T = -1, before any search); 8193 does not.</summary>
    [Fact]
    public void TheBitsLimitIncludes8192()
    {
        Assert.Equal("t", Assert.Throws<ArgumentOutOfRangeException>(() => V.HashToPrime(1, 1, -1, 1000036000099, 8192)).ParamName);
        Assert.Equal("bits", Assert.Throws<ArgumentOutOfRangeException>(() => V.HashToPrime(1, 1, -1, 1000036000099, 8193)).ParamName);
        Assert.Equal("t", Assert.Throws<ArgumentOutOfRangeException>(() => V.HashToPrime(1, 1, -1, 1000036000099, 8)).ParamName);
    }

    [Fact] public void SequentialSquare() => Base.Check(M, "sequentialSquare", a => S(V.SequentialSquare(Bi(a[0]), Dbl(a[1]), Bi(a[2]))));
    [Fact] public void VdfEval() => Base.Check(M, "vdfEval", a => Pf(V.VdfEval(Bi(a[0]), Dbl(a[1]), Bi(a[2]))));
    [Fact] public void VdfEvalCanonical() => Base.Check(M, "vdfEvalCanonical", a => Pf(V.VdfEvalCanonical(Bi(a[0]), Dbl(a[1]), Bi(a[2]))));
    [Fact] public void VerifyDetailed() => Base.Check(M, "vdfVerifyDetailed", a => Vd(V.VdfVerifyDetailed(Bi(a[0]), Bi(a[1]), Bi(a[2]), Dbl(a[3]), Bi(a[4]))));
    [Fact] public void VerifyCanonicalDetailed() => Base.Check(M, "vdfVerifyCanonicalDetailed", a => Vd(V.VdfVerifyCanonicalDetailed(Bi(a[0]), Bi(a[1]), Bi(a[2]), Dbl(a[3]), Bi(a[4]))));

    [Fact]
    public void CheckProductionModulus() => Base.Check(M, "checkProductionModulus", a =>
    {
        var (ok, reason) = V.CheckProductionModulus(Bi(a[0]));
        return ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = reason };
    });

    static TimelockOptions Opts(object? o)
    {
        var d = (D)o!;
        return new TimelockOptions
        {
            Steps = Dbl(d["steps"]), N = Bi(d["N"]), Beacon = d.GetValueOrDefault("beacon"),
            AllowInsecureDevModulus = d.GetValueOrDefault("allowInsecureDevModulus") as bool?,
        };
    }

    [Fact] public void DeriveTimelockInput() => Base.Check(M, "deriveTimelockInput", a => S(TL.DeriveTimelockInput(a[0], Bi(a[1]), a[2])));

    [Fact]
    public void RequireTimelock() => Base.Check(M, "requireTimelock", a =>
    {
        var q = TL.RequireTimelock(a[0], Opts(a[1]));
        return new D { ["kind"] = q.Kind, ["x"] = S(q.X), ["steps"] = q.Steps, ["N"] = S(q.N), ["actionDigest"] = q.ActionDigest };
    });

    [Fact]
    public void ProveTimelockElapsed() => Base.Check(M, "proveTimelockElapsed", a =>
    {
        var o = (D)a[3]!;
        var p = TL.ProveTimelockElapsed(a[0], Dbl(a[1]), Bi(a[2]), o.GetValueOrDefault("beacon"), o.GetValueOrDefault("allowInsecureDevModulus") as bool?);
        return new D { ["kind"] = p.Kind, ["y"] = S(p.Y), ["pi"] = S(p.Pi), ["steps"] = p.Steps };
    });

    [Fact]
    public void VerifyTimelock() => Base.Check(M, "verifyTimelock", a =>
    {
        object? proof = a[1];
        if (proof is D pd)
        {
            proof = pd.ToDictionary(e => e.Key, e => e.Key is "y" or "pi" && e.Value is string s ? (object?)Bi(s) : e.Value);
        }
        return TL.VerifyTimelock(a[0], proof, Opts(a[2]));
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "isProbablePrime", "isMillerRabinProbablePrime", "isStrongLucasProbablePrime", "modpow", "gcd", "canonicalVdfOutput", "bigIntToBytes", "bytesRoundTrip",
        "hashToPrime", "sequentialSquare", "vdfEval", "vdfEvalCanonical", "vdfVerifyDetailed", "vdfVerifyCanonicalDetailed", "checkProductionModulus",
        "deriveTimelockInput", "requireTimelock", "proveTimelockElapsed", "verifyTimelock",
    }); Assert.Equal(6673, Base.Total(M)); }
}
