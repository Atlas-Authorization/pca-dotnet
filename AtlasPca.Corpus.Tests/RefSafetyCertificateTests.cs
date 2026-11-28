using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the safety certificate (test-data/ref-safety-certificate.json.gz). A non-finite number is {"$num": text}; a secret is {"$bytes": seed}; the suite of an
/// <c>issueSafetyCertificate</c> case is {alg, pqSeed?} with the ML-DSA-65 key pair derived from the seed. The reference's legacy unbound-PQ opt-out (<c>allowUnboundPq</c>)
/// does not exist here: the cases that the reference accepts only through it are asserted as refused, by count.</summary>
public class RefSafetyCertificateTests
{
    const string M = "ref-safety-certificate";

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

    static object? Opts(L a) => a.Count > 1 ? Nums(a[1]) : null;

    static bool Unbound(D c) => Base.Args(c) is { Count: > 1 } a && a[1] is D o && o.GetValueOrDefault("allowUnboundPq") is true;

    [Fact] public void Constants() => Base.Check(M, "constants", _ => SafetyCertificate.Constants());
    [Fact] public void SafetyCertificateBound() => Base.Check(M, "safetyCertificateBound", a => Out(SafetyCertificate.Bound(Nums(a[0]))), min: 14);
    [Fact] public void SafetyCertificateStatement() => Base.Check(M, "safetyCertificateStatement", a => SafetyCertificate.Statement(Nums(a[0])), min: 12);
    [Fact] public void ValidateSafetyChecks() => Base.Check(M, "validateSafetyChecks", a => SafetyCertificate.ValidateChecks(Nums(a[0])), min: 63);
    [Fact] public void SafetyCertificateMessage() => Base.Check(M, "safetyCertificateMessage", a => SafetyCertificate.Message(Nums(a[0])), min: 5);

    [Fact]
    public void IssueSafetyCertificate() => Base.Check(M, "issueSafetyCertificate", a =>
    {
        var args = (D)Nums(a[0])!;
        string? alg = null;
        SuiteSecretKeys? keys = null;
        if (args.GetValueOrDefault("suite") is D suite)
        {
            alg = suite.GetValueOrDefault("alg") as string;
            if (suite.GetValueOrDefault("pqSeed") is { } seed) keys = new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) };
        }
        return SafetyCertificate.Issue(args.GetValueOrDefault("policy"), Base.Bytes(args["guardianSecret"]), args.GetValueOrDefault("grantRef") as string, args.GetValueOrDefault("instance") as string,
            args.GetValueOrDefault("checks"), args.GetValueOrDefault("issuedAt"), alg, keys);
    }, min: 35);

    [Fact]
    public void VerifySafetyCertificate()
    {
        Base.Check(M, "verifySafetyCertificate", a => Out(SafetyCertificate.Verify(Nums(a[0]), Opts(a))), skip: c => Unbound(c) ? "the unbound-PQ opt-out is not ported" : null, min: 93);
        // the two cases the reference accepts only through allowUnboundPq: refused here, for the unpinned signature
        var unbound = Base.Of(M, "verifySafetyCertificate").Where(Unbound).ToList();
        Assert.Equal(2, unbound.Count);
        foreach (var c in unbound)
        {
            Assert.True(((D)c["out"]!)["ok"] is true, "the reference accepts it through the opt-out");
            var have = SafetyCertificate.Verify(Nums(Base.Args(c)[0]), Opts(Base.Args(c)));
            Assert.Equal(false, have["ok"]);
            Assert.Equal("guardian signature does not verify", have["reason"]);
        }
    }

    [Fact] public void EncodeSafetyCertificate() => Base.Check(M, "encodeSafetyCertificate", a => SafetyCertificate.Encode(Nums(a[0])), min: 4);
    [Fact] public void DecodeSafetyCertificate() => Base.Check(M, "decodeSafetyCertificate", a => SafetyCertificate.Decode(a[0]), min: 20);
    [Fact] public void SafetyCertificateForCompliance() => Base.Check(M, "safetyCertificateForCompliance", a => SafetyCertificate.ForCompliance(Nums(a[0]), Opts(a)), min: 13);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "safetyCertificateBound", "safetyCertificateStatement", "validateSafetyChecks", "safetyCertificateMessage", "issueSafetyCertificate", "verifySafetyCertificate",
            "encodeSafetyCertificate", "decodeSafetyCertificate", "safetyCertificateForCompliance",
        });
        Assert.Equal(262, Base.Total(M));
    }
}
