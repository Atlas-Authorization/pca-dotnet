using AtlasPca.FheParts;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the pure parts of pca-fhe (quantization, gate policy, signed-claim and verdict-attestation layer) against
/// the TypeScript reference (test-data/ref-fhe.json.gz). The BFV evaluation is replayed by AtlasPca.Fhe.Tests.</summary>
public class RefFheTests
{
    const string M = "ref-fhe";

    static D Map(object? o) => (D)o!;
    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    [Fact] public void TransformedInputs() => Base.Check(M, "transformedInputs", a => FheRisk.TransformedInputs(Map(a[0])));
    [Fact] public void QuantizeRiskInputs() => Base.Check(M, "quantizeRiskInputs", a => FheRisk.QuantizeRiskInputs(Map(a[0]), a.Count > 1 ? a[1] ?? new object() : null));
    [Fact] public void WeightVector() => Base.Check(M, "weightVector", a => FheRisk.WeightVector(Map(a[0])));
    [Fact] public void FheRiskPolicy() => Base.Check(M, "fheRiskPolicy", a => FheRisk.FheRiskPolicy(Map(a[0]), a[1], a.Count > 2 ? a[2] : null));
    [Fact] public void PlaintextVerdict() => Base.Check(M, "plaintextVerdict", a => FheRisk.PlaintextVerdict(Map(a[0]), Map(a[1]), a[2]));
    [Fact] public void FromActn() => Base.Check(M, "fromActn", a => FheRisk.TransformedInputs(FheRisk.RiskInputsFromPCActn(Map(a[0]))));
    [Fact] public void Binding() => Base.Check(M, "binding", a => FheRisk.BindingFromPCActn(Map(a[0])));

    [Fact] public void Sign() => Base.Check(M, "sign", a => FheOrigin.SignRiskClaim(Map(a[0]), Pca.B64uDecode(a[1])!, (string)a[2]!, Base.Bytes(a[3])));
    [Fact] public void ClaimDigest() => Base.Check(M, "claimDigest", a => FheOrigin.SignedClaimDigest(a[0]));

    [Fact]
    public void VerifyClaim() => Base.Check(M, "verifyClaim", a =>
    {
        var e = Map(a[1]);
        var used = Strs(e["used"]).ToHashSet();
        var max = (int)IntentJs.Lng(e["max"]);
        var exp = new FheOrigin.ClaimExpectations(Strs(e["trustedSigners"]), (string)e["context"]!, e["binding"], e["policy"],
            k => !used.Contains(k) && used.Count < max && used.Add(k));
        var r = FheOrigin.VerifySignedRiskClaim(a[0], exp);
        return r.Ok ? new D { ["ok"] = true, ["claim"] = r.Claim, ["digest"] = r.Digest } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void NonceGuard() => Base.Check(M, "nonceGuard", a =>
    {
        var g = FheOrigin.MemoryNonceGuard((int)IntentJs.Lng(a[0]));
        return Strs(a[1]).Select(k => (object?)g(k)).ToList();
    });

    [Fact] public void Attest() => Base.Check(M, "attest", a => FheOrigin.AttestVerdict(Pca.B64uDecode(a[0])!, Map(a[1]), Map(a[2]), a[3] is true));

    [Fact]
    public void VerifyAttest() => Base.Check(M, "verifyAttest", a =>
    {
        var e = Map(a[1]);
        var r = FheOrigin.VerifyVerdictAttestation(a[0], Strs(e["trustedHolders"]), (string)e["claimDigest"]!, e.GetValueOrDefault("gate") as D);
        return r.Ok ? new D { ["ok"] = true, ["admit"] = r.Admit } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "transformedInputs", "quantizeRiskInputs", "weightVector", "fheRiskPolicy", "plaintextVerdict", "fromActn", "binding", "sign", "claimDigest", "verifyClaim", "attest",
            "verifyAttest", "nonceGuard",
        });
        Assert.Equal(1569, Base.Total(M));
    }
}
