using AtlasPca.FheParts;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Fhe.Tests;

/// <summary>The signed-claim evaluator refuses before any ciphertext is loaded: nothing here needs the SEAL native library.</summary>
public class FheSignedEvalTests
{
    static FheEvalKeys Keys => new("pk", "rk", "gk");

    static FheOrigin.ClaimExpectations Exp(Func<string, bool>? nonces = null) =>
        new(new[] { "someone" }, "ctx", new D(), new D(), nonces ?? (_ => true));

    [Fact]
    public void AnUnsignedOrMalformedClaimIsRefusedWithTheReason()
    {
        var r = FheSeal.EvalSignedRiskClaim(Keys, null, Exp());
        Assert.False(r.Ok);
        Assert.Null(r.Gate);
        Assert.Null(r.ClaimDigest);
        Assert.Equal("claim is not signed: malformed envelope", r.Reason);
        Assert.False(FheSeal.EvalSignedRiskClaim(Keys, new D { ["context"] = "ctx" }, Exp()).Ok);
    }

    [Fact]
    public void AClaimFromAnUntrustedSignerNeverReachesTheEvaluator()
    {
        var key = new byte[32];
        key[0] = 7;
        var claim = new D { ["encInputs"] = "AAAA", ["binding"] = new D(), ["policy"] = new D() };
        var signed = FheOrigin.SignRiskClaim(claim, key, "ctx");
        var r = FheSeal.EvalSignedRiskClaim(Keys, signed, Exp());
        Assert.False(r.Ok);
        Assert.Equal("signer is not a trusted encryptor", r.Reason);
    }
}
