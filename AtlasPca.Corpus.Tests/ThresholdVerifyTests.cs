using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class ThresholdVerifyTests
{
    static SuiteKey K(byte b) => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray()));
    static readonly SuiteKey A = K(1), G = K(2), P = K(3);
    static readonly byte[] Msg = System.Text.Encoding.UTF8.GetBytes("threshold message");
    static JL Set() => new() {
        new JD { ["role"] = "agent", ["publicKey"] = A.Id }, new JD { ["role"] = "guardian", ["publicKey"] = G.Id }, new JD { ["role"] = "principal", ["publicKey"] = P.Id } };
    static JD Share(string role, SuiteKey k, int t) => Signers.SignThresholdShare(role, k, Msg, Set(), t);
    static JD Sig(params JD[] shares) => Pca.AssembleThreshold(shares);
    static Num T(int t) => new(t.ToString());

    [Fact]
    public void CountsDistinctValidKeys()
    {
        var v = Pca.VerifyThreshold(Sig(Share("guardian", G, 2), Share("principal", P, 2)), Msg, Set(), T(2));
        Assert.True(v.Ok); Assert.Equal(2, v.Count); Assert.Equal(new[] { "guardian", "principal" }, v.Roles);
        var one = Pca.VerifyThreshold(Sig(Share("guardian", G, 2)), Msg, Set(), T(2));
        Assert.False(one.Ok); Assert.Equal("only 1 distinct valid key(s), need 2", one.Reason);
        // the same key twice counts once
        Assert.False(Pca.VerifyThreshold(Sig(Share("guardian", G, 2), Share("guardian", G, 2)), Msg, Set(), T(2)).Ok);
        // a share bound to another t does not verify
        var wrongT = Pca.VerifyThreshold(Sig(Share("guardian", G, 3)), Msg, Set(), T(1));
        Assert.Equal("invalid signature for role guardian", wrongT.Reason);
        // a share for a role whose key is not the registered one
        var other = new JD(Share("guardian", K(9), 1)) { ["role"] = "guardian" };
        Assert.Equal("share for role guardian uses a key not registered for that role", Pca.VerifyThreshold(Sig(other), Msg, Set(), T(1)).Reason);
        Assert.Equal("malformed share", Pca.VerifyThreshold(new JD { ["shares"] = new JL { "x" } }, Msg, Set(), T(1)).Reason);
        Assert.Contains("role judge is not in the signer set", Pca.VerifyThreshold(Sig(new JD { ["role"] = "judge", ["publicKey"] = G.Id, ["sig"] = "x" }), Msg, Set(), T(1)).Reason);
    }

    [Fact]
    public void SignerSetIsValidatedFirstAndTMustBeOneToThree()
    {
        Assert.StartsWith("invalid threshold t=4", Pca.VerifyThreshold(Sig(), Msg, Set(), T(4)).Reason);
        Assert.Equal("malformed signer set", Pca.VerifyThreshold(Sig(), Msg, new JL { new JD { ["role"] = "agent", ["publicKey"] = "x" } }, T(1)).Reason);
        Assert.Equal("signer set registers one key under two roles", Pca.VerifyThreshold(Sig(), Msg,
            new JL { new JD { ["role"] = "agent", ["publicKey"] = A.Id }, new JD { ["role"] = "guardian", ["publicKey"] = A.Id } }, T(1)).Reason);
        Assert.Equal("signer set registers more than one key for role agent", Pca.VerifyThreshold(Sig(), Msg,
            new JL { new JD { ["role"] = "agent", ["publicKey"] = A.Id }, new JD { ["role"] = "agent", ["publicKey"] = G.Id } }, T(1)).Reason);
        Assert.Equal("malformed signer set (pq_pk)", Pca.VerifyThreshold(Sig(), Msg,
            new JL { new JD { ["role"] = "agent", ["publicKey"] = A.Id, ["pq_pk"] = "AAAA" } }, T(1)).Reason);
    }

    [Fact]
    public void LeafBaselineIsTheAgentsEffectiveT1()
    {
        var leafSig = Pca.B64u(A.Ed!.Sign(Msg));
        var baseline = new AgentLeafBaseline(A.Id, leafSig);
        var v = Pca.VerifyThreshold(Sig(), Msg, Set(), T(1), baseline);
        Assert.True(v.Ok); Assert.Equal(new[] { "agent" }, v.Roles);
        Assert.False(Pca.VerifyThreshold(Sig(), Msg, Set(), T(2), baseline).Ok);
        Assert.True(Pca.VerifyThreshold(Sig(Share("guardian", G, 2)), Msg, Set(), T(2), baseline).Ok);
        Assert.False(Pca.VerifyThreshold(Sig(), Msg, Set(), T(1), new AgentLeafBaseline(G.Id, leafSig)).Ok);   // the holder must be the registered agent key
        Assert.False(Pca.VerifyThreshold(Sig(), Msg, Set(), T(1), new AgentLeafBaseline(A.Id, Pca.B64u(new byte[64]))).Ok);
        // a bare agent share (over the message itself, not the bound share message) does not count
        var bare = new JD { ["role"] = "agent", ["publicKey"] = A.Id, ["sig"] = leafSig };
        Assert.False(Pca.VerifyThreshold(Sig(bare), Msg, Set(), T(1)).Ok);
    }

    [Fact]
    public void FactoryNeedsAServerSideT()
    {
        Assert.Throws<ArgumentException>(() => ThresholdVerifiers.Create(new ThresholdVerifierOptions { SignerSet = Set() }));
        var v = ThresholdVerifiers.Create(new ThresholdVerifierOptions { SignerSet = Set(), T = 2, Scheme = "frost" });
        Assert.True(v.Label.AwaitingAudit); Assert.Equal("frost", v.Label.Level);
        Assert.False(ThresholdVerifiers.Create(new ThresholdVerifierOptions { SignerSet = Set(), T = 1 }).Label.AwaitingAudit);
    }
}
