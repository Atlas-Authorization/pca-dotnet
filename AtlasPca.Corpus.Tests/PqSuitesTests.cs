using System.Text;
using Xunit;

namespace AtlasPca.Corpus.Tests;

public class PqSuitesTests
{
    static byte[] Seed(int n, byte b) => Enumerable.Repeat(b, n).ToArray();
    static readonly byte[] Msg = Encoding.UTF8.GetBytes("pca suites");

    [Fact]
    public void ConstantsMatchTheVerifierTables()
    {
        Assert.Equal(Pq.Lens(Pq.Prim.MlDsa65), (PqSuites.MlDsa65PublicKeyBytes, PqSuites.MlDsa65SignatureBytes));
        Assert.Equal(Pq.Lens(Pq.Prim.MlDsa87), (PqSuites.MlDsa87PublicKeyBytes, PqSuites.MlDsa87SignatureBytes));
        Assert.Equal(Pq.Lens(Pq.Prim.Slh128f), (PqSuites.SlhDsaSha2128fPublicKeyBytes, PqSuites.SlhDsaSha2128fSignatureBytes));
        Assert.Equal(Pq.Lens(Pq.Prim.Slh256s), (PqSuites.SlhDsaSha2256sPublicKeyBytes, PqSuites.SlhDsaSha2256sSignatureBytes));
        Assert.Equal(PqKey.SeedBytes(Pq.Prim.Slh128f), PqSuites.SlhDsaSha2128fSeedBytes);
        Assert.Equal(PqKey.SeedBytes(Pq.Prim.Slh256s), PqSuites.SlhDsaSha2256sSeedBytes);
        Assert.Equal(3373, PqSuites.CompositeSignatureBytes);
        Assert.Equal(LessNative.PublicKeyBytes, PqSuites.LessCat1PublicKeyBytes);
    }

    [Fact]
    public void MlDsaRoundTripAndTamper()
    {
        var kp = PqSuites.MlDsa65Keygen(Seed(32, 7));
        Assert.Equal(kp.PublicKey, PqSuites.MlDsa65Keygen(Seed(32, 7)).PublicKey); // deterministic from the seed
        var sig = PqSuites.MlDsa65Sign(kp.SecretKey, Msg);
        Assert.True(PqSuites.MlDsa65Verify(kp.PublicKey, Msg, sig));
        Assert.True(PqSuites.MlDsa65VerifyB64u(PqSuites.EncodeMlDsaPublicKey(kp.PublicKey), Msg, Pca.B64u(sig)));
        Assert.False(PqSuites.MlDsa65Verify(kp.PublicKey, Encoding.UTF8.GetBytes("other"), sig));
        Assert.False(PqSuites.MlDsa65VerifyB64u("not-base64!", Msg, Pca.B64u(sig)));
        Assert.False(PqSuites.MlDsa65VerifyB64u(null, Msg, null));
        Assert.True(PqSuites.IsWellFormedPqPublicKey(PqSuites.EncodeMlDsaPublicKey(kp.PublicKey)));
        Assert.False(PqSuites.IsWellFormedPqPublicKey("AAAA"));
    }

    [Fact]
    public void SuiteSeamRoundTrips()
    {
        var ed = Seed(32, 3);
        var edId = Pca.B64u(EdKey.FromSeed(ed).Pub);
        var keys = new SuiteSecretKeys { EdSecret = ed, MlDsa = PqSuites.MlDsa65Keygen(Seed(32, 9)) };
        var plain = PqSuites.SignSuiteArtifact(null, keys, Msg);
        Assert.Null(plain.Alg); Assert.Null(plain.PqPk); Assert.Null(plain.PqSig);
        Assert.True(PqSuites.VerifyWithSuite(null, edId, null, Msg, plain.Sig, null));
        foreach (var alg in new[] { "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65" })
        {
            var f = PqSuites.SignSuiteArtifact(alg, keys, Msg);
            Assert.Equal(alg, f.Alg);
            Assert.Equal(PqSuites.EncodeMlDsaPublicKey(keys.MlDsa!.PublicKey), f.PqPk);
            Assert.True(PqSuites.VerifyLeafSuite(alg, edId, f.PqPk, Msg, f.Sig, f.PqSig));
            Assert.False(PqSuites.VerifyLeafSuite(alg, edId, f.PqPk, Encoding.UTF8.GetBytes("x"), f.Sig, f.PqSig));
            Assert.False(PqSuites.VerifyLeafSuite(alg, edId, f.PqPk, Msg, f.Sig, null));
        }
        Assert.Throws<ArgumentException>(() => PqSuites.SignWithSuite("ml-dsa-87", keys, Msg));   // key material missing
        Assert.Throws<ArgumentOutOfRangeException>(() => PqSuites.SignWithSuite("rot13", keys, Msg));
        Assert.False(PqSuites.IsKnownSigAlg("rot13"));
        Assert.True(PqSuites.IsKnownSigAlg("less-cat1"));
    }

    [Fact]
    public void CompositeBindsBothHalvesAndTheContext()
    {
        var ed = Seed(32, 5);
        var edPub = EdKey.FromSeed(ed).Pub;
        var ml = PqSuites.MlDsa65Keygen(Seed(32, 6));
        var sig = PqSuites.CompositeSign(ed, ml, Msg, Encoding.UTF8.GetBytes("ctx"));
        Assert.Equal(PqSuites.CompositeSignatureBytes, sig.Length);
        Assert.True(PqSuites.CompositeVerify(edPub, ml.PublicKey, Msg, sig, Encoding.UTF8.GetBytes("ctx")));
        Assert.False(PqSuites.CompositeVerify(edPub, ml.PublicKey, Msg, sig));                 // ctx mismatch
        Assert.False(PqSuites.CompositeVerify(edPub, ml.PublicKey, Msg, sig[..^1], Encoding.UTF8.GetBytes("ctx")));
        var bad = (byte[])sig.Clone(); bad[^1] ^= 1;
        Assert.False(PqSuites.CompositeVerify(edPub, ml.PublicKey, Msg, bad, Encoding.UTF8.GetBytes("ctx")));
        Assert.Throws<ArgumentOutOfRangeException>(() => PqSuites.CompositeRepresentative(Msg, new byte[256]));
        Assert.False(PqSuites.CompositeVerify(edPub, ml.PublicKey, Msg, sig, new byte[256]));
    }
}
