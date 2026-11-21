using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// O2: key material is overwritten on Dispose (CryptographicOperations.ZeroMemory) and a disposed key cannot sign.
public class K05O2Tests
{
    [Fact]
    public void ADisposedEdKeyHoldsNoSeedAndCannotSign()
    {
        var seed = Enumerable.Repeat((byte)7, 32).ToArray();
        var k = EdKey.FromSeed(seed);
        Assert.Equal(64, k.Sign(new byte[] { 1 }).Length);
        k.Dispose();
        Assert.All(k.Seed, b => Assert.Equal(0, b));
        Assert.All(seed, b => Assert.Equal(7, b)); // the caller's buffer is its own
        Assert.Throws<ObjectDisposedException>(() => k.Sign(new byte[] { 1 }));
    }

    [Fact]
    public void ADisposedPqKeyAndSuiteKeyAreZeroed()
    {
        var pq = PqKey.Generate(Pq.Prim.MlDsa65);
        var ed = EdKey.Generate();
        var suite = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", ed, pq);
        Assert.NotEmpty(suite.Sign(new byte[] { 1 }).Sig);
        suite.Dispose();
        Assert.All(pq.Sk, b => Assert.Equal(0, b));
        Assert.All(ed.Seed, b => Assert.Equal(0, b));
        Assert.Throws<ObjectDisposedException>(() => suite.Sign(new byte[] { 1 }));
    }
}
