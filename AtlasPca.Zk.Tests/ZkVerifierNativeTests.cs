using AtlasPca.Corpus.Tests;
using AtlasPca.Zk;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Zk.Tests;

/// <summary>The core's zk compliance checks with this library registered as their Groth16 engine, against the shared reference corpus: every case of the
/// functions that end in a pairing check (proof verification on both curves, the four SNARK backends, the verifier hook), the replay the core tests run
/// under recorded verdicts. Here the library decides, so each verdict is the real pairing's. Skipped (with the reason printed) only when the library is
/// absent and ATLAS_PCA_LIBPCAZK_REQUIRED is not 1.</summary>
public class ZkVerifierNativeTests
{
    static bool Ready()
    {
        if (ZkNative.Available()) return true;
        if (Environment.GetEnvironmentVariable("ATLAS_PCA_LIBPCAZK_REQUIRED") == "1") Assert.Fail("libpcazk must load (ATLAS_PCA_LIBPCAZK)");
        Console.WriteLine("SKIP: libpcazk not found (set ATLAS_PCA_LIBPCAZK)");
        return false;
    }

    [Fact]
    public void TheEngineFunctionsOfTheReferenceCorpusAgreeOnTheRealLibrary()
    {
        if (!Ready()) return;
        ZkReplay.Replay(ZkNative.Engine);
    }

    [Fact]
    public void RegisterMakesTheLibraryTheEngineOfTheVerifierAndStrictRefusesWhatOnlyTheReferenceAccepts()
    {
        if (!Ready()) return;
        var cases = Base.Of(ZkReplay.M, "verifyPolicyVmProof").ToDictionary(c => (string)c["name"]!, c => Base.Args(c));
        ZkNative.Register();
        try
        {
            Assert.True(ZkCompliance.Groth16EngineRegistered);
            foreach (var curve in new[] { "bn", "bls" })
            {
                // the embedded key of the proof's curve
                var valid = cases[$"verifyPolicyVmProof/{curve}/valid"];
                Assert.True(ZkCompliance.VerifyPolicyVmProof(valid[0]));
                Assert.True(ZkCompliance.VerifyPolicyVmProof(valid[0], new D { ["strict"] = true }));
                // a key whose protocol, nPublic or extra IC entries the reference never reads: accepted as the reference accepts it, refused on request
                foreach (var quirk in new[] { "quirk-vkey-ic-long", "quirk-vkey-nPublic-14", "quirk-vkey-protocol-plonk" })
                {
                    var a = cases[$"verifyPolicyVmProof/{curve}/{quirk}"];
                    var opts = ZkReplay.Opts(a[1])!;
                    Assert.True(ZkCompliance.VerifyPolicyVmProof(a[0], opts), quirk);
                    Assert.False(ZkCompliance.VerifyPolicyVmProof(a[0], new D(opts) { ["strict"] = true }), quirk);
                }
            }
        }
        finally { ZkCompliance.ResetGroth16Engine(); }
    }
}
