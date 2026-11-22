using System.Text.Json;
using AtlasPca.Fndsa.Native;
using Xunit;
using Core = AtlasPca.Fndsa.Fndsa;

namespace AtlasPca.Fndsa.Tests;

/// <summary>The core suite dispatch (Pq.Suites / Pca.VerifySuiteSig / share wire) for the pure fn-dsa-512 / fn-dsa-1024 suites: no backend registered is a
/// denial (unsupported_suite), the real libfndsa backend registered verifies the cross-implementation KATs. Same env gating as NativeFnDsaTests.</summary>
[Collection("fndsa-global-backend")]
public class CoreSuiteTests : IDisposable
{
    public CoreSuiteTests() => Core.ResetFalconBackend();
    public void Dispose() => Core.ResetFalconBackend();

    static byte[] Hex(JsonElement e, string k) => Convert.FromHexString(e.GetProperty(k).GetString()!);

    static List<JsonElement> Kats() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "ref-fndsa-kat.json"))).RootElement
            .GetProperty("c_signed").EnumerateArray().ToList();

    static bool Ready()
    {
        if (NativeFnDsa.Available()) return true;
        if (Environment.GetEnvironmentVariable("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") Assert.Fail("libfndsa must load (ATLAS_PCA_LIBFNDSA)");
        Console.WriteLine("SKIP: libfndsa not found (set ATLAS_PCA_LIBFNDSA)");
        return false;
    }

    static bool CoreVerify(JsonElement c, byte[]? vk = null, byte[]? msg = null, byte[]? sig = null) =>
        Pca.VerifySuiteSig(c.GetProperty("variant").GetString(), null, Pca.B64u(vk ?? Hex(c, "vk")), msg ?? Hex(c, "msg"), Pca.B64u(sig ?? Hex(c, "sig")), null);

    static byte[] Flip(byte[] a, int i) { var c = (byte[])a.Clone(); c[i] ^= 1; return c; }

    [Fact]
    public void NoBackendDeniesAndRefusesAsUnsupportedSuite()
    {
        foreach (var v in new[] { "fn-dsa-512", "fn-dsa-1024" })
        {
            Assert.DoesNotContain(v, Pq.Suites.Keys);
            Assert.Equal("unsupported_suite: " + v, Pq.Refusal(v));
            var size = v == "fn-dsa-512" ? 666 : 1280;
            Assert.Equal("unsupported_suite: " + v, Pca.ValidateShareSignatureWire(new() { ["alg"] = v, ["sig"] = Pca.B64u(new byte[size]) }));
        }
        var kats = Kats();
        Assert.NotEmpty(kats);
        foreach (var c in kats) Assert.False(CoreVerify(c)); // a well-formed KAT is never accepted without a backend
    }

    [Fact]
    public void RegisteredBackendVerifiesThroughTheCoreDispatch()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        Assert.Contains("fn-dsa-512", Pq.SupportedSuites());
        Assert.Contains("fn-dsa-1024", Pq.SupportedSuites());
        Assert.Null(Pca.ValidateShareSignatureWire(new() { ["alg"] = "fn-dsa-512", ["sig"] = Pca.B64u(new byte[666]) }));
        var kats = Kats();
        Assert.NotEmpty(kats);
        foreach (var c in kats)
        {
            byte[] vk = Hex(c, "vk"), msg = Hex(c, "msg"), sig = Hex(c, "sig");
            Assert.True(CoreVerify(c));
            Assert.False(CoreVerify(c, sig: Flip(sig, 40)));
            Assert.False(CoreVerify(c, msg: msg.Length > 0 ? Flip(msg, 0) : [1]));
            Assert.False(CoreVerify(c, vk: Flip(vk, 5)));
            Assert.False(CoreVerify(c, vk: vk[..^1])); // wrong-length pq_pk
            Assert.False(CoreVerify(c, sig: sig[..^1]));
        }
    }

    [Fact]
    public void SignThenCoreVerifyRoundTrip()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        foreach (var v in new[] { "fn-dsa-512", "fn-dsa-1024" })
        {
            var kp = NativeFnDsa.Keygen(v, Enumerable.Repeat((byte)4, 32).ToArray());
            var msg = new byte[] { 9, 8, 7 };
            var sig = Core.FndsaSign(v, kp.Sk, msg);
            Assert.True(Pca.VerifySuiteSig(v, null, Pca.B64u(kp.Pk), msg, Pca.B64u(sig), null));
            Assert.False(Pca.VerifySuiteSig(v, null, Pca.B64u(kp.Pk), [9, 8, 6], Pca.B64u(sig), null));
        }
    }
}
