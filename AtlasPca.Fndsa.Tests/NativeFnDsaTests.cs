using System.Text.Json;
using AtlasPca.Fndsa;
using AtlasPca.Fndsa.Native;
using Xunit;
using Core = AtlasPca.Fndsa.Fndsa;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Fndsa.Tests;

/// <summary>Real-primitive FN-DSA tests over libfndsa. Skipped (with the reason printed) only when the library is absent and ATLAS_PCA_LIBFNDSA_REQUIRED is not 1.</summary>
[Collection("fndsa-global-backend")]
public class NativeFnDsaTests : IDisposable
{
    static readonly string[] Variants = ["fn-dsa-512", "fn-dsa-1024"];

    // false = library absent and not required (skip); required + absent fails
    static bool Ready()
    {
        if (NativeFnDsa.Available()) return true;
        if (Environment.GetEnvironmentVariable("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") Assert.Fail("libfndsa must load (ATLAS_PCA_LIBFNDSA)");
        Console.WriteLine("SKIP: libfndsa not found (set ATLAS_PCA_LIBFNDSA)");
        return false;
    }

    public void Dispose() => Core.ResetFalconBackend();

    static byte[] Hex(JsonElement e, string k) => Convert.FromHexString(e.GetProperty(k).GetString()!);

    static JsonElement Kat() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "ref-fndsa-kat.json"))).RootElement;

    // the KAT carries seed labels, not seed bytes: the 32-byte seed is SHAKE256(UTF-8 label) cut to 32 bytes
    static byte[] LabelSeed(JsonElement e, string k) =>
        Shake256(System.Text.Encoding.UTF8.GetBytes(e.GetProperty(k).GetString()!), 32);

    // BouncyCastle: the platform Shake256 throws where the OS crypto lacks SHAKE (macOS)
    static byte[] Shake256(byte[] data, int outLen)
    {
        var d = new Org.BouncyCastle.Crypto.Digests.ShakeDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[outLen];
        d.OutputFinal(o, 0, outLen);
        return o;
    }

    static byte[] Seed(byte b) => Enumerable.Repeat(b, 32).ToArray();

    static byte[] Flip(byte[] a, int i) { var c = (byte[])a.Clone(); c[i] ^= 1; return c; }

    [Fact]
    public void WasmSignedKatsReproduceByteForByte()
    {
        if (!Ready()) return;
        var arr = Kat().GetProperty("wasm_signed");
        Assert.True(arr.GetArrayLength() > 0);
        foreach (var c in arr.EnumerateArray())
        {
            var v = c.GetProperty("variant").GetString()!;
            var kp = NativeFnDsa.Keygen(v, LabelSeed(c, "keygen_seed_label"));
            Assert.Equal(Hex(c, "vk"), kp.Pk);
            var sig = NativeFnDsa.Sign(v, kp.Sk, Hex(c, "msg"), LabelSeed(c, "sign_seed_label"));
            Assert.Equal(Hex(c, "sig"), sig);
            Assert.True(NativeFnDsa.Verify(v, Hex(c, "vk"), Hex(c, "msg"), Hex(c, "sig")));
        }
    }

    [Fact]
    public void CSignedKatsVerify()
    {
        if (!Ready()) return;
        var arr = Kat().GetProperty("c_signed");
        Assert.True(arr.GetArrayLength() > 0);
        foreach (var c in arr.EnumerateArray())
            Assert.True(NativeFnDsa.Verify(c.GetProperty("variant").GetString()!, Hex(c, "vk"), Hex(c, "msg"), Hex(c, "sig")));
    }

    [Fact]
    public void TamperedAndMalformedInputsAreRefused()
    {
        if (!Ready()) return;
        var c = Kat().GetProperty("wasm_signed")[0];
        var v = c.GetProperty("variant").GetString()!;
        byte[] vk = Hex(c, "vk"), msg = Hex(c, "msg"), sig = Hex(c, "sig");
        Assert.False(NativeFnDsa.Verify(v, vk, msg, Flip(sig, 40)));
        Assert.False(NativeFnDsa.Verify(v, vk, msg.Length > 0 ? Flip(msg, 0) : [1], sig));
        Assert.False(NativeFnDsa.Verify(v, Flip(vk, 5), msg, sig));
        Assert.False(NativeFnDsa.Verify(v, vk[..^1], msg, sig));
        Assert.False(NativeFnDsa.Verify(v, vk, msg, sig[..^1]));
        Assert.False(NativeFnDsa.Verify(v, null, msg, sig));
        Assert.False(NativeFnDsa.Verify(v, vk, null, sig));
        Assert.False(NativeFnDsa.Verify(v, vk, msg, null));
        Assert.False(NativeFnDsa.Verify(v, [], msg, sig));
        Assert.False(NativeFnDsa.Verify(v, vk, new byte[8193], sig));
        Assert.Throws<ArgumentOutOfRangeException>(() => NativeFnDsa.Verify("fn-dsa-768", vk, msg, sig));
        Assert.Throws<ArgumentException>(() => NativeFnDsa.Sign(v, [], msg));
        Assert.Throws<ArgumentException>(() => NativeFnDsa.Sign(v, NativeFnDsa.Keygen(v, Seed(1)).Sk, new byte[8193]));
        Assert.Throws<ArgumentException>(() => NativeFnDsa.Keygen(v, new byte[31]));
        Assert.Throws<ArgumentOutOfRangeException>(() => NativeFnDsa.Keygen("fn-dsa-768", Seed(1)));
    }

    [Fact]
    public void ZeroLengthMessageSignsAndVerifies()
    {
        if (!Ready()) return;
        foreach (var v in Variants)
        {
            var kp = NativeFnDsa.Keygen(v, Seed(7));
            var sig = NativeFnDsa.Sign(v, kp.Sk, []);
            Assert.True(NativeFnDsa.Verify(v, kp.Pk, [], sig));
            Assert.False(NativeFnDsa.Verify(v, kp.Pk, [0], sig));
        }
    }

    [Fact]
    public void RandomSeedRoundTripAndMaxMessage()
    {
        if (!Ready()) return;
        foreach (var v in Variants)
        {
            var kp = NativeFnDsa.Keygen(v, Seed(3));
            var msg = new byte[8192];
            for (int i = 0; i < msg.Length; i++) msg[i] = (byte)i;
            var s1 = NativeFnDsa.Sign(v, kp.Sk, msg);
            var s2 = NativeFnDsa.Sign(v, kp.Sk, msg);
            Assert.NotEqual(s1, s2); // fresh CSPRNG seed each time
            Assert.True(NativeFnDsa.Verify(v, kp.Pk, msg, s1));
            Assert.True(NativeFnDsa.Verify(v, kp.Pk, msg, s2));
        }
    }

    [Fact]
    public void BackendRoutesThroughCoreSeam()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        var kp = NativeFnDsa.Keygen("fn-dsa-1024", Seed(9));
        var m = new byte[] { 1, 2, 3 };
        var sig = Core.FndsaSign("fn-dsa-1024", kp.Sk, m);
        Assert.True(Core.FndsaVerify("fn-dsa-1024", kp.Pk, m, sig));
        Assert.False(Core.FndsaVerify("fn-dsa-1024", kp.Pk, [1, 2, 4], sig));
        Assert.False(Core.FndsaVerify("fn-dsa-512", kp.Pk, m, sig)); // wrong suite lengths
        Assert.Throws<ArgumentException>(() => Core.FndsaSign("fn-dsa-512", [1, 2, 3], m));
    }

    [Fact]
    public void HybridAndPureFramingRoundTripWithRealBackend()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        var leaf = new D { ["action"] = "read", ["n"] = 1L };
        var ed = Enumerable.Repeat((byte)5, 32).ToArray();
        using var edKey = EdKey.FromSeed(ed);
        foreach (var v in Variants)
        {
            var kp = NativeFnDsa.Keygen(v, Seed(11));
            var pure = Core.SignPcaWithFndsa(v, leaf, kp, null);
            Assert.True(Core.VerifyPcaFndsa(v, leaf, null, pure["pq_pk"], pure["sig"], null));
            var hy = Core.SignPcaWithFndsa("hybrid-ed25519-" + v, leaf, kp, ed);
            var holder = edKey.Id;
            Assert.True(Core.VerifyPcaFndsa(hy["alg"], leaf, holder, hy["pq_pk"], hy["sig"], hy["pq_sig"]));
            var other = new D { ["action"] = "write", ["n"] = 1L };
            Assert.False(Core.VerifyPcaFndsa(hy["alg"], other, holder, hy["pq_pk"], hy["sig"], hy["pq_sig"]));
        }
    }

    [Fact]
    public void MissingLibraryFailsLoudlyNotFalse()
    {
        if (NativeFnDsa.Available()) return; // only meaningful when absent
        Assert.Throws<FnDsaNativeException>(() => NativeFnDsa.Register());
        Assert.Throws<FnDsaNativeException>(() => NativeFnDsa.Verify("fn-dsa-512", new byte[897], [], new byte[666]));
    }
}
