using System.IO.Compression;
using System.Text;
using System.Text.Json;
using AtlasPca.Zk;
using Xunit;

namespace AtlasPca.Zk.Tests;

/// <summary>Groth16 over libpcazk against the shared reference corpus: every pairing case of verifyPolicyVmProof on BN254 and BLS12-381. The corpus holds the
/// reference's end-to-end verdicts, which include checks made before the pairing (envelope shape, circuit and system tags, context pins); the cases those
/// checks alone decide are not pairing questions and are left out by name. Skipped (with the reason printed) only when the library is absent and
/// ATLAS_PCA_LIBPCAZK_REQUIRED is not 1.</summary>
public class ZkNativeTests
{
    // refused by the caller's checks in front of the pairing, not by the pairing
    static readonly string[] GateOnly = ["expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "protocol-plonk", "proof-curve-wrong"];

    // false = library absent and not required (skip); required + absent fails
    static bool Ready()
    {
        if (ZkNative.Available()) return true;
        if (Environment.GetEnvironmentVariable("ATLAS_PCA_LIBPCAZK_REQUIRED") == "1") Assert.Fail("libpcazk must load (ATLAS_PCA_LIBPCAZK)");
        Console.WriteLine("SKIP: libpcazk not found (set ATLAS_PCA_LIBPCAZK)");
        return false;
    }

    static List<JsonElement> Cases()
    {
        using var gz = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "test-data", "ref-zk.json.gz")), CompressionMode.Decompress);
        using var text = new StreamReader(gz, new UTF8Encoding(false));
        var root = JsonDocument.Parse(text.ReadToEnd()).RootElement;
        Assert.Equal(root.GetProperty("count").GetInt32(), root.GetProperty("cases").GetArrayLength());
        return root.GetProperty("cases").EnumerateArray().ToList();
    }

    static byte[] Json(JsonElement parent, string member) =>
        Encoding.UTF8.GetBytes(parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(member, out var v) ? v.GetRawText() : "null");

    static JsonElement? Key(JsonElement opts) =>
        opts.ValueKind == JsonValueKind.Object && opts.TryGetProperty("verificationKey", out var k) && k.ValueKind != JsonValueKind.Null ? k : null;

    [Theory]
    [InlineData("verifyPolicyVmProof/bn/", ZkCurve.Bn254)]
    [InlineData("verifyPolicyVmProof/bls/", ZkCurve.Bls12381)]
    public void ThePairingCasesOfTheReferenceCorpusAgree(string prefix, ZkCurve curve)
    {
        if (!Ready()) return;
        var cases = Cases().Where(c => c.GetProperty("name").GetString()!.StartsWith(prefix, StringComparison.Ordinal)).ToList();
        static JsonElement Opts(JsonElement args) => args.GetArrayLength() > 1 ? args[1] : default;
        var defaultKey = Key(Opts(cases.Single(c => c.GetProperty("name").GetString() == prefix + "valid").GetProperty("args"))) ?? throw new InvalidDataException("the valid case has no key");
        var bad = new List<string>();
        int checkedCases = 0;
        foreach (var c in cases)
        {
            var name = c.GetProperty("name").GetString()!;
            var stem = name[prefix.Length..];
            var args = c.GetProperty("args");
            var key = Encoding.UTF8.GetBytes((Key(Opts(args)) ?? defaultKey).GetRawText());
            byte[] proof = Json(args[0], "proof"), signals = Json(args[0], "publicSignals");
            bool compat = ZkNative.Verify(curve, key, proof, signals).Valid;
            bool strict = ZkNative.Verify(curve, key, proof, signals, strict: true).Valid;
            var want = c.GetProperty("out");
            if (want.ValueKind == JsonValueKind.True)
            {
                // the reference accepts the quirk-* cases (a key whose protocol, nPublic or extra IC entries the reference never reads); strict mode refuses them
                if (!compat) bad.Add(name + ": the default mode must accept");
                if (strict == stem.StartsWith("quirk", StringComparison.Ordinal)) bad.Add(name + ": strict mode verdict " + strict);
            }
            else if (GateOnly.Any(g => stem.StartsWith(g, StringComparison.Ordinal))) continue;
            else if (compat || strict) bad.Add(name + ": must be refused in both modes");
            checkedCases++;
        }
        Assert.True(bad.Count == 0, string.Join("\n", bad));
        Assert.True(checkedCases > 40, $"only {checkedCases} cases replayed");
    }

    [Fact]
    public void AnInvalidProofIsAVerdictWithItsReason()
    {
        if (!Ready()) return;
        Assert.NotEqual("", ZkNative.Version());
        var valid = Cases().Single(c => c.GetProperty("name").GetString() == "verifyPolicyVmProof/bn/valid").GetProperty("args");
        string key = Key(valid[1])!.Value.GetRawText(), proof = valid[0].GetProperty("proof").GetRawText(), signals = valid[0].GetProperty("publicSignals").GetRawText();
        var ok = ZkNative.Verify(ZkCurve.Bn254, key, proof, signals);
        Assert.Equal(new ZkVerdict(true, 0, ok.ReasonText), ok);
        Assert.True(ZkNative.Verify(ZkCurve.Bn254, key, proof, signals, strict: true).Valid);
        var garbage = ZkNative.Verify(ZkCurve.Bn254, key, "{", signals);
        Assert.False(garbage.Valid);
        Assert.Equal(1, garbage.Reason);
        Assert.NotEqual("", garbage.ReasonText);
        // the BN254 key and proof are not a BLS12-381 statement
        var otherCurve = ZkNative.Verify(ZkCurve.Bls12381, key, proof, signals);
        Assert.False(otherCurve.Valid);
        Assert.NotEqual(0, otherCurve.Reason);
        // one signal fewer
        var fewer = ZkNative.Verify(ZkCurve.Bn254, key, proof, "[" + string.Join(",", valid[0].GetProperty("publicSignals").EnumerateArray().Skip(1).Select(s => s.GetRawText())) + "]");
        Assert.False(fewer.Valid);
        Assert.NotEqual(0, fewer.Reason);
    }

    [Fact]
    public void EmptyInputsAndABadSeedAreArgumentErrorsBeforeTheLibraryIsCalled()
    {
        var one = new byte[] { (byte)'1' };
        Assert.Throws<ArgumentException>(() => ZkNative.Verify(ZkCurve.Bn254, Array.Empty<byte>(), one, one));
        Assert.Throws<ArgumentException>(() => ZkNative.Verify(ZkCurve.Bn254, one, Array.Empty<byte>(), one));
        Assert.Throws<ArgumentException>(() => ZkNative.Verify(ZkCurve.Bn254, one, one, Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => ZkNative.Prove(ZkCurve.Bn254, Array.Empty<byte>(), one, one));
        Assert.Throws<ArgumentException>(() => ZkNative.Prove(ZkCurve.Bn254, one, Array.Empty<byte>(), one));
        Assert.Throws<ArgumentException>(() => ZkNative.Prove(ZkCurve.Bn254, one, one, Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => ZkNative.Prove(ZkCurve.Bn254, one, one, one, new byte[31]));
        Assert.Throws<ArgumentException>(() => ZkNative.Prove(ZkCurve.Bn254, one, one, one, new byte[33]));
    }

    [Fact]
    public void ProvingWithAProgramThatIsNotOneFailsAsAProveErrorNotAsAProof()
    {
        if (!Ready()) return;
        var e = Assert.Throws<ZkProveException>(() => ZkNative.Prove(ZkCurve.Bn254, Encoding.UTF8.GetBytes("not wasm"), Encoding.UTF8.GetBytes("not a zkey"), Encoding.UTF8.GetBytes("{}"), new byte[32]));
        Assert.InRange(e.Code, -6, -3);
        Assert.NotEqual("", e.Message);
    }

    [Fact]
    public void TheResolverTakesTheOverrideOnlyForThisLibrary()
    {
        Assert.Equal(IntPtr.Zero, NativeResolver.Resolve("other", typeof(ZkNative).Assembly, null));
        var saved = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBPCAZK");
        try
        {
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBPCAZK", Path.Combine(AppContext.BaseDirectory, "no-such-library"));
            Assert.Equal(IntPtr.Zero, NativeResolver.Resolve("pcazk", typeof(ZkNative).Assembly, null)); // an override that does not load falls to the default probing
        }
        finally { Environment.SetEnvironmentVariable("ATLAS_PCA_LIBPCAZK", saved); }
    }
}
