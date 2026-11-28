using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AtlasPca.Fndsa.Native;
using Xunit;
using Core = AtlasPca.Fndsa.Fndsa;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Fndsa.Tests;

/// <summary>FN-DSA end to end through the public sign path (Issue.SignPCActn over a SuiteKey) and the public verifier (Pca.VerifyPcactnCore), replaying
/// test-data/ref-fndsa-pcactn.json and the fn-dsa cases of producer-pq-vectors.json byte for byte. Gated on ATLAS_PCA_LIBFNDSA
/// (ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping). The registered backend is always reset afterwards.</summary>
[Collection("fndsa-global-backend")]
public class FndsaEndToEndTests : IDisposable
{
    public FndsaEndToEndTests() => Core.ResetFalconBackend();
    public void Dispose() => Core.ResetFalconBackend();

    static bool Ready()
    {
        if (NativeFnDsa.Available()) return true;
        if (Environment.GetEnvironmentVariable("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") Assert.Fail("libfndsa must load (ATLAS_PCA_LIBFNDSA)");
        Console.WriteLine("SKIP: libfndsa not found (set ATLAS_PCA_LIBFNDSA)");
        return false;
    }

    static byte[] LabelSeed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    static List<JsonElement> Cases() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "ref-fndsa-pcactn.json"))).RootElement
            .GetProperty("cases").EnumerateArray().ToList();

    static JD Obj(JsonElement e, string k) => (JD)Pca.ParseJson(e.GetProperty(k).GetRawText())!;

    static Verdict Verify(JsonElement c, JD grant)
    {
        var now = long.Parse(c.GetProperty("now_epoch").GetRawText(), System.Globalization.CultureInfo.InvariantCulture);
        return Pca.VerifyPcactnCore(Obj(c, "pcactn"), grant, now, c.GetProperty("audience").GetString() ?? "", planRoots: PlanRootPolicy.Skip);
    }

    // every case of one variant carries the same grant
    static Dictionary<string, JD> Grants(List<JsonElement> cases) =>
        cases.Where(c => c.TryGetProperty("grant", out _)).GroupBy(c => c.GetProperty("alg").GetString()!).ToDictionary(g => g.Key, g => Obj(g.First(), "grant"));

    [Fact]
    public void SignsTheFixtureBodyByteForByte()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        var n = 0;
        foreach (var c in Cases().Where(c => c.TryGetProperty("body", out _)))
        {
            var alg = c.GetProperty("alg").GetString()!;
            var prim = alg == "fn-dsa-512" ? Pq.Prim.FnDsa512 : Pq.Prim.FnDsa1024;
            var labels = c.GetProperty("key_labels");
            using var pq = PqKey.FromSeed(prim, LabelSeed(labels.GetProperty("fndsa_keygen").GetString()!), LabelSeed(labels.GetProperty("fndsa_sign_seed").GetString()!));
            Assert.Equal(c.GetProperty("pq_pk").GetString(), pq.PkB64u);
            using var suite = SuiteKey.Create(alg, null, pq);
            var signed = Issue.SignPCActn(Obj(c, "body"), suite);
            Assert.Equal(Pca.Canonicalize(Obj(c, "pcactn")), Pca.Canonicalize(signed));
            n++;
        }
        Assert.Equal(2, n);
    }

    [Fact]
    public void VerifiesEveryFixtureCaseWithTheBackend()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        var cases = Cases();
        var grants = Grants(cases);
        Assert.Equal(12, cases.Count);
        foreach (var c in cases)
        {
            var v = Verify(c, grants[c.GetProperty("alg").GetString()!]);
            Assert.True(c.GetProperty("expect_allow").GetBoolean() == v.Allow, $"{c.GetProperty("name").GetString()}: {v.Reason}");
        }
    }

    [Fact]
    public void WithoutABackendEveryCaseDenies()
    {
        var cases = Cases();
        var grants = Grants(cases);
        Core.ResetFalconBackend();
        foreach (var c in cases)
        {
            var v = Verify(c, grants[c.GetProperty("alg").GetString()!]);
            var name = c.GetProperty("name").GetString()!;
            Assert.False(v.Allow, name);
            if (name.EndsWith("/valid", StringComparison.Ordinal)) Assert.Contains("unsupported_suite", v.Reason ?? "");
        }
    }

    [Fact]
    public void SigningRefusesAsUnsupportedSuiteWithoutABackend()
    {
        Core.ResetFalconBackend();
        var e = Assert.Throws<ArgumentException>(() => PqKey.FromSeed(Pq.Prim.FnDsa512, new byte[32]));
        Assert.Contains("unsupported_suite: fn-dsa-512", e.Message);
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("fn-dsa-1024", null, null));
    }

    [Fact]
    public void ProducerVectorsReplayByteForByte()
    {
        if (!Ready()) return;
        NativeFnDsa.Register();
        var doc = (JD)Pca.ParseJson(File.ReadAllText(FindVectors()))!;
        var keys = (JD)doc["ed_keys"]!;
        var pq = (JD)doc["pq_keys"]!;
        var n = 0;
        foreach (var o in (List<object?>)doc["cases"]!)
        {
            var c = (JD)o!;
            if (!((string)c["name"]!).Contains("fn-dsa", StringComparison.Ordinal)) continue;
            var got = ProducerVectors.Produce((string)c["op"]!, (JD)c["args"]!, keys, pq);
            Assert.True(Pca.Canonicalize(c["expect"]) == Pca.Canonicalize(got), (string)c["name"]!);
            n++;
        }
        Assert.True(n >= 16, $"fn-dsa producer cases: {n}");
    }

    static string FindVectors()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
            foreach (var rel in new[] { Path.Combine("packages", "pca", "conformance"), "conformance" })
            {
                var p = Path.Combine(d, rel, "producer-pq-vectors.json");
                if (File.Exists(p)) return p;
            }
        throw new FileNotFoundException("producer-pq-vectors.json is missing (a vector file is never skipped)", AppContext.BaseDirectory);
    }
}
