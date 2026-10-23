using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>LESS suites through libatlas_less (<see cref="LessNative"/>): with the library (sdks/pca-less-c/build.sh, or
/// ATLAS_PCA_LIBLESS) the known answers of packages/pca/conformance/less-vectors.json, incl. the seed-padding malleation every
/// verifier must refuse; without it both suites are out of the manifest and refused with <c>unsupported_suite</c>.</summary>
public class LessTests
{
    static string VectorsPath()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "packages", "pca", "conformance", "less-vectors.json");
            if (File.Exists(p)) return p;
        }
        throw new InvalidOperationException("less-vectors.json not found");
    }

    [Fact]
    public void ManifestListsBothOrNeither()
    {
        var s = Pq.SupportedSuites();
        Assert.Equal(LessNative.Available, s.Contains("less-cat1"));
        Assert.Equal(LessNative.Available, s.Contains("hybrid-ed25519-less-cat1"));
    }

    [Fact]
    public void KnownAnswersOrRefusal()
    {
        if (!LessNative.Available)
        {
            Assert.False(Pca.VerifySuiteSig("less-cat1", null, new string('A', 129980), new byte[1], new string('A', 1540), null));
            return;
        }
        var doc = (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(VectorsPath()))!;
        var keys = (Dictionary<string, object?>)doc["keys"]!;
        var vs = (List<object?>)doc["vectors"]!;
        Assert.True(vs.Count >= 25);
        foreach (Dictionary<string, object?> v in vs.Cast<Dictionary<string, object?>>())
        {
            var key = (Dictionary<string, object?>)keys[(string)v["key"]!]!;
            var msg = Pca.B64uDecode(v["message"])!;
            var pk = v.TryGetValue("pq_pk_override", out var o) ? o : key["pq_pk"];
            var got = Pca.VerifySuiteSig((string)v["alg"]!, key["ed_pub"], pk, msg, v["sig"], v.TryGetValue("pq_sig", out var ps) ? ps : null);
            var want = (bool)((Dictionary<string, object?>)v["expect"]!)["allow"]!;
            Assert.True(got == want, $"{v["name"]}: {got}");
        }
    }
}
