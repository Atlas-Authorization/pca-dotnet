using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for LessNative.cs and the LESS seams of Pq / Pca (suite flags, wire shape, variable-length signatures).
/// The backend-dependent assertions run when libatlas_less is loadable (CI builds it and exports ATLAS_PCA_LIBLESS).</summary>
public class LessKillTests
{
    static D Vectors()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "packages", "pca", "conformance", "less-vectors.json");
            if (File.Exists(p)) return (D)Pca.ParseJson(File.ReadAllText(p))!;
        }
        throw new InvalidOperationException("less-vectors.json not found");
    }

    [Fact]
    public void SigLenOkEveryBound()
    {
        Assert.Equal(97484, LessNative.PublicKeyBytes);
        Assert.Equal(1153, LessNative.SignatureMinBytes);
        Assert.Equal(1329, LessNative.SignatureMaxBytes);
        var ok = new List<int>();
        for (int n = -20; n <= 1400; n++) if (LessNative.SigLenOk(n)) ok.Add(n);
        var want = new List<int>();
        for (int n = 1153; n <= 1329; n += 16) want.Add(n);
        Assert.Equal(want, ok);
        Assert.Equal(12, ok.Count);
        foreach (var n in new[] { 1152, 1330, 1345, 1137, 1328, 1154, 0, int.MinValue, int.MaxValue }) Assert.False(LessNative.SigLenOk(n));
        Assert.True(Pq.SigLenOk(Pq.Prim.Less, 1313)); Assert.False(Pq.SigLenOk(Pq.Prim.Less, 1312));
    }

    [Fact]
    public void LibraryIsLoadedWhenACandidateExists()
    {
        bool anyFile = LessNative.Candidates().Any(File.Exists);
        if (anyFile) Assert.True(LessNative.Available);
        else Assert.False(LessNative.Available);
        Assert.Equal(LessNative.Available, Pq.Suites.ContainsKey("less-cat1"));
        Assert.Equal(LessNative.Available, Pq.Suites.ContainsKey("hybrid-ed25519-less-cat1"));
    }

    [Fact]
    public void CandidatePathsFollowTheEnvironmentThenTheRepositoryBuildDirectory()
    {
        var old = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBLESS");
        try
        {
            var sep = Path.PathSeparator;
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", null);
            var none = LessNative.Candidates().ToList();
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", "");
            Assert.Equal(none, LessNative.Candidates().ToList());
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", $"/x/one{sep}/y/two{sep}{sep}");
            var withEnv = LessNative.Candidates().ToList();
            Assert.Equal(new[] { "/x/one", "/y/two" }, withEnv.Take(2));
            Assert.Equal(none, withEnv.Skip(2).ToList());
            if (none.Count > 0)
            {
                Assert.Equal(3, none.Count);
                Assert.Equal(new[] { "libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll" }, none.Select(Path.GetFileName));
                Assert.All(none, p => Assert.EndsWith(Path.Combine("sdks", "pca-less-c", "build", Path.GetFileName(p)!), p));
            }
        }
        finally { Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", old); }
    }

    [Fact]
    public void VerifyRefusesWrongLengthsBeforeCallingTheLibrary()
    {
        var msg = new byte[] { 1 };
        Assert.False(LessNative.Verify(new byte[10], msg, new byte[1153]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes], msg, new byte[1152]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes - 1], msg, new byte[1153]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes + 1], msg, new byte[1153]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes], msg, new byte[1153]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes], Array.Empty<byte>(), new byte[1153]));
        Assert.False(LessNative.Verify(new byte[LessNative.PublicKeyBytes], null!, new byte[1153]));
    }

    [Fact]
    public void WireShapeOfTheLessSuitesMatchesTheVectors()
    {
        if (!LessNative.Available) return;
        var doc = Vectors();
        var keys = (D)doc["keys"]!;
        var first = (D)((L)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["vectors"]!)[0]!;
        foreach (D v in ((L)doc["vectors"]!).Cast<D>())
        {
            var key = (D)keys[(string)v["key"]!]!;
            bool wireOk = (bool)((D)v["expect"]!)["wire_ok"]!;
            var pk = v.TryGetValue("pq_pk_override", out var o) ? o : key["pq_pk"];
            // a threshold share carries alg, sig (and pq_sig for the hybrid); the PCActn adds pq_pk
            var share = new D { ["alg"] = v["alg"], ["sig"] = v["sig"] };
            if (v.TryGetValue("pq_sig", out var ps)) share["pq_sig"] = ps;
            if (!(bool)((D)v["expect"]!)["wire_ok"]! && pk is string && v.ContainsKey("pq_pk_override")) continue;
            var shareErr = Pca.ValidateShareSignatureWire(share);
            // the pq_pk-only failures are judged by the PCActn wire, the rest by both
            var p = (D)IntentJs.Normalize(first["pcactn"])!;
            p["alg"] = v["alg"]; p["sig"] = v["sig"]; p["pq_pk"] = pk;
            if (v.TryGetValue("pq_sig", out var ps2)) p["pq_sig"] = ps2; else p.Remove("pq_sig");
            var wireErr = Pca.ValidateWire(p);
            if (wireOk) { Assert.Null(shareErr); Assert.True(wireErr == null, $"{v["name"]}: {wireErr}"); }
            else Assert.True(shareErr != null || wireErr != null, (string)v["name"]!);
        }
    }

    [Fact]
    public void PureLessCarriesNoPqSigAndTheHybridRequiresOne()
    {
        if (!LessNative.Available) return;
        var doc = Vectors();
        var pure = ((L)doc["vectors"]!).Cast<D>().First(v => (string)v["name"]! == "less-cat1-valid");
        var hybrid = ((L)doc["vectors"]!).Cast<D>().First(v => (string)v["name"]! == "hybrid-less-valid");
        var s = new D { ["alg"] = "less-cat1", ["sig"] = pure["sig"] };
        Assert.Null(Pca.ValidateShareSignatureWire(s));
        s["pq_sig"] = hybrid["pq_sig"];
        Assert.Equal("'pq_sig' must be absent for alg 'less-cat1'", Pca.ValidateShareSignatureWire(s));
        var h = new D { ["alg"] = "hybrid-ed25519-less-cat1", ["sig"] = hybrid["sig"] };
        Assert.StartsWith("'pq_sig' is not canonical base64url", Pca.ValidateShareSignatureWire(h));
        h["pq_sig"] = hybrid["pq_sig"];
        Assert.Null(Pca.ValidateShareSignatureWire(h));
        var shortSig = new D { ["alg"] = "less-cat1", ["sig"] = Pca.B64u(new byte[1153]) };
        Assert.Null(Pca.ValidateShareSignatureWire(shortSig));
        Assert.NotNull(Pca.ValidateShareSignatureWire(new D { ["alg"] = "less-cat1", ["sig"] = Pca.B64u(new byte[1152]) }));
    }

    static string ConfDir()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var c = Path.Combine(d.FullName, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }
}
