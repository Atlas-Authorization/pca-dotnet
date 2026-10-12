using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Runs the conformance corpus (vectors.json core + vectors-adversarial.json.gz) against the .NET verifier.
/// The adversarial vectors are split into chunks so a mutant is killed by the first failing chunk.</summary>
public class CorpusTests
{
    const int Chunks = 16;
    static readonly HashSet<string> Supported = new() { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" };
    static readonly HashSet<string> Registered = new() { "ed25519", "ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87",
        "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s" };

    static string Dir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var c = Path.Combine(d, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json")) && Directory.Exists(Path.Combine(d, "tools", "pca-audit"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }

    static readonly Lazy<Dictionary<string, object?>> Core = new(() =>
        (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(Dir(), "vectors.json")))!);
    static readonly Lazy<Dictionary<string, object?>> Adv = new(() =>
    {
        using var fs = File.OpenRead(Path.Combine(Dir(), "vectors-adversarial.json.gz"));
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var sr = new StreamReader(gz, new UTF8Encoding(false));
        return (Dictionary<string, object?>)Pca.ParseJson(sr.ReadToEnd())!;
    });

    static string AlgOf(Dictionary<string, object?> o) => o.TryGetValue("alg", out var a) && a is string s ? s : "ed25519";

    static string? UnsupportedSuite(Dictionary<string, object?> v)
    {
        if (!v.TryGetValue("pcactn", out var po) || po is not Dictionary<string, object?> p) return null;
        var req = v.TryGetValue("requires", out var r) ? r as string : null;
        // 0.4.1: a vector may name the suite it needs in `requires` (e.g. a threshold share under ml-dsa-87).
        if (req != null && Registered.Contains(req) && !Supported.Contains(req)) return req;
        if (req == "pq") { var a = AlgOf(p); return Supported.Contains(a) ? null : a; }
        if (req == "pq-nonleaf" && p.TryGetValue("cap_chain", out var cc) && cc is List<object?> chain)
            foreach (var hv in chain)
                if (hv is Dictionary<string, object?> hop) { var a = AlgOf(hop); if (!Supported.Contains(a)) return a; }
        return null;
    }

    static bool TerminalWireFalse(Dictionary<string, object?> checks) =>
        checks.Count == 1 && checks.TryGetValue("wire", out var w) && w is bool b && !b;

    static void RunVectors(List<object?> vs, int k, int step)
    {
        for (int i = k; i < vs.Count; i += step)
        {
            var v = (Dictionary<string, object?>)vs[i]!;
            var name = (string)v["name"]!;
            var exp = (Dictionary<string, object?>)v["expect"]!;
            var expChecks = (Dictionary<string, object?>)exp["checks"]!;
            if (UnsupportedSuite(v) != null && !TerminalWireFalse(expChecks)) continue;
            var ctx = (Dictionary<string, object?>)v["context"]!;
            long now = long.Parse(((Num)ctx["now"]!).Raw);
            var aud = (string)ctx["aud"]!;
            var grant = (Dictionary<string, object?>)v["grant"]!;
            List<string>? allowed = ctx.TryGetValue("allowed_suites", out var asObj) && asObj is List<object?> asl ? asl.Select(z => (string)z!).ToList() : null;
            Verdict got;
            try
            {
                got = v.ContainsKey("pcactn_json")
                    ? Pca.VerifyRaw((string)v["pcactn_json"]!, grant, now, aud, allowed)
                    : Pca.VerifyPcactnCore(v["pcactn"], grant, now, aud, allowed);
            }
            catch (Exception e) { Assert.Fail(name + " threw " + e.GetType().Name); return; }
            Assert.True(got.Allow == (bool)exp["allow"]!, $"{name} allow={got.Allow} ({got.Reason})");
            Assert.True(got.Checks.Count == expChecks.Count, $"{name} check count");
            foreach (var (key, w) in expChecks)
                Assert.True(got.Checks.TryGetValue(key, out var g) && g == (bool)w!, $"{name} check {key}");
        }
    }

    [Fact] public void CoreVectors() => BigStack.Run(() => RunVectors((List<object?>)Core.Value["vectors"]!, 0, 1));

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)] [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(15)]
    public void AdversarialChunk(int k) => BigStack.Run(() => RunVectors((List<object?>)Adv.Value["vectors"]!, k, Chunks));

    static void RunPrimitives(Dictionary<string, object?> prim)
    {
        if (prim.TryGetValue("canonical", out var cl))
            foreach (var x in (List<object?>)cl!)
            {
                var c = (Dictionary<string, object?>)x!;
                Assert.Equal((string)c["expect"]!, Pca.Canonicalize(c["value"]));
                if (c.ContainsKey("hash")) Assert.Equal((string)c["hash"]!, Pca.HashCanonical(c["value"]));
            }
        if (prim.TryGetValue("json_parse", out var jl))
            foreach (var x in (List<object?>)jl!)
            {
                var c = (Dictionary<string, object?>)x!;
                var input = (string)c["input"]!; bool accept = (bool)c["accept"]!;
                bool got; string? canon = null;
                try { canon = Pca.Canonicalize(Pca.ParseStrict(input)); got = true; } catch (Exception) { got = false; }
                Assert.True(got == accept, "json_parse " + input);
                if (accept && c.ContainsKey("canonical")) Assert.Equal((string)c["canonical"]!, canon);
            }
        if (prim.TryGetValue("b64u", out var bl))
            foreach (var x in (List<object?>)bl!)
            {
                var c = (Dictionary<string, object?>)x!;
                int? len = c.TryGetValue("len", out var l) && l is Num ln ? int.Parse(ln.Raw) : null;
                Assert.True((Pca.B64uDecode((string)c["input"]!, len) != null) == (bool)c["valid"]!, "b64u " + c["input"]);
            }
    }

    [Fact] public void CorePrimitives() => BigStack.Run(() => RunPrimitives((Dictionary<string, object?>)Core.Value["primitives"]!));
    [Fact] public void AdversarialPrimitives() => BigStack.Run(() => RunPrimitives((Dictionary<string, object?>)Adv.Value["primitives"]!));

    [Fact]
    public void MerkleParamsSharesArtifacts()
    {
        var prim = (Dictionary<string, object?>)Core.Value["primitives"]!;
        foreach (var x in (List<object?>)prim["merkle"]!)
        {
            var m = (Dictionary<string, object?>)x!;
            var leaves = (List<object?>)m["leaves"]!;
            var root = Pca.MerkleRoot(leaves);
            Assert.Equal((string)m["root"]!, root);
            var proofs = (List<object?>)m["proofs"]!;
            for (int i = 0; i < proofs.Count; i++)
                Assert.True(Pca.VerifyInclusion(root, (Dictionary<string, object?>)proofs[i]!, leaves[i]), "merkle proof " + i);
        }
        Assert.Equal((string)prim["params_digest_empty"]!, Pca.ParamsDigest(null));
        bool bare = false, wrong = false, bound = false;
        foreach (var x in (List<object?>)prim["threshold_share"]!)
        {
            var s = (Dictionary<string, object?>)x!;
            var sname = (s.TryGetValue("name", out var n) ? n as string : null) ?? (string)s["role"]!;
            bool want = !s.TryGetValue("valid", out var vo) || vo is not bool vb || vb;
            bool got = Pca.VerifyThresholdShare(s);
            Assert.True(got == want, "threshold_share " + sname);
            if (sname == "agent-bare-rejected" && !got) bare = true;
            if (sname == "agent-bound-wrong-set" && !got) wrong = true;
            if (sname.StartsWith("agent-bound-t") && got) bound = true;
        }
        Assert.True(bare && wrong);
        foreach (var x in (List<object?>)prim["pq_artifact"]!)
        {
            var a = (Dictionary<string, object?>)x!;
            var alg = a.TryGetValue("alg", out var av) ? av as string : null;
            if (alg == null || !Supported.Contains(alg)) continue;
            var msg = Pca.B64uDecode((string)a["message"]!);
            bool want = !a.TryGetValue("valid", out var vo) || vo is not bool vb || vb;
            bool got = msg != null && Pca.VerifySuiteSig(alg, a.GetValueOrDefault("ed_pub"), a.GetValueOrDefault("pq_pk"), msg, a.GetValueOrDefault("sig"), a.GetValueOrDefault("pq_sig"));
            Assert.True(got == want, "pq_artifact " + alg);
        }
    }
}
