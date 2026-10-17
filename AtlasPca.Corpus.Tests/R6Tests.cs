using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Round-6 shared vectors (packages/pca/conformance/vectors.json, gen-conformance-r6.mjs): whole signer-set
/// validation (R6-02, R6-03/R6-04), the signer-set hash in UTF-8 byte order, and malformed input that must be a clean
/// deny, never an exception (R6-05).</summary>
public class R6Tests
{
    static readonly HashSet<string> Supported = new(Pq.SupportedSuites()); // the capability manifest (SUITES.md)

    static string Dir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var c = Path.Combine(d, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }

    static readonly Lazy<Dictionary<string, object?>> Prim = new(() =>
        (Dictionary<string, object?>)((Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(Dir(), "vectors.json")))!)["primitives"]!);

    static List<Dictionary<string, object?>> Section(string k) =>
        ((List<object?>)Prim.Value[k]!).Cast<Dictionary<string, object?>>().ToList();

    [Fact]
    public void ThresholdSet_MatchesReference()
    {
        var bad = new List<string>();
        int ran = 0;
        foreach (var e in Section("threshold_set"))
        {
            if (e.TryGetValue("requires", out var r) && r is string req && !Supported.Contains(req)) continue;
            ran++;
            bool want = (bool)e["valid"]!;
            bool got;
            try { got = Pca.VerifyThresholdShare(e); } catch (Exception ex) { bad.Add($"{e["name"]}: THREW {ex.GetType().Name}"); continue; }
            if (got != want) bad.Add($"{e["name"]}: got {got} want {want}");
        }
        Assert.True(ran >= 50, "threshold_set ran " + ran);
        Assert.True(bad.Count == 0, string.Join("\n", bad));
    }

    [Fact]
    public void SignerSetHash_MatchesReference()
    {
        var bad = new List<string>();
        foreach (var e in Section("signer_set_hash"))
        {
            var h = Pca.SignerSetHashB64u((List<object?>)e["signer_set"]!);
            if (h != (string)e["hash"]!) bad.Add($"{e["name"]}: got {h}");
        }
        Assert.True(bad.Count == 0, string.Join("\n", bad));
    }

    [Fact]
    public void Malformed_IsACleanDeny()
    {
        var bad = new List<string>();
        foreach (var m in Section("malformed"))
        {
            var name = (string)m["name"]!;
            var input = m["input"];
            try
            {
                switch ((string)m["api"]!)
                {
                    case "chain":
                        {
                            var i = (Dictionary<string, object?>)input!;
                            var (_, ok) = Pca.VerifyChain((List<object?>)i["chain"]!, i["expected_root_issuer"], true);
                            if (ok) bad.Add(name + ": accepted");
                            break;
                        }
                    case "threshold_share":
                        if (Pca.VerifyThresholdShare(input)) bad.Add(name + ": accepted");
                        break;
                    case "pcactn_json":
                        {
                            var i = (Dictionary<string, object?>)input!;
                            long now = long.Parse(((Num)i["now"]!).Raw, System.Globalization.CultureInfo.InvariantCulture);
                            var v = Pca.VerifyRaw((string)i["text"]!, (Dictionary<string, object?>)i["grant"]!, now, (string)i["aud"]!);
                            if (v.Allow) bad.Add(name + ": allowed");
                            break;
                        }
                    default: bad.Add(name + ": unknown api"); break;
                }
            }
            catch (Exception ex) { bad.Add($"{name}: THREW {ex.GetType().Name}: {ex.Message}"); }
        }
        Assert.True(Section("malformed").Count >= 80);
        Assert.True(bad.Count == 0, string.Join("\n", bad));
    }

    // ------------------------------------------------------------------ primitives.depth (gen-conformance-depth.mjs)
    /// <summary>ITERATIVE expansion of an `expand` marker: `levels` nested arrays around `leaf` (never recursion).</summary>
    static object? Nest(int levels, object? leaf) { for (int i = 0; i < levels; i++) leaf = new List<object?> { leaf }; return leaf; }

    /// <summary>Replace (in place, iteratively) every string value equal to <paramref name="marker"/> in a parsed tree.</summary>
    static object? ExpandTree(object? root, string marker, Func<object?> make)
    {
        if (root is string s0 && s0 == marker) return make();
        var stack = new Stack<object?>(); stack.Push(root);
        while (stack.Count > 0)
        {
            switch (stack.Pop())
            {
                case Dictionary<string, object?> d:
                    foreach (var k in d.Keys.ToList()) { if (d[k] is string s && s == marker) d[k] = make(); else stack.Push(d[k]); }
                    break;
                case List<object?> l:
                    for (int i = 0; i < l.Count; i++) { if (l[i] is string s && s == marker) l[i] = make(); else stack.Push(l[i]); }
                    break;
            }
        }
        return root;
    }

    static bool RunDepth(Dictionary<string, object?> e)
    {
        var input = e["input"];
        if (e.TryGetValue("expand", out var exo) && exo is Dictionary<string, object?> ex)
        {
            var marker = (string)ex["marker"]!;
            int levels = int.Parse(((Num)ex["levels"]!).Raw, System.Globalization.CultureInfo.InvariantCulture);
            var leaf = ex["leaf"];
            var api0 = (string)e["api"]!;
            if (api0 == "chain" || api0 == "threshold_share") input = ExpandTree(input, marker, () => Nest(levels, leaf));
            else
            {
                var i = (Dictionary<string, object?>)input!;
                var leafText = leaf is Num n ? n.Raw : Pca.Canonicalize(leaf);
                i["text"] = ((string)i["text"]!).Replace(marker, new string('[', levels) + leafText + new string(']', levels));
            }
        }
        switch ((string)e["api"]!)
        {
            case "chain":
                {
                    var i = (Dictionary<string, object?>)input!;
                    return Pca.VerifyChain((List<object?>)i["chain"]!, i["expected_root_issuer"], true).Ok;
                }
            case "threshold_share": return Pca.VerifyThresholdShare(input);
            case "pcactn_json":
                {
                    var i = (Dictionary<string, object?>)input!;
                    long now = long.Parse(((Num)i["now"]!).Raw, System.Globalization.CultureInfo.InvariantCulture);
                    return Pca.VerifyRaw((string)i["text"]!, (Dictionary<string, object?>)i["grant"]!, now, (string)i["aud"]!).Allow;
                }
            case "json_parse":
                try { Pca.Canonicalize(Pca.ParseStrict((string)((Dictionary<string, object?>)input!)["text"]!)); return true; }
                catch (StrictJsonException) { return false; }
                catch (InvalidOperationException) { return false; }
            default: throw new InvalidOperationException("unknown api " + e["api"]);
        }
    }

    static void RunDepthCases(bool huge)
    {
        var bad = new List<string>();
        var entries = Section("depth");
        var picked = entries.Where(e => e.ContainsKey("expand") == huge).ToList();
        var t = new Thread(() =>
        {
            foreach (var e in picked)
            {
                var name = (string)e["name"]!;
                try { var got = RunDepth(e); if (got != (bool)e["valid"]!) bad.Add($"{name}: got {got} want {e["valid"]}"); }
                catch (Exception ex) { bad.Add($"{name}: THREW {ex.GetType().Name}: {ex.Message}"); }
            }
        }, 1024 * 1024);
        t.Start(); t.Join();
        Assert.True(entries.Count >= 29, "depth shrank: " + entries.Count);
        Assert.True(picked.Count >= (huge ? 5 : 20), "depth cases: " + picked.Count);
        foreach (var api in new[] { "chain", "threshold_share", "pcactn_json", "json_parse" }) Assert.Contains(picked, e => (string)e["api"]! == api);
        Assert.True(bad.Count == 0, string.Join("\n", bad));
    }

    /// <summary>Depth vectors at MAX_JSON_DEPTH-1 / limit / limit+1: every verdict matches the reference and no exception escapes.</summary>
    [Fact] public void Depth_MatchesReference() => RunDepthCases(huge: false);

    /// <summary>The 100000-level depth vectors (expanded iteratively): verdicts match and, on a 1 MiB stack, nothing exhausts the stack.
    /// Category=Huge: excluded from Stryker runs (a depth-cap-removing mutant overflows the stack and kills the shared test host).</summary>
    [Fact, Trait("Category", "Huge")] public void Depth_Huge_MatchesReference() => RunDepthCases(huge: true);
}
