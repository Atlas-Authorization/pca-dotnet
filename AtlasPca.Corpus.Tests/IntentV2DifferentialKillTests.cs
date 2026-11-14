using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential tests of IntentV2.Decide / Active against the TS reference decideIntentV2.
/// test-data/k042-intentv2-cases.json.gz is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java,
/// Python and PHP suites run the same file): every case asserts the EXACT check list (name, ok, reason, in order), the canonical
/// env and <c>active</c>. A thrown-internal-error reason is compared up to its prefix "&lt;check&gt; error (fail closed): ".</summary>
public class IntentV2DifferentialKillTests
{
    const string FailClosed = "(fail closed): ";

    // The corpus is split with System.Text.Json (BCL, no code under test) into the raw text of each case; a case is parsed with
    // Pca.ParseJson per test, so a mutant in the parser can never poison a process-wide cache (1000+ theories: one parse of the
    // whole file per test would be too slow).
    static readonly Lazy<List<(string Name, string Raw)>> RawCases = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-intentv2-cases.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-intentv2-cases.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            using var doc = System.Text.Json.JsonDocument.Parse(sr.ReadToEnd(), new System.Text.Json.JsonDocumentOptions { MaxDepth = 4096 });
            return doc.RootElement.GetProperty("cases").EnumerateArray().Select(e => (Name: e.GetProperty("name").GetString()!, Raw: e.GetRawText())).ToList();
        }
        throw new FileNotFoundException("test-data/k042-intentv2-cases.json.gz");
    });

    public static IEnumerable<object[]> Names() => RawCases.Value.Select(c => new object[] { c.Name });

    [Fact]
    public void CorpusIsTheFullOracle() => Assert.True(RawCases.Value.Count > 1000);

    [Theory]
    [MemberData(nameof(Names))]
    public void CaseMatchesTheReference(string name)
    {
        var cs = (D)Pca.ParseJson(RawCases.Value.First(c => c.Name == name).Raw)!;
        var p = (D)Pca.ParseJson((string)cs["p"]!)!;
        var grant = (D)Pca.ParseJson((string)cs["grant"]!)!;
        IntentV2Context? ctx = cs.ContainsKey("ctx") ? IntentV2Context.FromJsonText((string)cs["ctx"]!) : null;
        if (cs.ContainsKey("wp")) ctx = ctx!.WithParams(Pca.ParseJson((string)cs["wp"]!));
        long now = cs["now"] is Num n ? long.Parse(n.Raw) : Convert.ToInt64(cs["now"]);
        var d = IntentV2.Decide(p, grant, ctx, now);
        var want = (L)cs["checks"]!;
        var got = new List<string>();
        for (int i = 0; i < d.Checks.Count; i++)
        {
            var c = d.Checks[i];
            var r = c.Reason;
            if (r != null && r.Contains("unsupported_suite")) return; // a PQ suite this host's backend lacks: by design
            if (r != null && i < want.Count && want[i] is D w && w.TryGetValue("prefix", out var pf) && pf is true)
            {
                int k = r.IndexOf(FailClosed, StringComparison.Ordinal);
                if (k >= 0) r = r[..(k + FailClosed.Length)];
            }
            got.Add($"{c.Name}|{c.Ok}|{r ?? "null"}");
        }
        var wantS = want.Select(o => { var w = (D)o!; return $"{w["name"]}|{w["ok"]}|{(w.TryGetValue("reason", out var r) && r is string s ? s : "null")}"; }).ToList();
        Assert.Equal(string.Join("\n", wantS), string.Join("\n", got));
        Assert.Equal(cs.TryGetValue("env", out var e) && e is string es ? es : "{}", Pca.Canonicalize(d.Env));
        Assert.Equal(cs["active"] is true || cs["active"] as string == "true", IntentV2.Active(p, ctx));
    }
}
