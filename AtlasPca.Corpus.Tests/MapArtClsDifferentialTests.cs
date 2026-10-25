using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential tests of IntentMap (rule 19), IntentClassifier (rule 18) and the shared IntentArtifacts helpers against the TS
/// reference: test-data/k042-mapartcls.json.gz is written by tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs. Every validator case
/// asserts the EXACT reason (or null), every decision the exact verdict and every result member. One documented wording difference: TS
/// names the dimension path in "the action's &lt;path&gt; lies outside the committed map's dimension"; every native verifier says "the
/// action's value lies outside ...".</summary>
public class MapArtClsDifferentialTests
{
    const string Outside = "the action's value lies outside the committed map's dimension";

    static readonly Lazy<L> All = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-mapartcls.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-mapartcls.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            return (L)IntentJs.Normalize(Pca.ParseJson(sr.ReadToEnd()))!;
        }
        throw new FileNotFoundException("test-data/k042-mapartcls.json.gz");
    });

    static List<D> Of(string fn)
    {
        var o = All.Value.Cast<D>().Where(c => (string)c["fn"]! == fn).ToList();
        Assert.NotEmpty(o);
        return o;
    }
    static L Args(D c) => (L)c["args"]!;
    static void Report(List<string> bad) => Assert.True(bad.Count == 0, bad.Count + " divergent case(s):\n" + string.Join("\n", bad));
    static string Longs(IEnumerable<long> xs) => "[" + string.Join(",", xs) + "]";

    static void Validators(string fn, Func<object?, string?> v)
    {
        var bad = new List<string>();
        foreach (var c in Of(fn))
        {
            var want = c["out"] as string;
            string? got;
            try { got = v(Args(c)[0]); } catch (Exception t) { got = "THROWS " + t; }
            if (want != got) bad.Add($"{c["name"]}\n  want: {want}\n  got:  {got}");
        }
        Report(bad);
    }

    [Fact] public void HeaderLeaf() => Validators("header", IntentMap.HeaderError);
    [Fact] public void CellLeaf() => Validators("cell", IntentMap.CellError);
    [Fact] public void MetricsLeaf() => Validators("metrics", IntentMap.MetricsError);
    [Fact] public void LearnerLeaf() => Validators("learner", IntentMap.LearnerError);
    [Fact] public void DisclosureShape() => Validators("disclosure", IntentMap.DisclosureError);
    [Fact] public void VerdictWire() => Validators("verdictwire", IntentClassifier.ValidateVerdictWire);
    [Fact] public void ClassifierPolicy() => Validators("policy", IntentClassifier.ValidatePolicy);

    [Fact]
    public void NumericCells()
    {
        var bad = new List<string>();
        foreach (var c in Of("numcells"))
        {
            var got = IntentMap.NumCells((D)Args(c)[0]!).Select(r => $"[{r.Lo},{r.Hi}]");
            var want = ((L)c["out"]!).Select(w => $"[{IntentJs.Lng(((L)w!)[0])},{IntentJs.Lng(((L)w!)[1])}]");
            if (!want.SequenceEqual(got)) bad.Add($"{c["name"]}\n  want: {string.Join("", want)}\n  got:  {string.Join("", got)}");
        }
        Report(bad);
    }

    [Fact]
    public void CellOfTheAction()
    {
        var bad = new List<string>();
        foreach (var c in Of("cellof"))
        {
            var a = Args(c); string got, w;
            try
            {
                var r = IntentMap.CellOf((D)a[0]!, a[1], a.Count > 2 ? a[2] : null);
                got = r == null ? "null" : Longs(r.Value.Cell) + " " + r.Value.Flat;
            }
            catch (Exception t) { got = "THROWS " + t; }
            var want = c["out"];
            w = want == null ? "null" : Longs(((L)IntentJs.Get(want, "cell")!).Select(IntentJs.Lng)) + " " + IntentJs.Lng(IntentJs.Get(want, "flat"));
            if (w != got) bad.Add($"{c["name"]}\n  want: {w}\n  got:  {got}");
        }
        Report(bad);
    }

    [Fact]
    public void Commitment()
    {
        var bad = new List<string>();
        foreach (var c in Of("commit"))
        {
            string got;
            try { got = IntentMap.CommitLeaves(Args(c)[0]); } catch (Exception t) { got = "THROWS " + t; }
            if ((string)c["out"]! != got) bad.Add($"{c["name"]}\n  want: {c["out"]}\n  got:  {got}");
        }
        Report(bad);
    }

    static string Render(IntentMap.Decision d) => $"{(d.Ok ? "true" : "false")}|{d.Reason ?? "null"}|{(d.Cell == null ? "null" : Longs(d.Cell))}|{d.PPpm}|{d.ResidualRiskPpm}";
    static string RenderWant(D o)
    {
        if (o["ok"] is true) return $"true|null|{Longs(((L)o["cell"]!).Select(IntentJs.Lng))}|{IntentJs.Lng(o["p_ppm"])}|{IntentJs.Lng(o["residual_risk_ppm"])}";
        var r = (string)o["reason"]!;
        if (r.StartsWith("the action's ", StringComparison.Ordinal) && r.EndsWith(" lies outside the committed map's dimension", StringComparison.Ordinal)) r = Outside;
        return "false|" + r + "|null|0|0";
    }

    [Fact]
    public void MapDecisions()
    {
        var bad = new List<string>();
        foreach (var c in Of("decide"))
        {
            var want = RenderWant((D)c["out"]!); string got;
            try { got = Render(IntentMap.DecidePrimitive(Args(c)[0])); } catch (Exception t) { got = "THROWS " + t; }
            if (want != got) bad.Add($"{c["name"]}\n  want: {want}\n  got:  {got}");
        }
        Report(bad);
    }

    static string RenderClass(bool ok, string? reason, D? classes) => $"{(ok ? "true" : "false")}|{reason ?? "null"}|{(classes == null ? "null" : Pca.Canonicalize(classes))}";

    [Fact]
    public void ClassifierDecisions()
    {
        var bad = new List<string>();
        foreach (var c in Of("classify"))
        {
            var o = (D)c["out"]!;
            var want = RenderClass(o["ok"] is true, o.GetValueOrDefault("reason") as string, o.GetValueOrDefault("classes") as D); string got;
            try { var r = IntentClassifier.Decide(Args(c)[0]); got = RenderClass(r.Ok, r.Reason, r.Classes); } catch (Exception t) { got = "THROWS " + t; }
            if (want != got) bad.Add($"{c["name"]}\n  want: {want}\n  got:  {got}");
        }
        Report(bad);
    }

    /// <summary>The classifier decision through the already-normalized entry (no second normalization) agrees too.</summary>
    [Fact]
    public void ClassifierDecisionsNormalizedEntry()
    {
        foreach (var c in Of("classify"))
        {
            if (Args(c)[0] is not D input) continue;
            var o = (D)c["out"]!;
            var r = IntentClassifier.Decide(input);
            Assert.Equal(o.GetValueOrDefault("reason") as string, r.Reason);
            Assert.Equal(o["ok"] is true, r.Ok);
        }
    }

    [Fact]
    public void ArtifactSignature()
    {
        var a = Args(Of("sigfixture")[0]);
        var v = (D)a[0]!; var pk = (string)a[1]!; var other = (string)a[2]!;
        var dom = IntentClassifier.IntentClassifierDomain;
        Assert.True(IntentArtifacts.VerifyArtifactSig(dom, v, pk, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, v, other, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom + "x", v, pk, null));
        var noSig = new D(v); noSig.Remove("sig");
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, noSig, pk, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, new D(v) { ["sig"] = new Num("5") }, pk, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, v, null, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, v, new Num("5"), null));
        // a body without a strict canonical form is a failed signature (never an exception, never a pass)
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, new D(v) { ["label"] = "a\uD800" }, pk, null));
        Assert.False(IntentArtifacts.VerifyArtifactSig(dom, new D(v) { ["v"] = new Num("1.0") }, pk, null));
    }
}
