using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Rule 14 (signed action schemas) differential tests against the TS reference: test-data/k042-actionschema.json is written by
/// tools/pca-audit/java-mutate/k042-actionschema-oracle.mts (shape / verify / paramValueViolation / conformAction / accumulationParams /
/// canonProjection on inputs at the exact boundary of every rule; every input is raw JSON text). Exact reasons are compared; the four
/// value-domain reasons spelled without the bound here (as in Java) are mapped by <see cref="Reason"/>; the strict canonicalizer's own
/// message is language-specific, so a "malformed schema: " reason is compared by prefix.</summary>
public class ActionSchemaDifferentialTests
{
    static readonly Lazy<D> Data = new(() => (D)Pca.ParseJson(File.ReadAllText(Path.Combine(Dir(), "k042-actionschema.json")))!);
    static string Dir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            if (File.Exists(Path.Combine(d, "test-data", "k042-actionschema.json"))) return Path.Combine(d, "test-data");
            if (File.Exists(Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-actionschema.json"))) return Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data");
        }
        throw new FileNotFoundException("test-data/k042-actionschema.json");
    }
    static L Cases(string k) => (L)Data.Value[k]!;
    static object? J(object? raw) => IntentJs.Normalize(Pca.ParseJson((string)raw!));
    static string? Reason(string? ts) => ts == null ? null : Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(ts,
        @"longer than \d+ UTF-8 bytes$", "longer than the declared max_len"), @"below min -?\d+$", "below min"), @"above max -?\d+$", "above max"),
        @"array items must be strings of at most \d+ UTF-8 bytes$", "array items must be strings within max_len UTF-8 bytes");
    static void Report(List<string> bad, int n) { if (bad.Count > 0) Assert.Fail($"{bad.Count}/{n} mismatches:\n" + string.Join("\n", bad.Take(60))); }
    static string? Str(object? o) => o as string;

    [Fact]
    public void Shape()
    {
        var bad = new List<string>(); var cs = Cases("shape");
        foreach (D c in cs)
        {
            var want = Str(c["expect"]); var got = ActionSchema.ShapeError(J(c["doc"]));
            if (want != null && want.StartsWith("malformed schema: ") && got != null && got.StartsWith("malformed schema: ")) continue;
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }

    [Fact]
    public void ParamValueViolation()
    {
        var bad = new List<string>(); var cs = Cases("pvv");
        foreach (D c in cs)
        {
            var e = c["expect"];
            var want = e == null ? null : IntentJs.Get(e, "code") + "|" + Reason(Str(IntentJs.Get(e, "reason")));
            var r = ActionSchema.ParamValueViolation((D)J(c["d"])!, J(c["x"]));
            var got = r == null ? null : r.Value.Code + "|" + r.Value.Reason;
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }

    [Fact]
    public void Conform()
    {
        var bad = new List<string>(); var cs = Cases("conform");
        foreach (D c in cs)
        {
            var e = (D)c["expect"]!;
            var want = e["ok"] is true ? "ok|null|null|null" : $"false|{e["code"]}|{e["path"] ?? "null"}|{Reason(Str(e["reason"]))}";
            string got;
            try { var r = ActionSchema.ConformAction(J(c["doc"]), (string)c["verb"]!, J(c["params"])); got = (r.Ok ? "ok" : "false") + $"|{r.Code ?? "null"}|{r.Path ?? "null"}|{r.Reason ?? "null"}"; }
            catch (Exception x) { got = "threw " + x.GetType().Name; }
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }

    [Fact]
    public void Verify()
    {
        var bad = new List<string>(); var cs = Cases("verify");
        foreach (D c in cs)
        {
            var want = Str(c["expect"]); var got = ActionSchema.Verify(J(c["doc"]), J(c["keys"]));
            if (want != null && want.StartsWith("malformed schema: ") && got != null && got.StartsWith("malformed schema: ")) continue;
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }

    [Fact]
    public void AccumulationParams()
    {
        var bad = new List<string>(); var cs = Cases("acc");
        foreach (D c in cs)
        {
            var want = string.Join(",", ((L)c["expect"]!).Cast<string>());
            string got;
            try { got = string.Join(",", ActionSchema.AccumulationParams((D)J(c["v"])!, (string)c["unit"]!)); } catch (Exception x) { got = "threw " + x.GetType().Name; }
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }

    [Fact]
    public void CanonProjection()
    {
        var bad = new List<string>(); var cs = Cases("canon");
        foreach (D c in cs)
        {
            var e = (D)c["expect"]!;
            var want = e["ok"] is true ? Pca.Canonicalize(e["out"]) : "threw";
            string got;
            try { got = Pca.Canonicalize(ActionSchema.CanonProjection(J(c["doc"]), (string)c["verb"]!, (D)J(c["params"])!)); } catch (Exception) { got = "threw"; }
            if (want != got) bad.Add($"{c["name"]}: want <{want}> got <{got}>");
        }
        Report(bad, cs.Count);
    }
}
