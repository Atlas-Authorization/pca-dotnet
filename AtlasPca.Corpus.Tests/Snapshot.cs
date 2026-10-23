using System.IO.Compression;
using System.Text;
using System.Text.Json;
using AtlasPca;

namespace AtlasPca.Corpus.Tests;

/// <summary>Characterization snapshot of every observable verifier output over the conformance corpus (core + adversarial)
/// and tools/pca-audit/native-mutation/inputs.jsonl.gz: verdict, diagnostic reason, rejection message, canonical forms.
/// Regenerate: PCA_SNAPSHOT_WRITE=path dotnet test --filter WriteSnapshot</summary>
public static class Snapshot
{
    public static string Root()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
            if (File.Exists(Path.Combine(d, "packages", "pca", "conformance", "vectors.json")) && Directory.Exists(Path.Combine(d, "tools", "pca-audit"))) return d;
        throw new InvalidOperationException("repo root not found");
    }

    public static string SnapPath() => Path.Combine(Root(), "sdks", "dotnet-pca", "AtlasPca.Corpus.Tests", "test-data", "reasons.tsv.gz");

    public static string Esc(string? s)
    {
        if (s == null) return "<nil>";
        var b = new StringBuilder();
        foreach (var ch in s)
        {
            if (ch == '\\') b.Append("\\\\");
            else if (ch == '\n') b.Append("\\n");
            else if (ch == '\t') b.Append("\\t");
            else if (ch == '\r') b.Append("\\r");
            else if (ch < 0x20) b.Append($"\\u{(int)ch:x4}");
            else b.Append(ch);
        }
        return b.ToString();
    }

    public static string Fmt(Verdict g) =>
        (g.Allow ? "true" : "false") + "|" + string.Join(",", g.Checks.Select(kv => kv.Key + "=" + (kv.Value ? "true" : "false"))) + "|" + Esc(g.Reason);

    static string Guard(Func<string> f)
    {
        try { return f(); }
        catch (Exception e) { return "THROW:" + e.GetType().Name + ":" + Esc(e.Message); }
    }

    public static string ParseOutcome(string input, bool lax)
    {
        try { return Esc(Pca.Canonicalize(lax ? Pca.ParseJson(input) : Pca.ParseStrict(input))); }
        catch (StrictJsonException e) { return "err:" + Esc(e.Message); }
        catch (Exception e) { return "THROW:" + e.GetType().Name + ":" + Esc(e.Message); }
    }

    public static Verdict VerifyVector(Dictionary<string, object?> v)
    {
        var ctx = (Dictionary<string, object?>)v["context"]!;
        long now = long.Parse(((Num)ctx["now"]!).Raw);
        var aud = (string)ctx["aud"]!;
        var grant = (Dictionary<string, object?>)v["grant"]!;
        List<string>? allowed = ctx.TryGetValue("allowed_suites", out var a) && a is List<object?> l ? l.Select(z => (string)z!).ToList() : null;
        var ip = ctx.GetValueOrDefault("intent_policy_json") is string ipj ? IntentPolicy.FromJsonText(ipj) : IntentPolicy.FromJson(ctx.GetValueOrDefault("intent_policy"));
        var v2 = ctx.ContainsKey("intent_v2") ? IntentV2Context.FromJson(ctx["intent_v2"]) : null;
        return v.ContainsKey("pcactn_json")
            ? Pca.VerifyRaw((string)v["pcactn_json"]!, grant, now, aud, allowed, ip, v2)
            : Pca.VerifyPcactnCore(v["pcactn"], grant, now, aud, allowed, ip, v2);
    }

    static Dictionary<string, object?>? core, adv;
    static List<JsonElement>? inputs;
    static Dictionary<string, string>? snap;

    public static Dictionary<string, object?> Core() => core ??= (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(Root(), "packages", "pca", "conformance", "vectors.json")))!;

    public static Dictionary<string, object?> Adv()
    {
        if (adv != null) return adv;
        using var fs = File.OpenRead(Path.Combine(Root(), "packages", "pca", "conformance", "vectors-adversarial.json.gz"));
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var sr = new StreamReader(gz, new UTF8Encoding(false));
        return adv = (Dictionary<string, object?>)Pca.ParseJson(sr.ReadToEnd())!;
    }

    public static List<JsonElement> Inputs()
    {
        if (inputs != null) return inputs;
        using var fs = File.OpenRead(Path.Combine(Root(), "tools", "pca-audit", "native-mutation", "inputs.jsonl.gz"));
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var sr = new StreamReader(gz, new UTF8Encoding(false));
        var l = new List<JsonElement>();
        string? line;
        while ((line = sr.ReadLine()) != null) if (line.Length > 0) l.Add(JsonDocument.Parse(line).RootElement.Clone());
        return inputs = l;
    }

    public static Dictionary<string, string> Load()
    {
        if (snap != null) return snap;
        var m = new Dictionary<string, string>();
        using var fs = File.OpenRead(SnapPath());
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var sr = new StreamReader(gz, new UTF8Encoding(false));
        string? l;
        while ((l = sr.ReadLine()) != null) { int t = l.IndexOf('\t'); if (t > 0) m[l[..t]] = l[(t + 1)..]; }
        return snap = m;
    }

    public static List<(string, string)> ComputeInputs(int k, int step)
    {
        var o = new List<(string, string)>();
        var all = Inputs();
        for (int i = k; i < all.Count; i += step)
        {
            var c = all[i];
            var raw = c.GetProperty("raw").GetString()!;
            string val;
            if (c.GetProperty("kind").GetString() == "verify")
            {
                val = Guard(() =>
                {
                    var grant = (Dictionary<string, object?>)Pca.ParseJson(c.GetProperty("grant").GetString()!)!;
                    List<string>? allowed = null;
                    if (c.TryGetProperty("allowed_suites", out var al) && al.ValueKind == JsonValueKind.Array) allowed = al.EnumerateArray().Select(x => x.GetString()!).ToList();
                    var ip = c.TryGetProperty("intent_policy_json", out var ipjEl) && ipjEl.ValueKind == JsonValueKind.String ? IntentPolicy.FromJsonText(ipjEl.GetString()!)
                        : c.TryGetProperty("intent_policy", out var ipEl) ? IntentPolicy.FromJson(Pca.ParseJson(ipEl.GetRawText())) : null;
                    var v2 = c.TryGetProperty("intent_v2", out var v2El) ? IntentV2Context.FromJson(Pca.ParseJson(v2El.GetRawText())) : null;
                    return Fmt(Pca.VerifyRaw(raw, grant, c.GetProperty("now").GetInt64(), c.GetProperty("aud").GetString()!, allowed, ip, v2));
                });
            }
            else val = ParseOutcome(raw, false) + "|len=" + ParseOutcome(raw, true);
            if (val.Length > 600) val = val[..600] + "#" + val.Length;
            o.Add(("in:" + c.GetProperty("id").GetString(), val));
        }
        return o;
    }

    public static List<(string, string)> ComputeVectors(Dictionary<string, object?> doc, string tag, int k, int step)
    {
        var o = new List<(string, string)>();
        var vs = (List<object?>)doc["vectors"]!;
        for (int i = k; i < vs.Count; i += step)
        {
            var v = (Dictionary<string, object?>)vs[i]!;
            o.Add(($"{tag}:v:{v["name"]}", Guard(() => Fmt(VerifyVector(v)))));
        }
        if (k == 0 && doc.TryGetValue("primitives", out var pr) && pr is Dictionary<string, object?> prim)
        {
            if (prim.TryGetValue("json_parse", out var jp) && jp is List<object?> jl)
                for (int n = 0; n < jl.Count; n++)
                {
                    var inp = (string)((Dictionary<string, object?>)jl[n]!)["input"]!;
                    o.Add(($"{tag}:jp:{n}:{Esc(inp.Length > 80 ? inp[..80] : inp)}", ParseOutcome(inp, false) + "|len=" + ParseOutcome(inp, true)));
                }
            if (prim.TryGetValue("canonical", out var cn) && cn is List<object?> cl)
                for (int n = 0; n < cl.Count; n++)
                {
                    var val = ((Dictionary<string, object?>)cl[n]!)["value"];
                    o.Add(($"{tag}:cn:{n}", Esc(Guard(() => Pca.Canonicalize(val) + "|" + Pca.HashCanonical(val)))));
                }
            if (prim.TryGetValue("b64u", out var b6) && b6 is List<object?> bl)
                for (int n = 0; n < bl.Count; n++)
                {
                    var b = (Dictionary<string, object?>)bl[n]!;
                    int? len = b.TryGetValue("len", out var ln) && ln is Num nn ? int.Parse(nn.Raw) : null;
                    var r = Pca.B64uDecode((string)b["input"]!, len);
                    o.Add(($"{tag}:b6:{n}", r == null ? "nil" : Convert.ToHexString(r).ToLowerInvariant()));
                }
        }
        return o;
    }

    public static void Write(string path)
    {
        var all = ComputeVectors(Core(), "core", 0, 1).Concat(ComputeVectors(Adv(), "adv", 0, 1)).Concat(ComputeInputs(0, 1)).ToList();
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.SmallestSize);
        using var sw = new StreamWriter(gz, new UTF8Encoding(false));
        foreach (var (k, v) in all) sw.Write(Esc(k) + "\t" + v + "\n");
    }
}
