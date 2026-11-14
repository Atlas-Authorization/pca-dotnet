using System.Collections;
using System.Globalization;
using System.Runtime;
using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Shared harness of the k05 differential oracles: test-data/k05-&lt;module&gt;.json.gz = {cases: [{fn, name, args, out}]}
/// written by the TypeScript reference. Bytes are {"$bytes": b64url}; a reference throw is {"$throws": message, code?} (the native
/// must refuse; when <c>code</c> is present a thrown refusal must carry that code; a refusal by value carries none). fn names ending in <c>@suspect</c> are reported, never failed.</summary>
static class K05
{
    /// <summary>A mapper returns this when the native refuses by value (null / false / an error result) where the reference throws.</summary>
    public static readonly object Refused = new();

    // one module at a time (the assembly runs its tests serially, a class reads one module): all ten parsed oracles are ~3 GiB,
    // over the mutation runs' per-test-host GC heap cap
    static readonly object Gate = new();
    // two fields, no local copy: an unoptimized (tier-0) frame keeps every local alive to method end, and a local holding the old module
    // while the next one parses puts both in the heap (an OutOfMemoryException on the unmutated source, shard 6 of run 42109424696)
    static string? LoadedModule;
    static List<D>? LoadedCases;

    public static List<D> Cases(string module)
    {
        lock (Gate)
        {
            if (LoadedModule == module) return LoadedCases!;
            LoadedModule = null;
            LoadedCases = null;
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect();
            var file = "k05-" + module + ".json.gz";
            var d = AppContext.BaseDirectory;
            for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
            {
                var f = Path.Combine(d, "test-data", file);
                if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", file);
                if (!File.Exists(f)) continue;
                LoadedCases = ((L)((D)FixtureJson.Parse(Inflate(f))!)["cases"]!).Cast<D>().ToList(); // the unmutated reader: this cache outlives mutants
                LoadedModule = module;
                return LoadedCases;
            }
            throw new FileNotFoundException("test-data/" + file);
        }
    }

    // sized from the gzip trailer: ReadToEnd holds chunks and the final string together, twice the peak on a 172 MB oracle
    static string Inflate(string f)
    {
        var raw = File.ReadAllBytes(f);
        var text = new byte[BitConverter.ToInt32(raw, raw.Length - 4)];
        using var gz = new GZipStream(new MemoryStream(raw), CompressionMode.Decompress);
        gz.ReadExactly(text);
        return new UTF8Encoding(false).GetString(text);
    }

    public static IEnumerable<D> Of(string module, string fn) => Cases(module).Where(c => (string)c["fn"]! == fn || (string)c["fn"]! == fn + "@suspect");
    public static L Args(D c) => (L)c["args"]!;

    // ---- argument helpers ----
    public static byte[] Bytes(object? a) => Pca.B64uDecode(((D)a!)["$bytes"]) ?? throw new InvalidDataException("bad $bytes");
    public static bool IsBytes(object? a) => a is D m && m.Count == 1 && m.ContainsKey("$bytes");
    public static long Long(object? a) => IntentJs.Lng(a);
    public static bool IsJsonInt(object? a) => a is Num n && long.TryParse(n.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _);
    public static object? Deep(object? a) => a switch
    {
        D m => m.ToDictionary(e => e.Key, e => Deep(e.Value)),
        L l => l.Select(Deep).ToList(),
        _ => a,
    };

    // ---- result -> JSON tree ----
    public static object? Json(object? v) => v switch
    {
        null => null,
        string or bool or Num => v,
        byte[] b => new D { ["$bytes"] = Pca.B64u(b) },
        int or long or short or uint or ulong or double or float or decimal => IntentJs.Normalize(new Num(Convert.ToString(v, CultureInfo.InvariantCulture)!)),
        IDictionary m => m.Keys.Cast<object>().ToDictionary(k => k.ToString()!, k => Json(m[k])),
        IEnumerable e => e.Cast<object?>().Select(Json).ToList(),
        _ => throw new InvalidOperationException("K05.Json: map " + v.GetType() + " explicitly"),
    };

    /// <summary>Deterministic text of a JSON tree: sorted keys (ordinal), numbers as JavaScript prints them, every non-ASCII code unit
    /// escaped (so lone surrogates compare too). Equal text = equal value.</summary>
    public static string Show(object? v)
    {
        var sb = new StringBuilder();
        void S(string s)
        {
            sb.Append('"');
            foreach (var ch in s)
                if (ch == '"' || ch == '\\') sb.Append('\\').Append(ch);
                else if (ch < 0x20 || ch > 0x7e) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                else sb.Append(ch);
            sb.Append('"');
        }
        void W(object? x)
        {
            switch (x)
            {
                case null: sb.Append("null"); break;
                case bool b: sb.Append(b ? "true" : "false"); break;
                case string s: S(s); break;
                case Num n: sb.Append(IntentJs.NormNum(n.Raw).Raw); break;
                case L l: sb.Append('['); for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); W(l[i]); } sb.Append(']'); break;
                case D m:
                    sb.Append('{');
                    var first = true;
                    foreach (var k in m.Keys.OrderBy(k => k, StringComparer.Ordinal))
                    {
                        if (!first) sb.Append(','); first = false;
                        S(k); sb.Append(':'); W(m[k]);
                    }
                    sb.Append('}');
                    break;
                default: W(Json(x)); break;
            }
        }
        W(v);
        return sb.ToString();
    }

    public static bool Eq(object? want, object? have) => Show(want) == Show(Json(have));

    public static bool Throws(D c, out string? code)
    {
        code = null;
        if (c["out"] is D o && o.ContainsKey("$throws")) { code = o.GetValueOrDefault("code") as string; return true; }
        return false;
    }

    /// <summary>The exception's Code property, else a leading "code: " of its message (the convention of the untyped .NET refusals).</summary>
    static string? CodeOf(Exception e)
    {
        if (e.GetType().GetProperty("Code")?.GetValue(e) is string c) return c;
        var i = e.Message.IndexOf(": ", StringComparison.Ordinal);
        return i > 0 && e.Message[..i].All(ch => ch is >= 'a' and <= 'z' or '_') ? e.Message[..i] : null;
    }

    /// <summary>Replay every case of (module, fn): <paramref name="run"/> maps the args to the native call and returns its result
    /// (or <see cref="Refused"/>); <paramref name="eq"/> overrides the comparison (default: JSON equality with out);
    /// <paramref name="skip"/> returns a reason to skip a case (counted, listed in the output). Returns the number compared.</summary>
    public static int Check(string module, string fn, Func<L, object?> run, Func<D, object?, bool>? eq = null, Func<D, string?>? skip = null, int min = 1)
    {
        var bad = new List<string>(); var suspect = new List<string>(); int n = 0, skipped = 0;
        foreach (var c in Of(module, fn))
        {
            var name = (string)c["name"]!;
            if (skip?.Invoke(c) is string why) { skipped++; continue; }
            n++;
            var isSuspect = ((string)c["fn"]!).EndsWith("@suspect", StringComparison.Ordinal);
            var sink = isSuspect ? suspect : bad;
            var wantThrow = Throws(c, out var code);
            object? have; Exception? ex = null;
            try { have = run(Args(c)); } catch (Exception e) { have = null; ex = e; }
            if (wantThrow)
            {
                if (ex == null && !ReferenceEquals(have, Refused)) sink.Add($"{name}\n   want throw {Show(c["out"])}\n   have {Safe(have)}");
                else if (code != null && ex != null && CodeOf(ex) is string hc && hc != code) sink.Add($"{name}\n   want code {code}\n   have code {hc}: {ex.Message}");
                else if (code != null && ex != null && CodeOf(ex) == null) sink.Add($"{name}\n   want code {code}\n   have {ex.GetType().Name}: {ex.Message}");
                continue;
            }
            if (ex != null) { sink.Add($"{name}\n   want {Show(c["out"])}\n   threw {ex.GetType().Name}: {ex.Message}"); continue; }
            bool ok;
            try { ok = eq != null ? eq(c, have) : !ReferenceEquals(have, Refused) && Eq(c["out"], have); }
            catch (Exception e) { ok = false; have = "compare threw " + e.Message; }
            if (!ok) sink.Add($"{name}\n   want {Show(c["out"])}\n   have {Safe(have)}");
        }
        if (suspect.Count > 0) Console.WriteLine($"k05 {module}/{fn}: {suspect.Count} @suspect divergence(s) (reported, not failed):\n" + string.Join("\n", suspect.Take(10)));
        Assert.True(bad.Count == 0, $"{module}/{fn}: {bad.Count} of {n} divergent ({skipped} skipped):\n" + string.Join("\n", bad.Take(40)));
        Assert.True(n >= min, $"{module}/{fn}: only {n} cases compared ({skipped} skipped)");
        return n;
    }

    static string Safe(object? h)
    {
        if (ReferenceEquals(h, Refused)) return "<refused>";
        try { return Show(Json(h)); } catch { return h?.ToString() ?? "null"; }
    }

    /// <summary>Every fn of the module is either checked by a [Fact] or listed as skipped with a reason.</summary>
    public static void Covers(string module, IEnumerable<string> handled)
    {
        var h = new HashSet<string>(handled);
        var missing = Cases(module).Select(c => ((string)c["fn"]!).Replace("@suspect", "")).Distinct().Where(f => !h.Contains(f)).ToList();
        Assert.True(missing.Count == 0, $"{module}: fn(s) with no test: {string.Join(", ", missing)}");
    }
}
