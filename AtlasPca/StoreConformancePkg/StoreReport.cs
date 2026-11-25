// Folding the per-test reports of a conformance run: the overall status, the human-readable text and the JSON-safe form.
using System.Globalization;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

/// <summary>One test of a conformance run: <see cref="Status"/> is pass, fail, skip or unresolved.</summary>
public sealed class KitTestReport
{
    public string Test { get; set; } = "";
    /// <summary><c>consume</c> or <c>advance</c>.</summary>
    public string Kind { get; set; } = "";
    public string Status { get; set; } = "";
    public long Ops { get; set; }
    public long Keys { get; set; }
    public long Errors { get; set; }
    public List<KeyResult> Violations { get; set; } = new();
    public long Unresolved { get; set; }
    public string? Note { get; set; }

    public D ToJson(bool nonFiniteAsNull = false)
    {
        var o = new D
        {
            ["test"] = Test, ["kind"] = Kind, ["status"] = Status, ["ops"] = Ops, ["keys"] = Keys, ["errors"] = Errors,
            ["violations"] = Violations.Select(v => (object?)v.ToJson(nonFiniteAsNull)).ToList(), ["unresolved"] = Unresolved,
        };
        if (Note != null) o["note"] = Note;
        return o;
    }

    public static KitTestReport FromJson(object? v)
    {
        var m = (D)v!;
        long N(string k) => (long)HistoryOp.DecodeNumber(m[k]);
        return new KitTestReport
        {
            Test = (string)m["test"]!, Kind = (string)m["kind"]!, Status = (string)m["status"]!, Ops = N("ops"), Keys = N("keys"), Errors = N("errors"),
            Violations = ((L)m["violations"]!).Select(KeyResult.FromJson).ToList(), Unresolved = N("unresolved"), Note = m.GetValueOrDefault("note") as string,
        };
    }
}

/// <summary>A conformance report: the adapter's name, the overall status (pass, fail or unresolved) and every test.</summary>
public sealed class KitReport
{
    public string Adapter { get; set; } = "";
    public string Status { get; set; } = "";
    public List<KitTestReport> Tests { get; set; } = new();

    public D ToJson(bool nonFiniteAsNull = false) => new() { ["adapter"] = Adapter, ["status"] = Status, ["tests"] = Tests.Select(t => (object?)t.ToJson(nonFiniteAsNull)).ToList() };

    public static KitReport FromJson(object? v)
    {
        var m = (D)v!;
        return new KitReport { Adapter = (string)m["adapter"]!, Status = (string)m["status"]!, Tests = ((L)m["tests"]!).Select(KitTestReport.FromJson).ToList() };
    }
}

public static class KitReports
{
    /// <summary>The overall status: <c>fail</c> when any test failed, else <c>unresolved</c> when any is, else <c>pass</c> (a skip never fails a run).</summary>
    public static string Overall(IEnumerable<string> statuses)
    {
        var l = statuses.ToList();
        if (l.Contains("fail")) return "fail";
        if (l.Contains("unresolved")) return "unresolved";
        return "pass";
    }

    public static string Overall(IEnumerable<KitTestReport> tests) => Overall(tests.Select(t => t.Status));

    static string OpName(string kind) => kind == "consume" ? "consumeOnce" : kind == "advance" ? "advance" : kind;

    /// <summary>Human-readable report: one line per test, then each violating key's minimal counterexample (at most <paramref name="maxKeys"/> per test).</summary>
    public static string Format(KitReport r, int maxKeys = 3)
    {
        var o = new List<string> { $"pca-store-conformance: {r.Adapter} -> {r.Status.ToUpperInvariant()}" };
        foreach (var t in r.Tests)
        {
            var name = $"{t.Test}/{OpName(t.Kind)}".PadRight(24);
            var stats = t.Status == "skip" ? "" : $"{t.Ops} ops, {t.Keys} keys, {t.Errors} errors/timeouts";
            var extra = string.Join("; ", new[]
            {
                t.Violations.Count > 0 ? $"{t.Violations.Count} NON-LINEARIZABLE key(s)" : "",
                t.Unresolved != 0 ? $"{t.Unresolved} unresolved key(s) (over the search budget)" : "",
                t.Note ?? "",
            }.Where(s => s.Length > 0));
            o.Add($"  [{t.Status.ToUpperInvariant()}] {name} {string.Join("; ", new[] { stats, extra }.Where(s => s.Length > 0))}");
            foreach (var v in t.Violations.Take(Math.Max(maxKeys, 0)))
            {
                o.Add($"      key {v.Key} ({v.Ops} ops, decided by {v.Method}): {(v.Minimized == true ? "minimal counterexample" : "violating history (not shrunk)")}:");
                foreach (var line in HistoryChecker.FormatOps(v.Counterexample ?? new List<HistoryOp>())) o.Add($"        {line}");
            }
        }
        return string.Join("\n", o);
    }

    /// <summary>JSON-safe form (Infinity -> null), two-space indented, as <c>JSON.stringify(report, replacer, 2)</c>.</summary>
    public static string Json(KitReport r)
    {
        var sb = new StringBuilder();
        Write(sb, r.ToJson(nonFiniteAsNull: true), 0);
        return sb.ToString();
    }

    static void Write(StringBuilder sb, object? v, int depth)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: JsJson.Str(sb, s); break;
            case double d: sb.Append(double.IsFinite(d) ? JsJson.NumberToString(d) : "null"); break;
            case int or long: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case D m:
                if (m.Count == 0) { sb.Append("{}"); break; }
                sb.Append("{\n");
                int i = 0;
                foreach (var (k, x) in m)
                {
                    if (i++ > 0) sb.Append(",\n");
                    sb.Append(' ', 2 * (depth + 1));
                    JsJson.Str(sb, k);
                    sb.Append(": ");
                    Write(sb, x, depth + 1);
                }
                sb.Append('\n').Append(' ', 2 * depth).Append('}');
                break;
            case L l:
                if (l.Count == 0) { sb.Append("[]"); break; }
                sb.Append("[\n");
                for (int j = 0; j < l.Count; j++)
                {
                    if (j > 0) sb.Append(",\n");
                    sb.Append(' ', 2 * (depth + 1));
                    Write(sb, l[j], depth + 1);
                }
                sb.Append('\n').Append(' ', 2 * depth).Append(']');
                break;
            default: throw new InvalidOperationException("StoreReport.Write: unexpected " + v.GetType());
        }
    }
}
