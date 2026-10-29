// DECISION OBLIGATIONS: an allow may carry obligations the policy enforcement point must perform; a PEP that cannot perform every one
// turns the allow into a deny (PepObligationGate). `undo_window` {id, window_end}: the action runs under a veto window (undo ledger
// record `id`, open until `window_end`); a PEP that does not run undo windows must not list it as supported. Port of packages/pca/src/obligations.ts; replays
// packages/pca/conformance/obligations-vectors.json. Everything is total. A null list means absent (the empty list).
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record ObligationMerge(bool Ok, IReadOnlyList<object?> Obligations, string? Reason = null);

public sealed record ObligationGate(string Decision, IReadOnlyList<object?> Perform, IReadOnlyList<string> Unsupported, string? Reason = null);

/// <summary>Outcome is "ok" or "escalate"; Overdue indexes the overdue obligations; Status is "obligation_unmet" on escalate.</summary>
public sealed record ObligationOutcome(string Outcome, IReadOnlyList<int> Overdue, string? Status = null);

public static class Obligations
{
    public static readonly string[] Kinds = { "log", "notify", "redact", "watermark", "require_receipt", "undo_window" };
    public const int MaxObligations = 16;
    const int MaxRedactFields = 32;
    static readonly Regex FieldRe = new(@"\A[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}\z", RegexOptions.CultureInvariant);
    static readonly Dictionary<string, string[]> Allowed = new()
    {
        ["log"] = new[] { "sink" }, ["notify"] = new[] { "to" }, ["redact"] = new[] { "fields" }, ["watermark"] = new[] { "id" }, ["require_receipt"] = Array.Empty<string>(),
        ["undo_window"] = new[] { "id", "window_end" },
    };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    static string? ParamsError(string kind, JD p)
    {
        foreach (var k in p.Keys) if (!Allowed[kind].Contains(k)) return $"unknown parameter '{k}' for '{kind}'";
        if (kind == "log" && p.ContainsKey("sink") && !Str(p["sink"], 128)) return "log.sink must be a non-empty string of at most 128 characters";
        if (kind == "notify" && !Str(p.GetValueOrDefault("to"), 256)) return "notify.to is required (a non-empty string of at most 256 characters)";
        if (kind == "watermark" && !Str(p.GetValueOrDefault("id"), 128)) return "watermark.id is required (a non-empty string of at most 128 characters)";
        if (kind == "undo_window" && (!Str(p.GetValueOrDefault("id"), 128) || !Pca.SafeNat(p.GetValueOrDefault("window_end"), out _)))
            return "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)";
        if (kind == "redact")
        {
            if (p.GetValueOrDefault("fields") is not List<object?> f || f.Count == 0 || f.Count > MaxRedactFields || !f.All(x => x is string s && FieldRe.IsMatch(s))) return "redact.fields must be 1..32 dotted field paths";
            if (f.Distinct().Count() != f.Count) return "redact.fields has a duplicate";
        }
        return null;
    }

    /// <summary>Null = well formed.</summary>
    public static string? ObligationError(object? o)
    {
        if (o is not JD m) return "an obligation must be an object";
        foreach (var k in m.Keys) if (k != "kind" && k != "params" && k != "due") return $"unknown member '{k}'";
        if (m.GetValueOrDefault("kind") is not string kind || !Kinds.Contains(kind)) return $"unknown obligation kind '{(m.GetValueOrDefault("kind") is string ks ? ks : "?")}'";
        if (m.ContainsKey("due") && !Pca.SafeNat(m["due"], out _)) return "due must be a non-negative safe integer";
        object? p = m.ContainsKey("params") ? m["params"] : new JD();
        if (p is not JD pm) return "params must be an object";
        return ParamsError(kind, pm);
    }

    /// <summary>Null = a well-formed, duplicate-free list of at most MaxObligations. Null (absent) is the empty list.</summary>
    public static string? ObligationsError(object? list)
    {
        if (list == null) return null;
        if (list is not List<object?> l) return "obligations must be an array";
        if (l.Count > MaxObligations) return $"more than {MaxObligations} obligations";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < l.Count; i++)
        {
            var e = ObligationError(l[i]);
            if (e != null) return $"obligations[{i}]: {e}";
            string key;
            try { key = ObligationKey(l[i]); } catch (Exception) { return $"obligations[{i}]: not canonicalizable"; }
            if (!seen.Add(key)) return $"obligations[{i}] duplicates an earlier obligation";
        }
        return null;
    }

    /// <summary>The canonical identity of an obligation (kind, parameters, due): equal keys are the same obligation. May throw on out-of-profile text.</summary>
    public static string ObligationKey(object? o)
    {
        var m = (JD)o!;
        var k = new JD { ["kind"] = m["kind"], ["params"] = m.GetValueOrDefault("params") ?? new JD() };
        if (m.ContainsKey("due")) k["due"] = m["due"];
        return Pca.Canonicalize(k);
    }

    /// <summary>The union of obligation lists, deduplicated by ObligationKey and sorted by key in UTF-8 byte order. Any malformed input is a refusal.</summary>
    public static ObligationMerge Merge(IReadOnlyList<object?> lists)
    {
        try
        {
            var by = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var l in lists)
            {
                var e = ObligationsError(l);
                if (e != null) return new(false, Array.Empty<object?>(), e);
                if (l is List<object?> items) foreach (var o in items) by[ObligationKey(o)] = o;
            }
            if (by.Count > MaxObligations) return new(false, Array.Empty<object?>(), $"more than {MaxObligations} obligations after merging");
            var keys = by.Keys.ToList();
            keys.Sort(IntentJs.CompareUtf8);
            return new(true, keys.Select(k => by[k]).ToList());
        }
        catch (Exception) { return new(false, Array.Empty<object?>(), "evaluation error (fail closed)"); }
    }

    /// <summary>The PEP rule. supported is the set of kinds this PEP performs. An allow (or an answered escalate) with any obligation outside it is a deny, as is a malformed list or supported set. A deny and an unanswered escalate pass through with nothing to perform.</summary>
    public static ObligationGate PepObligationGate(string decision, bool answered, object? obligations, object? supported)
    {
        var none = Array.Empty<object?>(); var noneS = Array.Empty<string>();
        try
        {
            var eff = PcaDecision.PepDecision(decision, answered);
            if (eff != "allow") return new(eff == "escalate" ? "escalate" : "deny", none, noneS);
            var e = ObligationsError(obligations);
            if (e != null) return new("deny", none, noneS, $"malformed obligations: {e}");
            if (supported is not List<object?> sup || !sup.All(s => s is string)) return new("deny", none, noneS, "the supported obligation kinds are malformed");
            var list = obligations as List<object?> ?? new List<object?>();
            var missing = list.Select(o => (string)((JD)o!)["kind"]!).Where(k => !sup.Contains(k)).Distinct().ToList();
            missing.Sort(IntentJs.CompareUtf8);
            if (missing.Count > 0) return new("deny", none, missing, $"the enforcement point does not support obligation(s) {string.Join(", ", missing)}");
            return new("allow", list, noneS);
        }
        catch (Exception) { return new("deny", none, noneS, "evaluation error (fail closed)"); }
    }

    /// <summary>After the action: which obligations are overdue (due &lt;= now, not in fulfilled)? A malformed input is overdue-everything.</summary>
    public static ObligationOutcome Outcome(object? obligations, object? fulfilled, object? now)
    {
        try
        {
            var list = obligations as List<object?> ?? new List<object?>();
            var bad = ObligationsError(obligations) != null || fulfilled is not List<object?> f || !f.All(i => Pca.SafeNat(i, out _)) || !Pca.SafeNat(now, out _);
            if (bad) return new("escalate", Enumerable.Range(0, list.Count).ToList(), "obligation_unmet");
            Pca.SafeNat(now, out var n);
            var done = ((List<object?>)fulfilled!).Select(i => { Pca.SafeNat(i, out var v); return v; }).ToHashSet();
            var overdue = new List<int>();
            for (var i = 0; i < list.Count; i++)
            {
                var m = (JD)list[i]!;
                if (m.ContainsKey("due") && Pca.SafeNat(m["due"], out var due) && due <= n && !done.Contains(i)) overdue.Add(i);
            }
            return overdue.Count > 0 ? new("escalate", overdue, "obligation_unmet") : new("ok", Array.Empty<int>());
        }
        catch (Exception) { return new("escalate", Array.Empty<int>(), "obligation_unmet"); }
    }
}
