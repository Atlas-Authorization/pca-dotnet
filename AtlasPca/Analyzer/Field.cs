using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>A numeric interval with open or closed ends (infinite ends allowed).</summary>
public readonly record struct NumInterval(double Lo, bool LoInclusive, double Hi, bool HiInclusive)
{
    public D ToJson() => new() { ["lo"] = Jx.NumOut(Lo), ["loInclusive"] = LoInclusive, ["hi"] = Jx.NumOut(Hi), ["hiInclusive"] = HiInclusive };
}

/// <summary>Per-field probe values and interval arithmetic of the numeric conjunction check.</summary>
public static class Field
{
    public const string FreshString = "\u0000atlas-analyzer::fresh-unmatched\u0000";
    public static readonly NumInterval FullInterval = new(double.NegativeInfinity, false, double.PositiveInfinity, false);

    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");
    internal static bool IsLeaf(object? c) => c is D d && !IsGroup(d) && d.GetValueOrDefault("field") is string;

    static List<double> NumericCellReps(List<double> thresholds)
    {
        var sorted = new List<double>();
        foreach (var t in thresholds) if (double.IsFinite(t) && !sorted.Contains(t)) sorted.Add(t);
        sorted.Sort((a, b) => a.CompareTo(b));
        var o = new List<double>();
        if (sorted.Count == 0) return o;
        o.Add(sorted[0] - 1);
        for (int i = 0; i < sorted.Count; i++)
        {
            o.Add(sorted[i]);
            if (i + 1 < sorted.Count) o.Add((sorted[i] + sorted[i + 1]) / 2);
        }
        o.Add(sorted[^1] + 1);
        return o;
    }

    static string ValueKey(object? x) => x is string s && s == FreshString ? "s:__fresh__" : Jx.Typeof(x) + ":" + JsJson.Stringify(Jx.IsUndef(x) ? null : x);

    /// <summary>fieldProbes: the literals, threshold cells, prefix extensions and one fresh value that distinguish every condition on a field.</summary>
    public static List<object?> FieldProbes(IEnumerable<object?> conditions)
    {
        var literals = new List<object?>(); var thresholds = new List<double>(); var prefixes = new List<string>();
        foreach (var c in conditions)
        {
            if (!IsLeaf(c)) continue;
            var cd = (D)c!;
            if (cd.ContainsKey("ref")) continue;
            var v = cd.TryGetValue("value", out var vv) ? vv : Jx.Undef;
            switch (cd.GetValueOrDefault("op") as string)
            {
                case "eq": case "ne":
                    literals.Add(v);
                    if (Jx.Fin(v) is double f) thresholds.Add(f);
                    break;
                case "in": case "nin":
                    if (v is L l) foreach (var x in l) { literals.Add(x); if (Jx.Fin(x) is double g) thresholds.Add(g); }
                    break;
                case "lt": case "lte": case "gt": case "gte":
                    if (Jx.Fin(v) is double h) thresholds.Add(h);
                    break;
                case "prefix": case "like": case "matches": case "is_a":
                    if (v is string s) { literals.Add(s); if ((string?)cd.GetValueOrDefault("op") == "prefix") prefixes.Add(s); }
                    break;
                case "member_of":
                    if (v is string m) literals.Add(m);
                    else if (v is L ml) foreach (var x in ml) if (x is string xs) literals.Add(xs);
                    break;
            }
        }
        var outl = new List<object?>(); var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(object? x) { if (seen.Add(ValueKey(x))) outl.Add(x); }
        foreach (var l in literals) Add(l);
        foreach (var n in NumericCellReps(thresholds)) Add(Jx.N(n));
        foreach (var p in prefixes) { Add(p); Add(p + "x"); }
        Add(FreshString);
        return outl;
    }

    /// <summary>tightenInterval: narrows an interval by one comparison; a non-finite operand leaves it unchanged.</summary>
    public static NumInterval TightenInterval(NumInterval iv, object? op, object? value)
    {
        if (Jx.Fin(value) is not double v) return iv;
        var n = iv;
        switch (op as string)
        {
            case "eq":
                if (v > n.Lo || (v == n.Lo && !n.LoInclusive)) n = n with { Lo = v, LoInclusive = true };
                if (v < n.Hi || (v == n.Hi && !n.HiInclusive)) n = n with { Hi = v, HiInclusive = true };
                break;
            case "gte": if (v > n.Lo) n = n with { Lo = v, LoInclusive = true }; break;
            case "gt": if (v > n.Lo || (v == n.Lo && n.LoInclusive)) n = n with { Lo = v, LoInclusive = false }; break;
            case "lte": if (v < n.Hi) n = n with { Hi = v, HiInclusive = true }; break;
            case "lt": if (v < n.Hi || (v == n.Hi && n.HiInclusive)) n = n with { Hi = v, HiInclusive = false }; break;
        }
        return n;
    }

    public static bool IntervalEmpty(NumInterval iv)
    {
        if (iv.Lo > iv.Hi) return true;
        if (iv.Lo == iv.Hi) return !(iv.LoInclusive && iv.HiInclusive);
        return false;
    }

    /// <summary>numericConjunctionSatisfiable: false only when some field's comparisons leave an empty interval.</summary>
    public static bool NumericConjunctionSatisfiable(IEnumerable<object?> conditions)
    {
        var byField = new Dictionary<string, NumInterval>(StringComparer.Ordinal);
        foreach (var c in conditions)
        {
            if (!IsLeaf(c)) continue;
            var cd = (D)c!;
            if (cd.ContainsKey("ref")) continue;
            var f = (string)cd["field"]!;
            var iv = byField.TryGetValue(f, out var cur) ? cur : FullInterval;
            byField[f] = TightenInterval(iv, cd.GetValueOrDefault("op"), cd.TryGetValue("value", out var vv) ? vv : Jx.Undef);
        }
        foreach (var iv in byField.Values) if (IntervalEmpty(iv)) return false;
        return true;
    }
}
