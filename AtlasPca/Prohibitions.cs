using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The trigger (<c>when</c>) of a prohibition or a veto clause, in veto polarity: anything that cannot be decided counts as MATCHED (a malformed trigger, an unsafe
/// regex, an oversized regex subject, an unknown op, a missing field or operand), because a veto that cannot be evaluated must still apply. Total: it never throws.</summary>
public static partial class Prohibitions
{
    /// <summary>The longest action resource a <c>re:</c> trigger is matched against; a longer one makes the trigger match (the veto applies).</summary>
    public const int MaxReResourceLen = 512;
    const int MaxConditionDepth = 32;

    static string[] Ops => new[] { "eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of" };

    /// <summary>JavaScript <c>String(x)</c> for the values a malformed op can be.</summary>
    internal static string JsString(object? x) => x switch
    {
        null => "null",
        string s => s,
        bool b => b ? "true" : "false",
        JD => "[object Object]",
        JL l => string.Join(",", l.Select(e => e == null ? "" : JsString(e))),
        _ => IntentJs.NumOf(x) is double d ? JsCanon.NumberString(d) : x.ToString() ?? "",
    };

    /// <summary>JavaScript <c>String(m.k)</c>: a missing member prints <c>undefined</c>, a null one <c>null</c>.</summary>
    internal static string JsMember(JD m, string k) => m.TryGetValue(k, out var v) ? JsString(v) : "undefined";

    static string? ValidateCondition(object? c, int depth = 0)
    {
        if (c is not JD m) return "condition not an object";
        if (depth > MaxConditionDepth) return "condition nesting too deep";
        if (m.ContainsKey("all_of") || m.ContainsKey("any_of") || m.ContainsKey("not"))
        {
            if (m.ContainsKey("not")) return ValidateCondition(m["not"], depth + 1);
            var key = m.ContainsKey("all_of") ? "all_of" : "any_of";
            if (m[key] is not JL arr || arr.Count == 0) return $"condition.{key} must be a non-empty array";
            foreach (var child in arr)
            {
                var e = ValidateCondition(child, depth + 1);
                if (e != null) return e;
            }
            return null;
        }
        if (m.GetValueOrDefault("field") is not string { Length: > 0 }) return "condition.field missing";
        if (m.GetValueOrDefault("op") is not string op || !Ops.Contains(op)) return $"unknown condition op {JsMember(m, "op")}";
        if (m.ContainsKey("ref") && m["ref"] is not string { Length: > 0 }) return "bad condition.ref";
        if (op == "member_of" && m.ContainsKey("collection") && m["collection"] is not string { Length: > 0 }) return "bad condition.collection";
        return null;
    }

    /// <summary>Null when <paramref name="w"/> is a well-formed trigger, else why not (prefixed with <paramref name="label"/>).</summary>
    public static string? ValidateWhen(object? w, string label)
    {
        if (w is not JD m) return $"{label}: not an object";
        var v = m.GetValueOrDefault("verb");
        var verbOk = v is string { Length: > 0 } || (v is JL vl && vl.Count > 0 && vl.All(x => x is string { Length: > 0 }));
        if (!verbOk) return $"{label}: bad verb";
        if (m.ContainsKey("resource"))
        {
            if (m["resource"] is not string r) return $"{label}: bad resource";
            if (r.StartsWith("re:", StringComparison.Ordinal))
            {
                var src = r[3..];
                if (src.Length > 200 || !SafeRegex.IsSafeSource(src)) return $"{label}: unsafe regex resource";
            }
        }
        if (m.ContainsKey("where"))
        {
            if (m["where"] is not JL where) return $"{label}: where not an array";
            foreach (var c in where)
            {
                var e = ValidateCondition(c);
                if (e != null) return $"{label}: {e}";
            }
        }
        return null;
    }

    /// <summary>Does the trigger match? verb and resource as the permission DSL; the <c>where</c> conditions conservatively (only a provably false one clears the match).</summary>
    public static bool WhenMatches(object? w, Dictionary<string, object?>? ctx)
    {
        try
        {
            if (ValidateWhen(w, "when") != null) return true;
            var m = (JD)w!;
            var a = ctx != null && ctx.TryGetValue("action", out var av) ? av as JD : null;
            if (a == null || a.GetValueOrDefault("verb") is not string || a.GetValueOrDefault("resource") is not string resource) return true;
            var oversized = m.GetValueOrDefault("resource") is string r && r.StartsWith("re:", StringComparison.Ordinal) && resource.Length > MaxReResourceLen;
            // an evaluation REFUSED by the document budget is "could not decide", never "no match": a veto must apply
            var refused0 = SafeRegex.RefusalCount;
            var vr = new JD { ["verb"] = m["verb"] };
            if (!oversized && m.ContainsKey("resource")) vr["resource"] = m["resource"];
            if (!Predicates.PredicateMatches(vr, ctx) && SafeRegex.RefusalCount == refused0) return false;
            if (m.GetValueOrDefault("where") is JL where)
                foreach (var c in where) if (Predicates.EvaluateConditionTri(c, ctx) == Predicates.Tri.False) return false;
            return true;
        }
        catch (Exception) { return true; }
    }

    /// <summary>The AFFIRMATIVE match (plain permission-DSL semantics: an unresolvable condition is not a match).</summary>
    public static bool WhenAffirmative(object? w, Dictionary<string, object?>? ctx)
    {
        try { return ValidateWhen(w, "when") == null && Predicates.PredicateMatches(w, ctx); }
        catch (Exception) { return false; }
    }
}
