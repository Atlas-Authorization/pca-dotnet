// The deterministic predicate DSL (packages/pca/src/predicates.ts evaluatePredicates): the ONE evaluator the Intent Layer v2
// `layers` check runs each ceiling through (mirrors Predicates.java / Predicates.kt). Pure data, total, fail closed.
using System.Text.RegularExpressions;

namespace AtlasPca;

/// <summary>
/// A predicate is <c>{verb, resource?, where?}</c>: <c>verb</c> a string (<c>"*"</c> = any) or a list of them; <c>resource</c>
/// exact, <c>"*"</c>, a trailing-<c>*</c> prefix or <c>re:&lt;pattern&gt;</c> (full match, <see cref="SafeRegex"/>); <c>where</c> a list
/// of conditions that must all hold. A condition is a leaf <c>{field, op, value | ref, collection?}</c> over a dotted path rooted
/// at <c>action</c>, <c>subject</c> or <c>env</c>, or a grouping <c>all_of</c> / <c>any_of</c> / <c>not</c> evaluated
/// three-valued. Numbers compare by binary64 value, strings by UTF-8 bytes, equality by the canonical JSON text.
/// </summary>
public static class Predicates
{
    public const int MaxPatternSubjectLen = 512;
    public const int MaxLikePatternLen = 512;
    public const int MaxMatchesPatternLen = 200;
    public const int MaxMemberClosureNodes = 10_000;
    public const int MaxReResourceLen = 512;

    /// <summary>Three-valued condition truth.</summary>
    public enum Tri { True, False, Unknown }

    static readonly HashSet<string> Roots = new() { "action", "subject", "env" };
    static readonly HashSet<string> Forbidden = new() { "__proto__", "constructor", "prototype" };
    static readonly Regex Index = new(@"^(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant);

    static bool IsJsObject(object? x) => x is Dictionary<string, object?> || x is List<object?>;

    /// <summary>The resolved value of a dotted path (own members only).</summary>
    public readonly record struct Resolved(bool Found, object? Value);

    /// <summary>Resolve a dotted path into the context. Own members only; an unknown root is not found.</summary>
    public static Resolved ResolvePath(Dictionary<string, object?>? ctx, object? path)
    {
        if (path is not string ps || ps.Length == 0) return default;
        var segs = ps.Split('.');
        if (!Roots.Contains(segs[0])) return default;
        if (ctx == null || !ctx.TryGetValue(segs[0], out var cur)) return default;
        for (int i = 1; i < segs.Length; i++)
        {
            var s = segs[i];
            if (Forbidden.Contains(s) || !IsJsObject(cur)) return default;
            if (cur is List<object?> l)
            {
                if (!Index.IsMatch(s)) return default;
                double idx = double.Parse(s, System.Globalization.CultureInfo.InvariantCulture);
                if (idx >= l.Count) return default;
                cur = l[(int)idx];
            }
            else
            {
                var m = (Dictionary<string, object?>)cur!;
                if (!m.TryGetValue(s, out cur)) return default;
            }
        }
        return new Resolved(true, cur);
    }

    static bool DeepEq(object? a, object? b) => IntentJs.JsonEquals(a, b);

    static int? Ordered(object? a, object? b)
    {
        var x = IntentJs.NumOf(a); var y = IntentJs.NumOf(b);
        if (x is double u && y is double w)
        {
            if (!double.IsFinite(u) || !double.IsFinite(w)) return null;
            return u < w ? -1 : u > w ? 1 : 0;
        }
        if (a is string sa && b is string sb)
        {
            if (Pca.HasLoneSurrogate(sa) || Pca.HasLoneSurrogate(sb)) return null;
            return Math.Sign(IntentJs.CompareUtf8(sa, sb));
        }
        return null;
    }

    const int Lit = 0, One = 1, Star = 2;

    static int[][]? ParseGlob(string glob)
    {
        var output = new List<int[]>();
        for (int i = 0; i < glob.Length; i++)
        {
            char ch = glob[i];
            if (ch == '\\')
            {
                if (i + 1 >= glob.Length) return null;
                output.Add(new[] { Lit, (int)glob[i + 1] });
                i++;
            }
            else if (ch == '*') { if (output.Count == 0 || output[^1][0] != Star) output.Add(new[] { Star, 0 }); }
            else if (ch == '?') output.Add(new[] { One, 0 });
            else output.Add(new[] { Lit, (int)ch });
        }
        return output.ToArray();
    }

    internal static bool? GlobMatch(string glob, string s)
    {
        var toks = ParseGlob(glob);
        if (toks == null) return null;
        int ti = 0, si = 0, starTi = -1, starSi = 0;
        while (si < s.Length)
        {
            var t = ti < toks.Length ? toks[ti] : null;
            if (t != null && t[0] == Star) { starTi = ++ti; starSi = si; }
            else if (t != null && (t[0] == One || s[si] == t[1])) { ti++; si++; }
            else if (starTi >= 0) { ti = starTi; si = ++starSi; }
            else return false;
        }
        while (ti < toks.Length && toks[ti][0] == Star) ti++;
        return ti == toks.Length;
    }

    static bool? TypeTagMatch(object? v, string t)
    {
        if (v is string s) return s == t || s.StartsWith(t + "::", StringComparison.Ordinal);
        if (v is Dictionary<string, object?> m)
        {
            bool decidable = false, matched = false;
            if (m.TryGetValue("type", out var ty) && ty is string tys)
            {
                decidable = true;
                if (tys == t || tys.StartsWith(t + "::", StringComparison.Ordinal)) matched = true;
            }
            if (m.TryGetValue("tags", out var tags) && tags is List<object?> tl)
            {
                decidable = true;
                if (tl.Any(x => x is string xs && xs == t)) matched = true;
            }
            return decidable ? matched : null;
        }
        return null;
    }

    static List<string> NeighboursOf(Dictionary<string, object?> adj, string node)
    {
        var output = new List<string>();
        if (Forbidden.Contains(node) || !adj.TryGetValue(node, out var raw)) return output;
        if (raw is string s) output.Add(s);
        else if (raw is List<object?> l) foreach (var x in l) if (x is string xs) output.Add(xs);
        return output;
    }

    static HashSet<string> MemberClosure(string start, Dictionary<string, object?> adj)
    {
        var seen = new HashSet<string> { start };
        var queue = new Queue<string>();
        queue.Enqueue(start);
        int visited = 0;
        while (queue.Count > 0 && visited < MaxMemberClosureNodes)
        {
            visited++;
            var node = queue.Dequeue();
            foreach (var n in NeighboursOf(adj, node)) if (seen.Add(n)) queue.Enqueue(n);
        }
        return seen;
    }

    static bool ParamsUnavailable(Dictionary<string, object?>? ctx)
    {
        var a = ctx != null && ctx.TryGetValue("action", out var av) ? av : null;
        var p = a is Dictionary<string, object?> am && am.TryGetValue("params", out var pv) ? pv : null;
        return !IsJsObject(p);
    }

    static bool ParamsRooted(string path) => path == "action.params" || path.StartsWith("action.params.", StringComparison.Ordinal);
    static Tri T(bool b) => b ? Tri.True : Tri.False;

    static Tri TriLeaf(Dictionary<string, object?> c, Dictionary<string, object?>? ctx)
    {
        var field = IntentJs.Get(c, "field");
        var op = IntentJs.Get(c, "op");
        if (field is not string f0 || f0.Length == 0) return Tri.Unknown;
        if (op is not string ops) return Tri.Unknown;
        if (ParamsRooted(f0) && ParamsUnavailable(ctx)) return Tri.Unknown;
        var refv = IntentJs.Get(c, "ref");
        if (refv is string rs && ParamsRooted(rs) && ParamsUnavailable(ctx)) return Tri.Unknown;
        var f = ResolvePath(ctx, f0);
        if (ops == "exists") return T(IntentJs.Get(c, "value") is false && c.ContainsKey("value") ? !f.Found : f.Found);
        if (!f.Found) return Tri.Unknown;
        var v = f.Value;
        bool hasRef = c.ContainsKey("ref");

        if (ops == "member_of")
        {
            if (v is not string vs) return Tri.Unknown;
            if (IntentJs.Get(c, "collection") is not string coll || coll.Length == 0) return Tri.Unknown;
            var cr = ResolvePath(ctx, coll);
            if (!cr.Found || cr.Value is not Dictionary<string, object?> adj) return Tri.Unknown;
            object? target;
            if (hasRef)
            {
                var r = ResolvePath(ctx, refv);
                if (!r.Found) return Tri.Unknown;
                target = r.Value;
            }
            else
            {
                if (!c.ContainsKey("value")) return Tri.Unknown;
                target = c["value"];
            }
            var targets = new List<string>();
            if (target is List<object?> tl) { foreach (var x in tl) if (x is string xs) targets.Add(xs); }
            else if (target is string ts) targets.Add(ts);
            if (targets.Count == 0) return Tri.Unknown;
            var reach = MemberClosure(vs, adj);
            return T(targets.Any(reach.Contains));
        }

        object? operand;
        if (hasRef)
        {
            var r = ResolvePath(ctx, refv);
            if (!r.Found) return Tri.Unknown;
            operand = r.Value;
        }
        else
        {
            if (!c.ContainsKey("value")) return Tri.Unknown;
            operand = c["value"];
        }

        switch (ops)
        {
            case "eq": return T(DeepEq(v, operand));
            case "ne": return T(!DeepEq(v, operand));
            case "in":
            case "nin":
                {
                    if (operand is not List<object?> ol) return Tri.Unknown;
                    bool any = ol.Any(x => DeepEq(v, x));
                    return T((ops == "in") == any);
                }
            case "lt": case "lte": case "gt": case "gte":
                {
                    var o = Ordered(v, operand);
                    if (o is not int oi) return Tri.Unknown;
                    return ops switch { "lt" => T(oi < 0), "lte" => T(oi <= 0), "gt" => T(oi > 0), _ => T(oi >= 0) };
                }
            case "prefix":
                if (v is not string pv || operand is not string po) return Tri.Unknown;
                return T(pv.StartsWith(po, StringComparison.Ordinal));
            case "like":
                {
                    if (v is not string sv || operand is not string so) return Tri.Unknown;
                    if (so.Length > MaxLikePatternLen || sv.Length > MaxPatternSubjectLen) return Tri.Unknown;
                    var m = GlobMatch(so, sv);
                    return m is bool mb ? T(mb) : Tri.Unknown;
                }
            case "matches":
                {
                    if (v is not string sv || operand is not string so) return Tri.Unknown;
                    if (so.Length > MaxMatchesPatternLen || sv.Length > MaxPatternSubjectLen) return Tri.Unknown;
                    if (!SafeRegex.IsSafeSource(so)) return Tri.Unknown;
                    if (!SafeRegex.Charge(so, sv.Length)) return Tri.Unknown;
                    var r = SafeRegex.FullMatch(so, sv);
                    return r is bool rb ? T(rb) : Tri.Unknown;
                }
            case "is_a":
                {
                    if (operand is not string to || to.Length == 0) return Tri.Unknown;
                    var t = TypeTagMatch(v, to);
                    return t is bool tb ? T(tb) : Tri.Unknown;
                }
            default:
                return Tri.Unknown;
        }
    }

    /// <summary>Three-valued evaluation of a condition (leaf or grouping). Total.</summary>
    public static Tri EvaluateConditionTri(object? c, Dictionary<string, object?>? ctx) => SafeRegex.WithBudget(() => ConditionInner(c, ctx));

    static Tri ConditionInner(object? c, Dictionary<string, object?>? ctx)
    {
        try
        {
            if (c is not Dictionary<string, object?> m) return Tri.Unknown; // an array is no condition (no string field)
            if (m.ContainsKey("all_of") || m.ContainsKey("any_of") || m.ContainsKey("not"))
            {
                if (m.ContainsKey("all_of"))
                {
                    if (m["all_of"] is not List<object?> xs || xs.Count == 0) return Tri.Unknown;
                    bool sawUnknown = false;
                    foreach (var x in xs)
                    {
                        var t = EvaluateConditionTri(x, ctx);
                        if (t == Tri.False) return Tri.False;
                        if (t == Tri.Unknown) sawUnknown = true;
                    }
                    return sawUnknown ? Tri.Unknown : Tri.True;
                }
                if (m.ContainsKey("any_of"))
                {
                    if (m["any_of"] is not List<object?> xs || xs.Count == 0) return Tri.Unknown;
                    bool sawUnknown = false;
                    foreach (var x in xs)
                    {
                        var t = EvaluateConditionTri(x, ctx);
                        if (t == Tri.True) return Tri.True;
                        if (t == Tri.Unknown) sawUnknown = true;
                    }
                    return sawUnknown ? Tri.Unknown : Tri.False;
                }
                var inner = EvaluateConditionTri(m["not"], ctx);
                return inner == Tri.True ? Tri.False : inner == Tri.False ? Tri.True : Tri.Unknown;
            }
            return TriLeaf(m, ctx);
        }
        catch (Exception) { return Tri.Unknown; }
    }

    /// <summary>One condition: true iff cleanly decided true.</summary>
    public static bool EvaluateCondition(object? c, Dictionary<string, object?>? ctx) => EvaluateConditionTri(c, ctx) == Tri.True;

    static bool VerbMatches(object? p, string verb)
    {
        if (p is string s) return s == "*" || s == verb;
        if (p is List<object?> l) return l.Any(x => x is string xs && (xs == "*" || xs == verb));
        return false;
    }

    static bool ResourceMatches(Dictionary<string, object?> p, string resource)
    {
        if (!p.TryGetValue("resource", out var pattern)) return true;
        if (pattern is not string pat) return false;
        if (pat == "*") return true;
        if (pat.StartsWith("re:", StringComparison.Ordinal))
        {
            var src = pat.Substring(3);
            if (src.Length > 200) return false;
            if (resource.Length > MaxReResourceLen) return false;
            if (!SafeRegex.IsSafeSource(src)) return false;
            if (!SafeRegex.Charge(src, resource.Length)) return false;
            return SafeRegex.FullMatch(src, resource) == true;
        }
        if (pat.EndsWith('*')) return resource.StartsWith(pat[..^1], StringComparison.Ordinal);
        return pat == resource;
    }

    /// <summary>Does a single predicate permit the action?</summary>
    public static bool PredicateMatches(object? p, Dictionary<string, object?>? ctx) => SafeRegex.WithBudget(() => PredicateInner(p, ctx));

    static bool PredicateInner(object? p, Dictionary<string, object?>? ctx)
    {
        try
        {
            if (p is not Dictionary<string, object?> pm) return false; // an array has no verb
            var a = ctx != null && ctx.TryGetValue("action", out var av) ? av as Dictionary<string, object?> : null;
            if (a == null) return false;
            if (IntentJs.Get(a, "verb") is not string verb || IntentJs.Get(a, "resource") is not string resource) return false;
            if (!VerbMatches(IntentJs.Get(pm, "verb"), verb)) return false;
            if (!ResourceMatches(pm, resource)) return false;
            if (pm.TryGetValue("where", out var w))
            {
                if (w is not List<object?> wl) return false;
                foreach (var c in wl) if (!EvaluateCondition(c, ctx)) return false;
            }
            return true;
        }
        catch (Exception) { return false; }
    }

    /// <summary>An action is allowed iff it matches AT LEAST ONE predicate. Default-deny: an empty or non-list set allows nothing.</summary>
    public static bool EvaluatePredicates(object? predicates, Dictionary<string, object?>? ctx) =>
        SafeRegex.WithBudget(() => predicates is List<object?> l && l.Count > 0 && l.Any(p => PredicateMatches(p, ctx)));

    // ---- B6 (0.5): name the limit that was not met (TypeScript firstUnmetLimit / describeCondition / showValue) ----

    static readonly Dictionary<string, string> OpText = new()
    {
        ["eq"] = "==", ["ne"] = "!=", ["lt"] = "<", ["lte"] = "<=", ["gt"] = ">", ["gte"] = ">=", ["in"] = "in", ["nin"] = "not in",
        ["prefix"] = "starts with", ["like"] = "like", ["matches"] = "matches", ["is_a"] = "is a", ["member_of"] = "member of",
    };
    const int MaxShownString = 64, MaxShownItems = 8;

    /// <summary>A scalar operand in a denial reason: only safe integers, booleans, null and plain short strings are spelled out.</summary>
    internal static string ShowValue(object? v, int depth = 0)
    {
        if (v == null) return "null";
        if (v is bool b) return b ? "true" : "false";
        if (IntentJs.IsNumber(v)) return IntentJs.IsSafeInteger(v) ? IntentJs.Lng(v).ToString(System.Globalization.CultureInfo.InvariantCulture) : "<number>";
        if (v is string s)
            return s.Length <= MaxShownString && !s.Any(ch => ch < ' ' || ch == '"' || ch == '\\' || char.IsSurrogate(ch)) ? "\"" + s + "\"" : "\"...\"";
        if (v is List<object?> l && depth == 0) return l.Count <= MaxShownItems ? "[" + string.Join(", ", l.Select(x => ShowValue(x, 1))) + "]" : "[...]";
        return "<value>";
    }

    static bool IsGroup(Dictionary<string, object?> c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    /// <summary>The condition as the limit a reader recognises: <c>amount &lt;= 500</c>, <c>currency in ["usd", "eur"]</c>.</summary>
    internal static string DescribeCondition(object? cond, int depth = 0)
    {
        if (cond is List<object?>) return "<field> <condition>"; // the reference treats an array as a leaf with no field or op
        if (cond is not Dictionary<string, object?> c) return "<condition>";
        if (IsGroup(c))
        {
            if (depth >= 2) return "(...)";
            string Kids(object? xs) => string.Join("; ", ((List<object?>)xs!).Take(MaxShownItems).Select(x => DescribeCondition(x, depth + 1)));
            if (c.TryGetValue("all_of", out var all) && all is List<object?>) return $"all of ({Kids(all)})";
            if (c.TryGetValue("any_of", out var any) && any is List<object?>) return $"any of ({Kids(any)})";
            if (c.TryGetValue("not", out var not)) return $"not ({DescribeCondition(not, depth + 1)})";
            return "<condition>";
        }
        var f = IntentJs.Get(c, "field") is string fs ? fs : "<field>";
        var name = f.StartsWith("action.params.", StringComparison.Ordinal) ? f.Substring("action.params.".Length) : f;
        var op = IntentJs.Get(c, "op") as string;
        if (op == "exists") return IntentJs.Get(c, "value") is false ? name + " absent" : name + " present";
        if (op == null || !OpText.TryGetValue(op, out var text)) return name + " <condition>";
        return $"{name} {text} " + (c.TryGetValue("ref", out var r) ? (r is string rs ? rs : "<ref>") : ShowValue(IntentJs.Get(c, "value")));
    }

    static object? NarrowestUnmet(object? c, Dictionary<string, object?>? ctx, int depth = 0)
    {
        if (depth < 4 && c is Dictionary<string, object?> m && IsGroup(m) && m.TryGetValue("all_of", out var all) && all is List<object?> xs)
            foreach (var x in xs) if (!EvaluateCondition(x, ctx)) return NarrowestUnmet(x, ctx, depth + 1);
        return c;
    }

    /// <summary>When a predicate's verb and resource are in scope but a <c>where</c> limit is not met, the narrowest unmet limit
    /// described; null when no predicate is in scope (the plain "no predicate permits" wording stays).</summary>
    public static string? FirstUnmetLimit(object? predicates, Dictionary<string, object?>? ctx) => SafeRegex.WithBudget<string?>(() =>
    {
        var a = ctx != null && ctx.TryGetValue("action", out var av) ? av as Dictionary<string, object?> : null;
        if (a == null || IntentJs.Get(a, "verb") is not string verb || IntentJs.Get(a, "resource") is not string resource) return null;
        if (predicates is not List<object?> l) return null;
        foreach (var p in l)
        {
            if (p is not Dictionary<string, object?> pm || !VerbMatches(IntentJs.Get(pm, "verb"), verb) || !ResourceMatches(pm, resource)) continue;
            if (IntentJs.Get(pm, "where") is not List<object?> wl) continue;
            foreach (var c in wl) if (!EvaluateCondition(c, ctx)) return DescribeCondition(NarrowestUnmet(c, ctx));
        }
        return null;
    });
}
