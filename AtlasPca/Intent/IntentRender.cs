// Deterministic plain-language rendering of grants, questions and actions, and the back-translation diff. Every sentence is a fixed
// template over the data (no model anywhere), so the same grant always renders the same text. Anything the templates do not know
// is rendered as an explicit "not understood" line. Policies, caveats and conditions are JSON trees.
using System.Globalization;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentRender
{
    static string JsStr(object? v) => JsX.Str(v);

    /// <summary>The reference's <c>new Date(ms).toISOString()</c>; an invalid time value throws.</summary>
    internal static string IsoString(double ms)
    {
        if (!double.IsFinite(ms) || Math.Abs(ms) > 8.64e15) throw new ArgumentException("Invalid time value");
        long t = (long)ms;
        long days = Math.DivRem(t, 86_400_000L, out long rem);
        if (rem < 0) { rem += 86_400_000L; days--; }
        // civil date from the day count (proleptic Gregorian)
        long z = days + 719468;
        long era = (z >= 0 ? z : z - 146096) / 146097;
        long doe = z - era * 146097;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long d = doy - (153 * mp + 2) / 5 + 1;
        long m = mp < 10 ? mp + 3 : mp - 9;
        if (m <= 2) y++;
        string year = y >= 0 && y <= 9999 ? y.ToString("D4", CultureInfo.InvariantCulture) : (y < 0 ? "-" : "+") + Math.Abs(y).ToString("D6", CultureInfo.InvariantCulture);
        long h = rem / 3_600_000L, mi = rem / 60_000L % 60, s = rem / 1000L % 60, ms3 = rem % 1000;
        return string.Format(CultureInfo.InvariantCulture, "{0}-{1:D2}-{2:D2}T{3:D2}:{4:D2}:{5:D2}.{6:D3}Z", year, m, d, h, mi, s, ms3);
    }

    static string ReplaceFirst(string s, char a, char b)
    {
        int i = s.IndexOf(a);
        return i < 0 ? s : s[..i] + b + s[(i + 1)..];
    }

    /// <summary><c>d.replace(/\.$/, '').replace(/^./, c =&gt; c.toLowerCase())</c>.</summary>
    static string LowerFirst(string d)
    {
        var s = d.EndsWith('.') ? d[..^1] : d;
        if (s.Length == 0) return s;
        char c = s[0];
        if (c is '\n' or '\r' or '\u2028' or '\u2029') return s;
        return char.ToLowerInvariant(c) + s[1..];
    }

    static string StripDot(string d) => d.EndsWith('.') ? d[..^1] : d;

    public static string LabelOf(string path)
    {
        if (path == "action.resource") return "resource";
        var parts = path.Split('.');
        return parts[^1].Replace('_', ' ');
    }

    static string Fmt(object? v)
    {
        if (v is string s) return "\"" + s + "\"";
        if (v is L l) return string.Join(", ", l.Select(Fmt));
        return JsStr(v);
    }

    const string Unreadable = "an unreadable condition (not understood)";

    public static string RenderCondition(object? c)
    {
        if (c is not D m) return Unreadable;
        if (m.ContainsKey("all_of") || m.ContainsKey("any_of") || m.ContainsKey("not"))
        {
            if (m.ContainsKey("all_of")) return "all of: " + Joined(m["all_of"], " and ");
            if (m.ContainsKey("any_of")) return "either " + Joined(m["any_of"], " or ");
            return "it is not the case that " + RenderCondition(m["not"]);
        }
        if (m.GetValueOrDefault("field") is not string field) return Unreadable;
        var lbl = "the " + LabelOf(field);
        var op = m.GetValueOrDefault("op");
        var v = m.ContainsKey("ref") ? "the " + LabelOf(m["ref"] as string ?? throw new InvalidOperationException("path.split is not a function")) : Fmt(m.TryGetValue("value", out var val) ? val : Jx.Undef);
        switch (op as string ?? "\0")
        {
            case "eq": return lbl + " is " + v;
            case "ne": return lbl + " is not " + v;
            case "in": return lbl + " is one of " + v;
            case "nin": return lbl + " is none of " + v;
            case "lt": return lbl + " is less than " + v;
            case "lte": return lbl + " is at most " + v;
            case "gt": return lbl + " is more than " + v;
            case "gte": return lbl + " is at least " + v;
            case "prefix": return lbl + " starts with " + v;
            case "exists": return m.GetValueOrDefault("value") is false ? lbl + " is absent" : lbl + " is present";
            case "like": return lbl + " matches the pattern " + v;
            case "matches": return lbl + " matches the regular expression " + v;
            case "is_a": return lbl + " is of type " + v;
            case "member_of": return lbl + " belongs to " + v;
            default: return lbl + " has an unrecognised test \"" + JsStr(m.TryGetValue("op", out var o2) ? o2 : Jx.Undef) + "\" (not understood)";
        }
    }

    /// <summary><c>(xs ?? []).map(renderCondition).map(s =&gt; "(s)").join(sep)</c>; a non-array throws like <c>.map</c>.</summary>
    static string Joined(object? xs, string sep)
    {
        if (xs == null) return "";
        if (xs is not L l) throw new InvalidOperationException("map is not a function");
        return string.Join(sep, l.Select(x => "(" + RenderCondition(x) + ")"));
    }

    static string RenderResource(object? r)
    {
        if (Jx.IsUndef(r) || r is "*") return "on any resource";
        if (r is not string s) return "on an unreadable resource matcher (not understood)";
        if (s.StartsWith("re:", StringComparison.Ordinal)) return "on resources matching the regular expression \"" + s[3..] + "\"";
        if (s.EndsWith('*')) return "on resources under \"" + s[..^1] + "\"";
        return "only on resource \"" + s + "\"";
    }

    static string OneVerb(string x, Catalog catalog)
    {
        if (x == "*") return "ANY action of any connector";
        var s = catalog.Get(x);
        return s != null ? LowerFirst(s.Description) + " [" + x + ", " + ReplaceFirst(s.Reversibility, '_', '-') + "]" : "\"" + x + "\" [uncatalogued: treated as irreversible]";
    }

    static string RenderVerb(object? v, Catalog catalog) =>
        v is L l ? string.Join("; or ", l.Select(x => OneVerb(JsStr(x), catalog))) : OneVerb(JsStr(v), catalog);

    public static string RenderCaveat(object? c)
    {
        var type = c == null ? Jx.Undef : Jx.Prop(c, "type");
        switch (type as string ?? "\0")
        {
            case "expires": return "The grant expires at " + IsoString(Jx.ToNumber(Jx.Prop(c, "at"))) + ".";
            case "not_before": return "The grant is not valid before " + IsoString(Jx.ToNumber(Jx.Prop(c, "at"))) + ".";
            case "rate": return "At most " + JsStr(Jx.Prop(c, "max")) + " actions in any " + JsStr(Jx.Prop(c, "per_secs")) + " seconds.";
            case "max_blast_radius": return "No action whose blast radius exceeds " + JsStr(Jx.Prop(c, "max")) + " (on a 0–1 scale).";
            case "reversibility_max": return "Nothing more severe than \"" + ReplaceFirst(JsStr(Jx.Prop(c, "class")), '_', '-') + "\" (reversible < rate-limited < irreversible).";
            case "delegation_depth": return "It may be re-delegated at most " + JsStr(Jx.Prop(c, "max")) + " level(s) deep.";
            case "budget_alloc": return "A trust-budget allocation of " + JsStr(Jx.Prop(c, "limit")) + " is carried for sub-delegation.";
            default: return "An unrecognised constraint of type \"" + JsStr(type) + "\" (NOT UNDERSTOOD: do not rely on this grant until it is explained).";
        }
    }

    /// <summary>A grant as numbered plain-language sentences.</summary>
    public static string RenderGrant(object? policy, Catalog? catalog = null)
    {
        catalog ??= Catalog.Default;
        var np = IntentPolicyKit.NormalizePolicy(policy);
        var predicates = (L)np["predicates"]!;
        var caveats = (L)np["caveats"]!;
        if (predicates.Count == 0) return "This grant allows nothing.";
        var lines = new List<string> { "The agent may do the following, and nothing else:" };
        for (int i = 0; i < predicates.Count; i++)
        {
            var p = predicates[i];
            var where = Jx.Prop(p, "where");
            var conds = new List<string>();
            if (!Jx.IsUndef(where) && where != null)
            {
                if (where is not L wl) throw new InvalidOperationException("map is not a function");
                foreach (var c in wl) conds.Add(RenderCondition(c));
            }
            lines.Add((i + 1) + ". " + RenderVerb(Jx.Prop(p, "verb"), catalog) + ", " + RenderResource(Jx.Prop(p, "resource"))
                + (conds.Count == 0 ? "" : ", only when " + string.Join(", and ", conds)) + ".");
        }
        if (caveats.Count > 0)
        {
            lines.Add("Limits that apply to everything above:");
            foreach (var c in caveats) lines.Add("- " + RenderCaveat(c));
        }
        return string.Join("\n", lines);
    }

    // ---- outcome / question rendering ----

    static string NumStr(double d) => JsX.JsNumString(d);

    static string RenderDimCell(Dim d, int i)
    {
        var lbl = LabelOf(d.Path);
        if (d is NumDim n)
        {
            var c = NumCells(n)[i];
            if (c.Lo == c.Hi) return lbl + " exactly " + NumStr(c.Lo);
            return "any " + lbl + " from " + NumStr(c.Lo) + " to " + NumStr(c.Hi) + " (e.g. " + NumStr(i > 0 ? c.Lo : c.Hi) + ")";
        }
        var v = ((CatDim)d).Values[i];
        if (v.Kind == "exact") return lbl + " \"" + v.Value + "\"";
        if (v.Kind == "prefix") return "a " + lbl + " under \"" + v.Value + "\" (not otherwise named)";
        return "a " + lbl + " not named anywhere in the grant or your request";
    }

    public static string RenderQuestion(VerbSpace vs, IReadOnlyList<int> cell, Catalog? catalog = null)
    {
        catalog ??= Catalog.Default;
        var s = catalog.Get(vs.Verb);
        var what = s != null ? StripDot(s.Description) + " [" + vs.Verb + "]" : "perform \"" + vs.Verb + "\"";
        var parts = new List<string>();
        for (int k = 0; k < vs.Dims.Count; k++) parts.Add(RenderDimCell(vs.Dims[k], cell[k]));
        return "Should the agent be allowed to: " + what + (parts.Count == 0 ? "" : ", with " + string.Join(", ", parts)) + "?";
    }

    // ---- back-translation diff ----

    /// <summary>What a rendering asserts about one dimension (numeric: [min, max] of the accepted values; categorical: value labels).</summary>
    public sealed class DimClaim
    {
        public string Path { get; }
        public bool Any { get; }
        public double[]? Range { get; }
        public List<string>? Values { get; }
        internal DimClaim(string path, bool any, double[]? range, List<string>? values) { Path = path; Any = any; Range = range; Values = values; }

        internal bool SameAs(DimClaim o) =>
            Path == o.Path && Any == o.Any && (Range == null ? o.Range == null : o.Range != null && Range.SequenceEqual(o.Range))
            && (Values == null ? o.Values == null : o.Values != null && Values.SequenceEqual(o.Values));

        public D ToJson()
        {
            var m = new D { ["path"] = Path, ["any"] = Any };
            if (Range != null) m["range"] = new L { N(Range[0]), N(Range[1]) };
            if (Values != null) m["values"] = Values.Select(v => (object?)v).ToList();
            return m;
        }
    }

    public sealed class VerbClaim
    {
        public string Verb { get; }
        public bool Allowed { get; }
        public bool BoxShaped { get; }
        public List<DimClaim> Dims { get; }
        internal VerbClaim(string verb, bool allowed, bool boxShaped, List<DimClaim> dims) { Verb = verb; Allowed = allowed; BoxShaped = boxShaped; Dims = dims; }

        public D ToJson() => new() { ["verb"] = Verb, ["allowed"] = Allowed, ["boxShaped"] = BoxShaped, ["dims"] = Dims.Select(d => (object?)d.ToJson()).ToList() };
    }

    /// <summary>What the policy asserts over the space, verb by verb and dimension by dimension.</summary>
    public static List<VerbClaim> ClaimsOf(object? policy, Omega omega)
    {
        var a = IntentPolicyKit.MakeAdmitter(policy);
        var output = new List<VerbClaim>();
        foreach (var vs in omega.Verbs)
        {
            double n = VerbCellCount(vs);
            var acc = new List<int[]>();
            for (double c = 0; c < n; c++)
            {
                var idx = DecodeCell(vs, c);
                if (a.Admits(vs, CellRep(vs, idx))) acc.Add(idx);
            }
            var proj = new List<SortedSet<int>>();
            for (int k = 0; k < vs.Dims.Count; k++) proj.Add(new SortedSet<int>(acc.Select(x => x[k])));
            double boxCount = 1;
            foreach (var s in proj) boxCount *= s.Count;
            var dims = new List<DimClaim>();
            for (int k = 0; k < vs.Dims.Count; k++)
            {
                var d = vs.Dims[k];
                var s = proj[k];
                bool any = s.Count == CellCount(d);
                if (d is NumDim nd)
                {
                    double[]? range = null;
                    if (s.Count > 0)
                    {
                        var cells = NumCells(nd);
                        range = new[] { cells[s.Min].Lo, cells[s.Max].Hi };
                    }
                    dims.Add(new DimClaim(d.Path, any, range, null));
                }
                else
                {
                    var cd = (CatDim)d;
                    dims.Add(new DimClaim(d.Path, any, null, s.Select(i => cd.Values[i].Kind == "prefix" ? cd.Values[i].Value + "*" : cd.Values[i].Value).ToList()));
                }
            }
            output.Add(new VerbClaim(vs.Verb, acc.Count > 0, acc.Count == boxCount, dims));
        }
        return output;
    }

    /// <summary>One difference between two readings, with the sentence shown to the principal.</summary>
    public sealed record ClaimDiff(string Verb, string Kind, string? Path, string Text)
    {
        public D ToJson()
        {
            var m = new D { ["verb"] = Verb, ["kind"] = Kind };
            if (Path != null) m["path"] = Path;
            m["text"] = Text;
            return m;
        }
    }

    static string DimText(DimClaim c)
    {
        if (c.Any) return "any value";
        if (c.Range != null) return NumStr(c.Range[0]) + " to " + NumStr(c.Range[1]);
        return c.Values != null && c.Values.Count > 0 ? string.Join(", ", c.Values) : "nothing";
    }

    sealed record Wording(Func<string, string> Extra, Func<string, string> Missing, Func<string, string> Shape, Func<string, string, string, string, string> Dim);

    static List<ClaimDiff> DiffClaims(List<VerbClaim> g, List<VerbClaim> s, Wording w)
    {
        var output = new List<ClaimDiff>();
        for (int i = 0; i < g.Count; i++)
        {
            var gc = g[i];
            var sc = s[i];
            if (gc.Allowed && !sc.Allowed) { output.Add(new ClaimDiff(gc.Verb, "extra-verb", null, w.Extra(gc.Verb))); continue; }
            if (!gc.Allowed && sc.Allowed) { output.Add(new ClaimDiff(gc.Verb, "missing-verb", null, w.Missing(gc.Verb))); continue; }
            if (!gc.Allowed) continue;
            if (gc.BoxShaped != sc.BoxShaped) output.Add(new ClaimDiff(gc.Verb, "shape", null, w.Shape(gc.Verb)));
            for (int k = 0; k < gc.Dims.Count; k++)
            {
                var gd = gc.Dims[k];
                var sd = sc.Dims[k];
                if (gd.SameAs(sd)) continue;
                var kind = "different";
                if (gd.Range != null && sd.Range != null)
                    kind = gd.Range[0] <= sd.Range[0] && gd.Range[1] >= sd.Range[1] ? "looser" : gd.Range[0] >= sd.Range[0] && gd.Range[1] <= sd.Range[1] ? "tighter" : "different";
                else if (gd.Values != null && sd.Values != null)
                    kind = sd.Values.All(gd.Values.Contains) ? "looser" : gd.Values.All(sd.Values.Contains) ? "tighter" : "different";
                else if (gd.Any && !sd.Any) kind = "looser";
                output.Add(new ClaimDiff(gc.Verb, kind, gd.Path, w.Dim(gc.Verb, gd.Path, DimText(gd), DimText(sd))));
            }
        }
        return output;
    }

    /// <summary>Render the grant and the intent slots into the same claim form over the space and list every difference.</summary>
    public static List<ClaimDiff> BackTranslationDiff(object? grant, object? slots, Omega omega) =>
        DiffClaims(ClaimsOf(grant, omega), ClaimsOf(IntentDerive.SlotsToPolicy(slots), omega), new Wording(
            v => "The grant allows " + v + ", which your request did not mention.",
            v => "Your request mentions " + v + ", but the grant does not allow it.",
            v => "The grant's rule for " + v + " is a combination of cases that your request did not describe.",
            (v, path, a, b) => "For " + v + ", the grant allows " + LabelOf(path) + " " + a + "; your request said " + b + "."));

    /// <summary>The same claim diff between two grants; the kind is from a's point of view (looser = a allows more).</summary>
    public static List<ClaimDiff> ClaimDiffOf(object? a, object? b, Omega omega, string n0 = "the first reading", string n1 = "the second reading") =>
        DiffClaims(ClaimsOf(a, omega), ClaimsOf(b, omega), new Wording(
            v => n0 + " allows " + v + "; " + n1 + " does not.",
            v => n1 + " allows " + v + "; " + n0 + " does not.",
            v => n0 + " and " + n1 + " describe " + v + " with differently shaped rules.",
            (v, path, x, y) => "For " + v + ", " + n0 + " allows " + LabelOf(path) + " " + x + "; " + n1 + " allows " + y + "."));

    /// <summary>A concrete action in plain language; values are printed verbatim, so nothing is hidden (a double or a string; other JSON values print as the reference's String()).</summary>
    public static string RenderAction(VerbSpace vs, IReadOnlyDictionary<string, object?> values, Catalog? catalog = null)
    {
        catalog ??= Catalog.Default;
        var s = catalog.Get(vs.Verb);
        var what = s != null ? StripDot(s.Description) + " [" + vs.Verb + ", " + ReplaceFirst(vs.Reversibility, '_', '-') + "]" : "perform \"" + vs.Verb + "\" [uncatalogued: treated as irreversible]";
        var parts = new List<string>();
        foreach (var k in values.Keys.OrderBy(key => key, StringComparer.Ordinal))
        {
            var v = values[k];
            parts.Add(LabelOf(k) + " " + (v is string str ? "\"" + str + "\"" : JsStr(v is double d ? new Num(NumStr(d)) : v)));
        }
        return "The agent wants to: " + what + (parts.Count == 0 ? "" : ", with " + string.Join(", ", parts)) + ".";
    }
}
