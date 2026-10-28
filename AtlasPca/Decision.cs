// Ternary decision, tighten-only model rule (rule 21) and units check (rule 20): a port of packages/pca/src/decision.ts and
// envelope-rules.ts (the TypeScript is authoritative; same reason strings). deny < escalate < allow; Meet (the minimum) is
// the only combinator, so escalate never becomes allow. Every function is total; anything malformed fails closed.
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The outcome of rule 21 (<see cref="PcaDecision.DecideTighten"/>).</summary>
public sealed record TightenResult(string Outcome, bool Legacy, IReadOnlyList<string> Offending, string? Reason);

public static class PcaDecision
{
    public const string Deny = "deny", Escalate = "escalate", Allow = "allow";
    public const int MaxTightenRules = 64;

    static int Rank(string? d) => d switch { Deny => 0, Escalate => 1, Allow => 2, _ => -1 };

    /// <summary>The lower of two decisions; an unknown value is deny.</summary>
    public static string Meet(string? a, string? b)
    {
        int x = Rank(a), y = Rank(b);
        if (x < 0 || y < 0) return Deny;
        return x <= y ? a! : b!;
    }

    /// <summary>The highest decision a model signal permits (anything but ok / escalate is deny).</summary>
    public static string SignalCeiling(object? s) => s is "ok" ? Allow : s is "escalate" ? Escalate : Deny;

    /// <summary>G-T9: a model can only move a decision down.</summary>
    public static string Tighten(string? basis, object? signal) => Meet(basis, SignalCeiling(signal));

    /// <summary>An escalate with a verified answer is allow; an answer never upgrades deny; any other string is returned as is (the reference).</summary>
    public static string PepDecision(string? d, bool answered) => d == Escalate && answered ? Allow : d!;

    /// <summary>A failing check is escalate-class iff its reason (after <c>&lt;check&gt;: </c>) starts with one of these.</summary>
    public static readonly string[] EscalateReasonPrefixes = { "intent_required:", "escalate:" };

    /// <summary>The ternary decision of a verdict <c>{allow, checks, reasons}</c> (the wire shape of decision-vectors.json).</summary>
    public static string DecisionOf(object? verdict)
    {
        try
        {
            if (verdict is not JD v) return Deny;
            if (IntentJs.Get(v, "allow") is true) return Allow;
            if (IntentJs.Get(v, "checks") is not JD checks) return Deny;
            var reasons = (IntentJs.Get(v, "reasons") as JL ?? new JL()).OfType<string>().ToList();
            return Of(checks.Where(kv => kv.Value is "fail").Select(kv => kv.Key), reasons);
        }
        catch (Exception) { return Deny; }
    }

    /// <summary>The ternary decision of a non-allowed verdict from its failing check names and its reasons.</summary>
    public static string Of(IEnumerable<string> failingChecks, IReadOnlyList<string> reasons)
    {
        int failing = 0;
        foreach (var name in failingChecks)
        {
            failing++;
            var head = name + ": ";
            var own = reasons.Where(r => r.StartsWith(head, StringComparison.Ordinal)).ToList();
            if (own.Count == 0) return Deny;
            if (!own.All(r => EscalateReasonPrefixes.Any(p => r.Substring(head.Length).StartsWith(p, StringComparison.Ordinal)))) return Deny;
        }
        return failing > 0 ? Escalate : Deny;
    }

    // ---------------------------------------------------------------------------------------- envelope rules

    static readonly Regex NameRe = new(@"^[a-z][a-z0-9_]{0,63}\z", RegexOptions.CultureInvariant);
    static readonly Regex ParamPathRe = new(@"^action\.params\.[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);

    static string? ClosedMembers(JD o, string[] required, string[] optional, string where) => IntentArtifacts.ClosedMembers(o, required, optional, where);

    /// <summary>Null = well-formed. A closed list of <c>{id, when, signal}</c> (<c>reason</c> optional); ids distinct. A JSON
    /// <c>null</c> is NOT "absent": only a missing member is (callers pass <paramref name="present"/>).</summary>
    public static string? TightenListError(object? t, bool present = true)
    {
        if (!present) return null;
        if (t is not JL arr) return "tighten must be an array";
        if (arr.Count > MaxTightenRules) return $"tighten has more than {MaxTightenRules} rules";
        var ids = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < arr.Count; i++)
        {
            if (arr[i] is not JD r) return $"tighten[{i}] must be an object";
            var e = ClosedMembers(r, new[] { "id", "when", "signal" }, new[] { "reason" }, $"tighten[{i}]");
            if (e != null) return e;
            if (r["id"] is not string id || !NameRe.IsMatch(id)) return $"tighten[{i}].id must match ^[a-z][a-z0-9_]{{0,63}}$";
            if (!ids.Add(id)) return $"tighten[{i}].id '{id}' is a duplicate";
            if (r["when"] is not JD) return $"tighten[{i}].when must be a condition object";
            if (r["signal"] is not ("escalate" or "deny")) return $"tighten[{i}].signal must be 'escalate' or 'deny'";
            if (r.TryGetValue("reason", out var rs) && (rs is not string s || s.Length > 256)) return $"tighten[{i}].reason must be a string of at most 256 characters";
        }
        return null;
    }

    /// <summary>Null = well-formed policy unit tags <c>{ 'action.params.&lt;name&gt;': {kind, currency?, exponent?} }</c>.</summary>
    public static string? UnitTagsError(object? u)
    {
        if (u is not JD m) return "units must be an object";
        if (m.Count > 64) return "units has more than 64 entries";
        foreach (var k in IntentJs.JsKeys(m.Keys))
        {
            var x = m[k];
            if (!ParamPathRe.IsMatch(k)) return $"units key '{k}' must be an action.params.<name> path";
            if (x is not JD t) return $"units['{k}'] must be an object";
            var e = ClosedMembers(t, new[] { "kind" }, new[] { "currency", "exponent" }, $"units['{k}']");
            if (e != null) return e;
            if (t["kind"] is not string kind || kind.Length == 0 || kind.Length > 64) return $"units['{k}'].kind must be a string of 1..64 characters";
            if (t.TryGetValue("currency", out var c) && (c is not string cs || cs.Length == 0 || cs.Length > 16)) return $"units['{k}'].currency must be a string of 1..16 characters";
            if (t.TryGetValue("exponent", out var ex) && !(IntentJs.IsInt(ex) && IntentJs.NumOf(ex)!.Value is >= 0 and <= 18)) return $"units['{k}'].exponent must be an integer in [0, 18]";
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------- rule 21

    public static bool IsModelDerivedPath(object? path, IReadOnlyList<string>? singleSource = null)
    {
        singleSource ??= Array.Empty<string>();
        if (path is not string p) return false;
        var seg = p.Split('.');
        if (seg[0] != "env" || seg.Length < 2) return false;
        if (seg[1] is "class" or "prov" or "judge" or "detect") return true;
        if (seg[1] == "world") return seg.Length == 2 ? singleSource.Count > 0 : singleSource.Contains(seg[2]);
        return false;
    }

    static void CollectPaths(object? c, HashSet<string> o, int depth)
    {
        if (depth > 64 || c is not JD m) return;
        foreach (var k in new[] { "all_of", "any_of" })
            if (m.TryGetValue(k, out var xs) && xs is JL l) foreach (var x in l) CollectPaths(x, o, depth + 1);
        if (m.TryGetValue("not", out var n)) CollectPaths(n, o, depth + 1);
        foreach (var k in new[] { "field", "ref", "collection" })
            if (m.TryGetValue(k, out var s) && s is string str) o.Add(str);
    }

    static void CollectPredicatePaths(IEnumerable<object?> lists, Func<object?, bool>? inScope, HashSet<string> o)
    {
        foreach (var list in lists)
        {
            if (list is not JL arr) continue;
            foreach (var p in arr)
            {
                if (inScope != null && !inScope(p)) continue;
                if (IntentJs.Get(p, "where") is JL w) foreach (var c in w) CollectPaths(c, o, 0);
            }
        }
    }

    static List<string> SortedUtf8(IEnumerable<string> xs) => IntentJs.SortedUtf8(xs);

    /// <summary>Every model-derived env path a list of predicate lists reads, UTF-8 sorted and de-duplicated.</summary>
    public static List<string> ModelPathsRead(IEnumerable<object?> predicateLists, IReadOnlyList<string>? singleSource = null)
    {
        var found = new HashSet<string>(StringComparer.Ordinal);
        CollectPredicatePaths(predicateLists, null, found);
        return SortedUtf8(found.Where(p => IsModelDerivedPath(p, singleSource)));
    }

    static TightenResult DenyT(string why, IReadOnlyList<string>? off = null) => new(Deny, false, off ?? Array.Empty<string>(), why);

    /// <summary>Rule 21 over <c>{predicates, tighten, polarity, single_source, context}</c>. Total.</summary>
    public static TightenResult DecideTighten(JD input)
    {
        try
        {
            var single = (IntentJs.Get(input, "single_source") as JL ?? new JL()).OfType<string>().ToList();
            object? pol = null;
            if (input.TryGetValue("polarity", out pol) && pol is not "legacy") return DenyT("model_polarity must be 'legacy' when present");
            var tightenPresent = input.ContainsKey("tighten");
            var le = TightenListError(IntentJs.Get(input, "tighten"), tightenPresent);
            if (le != null) return DenyT("malformed tighten list: " + le);
            var offending = ModelPathsRead(IntentJs.Get(input, "predicates") as JL ?? new JL(), single);
            bool legacy = pol is "legacy" && offending.Count > 0;
            if (offending.Count > 0 && !legacy)
                return DenyT($"a grant's where reads model-derived path(s) {string.Join(", ", offending)}: a model may only tighten (move them into tighten[]) (rule 21)", offending);
            string outcome = "ok";
            string? reason = null;
            void Lower(string s, string why)
            {
                if (Rank(SignalCeiling(s)) < Rank(SignalCeiling(outcome))) { outcome = s; reason = why; }
            }
            var ctx = IntentJs.Get(input, "context") as JD ?? new JD();
            foreach (var x in tightenPresent ? (JL)input["tighten"]! : new JL())
            {
                var r = (JD)x!;
                var t = Predicates.EvaluateConditionTri(r["when"], ctx);
                var id = (string)r["id"]!;
                if (t == Predicates.Tri.True)
                {
                    var sig = (string)r["signal"]!;
                    var extra = r.TryGetValue("reason", out var rs) ? $" ({(string)rs!})" : "";
                    Lower(sig, $"{(sig == "deny" ? "denied by" : "escalate: asked by")} tighten rule '{id}'{extra}");
                }
                else if (t == Predicates.Tri.Unknown) Lower("escalate", $"escalate: rule '{id}' could not be decided (a value it reads is missing or ill-typed)");
            }
            return new TightenResult(outcome, legacy, offending, reason);
        }
        catch (Exception e) { return DenyT("evaluation error (fail closed): " + e.Message); }
    }

    // ---------------------------------------------------------------------------------------- rule 20

    /// <summary>JavaScript <c>String(v)</c> of a JSON value (numbers print as JavaScript prints them).</summary>
    internal static string JsValueString(object? v) => v switch
    {
        null => "null",
        string s => s,
        bool b => b ? "true" : "false",
        JL l => string.Join(",", l.Select(x => x == null ? "" : JsValueString(x))),
        JD => "[object Object]",
        _ => IntentJs.NumOf(v) is double d ? (double.IsFinite(d) ? JsCanon.NumberString(d) : d.ToString(System.Globalization.CultureInfo.InvariantCulture)) : v.ToString() ?? "",
    };

    static string TagText(JD? t)
    {
        if (t == null) return "no unit";
        var sb = new StringBuilder(t.TryGetValue("kind", out var k) && k != null ? JsValueString(k) : "?");
        if (t.TryGetValue("currency", out var c)) sb.Append('/').Append(JsValueString(c));
        if (t.TryGetValue("exponent", out var e)) sb.Append("/e").Append(JsValueString(e));
        return sb.ToString();
    }

    /// <summary>JavaScript <c>===</c> on two JSON scalars (an object or array equals nothing but itself, which a parsed tree never shares).</summary>
    static bool StrictEq(object? a, object? b)
    {
        if (a is string x) return b is string y && x == y;
        if (a is bool p) return b is bool q && p == q;
        if (a == null) return b == null;
        if (IntentJs.NumOf(a) is double da) return IntentJs.NumOf(b) is double db && da == db;
        return false;
    }

    static bool SameTag(JD a, JD b)
    {
        foreach (var k in new[] { "kind", "currency", "exponent" })
        {
            if (a.ContainsKey(k) != b.ContainsKey(k)) return false;
            if (a.ContainsKey(k) && !StrictEq(a[k], b[k])) return false;
        }
        return true;
    }

    static bool VerbInScope(object? p, string verb)
    {
        var v = IntentJs.Get(p, "verb");
        return v is "*" || (v is string s && s == verb) || (v is JL l && l.Any(x => x is string xs && xs == verb));
    }

    /// <summary>Rule 20: the policy's unit tags must equal the unit the action schema declares for each parameter. Total.</summary>
    public static (bool Ok, string? Reason) DecideUnits(JD input)
    {
        static (bool, string?) Fail(string m) => (false, m);
        try
        {
            var te = UnitTagsError(IntentJs.Get(input, "units"));
            if (te != null) return Fail(te);
            var tags = (JD)input["units"]!;
            if (IntentJs.Get(input, "verb") is not string verb || verb.Length == 0) return Fail("the verb is missing");
            object? sUnitsObj = input.ContainsKey("schema_units") ? input["schema_units"] : new JD();
            if (sUnitsObj is not JD sUnits) return Fail("the schema units table must be an object");
            if (IntentJs.Get(input, "verb_params") is not JD prm) return Fail($"the schema does not declare verb '{verb}'");
            (bool Has, JD? Tag) Declared(string path)
            {
                if (!prm.TryGetValue(path, out var dv) || dv is not JD d) return (false, null);
                JD? tag = d.TryGetValue("unit", out var id) && id is string ids && sUnits.TryGetValue(ids, out var tv) ? tv as JD : null;
                return (true, tag);
            }
            foreach (var path in tags.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                var d = Declared(path);
                if (!d.Has) continue;
                if (d.Tag == null || !SameTag(d.Tag, (JD)tags[path]!))
                    return Fail($"'{path}' is declared as {TagText(d.Tag)} by the action schema but the policy term is tagged {TagText((JD)tags[path]!)} (unit confusion)");
            }
            var read = new HashSet<string>(StringComparer.Ordinal);
            CollectPredicatePaths(IntentJs.Get(input, "predicates") as JL ?? new JL(), p => VerbInScope(p, verb), read);
            foreach (var path in read.OrderBy(k => k, StringComparer.Ordinal))
            {
                if (!ParamPathRe.IsMatch(path)) continue;
                var d = Declared(path);
                if (d.Has && d.Tag != null && !tags.ContainsKey(path)) return Fail($"a policy term reads '{path}' ({TagText(d.Tag)}) without a unit tag");
            }
            return (true, null);
        }
        catch (Exception e) { return Fail("evaluation error (fail closed): " + e.Message); }
    }

    /// <summary>One reported intent-v2 check, as <see cref="FoldV2Reasons"/> reads it.</summary>
    public readonly record struct V2CheckResult(string Name, bool Ok, string? Reason);

    /// <summary>The ordered reason list of a verdict (decision.ts foldV2Reasons): <paramref name="baseReasons"/> (the core's own), then one
    /// <c>&lt;check&gt;: &lt;reason&gt;</c> for EVERY failing intent-v2 check not already listed, in pipeline order. A failing check with no
    /// reason adds nothing (<see cref="DecisionOf(object?)"/> then reads it as a hard failure). The core keeps only its first failure, so
    /// without this fold a multi-check escalation would look like a deny.</summary>
    public static List<string> FoldV2Reasons(IEnumerable<string> baseReasons, IEnumerable<V2CheckResult> v2)
    {
        var o = baseReasons.ToList();
        foreach (var c in v2)
        {
            if (c.Ok || c.Reason == null) continue;
            var r = c.Name + ": " + c.Reason;
            if (!o.Contains(r)) o.Add(r);
        }
        return o;
    }
}
