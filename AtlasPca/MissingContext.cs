// TYPED MISSING CONTEXT and the STORED-WINS merge: when a permit condition cannot be decided because a value is absent, the decision
// names what is missing and who may supply it (escalate), or denies when only the agent could say it. Request-supplied context never
// replaces a value bound by the grant or chain. Port of packages/pca/src/missing-context.ts; replays
// packages/pca/conformance/missing-context-vectors.json. Everything is total: any failure is a deny.
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public sealed record MissingItem(string Path, string Supplier);

public sealed record BoundContext(JD Context, List<string> Conflicts, List<string> Dropped);

public sealed record TypedDecision(string Decision, string? Reason, List<MissingItem> Missing);

public static class MissingContext
{
    public static readonly string[] Suppliers = { "principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted" };
    static readonly HashSet<string> Forbidden = new() { "__proto__", "constructor", "prototype" };
    static readonly Regex SupplierPath = new(@"\A(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*\z", RegexOptions.CultureInvariant);

    /// <summary>The longest table key equal to path or a prefix of it at a segment boundary; none is principal.</summary>
    public static string SupplierOf(string path, JD table)
    {
        string? best = null;
        foreach (var k in table.Keys) if ((path == k || path.StartsWith(k + ".", StringComparison.Ordinal)) && (best == null || k.Length > best.Length)) best = k;
        return best == null ? "principal" : (string)table[best]!;
    }

    /// <summary>Null = a well-formed table.</summary>
    public static string? SupplierTableError(object? t)
    {
        if (t is not JD m) return "the supplier table must be an object";
        foreach (var (k, v) in m)
        {
            if (!SupplierPath.IsMatch(k) || k.Split('.').Any(Forbidden.Contains)) return $"bad supplier path '{k}'";
            if (v is not string s || !Suppliers.Contains(s)) return $"bad supplier for '{k}'";
        }
        return null;
    }

    static object? Copy(object? v) => v switch
    {
        JD m => m.ToDictionary(p => p.Key, p => Copy(p.Value)),
        JL l => l.Select(Copy).ToList(),
        _ => v,
    };

    /// <summary>Flatten a plain-object tree into dotted leaf paths (sorted keys). Arrays and non-objects are leaves.</summary>
    static void Leaves(object? v, string prefix, SortedDictionary<string, object?> output, int depth = 0)
    {
        if (depth > 16) { output[prefix] = v; return; }
        if (v is JD m && m.Count > 0)
        {
            foreach (var k in m.Keys) if (!Forbidden.Contains(k)) Leaves(m[k], $"{prefix}.{k}", output, depth + 1);
        }
        else output[prefix] = v;
    }

    static void SetPath(JD root, string[] segs, object? value)
    {
        var cur = root;
        for (int i = 0; i < segs.Length - 1; i++)
        {
            if (!(cur.TryGetValue(segs[i], out var next) && next is JD)) cur[segs[i]] = next = new JD();
            cur = (JD)next!;
        }
        cur[segs[^1]] = value;
    }

    static bool Same(object? a, object? b) => Pca.HashCanonical(new JD { ["v"] = a }) == Pca.HashCanonical(new JD { ["v"] = b });

    /// <summary>Merge supplied into bound. Bound wins. May throw on a malformed bound context (callers fail closed).</summary>
    public static BoundContext BindContext(JD bound, object? supplied, JD? table = null)
    {
        table ??= new JD();
        var ctx = (JD)Copy(bound)!;
        var conflicts = new List<string>(); var dropped = new List<string>();
        if (supplied is not JD sup) return new(ctx, conflicts, dropped);
        var flat = new SortedDictionary<string, object?>(StringComparer.Ordinal);
        if (sup.GetValueOrDefault("action") is JD act && act.GetValueOrDefault("params") is JD ap) Leaves(ap, "action.params", flat);
        if (sup.GetValueOrDefault("subject") is JD subj) Leaves(subj, "subject", flat);
        if (sup.GetValueOrDefault("env") is JD env) Leaves(env, "env", flat);
        foreach (var (path, value) in flat)
        {
            if (SupplierOf(path, table) == "agent_declared_untrusted") { dropped.Add(path); continue; }
            var r = Predicates.ResolvePath(ctx, path);
            if (r.Found)
            {
                if (!Same(r.Value, value)) conflicts.Add(path);
                continue;
            }
            var segs = path.Split('.');
            var blocked = false;
            for (int i = 2; i < segs.Length; i++)
            {
                var r2 = Predicates.ResolvePath(ctx, string.Join(".", segs.Take(i)));
                if (r2.Found && r2.Value is not JD) blocked = true;
            }
            if (blocked) { conflicts.Add(path); continue; }
            if (path.StartsWith("action.params", StringComparison.Ordinal))
            {
                var a = ctx.GetValueOrDefault("action") ?? new JD { ["verb"] = "", ["resource"] = "" };
                if (a is not JD am) throw new InvalidOperationException("action is not an object");
                if (am.GetValueOrDefault("params") is not JD) am["params"] = new JD();
                ctx["action"] = am;
            }
            SetPath(ctx, segs, Copy(value));
        }
        return new(ctx, conflicts, dropped);
    }

    static bool IsGroup(object? c) => c is JD m && (m.ContainsKey("all_of") || m.ContainsKey("any_of") || m.ContainsKey("not"));

    static void Collect(object? c, JD ctx, HashSet<string> output, bool[] ill, int depth = 0)
    {
        if (depth > 64 || (c is not JD && c is not JL)) { ill[0] = true; return; }
        if (IsGroup(c))
        {
            var m = (JD)c!;
            object? kids = m.ContainsKey("all_of") ? m["all_of"] : m.ContainsKey("any_of") ? m["any_of"] : new JL { m["not"] };
            if (kids is not JL kl || kl.Count == 0) { ill[0] = true; return; }
            foreach (var k in kl) Collect(k, ctx, output, ill, depth + 1);
            return;
        }
        if (Predicates.EvaluateConditionTri(c, ctx) != Predicates.Tri.Unknown) return;
        var absent = false;
        if (c is JD cm)
        {
            foreach (var p in new[] { cm.GetValueOrDefault("field"), cm.GetValueOrDefault("ref") })
                if (p is string ps && ps.Length > 0 && !Predicates.ResolvePath(ctx, ps).Found) { output.Add(ps); absent = true; }
            if (cm.GetValueOrDefault("field") is string f && (f == "action.params" || f.StartsWith("action.params.", StringComparison.Ordinal)))
            {
                var p = (ctx.GetValueOrDefault("action") as JD)?.GetValueOrDefault("params");
                if (p is not JD && p is not JL) { output.Add(f); absent = true; }
            }
        }
        if (!absent) ill[0] = true;
    }

    /// <summary>Decide a permit condition list (implicit AND) over the bound context plus whatever the request supplied.</summary>
    public static TypedDecision DecideWithMissing(object? conditions, object? bound, object? supplied = null, object? suppliers = null)
    {
        TypedDecision Deny(string reason, List<MissingItem>? missing = null) => new("deny", reason, missing ?? new());
        try
        {
            if (bound is not JD bm || bm.GetValueOrDefault("action") is not JD) return Deny("bad_context");
            object table = suppliers ?? new JD();
            var te = SupplierTableError(table);
            if (te != null) return Deny($"bad supplier table: {te}");
            var tbl = (JD)table;
            if (conditions is not JL wl || wl.Count == 0) return Deny("condition_false");
            var b = BindContext(bm, supplied, tbl);
            if (b.Conflicts.Count > 0) return Deny($"context_shadow: {string.Join(",", b.Conflicts)}");
            var t = Predicates.EvaluateConditionTri(new JD { ["all_of"] = wl }, b.Context);
            if (t == Predicates.Tri.True) return new("allow", null, new());
            if (t == Predicates.Tri.False) return Deny("condition_false");
            var paths = new HashSet<string>(); var ill = new bool[1];
            foreach (var c in wl) Collect(c, b.Context, paths, ill);
            if (paths.Count == 0 || ill[0]) return Deny("ill_typed_context");
            var sorted = paths.ToList(); sorted.Sort(StringComparer.Ordinal);
            var missing = sorted.Select(p => new MissingItem(p, SupplierOf(p, tbl))).ToList();
            var untrusted = missing.Where(m => m.Supplier == "agent_declared_untrusted").ToList();
            if (untrusted.Count > 0) return Deny($"missing_context_untrusted: {string.Join(",", untrusted.Select(m => m.Path))}", missing);
            return new("escalate", $"escalate: missing_context {string.Join(",", missing.Select(m => $"{m.Supplier}:{m.Path}"))}", missing);
        }
        catch (Exception) { return Deny("evaluation error (fail closed)"); }
    }
}
