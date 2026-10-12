// PCA 0.4.1 policy-layer caveat helpers, mirroring `policyCaveats` (packages/pca/src/policy-vm.ts) and the caveat evaluator
// (`envelopeCaveatEvaluator` in predicates.ts + `max_spend` in agent-native.ts).
using System.Globalization;
using System.Numerics;

namespace AtlasPca;

/// <summary>
/// Policy-layer caveat helpers (0.4.1). The core verifier (<see cref="Pca.VerifyPcactnCore"/>, the nine checks) and the
/// ASP.NET Core middleware treat caveats as opaque and do NOT evaluate them. A resource server that enforces a grant's caveats
/// calls <c>Caveats.EvaluateCaveats(Caveats.PolicyCaveats(grant, chain), ctx)</c> with its own action parameters.
/// <see cref="PolicyCaveats"/> includes the caveats placed directly on the ROOT grant (outside the <c>envelope</c> caveat):
/// before 0.4.1 the reference policy layer signed those but never evaluated them.
///
/// The context is a dictionary with snake_case keys, exactly the <c>context</c> of the <c>primitives.caveat_eval</c> vectors:
/// <c>now</c> (epoch ms), <c>delegation_depth</c>, <c>blast_radius</c>, <c>reversibility_class</c>, <c>recent_action_times</c>
/// (all optional) and <c>action</c> (<c>{verb, resource, reversibility_class, params}</c>). An absent optional field leaves the
/// caveat that needs it unsatisfied. Unknown caveat types (and <c>note</c>, <c>envelope</c>, <c>resource_prefix</c>,
/// <c>predicates</c>, <c>tool_schema</c>) are unsatisfied: fail closed.
/// </summary>
public static class Caveats
{
    /// <summary>The verdict of <see cref="EvaluateCaveats"/>: <c>Ok</c> iff every caveat is satisfied; <c>Failed</c> = the
    /// unsatisfied types, in order (<c>"&lt;malformed&gt;"</c> when a caveat's type is not a string).</summary>
    public sealed record Result(bool Ok, IReadOnlyList<string> Failed);

    static readonly string[] ReversibilityOrder = { "reversible", "rate_limited", "irreversible" };

    /// <summary>The ROOT grant's caveats the policy layer evaluates: <c>grant.caveats</c> without its FIRST <c>envelope</c>
    /// caveat (order kept; a second envelope stays and is unsatisfied). A non-list <c>caveats</c> is returned as is (and refused
    /// by <see cref="EvaluateCaveats"/>); a non-object grant yields null. The input is never mutated.</summary>
    public static object? RootCaveats(object? grant)
    {
        if (grant is not Dictionary<string, object?> g) return null;
        var cs = g.GetValueOrDefault("caveats");
        if (cs is not List<object?> list) return cs;
        var output = new List<object?>(list);
        int i = output.FindIndex(c => c is Dictionary<string, object?> d && d.GetValueOrDefault("type") is "envelope");
        if (i >= 0) output.RemoveAt(i);
        return output;
    }

    /// <summary>Every caveat the policy layer evaluates for an action under <paramref name="grant"/> delegated along
    /// <paramref name="chain"/> (root first): <see cref="RootCaveats"/> of the grant, then the caveats the hops appended
    /// (<c>leaf.caveats</c> beyond the grant's, leaf = the last chain element). Nothing is appended when the chain is absent,
    /// empty or not a list, or when either caveat list is not a list.</summary>
    public static object? PolicyCaveats(object? grant, object? chain)
    {
        var root = RootCaveats(grant);
        if (root is not List<object?> rl) return root;
        var output = new List<object?>(rl);
        if (chain is List<object?> ch && ch.Count > 0
            && ch[^1] is Dictionary<string, object?> leaf && leaf.GetValueOrDefault("caveats") is List<object?> lcs
            && ((Dictionary<string, object?>)grant!).GetValueOrDefault("caveats") is List<object?> gcs)
        {
            for (int k = gcs.Count; k < lcs.Count; k++) output.Add(lcs[k]);
        }
        return output;
    }

    /// <summary>Evaluate every caveat against <paramref name="ctx"/>. Total: never throws; a non-list =&gt;
    /// <c>Ok=false, Failed=["&lt;malformed caveats&gt;"]</c>.</summary>
    public static Result EvaluateCaveats(object? caveats, object? ctx)
    {
        if (caveats is not List<object?> list) return new Result(false, new[] { "<malformed caveats>" });
        var failed = new List<string>();
        foreach (var cv in list)
        {
            bool ok;
            try { ok = Satisfied(cv, ctx); }
            catch (Exception) { ok = false; }
            if (!ok) failed.Add(cv is Dictionary<string, object?> d && d.GetValueOrDefault("type") is string t ? t : "<malformed>");
        }
        return new Result(failed.Count == 0, failed);
    }

    /// <summary>One caveat against <paramref name="ctx"/>; false (unsatisfied) for anything malformed or unknown.</summary>
    public static bool Satisfied(object? caveat, object? ctx)
    {
        if (caveat is not Dictionary<string, object?> cv || ctx is not Dictionary<string, object?> c) return false;
        var type = cv.GetValueOrDefault("type") as string;
        if (type == "max_spend") return MaxSpend(cv, c);
        if (Fin(c.GetValueOrDefault("now")) is not double now) return false;
        switch (type)
        {
            case "expires":
                return Fin(cv.GetValueOrDefault("at")) is double at && now < at;
            case "not_before":
                return Fin(cv.GetValueOrDefault("at")) is double nb && now >= nb;
            case "rate":
            {
                if (Fin(cv.GetValueOrDefault("max")) is not double max || Fin(cv.GetValueOrDefault("per_secs")) is not double per || per <= 0) return false;
                if (c.GetValueOrDefault("recent_action_times") is not List<object?> times) return false;
                double lo = now - per * 1000;
                int n = 0;
                foreach (var t in times) if (Fin(t) is double d && d > lo && d <= now) n++;
                return n < max;
            }
            case "max_blast_radius":
                return Fin(cv.GetValueOrDefault("max")) is double mb && Fin(c.GetValueOrDefault("blast_radius")) is double br && br <= mb;
            case "reversibility_max":
            {
                if (cv.GetValueOrDefault("class") is not string lim || c.GetValueOrDefault("reversibility_class") is not string cur) return false;
                int li = Array.IndexOf(ReversibilityOrder, lim), ci = Array.IndexOf(ReversibilityOrder, cur);
                return li >= 0 && ci >= 0 && ci <= li;
            }
            case "delegation_depth":
                return Fin(cv.GetValueOrDefault("max")) is double md && Fin(c.GetValueOrDefault("delegation_depth")) is double dd && dd <= md;
            case "budget_alloc":
                return Fin(cv.GetValueOrDefault("limit")) is double bl && bl >= 0;
            default:
                return false;
        }
    }

    /// <summary><c>max_spend {usd}</c>: <c>usd</c> a finite number &gt;= 0; <c>ctx.action.params</c> an object with an own finite
    /// <c>amount</c> &gt;= 0 and <c>amount &lt;= usd</c>; an own <c>currency</c>, when present, exactly "usd" or "USD". Does not
    /// need <c>now</c>.</summary>
    static bool MaxSpend(Dictionary<string, object?> cv, Dictionary<string, object?> c)
    {
        if (Fin(cv.GetValueOrDefault("usd")) is not double lim || lim < 0) return false;
        if (c.GetValueOrDefault("action") is not Dictionary<string, object?> act) return false;
        if (act.GetValueOrDefault("params") is not Dictionary<string, object?> p) return false;
        if (!p.TryGetValue("amount", out var a) || Fin(a) is not double amount || amount < 0) return false;
        if (p.TryGetValue("currency", out var cur) && !(cur is "usd" or "USD")) return false;
        return amount <= lim;
    }

    /// <summary>A finite JSON number as a double (JavaScript semantics: an overflowing literal is not finite), else null.</summary>
    static double? Fin(object? o)
    {
        double d;
        switch (o)
        {
            case Num n:
                if (!double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return null;
                break;
            case double x: d = x; break;
            case float x: d = x; break;
            case int x: d = x; break;
            case long x: d = x; break;
            case short x: d = x; break;
            case byte x: d = x; break;
            case decimal x: d = (double)x; break;
            case BigInteger x: d = (double)x; break;
            default: return null;
        }
        return double.IsFinite(d) ? d : null;
    }
}
