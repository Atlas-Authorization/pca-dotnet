// Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them autonomously) and
// evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels something upstream attached; this
// checks them against ceilings and never tracks data through a program.
//
// A policy is {classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}; a context is
// {verb, resource, taint, trustedRefs?}; a result is {outcome: allow|step_up|deny, class?, reason?}. JSON values are the core's:
// Dictionary<string, object?>, List<object?>, string, bool, Num.
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Research;

public static class Dlp
{
    static bool IsNum(object? x) => IntentJs.NumOf(x) is double d && !double.IsNaN(d);
    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;
    static string JsNum(double x) => JsX.JsNumString(x);
    static bool Has(D m, string k) => m.ContainsKey(k);
    static object? Get(D m, string k) => m.TryGetValue(k, out var v) ? v : null;

    static bool Matches(object? pattern, object? resource)
    {
        if (pattern is string star && star == "*") return true;
        if (pattern is not string p) throw new ArgumentException("DLP: a class resource must be a string");
        if (p.EndsWith('*'))
        {
            if (resource is not string r) throw new ArgumentException("DLP: the resource must be a string");
            return r.StartsWith(p[..^1], StringComparison.Ordinal);
        }
        return resource is string s && p == s;
    }

    static double Specificity(string pattern)
    {
        if (pattern == "*") return 0.0;
        if (pattern.EndsWith('*')) return pattern.Length - 1;
        return pattern.Length + 1000; // exact beats any prefix
    }

    // a malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling (unconstrained) sorts last
    static double Strictness(D c)
    {
        var m = Get(c, "maxTaintForAuto");
        if (m == null && !Has(c, "maxTaintForAuto")) return double.PositiveInfinity;
        return IsNum(m) ? Dv(m) : double.NegativeInfinity;
    }

    static bool VerbMatches(D c, object? verb)
    {
        var vs = Get(c, "verbs");
        if (!JsX.Truthy(vs)) return true;
        if (vs is L l) return l.Any(e => JsX.StrictEq(e, verb));
        if (vs is string s) return s.Contains(verb is string vv ? vv : JsX.Str(verb), StringComparison.Ordinal);
        throw new ArgumentException("DLP: verbs must be a list");
    }

    static int Cmp(double x) => double.IsNaN(x) || x == 0.0 ? 0 : x < 0 ? -1 : 1;

    // The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equals the STRICTEST wins. Null for none.
    static D? ClassFor(L classes, D ctx)
    {
        var applicable = new List<D>();
        foreach (var o in classes)
        {
            if (o is not D c) throw new ArgumentException("DLP: a class must be an object");
            if (Matches(Get(c, "resource"), Get(ctx, "resource")) && VerbMatches(c, Has(ctx, "verb") ? Get(ctx, "verb") : JsX.Undef)) applicable.Add(c);
        }
        if (applicable.Count == 0) return null;
        // stable insertion sort (List.Sort is not stable)
        for (int i = 1; i < applicable.Count; i++)
        {
            var x = applicable[i];
            int j = i - 1;
            while (j >= 0 && Order(applicable[j], x) > 0) { applicable[j + 1] = applicable[j]; j--; }
            applicable[j + 1] = x;
        }
        return applicable[0];
    }

    static int Order(D a, D b)
    {
        int s = Cmp(Specificity((string)Get(b, "resource")!) - Specificity((string)Get(a, "resource")!));
        return s != 0 ? s : Cmp(Strictness(a) - Strictness(b));
    }

    // A ceiling that is present but not a number would make every comparison false and allow everything.
    static bool Malformed(D policy, D? cls)
    {
        if (cls != null) return (Has(cls, "maxTaintForAuto") && !IsNum(Get(cls, "maxTaintForAuto"))) || (Has(cls, "hardDenyAbove") && !IsNum(Get(cls, "hardDenyAbove")));
        return Has(policy, "defaultMaxTaintForAuto") && !IsNum(Get(policy, "defaultMaxTaintForAuto"));
    }

    static D Result(string outcome, D? cls, string? reason)
    {
        var r = new D { ["outcome"] = outcome };
        if (cls != null && Has(cls, "name")) r["class"] = cls["name"];
        if (reason != null) r["reason"] = reason;
        return r;
    }

    /// <summary>Evaluate an action's data flow against the DLP policy. Fails CLOSED: a malformed policy or ceiling is a deny, and a taint that is not a
    /// finite number is treated as maximally tainted so it can never beat a ceiling.</summary>
    public static D EvaluateDlp(D? policy, D ctx)
    {
        if (policy == null || Get(policy, "classes") is not L classes) return Result("deny", null, "malformed DLP policy");
        var cls = ClassFor(classes, ctx);
        if (Malformed(policy, cls)) return Result("deny", cls, "malformed DLP policy: ceilings must be numbers");
        var max = cls != null ? Get(cls, "maxTaintForAuto") : Get(policy, "defaultMaxTaintForAuto");
        var hasMax = cls != null ? Has(cls, "maxTaintForAuto") : Has(policy, "defaultMaxTaintForAuto");
        var bad = !IntentJs.IsFinite(Get(ctx, "taint"));
        var taint = bad ? double.PositiveInfinity : Dv(Get(ctx, "taint"));
        if (!hasMax) return Result("allow", cls, null); // no ceiling at all: nothing to compare against
        var m = Dv(max);
        var label = cls != null && Get(cls, "name") != null ? JsX.Str(Get(cls, "name")) : "<default>";
        if (cls != null && Has(cls, "hardDenyAbove") && (bad || taint > Dv(Get(cls, "hardDenyAbove"))))
            return Result("deny", cls, "taint " + JsNum(taint) + " exceeds hard ceiling " + JsNum(Dv(Get(cls, "hardDenyAbove"))) + " for '" + label + "'");
        if (bad || taint > m) return Result("step_up", cls, "taint " + JsNum(taint) + " > " + JsNum(m) + " for '" + label + "' — needs human review");
        return Result("allow", cls, null);
    }

    /// <summary>Preset with no options: no classes.</summary>
    public static D DefaultDlpPolicy() => DefaultDlpPolicy(new D());

    /// <summary>Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. <paramref name="opts"/> is {piiResource?, secretsResource?}.</summary>
    public static D DefaultDlpPolicy(D? opts)
    {
        var classes = new L();
        if (opts != null && JsX.Truthy(Get(opts, "piiResource"))) classes.Add(Cls("pii", Get(opts, "piiResource"), 0, 2));
        if (opts != null && JsX.Truthy(Get(opts, "secretsResource"))) classes.Add(Cls("secrets", Get(opts, "secretsResource"), 0, 0));
        return new D { ["classes"] = classes };
    }

    static D Cls(string name, object? resource, long max, long hard) => new()
    {
        ["name"] = name, ["resource"] = resource, ["maxTaintForAuto"] = IntentJs.OfLong(max), ["hardDenyAbove"] = IntentJs.OfLong(hard),
    };
}
