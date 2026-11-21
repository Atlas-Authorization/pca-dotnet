using static AtlasPca.Explain.ExplainJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>Import external authorization policy into PCA: each translator compiles a policy source into PCA envelope predicates plus a report of
/// what was and was not translated; everything unmodeled fails closed (default deny). A result is the JSON map
/// <c>{predicates, denies, caveats, report: {source, translated, skipped, errors}}</c>. <see cref="Cedar"/> (permit / forbid), <see cref="Rego"/>
/// (an OPA allow-rule subset), <see cref="OpenFga"/> (a ReBAC model and tuples) and <see cref="Cel"/> (strict CEL conditions). The emitted predicates
/// plug into an envelope; <c>denies</c> (Cedar forbid) is applied by <see cref="Decide"/> (deny-overrides-permit) on top of the core evaluator.</summary>
public static class PolicyBridge
{
    internal static D NewReport(string source) => new() { ["source"] = source, ["translated"] = new L(), ["skipped"] = new L(), ["errors"] = new L() };

    internal static L ListOf(D report, string key) => (L)report[key]!;

    internal static D Result(L predicates, L denies, D report) => new() { ["predicates"] = predicates, ["denies"] = denies, ["caveats"] = new L(), ["report"] = report };

    /// <summary>Decide one action under a translation with deny-overrides-permit (Cedar's combining rule) on the core evaluator: any matching deny
    /// denies; otherwise the permit predicates decide. Fails closed on an incomplete translation (a result whose report carries errors). Returns
    /// <c>{allowed, matched?, reason?}</c>.</summary>
    public static D Decide(D result, D ctx)
    {
        if (result.GetValueOrDefault("report") is D rep && rep.GetValueOrDefault("errors") is L errs && errs.Count > 0)
            return PbJs.Obj("allowed", false, "reason", "translation incomplete (fail closed)");
        var denies = result.GetValueOrDefault("denies");
        if (denies is L dl && dl.Count > 0 && Predicates.EvaluatePredicates(denies, ctx))
            return PbJs.Obj("allowed", false, "matched", FirstMatch(dl, ctx), "reason", "forbidden by deny policy");
        var permits = result.GetValueOrDefault("predicates");
        if (Predicates.EvaluatePredicates(permits, ctx)) return PbJs.Obj("allowed", true, "matched", FirstMatch((L)permits!, ctx));
        return PbJs.Obj("allowed", false, "reason", DenialReason(permits, ctx));
    }

    static object? FirstMatch(L predicates, D ctx)
    {
        foreach (var p in predicates) if (Predicates.PredicateMatches(p, ctx)) return p;
        return null;
    }

    /// <summary>Why the predicates denied: "envelope grants no predicates" for an empty set, "&lt;limit&gt; not satisfied for &lt;verb&gt; on &lt;resource&gt;"
    /// when a limit in scope is unmet, else "no predicate permits &lt;verb&gt; on &lt;resource&gt;".</summary>
    static string DenialReason(object? predicates, D ctx)
    {
        if (predicates is not L pl || pl.Count == 0) return "envelope grants no predicates";
        var a = Q(ctx, "action");
        var vr = $"{S(Q(a, "verb"))} on {S(Q(a, "resource"))}";
        var limit = Predicates.FirstUnmetLimit(predicates, ctx);
        return limit != null ? $"{limit} not satisfied for {vr}" : $"no predicate permits {vr}";
    }
}
