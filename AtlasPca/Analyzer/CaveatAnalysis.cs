using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Static analysis of a caveat list: satisfiable at all, why not, and the reversibility ceiling it implies.</summary>
public sealed class CaveatAnalysisResult
{
    public bool Sat { get; init; }
    public string? Reason { get; init; }
    public int? RevCap { get; init; }

    public D ToJson()
    {
        var o = new D { ["sat"] = Sat };
        if (Reason != null) o["reason"] = Reason;
        if (RevCap != null) o["revCap"] = Jx.N(RevCap.Value);
        return o;
    }
}

public static class CaveatAnalysis
{
    /// <summary>The reversibility classes, least to most severe.</summary>
    public static readonly IReadOnlyList<string> ReversibilityOrder = new[] { "reversible", "rate_limited", "irreversible" };

    static CaveatAnalysisResult No(string why) => new() { Sat = false, Reason = why };

    /// <summary>analyzeCaveats: the empty-window / forbids-everything / unknown-type checks. A non-array input is unsatisfiable (fail closed).</summary>
    public static CaveatAnalysisResult AnalyzeCaveats(object? caveats)
    {
        if (caveats is not L list) return No("caveats are not an array");
        double notBeforeMax = double.NegativeInfinity, expiresMin = double.PositiveInfinity;
        int? revCap = null;
        foreach (var o in list)
        {
            if (o is not D cv || cv.GetValueOrDefault("type") is not string type) return No("malformed caveat (not an object with a string type)");
            switch (type)
            {
                case "expires":
                {
                    if (Jx.Fin(Jx.Prop(cv, "at")) is not double at) return No("expires.at is not a finite number");
                    expiresMin = Math.Min(expiresMin, at);
                    break;
                }
                case "not_before":
                {
                    if (Jx.Fin(Jx.Prop(cv, "at")) is not double at) return No("not_before.at is not a finite number");
                    notBeforeMax = Math.Max(notBeforeMax, at);
                    break;
                }
                case "rate":
                {
                    var max = Jx.Fin(Jx.Prop(cv, "max")); var per = Jx.Fin(Jx.Prop(cv, "per_secs"));
                    if (max == null || per == null || per <= 0) return No("rate caveat requires finite max and per_secs > 0");
                    if (max < 1) return No($"rate.max {Jx.NumStr(max.Value)} < 1 forbids every action");
                    break;
                }
                case "max_blast_radius":
                {
                    if (Jx.Fin(Jx.Prop(cv, "max")) is not double max) return No("max_blast_radius.max is not a finite number");
                    if (max < 0) return No("max_blast_radius.max < 0 forbids every action");
                    break;
                }
                case "reversibility_max":
                {
                    var cls = Jx.Prop(cv, "class");
                    var name = AtlasPca.InteropJs.JsX.Str(cls);
                    var idx = ReversibilityOrder.ToList().IndexOf(name);
                    if (idx < 0) return No($"reversibility_max.class '{name}' is unknown");
                    revCap = revCap == null ? idx : Math.Min(revCap.Value, idx);
                    break;
                }
                case "delegation_depth":
                {
                    if (Jx.Fin(Jx.Prop(cv, "max")) is not double max) return No("delegation_depth.max is not a finite number");
                    if (max < 0) return No("delegation_depth.max < 0 forbids every action");
                    break;
                }
                case "budget_alloc":
                {
                    var lim = Jx.Fin(Jx.Prop(cv, "limit"));
                    if (lim == null || lim < 0) return No("budget_alloc.limit must be a finite number >= 0");
                    break;
                }
                default:
                    return No($"unknown caveat type '{type}' (fail closed)");
            }
        }
        if (!double.IsNegativeInfinity(notBeforeMax) && !double.IsPositiveInfinity(expiresMin) && notBeforeMax >= expiresMin)
            return No($"not_before ({Jx.NumStr(notBeforeMax)}) >= expires ({Jx.NumStr(expiresMin)}): the validity window is empty");
        return new CaveatAnalysisResult { Sat = true, RevCap = revCap };
    }
}
