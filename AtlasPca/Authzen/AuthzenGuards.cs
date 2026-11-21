using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Authzen;

/// <summary>The AuthZEN information model guards, the default request-to-action mapping and the approval-required (AARP) reading of a decision.</summary>
public static class AuthzenGuards
{
    public const string PcaApprovalKey = "pca_approval";
    public const string PcaActionKey = "pca_action";
    public const string PcaProvenanceKey = "pca_provenance";

    static bool IsRec(object? x) => x is D;
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;
    static bool Str(object? x) => x is string;

    static bool IsRequiredThreshold(object? x) =>
        x is D d && Jx.Fin(G(d, "t")) is double t && (t == 1 || t == 2 || t == 3) && G(d, "proof") is string && G(d, "optimisticAllowed") is bool;

    public static bool IsAuthzenSubject(object? x) => IsRec(x) && Str(G(x, "type")) && Str(G(x, "id"));
    public static bool IsAuthzenAction(object? x) => IsRec(x) && Str(G(x, "name"));
    public static bool IsAuthzenResource(object? x) => IsRec(x) && Str(G(x, "type")) && Str(G(x, "id"));

    public static bool IsAccessEvaluationRequest(object? x) =>
        IsRec(x) && IsAuthzenSubject(G(x, "subject")) && IsAuthzenAction(G(x, "action")) && IsAuthzenResource(G(x, "resource")) && (Jx.IsUndef(G(x, "context")) || IsRec(G(x, "context")));

    public static bool IsAccessEvaluationsRequest(object? x) => IsRec(x) && G(x, "evaluations") is L;

    public static bool IsCoazToolAuthorizationRequest(object? x) => IsRec(x) && IsAuthzenSubject(G(x, "subject")) && IsRec(G(x, "tool")) && Str(G(G(x, "tool"), "name"));

    /// <summary>approvalOf: the pending approval reference of a decision (reconstructed field by field), or null. A null response or null context throws (the reference TypeError).</summary>
    public static D? ApprovalOf(object? resp)
    {
        var ctx = Jx.Prop(resp, "context");
        if (Jx.IsUndef(ctx)) return null;
        var p = Jx.Prop(ctx, PcaApprovalKey);
        if (p is D d && G(d, "approval_required") is true && G(d, "auth_req_id") is string id)
        {
            var tier = Jx.Fin(G(d, "tier")) == 3 ? 3 : 2;
            var rt = G(d, "required_threshold");
            var threshold = IsRequiredThreshold(rt) ? rt : new D { ["t"] = Jx.N(tier), ["proof"] = tier == 3 ? "strong" : "standard", ["optimisticAllowed"] = false };
            var risk = G(d, "risk"); var at = G(d, "requested_at");
            return new D
            {
                ["approval_required"] = true, ["auth_req_id"] = id, ["tier"] = Jx.N(tier), ["required_threshold"] = threshold,
                ["goal_commit"] = G(d, "goal_commit") is string gc ? gc : "",
                ["risk"] = Jx.IsNum(risk) ? risk : Jx.N(1),
                ["reason"] = G(d, "reason") is string rs ? rs : "approval required",
                ["requested_at"] = Jx.IsNum(at) ? at : Jx.N(0),
            };
        }
        return null;
    }

    public static bool IsApprovalRequired(object? resp) => ApprovalOf(resp) != null;

    static string? PickReversibility(D req)
    {
        if (G(G(req, "action"), "properties") is D fa && G(fa, "reversibility_class") is string a) return a;
        if (G(req, "context") is D fc && G(fc, "reversibility_class") is string c) return c;
        return null;
    }

    static D? EnvFromContext(object? context)
    {
        if (context is not D c) return null;
        var o = new D();
        foreach (var (k, v) in c) { if (k == PcaActionKey || k == PcaApprovalKey) continue; o[k] = v; }
        return o.Count > 0 ? o : null;
    }

    /// <summary>defaultToAction: the analyzer action of an AuthZEN request (resource = type:id, params = resource then action properties).</summary>
    public static D DefaultToAction(D req)
    {
        var resObj = G(req, "resource"); var actObj = G(req, "action");
        var id = (string)G(resObj, "id")!; var type = (string)G(resObj, "type")!;
        var resource = id.Length > 0 ? type + ":" + id : type;
        var prm = new D();
        if (G(resObj, "properties") is D rp) foreach (var (k, v) in rp) prm[k] = v;
        if (G(actObj, "properties") is D ap) foreach (var (k, v) in ap) prm[k] = v;
        var o = new D { ["verb"] = G(actObj, "name"), ["resource"] = resource, ["params"] = prm };
        var rc = PickReversibility(req);
        if (rc != null) o["reversibilityClass"] = rc;
        if (G(G(req, "subject"), "properties") is D sp) o["subject"] = sp;
        var env = EnvFromContext(G(req, "context"));
        if (env != null) o["env"] = env;
        return o;
    }
}
