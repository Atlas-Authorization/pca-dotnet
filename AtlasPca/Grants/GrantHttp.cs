// Framework-neutral HTTP bindings of the grant management resource and of the hosted lease routes (packages/pca-grants http.ts and
// lease-http.ts): a request record in, a response record out; the host maps its framework onto them and authenticates the caller.
using System.Globalization;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary>A request below the mount point (<c>Path</c> like <c>/pca/grants/g_1/amend</c>). <c>Body</c> is a parsed JSON tree; <c>Context</c> is whatever the host's authenticator needs.</summary>
public sealed record GrantHttpRequest(string Method, string Path, IReadOnlyDictionary<string, string?>? Query = null, object? Body = null, object? Context = null);

public sealed record GrantHttpResponse(int Status, object? Body);

/// <summary>Who is calling, as the host authenticated them. <c>Principal</c> limits every read and write to that principal's grants.</summary>
public sealed record GrantCaller(string? Principal = null, bool Admin = false);

public static class GrantHttp
{
    public const string GrantsPath = "/pca/grants";
    public const string NeedsPath = "/pca/needs";

    static readonly Dictionary<string, int> Status = new()
    {
        ["not_found"] = 404, ["conflict"] = 409, ["bad_request"] = 400, ["not_narrower"] = 422, ["signature_required"] = 401, ["bad_signature"] = 401, ["step_up_required"] = 403,
        ["not_active"] = 409, ["need_not_lowered_only"] = 422, ["need_not_adjustable"] = 422, ["forbidden"] = 403,
    };

    static GrantHttpResponse Err(Exception e) =>
        e is GrantError ge ? new(Status[ge.Code], new JD { ["error"] = ge.Code, ["message"] = ge.Message }) : new(500, new JD { ["error"] = "server_error" });

    internal static GrantHttpResponse Json(int status, object? body) => new(status, body);
    internal static GrantHttpResponse Plain(int status, string error) => new(status, new JD { ["error"] = error });

    /// <summary>Discovery fragment for <c>/.well-known/pca-configuration</c>.</summary>
    public static JD GrantManagementMetadata(string baseUrl) => new()
    {
        ["grant_management"] = new JD
        {
            ["grants_endpoint"] = baseUrl + GrantsPath, ["needs_endpoint"] = baseUrl + NeedsPath, ["amend_actions"] = new JL { "narrow", "merge", "replace" },
            ["revoke_scopes"] = new JL { "grant", "agent", "subtree" }, ["widening"] = "new_grant_id_with_supersedes",
        },
    };

    /// <summary>JavaScript <c>Number(text)</c> for the decimal forms a query carries (blank is 0, anything unreadable is NaN).</summary>
    internal static double JsNumber(string s)
    {
        var t = s.Trim();
        if (t.Length == 0) return 0;
        return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;
    }

    internal static string[] Segments(string path) => path.Split('/').Where(x => x.Length > 0).ToArray();

    /// <summary>The handler of the grant routes. <paramref name="authenticate"/> returns null for an unauthenticated request.</summary>
    public static Func<GrantHttpRequest, GrantHttpResponse> Handler(GrantService svc, Func<GrantHttpRequest, GrantCaller?> authenticate) => req =>
    {
        try
        {
            var who = authenticate(req);
            if (who == null || (!who.Admin && string.IsNullOrEmpty(who.Principal))) return Plain(401, "unauthenticated");
            var seg = Segments(req.Path);
            string? Q(string k) => req.Query != null && req.Query.TryGetValue(k, out var v) ? v : null;
            bool HasQ(string k) => req.Query != null && req.Query.TryGetValue(k, out var v) && v != null;
            var b = req.Body as JD ?? new JD();
            // a principal-scoped caller may only see and touch its own grants
            void Own(string id)
            {
                var g = svc.Inspect(id);
                if (!who.Admin && G.Get(g, "principal") as string != who.Principal) throw new GrantError("not_found", "no such grant");
            }
            string? Seg(int i) => i < seg.Length ? seg[i] : null;
            if (Seg(0) != "pca") return Plain(404, "not_found");
            if (Seg(1) == "grants")
            {
                if (seg.Length == 2 && req.Method == "GET")
                {
                    var status = Q("status");
                    if (HasQ("status") && status is not ("active" or "revoked" or "superseded")) throw new GrantError("bad_request", "bad status");
                    var principal = who.Admin ? Q("principal") : who.Principal;
                    double? limit = HasQ("limit") ? JsNumber(Q("limit")!) : null;
                    var f = new GrantListFilter(
                        string.IsNullOrEmpty(principal) ? null : principal, string.IsNullOrEmpty(Q("agent")) ? null : Q("agent"), string.IsNullOrEmpty(status) ? null : status,
                        limit is double l && double.IsFinite(l) ? l : null, string.IsNullOrEmpty(Q("cursor")) ? null : Q("cursor"));
                    return new(200, svc.List(f));
                }
                var id = Seg(2);
                if (string.IsNullOrEmpty(id)) return Plain(404, "not_found");
                Own(id);
                if (seg.Length == 3 && req.Method == "GET") return new(200, svc.Inspect(id));
                if (seg.Length == 3 && req.Method == "DELETE")
                {
                    var scope = HasQ("scope") ? Q("scope") : "grant";
                    var sig = b.GetValueOrDefault("sig") as string;
                    // a principal-scoped caller must still sign; only an admin may revoke without a principal signature
                    var auth = who.Admin && string.IsNullOrEmpty(sig) ? new JD { ["admin"] = true } : new JD { ["sig"] = sig ?? "" };
                    var revoked = svc.Revoke(id, scope, auth);
                    return new(200, new JD { ["revoked"] = revoked.Cast<object?>().ToList() });
                }
                if (seg.Length == 4 && seg[3] == "amend" && req.Method == "POST")
                {
                    var (grant, created) = svc.Amend(id, req.Body);
                    return new(created ? 201 : 200, grant);
                }
                if (seg.Length == 4 && seg[3] == "needs" && req.Method == "POST") return new(201, svc.RequestNeeds(id, b.GetValueOrDefault("needs")));
            }
            if (Seg(1) == "needs" && !string.IsNullOrEmpty(Seg(2)) && Seg(3) == "approve" && req.Method == "POST")
            {
                Own(svc.NeedGrantId(seg[2]));
                if (b.GetValueOrDefault("sig") is not string sg || b.GetValueOrDefault("approved") is not JL) throw new GrantError("bad_request", "sig and approved are required");
                var (grant, _) = svc.ApproveNeeds(seg[2], b["approved"], sg, b.GetValueOrDefault("step_up_ref") as string);
                return new(201, grant);
            }
            if (Seg(1) == "needs" && !string.IsNullOrEmpty(Seg(2)) && Seg(3) == "deny" && req.Method == "POST")
            {
                Own(svc.NeedGrantId(seg[2]));
                svc.DenyNeeds(seg[2]);
                return new(200, new JD { ["status"] = "denied" });
            }
            return Plain(404, "not_found");
        }
        catch (Exception e) { return Err(e); }
    };
}
