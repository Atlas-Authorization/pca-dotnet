// Lease operations beyond verification: the authority-side renewal and the hosted lease routes (packages/pca-grants lease.ts renewLease
// and lease-http.ts). The server stores only records the lease authority already signed; it never mints one.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

public static class Leases
{
    /// <summary>Authority side: sign and register the next record of a lease. Returns <c>{ok: true, record}</c> or <c>{ok: false, code}</c>
    /// (code: bad_input, unknown_lease, vetoed, expired_lease or any code of <see cref="LeaseRegistry.Accept"/>).
    /// <paramref name="veto"/> may only REFUSE a renewal, never lengthen the lease.</summary>
    public static JD RenewLease(EdKey key, LeaseRegistry registry, string id, object? now, object? increment, string justificationDigest,
        IReadOnlyList<object?>? approvers = null, Func<JD, bool>? veto = null, IReadOnlyList<string>? chain = null)
    {
        static JD No(string code) => new() { ["ok"] = false, ["code"] = code };
        if (!Pca.SafeNat(now, out var n) || !Pca.SafeNat(increment, out var inc) || inc < 1) return No("bad_input");
        var cur = registry.Get(id);
        if (cur == null) return No("unknown_lease");
        if (veto != null && veto(cur)) return No("vetoed");
        var expires = Math.Min(n + inc, Lease.Cap(cur));
        var next = G.Without(cur, "v", "sig", "authority");
        next["seq"] = G.N(G.L(cur["seq"]) + 1);
        next["renewed_at"] = G.N(n);
        next["expires_at"] = G.N(expires);
        next["justification_digest"] = justificationDigest;
        next["approvers"] = approvers != null ? approvers.ToList() : cur["approvers"]; // taken as given: a member that is not text makes the record unsignable (bad_input)
        JD? record = null;
        try { record = GrantSigning.SignLease(key, next); }
        catch (Exception) { return No(expires <= n ? "expired_lease" : "bad_input"); }
        var r = registry.Accept(record, chain);
        if (r.Ok) return new JD { ["ok"] = true, ["record"] = record };
        var refused = No(r.Code!);
        if (r.Reason != null) refused["reason"] = r.Reason;
        return refused;
    }
}

public static class LeaseHttp
{
    public const string LeasesPath = "/pca/leases";

    static readonly Dictionary<string, int> Status = new()
    {
        ["bad_record"] = 400, ["bad_seq"] = 409, ["stale_seq"] = 409, ["lease_fork"] = 409, ["renewal_mismatch"] = 422, ["over_max_ttl"] = 422, ["ttl_ceiling"] = 422, ["not_extending"] = 422,
        ["stale_justification"] = 422, ["expired_lease"] = 409, ["revoked"] = 409, ["sod"] = 403, ["unknown_authority"] = 403, ["store_unreachable"] = 503,
    };

    /// <summary>Discovery fragment for <c>/.well-known/pca-configuration</c>.</summary>
    public static JD LeaseManagementMetadata(string baseUrl) => new()
    {
        ["leases"] = new JD { ["leases_endpoint"] = baseUrl + LeasesPath, ["revoke_targets"] = new JL { "lease", "prefix", "grant" } },
    };

    static JD DecisionJson(LeaseDecision d)
    {
        var o = new JD { ["decision"] = d.Decision };
        if (d.Code != null) o["code"] = d.Code;
        if (d.LeaseId != null) o["lease_id"] = d.LeaseId;
        if (d.ExpiresAt != null) o["expires_at"] = G.N(d.ExpiresAt.Value);
        return o;
    }

    static JD HistoryJson(LeaseHistoryEntry h) => new()
    {
        ["seq"] = G.N(h.Seq), ["renewed_at"] = G.N(h.RenewedAt), ["expires_at"] = G.N(h.ExpiresAt), ["justification_digest"] = h.JustificationDigest,
    };

    /// <summary>The handler of the lease routes: POST /pca/leases (issue or renew), POST /pca/leases/revoke, GET /pca/leases/:id, POST /pca/leases/:id/check.</summary>
    public static Func<GrantHttpRequest, GrantHttpResponse> Handler(LeaseRegistry reg, Func<GrantHttpRequest, GrantCaller?> authenticate, Func<long>? now = null)
    {
        var clock = now ?? (() => AtlasPca.ReplayClock.NowMs());
        return req =>
        {
            try
            {
                var who = authenticate(req);
                if (who == null || (!who.Admin && string.IsNullOrEmpty(who.Principal))) return GrantHttp.Plain(401, "unauthenticated");
                var seg = GrantHttp.Segments(req.Path);
                var b = req.Body as JD ?? new JD();
                if (seg.Length < 2 || seg[0] != "pca" || seg[1] != "leases") return GrantHttp.Plain(404, "not_found");
                // a lease belongs to its holder: a non-admin sees and checks only leases it holds
                bool Visible(object? holder) => who.Admin || (holder is string h && who.Principal == h);
                if (seg.Length == 2 && req.Method == "POST")
                {
                    if (!who.Admin) return GrantHttp.Plain(403, "forbidden");
                    var chain = b.GetValueOrDefault("chain") is JL cl && cl.All(x => x is string) ? cl.Select(x => (string)x!).ToList() : new List<string>();
                    var r = reg.Accept(b.GetValueOrDefault("lease"), chain);
                    if (r.Ok) return new(r.Replaced ? 201 : 200, new JD { ["ok"] = true, ["replaced"] = r.Replaced, ["seq"] = G.N(r.Seq) });
                    var err = new JD { ["error"] = r.Code };
                    if (!string.IsNullOrEmpty(r.Reason)) err["message"] = r.Reason;
                    return new(Status.GetValueOrDefault(r.Code!, 400), err);
                }
                if (seg.Length == 3 && seg[2] == "revoke" && req.Method == "POST")
                {
                    if (!who.Admin) return GrantHttp.Plain(403, "forbidden");
                    var r = reg.Revoke(b.GetValueOrDefault("revocation"));
                    return r.Ok ? new GrantHttpResponse(200, new JD { ["ok"] = true, ["revoked"] = G.N(r.Revoked) })
                        : GrantHttp.Plain(r.Code == "store_unreachable" ? 503 : r.Code == "unknown_authority" ? 403 : 400, r.Code!);
                }
                var id = seg.Length > 2 ? seg[2] : null;
                if (string.IsNullOrEmpty(id)) return GrantHttp.Plain(404, "not_found");
                if (seg.Length == 3 && req.Method == "GET")
                {
                    var cur = reg.Get(id);
                    if (cur == null || !Visible(cur["holder"])) return GrantHttp.Plain(404, "not_found");
                    return new(200, new JD { ["lease"] = cur, ["history"] = reg.History(id).Select(h => (object?)HistoryJson(h)).ToList() });
                }
                if (seg.Length == 4 && seg[3] == "check" && req.Method == "POST")
                {
                    var cur = reg.Get(id);
                    if (cur == null || !Visible(cur["holder"])) return GrantHttp.Plain(404, "not_found");
                    var d = Lease.Check(b.GetValueOrDefault("lease"), reg, G.N(clock()));
                    return new(d.Decision == "allow" ? 200 : 403, DecisionJson(d));
                }
                return GrantHttp.Plain(404, "not_found");
            }
            catch (Exception) { return GrantHttp.Plain(500, "server_error"); }
        };
    }
}
