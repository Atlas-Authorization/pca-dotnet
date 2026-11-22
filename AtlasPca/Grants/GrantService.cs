// GRANT MANAGEMENT: list / inspect / amend / revoke and incremental authorization for principals (packages/pca-grants grant-resource.ts).
// Nothing widens in place: a widening creates a NEW grant id with `supersedes`. The pure verification (verifyAmendment, verifyRevokeSignature,
// verifyNeedApproval, the authority order and digest) is K3; this is the stateful service over a grant store.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary>A grant-management refusal; <c>Code</c> is one of not_found, conflict, bad_request, not_narrower, signature_required, bad_signature,
/// step_up_required, not_active, need_not_lowered_only, need_not_adjustable, forbidden.</summary>
public sealed class GrantError : CodedException { public GrantError(string code, string message) : base(code, message) { } }

/// <summary>Grant and need-request storage. Records are JSON trees; an implementation must hand out copies (callers mutate what they get and put it back).</summary>
public interface IGrantStore
{
    JD? Get(string id);
    void Put(JD grant);
    /// <summary>Every grant, in first-put order.</summary>
    List<JD> List();
    JD? GetNeed(string id);
    void PutNeed(JD need);
    List<JD> ListNeeds(string grantId);
}

public sealed class MemoryGrantStore : IGrantStore
{
    readonly Dictionary<string, JD> g = new(StringComparer.Ordinal);
    readonly List<string> gOrder = new();
    readonly Dictionary<string, JD> n = new(StringComparer.Ordinal);
    readonly List<string> nOrder = new();

    static string Id(JD d) => (string)d["id"]!;
    public JD? Get(string id) => g.TryGetValue(id, out var x) ? G.CloneD(x) : null;
    public void Put(JD grant) { var id = Id(grant); if (!g.ContainsKey(id)) gOrder.Add(id); g[id] = G.CloneD(grant); }
    public List<JD> List() => gOrder.Select(i => G.CloneD(g[i])).ToList();
    public JD? GetNeed(string id) => n.TryGetValue(id, out var x) ? G.CloneD(x) : null;
    public void PutNeed(JD need) { var id = Id(need); if (!n.ContainsKey(id)) nOrder.Add(id); n[id] = G.CloneD(need); }
    public List<JD> ListNeeds(string grantId) => nOrder.Select(i => n[i]).Where(x => G.Get(x, "grant_id") is string s && s == grantId).Select(G.CloneD).ToList();
}

/// <summary>Host-supplied views of a grant (usage, remaining budget, policy card, residual); each fills one member of an inspected grant.</summary>
public sealed class GrantProviders
{
    public Func<JD, object?>? Usage { get; init; }
    public Func<JD, object?>? RemainingBudget { get; init; }
    public Func<JD, object?>? PolicyCard { get; init; }
    public Func<JD, object?>? Residual { get; init; }
}

public sealed class GrantServiceOptions
{
    public required IGrantStore Store { get; init; }
    public required Func<long> Now { get; init; }
    /// <summary>"grant" or "need".</summary>
    public required Func<string, string> NewId { get; init; }
    public GrantProviders? Providers { get; init; }
    /// <summary>Confirms a satisfied step-up for a widening change. Absent: widening is refused (fail closed).</summary>
    public Func<string, JD, bool>? VerifyStepUp { get; init; }
    /// <summary>(ids revoked, scope, root grant).</summary>
    public Action<List<string>, string, JD>? OnRevoke { get; init; }
    /// <summary>(kind: amend, revoke, supersede or need; grant).</summary>
    public Action<string, JD>? OnChange { get; init; }
    /// <summary>Typed validation of a need: a non-empty string refuses it.</summary>
    public Func<JD, string?>? ValidateNeed { get; init; }
}

/// <summary>Filter of <see cref="GrantService.List"/>. <c>Limit</c> is a JavaScript number (any double).</summary>
public sealed record GrantListFilter(string? Principal = null, string? Agent = null, string? Status = null, double? Limit = null, string? Cursor = null);

public sealed class GrantService
{
    public const string AmendDomain = K3.GrantAmendDomain;
    public const string RevokeDomain = K3.GrantRevokeDomain;
    public const string NeedApproveDomain = K3.NeedApproveDomain;

    static readonly Dictionary<string, string> FailMessage = new()
    {
        ["not_found"] = "no such grant", ["conflict"] = "conflict", ["bad_request"] = "malformed request", ["not_narrower"] = "a narrow amendment must be strictly narrower",
        ["signature_required"] = "the amendment is signed (by the principal when it widens)", ["bad_signature"] = "the signature does not verify for this grant revision",
        ["step_up_required"] = "widening needs a satisfied step-up", ["not_active"] = "grant is not active", ["need_not_lowered_only"] = "an approval may only lower amounts of the requested needs",
        ["need_not_adjustable"] = "the need is not adjustable", ["forbidden"] = "not authorised",
    };

    readonly GrantServiceOptions o;
    public GrantService(GrantServiceOptions options) { o = options; }

    static GrantError Fail(string code) => new(code, FailMessage[code]);
    static string Digest(object? authority) => K3.AuthorityDigest(authority) ?? throw new InvalidOperationException("authority digest");

    static JD HistoryEntry(long rev, object? authority, long at, string action) =>
        new() { ["rev"] = G.N(rev), ["authority_digest"] = Digest(authority), ["at"] = G.N(at), ["action"] = action };

    /// <summary>Create a grant record (the host calls this when a grant is registered). <paramref name="g"/>: <c>{id, principal, agent, chain_digest, authority, parent?, adjustable?, status?}</c>.</summary>
    public JD Register(JD g)
    {
        if (!K3.AuthorityOk(G.Get(g, "authority"))) throw new GrantError("bad_request", "malformed authority");
        if (G.Get(g, "id") is not string id) throw new GrantError("bad_request", "malformed request");
        if (o.Store.Get(id) != null) throw new GrantError("conflict", "grant id exists");
        var now = o.Now();
        var rec = new JD(g);
        rec["status"] = G.Get(g, "status") ?? "active";
        rec["rev"] = G.N(1);
        rec["created_at"] = G.N(now);
        rec["history"] = new JL { HistoryEntry(1, g["authority"], now, "create") };
        o.Store.Put(rec);
        return G.CloneD(rec);
    }

    JD View(JD g, bool rich)
    {
        var v = G.Without(g, "history");
        v["authority_digest"] = Digest(g["authority"]);
        v["pending_needs"] = o.Store.ListNeeds((string)g["id"]!).Where(n => G.Get(n, "status") is "pending").Select(n => n["id"]).ToList();
        var p = o.Providers;
        if (rich && p?.Usage != null) v["usage"] = p.Usage(g);
        if (rich && p?.RemainingBudget != null) v["remaining_budget"] = p.RemainingBudget(g);
        if (rich && p?.PolicyCard != null) v["policy_card"] = p.PolicyCard(g);
        if (rich && p?.Residual != null) v["residual"] = p.Residual(g);
        return v;
    }

    /// <summary>A page of grants (<c>{grants, next_cursor?}</c>), filtered, ordered by id and cut at <c>limit</c> (default 50, 1..200).</summary>
    public JD List(GrantListFilter? f = null)
    {
        f ??= new GrantListFilter();
        var lim = f.Limit ?? 50;
        var limit = (int)Math.Truncate(Math.Min(Math.Max(lim, 1), 200));
        var all = o.Store.List()
            .Where(g => (f.Principal == null || G.Get(g, "principal") as string == f.Principal) && (f.Agent == null || G.Get(g, "agent") as string == f.Agent) && (f.Status == null || G.Get(g, "status") as string == f.Status))
            .OrderBy(g => (string)g["id"]!, StringComparer.Ordinal)
            .Where(g => f.Cursor == null || string.CompareOrdinal((string)g["id"]!, f.Cursor) > 0)
            .ToList();
        var page = all.Take(limit).ToList();
        var res = new JD { ["grants"] = page.Select(g => (object?)View(g, false)).ToList() };
        if (all.Count > limit) res["next_cursor"] = page[^1]["id"];
        return res;
    }

    JD Must(string id) => o.Store.Get(id) ?? throw new GrantError("not_found", "no such grant");

    public JD Inspect(string id) => View(Must(id), true);

    /// <summary>Amend a grant. <paramref name="req"/>: <c>{action, authority, sig?, signed_by?, step_up_ref?}</c>. Returns <c>{grant, created}</c>.</summary>
    public (JD Grant, bool Created) Amend(string id, object? req)
    {
        var cur = Must(id);
        var v = K3.VerifyAmendment(cur, req, false);
        // the (possibly consuming) step-up is evaluated only when everything else already passed
        if (!v.Ok && v.Code == "step_up_required" && G.Get(req, "step_up_ref") is string sref && sref.Length > 0 && o.VerifyStepUp != null && o.VerifyStepUp(sref, cur)) v = K3.VerifyAmendment(cur, req, true);
        if (!v.Ok) throw Fail(v.Code!);
        var now = o.Now();
        var action = (string)G.Get(req, "action")!;
        if (!v.Widens)
        {
            cur["authority"] = v.Authority;
            var rev = G.L(cur["rev"]) + 1;
            cur["rev"] = G.N(rev);
            ((JL)cur["history"]!).Add(HistoryEntry(rev, v.Authority, now, action));
            o.Store.Put(cur);
            o.OnChange?.Invoke("amend", cur);
            return (View(cur, true), false);
        }
        var nid = o.NewId("grant");
        var fresh = new JD(cur)
        {
            ["id"] = nid, ["authority"] = v.Authority, ["rev"] = G.N(1), ["status"] = "active", ["supersedes"] = cur["id"], ["created_at"] = G.N(now),
            ["history"] = new JL { HistoryEntry(1, v.Authority, now, "supersedes:" + (string)cur["id"]!) },
        };
        fresh.Remove("superseded_by");
        cur["status"] = "superseded";
        cur["superseded_by"] = nid;
        o.Store.Put(fresh);
        o.Store.Put(cur);
        o.OnChange?.Invoke("supersede", fresh);
        return (View(fresh, true), true);
    }

    /// <summary>Revoke. Authorised by the principal's signature over {grant id, scope} (<paramref name="auth"/> has a <c>sig</c>) or by a host-authenticated
    /// admin (<c>{admin: true}</c>). <c>agent</c> revokes every grant of the grant's agent and principal; <c>subtree</c> the grant and every descendant by <c>parent</c>.</summary>
    public List<string> Revoke(string id, object? scope, JD auth)
    {
        if (scope is not ("grant" or "agent" or "subtree")) throw new GrantError("bad_request", "unknown scope");
        var sc = (string)scope;
        var root = Must(id);
        if (auth.ContainsKey("sig"))
        {
            var rv = K3.VerifyRevokeSignature(root, sc, auth["sig"]);
            if (!rv.Ok) throw Fail(rv.Code!);
        }
        else if (G.Get(auth, "admin") is not true) throw new GrantError("forbidden", "not authorised");
        var all = o.Store.List();
        List<JD> hit;
        if (sc == "grant") hit = new List<JD> { root };
        else if (sc == "agent") hit = all.Where(g => Equals(G.Get(g, "agent"), G.Get(root, "agent")) && Equals(G.Get(g, "principal"), G.Get(root, "principal"))).ToList();
        else
        {
            var ids = new HashSet<string>(StringComparer.Ordinal) { id };
            for (bool grew = true; grew;)
            {
                grew = false;
                foreach (var g in all)
                    if (G.Get(g, "parent") is string p && ids.Contains(p) && !ids.Contains((string)g["id"]!)) { ids.Add((string)g["id"]!); grew = true; }
            }
            hit = all.Where(g => ids.Contains((string)g["id"]!)).ToList();
        }
        var revoked = new List<string>();
        foreach (var g in hit)
        {
            if (G.Get(g, "status") is "revoked") continue;
            g["status"] = "revoked";
            ((JL)g["history"]!).Add(HistoryEntry(G.L(g["rev"]), g["authority"], o.Now(), "revoke:" + sc));
            o.Store.Put(g);
            revoked.Add((string)g["id"]!);
        }
        o.OnRevoke?.Invoke(revoked, sc, root);
        o.OnChange?.Invoke("revoke", root);
        return revoked;
    }

    static bool LimitsOk(object? l) => l is JD d && d.Values.All(v => v is Num && IntentJs.IsFinite(v) && IntentJs.NumOf(v)!.Value >= 0);

    /// <summary>Agent side: ask for more. Typed needs only; no authority changes until the principal approves.</summary>
    public JD RequestNeeds(string grantId, object? needs)
    {
        var g = Must(grantId);
        if (G.Get(g, "status") is not "active") throw new GrantError("not_active", "grant is " + G.Get(g, "status"));
        if (needs is not JL list || list.Count < 1 || list.Count > 32) throw new GrantError("bad_request", "1..32 needs");
        foreach (var n in list)
        {
            if (n is not JD nd || !G.Str(G.Get(nd, "verb"), 128) || !G.Str(G.Get(nd, "resource"), 512) || (nd.ContainsKey("limits") && !LimitsOk(nd["limits"]))) throw new GrantError("bad_request", "malformed need");
            var e = o.ValidateNeed?.Invoke(nd);
            if (!string.IsNullOrEmpty(e)) throw new GrantError("bad_request", e);
        }
        var nr = new JD { ["id"] = o.NewId("need"), ["grant_id"] = grantId, ["needs"] = G.Clone(list), ["status"] = "pending", ["created_at"] = G.N(o.Now()) };
        o.Store.PutNeed(nr);
        o.OnChange?.Invoke("need", g);
        return G.CloneD(nr);
    }

    /// <summary>Principal side: approve the delta. <paramref name="approved"/> must cover the same needs in order, amounts only LOWERED and only when adjustable.</summary>
    public (JD Grant, bool Created) ApproveNeeds(string needId, object? approved, object? sig, string? stepUpRef = null)
    {
        var nr = o.Store.GetNeed(needId) ?? throw new GrantError("not_found", "no such need request");
        if (G.Get(nr, "status") is not "pending") throw new GrantError("conflict", "need request is " + G.Get(nr, "status"));
        var g = Must((string)nr["grant_id"]!);
        var v = K3.VerifyNeedApproval(nr, g, approved, sig, false);
        if (!v.Ok && v.Code == "step_up_required" && !string.IsNullOrEmpty(stepUpRef) && o.VerifyStepUp != null && o.VerifyStepUp(stepUpRef, g)) v = K3.VerifyNeedApproval(nr, g, approved, sig, true);
        if (!v.Ok) throw Fail(v.Code!);
        var nid = o.NewId("grant");
        var now = o.Now();
        var fresh = new JD(g)
        {
            ["id"] = nid, ["authority"] = v.Authority, ["rev"] = G.N(1), ["status"] = "active", ["supersedes"] = g["id"], ["created_at"] = G.N(now),
            ["history"] = new JL { HistoryEntry(1, v.Authority, now, "needs:" + needId) },
        };
        fresh.Remove("superseded_by");
        g["status"] = "superseded";
        g["superseded_by"] = nid;
        nr["status"] = "approved";
        nr["result_grant_id"] = nid;
        o.Store.Put(fresh);
        o.Store.Put(g);
        o.Store.PutNeed(nr);
        o.OnChange?.Invoke("supersede", fresh);
        return (View(fresh, true), true);
    }

    /// <summary>The grant a need request belongs to.</summary>
    public string NeedGrantId(string needId) => (string)(o.Store.GetNeed(needId) ?? throw new GrantError("not_found", "no such need request"))["grant_id"]!;

    public void DenyNeeds(string needId)
    {
        var nr = o.Store.GetNeed(needId) ?? throw new GrantError("not_found", "no such need request");
        if (G.Get(nr, "status") is not "pending") throw new GrantError("conflict", "need request is " + G.Get(nr, "status"));
        nr["status"] = "denied";
        o.Store.PutNeed(nr);
    }

    // ---- signed message bodies ----
    public static JD AmendMessage(JD grant, string action, JD authority) => K3.AmendMessage(grant, action, authority);
    public static JD GrantRevokeMessage(object? id, string scope) => K3.GrantRevokeMessage(id, scope);
    public static JD NeedApproveMessage(JD needRequest, object? rev, object? approved) => K3.NeedApproveMessage(needRequest, rev, approved);
}
