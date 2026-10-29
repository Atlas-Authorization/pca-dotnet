// BREAK-GLASS GRANTS (verification side): a pre-authorized, short-lived, small-budget emergency grant with a mandatory signed review
// after the fact. A use is recorded only when the enforcement point reports the notification delivered; a holder whose review is
// overdue, or whose use was judged unjustified, is frozen. Port of packages/pca-grants/src/breakglass.ts; replays
// packages/pca/conformance/break-glass-vectors.json. Everything is total. State is kept per holder (one atomic document per holder).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Ok true: Replaced is set. Otherwise Code names the refusal.</summary>
public sealed record BreakGlassResult(bool Ok, string? Code = null, bool Replaced = false);

/// <summary>Decision is allow or deny; Code on deny; Id when known; Use, Remaining, ReviewDue on allow.</summary>
public sealed record BreakGlassDecision(string Decision, string? Code = null, string? Id = null, long Use = 0, long Remaining = 0, long ReviewDue = 0);

public sealed record BreakGlassPolicy(IReadOnlyList<string> Authorities, IReadOnlyList<string> Reviewers);

public sealed class BreakGlassRegistry
{
    sealed class Entry
    {
        public JD Rec = new();
        public List<long> UseAt = new();
        public JD? Review;
    }

    readonly BreakGlassPolicy policy;
    readonly Dictionary<string, Dictionary<string, Entry>> holders = new();
    readonly object gate = new();

    public BreakGlassRegistry(BreakGlassPolicy policy) { this.policy = policy; }

    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }
    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    static bool Frozen(Dictionary<string, Entry>? grants, long now) =>
        grants != null && grants.Values.Any(e => e.Review is { } rv ? (string?)rv["outcome"] == "unjustified" : e.UseAt.Count > 0 && now >= e.UseAt[0] + L(e.Rec["review_within"]));

    /// <summary>Register an issued record. A frozen holder gets no new one.</summary>
    public BreakGlassResult Accept(object? rec, object? now)
    {
        lock (gate)
        {
            if (!BreakGlass.VerifyBreakGlass(rec) || !Pca.SafeNat(now, out var n)) return new(false, "bad_record");
            var r = (JD)rec!;
            if (!policy.Authorities.Contains((string)r["authority"]!)) return new(false, "unknown_authority");
            var holder = (string)r["holder"]!; var id = (string)r["id"]!;
            if (!holders.TryGetValue(holder, out var grants)) holders[holder] = grants = new();
            if (grants.TryGetValue(id, out var cur)) return (string)cur.Rec["sig"]! == (string)r["sig"]! ? new(true, null, false) : new(false, "id_conflict");
            if (Frozen(grants, n)) return new(false, "holder_frozen");
            grants[id] = new Entry { Rec = r };
            return new(true, null, true);
        }
    }

    /// <summary>Record one use; notified must be true. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification.</summary>
    public BreakGlassDecision Use(object? id, object? holder, object? actionDigest, object? now, object? notified)
    {
        lock (gate)
        {
            if (!Str(id, 128) || !Str(holder, 128) || !Str(actionDigest, 128) || !Pca.SafeNat(now, out var n) || notified is not bool ok) return new("deny", "bad_input");
            var i = (string)id!;
            if (!holders.TryGetValue((string)holder!, out var grants) || !grants.TryGetValue(i, out var e)) return new("deny", "unknown_break_glass", i);
            if (Frozen(grants, n)) return new("deny", "holder_frozen", i);
            if (e.Review is { } rv && (string?)rv["outcome"] == "unjustified") return new("deny", "revoked", i);
            if (n < L(e.Rec["issued_at"])) return new("deny", "not_yet_valid", i);
            if (n >= L(e.Rec["expires_at"])) return new("deny", "expired", i);
            if (e.UseAt.Count >= L(e.Rec["max_uses"])) return new("deny", "budget_exhausted", i);
            if (!ok) return new("deny", "not_notified", i);
            e.UseAt.Add(n);
            return new("allow", null, i, e.UseAt.Count, L(e.Rec["max_uses"]) - e.UseAt.Count, e.UseAt[0] + L(e.Rec["review_within"]));
        }
    }

    /// <summary>Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze.</summary>
    public BreakGlassResult Review(object? rec, object? holder, object? now)
    {
        lock (gate)
        {
            if (!BreakGlass.VerifyReview(rec) || !Str(holder, 128) || !Pca.SafeNat(now, out var n)) return new(false, "bad_record");
            var r = (JD)rec!;
            if (!policy.Reviewers.Contains((string)r["reviewer"]!)) return new(false, "unknown_reviewer");
            if (!holders.TryGetValue((string)holder!, out var grants) || !grants.TryGetValue((string)r["id"]!, out var e)) return new(false, "unknown_break_glass");
            var reviewer = (string)r["reviewer"]!;
            if (reviewer == (string)e.Rec["holder"]! || reviewer == (string)e.Rec["authority"]!) return new(false, "sod");
            if (e.Review != null) return (string)e.Review["sig"]! == (string)r["sig"]! ? new(true, null, false) : new(false, "already_reviewed");
            if (e.UseAt.Count == 0) return new(false, "nothing_to_review");
            if (L(r["at"]) < e.UseAt[0] || L(r["at"]) > n) return new(false, "bad_time");
            e.Review = r;
            return new(true, null, true);
        }
    }

    /// <summary>Fail closed: malformed input is frozen.</summary>
    public bool IsFrozen(object? holder, object? now)
    {
        lock (gate)
        {
            if (!Str(holder, 128) || !Pca.SafeNat(now, out var n)) return true;
            return Frozen(holders.GetValueOrDefault((string)holder!), n);
        }
    }
}

public static class BreakGlass
{
    public const string Domain = "atlas-pca/break-glass/v1\0";
    public const string ReviewDomain = "atlas-pca/break-glass-review/v1\0";
    public const long MaxWindowMs = 86_400_000;
    public const long MaxUses = 16;
    public const long MaxReviewWithinMs = 30L * 86_400_000;
    static readonly string[] BodyKeys = { "v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority" };
    static readonly string[] ReviewKeys = { "v", "id", "outcome", "notes_digest", "at", "reviewer" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;
    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }

    static JD? WellFormed(object? v)
    {
        if (v is not JD b || !Pca.SafeNat(b.GetValueOrDefault("v"), out var ver) || ver != 1) return null;
        if (!Str(b.GetValueOrDefault("id"), 128) || !Str(b.GetValueOrDefault("holder"), 128) || !Str(b.GetValueOrDefault("grant_ref"), 256)) return null;
        if (!Str(b.GetValueOrDefault("reason_digest"), 128) || !Str(b.GetValueOrDefault("notify_to"), 256) || !Str(b.GetValueOrDefault("authority"), 128)) return null;
        foreach (var k in new[] { "max_uses", "issued_at", "expires_at", "review_within" }) if (!Pca.SafeNat(b.GetValueOrDefault(k), out _)) return null;
        var uses = L(b["max_uses"]);
        if (uses < 1 || uses > MaxUses) return null;
        var issued = L(b["issued_at"]); var expires = L(b["expires_at"]);
        if (expires <= issued || expires - issued > MaxWindowMs) return null;
        var rw = L(b["review_within"]);
        return rw >= 1 && rw <= MaxReviewWithinMs ? b : null;
    }

    public static bool VerifyBreakGlass(object? v)
    {
        var b = WellFormed(v);
        if (b == null) return false;
        var body = new JD();
        foreach (var k in BodyKeys) body[k] = b[k];
        return Pca.VerifyDomain(Domain, body, b["authority"], b.GetValueOrDefault("sig"));
    }

    static JD? ReviewWellFormed(object? v)
    {
        if (v is not JD r || !Pca.SafeNat(r.GetValueOrDefault("v"), out var ver) || ver != 1) return null;
        if (!Str(r.GetValueOrDefault("id"), 128) || !Str(r.GetValueOrDefault("notes_digest"), 128) || !Str(r.GetValueOrDefault("reviewer"), 128)) return null;
        if (r.GetValueOrDefault("outcome") is not ("justified" or "unjustified")) return null;
        return Pca.SafeNat(r.GetValueOrDefault("at"), out _) ? r : null;
    }

    public static bool VerifyReview(object? v)
    {
        var r = ReviewWellFormed(v);
        if (r == null) return false;
        var body = new JD();
        foreach (var k in ReviewKeys) body[k] = r[k];
        return Pca.VerifyDomain(ReviewDomain, body, r["reviewer"], r.GetValueOrDefault("sig"));
    }
}
