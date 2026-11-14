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

/// <summary>One numbered use of a break-glass grant.</summary>
public sealed record BreakGlassUseEntry(long N, string ActionDigest, long At);

/// <summary>State is kept per holder shard (one atomic document per shard, the holder's id hashed over the shard count), on a REQUIRED durable store
/// (<see cref="MemoryAtomicKv"/> is for tests and single-process use): a registry over a process-local default would forget a spent budget and an overdue
/// freeze on restart. Any store failure is <c>store_unreachable</c> (frozen for <see cref="IsFrozen"/>). Port of packages/pca-grants/src/breakglass.ts.</summary>
public sealed class BreakGlassRegistry
{
    const string MetaKey = "breakglass/meta";

    sealed class Entry
    {
        public JD Rec = new();
        public List<BreakGlassUseEntry> Uses = new();
        public JD? Review;
    }

    readonly BreakGlassPolicy policy;
    readonly IAtomicKv kv;
    readonly int shards;
    bool metaOk;

    public BreakGlassRegistry(BreakGlassPolicy policy, IAtomicKv kv, int shards = LeaseRegistry.DefaultShards)
    {
        if (kv == null) throw new ArgumentException("BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)", nameof(kv));
        if (shards < 1 || shards > LeaseRegistry.MaxShards) throw new ArgumentOutOfRangeException(nameof(shards), "BreakGlassRegistry: shards must be an integer from 1 to 4096");
        this.policy = policy;
        this.kv = kv;
        this.shards = shards;
    }

    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }
    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    string Key(string holder) => $"breakglass/{shards}/{LeaseRegistry.ShardOf(holder, shards)}";

    static Dictionary<string, Entry> Load(string? text)
    {
        try
        {
            if (text != null && Pca.ParseJson(text) is JD d && d.GetValueOrDefault("grants") is JD grants)
            {
                var o = new Dictionary<string, Entry>(StringComparer.Ordinal);
                foreach (var (id, v) in grants)
                {
                    if (v is not JD e || e.GetValueOrDefault("rec") is not JD rec || e.GetValueOrDefault("uses") is not List<object?> uses) return new();
                    var en = new Entry { Rec = rec, Review = e.GetValueOrDefault("review") as JD };
                    foreach (var u in uses)
                    {
                        if (u is not JD uj || !Pca.SafeNat(uj.GetValueOrDefault("n"), out var n) || uj.GetValueOrDefault("action_digest") is not string ad || !Pca.SafeNat(uj.GetValueOrDefault("at"), out var at)) return new();
                        en.Uses.Add(new BreakGlassUseEntry(n, ad, at));
                    }
                    o[id] = en;
                }
                return o;
            }
        }
        catch (Exception) { /* an unreadable document is an empty shard */ }
        return new();
    }

    static string Serialize(Dictionary<string, Entry> grants)
    {
        var g = new JD();
        foreach (var (id, e) in grants)
        {
            var o = new JD
            {
                ["rec"] = e.Rec,
                ["uses"] = e.Uses.Select(u => (object?)new JD { ["n"] = IntentJs.OfLong(u.N), ["action_digest"] = u.ActionDigest, ["at"] = IntentJs.OfLong(u.At) }).ToList(),
            };
            if (e.Review != null) o["review"] = e.Review;
            g[id] = o;
        }
        return Pca.Canonicalize(new JD { ["grants"] = g });
    }

    bool Ready()
    {
        if (metaOk) return true;
        kv.Update(MetaKey, prev => prev == null ? Pca.Canonicalize(new JD { ["v"] = IntentJs.OfLong(1), ["shards"] = IntentJs.OfLong(shards) }) : null);
        var m = kv.Get(MetaKey);
        metaOk = m != null && Pca.ParseJson(m) is JD d && Pca.SafeNat(d.GetValueOrDefault("shards"), out var n) && n == shards;
        return metaOk;
    }

    /// <summary>Frozen: a grant of this holder was judged unjustified, or has uses, no review and a review clock that has run out.</summary>
    static bool FrozenIn(Dictionary<string, Entry> grants, string holder, long now) =>
        grants.Values.Any(e => (string)e.Rec["holder"]! == holder
            && (e.Review is { } rv ? (string?)rv["outcome"] == "unjustified" : e.Uses.Count > 0 && now >= e.Uses[0].At + L(e.Rec["review_within"])));

    /// <summary>Register an issued record. A frozen holder gets no new one.</summary>
    public BreakGlassResult Accept(object? rec, object? now)
    {
        if (!BreakGlass.VerifyBreakGlass(rec) || !Pca.SafeNat(now, out var n)) return new(false, "bad_record");
        var r = (JD)rec!;
        if (!policy.Authorities.Contains((string)r["authority"]!)) return new(false, "unknown_authority");
        var holder = (string)r["holder"]!; var id = (string)r["id"]!;
        BreakGlassResult result = new(false, "store_unreachable");
        try
        {
            if (!Ready()) return result;
            kv.Update(Key(holder), prev =>
            {
                var grants = Load(prev);
                if (grants.TryGetValue(id, out var cur)) { result = (string)cur.Rec["sig"]! == (string)r["sig"]! ? new(true, null, false) : new(false, "id_conflict"); return null; }
                if (FrozenIn(grants, holder, n)) { result = new(false, "holder_frozen"); return null; }
                grants[id] = new Entry { Rec = r };
                result = new(true, null, true);
                return Serialize(grants);
            });
        }
        catch (Exception) { return new(false, "store_unreachable"); }
        return result;
    }

    /// <summary>Record one use; notified must be true. Checks in order: input, existence, holder, freeze, revocation by review, window, budget, notification.</summary>
    public BreakGlassDecision Use(object? id, object? holder, object? actionDigest, object? now, object? notified)
    {
        if (!Str(id, 128) || !Str(holder, 128) || !Str(actionDigest, 128) || !Pca.SafeNat(now, out var n) || notified is not bool ok) return new("deny", "bad_input");
        var i = (string)id!; var h = (string)holder!; var ad = (string)actionDigest!;
        BreakGlassDecision result = new("deny", "store_unreachable", i);
        try
        {
            if (!Ready()) return result;
            kv.Update(Key(h), prev =>
            {
                var grants = Load(prev);
                BreakGlassDecision? Deny(string code) { result = new("deny", code, i); return null; }
                if (!grants.TryGetValue(i, out var e)) { Deny("unknown_break_glass"); return null; }
                if ((string)e.Rec["holder"]! != h) { Deny("wrong_holder"); return null; }
                if (FrozenIn(grants, h, n)) { Deny("holder_frozen"); return null; }
                if (e.Review is { } rv && (string?)rv["outcome"] == "unjustified") { Deny("revoked"); return null; }
                if (n < L(e.Rec["issued_at"])) { Deny("not_yet_valid"); return null; }
                if (n >= L(e.Rec["expires_at"])) { Deny("expired"); return null; }
                if (e.Uses.Count >= L(e.Rec["max_uses"])) { Deny("budget_exhausted"); return null; }
                if (!ok) { Deny("not_notified"); return null; }
                e.Uses.Add(new BreakGlassUseEntry(e.Uses.Count + 1, ad, n));
                result = new("allow", null, i, e.Uses.Count, L(e.Rec["max_uses"]) - e.Uses.Count, e.Uses[0].At + L(e.Rec["review_within"]));
                return Serialize(grants);
            });
        }
        catch (Exception) { return new("deny", "store_unreachable", i); }
        return result;
    }

    /// <summary>Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze.</summary>
    public BreakGlassResult Review(object? rec, object? holder, object? now)
    {
        if (!BreakGlass.VerifyReview(rec) || !Str(holder, 128) || !Pca.SafeNat(now, out var n)) return new(false, "bad_record");
        var r = (JD)rec!;
        if (!policy.Reviewers.Contains((string)r["reviewer"]!)) return new(false, "unknown_reviewer");
        var h = (string)holder!;
        BreakGlassResult result = new(false, "store_unreachable");
        try
        {
            if (!Ready()) return result;
            kv.Update(Key(h), prev =>
            {
                var grants = Load(prev);
                BreakGlassResult? Fail(string code) { result = new(false, code); return null; }
                if (!grants.TryGetValue((string)r["id"]!, out var e) || (string)e.Rec["holder"]! != h) { Fail("unknown_break_glass"); return null; }
                var reviewer = (string)r["reviewer"]!;
                if (reviewer == (string)e.Rec["holder"]! || reviewer == (string)e.Rec["authority"]!) { Fail("sod"); return null; }
                if (e.Review != null)
                {
                    if ((string)e.Review["sig"]! == (string)r["sig"]!) result = new(true, null, false); else Fail("already_reviewed");
                    return null;
                }
                if (e.Uses.Count == 0) { Fail("nothing_to_review"); return null; }
                if (L(r["at"]) < e.Uses[0].At || L(r["at"]) > n) { Fail("bad_time"); return null; }
                e.Review = r;
                result = new(true, null, true);
                return Serialize(grants);
            });
        }
        catch (Exception) { return new(false, "store_unreachable"); }
        return result;
    }

    /// <summary>Fail closed: malformed input, an unreachable store and a mismatched shard count are all frozen.</summary>
    public bool IsFrozen(object? holder, object? now)
    {
        if (!Str(holder, 128) || !Pca.SafeNat(now, out var n)) return true;
        try
        {
            if (!Ready()) return true;
            var h = (string)holder!;
            return FrozenIn(Load(kv.Get(Key(h))), h, n);
        }
        catch (Exception) { return true; }
    }

    /// <summary>The numbered use log of a grant, oldest first (empty when the grant or the shard is unknown).</summary>
    public IReadOnlyList<BreakGlassUseEntry> Uses(string holder, string id)
    {
        if (!Ready()) return new List<BreakGlassUseEntry>();
        return Load(kv.Get(Key(holder))).TryGetValue(id, out var e) ? e.Uses.ToList() : new List<BreakGlassUseEntry>();
    }
}

public static class BreakGlass
{
    public const string Domain = "atlas-pca/break-glass/v1\0";
    public const string ReviewDomain = "atlas-pca/break-glass-review/v1\0";
    public const long MaxWindowMs = 86_400_000;
    public const long MaxUses = 16;
    public const long MaxReviewWithinMs = 30L * 86_400_000;
    static string[] BodyKeys => new string[] { "v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority" };
    static string[] ReviewKeys => new string[] { "v", "id", "outcome", "notes_digest", "at", "reviewer" };

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
