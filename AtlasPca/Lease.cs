// LEASES (verification side): a time-boxed grant or credential that must be renewed to stay alive, has a hard max_ttl it can never
// outlive, and dies at once when revoked. A lease authority signs a record; LeaseRegistry keeps the newest record per lease_id.
// Port of packages/pca-grants/src/lease.ts; replays packages/pca/conformance/lease-vectors.json. Everything is total.
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record LeaseAccept(bool Ok, string? Code = null, bool Replaced = false, long Seq = 0, string? Reason = null);

public sealed record LeaseRevoke(bool Ok, string? Code = null, int Revoked = 0);

/// <summary>Decision is "allow" or "deny"; Code is set on deny; LeaseId when known; ExpiresAt on allow.</summary>
public sealed record LeaseDecision(string Decision, string? Code = null, string? LeaseId = null, long? ExpiresAt = null);

public sealed record LeaseHistoryEntry(long Seq, long RenewedAt, long ExpiresAt, string JustificationDigest);

public sealed record LeasePolicy(IReadOnlyList<string> Authorities, long MinApprovals = 1, IReadOnlyList<string>? EligibleApprovers = null, bool FreshJustification = true, long? MaxTtlCeiling = null);

/// <summary>Options of a <see cref="LeaseRegistry"/>: the shard count (fixed for the life of the store) and the pruning clock.</summary>
public sealed record LeaseRegistryOptions(int Shards = LeaseRegistry.DefaultShards, Func<long>? Clock = null);

/// <summary>The registry keeps each lease in the shard its id hashes to, so an issue, a renewal and a check read and write one small document, and
/// unrelated leases never contend for one value. A path-prefix or grant revocation is written to EVERY shard (it can cover leases anywhere); a revocation
/// of one lease id only to that lease's shard. Within a shard each operation is one atomic <see cref="IAtomicKv.Update"/>. The registry holds
/// revocations, so a process-local default would forget them on restart: the store is REQUIRED (<see cref="MemoryAtomicKv"/> is for tests and
/// single-process use). Any store failure is reported as <c>store_unreachable</c>, never as a pass. Port of packages/pca-grants/src/lease.ts.</summary>
public sealed class LeaseRegistry
{
    public const int DefaultShards = 16, MaxShards = 4096;
    const string MetaKey = "lease/meta";

    /// <summary>One shard's document: the leases whose id hashes here and every prefix / grant revocation.</summary>
    internal sealed class Shard
    {
        public Dictionary<string, (JD Current, List<LeaseHistoryEntry> History)> Leases = new(StringComparer.Ordinal);
        public List<JD> Revocations = new();
    }

    readonly LeasePolicy policy;
    readonly IAtomicKv kv;
    readonly int shards;
    readonly Func<long> clock;
    bool metaOk;

    /// <param name="policy">The registry policy. <c>MaxTtlCeiling</c> (ms) refuses a longer <c>max_ttl</c> (<c>ttl_ceiling</c>) and prunes a revocation once
    /// <c>revoked_at + ceiling</c> is past (every lease it could cover is then beyond its own cap); absent, nothing is ever pruned.</param>
    /// <param name="kv">The durable key-value store (required).</param>
    /// <param name="options">The shard count (default 16; a store opened with another count is refused) and the pruning clock (epoch ms; the system clock by default).</param>
    public LeaseRegistry(LeasePolicy policy, IAtomicKv kv, LeaseRegistryOptions? options = null)
    {
        // The registry holds revocations: a process-local default would forget them on restart, so the store is required.
        if (kv == null) throw new ArgumentException("LeaseRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)", nameof(kv));
        var o = options ?? new LeaseRegistryOptions();
        if (o.Shards < 1 || o.Shards > MaxShards) throw new ArgumentOutOfRangeException(nameof(options), "LeaseRegistry: shards must be an integer from 1 to 4096");
        if (policy.MaxTtlCeiling is long c && (c < 1 || c > 9007199254740991L)) throw new ArgumentOutOfRangeException(nameof(policy), "LeaseRegistry: maxTtlCeiling must be a positive integer");
        this.policy = policy;
        this.kv = kv;
        shards = o.Shards;
        clock = o.Clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public int ShardCount => shards;

    static string ShardKey(int n, int i) => $"lease/{n}/{i}";

    /// <summary>The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes.</summary>
    internal static int ShardOf(string id, int shards)
    {
        var h = Pca.Sha256Of(System.Text.Encoding.UTF8.GetBytes(id));
        return (int)((((uint)h[0] << 24) | ((uint)h[1] << 16) | ((uint)h[2] << 8) | h[3]) % (uint)shards);
    }

    static Shard Load(string? text)
    {
        try
        {
            if (text != null && Pca.ParseJson(text) is JD d && d.GetValueOrDefault("leases") is JD leases && d.GetValueOrDefault("revocations") is List<object?> revs)
            {
                var st = new Shard();
                foreach (var (id, v) in leases)
                {
                    if (v is not JD ls || ls.GetValueOrDefault("current") is not JD cur || ls.GetValueOrDefault("history") is not List<object?> hist) return new Shard();
                    var h = new List<LeaseHistoryEntry>();
                    foreach (var e in hist)
                    {
                        if (e is not JD he || !Pca.SafeNat(he.GetValueOrDefault("seq"), out var sq) || !Pca.SafeNat(he.GetValueOrDefault("renewed_at"), out var ra)
                            || !Pca.SafeNat(he.GetValueOrDefault("expires_at"), out var ea) || he.GetValueOrDefault("justification_digest") is not string jd) return new Shard();
                        h.Add(new LeaseHistoryEntry(sq, ra, ea, jd));
                    }
                    st.Leases[id] = (cur, h);
                }
                foreach (var r in revs) if (r is JD rj) st.Revocations.Add(rj); else return new Shard();
                return st;
            }
        }
        catch (Exception) { /* an unreadable document is an empty shard, as in the reference */ }
        return new Shard();
    }

    static string Serialize(Shard st)
    {
        var leases = new JD();
        foreach (var (id, (cur, hist)) in st.Leases)
            leases[id] = new JD
            {
                ["current"] = cur,
                ["history"] = hist.Select(h => (object?)new JD { ["seq"] = IntentJs.OfLong(h.Seq), ["renewed_at"] = IntentJs.OfLong(h.RenewedAt), ["expires_at"] = IntentJs.OfLong(h.ExpiresAt), ["justification_digest"] = h.JustificationDigest }).ToList(),
            };
        return Pca.Canonicalize(new JD { ["leases"] = leases, ["revocations"] = st.Revocations.Cast<object?>().ToList() });
    }

    /// <summary>Pin the shard count in the store on first use; a different count would make existing leases invisible, so it is refused.</summary>
    bool Ready()
    {
        if (metaOk) return true;
        kv.Update(MetaKey, prev => prev == null ? Pca.Canonicalize(new JD { ["v"] = IntentJs.OfLong(1), ["shards"] = IntentJs.OfLong(shards) }) : null);
        var m = kv.Get(MetaKey);
        metaOk = m != null && Pca.ParseJson(m) is JD d && Pca.SafeNat(d.GetValueOrDefault("shards"), out var n) && n == shards;
        return metaOk;
    }

    void Prune(Shard st)
    {
        if (policy.MaxTtlCeiling is not long c) return;
        var now = clock();
        st.Revocations.RemoveAll(r => L(r["revoked_at"]) + c < now);
    }

    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }

    /// <summary>Take an issue (seq 1) or a renewal (seq = current + 1). chain: the keys in the holder's delegation chain.</summary>
    public LeaseAccept Accept(object? rec, IReadOnlyList<string>? chain = null)
    {
        if (!Lease.VerifyLease(rec)) return new(false, "bad_record");
        var l = (JD)rec!;
        if (!policy.Authorities.Contains((string)l["authority"]!)) return new(false, "unknown_authority");
        var approvers = ((List<object?>)l["approvers"]!).Select(a => (string)a!).ToList();
        var sod = Lease.SodError((string)l["requester"]!, (string)l["holder"]!, approvers, policy.MinApprovals, policy.EligibleApprovers, chain);
        if (sod != null) return new(false, "sod", Reason: sod);
        if (L(l["expires_at"]) > Lease.Cap(l)) return new(false, "over_max_ttl");
        if (policy.MaxTtlCeiling is long ceiling && L(l["max_ttl"]) > ceiling) return new(false, "ttl_ceiling");
        var id = (string)l["lease_id"]!;
        var seq = L(l["seq"]);
        LeaseAccept result = new(false, "store_unreachable");
        try
        {
            if (!Ready()) return result;
            kv.Update(ShardKey(shards, ShardOf(id, shards)), prev =>
            {
                var st = Load(prev);
                LeaseAccept? Fail(string code, string? reason = null) { result = new(false, code, Reason: reason); return null; }
                if (st.Revocations.Any(r => Lease.Covers(r, l))) { Fail("revoked"); return null; }
                st.Leases.TryGetValue(id, out var have);
                if (have.Current == null)
                {
                    if (seq != 1) { Fail("bad_seq", "a new lease starts at seq 1"); return null; }
                }
                else
                {
                    var cur = have.Current;
                    var cs = L(cur["seq"]);
                    if (seq < cs) { Fail("stale_seq"); return null; }
                    if (seq == cs)
                    {
                        if ((string)cur["sig"]! == (string)l["sig"]!) result = new(true, null, false, seq); else Fail("lease_fork");
                        return null;
                    }
                    if (seq != cs + 1) { Fail("bad_seq", "renewals advance seq by exactly 1"); return null; }
                    foreach (var k in new[] { "authority", "path", "grant_ref", "holder", "requester" }) if ((string)l[k]! != (string)cur[k]!) { Fail("renewal_mismatch"); return null; }
                    foreach (var k in new[] { "max_ttl", "issued_at" }) if (L(l[k]) != L(cur[k])) { Fail("renewal_mismatch"); return null; }
                    if (L(l["renewed_at"]) >= L(cur["expires_at"])) { Fail("expired_lease", "an expired lease cannot be renewed"); return null; }
                    if (L(l["renewed_at"]) < L(cur["renewed_at"]) || L(l["expires_at"]) <= L(cur["expires_at"])) { Fail("not_extending"); return null; }
                    if (policy.FreshJustification && (string)l["justification_digest"]! == (string)cur["justification_digest"]!) { Fail("stale_justification"); return null; }
                }
                var entry = new LeaseHistoryEntry(seq, L(l["renewed_at"]), L(l["expires_at"]), (string)l["justification_digest"]!);
                var history = have.Current == null ? new List<LeaseHistoryEntry>() : have.History.ToList();
                history.Add(entry);
                st.Leases[id] = (l, history);
                Prune(st);
                result = new(true, null, true, seq);
                return Serialize(st);
            });
        }
        catch (Exception) { return new(false, "store_unreachable"); }
        return result;
    }

    /// <summary>Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; the count is the leases covered across all of them.</summary>
    public LeaseRevoke Revoke(object? rec)
    {
        if (!Lease.VerifyRevocation(rec)) return new(false, "bad_record");
        var r = (JD)rec!;
        if (!policy.Authorities.Contains((string)r["authority"]!)) return new(false, "unknown_authority");
        var targets = (string)r["target"]! == "lease" ? new[] { ShardOf((string)r["value"]!, shards) } : Enumerable.Range(0, shards).ToArray();
        var n = 0;
        try
        {
            if (!Ready()) return new(false, "store_unreachable");
            foreach (var i in targets)
            {
                var count = 0;
                kv.Update(ShardKey(shards, i), prev =>
                {
                    var st = Load(prev);
                    count = 0; // the store may retry: count only the attempt that lands
                    if (!st.Revocations.Any(x => (string)x["sig"]! == (string)r["sig"]!)) st.Revocations.Add(r);
                    count += st.Leases.Values.Count(s => Lease.Covers(r, s.Current));
                    Prune(st);
                    return Serialize(st);
                });
                n += count;
            }
        }
        catch (Exception) { return new(false, "store_unreachable"); }
        return new(true, null, n);
    }

    Shard ShardFor(string id)
    {
        if (!Ready()) throw new InvalidOperationException("shard count mismatch");
        return Load(kv.Get(ShardKey(shards, ShardOf(id, shards))));
    }

    /// <summary>The newest record of a lease, or null. Throws when the store cannot answer.</summary>
    public JD? Get(string id) => ShardFor(id).Leases.TryGetValue(id, out var s) ? s.Current : null;

    /// <summary>The renewal ledger of a lease, oldest first. Throws when the store cannot answer.</summary>
    public IReadOnlyList<LeaseHistoryEntry> History(string id) => ShardFor(id).Leases.TryGetValue(id, out var s) ? s.History.ToList() : new List<LeaseHistoryEntry>();

    /// <summary>The newest record of a lease and whether a stored revocation covers it. Throws when the store cannot answer.</summary>
    internal (JD Current, bool Revoked)? Lookup(string id)
    {
        var st = ShardFor(id);
        if (!st.Leases.TryGetValue(id, out var s)) return null;
        return (s.Current, st.Revocations.Any(r => Lease.Covers(r, s.Current)));
    }

    /// <summary>Revocations held by one shard (for operators and the conformance kit).</summary>
    public IReadOnlyList<JD> ShardRevocations(int i)
    {
        if (i < 0 || i >= shards) throw new ArgumentOutOfRangeException(nameof(i), "no such shard");
        return Load(kv.Get(ShardKey(shards, i))).Revocations.ToList();
    }
}

public static class Lease
{
    public const string Domain = "atlas-pca/lease/v1\0";
    public const string RevokeDomain = "atlas-pca/lease-revoke/v1\0";
    const int MaxApprovers = 16;
    static Regex PathRe => Rx.Get(@"\A[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}\z", RegexOptions.CultureInvariant);
    static string[] BodyKeys => new string[] { "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority" };
    static string[] RevKeys => new string[] { "v", "target", "value", "revoked_at", "authority" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;
    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }

    static JD? WellFormed(object? v)
    {
        if (v is not JD l || !Pca.SafeNat(l.GetValueOrDefault("v"), out var ver) || ver != 1) return null;
        if (!Str(l.GetValueOrDefault("lease_id"), 128) || !Str(l.GetValueOrDefault("grant_ref"), 256) || !Str(l.GetValueOrDefault("holder"), 128) || !Str(l.GetValueOrDefault("requester"), 128)) return null;
        if (!Str(l.GetValueOrDefault("authority"), 128) || !Str(l.GetValueOrDefault("justification_digest"), 128)) return null;
        if (l.GetValueOrDefault("path") is not string path || !PathRe.IsMatch(path)) return null;
        foreach (var k in new[] { "seq", "issued_at", "renewed_at", "expires_at", "max_ttl" }) if (!Pca.SafeNat(l.GetValueOrDefault(k), out _)) return null;
        var seq = L(l["seq"]); var issued = L(l["issued_at"]); var renewed = L(l["renewed_at"]);
        if (seq < 1 || L(l["max_ttl"]) < 1) return null;
        if (renewed < issued || L(l["expires_at"]) <= renewed || (seq == 1 && renewed != issued)) return null;
        if (l.GetValueOrDefault("approvers") is not List<object?> ap || ap.Count > MaxApprovers || !ap.All(a => Str(a, 128))) return null;
        return l;
    }

    /// <summary>issued_at + max_ttl.</summary>
    internal static long Cap(JD l) => L(l["issued_at"]) + L(l["max_ttl"]);

    /// <summary>Well formed and signed by its authority over exactly its content. Does NOT check the cap (the registry reports over_max_ttl).</summary>
    public static bool VerifyLease(object? v)
    {
        var l = WellFormed(v);
        if (l == null) return false;
        var body = new JD();
        foreach (var k in BodyKeys) body[k] = l[k];
        return Pca.VerifyDomain(Domain, body, l["authority"], l.GetValueOrDefault("sig"));
    }

    static JD? RevWellFormed(object? v)
    {
        if (v is not JD r || !Pca.SafeNat(r.GetValueOrDefault("v"), out var ver) || ver != 1) return null;
        if (!Str(r.GetValueOrDefault("value"), 256) || !Str(r.GetValueOrDefault("authority"), 128) || !Pca.SafeNat(r.GetValueOrDefault("revoked_at"), out _)) return null;
        if (r.GetValueOrDefault("target") is not string t || (t != "lease" && t != "prefix" && t != "grant")) return null;
        if (t == "prefix" && !PathRe.IsMatch((string)r["value"]!)) return null;
        return r;
    }

    public static bool VerifyRevocation(object? v)
    {
        var r = RevWellFormed(v);
        if (r == null) return false;
        var body = new JD();
        foreach (var k in RevKeys) body[k] = r[k];
        return Pca.VerifyDomain(RevokeDomain, body, r["authority"], r.GetValueOrDefault("sig"));
    }

    /// <summary>prefix covers path iff equal or path continues it at a segment boundary.</summary>
    public static bool PathUnder(string path, string prefix) => path == prefix || path.StartsWith(prefix + "/", StringComparison.Ordinal);

    internal static bool Covers(JD r, JD l)
    {
        if (L(l["issued_at"]) > L(r["revoked_at"])) return false;
        var value = (string)r["value"]!;
        return (string)r["target"]! switch
        {
            "lease" => (string)l["lease_id"]! == value,
            "grant" => (string)l["grant_ref"]! == value,
            _ => PathUnder((string)l["path"]!, value),
        };
    }

    /// <summary>Separation of duties over one record: a reason, or null. chain is every key in the holder's delegation chain.</summary>
    public static string? SodError(string requester, string holder, IReadOnlyList<string> approvers, long minApprovals = 1, IReadOnlyList<string>? eligibleApprovers = null, IReadOnlyList<string>? chain = null)
    {
        if (minApprovals < 1 || minApprovals > 9007199254740991) return "minApprovals must be a positive integer";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in approvers)
        {
            if (!seen.Add(a)) return "an approver is listed twice";
            if (a == requester) return "the requester may not approve their own request";
            if (a == holder) return "the holder may not approve its own lease";
            if (chain != null && chain.Contains(a)) return "an approver appears in the holder's delegation chain";
            if (eligibleApprovers != null && !eligibleApprovers.Contains(a)) return "an approver is not eligible";
        }
        return approvers.Count < minApprovals ? $"{approvers.Count} approver(s), need {minApprovals}" : null;
    }

    /// <summary>Is presented a live lease? It must verify, be the newest record the registry holds, be inside its window and its cap, and not be covered by a revocation. Fails closed.</summary>
    public static LeaseDecision Check(object? presented, LeaseRegistry registry, object? now)
    {
        if (!Pca.SafeNat(now, out var n)) return new("deny", "bad_input");
        if (!VerifyLease(presented)) return new("deny", "bad_record");
        var p = (JD)presented!;
        var id = (string)p["lease_id"]!;
        try
        {
            var found = registry.Lookup(id);
            if (found == null) return new("deny", "unknown_lease", id);
            var (cur, revoked) = found.Value;
            if ((string)cur["sig"]! != (string)p["sig"]!) return new("deny", "superseded", id);
            if (revoked) return new("deny", "revoked", id);
            if (n < L(cur["renewed_at"])) return new("deny", "not_yet_valid", id);
            if (n >= Cap(cur)) return new("deny", "past_max_ttl", id);
            if (n >= L(cur["expires_at"])) return new("deny", "expired", id);
            return new("allow", null, id, L(cur["expires_at"]));
        }
        catch (Exception) { return new("deny", "store_unreachable", id); }
    }
}
