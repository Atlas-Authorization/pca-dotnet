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

public sealed record LeasePolicy(IReadOnlyList<string> Authorities, long MinApprovals = 1, IReadOnlyList<string>? EligibleApprovers = null, bool FreshJustification = true);

public sealed class LeaseRegistry
{
    internal sealed class State { public JD Current = new(); public List<LeaseHistoryEntry> History = new(); }

    internal readonly Dictionary<string, State> Leases = new();
    internal readonly List<JD> Revocations = new();
    readonly LeasePolicy policy;
    internal readonly object Gate = new();

    public LeaseRegistry(LeasePolicy policy) { this.policy = policy; }

    static long L(object? o) { Pca.SafeNat(o, out var n); return n; }

    /// <summary>Take an issue (seq 1) or a renewal (seq = current + 1). chain: the keys in the holder's delegation chain.</summary>
    public LeaseAccept Accept(object? rec, IReadOnlyList<string>? chain = null)
    {
        lock (Gate)
        {
            if (!Lease.VerifyLease(rec)) return new(false, "bad_record");
            var l = (JD)rec!;
            if (!policy.Authorities.Contains((string)l["authority"]!)) return new(false, "unknown_authority");
            var approvers = ((List<object?>)l["approvers"]!).Select(a => (string)a!).ToList();
            var sod = Lease.SodError((string)l["requester"]!, (string)l["holder"]!, approvers, policy.MinApprovals, policy.EligibleApprovers, chain);
            if (sod != null) return new(false, "sod", Reason: sod);
            if (L(l["expires_at"]) > Lease.Cap(l)) return new(false, "over_max_ttl");
            if (Revocations.Any(r => Lease.Covers(r, l))) return new(false, "revoked");
            var id = (string)l["lease_id"]!;
            var seq = L(l["seq"]);
            Leases.TryGetValue(id, out var st);
            if (st == null)
            {
                if (seq != 1) return new(false, "bad_seq", Reason: "a new lease starts at seq 1");
            }
            else
            {
                var cur = st.Current;
                var cs = L(cur["seq"]);
                if (seq < cs) return new(false, "stale_seq");
                if (seq == cs) return (string)cur["sig"]! == (string)l["sig"]! ? new(true, null, false, seq) : new(false, "lease_fork");
                if (seq != cs + 1) return new(false, "bad_seq", Reason: "renewals advance seq by exactly 1");
                foreach (var k in new[] { "authority", "path", "grant_ref", "holder", "requester" }) if ((string)l[k]! != (string)cur[k]!) return new(false, "renewal_mismatch");
                foreach (var k in new[] { "max_ttl", "issued_at" }) if (L(l[k]) != L(cur[k])) return new(false, "renewal_mismatch");
                if (L(l["renewed_at"]) >= L(cur["expires_at"])) return new(false, "expired_lease", Reason: "an expired lease cannot be renewed");
                if (L(l["renewed_at"]) < L(cur["renewed_at"]) || L(l["expires_at"]) <= L(cur["expires_at"])) return new(false, "not_extending");
                if (policy.FreshJustification && (string)l["justification_digest"]! == (string)cur["justification_digest"]!) return new(false, "stale_justification");
            }
            var entry = new LeaseHistoryEntry(seq, L(l["renewed_at"]), L(l["expires_at"]), (string)l["justification_digest"]!);
            if (st == null) Leases[id] = new State { Current = l, History = new() { entry } };
            else { st.Current = l; st.History.Add(entry); }
            return new(true, null, true, seq);
        }
    }

    /// <summary>Take a signed revocation. Idempotent.</summary>
    public LeaseRevoke Revoke(object? rec)
    {
        lock (Gate)
        {
            if (!Lease.VerifyRevocation(rec)) return new(false, "bad_record");
            var r = (JD)rec!;
            if (!policy.Authorities.Contains((string)r["authority"]!)) return new(false, "unknown_authority");
            if (!Revocations.Any(x => (string)x["sig"]! == (string)r["sig"]!)) Revocations.Add(r);
            return new(true, null, Leases.Values.Count(s => Lease.Covers(r, s.Current)));
        }
    }

    public JD? Get(string id) { lock (Gate) return Leases.TryGetValue(id, out var s) ? s.Current : null; }

    public IReadOnlyList<LeaseHistoryEntry> History(string id) { lock (Gate) return Leases.TryGetValue(id, out var s) ? s.History.ToList() : new List<LeaseHistoryEntry>(); }
}

public static class Lease
{
    public const string Domain = "atlas-pca/lease/v1\0";
    public const string RevokeDomain = "atlas-pca/lease-revoke/v1\0";
    const int MaxApprovers = 16;
    static readonly Regex PathRe = new(@"\A[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}\z", RegexOptions.CultureInvariant);
    static readonly string[] BodyKeys = { "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority" };
    static readonly string[] RevKeys = { "v", "target", "value", "revoked_at", "authority" };

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
        if (minApprovals < 1) return "minApprovals must be a positive integer";
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
        lock (registry.Gate)
        {
            if (!registry.Leases.TryGetValue(id, out var st)) return new("deny", "unknown_lease", id);
            var cur = st.Current;
            if ((string)cur["sig"]! != (string)p["sig"]!) return new("deny", "superseded", id);
            if (registry.Revocations.Any(r => Covers(r, cur))) return new("deny", "revoked", id);
            if (n < L(cur["renewed_at"])) return new("deny", "not_yet_valid", id);
            if (n >= Cap(cur)) return new("deny", "past_max_ttl", id);
            if (n >= L(cur["expires_at"])) return new("deny", "expired", id);
            return new("allow", null, id, L(cur["expires_at"]));
        }
    }
}
