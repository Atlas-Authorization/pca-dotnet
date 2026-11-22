// Signing side of the lease, lease-revocation, agent-blueprint and break-glass records (packages/pca-grants lease.ts, blueprint.ts,
// breakglass.ts). A record is accepted for signing exactly when the verifier would accept it: the record is signed over the body
// the verifier rebuilds, then checked with the very verification the registries use, so a refusal here and a refusal there cannot differ.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Grants;

public static class GrantSigning
{
    static readonly string[] LeaseKeys = { "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority" };
    static readonly string[] RevKeys = { "v", "target", "value", "revoked_at", "authority" };
    static readonly string[] BlueprintKeys = { "v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator" };
    static readonly string[] BreakGlassKeys = { "v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority" };
    static readonly string[] ReviewKeys = { "v", "id", "outcome", "notes_digest", "at", "reviewer" };

    /// <summary><c>{v: 1, ...fields, [who]: key}</c>: later members override earlier ones, as the object spread does.</summary>
    static JD Base(object? fields, EdKey key, string who)
    {
        if (fields is not JD f) throw new ArgumentException("a record must be an object");
        var b = new JD { ["v"] = new Num("1") };
        foreach (var kv in f) b[kv.Key] = kv.Value;
        b[who] = key.Id;
        return b;
    }

    static JD Signed(JD b, string domain, string[] keys, EdKey key)
    {
        var rec = new JD(b);
        rec["sig"] = Sig.SignBody(domain, G.Pick(b, keys), key);
        return rec;
    }

    /// <summary>Sign a lease record. Throws on a malformed record or one that outlives its cap (issued_at + max_ttl).</summary>
    public static JD SignLease(EdKey key, object? lease)
    {
        var rec = Signed(Base(lease, key, "authority"), Lease.Domain, LeaseKeys, key);
        if (!Lease.VerifyLease(rec) || G.L(rec["expires_at"]) > Lease.Cap(rec)) throw new ArgumentException("signLease: a malformed lease, or one past issued_at + max_ttl");
        return rec;
    }

    /// <summary>Conformance-vector builder only: signs a well-formed record that outlives its cap, to prove verifiers refuse it.</summary>
    public static JD SignLeaseUnsafeOverCap(EdKey key, object? lease)
    {
        var rec = Signed(Base(lease, key, "authority"), Lease.Domain, LeaseKeys, key);
        if (!Lease.VerifyLease(rec)) throw new ArgumentException("signLeaseUnsafeOverCap: malformed");
        return rec;
    }

    public static JD SignLeaseRevocation(EdKey key, object? revocation)
    {
        var rec = Signed(Base(revocation, key, "authority"), Lease.RevokeDomain, RevKeys, key);
        if (!Lease.VerifyRevocation(rec)) throw new ArgumentException("signLeaseRevocation: malformed");
        return rec;
    }

    /// <summary>Sign a blueprint record with the operator's key. Throws on a malformed record.</summary>
    public static JD SignBlueprint(EdKey key, object? blueprint)
    {
        var rec = Signed(Base(blueprint, key, "operator"), Blueprint.Domain, BlueprintKeys, key);
        if (!Blueprint.Verify(rec)) throw new ArgumentException("signBlueprint: a malformed blueprint");
        return rec;
    }

    public static JD SignBreakGlass(EdKey key, object? record)
    {
        var rec = Signed(Base(record, key, "authority"), BreakGlass.Domain, BreakGlassKeys, key);
        if (!BreakGlass.VerifyBreakGlass(rec)) throw new ArgumentException("signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16");
        return rec;
    }

    public static JD SignBreakGlassReview(EdKey key, object? review)
    {
        var rec = Signed(Base(review, key, "reviewer"), BreakGlass.ReviewDomain, ReviewKeys, key);
        if (!BreakGlass.VerifyReview(rec)) throw new ArgumentException("signBreakGlassReview: malformed");
        return rec;
    }
}
