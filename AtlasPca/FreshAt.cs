// Consistency tokens (`fresh_at`): a port of packages/pca/src/fresh-at.ts (the TypeScript is authoritative). A token is a signed
// high-water mark of the verifier-side state a write produced; a verifier refuses to DECIDE against state older than the token
// (`stale_state` is an escalate, never an allow). Every function is total: malformed input yields the failure value, never an exception.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>The four monotone counters plus the policy digest a token orders.</summary>
public sealed record FreshAtState(long RevocationEpoch, long LedgerTreeSize, long BudgetVersion, long PolicyRevision, string PolicyDigest)
{
    /// <summary>Reads <c>{revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}</c>; null when malformed.</summary>
    public static FreshAtState? FromJson(object? o)
    {
        if (o is not JD d || IntentJs.Get(d, "policy_digest") is not string pd) return null;
        if (!Pca.SafeNat(IntentJs.Get(d, "revocation_epoch"), out var re) || !Pca.SafeNat(IntentJs.Get(d, "ledger_tree_size"), out var lt)
            || !Pca.SafeNat(IntentJs.Get(d, "budget_version"), out var bv) || !Pca.SafeNat(IntentJs.Get(d, "policy_revision"), out var pr)) return null;
        return new FreshAtState(re, lt, bv, pr, pd);
    }
}

/// <summary><paramref name="Decision"/> is <c>ok</c>, <c>escalate</c> (Code <c>stale_state</c>, Behind lists the counters) or <c>deny</c>
/// (Code <c>bad_token</c>, <c>wrong_scope</c>, <c>token_from_the_future</c>, <c>token_too_old</c> or <c>policy_fork</c>).</summary>
public sealed record FreshAtVerdict(string Decision, string? Code, IReadOnlyList<string> Behind);

public static class FreshAt
{
    public const string Domain = "atlas-pca/fresh-at/v1\0";
    public const string RefDomain = "atlas-pca/fresh-at-ref/v1";
    /// <summary>A token issued more than this far ahead of the verifier clock is refused.</summary>
    public const long MaxFutureSkewMs = 60_000;

    static readonly string[] Numeric = { "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    static JD BodyOf(JD t) => new()
    {
        ["v"] = t["v"], ["scope"] = t["scope"], ["revocation_epoch"] = t["revocation_epoch"], ["ledger_tree_size"] = t["ledger_tree_size"],
        ["budget_version"] = t["budget_version"], ["policy_revision"] = t["policy_revision"], ["policy_digest"] = t["policy_digest"],
        ["issued_at"] = t["issued_at"], ["signer"] = t["signer"],
    };

    /// <summary>Well formed and signed by <paramref name="signer"/> over exactly its content. Never throws.</summary>
    public static bool Verify(object? token, string signer)
    {
        try
        {
            if (token is not JD d || !(IntentJs.Get(d, "v") is Num one && one.Raw == "1") || IntentJs.Get(d, "signer") is not string ts || ts != signer
                || !Str(IntentJs.Get(d, "scope"), 256) || !Str(IntentJs.Get(d, "policy_digest"), 128) || !Pca.SafeNat(IntentJs.Get(d, "issued_at"), out _)) return false;
            foreach (var k in Numeric) if (!Pca.SafeNat(IntentJs.Get(d, k), out _)) return false;
            return Pca.VerifyDomain(Domain, BodyOf(d), signer, IntentJs.Get(d, "sig"));
        }
        catch (Exception) { return false; }
    }

    /// <summary>The content address a PCActn or request signs to bind the token it carried; null when the token cannot be canonicalized.</summary>
    public static string? Digest(object? token)
    {
        try { return Pca.HashCanonical(new JD { ["d"] = RefDomain, ["t"] = token }); }
        catch (Exception) { return null; }
    }

    static FreshAtVerdict Deny(string code) => new("deny", code, Array.Empty<string>());

    /// <summary>May the verifier decide against <paramref name="local"/> for a request carrying <paramref name="token"/>? Each step fails
    /// closed, in this order: signature / shape, scope, issued in the future (more than 60 s), token age, policy fork (same revision,
    /// different digest), then any counter behind the token escalates <c>stale_state</c>.</summary>
    public static FreshAtVerdict Check(object? token, FreshAtState local, string signer, string scope, long now, long? maxTokenAgeMs = null)
    {
        try
        {
            if (!Verify(token, signer)) return Deny("bad_token");
            var t = (JD)token!;
            if ((string)t["scope"]! != scope) return Deny("wrong_scope");
            Pca.SafeNat(t["issued_at"], out var issued);
            if (!(issued <= now + MaxFutureSkewMs)) return Deny("token_from_the_future");
            if (maxTokenAgeMs is long max && !(now - issued <= max)) return Deny("token_too_old");
            Pca.SafeNat(t["policy_revision"], out var theirPolicy);
            if (theirPolicy == local.PolicyRevision && (string)t["policy_digest"]! != local.PolicyDigest) return Deny("policy_fork");
            var behind = new List<string>();
            var mine = new[] { local.RevocationEpoch, local.LedgerTreeSize, local.BudgetVersion, local.PolicyRevision };
            for (int i = 0; i < Numeric.Length; i++)
            {
                Pca.SafeNat(t[Numeric[i]], out var theirs);
                if (!(mine[i] >= theirs)) behind.Add(Numeric[i]);
            }
            return behind.Count == 0 ? new FreshAtVerdict("ok", null, Array.Empty<string>()) : new FreshAtVerdict("escalate", "stale_state", behind);
        }
        catch (Exception) { return Deny("bad_token"); }
    }

    // ---- the PCActn member + the verifier check -----------------------------------------------------------------------------

    static readonly HashSet<string> WireKeys = new()
        { "v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer", "sig" };

    /// <summary>Wire shape of the <c>fresh_at</c> member (closed key set: an unknown key would be unsigned malleability inside a signed member).
    /// Returns the problem or null. It does NOT check the signature (that is the <c>fresh_at</c> check).</summary>
    public static string? WireError(object? v)
    {
        if (v is not JD d) return "'fresh_at' must be an object";
        foreach (var k in d.Keys) if (!WireKeys.Contains(k)) return $"'fresh_at' has an unknown field '{k}'";
        if (!(IntentJs.Get(d, "v") is Num one && one.Raw == "1")) return "'fresh_at.v' must be 1";
        if (!Str(IntentJs.Get(d, "scope"), 256) || !Str(IntentJs.Get(d, "policy_digest"), 128)) return "'fresh_at' scope and policy_digest must be non-empty strings";
        foreach (var k in new[] { "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at" })
            if (!Pca.SafeNat(IntentJs.Get(d, k), out _)) return $"'fresh_at.{k}' must be a non-negative safe integer";
        if (Pca.B64uDecode(IntentJs.Get(d, "signer"), 32) == null) return "'fresh_at.signer' is not canonical base64url (32 bytes)";
        if (Pca.B64uDecode(IntentJs.Get(d, "sig"), 64) == null) return "'fresh_at.sig' is not canonical base64url (64 bytes)";
        return null;
    }

    static readonly FreshAtCheck NoCheck = new("none", null);
    static FreshAtCheck FailWith(string reason) => new("fail", reason);

    /// <summary>The verifier's <c>fresh_at</c> check. Reported (pass / fail) only when the PCActn carries the member
    /// (<paramref name="hasMember"/>), a side-carried token is read, or the policy requires one; otherwise <c>none</c> (the verdict is
    /// byte-identical to before). A stale verifier is an ESCALATE-class failure (<c>escalate: stale_state ...</c>), anything else is a hard failure.</summary>
    public static FreshAtCheck Decide(object? member, bool hasMember, FreshAtPolicy? policy, long now)
    {
        try
        {
            if (policy == null) return hasMember ? FailWith("the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)") : NoCheck;
            if (!hasMember && !policy.HasSideCarried)
                return policy.Require ? FailWith("escalate: a consistency token is required (refresh and retry with the token of your latest write)") : NoCheck;
            var token = hasMember ? member : policy.SideCarried;
            var v = Check(token, policy.Local, policy.Signer, policy.Scope, now, policy.MaxTokenAgeMs);
            if (v.Decision == "ok") return new FreshAtCheck("pass", null);
            if (v.Decision == "escalate") return FailWith($"escalate: stale_state (verifier state is behind the token on {string.Join(", ", v.Behind)})");
            return FailWith(v.Code ?? "bad_token");
        }
        catch (Exception) { return FailWith("bad_token"); }
    }
}

/// <summary>Verifier-side configuration of the <c>fresh_at</c> check. Absent policy: a PCActn that carries <c>fresh_at</c> is refused.</summary>
public sealed class FreshAtPolicy
{
    /// <summary>The pinned token signer (base64url Ed25519 public key).</summary>
    public string Signer { get; }
    /// <summary>The scope this verifier decides for; a token for another scope is refused.</summary>
    public string Scope { get; }
    /// <summary>The verifier's OWN current state counters.</summary>
    public FreshAtState Local { get; }
    public long? MaxTokenAgeMs { get; }
    /// <summary>Every PCActn must carry (or have side-carried) a token; none is <c>escalate: a consistency token is required</c>.</summary>
    public bool Require { get; }
    /// <summary>True when a side-carried token was presented (even a null one). It is read only when the PCActn has no member.</summary>
    public bool HasSideCarried { get; }
    public object? SideCarried { get; }

    public FreshAtPolicy(string signer, string scope, FreshAtState local, long? maxTokenAgeMs = null, bool require = false, bool hasSideCarried = false, object? sideCarried = null)
    {
        Signer = signer; Scope = scope; Local = local; MaxTokenAgeMs = maxTokenAgeMs; Require = require; HasSideCarried = hasSideCarried; SideCarried = sideCarried;
    }

    /// <summary>Reads <c>{signer, scope, local, max_token_age_ms?, require?, side_carried?}</c> (a present <c>side_carried</c>, null included, means a
    /// token was presented); null when malformed.</summary>
    public static FreshAtPolicy? FromJson(object? o)
    {
        if (o is not JD d || IntentJs.Get(d, "signer") is not string signer || IntentJs.Get(d, "scope") is not string scope || FreshAtState.FromJson(IntentJs.Get(d, "local")) is not { } local) return null;
        long? max = null;
        if (d.ContainsKey("max_token_age_ms")) { if (!Pca.SafeNat(d["max_token_age_ms"], out var m)) return null; max = m; }
        return new FreshAtPolicy(signer, scope, local, max, IntentJs.Get(d, "require") is true, d.ContainsKey("side_carried"), IntentJs.Get(d, "side_carried"));
    }
}

/// <summary><paramref name="Status"/> is <c>none</c> (not reported), <c>pass</c> or <c>fail</c> (with the reason after <c>fresh_at: </c>).</summary>
public sealed record FreshAtCheck(string Status, string? Reason);
