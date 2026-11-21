// Opening an optimistic bonded claim (the reference openOptimistic): the agent acts immediately on a signed, bonded claim of compliance; a watchtower can file a
// fraud proof within the challenge window to slash the bond. The verification side is in Optimistic.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>What <see cref="Optimistic.OpenOptimistic"/> reads. <c>ChallengeWindowMs</c> must be within the policy bounds (else it throws); <c>IssuedAt</c> within the
/// policy skew of <c>ServerNow</c>; <c>ServerNow</c> defaults to the wall clock; <c>DefaultWindowMs</c> is the policy default window (5 minutes).</summary>
public sealed class OpenOptimisticOptions
{
    public string BondRef { get; set; } = "";
    public double ClaimedR { get; set; }
    public double? ChallengeWindowMs { get; set; }
    public double? IssuedAt { get; set; }
    public double? ServerNow { get; set; }
    public ChallengeWindowPolicy WindowPolicy { get; set; } = ChallengeWindowPolicy.Default;
    public double DefaultWindowMs { get; set; } = 5 * 60 * 1000;
}

public static partial class Optimistic
{
    /// <summary>Validate a claim's (issued_at, window) against server time and policy: a reason, or null.</summary>
    public static string? ValidateWindow(double issuedAt, double windowMs, double serverNow, ChallengeWindowPolicy? policy = null)
    {
        policy ??= ChallengeWindowPolicy.Default;
        if (!double.IsFinite(serverNow)) return "server time is not finite";
        if (!double.IsFinite(issuedAt) || !double.IsFinite(windowMs)) return "malformed challenge window";
        if (Math.Abs(issuedAt - serverNow) > policy.MaxSkewMs) return "issued_at is outside the allowed skew of server time";
        if (windowMs < policy.MinWindowMs) return "challenge window is below the minimum";
        if (windowMs > policy.MaxWindowMs) return "challenge window exceeds the maximum";
        return null;
    }

    /// <summary>Open an optimistic claim for <paramref name="pcactn"/>, signed by the agent-leaf <paramref name="signerSeed"/> (an Ed25519 seed). REFUSES (throws
    /// <see cref="ArgumentException"/>) when the action is irreversible: irreversible actions take the full threshold path.</summary>
    public static JD OpenOptimistic(JD pcactn, OpenOptimisticOptions o, byte[] signerSeed)
    {
        var rc = (pcactn.GetValueOrDefault("action") as JD)?.GetValueOrDefault("reversibility_class");
        if (rc as string == Irreversible) throw new ArgumentException("openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)");
        if (!double.IsFinite(o.ClaimedR)) throw new ArgumentException("openOptimistic: claimedR must be finite");
        var serverNow = o.ServerNow is double sn && double.IsFinite(sn) ? sn : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var issuedAt = o.IssuedAt is double ia && double.IsFinite(ia) ? ia : serverNow;
        var windowMs = o.ChallengeWindowMs ?? o.DefaultWindowMs;
        var bad = ValidateWindow(issuedAt, windowMs, serverNow, o.WindowPolicy);
        if (bad != null) throw new ArgumentException("openOptimistic: " + bad);
        var body = new JD
        {
            ["pcactn_digest"] = Pca.HashCanonical(pcactn), ["bond_ref"] = o.BondRef, ["claimed_r"] = IntentJs.Normalize(o.ClaimedR), ["reversibility_class"] = rc is string s ? s : "unknown",
            ["issued_at"] = IntentJs.Normalize(issuedAt), ["challenge_window_ms"] = IntentJs.Normalize(windowMs),
        };
        var text = JsCanon.Lenient(body) ?? throw new ArgumentException("openOptimistic: the claim is not canonicalizable");
        using var key = EdKey.FromSeed(signerSeed);
        body["sig"] = Pca.B64u(key.Sign(IntentJs.Utf8(ClaimDomain + text)));
        return body;
    }

    /// <summary>The reference <c>openChargeBond</c>: the dispute/refund window of a charge, a thin wrapper over <see cref="OpenOptimistic"/> (refuses an irreversible charge).</summary>
    public static JD OpenChargeBond(JD pcactn, OpenOptimisticOptions o, byte[] signerSeed) => OpenOptimistic(pcactn, o, signerSeed);
}
