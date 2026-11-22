// The PCActn's aud / iat / exp checked BEFORE any signature verification or metering (the reference pcactn-cheap-claims.ts). These are
// unauthenticated fields at this point, so a pass proves nothing; a FAIL is final: the full verifier makes exactly the same audience and validity
// decisions on the same fields, so a document refused here could never be admitted. O(1).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Which full-verifier check a <see cref="Pca.PcactnCheapClaims"/> refusal corresponds to (<c>audience</c> or <c>validity</c>).</summary>
public sealed record PcactnCheapClaimFailure(string Check, string Reason);

public static partial class Pca
{
    /// <summary>Null when both checks pass. <paramref name="audience"/> is this verifier's audience id; <paramref name="now"/> is epoch ms.</summary>
    public static PcactnCheapClaimFailure? PcactnCheapClaims(JD p, string audience, double now)
    {
        if (Get(p, "aud") is not string aud || aud.Length == 0 || aud != audience) return new("audience", "aud does not match this resource server / instance");
        if (!IntentJs.IsSafeInteger(Get(p, "iat")) || !IntentJs.IsSafeInteger(Get(p, "exp"))) return new("validity", "iat and exp must be safe-integer epoch ms");
        var iat = IntentJs.Lng(Get(p, "iat")); var exp = IntentJs.Lng(Get(p, "exp"));
        if (!(double.IsFinite(now) && Math.Floor(now) == now && Math.Abs(now) <= MaxSafeInt)) return new("validity", "the verifier clock is not a safe integer epoch-ms");
        if (!(exp > iat)) return new("validity", "exp must be greater than iat");
        if (exp - iat > MaxLifetimeMs) return new("validity", $"lifetime exceeds {MaxLifetimeMs} ms");
        if (iat > now + MaxSkewMs) return new("validity", "iat is in the future (clock skew)");
        if (now > exp) return new("validity", "the PCActn has expired");
        return null;
    }
}
