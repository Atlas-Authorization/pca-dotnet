// One-time-use guard for a signature-verified PCActn (the vault's replay check): the nonce is consumed once under a key that binds the audience, the
// grant and the leaf holder. Run it only AFTER the PCActn verified, last of the authorization checks. Never throws: a store failure is a denial. The check
// order follows the formally verified replay decision (no store call before every pre-check passed).
using System.Security.Cryptography;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connect;

/// <summary>The guard's verdict: <see cref="Ok"/>, else a denial <see cref="Code"/> (malformed, audience, not_yet_valid, expired, replay, store_unavailable) and a reason.</summary>
public sealed record ReplayVerdict(bool Ok, string? Code, string? Reason);

public static class ConnectReplayGuard
{
    const long MaxLifetimeMs = 3_600_000;
    const long MaxSkewMs = 60_000;
    const int MaxReplayComponentLen = 512;
    const int MaxAudLen = 256;
    const int MaxNonceLen = 128;
    const long MaxSafe = 9007199254740991;

    static ReplayVerdict Deny(string code, string reason) => new(false, code, reason);

    static int U8(string s) => Encoding.UTF8.GetByteCount(s);

    static bool SafeNonNegInt(object? o) => IntentJs.IsNonNeg(o); // a safe integer that is not -0

    static bool WellFormed(string s) => s.Length != 0 && !Pca.HasLoneSurrogate(s) && U8(s) <= MaxReplayComponentLen;

    /// <summary>The length-prefixed, injective key of the parts, hashed: <c>namespace:b64u(sha256)</c>. Throws on a lone surrogate.</summary>
    internal static string ReplayKey(string ns, params string[] parts)
    {
        var buf = new List<byte>();
        foreach (var part in new[] { ns }.Concat(parts))
        {
            if (Pca.HasLoneSurrogate(part)) throw new ArgumentException("replayKey: every part must be a well-formed string (no lone surrogates)");
            var b = Encoding.UTF8.GetBytes(part);
            buf.Add((byte)(b.Length >> 24)); buf.Add((byte)(b.Length >> 16)); buf.Add((byte)(b.Length >> 8)); buf.Add((byte)b.Length);
            buf.AddRange(b);
        }
        return ns + ":" + Pca.B64u(SHA256.HashData(buf.ToArray()));
    }

    /// <summary>Decide whether <paramref name="p"/> (a parsed PCActn) may be accepted once, for the verifier audience <paramref name="aud"/> at <paramref name="now"/> (epoch ms).</summary>
    public static ReplayVerdict Guard(IStateStore store, object? p, string? aud, long now)
    {
        var pm = p as D;
        bool objectOk = pm != null;
        var chain = objectOk ? pm!.GetValueOrDefault("cap_chain") : null;
        var leaf = chain is L cl && cl.Count > 0 ? cl[^1] : null;
        bool leafOk = leaf is D ld && ld.GetValueOrDefault("holder") is string && objectOk && pm!.GetValueOrDefault("grant_ref") is string;
        bool componentsOk = leafOk && WellFormed((string)pm!["grant_ref"]!) && WellFormed((string)((D)leaf!)["holder"]!);
        bool hasNonce = objectOk && pm!.ContainsKey("nonce");
        var nonce = hasNonce ? pm![ "nonce"] : null;
        bool nonceOk = hasNonce && nonce is string ns && ns.Length != 0 && U8(ns) <= MaxNonceLen && !Pca.HasLoneSurrogate(ns);

        bool nowOk = now >= -MaxSafe && now <= MaxSafe;
        bool verifierAudOk = aud != null && aud.Length != 0 && U8(aud) <= MaxAudLen && !Pca.HasLoneSurrogate(aud);
        bool audMatches = objectOk && pm!.GetValueOrDefault("aud") is string pa && pa == aud;
        bool iatOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("iat"));
        bool expOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("exp"));
        long iat = iatOk ? IntentJs.Lng(pm!["iat"]) : 0, exp = expOk ? IntentJs.Lng(pm!["exp"]) : 0;
        bool counterOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("counter"));
        bool windowOk = iatOk && expOk && exp > iat && exp - iat <= MaxLifetimeMs;

        // the verified Pre
        if (!nowOk || !verifierAudOk || !objectOk) return Deny("malformed", !nowOk ? "verifier clock is not an integer epoch-ms" : !verifierAudOk ? "verifier audience is invalid" : "not a PCActn");
        if (!audMatches) return Deny("audience", "the PCActn is for another audience");
        if (!windowOk) return Deny("malformed", "iat / exp are not a valid bounded window");
        if (iat > now + MaxSkewMs) return Deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance");
        if (now > exp) return Deny("expired", "the PCActn has expired");
        if (!leafOk) return Deny("malformed", "no leaf holder / grant");
        if (!componentsOk) return Deny("malformed", "grant / holder is not a bounded string");
        if (!counterOk) return Deny("malformed", "counter is not a non-negative safe integer");
        // the retention horizon must be representable
        if (exp + MaxSkewMs > MaxSafe) return Deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)");
        long retainUntil = exp + MaxSkewMs;
        // nonce stage (a nonce is required)
        if (!hasNonce || !nonceOk) return Deny("malformed", hasNonce ? "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" : "a nonce is required");
        try
        {
            bool consumed = store.ConsumeOnce(ReplayKey("pca-nonce/v1", aud!, (string)pm!["grant_ref"]!, (string)((D)leaf!)["holder"]!, (string)nonce!), retainUntil, now);
            if (!consumed) return Deny("replay", "nonce already consumed");
        }
        catch (Exception e) { return Deny("store_unavailable", "replay store failed closed: " + (string.IsNullOrEmpty(e.Message) ? "error" : e.Message)); }
        return new ReplayVerdict(true, null, null);
    }
}
