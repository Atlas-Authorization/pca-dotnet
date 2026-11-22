// The remaining public helpers of the canonical compact-JWS gate (the reference strict-jws.ts isCanonicalCompactJws / assertCanonicalJwsSegments).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Jose;

public static partial class Jose
{
    /// <summary>True iff <paramref name="token"/> is the one canonical spelling of a compact JWS (<paramref name="parts"/> 3) or JWE (5). Never throws.</summary>
    public static bool IsCanonicalCompactJws(object? token, int parts = 3, int maxBytes = DefaultMaxJwsBytes, bool payloadJson = true)
    {
        try { AssertCanonicalCompactJws(token, parts, maxBytes, payloadJson); return true; }
        catch (CanonicalJwsException) { return false; }
    }

    /// <summary>The canonical gate for a DETACHED JWS: the protected-header and signature segments must be non-empty canonical base64url within <paramref name="maxBytes"/>
    /// together and the header a strict-JSON object. Returns the header; throws <see cref="CanonicalJwsException"/> otherwise.</summary>
    public static JD AssertCanonicalJwsSegments(object? protectedB64u, object? signatureB64u, int maxBytes = DefaultMaxJwsBytes)
    {
        if (protectedB64u is not string p || signatureB64u is not string s) throw new CanonicalJwsException("not-a-string");
        if (p.Length + s.Length > maxBytes) throw new CanonicalJwsException("too-long");
        if (p.Length == 0 || s.Length == 0) throw new CanonicalJwsException("empty-segment");
        var header = AsObject(ParseJsonBytesStrict(DecodeCanonicalBase64Url(p)));
        DecodeCanonicalBase64Url(s);
        return header;
    }
}
