// Shared JOSE kit for the native PCA packages (oidc, idjag, txn-tokens, dpop, sdjwt, vc): what the reference's `jose` library
// does for them, on the platform crypto (RSA / ECDsa / HMAC from System.Security.Cryptography, Ed25519 / Ed448 from BouncyCastle).
//
//   * canonical compact-JWS gate (one accepted spelling per token) .......... AssertCanonicalCompactJws
//   * compact JWS verify (alg allow-list, crit / b64, key-vs-alg agreement) .. CompactVerify
//   * JWT verify (typ, iss, sub, aud, nbf, exp, iat, maxTokenAge, tolerance) . JwtVerify
//   * JWK import (public; kty / crv / use / key_ops / alg checks) ............ ImportJwk, JoseKey
//   * RFC 7638 thumbprint ..................................................... JwkThumbprint
//   * local JWK Set resolver (kid / alg / use / key_ops matching) ............. CreateLocalJwkSet
//   * signing (EdDSA / ES* / RS* / PS* / HS*) from a private JWK or a seed ... SignJwt, SignCompact, Ed25519SeedJwk
//
// Errors: JoseException carries the reference's JOSEError code (ERR_JWS_INVALID, ERR_JWT_EXPIRED, ERR_JWT_CLAIM_VALIDATION_FAILED, ...)
// and, for claim failures, the claim name. JoseTypeError stands for the reference's plain TypeError / Error (a key of the wrong
// type, an unimportable key); it is NOT a JoseException, exactly as the reference does not make it a JOSEError.
//
// Consumers name the class through an alias (`using J = AtlasPca.Jose.Jose;`) because the namespace shares its name.
//
// shortcut: every decode of a key member or JWS segment is strict base64url (either alphabet, optional padding) and refuses stray
// characters, where the reference's Buffer decoder skips them; the packages gate tokens canonically first, so this only turns a
// would-be silent acceptance into a refusal. Upgrade only if a caller must accept garbage-tolerant key members.
// shortcut: Stringify orders integer-like object keys as JavaScript does, but prints numbers without an exponent form.
using System.Globalization;
using System.Text;
using AtlasPca;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Jose;

/// <summary>A failure the reference throws as a <c>JOSEError</c>: <see cref="Code"/> is its <c>code</c>; for a claim failure
/// <see cref="Claim"/> is the claim name and <see cref="Reason"/> its reason (<c>missing</c>, <c>invalid</c>, <c>check_failed</c>).</summary>
public class JoseException : Exception
{
    public string Code { get; }
    public string? Claim { get; }
    public string? Reason { get; }
    public JoseException(string code, string message, string? claim = null, string? reason = null) : base(message)
    {
        Code = code; Claim = claim; Reason = reason;
    }

    internal static JoseException Generic(string message) => new("ERR_JOSE_GENERIC", message);
    internal static JoseException JwsInvalid(string message) => new("ERR_JWS_INVALID", message);
    internal static JoseException JwtInvalid(string message) => new("ERR_JWT_INVALID", message);
    internal static JoseException NotSupported(string message) => new("ERR_JOSE_NOT_SUPPORTED", message);
    internal static JoseException Claim_(string message, string claim, string reason) => new("ERR_JWT_CLAIM_VALIDATION_FAILED", message, claim, reason);
    internal static JoseException Expired(string message, string claim) => new("ERR_JWT_EXPIRED", message, claim, "check_failed");
}

/// <summary>The reference's plain <c>TypeError</c> / <c>Error</c> (not a JOSEError): a key of the wrong type for the algorithm, a JWK the
/// platform cannot import, a bad option.</summary>
public sealed class JoseTypeError : Exception
{
    public JoseTypeError(string message) : base(message) { }
}

/// <summary>A token that is not the one canonical spelling of a compact JWS; <see cref="Reason"/> is the gate's reason token
/// (<c>bad-character</c>, <c>non-canonical-base64url</c>, <c>bad-segment-count</c>, ...).</summary>
public sealed class CanonicalJwsException : Exception
{
    public string Reason { get; }
    public CanonicalJwsException(string reason, string? detail = null)
        : base("non-canonical compact JWS: " + reason + (string.IsNullOrEmpty(detail) ? "" : " (" + detail + ")")) { Reason = reason; }
}

/// <summary>A token that passed the canonical gate: its segments, strict-JSON header and (for a three-part token) payload.</summary>
public sealed class CanonicalJws
{
    public List<string> Segments { get; }
    public D Header { get; }
    public D? Payload { get; }
    internal CanonicalJws(List<string> s, D h, D? p) { Segments = s; Header = h; Payload = p; }
}

/// <summary>A verified compact JWS: the parsed protected header and the payload bytes.</summary>
public sealed class JwsResult
{
    public D ProtectedHeader { get; }
    public byte[] Payload { get; }
    /// <summary>The key the resolver returned (null for a static key).</summary>
    public object? Key { get; }
    internal JwsResult(D h, byte[] p, object? key) { ProtectedHeader = h; Payload = p; Key = key; }
}

/// <summary>A verified JWT.</summary>
public sealed class JwtResult
{
    public D Payload { get; }
    public D ProtectedHeader { get; }
    public object? Key { get; }
    internal JwtResult(D p, D h, object? key) { Payload = p; ProtectedHeader = h; Key = key; }
}

/// <summary>Options of <see cref="Jose.CompactVerify"/> / <see cref="Jose.JwtVerify"/>. Everything null / empty is "not checked".</summary>
public sealed class JwtVerifyOptions
{
    /// <summary>Allowed <c>alg</c> values (null = any the kit supports).</summary>
    public IReadOnlyCollection<string>? Algorithms { get; init; }
    /// <summary>Expected header <c>typ</c> (compared case-insensitively with a leading <c>application/</c> dropped). Empty = unchecked.</summary>
    public string? Typ { get; init; }
    /// <summary>The issuer option given as one string (an empty string is required present but not compared, as the reference).</summary>
    public string? IssuerString { get; init; }
    /// <summary>The issuer option given as an array of allowed values.</summary>
    public IReadOnlyList<string>? IssuerList { get; init; }
    public string? Subject { get; init; }
    /// <summary>The audience option given as one string (an empty string is required present but not compared).</summary>
    public string? AudienceString { get; init; }
    /// <summary>The audience option given as an array.</summary>
    public IReadOnlyList<string>? AudienceList { get; init; }
    public IReadOnlyList<string>? RequiredClaims { get; init; }
    /// <summary>Clock tolerance in seconds (null = 0).</summary>
    public double? ClockTolerance { get; init; }
    /// <summary>Maximum token age in seconds (null = unchecked; 0 counts as unchecked for the age rule but still requires <c>iat</c>).</summary>
    public double? MaxTokenAge { get; init; }
    /// <summary>The current time in epoch MILLISECONDS (null = the system clock). NaN or beyond +-8.64e15 is an invalid Date: every time check then passes, as in the reference.</summary>
    public double? CurrentDateMs { get; init; }
    /// <summary>Header parameters named in <c>crit</c> that the caller understands, besides <c>b64</c>.</summary>
    public IReadOnlyCollection<string>? Crit { get; init; }
}

public static partial class Jose
{
    public const int DefaultMaxJwsBytes = 64 * 1024;

    /// <summary>The reference's <c>EmbeddedJWK</c> resolver: verify under the <c>jwk</c> member of the protected header (RFC 7515 s4.1.3). Pass it as the key of
    /// <see cref="CompactVerify"/> / <see cref="JwtVerify"/>.</summary>
    public static readonly Func<D, object?> EmbeddedJwk = header =>
    {
        if (header.GetValueOrDefault("jwk") is not D h) throw JoseException.JwsInvalid("\"jwk\" (JSON Web Key) Header Parameter must be a JSON object");
        var key = ImportJwk(new D(h) { ["ext"] = true }, header.GetValueOrDefault("alg") as string);
        if (key is not JoseKey jk || jk.IsPrivate) throw JoseException.JwsInvalid("\"jwk\" (JSON Web Key) Header Parameter must be a public key");
        return jk;
    };

    // ===================== bytes =====================

    /// <summary>UTF-8 as TextEncoder writes it (a lone surrogate becomes U+FFFD).</summary>
    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static string B64u(byte[] b) => Pca.B64u(b);

    /// <summary>Base64url as a JOSE library reads a key member or segment: either alphabet, optional padding; JoseException when undecodable.</summary>
    public static byte[] DecodeB64Lenient(string s)
    {
        var t = s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        foreach (var c in t)
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')) throw JoseException.Generic("invalid base64url");
        if (t.Length % 4 == 1) throw JoseException.Generic("invalid base64url");
        var p = t.Replace('-', '+').Replace('_', '/');
        switch (p.Length % 4) { case 2: p += "=="; break; case 3: p += "="; break; }
        try { return Convert.FromBase64String(p); }
        catch (FormatException) { throw JoseException.Generic("invalid base64url"); }
    }

    // ===================== canonical compact-JWS gate =====================

    /// <summary>One strictly canonical unpadded base64url segment (CanonicalJwsException otherwise).</summary>
    public static byte[] DecodeCanonicalBase64Url(string seg)
    {
        foreach (var c in seg)
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')) throw new CanonicalJwsException("bad-character");
        if (seg.Length % 4 == 1) throw new CanonicalJwsException("non-canonical-base64url", "impossible length");
        var p = seg.Replace('-', '+').Replace('_', '/');
        switch (p.Length % 4) { case 2: p += "=="; break; case 3: p += "="; break; }
        byte[] b;
        try { b = Convert.FromBase64String(p); }
        catch (FormatException) { throw new CanonicalJwsException("non-canonical-base64url"); }
        if (Pca.B64u(b) != seg) throw new CanonicalJwsException("non-canonical-base64url");
        return b;
    }

    /// <summary>A canonical base64url segment holding a strict-JSON document of any type (an SD-JWT Disclosure).</summary>
    public static object? DecodeCanonicalJsonSegment(string seg) => ParseJsonBytesStrict(DecodeCanonicalBase64Url(seg));

    static object? ParseJsonBytesStrict(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) throw new CanonicalJwsException("bom");
        string text;
        try { text = new UTF8Encoding(false, true).GetString(bytes); }
        catch (ArgumentException) { throw new CanonicalJwsException("bad-utf8"); }
        try { return Pca.ParseStrict(text); }
        catch (StrictJsonException e) { throw new CanonicalJwsException("bad-json", e.Message); }
    }

    static D AsObject(object? v) => v as D ?? throw new CanonicalJwsException("not-an-object");

    /// <summary>Three-part gate with a strict-JSON payload and the default size cap.</summary>
    public static CanonicalJws AssertCanonicalCompactJws(object? token) => AssertCanonicalCompactJws(token, 3, DefaultMaxJwsBytes, true);

    /// <summary>Throws CanonicalJwsException unless <paramref name="token"/> is the one canonical spelling of a compact JWS
    /// (<paramref name="parts"/> 3) or JWE (5): non-empty unpadded base64url segments that re-encode exactly, a strict-JSON header
    /// (and payload when <paramref name="payloadJson"/>).</summary>
    public static CanonicalJws AssertCanonicalCompactJws(object? token, int parts, int maxBytes, bool payloadJson)
    {
        if (token is not string t) throw new CanonicalJwsException("not-a-string");
        if (t.Length > maxBytes) throw new CanonicalJwsException("too-long");
        var segs = t.Split('.');
        if (segs.Length != parts) throw new CanonicalJwsException("bad-segment-count", segs.Length + " != " + parts);
        var bytes = new byte[segs.Length][];
        for (int i = 0; i < segs.Length; i++)
        {
            if (segs[i].Length == 0)
            {
                if (parts == 5 && i == 1) { bytes[i] = Array.Empty<byte>(); continue; }
                throw new CanonicalJwsException("empty-segment", "segment " + i);
            }
            bytes[i] = DecodeCanonicalBase64Url(segs[i]);
        }
        var header = AsObject(ParseJsonBytesStrict(bytes[0]));
        D? payload = null;
        if (parts == 3 && payloadJson) payload = AsObject(ParseJsonBytesStrict(bytes[1]));
        return new CanonicalJws(segs.ToList(), header, payload);
    }

    // ===================== JSON helpers =====================

    /// <summary>JSON text of a value as <c>JSON.stringify</c> writes it: object members in the engine's own-key order (integer-like keys
    /// first, ascending, then insertion order), strings escaped the way it does (lone surrogates as \udXXX).</summary>
    public static string Stringify(object? v)
    {
        var sb = new StringBuilder();
        Write(sb, v);
        return sb.ToString();
    }

    static void WriteStr(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static string NoNegZero(string t) => t == "-0" ? "0" : t;

    static void Write(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: WriteStr(sb, s); break;
            case Num n: sb.Append(NoNegZero(IntentJs.NormNum(n.Raw).Raw)); break; // JSON.stringify prints -0 as 0
            case int or long or short or byte: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case double d: sb.Append(double.IsFinite(d) ? NoNegZero(IntentJs.NormNum(d.ToString("R", CultureInfo.InvariantCulture)).Raw) : "null"); break;
            case D m:
                sb.Append('{');
                bool first = true;
                foreach (var k in IntentJs.JsKeys(m.Keys))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteStr(sb, k); sb.Append(':'); Write(sb, m[k]);
                }
                sb.Append('}');
                break;
            case L l:
                sb.Append('[');
                for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); Write(sb, l[i]); }
                sb.Append(']');
                break;
            case IEnumerable<string> ss: Write(sb, ss.Cast<object?>().ToList()); break;
            default: throw new InvalidOperationException("Stringify: unsupported " + v.GetType());
        }
    }

    /// <summary>The JavaScript number value of a JSON number (Num / int / long / double), else null.</summary>
    public static double? NumberOf(object? o) => IntentJs.NumOf(o);

    internal static D? Obj(object? o) => o as D;
    internal static string? Str(object? o) => o as string;

    /// <summary><c>JSON.parse</c> of the UTF-8 bytes as the reference's TextDecoder reads them (a BOM is dropped, bad bytes become U+FFFD); null when unparseable.</summary>
    internal static bool TryParseJsonLenient(byte[] bytes, out object? value)
    {
        try
        {
            var text = Encoding.UTF8.GetString(bytes);
            if (text.Length > 0 && text[0] == '﻿') text = text[1..];
            value = Pca.ParseJson(text);
            return true;
        }
        catch (StrictJsonException) { value = null; return false; }
    }

    // ===================== compact JWS verify =====================

    static void ValidateCrit(D prot, IReadOnlyCollection<string>? recognizedExtra)
    {
        if (!prot.TryGetValue("crit", out var crit)) return;
        if (crit is not L list || list.Count == 0 || list.Any(c => c is not string s || s.Length == 0))
            throw JoseException.JwsInvalid("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
        foreach (var c in list.Cast<string>())
        {
            if (c != "b64" && !(recognizedExtra?.Contains(c) ?? false)) throw JoseException.NotSupported($"Extension Header Parameter \"{c}\" is not recognized");
            if (!prot.ContainsKey(c)) throw JoseException.JwsInvalid($"Extension Header Parameter \"{c}\" is missing");
        }
    }

    /// <summary>The reference's <c>compactVerify</c>. <paramref name="key"/> is a public JWK (<c>Dictionary</c>), a secret
    /// (<c>byte[]</c>, HS* only), a <see cref="JoseKey"/> (also <see cref="EmbeddedJwk"/>), or a resolver <c>Func&lt;D, object?&gt;</c> from the protected header to one of those.
    /// Order of checks mirrors the reference: header, crit, alg allow-list, key type, signature decode, signature.</summary>
    public static JwsResult CompactVerify(string jws, object? key, JwtVerifyOptions? opts = null)
    {
        var parts = jws.Split('.');
        if (parts.Length != 3) throw JoseException.JwsInvalid("Invalid Compact JWS");
        string protectedB64 = parts[0], payloadSeg = parts[1], sigSeg = parts[2];
        D prot = new();
        if (protectedB64.Length > 0)
        {
            object? parsed;
            try
            {
                if (!TryParseJsonLenient(DecodeB64Lenient(protectedB64), out parsed)) throw JoseException.JwsInvalid("JWS Protected Header is invalid");
            }
            catch (JoseException) { throw JoseException.JwsInvalid("JWS Protected Header is invalid"); }
            if (parsed is D pd) prot = pd; // any other JSON value spreads to an object with no usable members: alg is missing below
        }
        ValidateCrit(prot, opts?.Crit);
        bool b64 = true;
        if (prot.TryGetValue("crit", out var cr) && cr is L cl && cl.Contains("b64"))
        {
            if (prot.GetValueOrDefault("b64") is not bool bb) throw JoseException.JwsInvalid("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
            b64 = bb;
        }
        if (prot.GetValueOrDefault("alg") is not string alg || alg.Length == 0) throw JoseException.JwsInvalid("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        if (opts?.Algorithms != null && !opts.Algorithms.Contains(alg)) throw new JoseException("ERR_JOSE_ALG_NOT_ALLOWED", "\"alg\" (Algorithm) Header Parameter value not allowed");

        object? resolved = null;
        bool wasResolver = false;
        if (key is Func<D, object?> resolver)
        {
            resolved = resolver(prot);
            wasResolver = true;
            CheckKeyType(alg, resolved);
            if (resolved is D rj) resolved = ImportJwk(rj, alg);
            key = resolved;
        }
        else CheckKeyType(alg, key);

        var data = Utf8(protectedB64 + "." + payloadSeg);
        byte[] sig;
        try { sig = DecodeB64Lenient(sigSeg); }
        catch (JoseException) { throw JoseException.JwsInvalid("Failed to base64url decode the signature"); }
        if (!VerifyWith(alg, key!, sig, data)) throw new JoseException("ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "signature verification failed");

        byte[] payload;
        if (b64)
        {
            try { payload = DecodeB64Lenient(payloadSeg); }
            catch (JoseException) { throw JoseException.JwsInvalid("Failed to base64url decode the payload"); }
        }
        else payload = Utf8(payloadSeg);
        return new JwsResult(prot, payload, wasResolver ? resolved : null);
    }

    // ===================== JWT verify =====================

    static string NormalizeTyp(string v) { var l = v.ToLowerInvariant(); return l.StartsWith("application/", StringComparison.Ordinal) ? l[12..] : l; }

    static bool Truthy(double? v) => v is double d && d != 0 && !double.IsNaN(d);

    /// <summary>The reference's <c>jwtVerify</c>: <see cref="CompactVerify"/>, then the claim rules. Every failure is a JoseException
    /// (ERR_JWT_INVALID, ERR_JWT_CLAIM_VALIDATION_FAILED, ERR_JWT_EXPIRED, ...) or a JoseTypeError.</summary>
    public static JwtResult JwtVerify(string jwt, object? key, JwtVerifyOptions? opts = null)
    {
        opts ??= new JwtVerifyOptions();
        var v = CompactVerify(jwt, key, opts);
        if (v.ProtectedHeader.GetValueOrDefault("crit") is L crit && crit.Contains("b64") && v.ProtectedHeader.GetValueOrDefault("b64") is false)
            throw JoseException.JwtInvalid("JWTs MUST NOT use unencoded payload");
        var payload = JwtClaims(v.ProtectedHeader, v.Payload, opts);
        return new JwtResult(payload, v.ProtectedHeader, v.Key);
    }

    /// <summary>The claims-set half of <see cref="JwtVerify"/> (the reference's <c>jwt_claims_set</c>) on an already verified payload.</summary>
    public static D JwtClaims(D protectedHeader, byte[] encodedPayload, JwtVerifyOptions opts)
    {
        object? parsed = null;
        if (TryParseJsonLenient(encodedPayload, out var pv)) parsed = pv;
        if (parsed is not D payload) throw JoseException.JwtInvalid("JWT Claims Set must be a top-level JSON object");
        if (!string.IsNullOrEmpty(opts.Typ)
            && !(protectedHeader.GetValueOrDefault("typ") is string t && NormalizeTyp(t) == NormalizeTyp(opts.Typ)))
            throw JoseException.Claim_("unexpected \"typ\" JWT header value", "typ", "check_failed");

        var presence = new List<string>();
        if (opts.RequiredClaims != null) presence.AddRange(opts.RequiredClaims);
        if (opts.MaxTokenAge != null) presence.Add("iat");
        bool hasAud = opts.AudienceString != null || opts.AudienceList != null;
        if (hasAud) presence.Add("aud");
        if (opts.Subject != null) presence.Add("sub");
        if (opts.IssuerString != null || opts.IssuerList != null) presence.Add("iss");
        presence.Reverse();
        foreach (var claim in presence.Distinct())
            if (!payload.ContainsKey(claim)) throw JoseException.Claim_($"missing required \"{claim}\" claim", claim, "missing");

        // `issuer &&`: an empty-string scalar is falsy (not compared); an array is always compared
        if ((opts.IssuerString is { Length: > 0 } || opts.IssuerList != null)
            && !(payload.GetValueOrDefault("iss") is string iss && (opts.IssuerString != null ? opts.IssuerString == iss : opts.IssuerList!.Contains(iss))))
            throw JoseException.Claim_("unexpected \"iss\" claim value", "iss", "check_failed");
        if (!string.IsNullOrEmpty(opts.Subject) && !(payload.GetValueOrDefault("sub") is string sub && sub == opts.Subject))
            throw JoseException.Claim_("unexpected \"sub\" claim value", "sub", "check_failed");
        if (hasAud && !(opts.AudienceString is { Length: 0 }))
        {
            var want = opts.AudienceString != null ? new List<string> { opts.AudienceString } : opts.AudienceList!.ToList();
            bool ok = false;
            var aud = payload.GetValueOrDefault("aud");
            if (aud is string sa) ok = want.Contains(sa);
            else if (aud is L la) ok = want.Any(w => la.Any(x => x is string xs && xs == w));
            if (!ok) throw JoseException.Claim_("unexpected \"aud\" claim value", "aud", "check_failed");
        }

        double tol = opts.ClockTolerance ?? 0;
        double now;
        if (opts.CurrentDateMs is not double ms) now = Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);
        else if (double.IsNaN(ms) || Math.Abs(ms) > 8.64e15) now = double.NaN;
        else now = Math.Floor(Math.Truncate(ms) / 1000.0);

        bool hasIat = payload.ContainsKey("iat");
        double? iatN = NumberOf(payload.GetValueOrDefault("iat"));
        if ((hasIat || Truthy(opts.MaxTokenAge)) && iatN == null)
            throw JoseException.Claim_("\"iat\" claim must be a number", "iat", "invalid");
        if (payload.ContainsKey("nbf"))
        {
            var nbf = NumberOf(payload["nbf"]);
            if (nbf == null) throw JoseException.Claim_("\"nbf\" claim must be a number", "nbf", "invalid");
            if (nbf > now + tol) throw JoseException.Claim_("\"nbf\" claim timestamp check failed", "nbf", "check_failed");
        }
        if (payload.ContainsKey("exp"))
        {
            var exp = NumberOf(payload["exp"]);
            if (exp == null) throw JoseException.Claim_("\"exp\" claim must be a number", "exp", "invalid");
            if (exp <= now - tol) throw JoseException.Expired("\"exp\" claim timestamp check failed", "exp");
        }
        if (Truthy(opts.MaxTokenAge))
        {
            double age = now - iatN!.Value;
            if (age - tol > opts.MaxTokenAge!.Value) throw JoseException.Expired("\"iat\" claim timestamp check failed (too far in the past)", "iat");
            if (age < 0 - tol) throw JoseException.Claim_("\"iat\" claim timestamp check failed (it should be in the past)", "iat", "check_failed");
        }
        return payload;
    }

    // ===================== JWS signing =====================

    /// <summary>The reference's <c>SignJWT</c> / <c>CompactSign</c> for an object payload: compact JWS of <paramref name="header"/> (must carry
    /// <c>alg</c>) and <paramref name="payload"/> (members written in <c>JSON.stringify</c> order) under a private JWK or secret.</summary>
    public static string SignJwt(D header, D payload, object privateKey) => SignCompact(header, Utf8(Stringify(payload)), privateKey);

    /// <summary>Compact JWS over raw payload bytes (b64url-encoded). <paramref name="key"/> is a private JWK, an HS secret (<c>byte[]</c>) or a <see cref="JoseKey"/> from a private JWK.</summary>
    public static string SignCompact(D header, byte[] payload, object key)
    {
        if (header.GetValueOrDefault("alg") is not string alg || alg.Length == 0) throw JoseException.JwsInvalid("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        if (header.ContainsKey("crit")) throw JoseException.NotSupported("crit is not supported when signing");
        var h = B64u(Utf8(Stringify(header)));
        var p = B64u(payload);
        var sig = SignRaw(alg, key, Utf8(h + "." + p));
        return h + "." + p + "." + B64u(sig);
    }

    // ===================== RFC 7638 thumbprint =====================

    static void Need(object? v, string what)
    {
        if (v is not string s || s.Length == 0) throw new JoseException("ERR_JWK_INVALID", what + " missing or invalid");
    }

    /// <summary>RFC 7638 JWK thumbprint (base64url of the hash of the required members, keys sorted), <paramref name="digest"/> sha256 (default) | sha384 | sha512.</summary>
    public static string JwkThumbprint(object? jwkObject, string? digest = null)
    {
        if (jwkObject is not D jwk) throw new JoseTypeError("JWK must be an object");
        digest ??= "sha256";
        if (digest != "sha256" && digest != "sha384" && digest != "sha512") throw new JoseTypeError("digestAlgorithm must one of \"sha256\", \"sha384\", or \"sha512\"");
        var c = new D();
        var kty = jwk.GetValueOrDefault("kty");
        if (kty is "EC")
        {
            Need(jwk.GetValueOrDefault("crv"), "\"crv\" (Curve) Parameter"); Need(jwk.GetValueOrDefault("x"), "\"x\" (X Coordinate) Parameter"); Need(jwk.GetValueOrDefault("y"), "\"y\" (Y Coordinate) Parameter");
            c["crv"] = jwk["crv"]; c["kty"] = kty; c["x"] = jwk["x"]; c["y"] = jwk["y"];
        }
        else if (kty is "OKP")
        {
            Need(jwk.GetValueOrDefault("crv"), "\"crv\" (Subtype of Key Pair) Parameter"); Need(jwk.GetValueOrDefault("x"), "\"x\" (Public Key) Parameter");
            c["crv"] = jwk["crv"]; c["kty"] = kty; c["x"] = jwk["x"];
        }
        else if (kty is "RSA")
        {
            Need(jwk.GetValueOrDefault("e"), "\"e\" (Exponent) Parameter"); Need(jwk.GetValueOrDefault("n"), "\"n\" (Modulus) Parameter");
            c["e"] = jwk["e"]; c["kty"] = kty; c["n"] = jwk["n"];
        }
        else if (kty is "oct")
        {
            Need(jwk.GetValueOrDefault("k"), "\"k\" (Key Value) Parameter");
            c["k"] = jwk["k"]; c["kty"] = kty;
        }
        else throw new JoseException("ERR_JOSE_NOT_SUPPORTED", "\"kty\" (Key Type) Parameter missing or unsupported");
        var bytes = Utf8(Stringify(c));
        return B64u(digest switch
        {
            "sha256" => System.Security.Cryptography.SHA256.HashData(bytes),
            "sha384" => System.Security.Cryptography.SHA384.HashData(bytes),
            _ => System.Security.Cryptography.SHA512.HashData(bytes),
        });
    }

    // ===================== local JWK Set =====================

    /// <summary>The reference's <c>createLocalJWKSet</c>: a key resolver over a JWK Set (<c>{keys: [...]}</c>). The returned function maps a
    /// protected header to the single matching public <see cref="JoseKey"/> (kid / alg / use / key_ops / curve matching) or throws
    /// ERR_JWKS_NO_MATCHING_KEY / ERR_JWKS_MULTIPLE_MATCHING_KEYS / ERR_JWKS_INVALID.</summary>
    public static Func<D, object?> CreateLocalJwkSet(object? jwks)
    {
        if (!(jwks is D set && set.GetValueOrDefault("keys") is L keys && keys.All(k => k is D)))
            throw new JoseException("ERR_JWKS_INVALID", "JSON Web Key Set malformed");
        var copy = keys.Select(k => (D)Deep(k)!).ToList();
        var cache = new Dictionary<(D, string), JoseKey>();
        return header =>
        {
            var alg = header.GetValueOrDefault("alg");
            var kid = header.GetValueOrDefault("kid");
            string kty = (alg is string a2 && a2.Length >= 2 ? a2[..2] : null) switch
            {
                "RS" or "PS" => "RSA",
                "ES" => "EC",
                "Ed" => "OKP",
                _ => throw JoseException.NotSupported("Unsupported \"alg\" value for a JSON Web Key Set"),
            };
            var candidates = copy.Where(jwk =>
            {
                bool c = jwk.GetValueOrDefault("kty") is string kt && kt == kty;
                if (c && kid is string kd) c = jwk.GetValueOrDefault("kid") is string jk && jk == kd;
                if (c && jwk.GetValueOrDefault("alg") is string ja) c = alg is string aa && aa == ja;
                if (c && jwk.GetValueOrDefault("use") is string ju) c = ju == "sig";
                if (c && jwk.GetValueOrDefault("key_ops") is L ops) c = ops.Any(o => o is string os && os == "verify");
                if (c && alg is "EdDSA") c = jwk.GetValueOrDefault("crv") is "Ed25519" or "Ed448";
                if (c)
                {
                    var crv = jwk.GetValueOrDefault("crv") as string;
                    switch (alg as string)
                    {
                        case "ES256": c = crv == "P-256"; break;
                        case "ES256K": c = crv == "secp256k1"; break;
                        case "ES384": c = crv == "P-384"; break;
                        case "ES512": c = crv == "P-521"; break;
                    }
                }
                return c;
            }).ToList();
            if (candidates.Count == 0) throw new JoseException("ERR_JWKS_NO_MATCHING_KEY", "no applicable key found in the JSON Web Key Set");
            if (candidates.Count != 1) throw new JoseException("ERR_JWKS_MULTIPLE_MATCHING_KEYS", "multiple matching keys found in the JSON Web Key Set");
            var jwkc = candidates[0];
            var ck = (jwkc, alg as string ?? "");
            if (!cache.TryGetValue(ck, out var jk2))
            {
                var withExt = new D(jwkc) { ["ext"] = true };
                var imported = ImportJwk(withExt, alg as string);
                if (imported is not JoseKey key || key.IsPrivate) throw new JoseException("ERR_JWKS_INVALID", "JSON Web Key Set members must be public keys");
                cache[ck] = jk2 = key;
            }
            return jk2;
        };
    }

    internal static object? Deep(object? a) => a switch
    {
        D m => m.ToDictionary(e => e.Key, e => Deep(e.Value)),
        L l => l.Select(Deep).ToList(),
        _ => a,
    };
}
