using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Jose;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using J = AtlasPca.Jose.Jose;

namespace AtlasPca.Spiffe;

/// <summary>A parsed, validated SPIFFE ID.</summary>
public sealed record SpiffeId(string Id, string TrustDomain, string Path)
{
    public D ToJson() => new() { ["id"] = Id, ["trustDomain"] = TrustDomain, ["path"] = Path };
}

/// <summary>What <see cref="SpiffeBridge.VerifyX509Svid"/> asks the revocation check about, once per presented certificate (leaf first).</summary>
public sealed record X509RevocationSubject(string SpiffeId, string SerialNumber, string Fingerprint256, int Position, bool IsLeaf)
{
    public D ToJson() => new() { ["spiffeId"] = SpiffeId, ["serialNumber"] = SerialNumber, ["fingerprint256"] = Fingerprint256, ["position"] = new Num(Position.ToString(CultureInfo.InvariantCulture)), ["isLeaf"] = IsLeaf };
}

/// <summary>What <see cref="SpiffeBridge.VerifyJwtSvid"/> asks the revocation check about. <paramref name="Jti"/> is the jti claim when it is a string, else null;
/// <paramref name="ExpiresAt"/> the exp claim (a JSON number); <paramref name="TokenHash"/> base64url SHA-256 of the token.</summary>
public sealed record JwtRevocationSubject(string SpiffeId, string? Jti, object? ExpiresAt, string TokenHash)
{
    public D ToJson()
    {
        var m = new D { ["spiffeId"] = SpiffeId };
        if (Jti != null) m["jti"] = Jti;
        m["expiresAt"] = ExpiresAt;
        m["tokenHash"] = TokenHash;
        return m;
    }
}

/// <summary>Return exactly <c>false</c> (boxed) to admit, <c>true</c> when revoked; anything else, or a throw, refuses (<c>revocation_unavailable</c>).</summary>
public delegate object? X509RevocationCheck(X509RevocationSubject subject);
/// <summary>As <see cref="X509RevocationCheck"/> for a JWT-SVID.</summary>
public delegate object? JwtRevocationCheck(JwtRevocationSubject subject);
/// <summary>A synchronous fetch that may throw.</summary>
public delegate object? Fetch();

/// <summary>Options of <see cref="SpiffeBridge.VerifyJwtSvid"/>.</summary>
public sealed class VerifyJwtSvidOptions
{
    /// <summary>REQUIRED audience(s).</summary>
    public List<string> Audience = new();
    /// <summary>A public JWK (<c>D</c>) or a key resolver <c>Func&lt;D, object?&gt;</c> (e.g. <see cref="TrustBundleSource.JwtKey"/>).</summary>
    public object? Key;
    public string? TrustDomain;
    /// <summary>Verification time (epoch ms); null = now.</summary>
    public double? CurrentDateMs;
    /// <summary>Permitted algorithms; null = <see cref="SpiffeBridge.JwtSvidAlgorithms"/>.</summary>
    public List<string>? Algorithms;
    /// <summary>Seconds (a number) or a time-period string such as "30s"; null = 0.</summary>
    public object? ClockTolerance;
    /// <summary>A <see cref="JwtRevocationCheck"/>, <see cref="SpiffeBridge.NotAFunction"/>, or null (not checked).</summary>
    public object? Revocation;
}

/// <summary>A verified JWT-SVID.</summary>
public sealed class JwtSvid
{
    public SpiffeId SpiffeId { get; }
    public D Claims { get; }
    public L Audience { get; }
    /// <summary>The exp claim (a JSON number).</summary>
    public object? ExpiresAt { get; }
    internal bool Verified;
    internal JwtSvid(SpiffeId id, D claims, L audience, object? exp) { SpiffeId = id; Claims = claims; Audience = audience; ExpiresAt = exp; }
}

/// <summary>A parsed X.509-SVID.</summary>
public sealed class X509Svid
{
    public SpiffeId SpiffeId { get; }
    /// <summary>base64url SubjectPublicKeyInfo DER of the certificate's public key.</summary>
    public string PublicKeyDer { get; }
    internal AttCert Certificate { get; }
    internal bool Verified;
    internal X509Svid(SpiffeId id, AttCert cert, string spki) { SpiffeId = id; Certificate = cert; PublicKeyDer = spki; }
}

/// <summary>Options of <see cref="SpiffeBridge.VerifyX509Svid"/>.</summary>
public sealed class VerifyX509SvidOptions
{
    public string? TrustDomain;
    /// <summary>Trust-bundle authorities: PEM text (possibly several certificates) or DER bytes.</summary>
    public List<object?> Roots = new();
    /// <summary>Verification time (epoch ms); null = now.</summary>
    public long? NowMs;
    /// <summary>Maximum chain length; null = 8.</summary>
    public long? MaxChainLength;
    /// <summary>An <see cref="X509RevocationCheck"/>, <see cref="SpiffeBridge.NotAFunction"/>, or null (not checked).</summary>
    public object? Revocation;
}

/// <summary>A PCA capability holder bound to a SPIFFE workload identity (holder = a base64url Ed25519 public key).</summary>
public sealed record SpiffeHolder(string Holder, string SpiffeId, string TrustDomain, string Path)
{
    public D ToJson() => new() { ["holder"] = Holder, ["spiffeId"] = SpiffeId, ["trustDomain"] = TrustDomain, ["path"] = Path };
}

/// <summary>Options of <see cref="SpiffeBridge.SvidToHolder"/>.</summary>
public sealed class SvidToHolderOptions
{
    /// <summary>A base64url signature over <see cref="SpiffeBridge.HolderBindingMessage"/> made with the X.509-SVID's private key (ECDSA is r||s); any non-string counts as absent.</summary>
    public object? Proof;
    /// <summary>Accept a holder key for a JWT-SVID that carries no matching cnf.jwk (only when it is authenticated by other means).</summary>
    public bool AcceptUnboundJwtHolder;
}

/// <summary>SPIFFE evidence for blueprint admission (a verified SVID bound to the instance key).</summary>
public sealed class SpiffeEvidence
{
    /// <summary>"x509" or "jwt".</summary>
    public string Kind = "";
    public object? Chain;
    public VerifyX509SvidOptions? VerifyX509;
    public object? Token;
    public VerifyJwtSvidOptions? VerifyJwt;
    public SvidToHolderOptions? Bind;
}

/// <summary>The admission verdict: <c>{ok, bound, identity?: {spiffe_id}, reason?}</c>.</summary>
public sealed record SpiffeAdmissionEvidenceResult(bool Ok, bool Bound, string? SpiffeId, string? Reason)
{
    public D ToJson()
    {
        var m = new D { ["ok"] = Ok, ["bound"] = Bound };
        if (SpiffeId != null) m["identity"] = new D { ["spiffe_id"] = SpiffeId };
        if (Reason != null) m["reason"] = Reason;
        return m;
    }
}

/// <summary>
/// Bridge PCA agent identity with SPIFFE / SPIRE workload identity: SPIFFE ID parsing, JWT-SVID and X.509-SVID verification against a trust bundle,
/// SVID to PCA holder binding, revocation and trust-bundle caches that fail closed, and blueprint-admission evidence. Every check fails closed; a
/// failure is a <see cref="SpiffeError"/> with a stable code (JOSE failures of a JWT-SVID are <see cref="JoseException"/>).
/// shortcut: X.509 issuance compares the issuer and subject names byte for byte (the reference compares canonical names); a chain whose names differ
/// only in case or spacing is refused (fail closed), upgrade when such a PKI must be accepted.
/// </summary>
public static class SpiffeBridge
{
    const string SpiffeScheme = "spiffe://";
    const int MaxSpiffeIdLength = 2048, MaxTrustDomainLength = 255;

    /// <summary>Signature algorithms the JWT-SVID specification allows.</summary>
    public static readonly IReadOnlyList<string> JwtSvidAlgorithms = new[] { "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" };

    /// <summary>Stands for a revocation option that is not a function: refused as <c>revocation_unavailable</c>.</summary>
    public static readonly object NotAFunction = new();

    static string Msg(Exception e) => e.Message;

    // ---- SPIFFE ID -----------------------------------------------------------------------------------------------

    static bool TdChar(char c) => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-';
    static bool SegChar(char c) => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-';

    /// <summary>Validate and parse <c>spiffe://&lt;trust-domain&gt;/&lt;path&gt;</c>: lowercase scheme; non-empty trust domain from [a-z0-9._-] (at most 255);
    /// path segments from [a-zA-Z0-9._-] with no empty segment, no "." / ".." segment and no trailing slash; at most 2048 characters.
    /// A bare <c>spiffe://trust-domain</c> is valid. Throws <see cref="SpiffeError"/>.</summary>
    public static SpiffeId ParseSpiffeId(object? sv)
    {
        if (sv is not string s || s.Length == 0) throw new SpiffeError("malformed_spiffe_id", "SPIFFE ID must be a non-empty string");
        if (s.Length > MaxSpiffeIdLength) throw new SpiffeError("id_too_long", $"SPIFFE ID exceeds {MaxSpiffeIdLength} bytes");
        if (!s.StartsWith(SpiffeScheme, StringComparison.Ordinal)) throw new SpiffeError("malformed_spiffe_id", $"SPIFFE ID must begin with \"{SpiffeScheme}\"");
        var rest = s[SpiffeScheme.Length..];
        int slash = rest.IndexOf('/');
        var trustDomain = slash == -1 ? rest : rest[..slash];
        var path = slash == -1 ? "" : rest[slash..];
        if (trustDomain.Length == 0) throw new SpiffeError("empty_trust_domain", "SPIFFE ID has an empty trust domain");
        if (trustDomain.Length > MaxTrustDomainLength) throw new SpiffeError("trust_domain_too_long", $"trust domain exceeds {MaxTrustDomainLength} bytes");
        if (!trustDomain.All(TdChar)) throw new SpiffeError("invalid_trust_domain", $"trust domain \"{trustDomain}\" must be lowercase and contain only [a-z0-9._-]");
        if (path != "")
        {
            if (path.EndsWith('/')) throw new SpiffeError("invalid_path", "SPIFFE ID path must not end with a trailing slash");
            var segments = path.Split('/');
            for (int i = 1; i < segments.Length; i++)
            {
                var seg = segments[i];
                if (seg.Length == 0) throw new SpiffeError("invalid_path", "SPIFFE ID path must not contain an empty segment");
                if (seg == "." || seg == "..") throw new SpiffeError("invalid_path", "SPIFFE ID path must not contain a \".\" or \"..\" segment");
                if (!seg.All(SegChar)) throw new SpiffeError("invalid_path", $"SPIFFE ID path segment \"{seg}\" contains an invalid character");
            }
        }
        return new SpiffeId(SpiffeScheme + trustDomain + path, trustDomain, path);
    }

    // ---- JWT-SVID ------------------------------------------------------------------------------------------------

    static Regex SecsRe => Rx.Get(@"^(\+|-)? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    static double JsRound(double x) => Math.Floor(x + 0.5);

    /// <summary>The jose time-period parser (seconds); <see cref="ArgumentException"/> when malformed.</summary>
    internal static double Secs(string str)
    {
        var m = SecsRe.Match(str);
        if (!m.Success || (m.Groups[4].Success && m.Groups[1].Success)) throw new ArgumentException("Invalid time period format");
        double value = double.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        double n = m.Groups[3].Value.ToLowerInvariant() switch
        {
            "sec" or "secs" or "second" or "seconds" or "s" => JsRound(value),
            "minute" or "minutes" or "min" or "mins" or "m" => JsRound(value * 60),
            "hour" or "hours" or "hr" or "hrs" or "h" => JsRound(value * 3600),
            "day" or "days" or "d" => JsRound(value * 86400),
            "week" or "weeks" or "w" => JsRound(value * 604800),
            _ => JsRound(value * (86400 * 365.25)),
        };
        return m.Groups[1].Value == "-" || m.Groups[4].Value.Equals("ago", StringComparison.OrdinalIgnoreCase) ? -n : n;
    }

    static string Sha256B64u(string s) => Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    /// <summary>Verify a JWT-SVID: the canonical compact spelling, the JWS signature against the key / resolver, the audience, exp (and nbf), a valid SPIFFE ID
    /// sub in the pinned trust domain, then the optional revocation check (last).</summary>
    public static JwtSvid VerifyJwtSvid(object? token, VerifyJwtSvidOptions opts)
    {
        if (opts.Revocation != null && opts.Revocation is not JwtRevocationCheck) throw new SpiffeError("revocation_unavailable", "revocation must be a function");
        if (string.IsNullOrEmpty(opts.TrustDomain)) throw new SpiffeError("missing_trust_domain", "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)");
        var audience = opts.Audience;
        if (audience.Count == 0 || audience.Any(a => a.Length == 0)) throw new SpiffeError("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)");
        var algorithms = opts.Algorithms ?? new List<string>(JwtSvidAlgorithms);
        var bad = algorithms.FirstOrDefault(a => a == "none" || a.ToUpperInvariant().StartsWith("HS", StringComparison.Ordinal));
        if (bad != null || algorithms.Count == 0) throw new SpiffeError("forbidden_algorithm", $"JWT-SVIDs must not use {bad ?? "an empty algorithm list"}");

        try { J.AssertCanonicalCompactJws(token); }
        catch (CanonicalJwsException cause) { throw new SpiffeError("malformed_token", cause.Message); }
        var tok = (string)token!;
        double? tol = null;
        switch (opts.ClockTolerance)
        {
            case null: break;
            case Num n: tol = double.Parse(n.Raw, CultureInfo.InvariantCulture); break;
            case double d: tol = d; break;
            case string s: tol = Secs(s); break;
            default: throw new ArgumentException("Invalid clockTolerance option type");
        }
        if (opts.Key == null) throw new JoseTypeError("Key for the algorithm must be one of type KeyObject, CryptoKey, JSON Web Key, or Uint8Array");
        var jo = new JwtVerifyOptions { Algorithms = algorithms, AudienceList = audience, ClockTolerance = tol, CurrentDateMs = opts.CurrentDateMs };
        var v = J.JwtVerify(tok, opts.Key, jo);
        var payload = v.Payload;
        if (v.ProtectedHeader.TryGetValue("typ", out var typ) && !(typ is string ts && (ts == "JWT" || ts == "JOSE")))
            throw new SpiffeError("invalid_typ", $"JWT-SVID header typ must be JWT or JOSE, got '{AtlasPca.Js.JsJson.ToJsString(typ)}'");
        var exp = payload.GetValueOrDefault("exp");
        if (exp is not Num) throw new SpiffeError("missing_exp", "JWT-SVID is missing the required \"exp\" claim");
        if (payload.GetValueOrDefault("sub") is not string sub) throw new SpiffeError("invalid_subject", "JWT-SVID \"sub\" must be a string SPIFFE ID");
        SpiffeId spiffeId;
        try { spiffeId = ParseSpiffeId(sub); }
        catch (SpiffeError err) { throw new SpiffeError("invalid_subject", "JWT-SVID \"sub\" is not a valid SPIFFE ID: " + err.Message); }
        if (spiffeId.TrustDomain != opts.TrustDomain)
            throw new SpiffeError("trust_domain_mismatch", $"JWT-SVID trust domain \"{spiffeId.TrustDomain}\" does not match expected \"{opts.TrustDomain}\"");
        var aud = payload.GetValueOrDefault("aud");
        var resolved = aud == null ? new L() : aud is string sa ? new L { sa } : aud is L la ? new L(la) : new L();
        var outSvid = new JwtSvid(spiffeId, payload, resolved, exp);
        if (opts.Revocation is JwtRevocationCheck check)
        {
            object? verdict;
            try { verdict = check(new JwtRevocationSubject(spiffeId.Id, payload.GetValueOrDefault("jti") as string, exp, Sha256B64u(tok))); }
            catch (Exception e) { throw new SpiffeError("revocation_unavailable", "revocation check failed: " + Msg(e)); }
            if (verdict is true) throw new SpiffeError("svid_revoked", $"JWT-SVID for {spiffeId.Id} is revoked");
            if (verdict is not false) throw new SpiffeError("revocation_unavailable", "revocation check did not return a boolean");
        }
        outSvid.Verified = true;
        return outSvid;
    }

    // ---- X.509-SVID ----------------------------------------------------------------------------------------------

    static AttCert ParseCert(string text, byte[] raw)
    {
        try { return AttestCerts.FromPem(text); }
        catch (AttestError) { /* not PEM: the reference then reads the bytes as DER */ }
        return AttestCerts.ParseDer(raw);
    }

    static AttCert ToCertificate(object? cert)
    {
        try
        {
            if (cert is string s) return ParseCert(s, Encoding.UTF8.GetBytes(s));
            if (cert is byte[] b) return ParseCert(Encoding.Latin1.GetString(b), b);
            throw new ArgumentException("certificate must be PEM text or DER bytes");
        }
        catch (Exception e) { throw new SpiffeError("malformed_certificate", "cannot parse certificate: " + Msg(e)); }
    }

    static CertFacts FactsOf(AttCert c)
    {
        try { return SpiffeDer.ReadCertFacts(c.Raw); }
        catch (Exception e) { throw new SpiffeError("malformed_certificate", "cannot read certificate extensions: " + Msg(e)); }
    }

    static SpiffeId ValidateLeaf(AttCert certificate)
    {
        var facts = FactsOf(certificate);
        if (facts.UnknownCritical.Count > 0) throw new SpiffeError("unsupported_critical_extension", $"certificate has an unsupported critical extension ({string.Join(", ", facts.UnknownCritical)})");
        if (facts.UriSans.Count == 0) throw new SpiffeError("no_uri_san", "X.509-SVID certificate has no URI SAN");
        if (facts.UriSans.Count > 1) throw new SpiffeError("multiple_uri_san", $"X.509-SVID certificate must have exactly one URI SAN, found {facts.UriSans.Count}");
        var spiffeId = ParseSpiffeId(facts.UriSans[0]);
        if (spiffeId.Path.Length == 0) throw new SpiffeError("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path");
        if (facts.IsCa) throw new SpiffeError("leaf_is_ca", "leaf certificate must not have the CA flag set to true");
        if (!facts.DigitalSignature) throw new SpiffeError("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage");
        if (facts.KeyCertSign) throw new SpiffeError("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage");
        if (facts.CrlSign) throw new SpiffeError("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage");
        return spiffeId;
    }

    /// <summary>Parse an X.509-SVID (PEM text or DER bytes) and validate it as a SPIFFE leaf. Does NOT check the chain, validity or revocation: use
    /// <see cref="VerifyX509Svid"/>. A parsed-only SVID is refused by <see cref="SvidToHolder"/>.</summary>
    public static X509Svid ParseX509Svid(object? cert)
    {
        var certificate = ToCertificate(cert);
        var id = ValidateLeaf(certificate);
        return new X509Svid(id, certificate, Pca.B64u(certificate.RawSpki));
    }

    static List<AttCert> CertsOf(object? input)
    {
        if (input is string s)
        {
            var blocks = AttestCerts.PemBlocks(s);
            if (blocks.Count == 0) throw new SpiffeError("malformed_certificate", "no PEM certificate found");
            return blocks.Select(ToCertificate).ToList();
        }
        return new List<AttCert> { ToCertificate(input) };
    }

    static CertFacts ValidateSigner(AttCert cert, string label)
    {
        var facts = FactsOf(cert);
        if (facts.UnknownCritical.Count > 0) throw new SpiffeError("unsupported_critical_extension", $"{label} has an unsupported critical extension ({string.Join(", ", facts.UnknownCritical)})");
        if (!facts.IsCa) throw new SpiffeError("chain_not_ca", $"{label} must have the CA flag set to true");
        if (!facts.KeyUsagePresent || !facts.KeyCertSign) throw new SpiffeError("chain_no_key_cert_sign", $"{label} must have 'keyCertSign' set as key usage");
        return facts;
    }

    static bool WithinValidity(AttCert c, long nowMs)
    {
        try { return AttestDer.DerValidAt(c.Raw, nowMs, 0); }
        catch (Exception) { return false; }
    }

    // ---- the issuance relation (the reference's X509Certificate.checkIssued) ----

    /// <summary>[content start, content end) of the TLV at <paramref name="off"/>, or null when it does not fit.</summary>
    static (int Start, int End)? Tlv(byte[] d, int off, int limit)
    {
        if (off + 2 > limit) return null;
        long len = d[off + 1];
        long p = off + 2;
        if ((len & 0x80) != 0)
        {
            int n = (int)(len & 0x7f);
            if (n == 0 || n > 4 || p + n > limit) return null;
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + d[p + i];
            p += n;
        }
        if (p + len > limit) return null;
        return ((int)p, (int)(p + len));
    }

    static byte[]? Skid(AttCert c)
    {
        var v = c.ExtValue("2.5.29.14");
        if (v == null || v.Length < 2 || v[0] != 0x04) return null;
        return Tlv(v, 0, v.Length) is { } t ? v[t.Start..t.End] : null;
    }

    static BigInteger IntOf(byte[] b) => b.Length == 0 ? BigInteger.Zero : new BigInteger(b, isUnsigned: false, isBigEndian: true);

    /// <summary>True when <paramref name="issuer"/> could have issued <paramref name="subject"/>: names, authority key id / serial / issuer, and keyCertSign.</summary>
    internal static bool CheckIssued(AttCert subject, AttCert issuer)
    {
        if (!subject.RawIssuer.AsSpan().SequenceEqual(issuer.RawSubject)) return false;
        var akid = subject.ExtValue("2.5.29.35");
        if (akid != null)
        {
            if (akid.Length == 0 || akid[0] != 0x30 || Tlv(akid, 0, akid.Length) is not { } seq) return false;
            byte[]? keyId = null, gens = null, serial = null;
            int off = seq.Start;
            while (off < seq.End)
            {
                if (Tlv(akid, off, seq.End) is not { } t) return false;
                if (akid[off] == 0x80) keyId = akid[t.Start..t.End];
                else if (akid[off] == 0xa1) gens = akid[t.Start..t.End];
                else if (akid[off] == 0x82) serial = akid[t.Start..t.End];
                off = t.End;
            }
            if (keyId != null && Skid(issuer) is { } sk && !keyId.AsSpan().SequenceEqual(sk)) return false;
            if (serial != null && IntOf(serial) != IntOf(issuer.Serial)) return false;
            if (gens != null)
            {
                // the first directoryName of authorityCertIssuer must name the issuer's own issuer
                int g = 0;
                while (g < gens.Length)
                {
                    if (Tlv(gens, g, gens.Length) is not { } t) return false;
                    if (gens[g] == 0xa4)
                    {
                        if (!gens.AsSpan(t.Start, t.End - t.Start).SequenceEqual(issuer.RawIssuer)) return false;
                        break;
                    }
                    g = t.End;
                }
            }
        }
        var ku = issuer.ExtValue("2.5.29.15");
        if (ku != null)
        {
            if (ku.Length == 0 || ku[0] != 0x03 || Tlv(ku, 0, ku.Length) is not { } t || t.End - t.Start < 2) return false;
            if ((ku[t.Start + 1] & 0x04) == 0) return false;
        }
        return true;
    }

    static bool IssuedAndSigned(AttCert cert, AttCert signer) => CheckIssued(cert, signer) && AttestCerts.SigOkBy(cert, signer);

    static string SerialHex(AttCert c)
    {
        var v = IntOf(c.Serial);
        var h = Convert.ToHexString(BigInteger.Abs(v).ToByteArray(isUnsigned: true, isBigEndian: true));
        return (v.Sign < 0 ? "-" : "") + h;
    }

    static string Fingerprint256(AttCert c) => string.Join(":", SHA256.HashData(c.Raw).Select(x => x.ToString("X2", CultureInfo.InvariantCulture)));

    /// <summary>Verify an X.509-SVID against a trust bundle: the leaf rules, its trust domain, every certificate's validity, each certificate signed by the next,
    /// signing certificates with cA and keyCertSign, pathLenConstraint, and an end at (or signed by) a bundle authority. <paramref name="chain"/> is PEM text
    /// (several certificates) or a list of PEM text / DER bytes, leaf first. Revocation is checked only through <c>opts.Revocation</c>.</summary>
    public static X509Svid VerifyX509Svid(object? chain, VerifyX509SvidOptions opts)
    {
        if (opts.Revocation != null && opts.Revocation is not X509RevocationCheck) throw new SpiffeError("revocation_unavailable", "revocation must be a function");
        long now = opts.NowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var items = new List<AttCert>();
        if (chain is string cs) items.AddRange(CertsOf(cs));
        else if (chain is System.Collections.IEnumerable list && chain is not byte[]) foreach (var c in list) items.AddRange(CertsOf(c));
        else throw new ArgumentException("chain must be PEM text or a list");
        if (items.Count == 0) throw new SpiffeError("chain_empty", "certificate chain is empty");
        if (items.Count > (opts.MaxChainLength ?? 8)) throw new SpiffeError("chain_too_long", "certificate chain is too long");
        var leaf = items[0];
        var spiffeId = ValidateLeaf(leaf);
        if (spiffeId.TrustDomain != opts.TrustDomain) throw new SpiffeError("chain_trust_domain_mismatch", $"SPIFFE ID trust domain '{spiffeId.TrustDomain}' is not '{opts.TrustDomain}'");
        var roots = new List<AttCert>();
        foreach (var r in opts.Roots) roots.AddRange(CertsOf(r));
        if (roots.Count == 0) throw new SpiffeError("chain_untrusted_root", "trust bundle has no X.509 authorities");

        foreach (var c in items)
            if (!WithinValidity(c, now)) throw new SpiffeError("chain_expired", "a certificate in the chain is not within its validity period");
        for (int i = 1; i < items.Count; i++)
        {
            var f = ValidateSigner(items[i], $"signing certificate #{i}");
            if (f.PathLen is double pl && i - 1 > pl) throw new SpiffeError("chain_path_len", $"signing certificate #{i} pathLenConstraint exceeded");
        }
        int below = items.Count - 1;
        for (int i = 0; i + 1 < items.Count; i++)
            if (!IssuedAndSigned(items[i], items[i + 1])) throw new SpiffeError("chain_signature", $"certificate #{i} is not signed by certificate #{i + 1}");
        var top = items[^1];
        if (items.Count == 1 && roots.Any(r => r.Raw.AsSpan().SequenceEqual(leaf.Raw))) throw new SpiffeError("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor");
        bool topIsAnchor = items.Count > 1 && roots.Any(r => r.Raw.AsSpan().SequenceEqual(top.Raw));
        if (!topIsAnchor)
        {
            var signer = roots.FirstOrDefault(r => IssuedAndSigned(top, r));
            if (signer == null) throw new SpiffeError("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle");
            if (!WithinValidity(signer, now)) throw new SpiffeError("chain_expired", "the trust bundle authority is not within its validity period");
            var f = ValidateSigner(signer, "trust bundle authority");
            if (f.PathLen is double pl && below > pl) throw new SpiffeError("chain_path_len", "trust bundle authority pathLenConstraint exceeded");
        }

        if (opts.Revocation is X509RevocationCheck check)
        {
            for (int i = 0; i < items.Count; i++)
            {
                var c = items[i];
                object? verdict;
                try { verdict = check(new X509RevocationSubject(spiffeId.Id, SerialHex(c), Fingerprint256(c), i, i == 0)); }
                catch (Exception e) { throw new SpiffeError("revocation_unavailable", "revocation check failed: " + Msg(e)); }
                if (verdict is true)
                    throw new SpiffeError(i == 0 ? "svid_revoked" : "chain_revoked", i == 0 ? $"X.509-SVID for {spiffeId.Id} is revoked" : $"signing certificate #{i} of the chain is revoked");
                if (verdict is not false) throw new SpiffeError("revocation_unavailable", "revocation check did not return a boolean");
            }
        }
        return new X509Svid(spiffeId, leaf, Pca.B64u(leaf.RawSpki)) { Verified = true };
    }

    // ---- SPIFFE ID <-> PCA agent-holder identity -----------------------------------------------------------------

    /// <summary>A 32-byte Ed25519 holder key (base64url text or raw bytes) as canonical base64url.</summary>
    static string NormalizeHolderKey(object? holderKey)
    {
        if (holderKey is byte[] raw)
        {
            if (raw.Length != 32) throw new SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key");
            return Pca.B64u(raw);
        }
        var bytes = Pca.B64uDecode(holderKey, 32);
        if (bytes == null) throw new SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url");
        return Pca.B64u(bytes);
    }

    /// <summary>Domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID.</summary>
    public static byte[] HolderBindingMessage(string spiffeId, string holder) => Encoding.UTF8.GetBytes("pca-spiffe-holder-binding-v1\n" + spiffeId + "\n" + holder);

    static string? Ed25519RawOfCert(AttCert cert)
    {
        try { var k = AttestCerts.KeyOf(cert); return k.Type == "ed25519" && k.Ed25519 != null ? Pca.B64u(k.Ed25519) : null; }
        catch (Exception) { return null; }
    }

    static bool ProofVerifies(AttCert cert, byte[] msg, byte[] sig)
    {
        try
        {
            var k = AttestCerts.KeyOf(cert);
            if (k.Type == "ed25519" && k.Ed25519 != null)
            {
                var v = new Ed25519Signer();
                v.Init(false, new Ed25519PublicKeyParameters(k.Ed25519, 0));
                v.BlockUpdate(msg, 0, msg.Length);
                return v.VerifySignature(sig);
            }
            if (k.Type == "ec" && k.Ec != null)
                return k.Ec.VerifyData(msg, sig, k.GoCurve == "P-384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (k.Type == "rsa" && k.Rsa != null) return k.Rsa.VerifyData(msg, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception) { }
        return false;
    }

    /// <summary>Bind a VERIFIED SPIFFE SVID to a PCA agent-holder. <paramref name="svid"/> MUST be the object returned by <see cref="VerifyJwtSvid"/> or
    /// <see cref="VerifyX509Svid"/>; anything else throws <c>unverified_svid</c>. <paramref name="holderKey"/> is base64url text, 32 raw bytes or null.
    /// An X.509-SVID with an Ed25519 key is its own holder; another key (or a different holder) needs <c>opts.Proof</c>. A JWT-SVID needs
    /// <paramref name="holderKey"/> and a matching <c>cnf.jwk</c> unless <c>opts.AcceptUnboundJwtHolder</c>.</summary>
    public static SpiffeHolder SvidToHolder(object? svid, object? holderKey = null, SvidToHolderOptions? opts = null)
    {
        if (!((svid is JwtSvid { Verified: true }) || (svid is X509Svid { Verified: true })))
            throw new SpiffeError("unverified_svid", "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)");
        var o = opts ?? new SvidToHolderOptions();
        string holder;
        SpiffeId parsed;
        if (svid is X509Svid x)
        {
            parsed = x.SpiffeId;
            var certEd = Ed25519RawOfCert(x.Certificate);
            if (holderKey == null)
            {
                if (certEd == null) throw new SpiffeError("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof");
                holder = NormalizeHolderKey(certEd);
            }
            else
            {
                holder = NormalizeHolderKey(holderKey);
                if (certEd == null || certEd != holder)
                {
                    if (o.Proof is not string proof) throw new SpiffeError("holder_binding_failed", "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required");
                    var sig = Pca.B64uDecode(proof);
                    bool ok = sig != null && ProofVerifies(x.Certificate, HolderBindingMessage(parsed.Id, holder), sig);
                    if (!ok) throw new SpiffeError("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key");
                }
            }
        }
        else
        {
            var j = (JwtSvid)svid!;
            parsed = j.SpiffeId;
            if (holderKey == null) throw new SpiffeError("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey");
            holder = NormalizeHolderKey(holderKey);
            var jwk = (j.Claims.GetValueOrDefault("cnf") as D)?.GetValueOrDefault("jwk") as D;
            bool bound = jwk != null && jwk.GetValueOrDefault("kty") is "OKP" && jwk.GetValueOrDefault("crv") is "Ed25519" && jwk.GetValueOrDefault("x") is string jx && jx == holder;
            if (!bound && !o.AcceptUnboundJwtHolder)
                throw new SpiffeError("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)");
        }
        return new SpiffeHolder(holder, parsed.Id, parsed.TrustDomain, parsed.Path);
    }

    /// <summary>The (validated, canonical) SPIFFE ID a <see cref="SpiffeHolder"/> was bridged from.</summary>
    public static string HolderToSpiffeId(SpiffeHolder holder) => ParseSpiffeId(holder.SpiffeId).Id;

    /// <summary>The SPIFFE ID the spiffe_bound caveat compares: the workload identity a VERIFIED SVID carries, only when that SVID is bound to
    /// <paramref name="leafHolder"/> (the key that signed the PCActn). Same binding rules as <see cref="SvidToHolder"/>.</summary>
    public static string SpiffeIdForHolder(object? svid, string? leafHolder, SvidToHolderOptions? opts = null)
    {
        var h = SvidToHolder(svid, leafHolder, opts);
        if (h.Holder != leafHolder) throw new SpiffeError("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder");
        return h.SpiffeId;
    }

    /// <summary>A discharge-issuer pin for a workload: <c>{label, class: "workload", pk, spiffe_id}</c> (an X.509-SVID with an Ed25519 key only).</summary>
    public static D WorkloadDischargePin(string label, object? svid)
    {
        var h = SvidToHolder(svid);
        return new D { ["label"] = label, ["class"] = "workload", ["pk"] = h.Holder, ["spiffe_id"] = h.SpiffeId };
    }

    // ---- revocation source ---------------------------------------------------------------------------------------

    static bool FinitePositiveOrder(double refreshMs, double maxStaleMs) =>
        !double.IsNaN(refreshMs) && !double.IsInfinity(refreshMs) && refreshMs > 0 && !double.IsNaN(maxStaleMs) && !double.IsInfinity(maxStaleMs) && maxStaleMs >= refreshMs;

    static string NormHex(string s) => s.Replace(":", "").ToUpperInvariant();

    static string NormSerial(string s)
    {
        var h = NormHex(s);
        // /^0+(?=.)/: the zeros stop one character short of the end, and that next character must not be a line terminator
        int z = 0;
        while (z < h.Length && h[z] == '0') z++;
        for (int k = z; k >= 1; k--)
            if (k < h.Length && h[k] is not ('\n' or '\r' or '\u2028' or '\u2029')) return h[k..];
        return h;
    }

    static List<string> ListOf(D raw, string key)
    {
        if (!raw.ContainsKey(key)) return new List<string>();
        if (raw[key] is not L l || l.Any(x => x is not string)) throw new SpiffeError("revocation_unavailable", $"revocation list field \"{key}\" must be an array of strings");
        return l.Select(x => (string)x!).ToList();
    }

    sealed class Snapshot
    {
        public readonly HashSet<string> Fingerprints = new(), Serials = new(), SpiffeIds = new(), Jtis = new(), TokenHashes = new();
    }

    static Snapshot ToSnapshot(object? list)
    {
        if (list is not D raw) throw new SpiffeError("revocation_unavailable", "revocation list must be an object");
        var s = new Snapshot();
        foreach (var x in ListOf(raw, "fingerprints")) s.Fingerprints.Add(NormHex(x));
        foreach (var x in ListOf(raw, "serials")) s.Serials.Add(NormSerial(x));
        foreach (var x in ListOf(raw, "spiffeIds")) s.SpiffeIds.Add(x);
        foreach (var x in ListOf(raw, "jtis")) s.Jtis.Add(x);
        foreach (var x in ListOf(raw, "tokenHashes")) s.TokenHashes.Add(x);
        return s;
    }

    /// <summary>A revocation snapshot cache that fails closed: before the first successful fetch, or once the last good snapshot is older than
    /// <c>maxStaleMs</c>, every check refuses with <c>revocation_unavailable</c>. A successful refresh replaces the snapshot. The fetch returns a JSON object
    /// <c>{fingerprints?, serials?, spiffeIds?, jtis?, tokenHashes?}</c> of string arrays.</summary>
    public sealed class RevocationSource
    {
        readonly Fetch fetch;
        readonly double refreshMs, maxStaleMs;
        readonly Func<long> now;
        readonly object gate = new();
        Snapshot? good;
        long goodAt;
        SpiffeError? lastFailure;

        /// <summary>For <see cref="VerifyX509SvidOptions.Revocation"/>: uses the cached snapshot, so call <see cref="EnsureFresh"/> first.</summary>
        public X509RevocationCheck X509 { get; }
        /// <summary>For <see cref="VerifyJwtSvidOptions.Revocation"/>: refreshes the snapshot itself when it is due.</summary>
        public JwtRevocationCheck Jwt { get; }

        internal RevocationSource(Fetch fetch, double refreshMs, double maxStaleMs, Func<long> now)
        {
            this.fetch = fetch; this.refreshMs = refreshMs; this.maxStaleMs = maxStaleMs; this.now = now;
            X509 = s =>
            {
                Snapshot snap;
                lock (gate) snap = Usable();
                return snap.Fingerprints.Contains(NormHex(s.Fingerprint256)) || snap.Serials.Contains(NormSerial(s.SerialNumber)) || snap.SpiffeIds.Contains(s.SpiffeId);
            };
            Jwt = s =>
            {
                Snapshot snap;
                lock (gate) { EnsureFresh(); snap = Usable(); }
                return snap.SpiffeIds.Contains(s.SpiffeId) || (s.Jti != null && snap.Jtis.Contains(s.Jti)) || snap.TokenHashes.Contains(s.TokenHash);
            };
        }

        void Run()
        {
            try
            {
                var snap = ToSnapshot(fetch());
                good = snap;
                goodAt = now();
                lastFailure = null;
            }
            catch (Exception e)
            {
                lastFailure = e as SpiffeError ?? new SpiffeError("revocation_unavailable", "revocation fetch failed: " + Msg(e));
            }
        }

        Snapshot Usable()
        {
            if (good == null || (double)(now() - goodAt) > maxStaleMs)
                throw lastFailure ?? new SpiffeError("revocation_unavailable", "no revocation snapshot available");
            return good;
        }

        /// <summary>Fetch when the snapshot is older than <c>refreshMs</c>; refuses when no snapshot younger than <c>maxStaleMs</c> exists afterwards.</summary>
        public void EnsureFresh()
        {
            lock (gate)
            {
                if (good == null || (double)(now() - goodAt) >= refreshMs) Run();
                Usable();
            }
        }

        /// <summary>Fetch now. Throws <c>revocation_unavailable</c> when the fetch fails or returns a malformed snapshot.</summary>
        public void Refresh()
        {
            lock (gate)
            {
                Run();
                if (lastFailure != null) throw lastFailure;
            }
        }
    }

    /// <summary>Create a <see cref="RevocationSource"/>; <paramref name="now"/> null = the system clock (epoch ms).</summary>
    public static RevocationSource CreateRevocationSource(Fetch? fetch, double refreshMs, double maxStaleMs, Func<long>? now = null)
    {
        if (fetch == null) throw new SpiffeError("revocation_unavailable", "createRevocationSource requires `fetch`");
        if (!FinitePositiveOrder(refreshMs, maxStaleMs)) throw new SpiffeError("revocation_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)");
        return new RevocationSource(fetch, refreshMs, maxStaleMs, now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
    }

    // ---- trust bundle source -------------------------------------------------------------------------------------

    static bool UsableBundle(object? b)
    {
        if (b is not D t) return false;
        bool j = false;
        if (t.TryGetValue("jwks", out var jw))
        {
            if (jw == null) throw new InvalidOperationException("Cannot read properties of null (reading 'keys')");
            j = jw is D jd && jd.GetValueOrDefault("keys") is L keys && keys.Count > 0;
        }
        bool x = t.GetValueOrDefault("x509Authorities") is L auth && auth.Count > 0;
        return j || x;
    }

    /// <summary>A trust-bundle cache that fails closed: a rejected or empty / malformed refresh keeps the last good bundle only until <c>maxStaleMs</c> after its
    /// last successful fetch; before the first success, or past that limit, every call throws <c>trust_bundle_unavailable</c> (fetch failed) or
    /// <c>trust_bundle_invalid</c> (fetched but empty / malformed). A bundle is never merged. The fetch returns
    /// <c>{jwks?: {keys: [...]}, x509Authorities?: [...]}</c>.</summary>
    public sealed class TrustBundleSource
    {
        readonly Fetch fetch;
        readonly double refreshMs, maxStaleMs;
        readonly Func<long> now;
        readonly object gate = new();
        D? good;
        long goodAt;
        SpiffeError? lastFailure;

        /// <summary>Key resolver for <see cref="VerifyJwtSvidOptions.Key"/>.</summary>
        public Func<D, object?> JwtKey { get; }

        internal TrustBundleSource(Fetch fetch, double refreshMs, double maxStaleMs, Func<long> now)
        {
            this.fetch = fetch; this.refreshMs = refreshMs; this.maxStaleMs = maxStaleMs; this.now = now;
            JwtKey = header =>
            {
                D bundle;
                lock (gate) bundle = Current();
                if (!bundle.TryGetValue("jwks", out var jwks)) throw new SpiffeError("trust_bundle_invalid", "trust bundle has no JWT authorities");
                if (jwks is not D jd || !jd.ContainsKey("keys")) throw new InvalidOperationException("Cannot read properties of undefined (reading 'length')");
                if (jd["keys"] is L kl && kl.Count == 0) throw new SpiffeError("trust_bundle_invalid", "trust bundle has no JWT authorities");
                return J.CreateLocalJwkSet(jwks)(header);
            };
        }

        void Refresh()
        {
            try
            {
                var b = fetch();
                if (!UsableBundle(b)) throw new SpiffeError("trust_bundle_invalid", "fetched trust bundle has no authorities");
                good = (D)b!;
                goodAt = now();
                lastFailure = null;
            }
            catch (Exception e)
            {
                lastFailure = e as SpiffeError ?? new SpiffeError("trust_bundle_unavailable", "trust bundle fetch failed: " + Msg(e));
            }
        }

        D Current()
        {
            if (good == null || (double)(now() - goodAt) >= refreshMs) Refresh();
            if (good == null || (double)(now() - goodAt) > maxStaleMs)
                throw lastFailure ?? new SpiffeError("trust_bundle_unavailable", "no trust bundle available");
            return good;
        }

        /// <summary>Authorities for <see cref="VerifyX509SvidOptions.Roots"/>. Throws a <see cref="SpiffeError"/> when no usable bundle exists.</summary>
        public List<object?> X509Roots()
        {
            lock (gate)
            {
                if (Current().GetValueOrDefault("x509Authorities") is not L roots || roots.Count == 0)
                    throw new SpiffeError("trust_bundle_invalid", "trust bundle has no X.509 authorities");
                return new List<object?>(roots);
            }
        }
    }

    /// <summary>Create a <see cref="TrustBundleSource"/>; <paramref name="now"/> null = the system clock (epoch ms).</summary>
    public static TrustBundleSource CreateTrustBundleSource(Fetch? fetch, double refreshMs, double maxStaleMs, Func<long>? now = null)
    {
        if (fetch == null) throw new SpiffeError("trust_bundle_unavailable", "createTrustBundleSource requires `fetch`");
        if (!FinitePositiveOrder(refreshMs, maxStaleMs)) throw new SpiffeError("trust_bundle_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)");
        return new TrustBundleSource(fetch, refreshMs, maxStaleMs, now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
    }

    // ---- admission evidence --------------------------------------------------------------------------------------

    /// <summary>Admit a workload under its verified SPIFFE ID: verify the SVID, bind it to <paramref name="instanceKey"/>, and return its identity. Anything
    /// unverifiable, unbound or for a different key is <c>ok: false</c> with the error code as the reason (a JOSE failure: its code; otherwise the exception type name).</summary>
    public static SpiffeAdmissionEvidenceResult SpiffeAdmissionEvidence(SpiffeEvidence e, string? instanceKey)
    {
        try
        {
            object svid = e.Kind == "x509" ? VerifyX509Svid(e.Chain, e.VerifyX509!) : VerifyJwtSvid(e.Token, e.VerifyJwt!);
            var h = SvidToHolder(svid, instanceKey, e.Bind);
            if (h.Holder != instanceKey) return new SpiffeAdmissionEvidenceResult(false, false, null, "SVID is bound to a different key");
            return new SpiffeAdmissionEvidenceResult(true, true, h.SpiffeId, null);
        }
        catch (SpiffeError err) { return new SpiffeAdmissionEvidenceResult(false, false, null, err.Code); }
        catch (JoseException err) { return new SpiffeAdmissionEvidenceResult(false, false, null, err.Code); }
        catch (JoseTypeError) { return new SpiffeAdmissionEvidenceResult(false, false, null, "TypeError"); }
        catch (Exception err) { return new SpiffeAdmissionEvidenceResult(false, false, null, err.GetType().Name); }
    }
}
