// Sender-constrained proof of possession for PCA: RFC 9449 DPoP proofs (a holder-key-signed dpop+jwt over the HTTP method and target URI, key
// thumbprint jkt), RFC 8705 mTLS x5t#S256 confirmation, and their binding to a PCActn's real holder key (the leaf of its capability chain, an
// Ed25519 key). Maps onto the reference's pca-dpop exports (PascalCase); JWKs are the JSON tree (Dictionary). Verification fails closed with a
// DpopVerificationException whose Code names the failed check.
//
// shortcut: normalizeHtu reads the URL with the minimal WHATWG reader in AtlasPca.Jose (IDNA through the platform mapping); an exotic URL it
// cannot parse is refused as ERR_INVALID_URL. String.toUpperCase special casing beyond sharp s is not modelled (ToUpperInvariant otherwise).
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Jose;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Dpop;

/// <summary>A DPoP proof (or PCActn / DPoP binding) that failed to verify; <see cref="Code"/> names the specific check.</summary>
public sealed class DpopVerificationException : Exception
{
    public string Code { get; }
    public DpopVerificationException(string code, string message) : base(message) { Code = code; }
}

/// <summary>A set of already-seen jti values.</summary>
public interface IJtiSeenSet
{
    bool Has(string jti);
    void Add(string jti);
}

/// <summary>A durable atomic jti replay store: <see cref="AddIfAbsent"/> must be atomic (of N concurrent calls with one key exactly one returns true).
/// The key is <c>jkt.jti</c>. An entry may be dropped once <c>nowSec &gt;= expiresAtSec</c>.</summary>
public interface IDpopReplayStore
{
    bool AddIfAbsent(string key, double expiresAtSec, double nowSec);
}

/// <summary>Issues and checks stateless server DPoP nonces (RFC 9449 s8, s9): a timestamp MACed with a server secret.</summary>
public interface IDpopNonceIssuer
{
    /// <summary>A fresh nonce (<paramref name="nowSec"/> null = now); the time must be a non-negative integer.</summary>
    string Issue(double? nowSec = null);
    /// <summary>True only for a nonce this issuer minted that is at most the ttl old and not from the future.</summary>
    bool Check(object? nonce, double? nowSec = null);
}

public sealed record CreateDpopProofInput
{
    /// <summary>HTTP method (stored upper-cased as htm).</summary>
    public string? Method { get; init; }
    /// <summary>Full request URL; htu is this with query and fragment removed.</summary>
    public string? Url { get; init; }
    /// <summary>The holder's private JWK (or a private <see cref="JoseKey"/>) that signs the proof.</summary>
    public object? PrivateKey { get; init; }
    /// <summary>The holder's public JWK, embedded in the proof header; drives the alg.</summary>
    public D? PublicJwk { get; init; }
    public string? Nonce { get; init; }
    public string? Ath { get; init; }
    /// <summary>Issued-at override (epoch seconds); null = now.</summary>
    public double? Iat { get; init; }
    /// <summary>Proof id override; null = a random UUID.</summary>
    public string? Jti { get; init; }
    /// <summary>Clock in epoch ms (default: the system clock).</summary>
    public Func<long>? NowMs { get; init; }
}

public sealed record VerifyDpopProofOptions
{
    public string? Method { get; init; }
    public string? Url { get; init; }
    /// <summary>Maximum accepted proof age in seconds (from iat to now).</summary>
    public double MaxAgeSec { get; init; }
    public string? ExpectedJkt { get; init; }
    public IJtiSeenSet? SeenJti { get; init; }
    public IDpopReplayStore? ReplayStore { get; init; }
    /// <summary>Default true: a verification with neither store is refused (replay_store_required).</summary>
    public bool? RequireReplayStore { get; init; }
    public IDpopNonceIssuer? NonceIssuer { get; init; }
    /// <summary>Override "now" (epoch seconds).</summary>
    public double? NowSec { get; init; }
    public string? ExpectedNonce { get; init; }
    public string? AccessToken { get; init; }
}

/// <summary>Options of <see cref="Dpop.AssertPcaDpop"/>: like <see cref="VerifyDpopProofOptions"/> with MaxAgeSec optional (default 300) and no ExpectedJkt.</summary>
public sealed record AssertPcaDpopOptions
{
    public string? Method { get; init; }
    public string? Url { get; init; }
    public double? MaxAgeSec { get; init; }
    public IJtiSeenSet? SeenJti { get; init; }
    public IDpopReplayStore? ReplayStore { get; init; }
    public bool? RequireReplayStore { get; init; }
    public IDpopNonceIssuer? NonceIssuer { get; init; }
    public double? NowSec { get; init; }
    public string? ExpectedNonce { get; init; }
    public string? AccessToken { get; init; }
}

/// <summary>A verified proof: its claims, the embedded public JWK and that key's RFC 7638 thumbprint.</summary>
public sealed record DpopVerifyResult(D Claims, D Jwk, string Jkt);

public static class Dpop
{
    /// <summary>JWS algorithms a DPoP proof may use: asymmetric only, never none or a MAC (RFC 9449 s4.2).</summary>
    public static readonly IReadOnlyList<string> DpopAllowedAlgs = new[] { "EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256" };
    public const string DpopJwtTyp = "dpop+jwt";
    public const double DpopDefaultMaxAgeSec = 300;
    public const double DpopClockSkewSec = 5;
    public const int DpopMaxProofBytes = 8192;
    public const int DpopInmemoryMaxEntries = 100_000;

    static DpopVerificationException Err(string code, string message) => new(code, message);

    // ===================== replay stores =====================

    sealed class InMemoryStore : IDpopReplayStore
    {
        readonly double _max;
        readonly Dictionary<string, double> _seen = new();
        public InMemoryStore(double max) { _max = max; }
        public bool AddIfAbsent(string key, double expiresAtSec, double nowSec)
        {
            lock (_seen)
            {
                if (!double.IsFinite(nowSec)) return false; // a non-finite clock admits nothing
                bool has = _seen.TryGetValue(key, out var held);
                if (has && !(nowSec >= held)) return false;
                if (!has && _seen.Count >= _max)
                {
                    foreach (var k in _seen.Where(e => nowSec >= e.Value).Select(e => e.Key).ToList()) _seen.Remove(k);
                    if (_seen.Count >= _max) throw new InvalidOperationException("replay store is full");
                }
                _seen[key] = expiresAtSec;
                return true;
            }
        }
    }

    /// <summary>Single-process, explicitly bounded store: when <paramref name="maxEntries"/> live entries are held a further new key makes AddIfAbsent
    /// throw (the verifier then refuses with replay_store_error) instead of evicting a live entry.</summary>
    public static IDpopReplayStore CreateInMemoryDpopReplayStore(double? maxEntries = null)
    {
        double max = maxEntries ?? DpopInmemoryMaxEntries;
        if (!double.IsFinite(max) || max != Math.Round(max) || max < 1) throw Err("misconfigured", "maxEntries must be a positive integer");
        return new InMemoryStore(max);
    }

    /// <summary>The conformance suite for a replay store: the failed checks (empty = conformant). <paramref name="make"/> returns a FRESH empty store.</summary>
    public static List<string> RunDpopReplayStoreConformance(Func<IDpopReplayStore> make)
    {
        var failures = new List<string>();
        var s = make();
        if (!s.AddIfAbsent("a", 200, 100)) failures.Add("first sight of a key returns true");
        if (s.AddIfAbsent("a", 200, 101)) failures.Add("second sight of the same key returns false");
        if (!s.AddIfAbsent("b", 200, 101)) failures.Add("a different key is independent");
        if (s.AddIfAbsent("a", 200, 199)) failures.Add("still seen one second before expiry");
        var t = make();
        t.AddIfAbsent("c", 200, 100);
        if (!t.AddIfAbsent("c", 400, 200)) failures.Add("an expired entry may be added again (nowSec >= expiresAtSec)");
        var u = make();
        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(() => u.AddIfAbsent("race", 200, 100))).ToArray();
        int wins = 0;
        foreach (var task in tasks)
        {
            try { if (task.GetAwaiter().GetResult()) wins++; }
            catch (Exception) { /* a store that throws under contention fails the check below */ }
        }
        if (wins != 1) failures.Add($"16 concurrent adds of one key: exactly one wins (got {wins})");
        return failures;
    }

    // ===================== server nonces =====================

    sealed class NonceIssuer : IDpopNonceIssuer
    {
        readonly byte[] _key; readonly double _ttl;
        public NonceIssuer(byte[] key, double ttl) { _key = key; _ttl = ttl; }
        byte[] Mac(byte[] ts) => HMACSHA256.HashData(_key, Pca.Cat(Encoding.UTF8.GetBytes("dpop-nonce\0"), ts))[..16];
        static double Now() => Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);
        public string Issue(double? nowSec = null)
        {
            double n = nowSec ?? Now();
            // BigInt(n): an integer; writeBigUInt64BE: 0 <= n < 2^64
            if (!double.IsFinite(n) || n != Math.Floor(n) || n < 0 || n >= 18446744073709551616.0) throw new ArgumentOutOfRangeException(nameof(nowSec), $"The number {n} cannot be converted to a BigInt");
            ulong v = (ulong)n;
            var ts = new byte[8];
            for (int i = 0; i < 8; i++) ts[i] = (byte)(v >> (56 - 8 * i));
            return Pca.B64u(Pca.Cat(ts, Mac(ts)));
        }
        public bool Check(object? nonce, double? nowSec = null)
        {
            if (nonce is not string s) return false;
            double now = nowSec ?? Now();
            var raw = Pca.B64uDecode(s, 24);
            if (raw == null) return false;
            var ts = raw[..8];
            if (!CryptographicOperations.FixedTimeEquals(raw.AsSpan(8, 16), Mac(ts))) return false;
            double issued = 0;
            foreach (var b in ts) issued = issued * 256 + b;
            return double.IsFinite(now) && issued <= now + DpopClockSkewSec && now - issued <= _ttl;
        }
    }

    /// <summary>Creates a nonce issuer: <paramref name="secret"/> at least 32 bytes, <paramref name="ttlSec"/> the lifetime (null = 300).</summary>
    public static IDpopNonceIssuer CreateDpopNonceIssuer(byte[]? secret, double? ttlSec = null)
    {
        if (secret == null || secret.Length < 32) throw Err("misconfigured", "nonce secret must be at least 32 bytes");
        double ttl = ttlSec ?? 300;
        if (!double.IsFinite(ttl) || ttl <= 0) throw Err("misconfigured", "nonce ttlSec must be positive");
        return new NonceIssuer((byte[])secret.Clone(), ttl);
    }

    // ===================== helpers =====================

    /// <summary>The JavaScript read <c>jwk.member</c>: undefined (null here) for anything that is not an object, a TypeError for null.</summary>
    static object? Member(object? jwk, string name)
    {
        if (jwk == null) throw new InvalidOperationException($"Cannot read properties of null (reading '{name}')");
        return (jwk as D)?.GetValueOrDefault(name);
    }

    /// <summary>JavaScript's <c>String(v)</c>, as far as an error message needs it.</summary>
    static string JsStr(object? v) => v switch
    {
        null => "undefined",
        string s => s,
        Num n => IntentJs.NormNum(n.Raw).Raw,
        bool b => b ? "true" : "false",
        L l => string.Join(",", l.Select(x => x == null ? "" : JsStr(x))),
        _ => "[object Object]",
    };

    /// <summary>The RFC 7638 JWK thumbprint (base64url); digest sha256 (default) | sha384 | sha512.</summary>
    public static string JwkThumbprint(object? jwk, string? digest = null) => J.JwkThumbprint(jwk, digest);

    /// <summary>The JWS alg for a key, from its JWK kty / crv. Throws unsupported_key for an unsupported or MAC key.</summary>
    public static string DpopAlgForJwk(object? jwk)
    {
        var kty = Member(jwk, "kty"); var crv = Member(jwk, "crv");
        switch (kty)
        {
            case "OKP":
                if (crv is "Ed25519" or "Ed448") return "EdDSA";
                throw Err("unsupported_key", $"unsupported OKP curve '{JsStr(crv)}' for DPoP");
            case "EC":
                if (crv is "P-256") return "ES256";
                if (crv is "P-384") return "ES384";
                if (crv is "P-521") return "ES512";
                throw Err("unsupported_key", $"unsupported EC curve '{JsStr(crv)}' for DPoP");
            case "RSA": return "PS256";
            default: throw Err("unsupported_key", $"unsupported key type '{JsStr(kty)}' for DPoP");
        }
    }

    /// <summary>True when the allow-listed JWS alg belongs to the key type of the JWK. Unknown algs never match.</summary>
    public static bool DpopAlgMatchesJwk(string? alg, object? jwk)
    {
        switch (alg)
        {
            case "EdDSA": return Member(jwk, "kty") is "OKP" && Member(jwk, "crv") is "Ed25519" or "Ed448";
            case "ES256": return Member(jwk, "kty") is "EC" && Member(jwk, "crv") is "P-256";
            case "ES384": return Member(jwk, "kty") is "EC" && Member(jwk, "crv") is "P-384";
            case "ES512": return Member(jwk, "kty") is "EC" && Member(jwk, "crv") is "P-521";
            case "PS256":
            case "RS256": return Member(jwk, "kty") is "RSA";
            default: return false;
        }
    }

    static D ToPublicJwk(D jwk)
    {
        var pub = new D();
        if (jwk.TryGetValue("kty", out var kty)) pub["kty"] = kty;
        foreach (var k in new[] { "crv", "x", "y", "n", "e" }) if (jwk.TryGetValue(k, out var v)) pub[k] = v;
        return pub;
    }

    /// <summary><c>protocol + "//" + host + pathname</c> of the URL (query, fragment and credentials dropped), e.g. <c>https://host:8443/path</c>.
    /// Throws <see cref="InvalidUrlException"/> (ERR_INVALID_URL) for a URL that does not parse.</summary>
    public static string NormalizeHtu(string? url)
    {
        var u = WhatwgUrl.Require(url);
        return u.Protocol + "//" + u.Host + u.Pathname;
    }

    /// <summary>The access-token hash <c>ath</c>: base64url(SHA-256(access token)), RFC 9449 s4.2.</summary>
    public static string AthFor(string accessToken) => Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));

    /// <summary><c>String.prototype.toUpperCase</c> for a method name (sharp s expands to SS; other special casings are not modelled).</summary>
    static string JsUpper(string s) => s.ToUpperInvariant().Replace("ß", "SS");

    // ===================== DPoP proof: create / verify =====================

    /// <summary>Builds and signs a DPoP proof JWT (<c>typ: dpop+jwt</c>, the embedded public JWK, claims htm / htu / iat / jti [/ nonce / ath]).</summary>
    public static string CreateDpopProof(CreateDpopProofInput input)
    {
        var publicJwk = ToPublicJwk(input.PublicJwk ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'kty')"));
        var alg = DpopAlgForJwk(publicJwk);
        double iat = input.Iat ?? Math.Floor((input.NowMs?.Invoke() ?? AtlasPca.ReplayClock.NowMs()) / 1000.0);
        var claims = new D
        {
            ["htm"] = JsUpper(input.Method ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'toUpperCase')")),
            ["htu"] = NormalizeHtu(input.Url),
            ["iat"] = iat,
            ["jti"] = input.Jti ?? Guid.NewGuid().ToString(),
        };
        if (input.Nonce != null) claims["nonce"] = input.Nonce;
        if (input.Ath != null) claims["ath"] = input.Ath;
        return J.SignJwt(new D { ["typ"] = DpopJwtTyp, ["alg"] = alg, ["jwk"] = publicJwk }, claims, input.PrivateKey ?? throw new JoseTypeError("Key must be one of type CryptoKey, KeyObject, or JSON Web Key"));
    }

    /// <summary>Verifies a DPoP proof: signature under the embedded jwk, typ, that htm / htu match the request, iat freshness, optional jkt, nonce and
    /// access-token binding, and jti replay rejection. Throws <see cref="DpopVerificationException"/> on any failure.</summary>
    public static DpopVerifyResult VerifyDpopProof(object? proof, VerifyDpopProofOptions opts)
    {
        // A NaN or infinite max age would disable the stale check (now - iat > NaN is never true): refuse it.
        if (!double.IsFinite(opts.MaxAgeSec) || opts.MaxAgeSec < 0) throw Err("max_age", "maxAgeSec must be a finite, non-negative number of seconds");
        if (opts.RequireReplayStore != false && opts.ReplayStore == null && opts.SeenJti == null)
            throw Err("replay_store_required", "no replay store configured; replay cannot be detected");
        if (proof is not string token || token.Length > DpopMaxProofBytes)
            throw Err("oversize", $"proof is not a string or exceeds {DpopMaxProofBytes} bytes");

        // reject a missing / non-public / absent-jwk header before trusting the signature
        D header;
        try { header = J.AssertCanonicalCompactJws(token).Header; } // canonical-spelling gate BEFORE the JOSE layer (jti / replay keys)
        catch (Exception e) { throw Err("malformed", $"not a JWS: {e.Message}"); }
        if (header.GetValueOrDefault("typ") is not DpopJwtTyp) throw Err("typ", $"header typ must be '{DpopJwtTyp}', got '{JsStr(header.GetValueOrDefault("typ"))}'");
        if (!header.ContainsKey("jwk")) throw Err("no_jwk", "proof header has no embedded jwk");
        // RFC 9449 s4.2: the header jwk MUST NOT contain a private key
        var hj = header["jwk"];
        if (hj is D hjd && new[] { "d", "p", "q", "dp", "dq", "qi", "k" }.Any(hjd.ContainsKey)) throw Err("private_jwk", "proof header jwk contains private key material");

        // the declared alg must belong to the embedded key's type (an EdDSA header over an RSA jwk is refused by name)
        if (header.GetValueOrDefault("alg") is string alg && DpopAllowedAlgs.Contains(alg) && !DpopAlgMatchesJwk(alg, hj))
            throw Err("alg_jwk_mismatch", $"alg '{alg}' does not match the embedded jwk key type");

        // signature: the embedded-JWK resolver verifies under the header jwk; the allow-list pins the asymmetric suite
        D payload, jwk;
        try
        {
            var res = J.JwtVerify(token, J.EmbeddedJwk, new JwtVerifyOptions { Algorithms = DpopAllowedAlgs, Typ = DpopJwtTyp });
            payload = res.Payload;
            jwk = res.ProtectedHeader.GetValueOrDefault("jwk") as D ?? throw Err("no_jwk", "verified header has no embedded jwk");
        }
        catch (DpopVerificationException) { throw; }
        catch (Exception e) { throw Err("signature", $"DPoP signature did not verify: {e.Message}"); }

        // claim shapes
        if (payload.GetValueOrDefault("htm") is not string htm) throw Err("htm", "htm is missing or not a string");
        if (payload.GetValueOrDefault("htu") is not string htu) throw Err("htu", "htu is missing or not a string");
        var iatN = payload.GetValueOrDefault("iat") is Num ? J.NumberOf(payload["iat"]) : null;
        if (iatN is not double iat || !double.IsFinite(iat)) throw Err("iat", "iat is missing or not a number");
        if (payload.GetValueOrDefault("jti") is not string jti || jti.Length == 0) throw Err("jti", "jti is missing or empty");

        // htm / htu bind the proof to this exact request
        if (htm != JsUpper(opts.Method ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'toUpperCase')"))) throw Err("htm", $"htm '{htm}' does not match request method");
        if (htu != NormalizeHtu(opts.Url)) throw Err("htu", $"htu '{htu}' does not match request URL");

        // freshness
        double now = opts.NowSec ?? Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);
        if (!double.IsFinite(now)) throw Err("now", "nowSec must be a finite number");
        if (!(iat <= now + DpopClockSkewSec)) throw Err("iat_future", "iat is in the future");
        if (!(now - iat <= opts.MaxAgeSec)) throw Err("iat_stale", $"proof is older than {IntentJs.NormNum(opts.MaxAgeSec.ToString("R", System.Globalization.CultureInfo.InvariantCulture)).Raw}s");

        // key binding
        var jkt = J.JwkThumbprint(jwk);
        if (opts.ExpectedJkt != null && jkt != opts.ExpectedJkt) throw Err("jkt", "embedded key thumbprint does not match expected jkt");

        // server nonce (RFC 9449 s8 / s9): when required, an absent or different nonce is rejected
        if (opts.ExpectedNonce != null && !(payload.GetValueOrDefault("nonce") is string pn && pn == opts.ExpectedNonce))
            throw Err("nonce", "proof nonce is missing or does not match the expected nonce");
        if (opts.NonceIssuer != null && !opts.NonceIssuer.Check(payload.GetValueOrDefault("nonce"), now))
            throw Err("nonce", "proof nonce is missing, forged or expired");

        // access-token binding (RFC 9449 s4.2 / s7.1): when presented with an access token, ath must match
        if (opts.AccessToken != null && !(payload.GetValueOrDefault("ath") is string pa && pa == AthFor(opts.AccessToken)))
            throw Err("ath", "proof ath is missing or does not match the access token");

        // replay: reject a reused jti, then record this one
        if (opts.SeenJti != null)
        {
            if (opts.SeenJti.Has(jti)) throw Err("jti_replay", $"jti '{jti}' has already been seen");
            opts.SeenJti.Add(jti);
        }
        if (opts.ReplayStore != null)
        {
            bool fresh;
            try { fresh = opts.ReplayStore.AddIfAbsent($"{jkt}.{jti}", iat + opts.MaxAgeSec + DpopClockSkewSec, now); }
            catch (Exception e) { throw Err("replay_store_error", $"replay store failed: {e.Message}"); }
            if (!fresh) throw Err("jti_replay", $"jti '{jti}' has already been seen");
        }

        var claims = new D(payload) { ["htm"] = htm, ["htu"] = htu, ["iat"] = payload["iat"], ["jti"] = jti };
        if (payload.GetValueOrDefault("nonce") is string nonce) claims["nonce"] = nonce;
        if (payload.GetValueOrDefault("ath") is string ath) claims["ath"] = ath;
        return new DpopVerifyResult(claims, jwk, jkt);
    }

    // ===================== RFC 8705 mTLS confirmation =====================

    static readonly Regex PemBody = new("-----BEGIN CERTIFICATE-----([\\s\\S]+?)-----END CERTIFICATE-----", RegexOptions.CultureInvariant);

    /// <summary>Node-style lenient base64: stops at the first '=', ignores a dangling sextet.</summary>
    static byte[] NodeBase64(string body)
    {
        int eq = body.IndexOf('=');
        var s = eq >= 0 ? body[..eq] : body;
        if (s.Length % 4 == 1) s = s[..^1];
        while (s.Length % 4 != 0) s += "=";
        return Convert.FromBase64String(s);
    }

    static byte[] PemToDer(string pem)
    {
        var m = PemBody.Match(pem);
        var body = Regex.Replace(m.Success ? m.Groups[1].Value : pem, "[^A-Za-z0-9+/=]", "");
        return NodeBase64(body);
    }

    /// <summary>RFC 8705 s3.1 <c>cnf</c>: <c>{"x5t#S256": b64u(sha256(DER))}</c> for DER bytes.</summary>
    public static D MtlsCnf(byte[] certDer) => new() { ["x5t#S256"] = Pca.B64u(SHA256.HashData(certDer)) };

    /// <summary>The same for a certificate given as PEM text (the DER body is hashed; nothing is parsed).</summary>
    public static D MtlsCnf(string certPem) => MtlsCnf(PemToDer(certPem));

    /// <summary>The thumbprint of a certificate that PARSES as X.509 (DER bytes). Throws <c>cert</c> otherwise.</summary>
    public static string MtlsThumbprint(byte[] certDer)
    {
        try
        {
            using var c = new X509Certificate2(certDer);
            return Pca.B64u(SHA256.HashData(c.RawData));
        }
        catch (Exception e) { throw Err("cert", $"not an X.509 certificate: {e.Message}"); }
    }

    /// <summary>The thumbprint of a certificate given as PEM text; a string that is not a PEM certificate is refused as <c>cert</c>.</summary>
    public static string MtlsThumbprint(string certPem)
    {
        try
        {
            if (!PemBody.IsMatch(certPem)) throw new ArgumentException("no PEM certificate");
            return MtlsThumbprint(PemToDer(certPem));
        }
        catch (DpopVerificationException) { throw; }
        catch (Exception e) { throw Err("cert", $"not an X.509 certificate: {e.Message}"); }
    }

    static string Want(object? cnf)
    {
        var want = (cnf as D)?.GetValueOrDefault("x5t#S256");
        if (want is not string w || w.Length == 0) throw Err("x5t_missing", "cnf has no 'x5t#S256' thumbprint");
        return w;
    }

    static D BoundCnf(string got, string want)
    {
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(got), Encoding.UTF8.GetBytes(want))) throw Err("x5t", "client certificate thumbprint does not match cnf x5t#S256");
        return new D { ["x5t#S256"] = got };
    }

    /// <summary>RFC 8705 s3.1: the presented client certificate (DER) must hash to the x5t#S256 of the token's cnf. Throws x5t_missing (no usable
    /// thumbprint in cnf), cert (unparseable certificate) or x5t (mismatch).</summary>
    public static D AssertMtlsBound(byte[] certDer, object? cnf) { var want = Want(cnf); return BoundCnf(MtlsThumbprint(certDer), want); }

    /// <summary><see cref="AssertMtlsBound(byte[], object)"/> for a PEM certificate.</summary>
    public static D AssertMtlsBound(string certPem, object? cnf) { var want = Want(cnf); return BoundCnf(MtlsThumbprint(certPem), want); }

    // ===================== PCActn <-> DPoP binding =====================

    /// <summary>The OKP / Ed25519 public JWK of the PCActn's bound holder key: the LEAF of its capability chain (<c>cap_chain[last].holder</c>).
    /// Throws <c>no_leaf</c> when the chain is empty.</summary>
    public static D LeafHolderJwk(object? p)
    {
        if (p == null) throw new InvalidOperationException("Cannot read properties of null (reading 'cap_chain')");
        var rawChain = (p as D)?.GetValueOrDefault("cap_chain");
        object? leaf;
        switch (rawChain)
        {
            case L chain:
                if (chain.Count == 0) throw Err("no_leaf", "PCActn capability chain is empty; no bound holder key");
                leaf = chain[^1];
                break;
            case string str: // chain[length - 1] is one character: it has no holder, so the key is absent
                if (str.Length == 0) throw Err("no_leaf", "PCActn capability chain is empty; no bound holder key");
                leaf = str[^1].ToString();
                break;
            case D obj: // an object is read by its numeric "length" member: chain[length - 1]
                var len = obj.GetValueOrDefault("length");
                var key = len != null && IntentJs.NumOf(len) is double ln && ln >= 1 && ln == Math.Floor(ln) ? ((long)ln - 1).ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
                if (key == null || !obj.TryGetValue(key, out leaf)) throw Err("no_leaf", "PCActn capability chain is empty; no bound holder key");
                break;
            default: throw new InvalidOperationException("Cannot read properties of undefined (reading 'length')");
        }
        if (leaf == null) throw new InvalidOperationException("Cannot read properties of null (reading 'holder')");
        var jwk = new D { ["kty"] = "OKP", ["crv"] = "Ed25519" };
        if (leaf is D ld && ld.ContainsKey("holder")) jwk["x"] = ld["holder"]; // an absent holder stays absent
        return jwk;
    }

    /// <summary>The <c>cnf: {jkt}</c> confirmation for a PCActn's bound holder key (RFC 9449 s6).</summary>
    public static D BindPcaToDpop(object? p) => new() { ["jkt"] = J.JwkThumbprint(LeafHolderJwk(p)) };

    /// <summary>Confirms a presented DPoP proof is held by the PCActn's bound holder key AND is for the given HTTP target: verifies the proof with
    /// ExpectedJkt fixed to the PCActn's leaf-holder thumbprint.</summary>
    public static DpopVerifyResult AssertPcaDpop(object? p, object? dpopProof, AssertPcaDpopOptions o)
    {
        var jkt = (string)BindPcaToDpop(p)["jkt"]!;
        return VerifyDpopProof(dpopProof, new VerifyDpopProofOptions
        {
            Method = o.Method, Url = o.Url, MaxAgeSec = o.MaxAgeSec ?? DpopDefaultMaxAgeSec, ExpectedJkt = jkt, SeenJti = o.SeenJti,
            ReplayStore = o.ReplayStore, RequireReplayStore = o.RequireReplayStore, NonceIssuer = o.NonceIssuer, NowSec = o.NowSec,
            ExpectedNonce = o.ExpectedNonce, AccessToken = o.AccessToken,
        });
    }
}
