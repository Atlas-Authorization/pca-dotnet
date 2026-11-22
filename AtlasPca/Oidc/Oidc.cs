// OpenID Connect for PCA: discovery (OIDC Discovery 1.0 s4), ID-token verification (OIDC Core 1.0 s3.1.3.7) over the shared JOSE kit,
// a fail-closed caching JWKS resolver, and the mapping of a verified token to a PCA principal descriptor.
// Maps onto the reference's discoverOidc / verifyIdToken / createOidcJwks / oidcPrincipal one to one (PascalCase).
//
// Values are the JSON tree (Dictionary / List / string / bool / Num / null). Network is injectable: an OidcFetch delegate (default:
// HttpClient) and a clock. Methods are synchronous.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using J = AtlasPca.Jose.Jose;
using JoseException = AtlasPca.Jose.JoseException;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Oidc;

/// <summary>The error of any discovery failure (network, non-2xx, bad JSON, issuer mismatch).</summary>
public sealed class OidcDiscoveryException : Exception
{
    public OidcDiscoveryException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>The error of any ID-token verification failure; <see cref="Code"/> is one of config, invalid_token, signature, issuer, audience, expired,
/// issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims.</summary>
public sealed class OidcVerificationException : Exception
{
    public string Code { get; }
    public OidcVerificationException(string code, string message, Exception? inner = null) : base(message, inner) { Code = code; }
}

/// <summary>A fetch reply: the status, the body text and the Content-Length header (null when absent).</summary>
public sealed record OidcHttpResponse(int Status, string Text, string? ContentLength = null)
{
    public bool Ok => Status >= 200 && Status <= 299;
}

/// <summary>An HTTP GET (Accept: application/json). The token cancels the request (the JWKS timeout).</summary>
public delegate OidcHttpResponse OidcFetch(string url, CancellationToken cancel);

public sealed class DiscoverOidcOptions
{
    /// <summary>Injectable fetch (default: a shared HttpClient).</summary>
    public OidcFetch? Fetch { get; init; }
    public CancellationToken Cancel { get; init; }
    /// <summary>Reject a document larger than this many bytes (default <see cref="Oidc.DefaultMaxDiscoveryBytes"/>).</summary>
    public double? MaxBytes { get; init; }
    /// <summary>Require https for the issuer and the advertised jwks_uri (default true).</summary>
    public bool? RequireHttps { get; init; }
}

public sealed class OidcJwksOptions
{
    public string? JwksUri { get; init; }
    public OidcFetch? Fetch { get; init; }
    public double? CacheMaxAgeSec { get; init; }
    public double? CooldownSec { get; init; }
    public double? MaxBytes { get; init; }
    public bool? RequireHttps { get; init; }
    public double? TimeoutMs { get; init; }
    /// <summary>Clock in epoch ms (default: the system clock).</summary>
    public Func<double>? Now { get; init; }
}

public sealed record VerifyIdTokenOptions
{
    /// <summary>Expected iss. Required.</summary>
    public string? Issuer { get; init; }
    /// <summary>Expected aud: a string or a list of strings. Required.</summary>
    public object? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? AuthorizedParty { get; init; }
    public string? AccessToken { get; init; }
    public string? Code { get; init; }
    public double? ClockToleranceSec { get; init; }
    public double? MaxTokenAgeSec { get; init; }
    public IReadOnlyList<string>? Algorithms { get; init; }
    public string? JwksUri { get; init; }
    public bool Discover { get; init; }
    public OidcFetch? Fetch { get; init; }
    public bool? RequireHttps { get; init; }
    bool _keySet; object? _key;
    /// <summary>Key material: a public JWK (Dictionary), an HS secret (byte[]), a JoseKey, or a resolver Func&lt;Dictionary, object?&gt; (e.g. <see cref="Oidc.CreateOidcJwks"/>).
    /// Setting it, even to null, takes precedence over jwksUri / discover (null then fails as a bad key).</summary>
    public object? Key { get => _key; init { _key = value; _keySet = true; } }
    internal bool KeySet => _keySet;
}

public sealed class OidcPrincipalOptions
{
    /// <summary>The principal's Ed25519 public key (canonical base64url); a non-string is refused like the reference.</summary>
    public object? PrincipalPublic { get; init; }
}

public static class Oidc
{
    public const int DefaultMaxDiscoveryBytes = 1024 * 1024;
    public const int DefaultJwksTimeoutMs = 5000;
    public const string OidcSubjectCaveat = "oidc_subject";

    /// <summary>The asymmetric OIDC signing algorithms allowed by default (symmetric algs are excluded).</summary>
    public static readonly IReadOnlyList<string> DefaultIdTokenAlgs = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA" };

    static readonly HttpClient Http = new();

    static OidcHttpResponse DefaultFetch(string url, CancellationToken cancel)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.TryAddWithoutValidation("accept", "application/json");
        using var res = Http.Send(req, cancel);
        var text = new StreamReader(res.Content.ReadAsStream(cancel), new UTF8Encoding(false)).ReadToEnd();
        string? cl = res.Content.Headers.ContentLength?.ToString(CultureInfo.InvariantCulture);
        return new OidcHttpResponse((int)res.StatusCode, text, cl);
    }

    // ===================== discovery =====================

    /// <summary>The discovery URL: <c>/.well-known/openid-configuration</c> appended to the issuer, one trailing slash normalised away.</summary>
    public static string DiscoveryUrl(string issuer) => (issuer.EndsWith('/') ? issuer[..^1] : issuer) + "/.well-known/openid-configuration";

    /// <summary>JavaScript's <c>Number(string)</c> (whitespace trimmed, empty = 0, hex / octal / binary prefixes, decimal with exponent, Infinity), NaN when it is not a number.</summary>
    static double JsNumber(string s)
    {
        var t = s.Trim(' ', '\t', '\n', '\r', '\v', '\f', ' ', '﻿', '\u2028', '\u2029');
        if (t.Length == 0) return 0;
        if (t.Length > 2 && t[0] == '0' && (t[1] is 'x' or 'X' or 'o' or 'O' or 'b' or 'B'))
        {
            int radix = t[1] is 'x' or 'X' ? 16 : t[1] is 'o' or 'O' ? 8 : 2;
            double v = 0;
            foreach (var c in t[2..])
            {
                int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
                if (d >= radix) return double.NaN;
                v = v * radix + d;
            }
            return v;
        }
        if (t is "Infinity" or "+Infinity") return double.PositiveInfinity;
        if (t == "-Infinity") return double.NegativeInfinity;
        foreach (var c in t)
            if (!(c >= '0' && c <= '9' || c is '+' or '-' or '.' or 'e' or 'E')) return double.NaN; // refuses "NaN", culture symbols
        return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : double.NaN;
    }

    /// <summary>Fetches and parses <c>${issuer}/.well-known/openid-configuration</c> (the provider metadata as a JSON object). Throws <see cref="OidcDiscoveryException"/>.</summary>
    public static D DiscoverOidc(string? issuer, DiscoverOidcOptions? opts = null)
    {
        opts ??= new DiscoverOidcOptions();
        if (string.IsNullOrEmpty(issuer)) throw new OidcDiscoveryException("discoverOidc: issuer must be a non-empty string");
        bool requireHttps = opts.RequireHttps != false;
        if (requireHttps && !WhatwgUrl_IsHttps(issuer)) throw new OidcDiscoveryException($"discoverOidc: issuer '{issuer}' is not an https URL");
        var doFetch = opts.Fetch ?? new OidcFetch(DefaultFetch);
        var url = DiscoveryUrl(issuer);
        OidcHttpResponse res;
        try { res = doFetch(url, opts.Cancel); }
        catch (Exception cause) { throw new OidcDiscoveryException($"discoverOidc: fetch of {url} failed", cause); }
        if (!res.Ok) throw new OidcDiscoveryException($"discoverOidc: {url} returned HTTP {res.Status}");
        double maxBytes = opts.MaxBytes ?? DefaultMaxDiscoveryBytes;
        double declared = JsNumber(res.ContentLength ?? "0"); // Number(null) is 0, a missing header never trips the cap
        if (res.ContentLength == null) declared = 0;
        if (double.IsFinite(declared) && declared > maxBytes) throw new OidcDiscoveryException($"discoverOidc: {url} response exceeds {Fmt(maxBytes)} bytes");
        object? body;
        try
        {
            if (Encoding.UTF8.GetByteCount(res.Text) > maxBytes) throw new OidcDiscoveryException($"discoverOidc: {url} response exceeds {Fmt(maxBytes)} bytes");
            body = Pca.ParseJson(res.Text);
        }
        catch (OidcDiscoveryException) { throw; }
        catch (Exception cause) { throw new OidcDiscoveryException($"discoverOidc: {url} did not return valid JSON", cause); }
        var meta = AsMetadata(body);
        var metaIssuer = (string)meta["issuer"]!;
        if (metaIssuer != issuer) throw new OidcDiscoveryException($"discoverOidc: metadata issuer '{metaIssuer}' does not match requested '{issuer}'");
        var jwksUri = (string)meta["jwks_uri"]!;
        if (requireHttps && !WhatwgUrl_IsHttps(jwksUri)) throw new OidcDiscoveryException($"discoverOidc: jwks_uri '{jwksUri}' is not an https URL");
        return meta;
    }

    static string Fmt(double d) => d.ToString("R", CultureInfo.InvariantCulture);
    static bool WhatwgUrl_IsHttps(string u) => AtlasPca.Jose.WhatwgUrl.IsHttps(u);

    static D AsMetadata(object? body)
    {
        if (body is not D rec) throw new OidcDiscoveryException("discoverOidc: metadata is not a JSON object");
        if (rec.GetValueOrDefault("issuer") is not string issuer || issuer.Length == 0) throw new OidcDiscoveryException("discoverOidc: metadata is missing a string \"issuer\"");
        if (rec.GetValueOrDefault("jwks_uri") is not string jwksUri || jwksUri.Length == 0) throw new OidcDiscoveryException("discoverOidc: metadata is missing a string \"jwks_uri\"");
        var meta = new D { ["issuer"] = issuer, ["jwks_uri"] = jwksUri };
        foreach (var (k, v) in rec) if (k != "issuer" && k != "jwks_uri") meta[k] = v;
        return meta;
    }

    // ===================== JWKS resolver =====================

    static OidcVerificationException KeysError(string message, Exception? cause = null) => new("keys", message, cause);

    sealed class JwksCache
    {
        public double At;
        public Func<D, object?> Resolve = null!;
        public HashSet<string> Kids = new();
    }

    /// <summary>A key resolver (pass as <see cref="VerifyIdTokenOptions.Key"/>) that caches the issuer's key set for <c>CacheMaxAgeSec</c> and FAILS CLOSED on a
    /// stale or unreachable set; an unknown <c>kid</c> triggers at most one refetch per <c>CooldownSec</c>. Throws <see cref="ArgumentException"/> on a bad option.</summary>
    public static Func<D, object?> CreateOidcJwks(OidcJwksOptions opts)
    {
        var jwksUri = opts.JwksUri;
        if (string.IsNullOrEmpty(jwksUri)) throw new ArgumentException("createOidcJwks: jwksUri is required");
        if ((opts.RequireHttps ?? true) && !jwksUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)");
        var now = opts.Now ?? (() => (double)AtlasPca.ReplayClock.NowMs());
        double maxAgeMs = (opts.CacheMaxAgeSec ?? 600) * 1000;
        double cooldownMs = (opts.CooldownSec ?? 30) * 1000;
        double maxBytes = opts.MaxBytes ?? 1024 * 1024;
        double timeoutMs = opts.TimeoutMs ?? DefaultJwksTimeoutMs;
        // a NaN or infinite age / cooldown would make every staleness comparison false and serve one key set forever
        foreach (var (name, v) in new (string, double?)[] { ("cacheMaxAgeSec", opts.CacheMaxAgeSec), ("cooldownSec", opts.CooldownSec), ("maxBytes", opts.MaxBytes), ("timeoutMs", opts.TimeoutMs) })
            if (v != null && !(double.IsFinite(v.Value) && v.Value >= 0)) throw new ArgumentException($"createOidcJwks: {name} must be a finite number >= 0");
        JwksCache? cache = null;
        double lastFetch = double.NegativeInfinity;
        var gate = new object();

        void Refetch()
        {
            var doFetch = opts.Fetch ?? new OidcFetch(DefaultFetch);
            lastFetch = now();
            Func<D, object?> resolve;
            L keys;
            try
            {
                if (timeoutMs != Math.Floor(timeoutMs) || timeoutMs > uint.MaxValue) throw new InvalidOperationException("The \"delay\" argument is out of range"); // AbortSignal.timeout takes a uint32
                using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Min(timeoutMs, int.MaxValue)));
                var res = doFetch(jwksUri, cts.Token);
                if (!res.Ok) throw new InvalidOperationException($"HTTP {res.Status}");
                if (Encoding.UTF8.GetByteCount(res.Text) > maxBytes) throw new InvalidOperationException($"response exceeds {Fmt(maxBytes)} bytes");
                var jwks = Pca.ParseJson(res.Text);
                if (jwks is not D jd || jd.GetValueOrDefault("keys") is not L kl) throw new InvalidOperationException("not a JWK Set");
                keys = kl;
                resolve = J.CreateLocalJwkSet(jwks); // throws on a key that is not a JSON object
            }
            catch (Exception cause) { throw KeysError($"could not fetch the issuer signing keys from {jwksUri}", cause); }
            cache = new JwksCache
            {
                At = now(),
                Resolve = resolve,
                Kids = keys.Select(k => (k as D)?.GetValueOrDefault("kid")).OfType<string>().ToHashSet(),
            };
        }

        return header =>
        {
            lock (gate)
            {
                double t = now();
                if (!double.IsFinite(t)) throw KeysError("the clock returned a non-finite time");
                if (cache == null || t - cache.At >= maxAgeMs)
                {
                    cache = null; // never serve a stale set, even if the refetch below fails
                    Refetch();
                }
                else if (header.GetValueOrDefault("kid") is string kid && !cache.Kids.Contains(kid) && t - lastFetch >= cooldownMs) Refetch();
                return cache!.Resolve(header);
            }
        };
    }

    /// <summary>Discovers the issuer's <c>jwks_uri</c> (https required unless <c>RequireHttps</c> is false) and builds the resolver.</summary>
    public static Func<D, object?> CreateOidcJwksFromIssuer(string issuer, OidcJwksOptions? opts = null)
    {
        opts ??= new OidcJwksOptions();
        var meta = DiscoverOidc(issuer, new DiscoverOidcOptions { RequireHttps = opts.RequireHttps, Fetch = opts.Fetch });
        return CreateOidcJwks(new OidcJwksOptions
        {
            JwksUri = (string)meta["jwks_uri"]!, Fetch = opts.Fetch, CacheMaxAgeSec = opts.CacheMaxAgeSec, CooldownSec = opts.CooldownSec,
            MaxBytes = opts.MaxBytes, RequireHttps = opts.RequireHttps, TimeoutMs = opts.TimeoutMs, Now = opts.Now,
        });
    }

    // ===================== ID-token verification =====================

    /// <summary>Verifies an ID token and returns its verified claims (iss, sub, aud, iat, exp guaranteed; nonce, azp, at_hash, c_hash, auth_time, email,
    /// email_verified, name, preferred_username, given_name, family_name, picture, cnf when present and well formed). Throws <see cref="OidcVerificationException"/>.</summary>
    public static D VerifyIdToken(string? idToken, VerifyIdTokenOptions? opts)
    {
        if (string.IsNullOrEmpty(idToken)) throw new OidcVerificationException("invalid_token", "verifyIdToken: idToken must be a non-empty string");
        if (opts == null) throw new OidcVerificationException("config", "verifyIdToken: opts is required");
        if (string.IsNullOrEmpty(opts.Issuer)) throw new OidcVerificationException("config", "verifyIdToken: opts.issuer is required");
        if (opts.Audience is not (string or System.Collections.IList)) throw new OidcVerificationException("config", "verifyIdToken: opts.audience is required");
        // a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check
        if (opts.ClockToleranceSec is double ct && !(double.IsFinite(ct) && ct >= 0)) throw new OidcVerificationException("config", "verifyIdToken: clockToleranceSec must be a finite number >= 0");
        if (opts.MaxTokenAgeSec is double ma && !(ma >= 0)) throw new OidcVerificationException("config", "verifyIdToken: maxTokenAgeSec must be a number >= 0");

        try { J.AssertCanonicalCompactJws(idToken); } // canonical-spelling gate BEFORE the JOSE layer (one accepted string form)
        catch (AtlasPca.Jose.CanonicalJwsException cause) { throw new OidcVerificationException("invalid_token", cause.Message); }

        var key = ResolveKey(opts);
        var verifyOptions = new AtlasPca.Jose.JwtVerifyOptions
        {
            IssuerString = opts.Issuer,
            AudienceString = opts.Audience as string,
            AudienceList = opts.Audience is System.Collections.IList al ? al.Cast<object?>().Select(x => x as string ?? "\0non-string").ToList() : null,
            Algorithms = (opts.Algorithms ?? DefaultIdTokenAlgs).ToList(),
            ClockTolerance = opts.ClockToleranceSec,
            MaxTokenAge = opts.MaxTokenAgeSec,
        };

        D payload;
        try { payload = J.JwtVerify(idToken, key, verifyOptions).Payload; }
        catch (Exception cause) { throw MapJoseError(cause); }

        var claims = ProjectClaims(payload, opts);
        var alg = ProtectedAlg(idToken);
        if (opts.AccessToken != null) CheckHalfHash("at_hash", claims.GetValueOrDefault("at_hash") as string, opts.AccessToken, alg);
        if (opts.Code != null) CheckHalfHash("c_hash", claims.GetValueOrDefault("c_hash") as string, opts.Code, alg);
        return claims;
    }

    static string? ProtectedAlg(string token)
    {
        var h = J.DecodeB64Lenient(token.Split('.')[0]);
        return Pca.ParseJson(Encoding.UTF8.GetString(h)) is D d ? d.GetValueOrDefault("alg") as string : null;
    }

    /// <summary>OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512). The value is hashed as the
    /// reference's <c>ascii</c> encoder writes it: the low byte of every UTF-16 code unit.</summary>
    static void CheckHalfHash(string name, string? actual, string value, string? alg)
    {
        if (actual == null) throw new OidcVerificationException(name, $"id token is missing the expected {name}");
        string? bits = alg == "EdDSA" ? "512" : alg != null && (alg.EndsWith("256", StringComparison.Ordinal) || alg.EndsWith("384", StringComparison.Ordinal) || alg.EndsWith("512", StringComparison.Ordinal)) ? alg[^3..] : null;
        if (bits == null) throw new OidcVerificationException(name, $"cannot compute {name} for alg {alg ?? "undefined"}");
        var data = new byte[value.Length];
        for (int i = 0; i < value.Length; i++) data[i] = (byte)(value[i] & 0xff);
        var digest = bits == "256" ? SHA256.HashData(data) : bits == "384" ? SHA384.HashData(data) : SHA512.HashData(data);
        var expected = Pca.B64u(digest[..(digest.Length / 2)]);
        if (actual != expected) throw new OidcVerificationException(name, $"id token {name} does not match the supplied value");
    }

    /// <summary><c>Key</c> wins, then <c>JwksUri</c>, then <c>Discover</c>. A URI is wrapped in the fail-closed resolver, built per call so no key set outlives the call.</summary>
    static object? ResolveKey(VerifyIdTokenOptions opts)
    {
        if (opts.KeySet) return opts.Key;
        var jwksUri = opts.JwksUri;
        if (jwksUri == null && opts.Discover) jwksUri = (string)DiscoverOidc(opts.Issuer, new DiscoverOidcOptions { RequireHttps = opts.RequireHttps, Fetch = opts.Fetch })["jwks_uri"]!;
        if (jwksUri == null) throw new OidcVerificationException("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)");
        try { return CreateOidcJwks(new OidcJwksOptions { JwksUri = jwksUri, RequireHttps = opts.RequireHttps }); }
        catch (ArgumentException cause) { throw new OidcVerificationException("config", $"verifyIdToken: {cause.Message}", cause); }
    }

    static string? AsString(object? v) => v is string s && s.Length > 0 ? s : null;
    static double? AsFinite(object? v) => v is Num && IntentJsNum(v) is double d && double.IsFinite(d) ? d : null;
    static double? IntentJsNum(object? v) => J.NumberOf(v);

    static D ProjectClaims(D payload, VerifyIdTokenOptions opts)
    {
        // the JOSE layer enforced iss / aud (and exp / nbf / age when present); re-read defensively and enforce the OIDC-required members it does not mandate
        var iss = AsString(payload.GetValueOrDefault("iss")) ?? throw new OidcVerificationException("issuer", "id token is missing the \"iss\" claim");
        var sub = AsString(payload.GetValueOrDefault("sub")) ?? throw new OidcVerificationException("claims", "id token is missing the \"sub\" claim");
        if (!payload.TryGetValue("aud", out var aud)) throw new OidcVerificationException("audience", "id token is missing the \"aud\" claim");
        if (!payload.TryGetValue("iat", out var iatRaw) || AsFinite(iatRaw) == null) throw new OidcVerificationException("issued_at", "id token is missing a numeric \"iat\" claim");
        if (!payload.TryGetValue("exp", out var expRaw) || AsFinite(expRaw) == null) throw new OidcVerificationException("expired", "id token is missing a numeric \"exp\" claim");

        var nonce = AsString(payload.GetValueOrDefault("nonce"));
        var azp = AsString(payload.GetValueOrDefault("azp"));
        var atHash = AsString(payload.GetValueOrDefault("at_hash"));
        var cHash = AsString(payload.GetValueOrDefault("c_hash"));

        // nonce binding (OIDC Core 3.1.3.7): when the RP supplied a nonce it MUST round-trip exactly
        if (opts.Nonce != null && nonce != opts.Nonce)
            throw new OidcVerificationException("nonce", nonce == null ? "id token is missing the expected nonce" : "id token nonce does not match the expected value");

        // azp: required when there is more than one audience; when present it MUST identify the relying party
        int audCount = aud is L al ? al.Count : 1;
        var expectedAzp = opts.AuthorizedParty ?? (opts.Audience as string);
        if (audCount > 1 && azp == null) throw new OidcVerificationException("azp", "id token has multiple audiences but no azp (authorized party)");
        if (azp != null && expectedAzp != null && azp != expectedAzp) throw new OidcVerificationException("azp", "id token azp does not match the authorized party");

        var cnf = payload.GetValueOrDefault("cnf") is D c ? new D(c) : null;
        var emailVerified = payload.GetValueOrDefault("email_verified") as bool?;
        var authTime = AsFinite(payload.GetValueOrDefault("auth_time")) != null ? payload["auth_time"] : null;
        var email = AsString(payload.GetValueOrDefault("email"));
        var name = AsString(payload.GetValueOrDefault("name"));
        var preferred = AsString(payload.GetValueOrDefault("preferred_username"));
        var given = AsString(payload.GetValueOrDefault("given_name"));
        var family = AsString(payload.GetValueOrDefault("family_name"));
        var picture = AsString(payload.GetValueOrDefault("picture"));

        var o = new D { ["iss"] = iss, ["sub"] = sub, ["aud"] = aud, ["iat"] = iatRaw, ["exp"] = expRaw };
        if (nonce != null) o["nonce"] = nonce;
        if (azp != null) o["azp"] = azp;
        if (atHash != null) o["at_hash"] = atHash;
        if (cHash != null) o["c_hash"] = cHash;
        if (authTime != null) o["auth_time"] = authTime;
        if (email != null) o["email"] = email;
        if (emailVerified != null) o["email_verified"] = emailVerified.Value;
        if (name != null) o["name"] = name;
        if (preferred != null) o["preferred_username"] = preferred;
        if (given != null) o["given_name"] = given;
        if (family != null) o["family_name"] = family;
        if (picture != null) o["picture"] = picture;
        if (cnf != null) o["cnf"] = cnf;
        return o;
    }

    static OidcVerificationException MapJoseError(Exception e)
    {
        switch (e)
        {
            case OidcVerificationException ve: return ve;
            case JoseException je:
                switch (je.Code)
                {
                    case "ERR_JWT_EXPIRED":
                        // the JOSE layer reuses its expiry error for a maxTokenAge violation, flagging it with claim "iat"
                        return je.Claim == "iat"
                            ? new OidcVerificationException("issued_at", "id token is older than the maximum accepted age", je)
                            : new OidcVerificationException("expired", "id token has expired", je);
                    case "ERR_JWT_CLAIM_VALIDATION_FAILED":
                        {
                            var code = je.Claim switch { "iss" => "issuer", "aud" => "audience", "iat" => "issued_at", "nbf" => "not_before", _ => "claims" };
                            return new OidcVerificationException(code, je.Message, je);
                        }
                    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
                        return new OidcVerificationException("signature", "id token signature verification failed", je);
                    default:
                        return new OidcVerificationException("invalid_token", je.Message, je);
                }
            default:
                return new OidcVerificationException("invalid_token", "id token verification failed", e);
        }
    }

    // ===================== principal mapping =====================

    /// <summary>Maps verified claims to a PCA principal descriptor: iss, sub, principalId (<c>iss#sub</c>), subjectCaveat, claims, and (when present)
    /// principalPublic (the cnf-bound Ed25519 key, or the supplied one), email, emailVerified, name, preferredUsername, authTime.
    /// Throws <see cref="ArgumentException"/> (the reference's TypeError) or <see cref="InvalidOperationException"/> (its Error).</summary>
    public static D OidcPrincipal(D claims, OidcPrincipalOptions? opts = null)
    {
        if (claims.GetValueOrDefault("iss") is not string iss || iss.Length == 0) throw new ArgumentException("oidcPrincipal: claims.iss is required");
        if (claims.GetValueOrDefault("sub") is not string sub || sub.Length == 0) throw new ArgumentException("oidcPrincipal: claims.sub is required");

        // a present-but-null cnf throws in the reference (it reads a member of null)
        if (claims.TryGetValue("cnf", out var cnfv) && cnfv == null) throw new ArgumentException("oidcPrincipal: cannot read properties of null (reading 'jwk')");
        var fromToken = Ed25519PublicFromCnf(claims.GetValueOrDefault("cnf"));
        var principalPublic = fromToken;
        if (opts?.PrincipalPublic != null)
        {
            var provided = CanonicalEd25519B64u(opts.PrincipalPublic) ?? throw new ArgumentException("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key");
            if (fromToken != null && fromToken != provided) throw new InvalidOperationException("oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token");
            principalPublic = provided;
        }
        var o = new D
        {
            ["iss"] = iss, ["sub"] = sub, ["principalId"] = $"{iss}#{sub}",
            ["subjectCaveat"] = new D { ["type"] = OidcSubjectCaveat, ["iss"] = iss, ["sub"] = sub },
            ["claims"] = claims,
        };
        if (principalPublic != null) o["principalPublic"] = principalPublic;
        if (claims.TryGetValue("email", out var v_email)) o["email"] = v_email;
        if (claims.TryGetValue("email_verified", out var v_emailVerified)) o["emailVerified"] = v_emailVerified;
        if (claims.TryGetValue("name", out var v_name)) o["name"] = v_name;
        if (claims.TryGetValue("preferred_username", out var v_preferredUsername)) o["preferredUsername"] = v_preferredUsername;
        if (claims.TryGetValue("auth_time", out var v_authTime)) o["authTime"] = v_authTime;
        return o;
    }

    /// <summary>True when <paramref name="cv"/> is an <c>oidc_subject</c> caveat with a non-empty string iss and sub.</summary>
    public static bool IsOidcSubjectCaveat(object? cv) =>
        cv is D r && r.GetValueOrDefault("type") is OidcSubjectCaveat
        && r.GetValueOrDefault("iss") is string i && i.Length > 0 && r.GetValueOrDefault("sub") is string s && s.Length > 0;

    static string? Ed25519PublicFromCnf(object? cnf)
    {
        if (cnf is not D c) return null;
        if (c.GetValueOrDefault("jwk") is not D jwk) return null;
        if (jwk.GetValueOrDefault("kty") is not "OKP" || jwk.GetValueOrDefault("crv") is not "Ed25519") return null;
        return jwk.GetValueOrDefault("x") is string x ? CanonicalEd25519B64u(x) : null;
    }

    /// <summary>The string itself when it is the canonical unpadded base64url of 32 bytes, else null.</summary>
    static string? CanonicalEd25519B64u(object? s) => s is string t && t.Length > 0 && Pca.B64uDecode(t, 32) != null ? t : null;
}
