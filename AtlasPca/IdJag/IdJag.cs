// ID-JAG (Identity Assertion JWT Authorization Grant, the cross-app access flow): verify a grant over the OIDC verifier, project it to a PCA
// principal and a root capability, and build the RFC 8693 token-exchange / RFC 7523 jwt-bearer request shapes.
// Maps onto the reference's verifyIdJag / idJagToPcaPrincipal / idJagToCapability / readIdJag* / tokenExchangeRequest / jwtBearerAssertion (PascalCase).
// Values are the JSON tree (Dictionary / List / string / bool / Num / null); the consumeJti store is a synchronous delegate.
using System.Text;
using AtlasPca;
using AtlasPca.Oidc;
using J = AtlasPca.Jose.Jose;
using Oi = AtlasPca.Oidc.Oidc;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IdJag;

/// <summary>The error of any ID-JAG verification failure; <see cref="Code"/> is an OIDC verification code (config, invalid_token, signature, issuer, audience,
/// expired, issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims) or actor, scope, grant.</summary>
public sealed class IdJagVerificationException : Exception
{
    public string Code { get; }
    public IdJagVerificationException(string code, string message, Exception? inner = null) : base(message, inner) { Code = code; }
}

/// <summary>Atomically records a jti as spent; it must return exactly <c>true</c> for a fresh one (any other value, or a throw, refuses the grant).</summary>
public delegate object? ConsumeJti(string jti, double expSec);

public sealed record VerifyIdJagOptions
{
    /// <summary>Expected iss. Required.</summary>
    public string? Issuer { get; init; }
    /// <summary>The resource app: the sole audience of the grant. Required.</summary>
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    /// <summary>Scopes the grant must carry (null = no requirement).</summary>
    public IReadOnlyList<string>? RequiredScopes { get; init; }
    public double? ClockToleranceSec { get; init; }
    public double? MaxTokenAgeSec { get; init; }
    public IReadOnlyList<string>? Algorithms { get; init; }
    public string? JwksUri { get; init; }
    public bool? Discover { get; init; }
    public OidcFetch? Fetch { get; init; }
    /// <summary>Draft-strict checks (typ, client_id, single-use jti); on unless exactly false.</summary>
    public bool? StrictDraft { get; init; }
    public string? ClientId { get; init; }
    public ConsumeJti? ConsumeJti { get; init; }
    bool _keySet; object? _key;
    /// <summary>Key material, as <see cref="VerifyIdTokenOptions.Key"/>. Setting it, even to null, takes precedence over JwksUri / Discover.</summary>
    public object? Key { get => _key; init { _key = value; _keySet = true; } }
    internal bool KeySet => _keySet;
}

public sealed class IdJagToCapabilityOptions
{
    /// <summary>The principal's 32-byte Ed25519 seed.</summary>
    public byte[]? PrincipalSecret { get; init; }
    /// <summary>The principal's public key (b64u); must be the seed's public key.</summary>
    public string? PrincipalPublic { get; init; }
    /// <summary>The holder (agent) key, b64u.</summary>
    public string? Holder { get; init; }
    /// <summary>Caveats appended after the three the grant produces (a JSON array, or null).</summary>
    public object? ExtraCaveats { get; init; }
    /// <summary>A post-quantum or hybrid root suite; when null the root is signed with Ed25519 from <see cref="PrincipalSecret"/>.</summary>
    public SuiteKey? Suite { get; init; }
}

public sealed class TokenExchangeRequestOptions
{
    public string? TokenEndpoint { get; init; }
    public string? SubjectToken { get; init; }
    public string? SubjectTokenType { get; init; }
    public string? ActorToken { get; init; }
    public string? ActorTokenType { get; init; }
    public string? Audience { get; init; }
    public string? Resource { get; init; }
    /// <summary>A scope string (split on whitespace) or a list of strings.</summary>
    public object? Scope { get; init; }
    public string? RequestedTokenType { get; init; }
    public string? ClientId { get; init; }
    /// <summary>Extra form members (string values kept, others dropped), spread over the standard ones.</summary>
    public object? Extra { get; init; }
}

public sealed class JwtBearerAssertionOptions
{
    public string? TokenEndpoint { get; init; }
    public string? Assertion { get; init; }
    public object? Scope { get; init; }
    public string? ClientId { get; init; }
    public string? ClientAssertion { get; init; }
    public object? Extra { get; init; }
}

public static class IdJag
{
    public const int MaxIdJagChars = 16384;
    public const string IdJagAuthorityCaveat = "idjag_authority";
    public const string IdJagProvenanceCaveat = "idjag_provenance";
    public const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string GrantTypeJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public const string TokenTypeIdJag = "urn:ietf:params:oauth:token-type:id-jag";
    public const string TokenTypeIdToken = "urn:ietf:params:oauth:token-type:id_token";
    public const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    public const string TokenTypeJwt = "urn:ietf:params:oauth:token-type:jwt";
    public const string ClientAssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    static IdJagVerificationException Err(string code, string message, Exception? inner = null) => new(code, message, inner);

    // ===================== verify =====================

    /// <summary>Verifies an ID-JAG and returns the grant (iss, sub, actor, agent, audience, scopes, iat, exp, jti?, nonce?, cnf?, oidcClaims).
    /// The OIDC verifier does every crypto and registered-claim check; this adds the single-audience rule, the actor, the scopes and (strict) typ,
    /// client_id and single-use jti. Throws <see cref="IdJagVerificationException"/>.</summary>
    public static D VerifyIdJag(string? jwt, VerifyIdJagOptions? opts)
    {
        if (string.IsNullOrEmpty(jwt)) throw Err("invalid_token", "verifyIdJag: jwt must be a non-empty string");
        if (jwt.Length > MaxIdJagChars) throw Err("invalid_token", "verifyIdJag: jwt exceeds the size limit");
        if (opts == null) throw Err("config", "verifyIdJag: opts is required");
        if (string.IsNullOrEmpty(opts.Issuer)) throw Err("config", "verifyIdJag: opts.issuer is required");
        if (string.IsNullOrEmpty(opts.Audience)) throw Err("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)");

        bool strict = opts.StrictDraft != false;
        if (strict && opts.ConsumeJti == null) throw Err("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)");
        if (strict && string.IsNullOrEmpty(opts.ClientId)) throw Err("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)");

        // reuse the OIDC verifier for every crypto + registered-claim check; re-wrap its failures as an ID-JAG error preserving the code
        var oidcOpts = new VerifyIdTokenOptions
        {
            Issuer = opts.Issuer, Audience = opts.Audience, Nonce = opts.Nonce, ClockToleranceSec = opts.ClockToleranceSec,
            MaxTokenAgeSec = opts.MaxTokenAgeSec, Algorithms = opts.Algorithms, JwksUri = opts.JwksUri, Discover = opts.Discover == true, Fetch = opts.Fetch,
        };
        if (opts.KeySet) oidcOpts = oidcOpts with { Key = opts.Key };
        D baseClaims;
        try { baseClaims = Oi.VerifyIdToken(jwt, oidcOpts); }
        catch (OidcVerificationException cause) { throw Err(cause.Code, cause.Message, cause); }
        catch (Exception cause) { throw Err("invalid_token", "ID-JAG verification failed", cause); }

        // ID-JAG is SINGLE-AUDIENCE: the resource app must be the sole aud
        var aud = baseClaims["aud"];
        var audList = aud is L al ? al : new L { aud };
        if (audList.Count != 1 || !(audList[0] is string a0 && a0 == opts.Audience))
            throw Err("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)");

        // the signature is verified, so the payload is authentic: read the non-OIDC claims (act, scope, jti) the projection does not surface
        D raw;
        try
        {
            var seg = jwt.Split('.');
            raw = Pca.ParseJson(System.Text.Encoding.UTF8.GetString(J.DecodeB64Lenient(seg[1]))) as D ?? throw new InvalidOperationException("not an object");
        }
        catch (Exception cause) { throw Err("invalid_token", "ID-JAG payload could not be decoded", cause); }

        var actor = AsActor(raw.GetValueOrDefault("act"))
            ?? throw Err("actor", "ID-JAG is missing a well-formed \"act\" (agent) claim with a string \"sub\"");
        var scopes = ParseScopes(raw.GetValueOrDefault("scope"), raw.GetValueOrDefault("scopes"))
            ?? throw Err("scope", "ID-JAG is missing the \"scope\" (or \"scopes\") claim");
        if (opts.RequiredScopes != null)
        {
            var have = new HashSet<string>(scopes.Cast<string>());
            foreach (var req in opts.RequiredScopes)
                if (!have.Contains(req)) throw Err("scope", $"ID-JAG does not grant the required scope \"{req}\"");
        }
        var jti = raw.GetValueOrDefault("jti") is string js && js.Length > 0 ? js : null;

        if (strict)
        {
            object? typ;
            try { typ = Pca.ParseJson(System.Text.Encoding.UTF8.GetString(J.DecodeB64Lenient(jwt.Split('.')[0]))) is D hd ? hd.GetValueOrDefault("typ") : null; }
            catch (Exception) { typ = null; }
            if (typ is not "oauth-id-jag+jwt") throw Err("grant", "ID-JAG header typ must be \"oauth-id-jag+jwt\"");
            if (raw.GetValueOrDefault("client_id") is not string cid || cid.Length == 0) throw Err("grant", "ID-JAG is missing \"client_id\"");
            if (cid != opts.ClientId) throw Err("grant", "ID-JAG client_id does not match the expected client");
            if (jti == null) throw Err("grant", "ID-JAG is missing \"jti\"");
            bool fresh;
            try { fresh = opts.ConsumeJti!(jti, IntentJsNum(baseClaims["exp"])) is true; } catch (Exception) { fresh = false; }
            if (!fresh) throw Err("grant", "ID-JAG jti was already used or the single-use store failed");
        }

        var o = new D
        {
            ["iss"] = baseClaims["iss"], ["sub"] = baseClaims["sub"], ["actor"] = actor, ["agent"] = actor["sub"], ["audience"] = opts.Audience,
            ["scopes"] = scopes, ["iat"] = baseClaims["iat"], ["exp"] = baseClaims["exp"],
        };
        if (jti != null) o["jti"] = jti;
        if (baseClaims.TryGetValue("nonce", out var nonce)) o["nonce"] = nonce;
        if (baseClaims.TryGetValue("cnf", out var cnf)) o["cnf"] = cnf;
        o["oidcClaims"] = baseClaims;
        return o;
    }

    static double IntentJsNum(object? v) => J.NumberOf(v) ?? double.NaN;

    static D? AsActor(object? v)
    {
        if (v is not D rec) return null;
        if (rec.GetValueOrDefault("sub") is not string sub || sub.Length == 0) return null;
        return new D(rec) { ["sub"] = sub };
    }

    /// <summary>JavaScript's <c>\s</c>.</summary>
    static bool IsJsSpace(char c) => c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or ' ' or ' ' or >= ' ' and <= ' ' or '\u2028' or '\u2029' or ' ' or ' ' or '　' or '﻿';

    static List<string> SplitWs(string s)
    {
        var parts = new List<string>();
        var cur = new StringBuilder();
        foreach (var c in s)
        {
            if (IsJsSpace(c)) { if (cur.Length > 0) parts.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(c);
        }
        if (cur.Length > 0) parts.Add(cur.ToString());
        return parts;
    }

    static L? ParseScopes(object? scope, object? scopes)
    {
        if (scope is string s) return SplitWs(s).Cast<object?>().ToList();
        if (scope is L sl) return sl.Where(x => x is string t && t.Length > 0).ToList();
        if (scopes is L ml) return ml.Where(x => x is string t && t.Length > 0).ToList();
        return null;
    }

    // ===================== principal / capability =====================

    /// <summary>The PCA principal descriptor of a verified grant (<see cref="Oi.OidcPrincipal"/> over its OIDC claims). Throws <see cref="ArgumentException"/>
    /// (the reference's TypeError) when the grant or its claims are not usable.</summary>
    public static D IdJagToPcaPrincipal(object? grant, OidcPrincipalOptions? opts = null)
    {
        if (grant is not D g) throw new ArgumentException("idJagToPcaPrincipal: grant is required");
        if (g.GetValueOrDefault("oidcClaims") is not D claims) throw new ArgumentException("oidcPrincipal: claims.iss is required");
        return Oi.OidcPrincipal(claims, opts);
    }

    /// <summary>Mints a root capability signed by the principal carrying the grant's authority, its provenance, the OIDC subject and any extra caveats.
    /// Returns {capability, principal, scopes}. Throws <see cref="ArgumentException"/> (TypeError) or <see cref="InvalidOperationException"/> (Error).</summary>
    public static D IdJagToCapability(object? grant, IdJagToCapabilityOptions? opts)
    {
        if (grant is not D g) throw new ArgumentException("idJagToCapability: grant is required");
        if (opts == null) throw new ArgumentException("idJagToCapability: opts is required");
        if (opts.PrincipalSecret == null) throw new ArgumentException("idJagToCapability: opts.principalSecret must be a Uint8Array");
        if (string.IsNullOrEmpty(opts.PrincipalPublic)) throw new ArgumentException("idJagToCapability: opts.principalPublic is required");
        if (string.IsNullOrEmpty(opts.Holder)) throw new ArgumentException("idJagToCapability: opts.holder (the agent key) is required");

        // derive the principal: this also validates principalPublic against the grant's cnf key when present
        var principal = IdJagToPcaPrincipal(g, new OidcPrincipalOptions { PrincipalPublic = opts.PrincipalPublic });

        var scopes = g.GetValueOrDefault("scopes") as L ?? throw new ArgumentException("idJagToCapability: grant.scopes is not iterable");
        var authority = new D { ["type"] = IdJagAuthorityCaveat, ["scopes"] = new L(scopes), ["aud"] = g.GetValueOrDefault("audience") };
        var provenance = new D
        {
            ["type"] = IdJagProvenanceCaveat, ["iss"] = g.GetValueOrDefault("iss"), ["sub"] = g.GetValueOrDefault("sub"), ["agent"] = g.GetValueOrDefault("agent"),
            ["aud"] = g.GetValueOrDefault("audience"), ["iat"] = g.GetValueOrDefault("iat"), ["exp"] = g.GetValueOrDefault("exp"),
        };
        if (g.GetValueOrDefault("jti") != null) provenance["jti"] = g["jti"];
        var caveats = new L { authority, provenance, principal["subjectCaveat"] };
        if (opts.ExtraCaveats != null)
        {
            if (opts.ExtraCaveats is not L extra) throw new ArgumentException("(opts.extraCaveats ?? []) is not iterable");
            caveats.AddRange(extra);
        }

        using var edKey = EdKey.FromSeed(opts.PrincipalSecret);
        if (edKey.Id != opts.PrincipalPublic) throw new ArgumentException("idJagToCapability: opts.principalSecret does not match opts.principalPublic");
        var suite = opts.Suite ?? SuiteKey.Ed25519(edKey);
        var capability = Issue.MintRoot(suite, opts.Holder, null, caveats);
        return new D { ["capability"] = capability, ["principal"] = principal, ["scopes"] = new L(scopes) };
    }

    public static bool IsIdJagAuthorityCaveat(object? cv) =>
        cv is D r && r.GetValueOrDefault("type") is IdJagAuthorityCaveat
        && r.GetValueOrDefault("scopes") is L sc && sc.All(s => s is string)
        && r.GetValueOrDefault("aud") is string a && a.Length > 0;

    public static bool IsIdJagProvenanceCaveat(object? cv) =>
        cv is D r && r.GetValueOrDefault("type") is IdJagProvenanceCaveat
        && r.GetValueOrDefault("iss") is string && r.GetValueOrDefault("sub") is string && r.GetValueOrDefault("agent") is string && r.GetValueOrDefault("aud") is string
        && r.GetValueOrDefault("iat") is Num && r.GetValueOrDefault("exp") is Num;

    static object? FirstCaveat(object? cap, string type)
    {
        if (cap is not D c || !c.TryGetValue("caveats", out var cv) || cv == null) return null;
        // `caveats.find` on anything that is not an array is a TypeError in the reference
        if (cv is not L list) throw new InvalidOperationException("cap.caveats.find is not a function");
        return list.FirstOrDefault(x => x is D d && d.GetValueOrDefault("type") is string t && t == type);
    }

    public static D? ReadIdJagAuthority(object? cap) => FirstCaveat(cap, IdJagAuthorityCaveat) is { } cv && IsIdJagAuthorityCaveat(cv) ? (D)cv : null;

    public static D? ReadIdJagProvenance(object? cap) => FirstCaveat(cap, IdJagProvenanceCaveat) is { } cv && IsIdJagProvenanceCaveat(cv) ? (D)cv : null;

    // ===================== XAA request shapes =====================

    /// <summary>A form-encoded POST request (url, method, headers, params, body).</summary>
    static D FormRequest(string url, List<(string Key, object? Value)> entries)
    {
        // an object literal: a repeated key keeps its first position and takes the last value
        var p = new D();
        foreach (var (k, v) in entries) p[k] = v;
        var clean = new D();
        foreach (var k in IntentJs.JsKeys(p.Keys)) if (p[k] is string s && s.Length > 0) clean[k] = s;
        var body = string.Join("&", clean.Select(e => FormEncode(e.Key) + "=" + FormEncode((string)e.Value!)));
        return new D
        {
            ["url"] = url, ["method"] = "POST",
            ["headers"] = new D { ["content-type"] = "application/x-www-form-urlencoded", ["accept"] = "application/json" },
            ["params"] = clean, ["body"] = body,
        };
    }

    /// <summary>The <c>application/x-www-form-urlencoded</c> byte serializer of <c>URLSearchParams</c>: alphanumerics and <c>*-._</c> stay, a space is <c>+</c>,
    /// every other UTF-8 byte is <c>%XX</c>; a lone surrogate is U+FFFD.</summary>
    static string FormEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            char c = (char)b;
            if (b < 0x80 && (char.IsAsciiLetterOrDigit(c) || c is '*' or '-' or '.' or '_')) sb.Append(c);
            else if (b == ' ') sb.Append('+');
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>The members `{...extra}` contributes: an object's own entries, an array's or string's indices (a number, null or bool contribute none).</summary>
    static IEnumerable<(string, object?)> Spread(object? extra)
    {
        switch (extra)
        {
            case D d: foreach (var e in d) yield return (e.Key, e.Value); break;
            case L l: for (int i = 0; i < l.Count; i++) yield return (i.ToString(System.Globalization.CultureInfo.InvariantCulture), l[i]); break;
            case string s: for (int i = 0; i < s.Length; i++) yield return (i.ToString(System.Globalization.CultureInfo.InvariantCulture), s[i].ToString()); break;
        }
    }

    static string? ScopeParam(object? scope)
    {
        if (scope == null) return null;
        IEnumerable<object?> parts = scope is L l ? l : scope is string s ? SplitWs(s) : throw new InvalidOperationException("scope.split is not a function");
        var kept = parts.OfType<string>().Where(x => x.Length > 0).ToList();
        return kept.Count > 0 ? string.Join(" ", kept) : null;
    }

    public static D TokenExchangeRequest(TokenExchangeRequestOptions? opts)
    {
        if (opts == null) throw new ArgumentException("tokenExchangeRequest: opts is required");
        if (string.IsNullOrEmpty(opts.TokenEndpoint)) throw new ArgumentException("tokenExchangeRequest: opts.tokenEndpoint is required");
        if (string.IsNullOrEmpty(opts.SubjectToken)) throw new ArgumentException("tokenExchangeRequest: opts.subjectToken is required");
        bool hasActor = !string.IsNullOrEmpty(opts.ActorToken);
        var e = new List<(string, object?)>
        {
            ("grant_type", GrantTypeTokenExchange), ("subject_token", opts.SubjectToken),
            ("subject_token_type", opts.SubjectTokenType ?? TokenTypeIdToken), ("requested_token_type", opts.RequestedTokenType ?? TokenTypeIdJag),
        };
        if (opts.Audience != null) e.Add(("audience", opts.Audience));
        if (opts.Resource != null) e.Add(("resource", opts.Resource));
        var scope = ScopeParam(opts.Scope);
        if (scope != null) e.Add(("scope", scope));
        if (hasActor) { e.Add(("actor_token", opts.ActorToken)); e.Add(("actor_token_type", opts.ActorTokenType ?? TokenTypeJwt)); }
        if (opts.ClientId != null) e.Add(("client_id", opts.ClientId));
        e.AddRange(Spread(opts.Extra));
        return FormRequest(opts.TokenEndpoint, e);
    }

    public static D JwtBearerAssertion(JwtBearerAssertionOptions? opts)
    {
        if (opts == null) throw new ArgumentException("jwtBearerAssertion: opts is required");
        if (string.IsNullOrEmpty(opts.TokenEndpoint)) throw new ArgumentException("jwtBearerAssertion: opts.tokenEndpoint is required");
        if (string.IsNullOrEmpty(opts.Assertion)) throw new ArgumentException("jwtBearerAssertion: opts.assertion is required");
        var scope = ScopeParam(opts.Scope);
        var e = new List<(string, object?)> { ("grant_type", GrantTypeJwtBearer), ("assertion", opts.Assertion) };
        if (scope != null) e.Add(("scope", scope));
        if (opts.ClientId != null) e.Add(("client_id", opts.ClientId));
        if (!string.IsNullOrEmpty(opts.ClientAssertion)) { e.Add(("client_assertion_type", ClientAssertionTypeJwtBearer)); e.Add(("client_assertion", opts.ClientAssertion)); }
        e.AddRange(Spread(opts.Extra));
        var request = FormRequest(opts.TokenEndpoint, e);
        var o = new D { ["grantType"] = GrantTypeJwtBearer, ["assertion"] = opts.Assertion };
        if (scope != null) o["scope"] = scope;
        o["request"] = request;
        return o;
    }
}
