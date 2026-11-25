using AtlasPca;
using AtlasPca.IdJag;
using AtlasPca.Oidc;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using J = AtlasPca.Jose.Jose;
using L = System.Collections.Generic.List<object?>;
using IJ = AtlasPca.IdJag.IdJag;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-idjag oracle. Function-valued options travel as JSON specs: <c>jwks</c> is a JWK Set the local key resolver is built from,
/// <c>consume</c> (absent | fresh | seen | throws | truthy) is the single-use jti store, <c>principalSecretLabel</c> names the Ed25519 seed
/// (sha256 of "atlas-pca-conformance/&lt;label&gt;"). verifyIdJag's result is {ok, grant | code, consumed}.</summary>
public class RefIdjagTests
{
    const string M = "ref-idjag";

    static double? Num(object? v) => v is AtlasPca.Num ? IntentJs.NumOf(v) : null;

    static OidcFetch Fetch(D spec)
    {
        var responses = (L)spec["responses"]!;
        int i = 0;
        return (url, _) =>
        {
            var r = (D)responses[Math.Min(i++, responses.Count - 1)]!;
            if (r.ContainsKey("throws")) throw new InvalidOperationException("boom");
            return new OidcHttpResponse((int)IntentJs.NumOf(r["status"])!.Value, (string)r["body"]!);
        };
    }

    // an option of a JS type the typed options cannot hold (a list or a number where the reference reads a string, a boolean where it reads a number) is left to the reference
    static string? VerifySkip(D c)
    {
        if (Base.Args(c)[1] is not D o) return null;
        if (o.GetValueOrDefault("algorithms") is { } al && al is not (L or string)) return "algorithms of another JS type";
        foreach (var k in new[] { "maxTokenAgeSec", "clockToleranceSec" })
            if (o.GetValueOrDefault(k) is { } v && v is not AtlasPca.Num) return k + " of another JS type";
        return null;
    }

    static object? Verify(object? token, object? optsRaw)
    {
        VerifyIdJagOptions? opts = null;
        if (optsRaw is D o)
        {
            // consumeJti travels as {mode}: fresh | seen | throw | truthy; anything else is not a function
            var mode = (o.GetValueOrDefault("consumeJti") as D)?.GetValueOrDefault("mode") as string;
            ConsumeJti? store = mode == null ? null : (jti, exp) =>
            {
                if (mode == "throw") throw new InvalidOperationException("store down");
                if (mode == "seen") return false;
                if (mode == "truthy") return 1; // truthy but not exactly true
                return true;
            };
            opts = new VerifyIdJagOptions
            {
                Issuer = o.GetValueOrDefault("issuer") as string,
                Audience = o.GetValueOrDefault("audience") as string,
                // any nonce that is not undefined is expected, and a value of another type never equals the token's
                Nonce = o.GetValueOrDefault("nonce") is { } nv ? nv as string ?? "\0nonce of another type" : null,
                RequiredScopes = o.GetValueOrDefault("requiredScopes") is L rs ? rs.Select(x => AtlasPca.Js.JsJson.ToJsString(x)).ToList() : null, // a scope that is not text is read as its string form
                ClockToleranceSec = Num(o.GetValueOrDefault("clockToleranceSec")),
                MaxTokenAgeSec = Num(o.GetValueOrDefault("maxTokenAgeSec")),
                Algorithms = o.GetValueOrDefault("algorithms") is L al ? al.OfType<string>().ToList() : o.GetValueOrDefault("algorithms") is string alg ? alg.Select(ch => ch.ToString()).ToList() : null,
                StrictDraft = o.GetValueOrDefault("strictDraft") as bool?,
                ClientId = o.GetValueOrDefault("clientId") as string,
                ConsumeJti = store,
                JwksUri = o.GetValueOrDefault("jwksUri") as string,
                Discover = o.GetValueOrDefault("discover") as bool?,
                Fetch = o.GetValueOrDefault("fetch") is D f && f.ContainsKey("responses") ? Fetch(f) : null,
            };
            if (o.ContainsKey("key")) opts = opts with { Key = o["key"] is D kd && kd.Count == 1 && kd.ContainsKey("jwks") ? J.CreateLocalJwkSet(kd["jwks"]) : Base.IsBytes(o["key"]) ? Base.Bytes(o["key"]) : o["key"] };
        }
        return IJ.VerifyIdJag(token as string, opts);
    }

    [Fact]
    public void VerifyIdJag() => Base.Check(M, "verifyIdJag", a => Verify(a[0], a[1]), skip: VerifySkip);

    [Fact]
    public void IdJagToPcaPrincipal() => Base.Check(M, "idJagToPcaPrincipal", a =>
        IJ.IdJagToPcaPrincipal(a[0], a.Count > 1 && a[1] is D p ? new OidcPrincipalOptions { PrincipalPublic = p.GetValueOrDefault("principalPublic") } : null));

    [Fact]
    public void IdJagToCapability() => Base.Check(M, "idJagToCapability", a =>
    {
        var o = a[1] as D;
        return IJ.IdJagToCapability(a[0], o == null ? null : new IdJagToCapabilityOptions
        {
            PrincipalSecret = Base.IsBytes(o.GetValueOrDefault("principalSecret")) ? Base.Bytes(o["principalSecret"]) : null,
            PrincipalPublic = o.GetValueOrDefault("principalPublic") as string,
            Holder = o.GetValueOrDefault("holder") as string,
            ExtraCaveats = o.GetValueOrDefault("extraCaveats"),
        });
    });

    [Fact]
    public void IsIdJagAuthorityCaveat() => Base.Check(M, "isIdJagAuthorityCaveat", a => IJ.IsIdJagAuthorityCaveat(a[0]));

    [Fact]
    public void IsIdJagProvenanceCaveat() => Base.Check(M, "isIdJagProvenanceCaveat", a => IJ.IsIdJagProvenanceCaveat(a[0]));

    [Fact]
    public void ReadIdJagAuthority() => Base.Check(M, "readIdJagAuthority", a => IJ.ReadIdJagAuthority(a[0]));

    [Fact]
    public void ReadIdJagProvenance() => Base.Check(M, "readIdJagProvenance", a => IJ.ReadIdJagProvenance(a[0]));

    // a `?? default` option of a non-string type survives in the reference (and is then dropped from the form): not representable in the typed options
    static string? TypeSkip(D c, params string[] keys)
    {
        if (Base.Args(c)[0] is not D o) return null;
        foreach (var k in keys) if (o.GetValueOrDefault(k) is { } v && v is not string) return "option of another JS type";
        return null;
    }

    [Fact]
    public void TokenExchangeRequest() => Base.Check(M, "tokenExchangeRequest", a => IJ.TokenExchangeRequest(a[0] is D o ? new TokenExchangeRequestOptions
    {
        TokenEndpoint = o.GetValueOrDefault("tokenEndpoint") as string,
        SubjectToken = o.GetValueOrDefault("subjectToken") as string,
        SubjectTokenType = o.GetValueOrDefault("subjectTokenType") as string,
        ActorToken = o.GetValueOrDefault("actorToken") as string,
        ActorTokenType = o.GetValueOrDefault("actorTokenType") as string,
        Audience = o.GetValueOrDefault("audience") as string,
        Resource = o.GetValueOrDefault("resource") as string,
        Scope = o.GetValueOrDefault("scope"),
        RequestedTokenType = o.GetValueOrDefault("requestedTokenType") as string,
        ClientId = o.GetValueOrDefault("clientId") as string,
        Extra = o.GetValueOrDefault("extra"),
    } : null), skip: c => TypeSkip(c, "subjectTokenType", "actorTokenType", "requestedTokenType"));

    [Fact]
    public void JwtBearerAssertion() => Base.Check(M, "jwtBearerAssertion", a => IJ.JwtBearerAssertion(a[0] is D o ? new JwtBearerAssertionOptions
    {
        TokenEndpoint = o.GetValueOrDefault("tokenEndpoint") as string,
        Assertion = o.GetValueOrDefault("assertion") as string,
        Scope = o.GetValueOrDefault("scope"),
        ClientId = o.GetValueOrDefault("clientId") as string,
        ClientAssertion = o.GetValueOrDefault("clientAssertion") as string,
        Extra = o.GetValueOrDefault("extra"),
    } : null));

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["MAX_ID_JAG_CHARS"] = (long)IJ.MaxIdJagChars, ["IDJAG_AUTHORITY_CAVEAT"] = IJ.IdJagAuthorityCaveat, ["IDJAG_PROVENANCE_CAVEAT"] = IJ.IdJagProvenanceCaveat,
        ["GRANT_TYPE_TOKEN_EXCHANGE"] = IJ.GrantTypeTokenExchange, ["GRANT_TYPE_JWT_BEARER"] = IJ.GrantTypeJwtBearer, ["TOKEN_TYPE_ID_JAG"] = IJ.TokenTypeIdJag,
        ["TOKEN_TYPE_ID_TOKEN"] = IJ.TokenTypeIdToken, ["TOKEN_TYPE_ACCESS_TOKEN"] = IJ.TokenTypeAccessToken, ["TOKEN_TYPE_JWT"] = IJ.TokenTypeJwt,
        ["CLIENT_ASSERTION_TYPE_JWT_BEARER"] = IJ.ClientAssertionTypeJwtBearer,
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[]
    {
        "constants", "verifyIdJag", "idJagToPcaPrincipal", "idJagToCapability", "isIdJagAuthorityCaveat", "isIdJagProvenanceCaveat",
        "readIdJagAuthority", "readIdJagProvenance", "tokenExchangeRequest", "jwtBearerAssertion",
    }); Assert.Equal(370, Base.Total(M)); }
}
