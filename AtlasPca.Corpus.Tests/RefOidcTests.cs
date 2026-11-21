using AtlasPca;
using AtlasPca.Oidc;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using J = AtlasPca.Jose.Jose;
using L = System.Collections.Generic.List<object?>;
using O = AtlasPca.Oidc.Oidc;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the reference's pca-oidc oracle: discovery, ID-token verification across algorithms, the JWKS resolver, principal mapping.
/// Function-valued options travel in the corpus as JSON specs ({jwks}, {resolver}, {fetch: {responses}}) that this file turns into the same callables.
/// A case whose option has a JavaScript type the typed .NET options cannot hold (a number where a string is expected, ...) is skipped with that reason.</summary>
public class RefOidcTests
{
    const string M = "ref-oidc";

    static double? Num(object? v) => v is AtlasPca.Num ? IntentJs.NumOf(v) : null;

    static OidcFetch Fetch(object? spec, List<string>? calls = null, Action? onCall = null)
    {
        var responses = (L)((D)spec!)["responses"]!;
        int i = 0;
        return (url, _) =>
        {
            calls?.Add(url);
            onCall?.Invoke();
            var r = (D)responses[Math.Min(i++, responses.Count - 1)]!;
            if (r.ContainsKey("throws")) throw new InvalidOperationException("boom");
            string? cl = null;
            if (r.GetValueOrDefault("headers") is D h)
                foreach (var (k, v) in h) if (k.ToLowerInvariant() == "content-length") cl = (string?)v;
            return new OidcHttpResponse((int)IntentJs.NumOf(r["status"])!.Value, (string)r["body"]!, cl);
        };
    }

    static Func<D, object?> Resolver(D r, List<string>? calls = null, Action? onCall = null, Func<double>? now = null) => O.CreateOidcJwks(new OidcJwksOptions
    {
        JwksUri = r.GetValueOrDefault("jwksUri") as string,
        Fetch = r.ContainsKey("fetch") ? Fetch(r["fetch"], calls, onCall) : null,
        CacheMaxAgeSec = Num(r.GetValueOrDefault("cacheMaxAgeSec")),
        CooldownSec = Num(r.GetValueOrDefault("cooldownSec")),
        MaxBytes = Num(r.GetValueOrDefault("maxBytes")),
        TimeoutMs = Num(r.GetValueOrDefault("timeoutMs")),
        RequireHttps = r.GetValueOrDefault("requireHttps") as bool?,
        Now = now,
    });

    static bool NotNum(D o, string k) => o.ContainsKey(k) && Num(o[k]) == null;
    static bool NotStr(D o, string k) => o.ContainsKey(k) && o[k] is not string;
    static bool NotBool(D o, string k) => o.ContainsKey(k) && o[k] is not bool;

    static string? VerifySkip(D c)
    {
        if (Base.Args(c)[1] is not D o) return null;
        foreach (var k in new[] { "nonce", "authorizedParty", "accessToken", "code" }) if (NotStr(o, k)) return "option of another JS type";
        foreach (var k in new[] { "maxTokenAgeSec", "clockToleranceSec" }) if (NotNum(o, k)) return "option of another JS type";
        if (NotBool(o, "requireHttps")) return "option of another JS type";
        if (o.ContainsKey("algorithms") && !(o["algorithms"] is L al && al.All(x => x is string))) return "option of another JS type";
        if (o.GetValueOrDefault("key") is D k2 && k2.GetValueOrDefault("resolver") is D r)
        {
            foreach (var k in new[] { "cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs" }) if (NotNum(r, k)) return "option of another JS type";
            if (NotBool(r, "requireHttps")) return "option of another JS type";
        }
        return null;
    }

    static VerifyIdTokenOptions? VerifyOpts(object? raw)
    {
        if (raw is not D o) return null;
        var b = new VerifyIdTokenOptions
        {
            Issuer = o.GetValueOrDefault("issuer") as string,
            Audience = o.GetValueOrDefault("audience"),
            Nonce = o.GetValueOrDefault("nonce") as string,
            AuthorizedParty = o.GetValueOrDefault("authorizedParty") as string,
            AccessToken = o.GetValueOrDefault("accessToken") as string,
            Code = o.GetValueOrDefault("code") as string,
            ClockToleranceSec = Num(o.GetValueOrDefault("clockToleranceSec")),
            MaxTokenAgeSec = Num(o.GetValueOrDefault("maxTokenAgeSec")),
            Algorithms = o.GetValueOrDefault("algorithms") is L al ? al.Select(x => x as string ?? "\0an algorithm of another type").ToList() : null,
            JwksUri = o.GetValueOrDefault("jwksUri") as string,
            Discover = o.GetValueOrDefault("discover") is true,
            Fetch = o.GetValueOrDefault("fetch") is D f && f.ContainsKey("responses") ? Fetch(f) : null,
            RequireHttps = o.GetValueOrDefault("requireHttps") as bool?,
        };
        // the key is only set when the case carries one (an absent key falls through to jwksUri / discover)
        return o.ContainsKey("key") ? b with { Key = KeyOf(o["key"]) } : b;
    }

    static object? KeyOf(object? k)
    {
        if (k is D d && d.Count == 1 && d.ContainsKey("jwks")) return J.CreateLocalJwkSet(d["jwks"]);
        if (k is D r && r.Count == 1 && r.ContainsKey("resolver")) return Resolver((D)r["resolver"]!);
        if (Base.IsBytes(k)) return Base.Bytes(k);
        return k;
    }

    [Fact]
    public void VerifyIdToken() => Base.Check(M, "verifyIdToken", a =>
    {
        // a token that is not a string (a number, null) is the reference's `typeof` refusal
        var opts = a[1];
        return O.VerifyIdToken(a[0] as string, VerifyOpts(opts));
    }, skip: VerifySkip);

    [Fact]
    public void DiscoveryUrl() => Base.Check(M, "discoveryUrl", a => O.DiscoveryUrl(a[0] as string ?? throw new ArgumentException("issuer is not a string")));

    static DiscoverOidcOptions? DiscoverOpts(object? raw)
    {
        if (raw is not D o) return null;
        return new DiscoverOidcOptions
        {
            Fetch = o.GetValueOrDefault("fetch") is D f && f.ContainsKey("responses") ? Fetch(f) : null,
            MaxBytes = Num(o.GetValueOrDefault("maxBytes")),
            // the reference requires https unless the option is exactly false
            RequireHttps = o.ContainsKey("requireHttps") ? !(o["requireHttps"] is false) : null,
        };
    }

    static string? DiscoverSkip(D c)
    {
        var a = Base.Args(c);
        if (a[1] is not D o) return "options bag is null (a JS TypeError, not representable)";
        if (NotNum(o, "maxBytes")) return "option of another JS type";
        return null;
    }

    [Fact]
    public void DiscoverOidc() => Base.Check(M, "discoverOidc", a => O.DiscoverOidc(a[0] as string, DiscoverOpts(a[1])), skip: DiscoverSkip);

    [Fact]
    public void DiscoverOidcCalls() => Base.Check(M, "discoverOidcCalls", a =>
    {
        var urls = new List<string>();
        var opts = (D)a[1]!;
        var o = new DiscoverOidcOptions { Fetch = Fetch(opts["fetch"], urls) };
        string outcome = "ok";
        try { O.DiscoverOidc(a[0] as string, o); } catch (Exception) { outcome = "error"; }
        return new D { ["urls"] = urls.Cast<object?>().ToList(), ["outcome"] = outcome };
    });

    static D Pick(D j)
    {
        var o = new D();
        foreach (var k in new[] { "kty", "crv", "x", "y", "n", "e" }) if (j.ContainsKey(k)) o[k] = j[k];
        return o;
    }

    static D Step(Func<D, object?> r, D header)
    {
        try { return new D { ["ok"] = Pick(((AtlasPca.Jose.JoseKey)r(header)!).ExportJwk()) }; }
        catch (OidcVerificationException e) when (e.Code == "keys") { return new D { ["err"] = "keys" }; }
        catch (Exception) { return new D { ["err"] = "other" }; }
    }

    static string? JwksSkip(D c)
    {
        var s = (D)Base.Args(c)[0]!;
        if (s.GetValueOrDefault("opts") is D o)
        {
            foreach (var k in new[] { "cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs" }) if (NotNum(o, k)) return "option of another JS type";
            if (NotBool(o, "requireHttps")) return "option of another JS type";
        }
        return null;
    }

    [Fact]
    public void CreateOidcJwks() => Base.Check(M, "createOidcJwks", a =>
    {
        var s = (D)a[0]!;
        double clock = 0;
        int fetches = 0;
        var spec = new D { ["jwksUri"] = s.GetValueOrDefault("jwksUri"), ["fetch"] = s["fetch"] };
        if (s.GetValueOrDefault("opts") is D extra) foreach (var (k, v) in extra) spec[k] = v;
        var r = Resolver(spec, null, () => fetches++, () => clock);
        var steps = new L();
        foreach (var st in (L)s["steps"]!)
        {
            var sd = (D)st!;
            clock = IntentJs.NumOf(sd["atMs"])!.Value;
            steps.Add(Step(r, (D)sd["header"]!));
        }
        return new D { ["steps"] = steps, ["fetches"] = fetches };
    }, skip: JwksSkip);

    [Fact]
    public void CreateOidcJwksFromIssuer() => Base.Check(M, "createOidcJwksFromIssuer", a =>
    {
        var s = (D)a[0]!;
        var urls = new List<string>();
        var o = s.GetValueOrDefault("opts") as D;
        var r = O.CreateOidcJwksFromIssuer((string)s["issuer"]!, new OidcJwksOptions
        {
            Fetch = Fetch(s["fetch"], urls),
            MaxBytes = o == null ? null : Num(o.GetValueOrDefault("maxBytes")),
            RequireHttps = o?.GetValueOrDefault("requireHttps") as bool?,
        });
        return new D { ["out"] = Step(r, (D)s["header"]!), ["urls"] = urls.Cast<object?>().ToList() };
    });

    [Fact]
    public void OidcPrincipal() => Base.Check(M, "oidcPrincipal", a =>
    {
        // a claims value that is not an object is the reference's TypeError
        var claims = a[0] as D ?? throw new ArgumentException("claims is not an object");
        var o = a.Count > 1 ? a[1] : null;
        return O.OidcPrincipal(claims, o is D od ? new OidcPrincipalOptions { PrincipalPublic = od.GetValueOrDefault("principalPublic") } : null);
    }, skip: c => Base.Args(c).Count > 1 && Base.Args(c)[1] is null ? "null options bag (a JS TypeError, not representable)" : null);

    [Fact]
    public void IsOidcSubjectCaveat() => Base.Check(M, "isOidcSubjectCaveat", a => O.IsOidcSubjectCaveat(a[0]));

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["DEFAULT_ID_TOKEN_ALGS"] = O.DefaultIdTokenAlgs.Cast<object?>().ToList(),
        ["DEFAULT_MAX_DISCOVERY_BYTES"] = O.DefaultMaxDiscoveryBytes,
        ["DEFAULT_JWKS_TIMEOUT_MS"] = O.DefaultJwksTimeoutMs,
        ["OIDC_SUBJECT_CAVEAT"] = O.OidcSubjectCaveat,
    });

    [Fact]
    public void EveryFnIsHandled() { Base.Covers(M, new[]
    {
        "verifyIdToken", "discoveryUrl", "discoverOidc", "discoverOidcCalls", "createOidcJwks", "createOidcJwksFromIssuer",
        "oidcPrincipal", "isOidcSubjectCaveat", "constants",
    }); Assert.Equal(662, Base.Total(M)); }
}
