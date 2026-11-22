using AtlasPca;
using AtlasPca.Oidc;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using J = AtlasPca.Jose.Jose;
using L = System.Collections.Generic.List<object?>;
using O = AtlasPca.Oidc.Oidc;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the second OIDC reference corpus (test-data/ref-oidc-java.json.gz): the same functions as ref-oidc under other argument shapes.
/// verifyIdToken carries the key set as <c>jwks</c>; discoverOidc takes the one HTTP response as a third argument; jwksScenario drives one resolver
/// through timed steps, each with the response its fetch will see.</summary>
public class RefOidcJavaTests
{
    const string M = "ref-oidc-java";

    static double? Num(object? v) => v is AtlasPca.Num ? IntentJs.NumOf(v) : null;

    static OidcHttpResponse Respond(object? r)
    {
        if (r is not D d || d.ContainsKey("throws")) throw new InvalidOperationException("net");
        return new OidcHttpResponse((int)IntentJs.NumOf(d["status"])!.Value, (string)d["text"]!, d.GetValueOrDefault("contentLength") as string);
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
            // a string where the list is expected is read by the reference element by element: its characters
            Algorithms = o.GetValueOrDefault("algorithms") switch
            {
                L al => al.Select(x => x as string ?? "\0an algorithm of another type").ToList(), // a non-string entry names no algorithm
                string s => s.Select(ch => ch.ToString()).ToList(),
                _ => null,
            },
            JwksUri = o.GetValueOrDefault("jwksUri") as string,
        };
        return o.ContainsKey("jwks") ? b with { Key = J.CreateLocalJwkSet(o["jwks"]) } : b;
    }

    [Fact]
    public void VerifyIdToken() => Base.Check(M, "verifyIdToken", a => O.VerifyIdToken(a[0] as string, VerifyOpts(a[1])), min: 423);

    [Fact]
    public void DiscoveryUrl() => Base.Check(M, "discoveryUrl", a => O.DiscoveryUrl((string)a[0]!), min: 6);

    [Fact]
    public void DiscoverOidc() => Base.Check(M, "discoverOidc", a =>
    {
        var o = (D)a[1]!;
        return O.DiscoverOidc(a[0] as string, new DiscoverOidcOptions
        {
            Fetch = (_, _) => Respond(a[2]),
            MaxBytes = Num(o.GetValueOrDefault("maxBytes")),
            RequireHttps = o.ContainsKey("requireHttps") ? !(o["requireHttps"] is false) : null,
        });
    }, min: 307);

    [Fact]
    public void OidcPrincipal() => Base.Check(M, "oidcPrincipal", a =>
    {
        // a present null is not "no key supplied" in the reference: it is a value that is not a key, which the typed option expresses as a non-string
        OidcPrincipalOptions? o = a.Count > 1 && a[1] is D od && od.ContainsKey("principalPublic") ? new OidcPrincipalOptions { PrincipalPublic = od["principalPublic"] ?? new object() } : null;
        return O.OidcPrincipal((D)a[0]!, o);
    }, min: 170);

    [Fact]
    public void IsOidcSubjectCaveat() => Base.Check(M, "isOidcSubjectCaveat", a => O.IsOidcSubjectCaveat(a[0]), min: 12);

    [Fact]
    public void JwksScenario() => Base.Check(M, "jwksScenario", a =>
    {
        var o = (D)a[0]!;
        double clock = 0;
        int fetches = 0;
        object? queued = null;
        var r = O.CreateOidcJwks(new OidcJwksOptions
        {
            JwksUri = o.ContainsKey("jwksUri") ? o["jwksUri"] as string : "https://idp.example.com/jwks",
            Fetch = (_, _) => { fetches++; return Respond(queued); },
            CacheMaxAgeSec = Num(o.GetValueOrDefault("cacheMaxAgeSec")),
            CooldownSec = Num(o.GetValueOrDefault("cooldownSec")),
            MaxBytes = Num(o.GetValueOrDefault("maxBytes")),
            TimeoutMs = Num(o.GetValueOrDefault("timeoutMs")),
            RequireHttps = o.GetValueOrDefault("requireHttps") as bool?,
            Now = () => clock,
        });
        var steps = new L();
        foreach (var st in (L)a[1]!)
        {
            var s = (D)st!;
            clock = IntentJs.NumOf(s["t"])!.Value;
            queued = s.GetValueOrDefault("resp");
            var res = new D();
            try { r((D)s["header"]!); res["ok"] = true; }
            catch (OidcVerificationException e) { res["ok"] = false; res["code"] = e.Code; }
            catch (Exception) { res["ok"] = false; res["code"] = "other"; }
            res["fetches"] = fetches;
            steps.Add(res);
        }
        return steps;
    }, min: 25);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "verifyIdToken", "discoveryUrl", "discoverOidc", "oidcPrincipal", "isOidcSubjectCaveat", "jwksScenario" });
        Assert.Equal(943, Base.Cases(M).Count);
    }
}
