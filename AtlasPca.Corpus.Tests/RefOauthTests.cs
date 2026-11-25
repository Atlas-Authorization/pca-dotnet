using AtlasPca.Oauth;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the OAuth / MCP-authorization bridge (test-data/ref-oauth.json.gz, TypeScript reference pca-oauth).</summary>
public class RefOauthTests
{
    const string M = "ref-oauth";

    static D? Opts(L a, int i) => a.Count > i ? (D?)a[i] : null;

    [Fact] public void ResourceIdentifierProblem() => Base.Check(M, "resourceIdentifierProblem", a => OAuthBridge.ResourceIdentifierProblem(a[0]));
    [Fact] public void PrmPathForResource() => Base.Check(M, "prmPathForResource", a => OAuthBridge.PrmPathForResource((string)a[0]!));
    [Fact] public void PrmUrlForResource() => Base.Check(M, "prmUrlForResource", a => OAuthBridge.PrmUrlForResource((string)a[0]!));
    [Fact] public void ProtectedResourceMetadata() => Base.Check(M, "protectedResourceMetadata", a => OAuthBridge.ProtectedResourceMetadata((D)a[0]!));
    [Fact] public void OauthDiscoveryHandler() => Base.Check(M, "oauthDiscoveryHandler", a => OAuthBridge.OauthDiscoveryHandler((D)a[0]!));
    [Fact] public void ParseProtectedResourceMetadata() => Base.Check(M, "parseProtectedResourceMetadata", a => OAuthBridge.ParseProtectedResourceMetadata(a[0], Opts(a, 1)));
    [Fact] public void WwwAuthenticate() => Base.Check(M, "wwwAuthenticate", a => OAuthBridge.WwwAuthenticate(a[0], Opts(a, 1)));
    [Fact] public void McpUnauthorized() => Base.Check(M, "mcpUnauthorized", a => OAuthBridge.McpUnauthorized(a[0], Opts(a, 1)));
    [Fact] public void UpgradeUnauthorizedChallenge() => Base.Check(M, "upgradeUnauthorizedChallenge", a => OAuthBridge.UpgradeUnauthorizedChallenge((D)a[0]!, a[1], Opts(a, 2)));
    [Fact] public void CheckResourceIndicator() => Base.Check(M, "checkResourceIndicator", a => OAuthBridge.CheckResourceIndicator(a[0], a[1]));
    [Fact] public void CheckTokenAudience() => Base.Check(M, "checkTokenAudience", a => OAuthBridge.CheckTokenAudience(a[0], a[1]));
    [Fact] public void BuildPcaGrantDetail() => Base.Check(M, "buildPcaGrantDetail", a => OAuthBridge.BuildPcaGrantDetail((D)a[0]!));
    [Fact] public void PcaGrantRequestParam() => Base.Check(M, "pcaGrantRequestParam", a => OAuthBridge.PcaGrantRequestParam((L)a[0]!));
    [Fact] public void AuthorizePcaGrantToken() => Base.Check(M, "authorizePcaGrantToken", a => OAuthBridge.AuthorizePcaGrantToken((D)a[0]!));
    [Fact] public void OauthScopeForAction() => Base.Check(M, "oauthScopeForAction", a => OAuthBridge.OauthScopeForAction(a[0], (D)a[1]!));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "resourceIdentifierProblem", "prmPathForResource", "prmUrlForResource", "protectedResourceMetadata", "oauthDiscoveryHandler",
        "parseProtectedResourceMetadata", "wwwAuthenticate", "mcpUnauthorized", "upgradeUnauthorizedChallenge", "checkResourceIndicator",
        "checkTokenAudience", "buildPcaGrantDetail", "pcaGrantRequestParam", "authorizePcaGrantToken", "oauthScopeForAction",
    }); Assert.Equal(840, Base.Total(M)); }
}
