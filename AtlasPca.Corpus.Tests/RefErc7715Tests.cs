using System.Numerics;
using AtlasPca;
using AtlasPca.Erc7715;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the ERC-7715 mapping and verification (test-data/ref-erc7715.json.gz, TS reference packages/pca-erc7715).
/// The chain id of a mapping option crosses as a decimal string and becomes a BigInteger first, like the reference's BigInt.</summary>
public class RefErc7715Tests
{
    const string M = "ref-erc7715";

    static object? Conv(object? x) => x is D d && d.GetValueOrDefault("chainId") is string c ? new D(d) { ["chainId"] = BigInteger.Parse(c) } : x;

    [Fact] public void GrantToPermissionRequest() => Base.Check(M, "grantToPermissionRequest", a => Erc7715.Erc7715.GrantToPermissionRequest(a[0], Conv(a[1])));
    [Fact] public void SupportsRequest() => Base.Check(M, "supportsRequest", a => Erc7715.Erc7715.SupportsRequest(a[0], a[1]));
    [Fact] public void RevokeParams() => Base.Check(M, "revokeParams", a => a.Count == 0 ? new D() : Erc7715.Erc7715.RevokeParams(a[0]));

    [Fact]
    public void VerifyGrantedPermission() => Base.Check(M, "verifyGrantedPermission", a =>
    {
        var o = a[3] as D;
        var owners = o?.GetValueOrDefault("owners") as D;
        Func<string, string?>? owner = owners != null ? c => owners.GetValueOrDefault(c) as string : null;
        return Erc7715.Erc7715.VerifyGrantedPermission(a[0], a[1], a[2], o?.GetValueOrDefault("allowedManagers"), owner);
    });

    [Fact] public void GrantDigestOf() => Base.Check(M, "grantDigestOf", a => Erc7715.Erc7715.GrantDigestOf(a[0]));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "grantToPermissionRequest", "supportsRequest", "revokeParams", "verifyGrantedPermission", "grantDigestOf" }); Assert.Equal(4314, Base.Total(M)); }
}
