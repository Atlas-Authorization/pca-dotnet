using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the cross-domain agent mesh and its Merkle primitives (test-data/k05-mesh.json.gz, TS reference
/// packages/pca/src/mesh.ts, ledger.ts verifyLedgerConsistency, revocation.ts verifyNonMembership). verifyMeshProof compares ok, reason, hop.</summary>
public class K05MeshDiffTests
{
    const string M = "mesh";

    [Fact]
    public void VerifyMeshProof() => K05.Check(M, "verifyMeshProof", a =>
    {
        var v = Mesh.Verify(a[0], a[1]);
        if (v.Ok) return new D { ["ok"] = true };
        var o = new D { ["ok"] = false, ["reason"] = v.Reason };
        if (v.Hop >= 0) o["hop"] = (long)v.Hop;
        return o;
    }, min: 5000);

    [Fact] public void CheckHeadAdvance() => K05.Check(M, "checkHeadAdvance", a => Mesh.CheckHeadAdvance(a[0], a[1], a.Count > 2 ? a[2] : null));
    [Fact] public void VerifyLedgerConsistency() => K05.Check(M, "verifyLedgerConsistency", a => Ledger.VerifyLedgerConsistency(a[0], a[1], a[2]));
    [Fact] public void VerifyNonMembership() => K05.Check(M, "verifyNonMembership", a => Mesh.NonMembership((string)a[0]!, a[1] as D, (string)a[2]!), min: 6000);

    [Fact]
    public void EffectiveAuthority() => K05.Check(M, "effectiveAuthority", a =>
    {
        var (e, why) = Mesh.Effective(a[0]);
        if (why != null) return new D { ["error"] = why };
        var o = new D { ["prefixes"] = e.Prefixes };
        if (e.Actions != null) o["actions"] = e.Actions;
        if (e.MaxAmount is double ma) o["maxAmount"] = ma;
        if (e.ExpiresAt is double ex) o["expiresAt"] = ex;
        if (e.Audience != null) o["audience"] = e.Audience;
        if (e.MaxHops is double mh) o["maxHops"] = mh;
        return o;
    });

    /// <summary>a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused.</summary>
    [Fact]
    public void EmptyHeadAdvances()
    {
        var j = (D)Pca.ParseJson("{\"e\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":0,\"root\":\"\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"n\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":3,\"root\":\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"ok\":{\"oldSize\":0,\"newSize\":3,\"path\":[]},\"path\":{\"oldSize\":0,\"newSize\":3,\"path\":[\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\"]},\"old1\":{\"oldSize\":1,\"newSize\":3,\"path\":[]}}")!;
        Assert.Null(Mesh.CheckHeadAdvance(j["e"], j["n"], j["ok"]));
        Assert.Equal("consistency proof required for a larger head", Mesh.CheckHeadAdvance(j["e"], j["n"], null));
        Assert.Equal("head is not consistent with the previous head (fork or rewrite)", Mesh.CheckHeadAdvance(j["e"], j["n"], j["path"]));
        Assert.Equal("consistency proof required for a larger head", Mesh.CheckHeadAdvance(j["e"], j["n"], j["old1"]));
    }

    [Fact]
    public void EveryFn() => K05.Covers(M, new[] { "verifyMeshProof", "checkHeadAdvance", "verifyLedgerConsistency", "verifyNonMembership", "effectiveAuthority" });
}
