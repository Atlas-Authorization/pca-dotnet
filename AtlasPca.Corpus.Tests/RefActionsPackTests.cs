using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of pack building, sharding, upgrade verification and the transparency payload against the TypeScript reference.</summary>
public class RefActionsPackTests
{
    const string M = "ref-actions-pack";

    [Fact] public void BuildPack() => Base.Check(M, "buildPack", a => ActionPacks.BuildPack((D)a[0]!, Base.Bytes(a[1])));
    [Fact] public void ShardDefs() => Base.Check(M, "shardDefs", a => ActionPacks.ShardDefs(((L)a[0]!).Select(x => (D)x!), a.Count > 1 ? a[1] : null));
    [Fact] public void VerifyUpgrade() => Base.Check(M, "verifyUpgrade", a => ActionPacks.VerifyUpgrade(a[0], a[1], a[2], a.Count > 3 ? a[3] as D : null, a.Count > 4 ? a[4] as D : null));
    [Fact] public void PackStatementPayload() => Base.Check(M, "packStatementPayload", a => ActionTransparency.PackStatementPayload((D)a[0]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "buildPack", "shardDefs", "verifyUpgrade", "packStatementPayload" }); Assert.Equal(86, Base.Total(M)); }
}
