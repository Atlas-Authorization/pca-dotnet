using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the pack build, signing and verification, the source sync and the domain bindings over the corpus the Python lane generated (the confirmation option is a
/// boolean argument, the sync input one object).</summary>
public class RefActionsBuildPyTests
{
    const string M = "ref-actions-build-py";

    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);

    static D Sync(L a)
    {
        var s = (D)a[0]!;
        return ActionSync.SyncSource(Defs(s["current"]), Defs(s["imported"]), (string)s["specDigest"]!, s["now"], s.GetValueOrDefault("lock") as D, null, _ => (bool)a[1]!);
    }

    [Fact] public void BuildArtifacts() => Base.Check(M, "buildArtifacts", a => ActionBuild.BuildArtifacts(Defs(a[0]), (D)a[1]!, Actions.CoreRegistry, _ => (bool)a[2]!));
    [Fact] public void ToolActionMapOf() => Base.Check(M, "toolActionMapOf", a => ActionBuild.ToolActionMapOf(Defs(a[0]))((string)a[1]!, (D)a[2]!));
    [Fact] public void GenerateTypes() => Base.Check(M, "generateTypes", a => ActionBuild.GenerateTypes(Defs(a[0])));
    [Fact] public void PackConsistencyError() => Base.Check(M, "packConsistencyError", a => ActionBuild.PackConsistencyError(a[0], Actions.CoreRegistry));
    [Fact] public void SignPack() => Base.Check(M, "signPack", a => ActionBuild.SignPack((D)a[0]!, (string)a[1]!, Base.Bytes(a[2]), Actions.CoreRegistry));
    [Fact] public void PackKeyOf() => Base.Check(M, "packKeyOf", a => ActionBuild.PackKeyOf((string)a[0]!, Base.Bytes(a[1])));
    [Fact] public void VerifyPack() => Base.Check(M, "verifyPack", a => ActionBuild.VerifyPack(a[0], (L)a[1]!, Actions.CoreRegistry));
    [Fact] public void SyncSource() => Base.Check(M, "syncSource", a => Sync(a));
    [Fact] public void SyncText() => Base.Check(M, "syncText", a => ActionSync.SyncText(Sync(a)));
    [Fact] public void DomainVerbs() => Base.Check(M, "domainVerbs", a => ActionBuiltin.DomainVerbs((string)a[0]!));
    [Fact] public void DomainRoles() => Base.Check(M, "domainRoles", a => ActionBuiltin.DomainRoles((string)a[0]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "buildArtifacts", "toolActionMapOf", "generateTypes", "packConsistencyError", "signPack", "packKeyOf", "verifyPack", "syncSource", "syncText", "domainVerbs", "domainRoles" }); Assert.Equal(183, Base.Total(M)); }
}
