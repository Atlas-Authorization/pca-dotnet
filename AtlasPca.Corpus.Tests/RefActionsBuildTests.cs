using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action build outputs and pack signing against the TypeScript reference.</summary>
public class RefActionsBuildTests
{
    const string M = "ref-actions-build";

    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);

    [Fact] public void BuildArtifacts() => Base.Check(M, "buildArtifacts", a => ActionBuild.BuildArtifacts(Defs(a[0]), (D)a[1]!, Actions.CoreRegistry));
    [Fact] public void GenerateTypes() => Base.Check(M, "generateTypes", a => ActionBuild.GenerateTypes(Defs(a[0])));
    [Fact] public void ToolAction() => Base.Check(M, "toolAction", a => ActionBuild.ToolActionMapOf(Defs(a[0]))((string)a[1]!, (D)a[2]!));
    [Fact] public void PackConsistencyError() => Base.Check(M, "packConsistencyError", a => ActionBuild.PackConsistencyError(a[0], Actions.CoreRegistry));
    [Fact] public void SignPack() => Base.Check(M, "signPack", a => ActionBuild.SignPack((D)a[0]!, (string)a[1]!, Base.Bytes(a[2]), Actions.CoreRegistry));
    [Fact] public void PackKeyOf() => Base.Check(M, "packKeyOf", a => ActionBuild.PackKeyOf((string)a[0]!, Base.Bytes(a[1])));
    [Fact] public void VerifyPack() => Base.Check(M, "verifyPack", a => ActionBuild.VerifyPack(a[0], (L)a[1]!, Actions.CoreRegistry));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "buildArtifacts", "generateTypes", "toolAction", "packConsistencyError", "signPack", "packKeyOf", "verifyPack" }); Assert.Equal(52, Base.Total(M)); }
}
