using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the confirmation-gated undo engine and its attestation check against the TypeScript reference.</summary>
public class RefActionsUndoEngineTests
{
    const string M = "ref-actions-undo-engine";

    [Fact]
    public void UndoPlan() => Base.Check(M, "undoPlan", a =>
        ActionUndoEngine.UndoEngine(((L)a[0]!).Select(x => (D)x!), a[1], null)((D)a[2]!));
    [Fact] public void Attested() => Base.Check(M, "attested", a => ActionUndoEngine.AttestationVerifier(a[1], Actions.CoreRegistry)((D)a[0]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "undoPlan", "attested" }); Assert.Equal(260, Base.Total(M)); }
}
