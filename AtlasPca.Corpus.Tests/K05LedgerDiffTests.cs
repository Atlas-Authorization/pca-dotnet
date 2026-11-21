using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the transparency ledger (test-data/k05-ledger.json.gz, TS reference packages/pca/src/ledger.ts),
/// through the pin-less overloads.</summary>
public class K05LedgerDiffTests
{
    const string M = "ledger";

    [Fact] public void Consistency() => K05.Check(M, "verifyLedgerConsistency", a => Ledger.VerifyLedgerConsistency(a[0], a[1], a[2]), min: 1815);
    [Fact] public void Inclusion() => K05.Check(M, "verifyLedgerInclusion", a => Ledger.VerifyLedgerInclusion((string)a[0]!, a[1], a[2]), min: 3);
    [Fact] public void WitnessedHead() => K05.Check(M, "verifyWitnessedHead", a => Ledger.VerifyWitnessedHead(a[0], (string)a[1]!), min: 225);
    [Fact] public void Equivocation() => K05.Check(M, "detectEquivocation", a => Ledger.DetectEquivocation(a[0], a[1], (string)a[2]!), min: 19);
    [Fact] public void Cosignature() => K05.Check(M, "verifyWitnessCosignature", a => Ledger.VerifyWitnessCosignature(a[0], a[1], (string)a[2]!), min: 90);
    [Fact] public void Cosignatures() => K05.Check(M, "verifyWitnessCosignatures", a => Ledger.VerifyWitnessCosignatures(a[0], a[1] as D), min: 218);
    [Fact] public void TreeHead() => K05.Check(M, "verifyTreeHead", a => Ledger.VerifyTreeHead(a[0], (string)a[1]!, a[2] as D), min: 395);
    [Fact] public void HeadConsistency() => K05.Check(M, "verifyHeadConsistency", a => Ledger.VerifyHeadConsistency(a[0], a[1], a[2], (string)a[3]!, a[4] as D), min: 25);

    [Fact]
    public void CheckpointChain() => K05.Check(M, "verifyCheckpointChain", a =>
    {
        var v = Ledger.VerifyCheckpointChain(a[0], (string)a[1]!, a[2] as D);
        if (v.Ok && v.At != 0) throw new InvalidOperationException("an ok verdict carries at = 0");
        return v.Ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["at"] = (long)v.At };
    }, min: 20);

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "verifyLedgerConsistency", "verifyLedgerInclusion", "verifyWitnessedHead", "detectEquivocation", "verifyWitnessCosignature",
        "verifyWitnessCosignatures", "verifyTreeHead", "verifyHeadConsistency", "verifyCheckpointChain",
    });
}
