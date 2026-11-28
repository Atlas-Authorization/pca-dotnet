using AtlasPca.ActionsKit;
using AtlasPca.Scitt;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the review flow (attestation verdicts, status, queue, confirm) and pack transparency over the corpus the Python lane generated: the custom trait
/// definitions, the reviewer options and the log keys are arguments of each call.</summary>
public class RefActionsReviewPyTests
{
    const string M = "ref-actions-review-py";

    static Dictionary<string, D> Reg(object? rd) => rd == null ? Actions.CoreRegistry : Actions.ExtendRegistry(Actions.CoreRegistry, (L)rd);
    static IEnumerable<D> Defs(object? xs) => ((L)xs!).Select(x => (D)x!);

    [Fact] public void VerifyAttestation() => Base.Check(M, "verifyAttestation", a => ImportReview.VerifyAttestation((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void ReviewStatus() => Base.Check(M, "reviewStatus", a => ImportReview.ReviewStatus((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void RevertStale() => Base.Check(M, "revertStale", a => ImportReview.RevertStale((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void ReviewPriority() => Base.Check(M, "reviewPriority", a => ImportReview.ReviewPriority((D)a[0]!, Actions.CoreRegistry));
    [Fact] public void ReviewQueueOrder() => Base.Check(M, "reviewQueueOrder", a => ImportReview.ReviewQueueOrder(Defs(a[0]), Actions.CoreRegistry),
        // the full-registry case is generated as the verbs of the ordered defs
        eq: (c, have) => Base.Eq(c["out"], c["name"] is string n && n.EndsWith("/all") && have is IEnumerable<D> ds ? ds.Select(d => (object?)d["verb"]).ToList() : have));
    [Fact] public void PrepareReview() => Base.Check(M, "prepareReview", a => ImportReview.PrepareReview((D)a[0]!, Actions.CoreRegistry, a.Count > 1 ? a[1] as D : null));

    [Fact]
    public void ConfirmDef() => Base.Check(M, "confirmDef", a =>
    {
        var o = (D)a[1]!;
        return ImportReview.ConfirmDef((D)a[0]!, Reg(o.GetValueOrDefault("regDefs")), (string)o["kid"]!, Base.Bytes(o["seed"]),
            o.GetValueOrDefault("pins") is D { Count: > 0 } pins ? pins : null, (L)o["finalTraits"]!, o.GetValueOrDefault("dismissed") is L { Count: > 0 } dis ? dis : null, o["ts"]);
    });

    [Fact] public void PackStatementPayload() => Base.Check(M, "packStatementPayload", a => ActionTransparency.PackStatementPayload((D)a[0]!));

    [Fact]
    public void AppendPackToLog() => Base.Check(M, "appendPackToLog", a =>
    {
        var svc = new TransparencyService("EdDSA", CoseKey.Ed25519Private(Base.Bytes(a[2])), "ts");
        var key = CoseKey.Ed25519Private(Base.Bytes(a[1]));
        return ((L)a[0]!).Select(p =>
        {
            var r = ActionTransparency.AppendPackToLog((D)p!, svc, "EdDSA", key, "registry");
            return (object?)new D { ["statement"] = r.Statement, ["receipt"] = r.Receipt, ["index"] = r.Index, ["root"] = r.Root };
        }).ToList();
    });

    [Fact]
    public void VerifyPackLogEntry() => Base.Check(M, "verifyPackLogEntry", a =>
    {
        var e = (D)a[1]!;
        // a missing statement or receipt is not bytes: the reference's verifier throws on it and answers false
        if (e.GetValueOrDefault("statement") is null || e.GetValueOrDefault("receipt") is null) return false;
        return ActionTransparency.VerifyPackLogEntry((D)a[0]!, Base.Bytes(e["statement"]), Base.Bytes(e["receipt"]),
            CoseKey.Ed25519Public(Base.Bytes(a[2])), CoseKey.Ed25519Public(Base.Bytes(a[3])), a[4] as string);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "verifyAttestation", "reviewStatus", "revertStale", "reviewPriority", "reviewQueueOrder", "prepareReview", "confirmDef", "packStatementPayload", "appendPackToLog", "verifyPackLogEntry" }); Assert.Equal(229, Base.Total(M)); }
}
