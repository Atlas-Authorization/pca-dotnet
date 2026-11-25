using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of the canonical approval render (test-data/base-approval.json.gz, TS reference
/// packages/pca/src/approval-render.ts + packages/pca-actions/src/approval-render.ts / approval-profiles.ts).</summary>
public class BaseApprovalDiffTests
{
    const string M = "approval";

    [Fact] public void RenderShapeError() => Base.Check(M, "approvalRenderShapeError", a => Approval.RenderShapeError(a[0]));
    [Fact] public void RenderDigest() => Base.Check(M, "approvalRenderDigest", a => Approval.RenderDigest(a[0]));
    [Fact] public void Challenge() => Base.Check(M, "approvalChallengeB64u", a => Approval.Challenge(a[0], a[1]));
    [Fact] public void BindingWords() => Base.Check(M, "bindingWords", a => Approval.BindingWords(a[0]));
    // no def here carries a signed confirmation: the TS render is always unreviewed (confirmed = false)
    [Fact] public void Render() => Base.Check(M, "renderApproval", a => Approval.Render((D)a[0]!, a.Count > 1 ? a[1] : null, false));
    [Fact] public void ValidateDef() => Base.Check(M, "validateDef", a => Actions.ValidateDef(a[0]));
    [Fact] public void Psd2Linking() => Base.Check(M, "psd2Linking", a => Approval.Psd2Linking((D)a[0]!));

    // typed (long, long) port: a non-integer argument cannot be passed (the TS refuses every one of them)
    [Fact]
    public void MinorToDecimal() => Base.Check(M, "minorToDecimal", a => Approval.MinorToDecimal(Base.Long(a[0]), Base.Long(a[1])),
        skip: c => Base.Args(c).All(Base.IsJsonInt) ? null : "not a JSON integer argument");

    // the challenge is bytes in TS ({$bytes}), the b64url string here
    [Fact]
    public void Batch() => Base.Check(M, "approvalBatch", a =>
    {
        var r = Approval.Batch((L)a[0]!);
        r["challenge"] = new D { ["$bytes"] = r["challenge"] };
        return r;
    });

    [Fact] public void SpcExpectation() => Base.Check(M, "spcExpectation", a => Approval.SpcExpectation((D)a[0]!, (string)a[1]!, a.Count > 2 ? (string)a[2]! : "name"));
    [Fact] public void CibaApprovalDetails() => Base.Check(M, "cibaApprovalDetails", a => Approval.CibaApprovalDetails((D)a[0]!));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "approvalRenderShapeError", "approvalRenderDigest", "approvalChallengeB64u", "bindingWords", "renderApproval", "validateDef",
        "psd2Linking", "minorToDecimal", "approvalBatch",
        "spcExpectation", "cibaApprovalDetails",
    }); Assert.Equal(4791, Base.Total(M)); }
}
