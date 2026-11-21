using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the canonical approval render (test-data/k05-approval.json.gz, TS reference
/// packages/pca/src/approval-render.ts + packages/pca-actions/src/approval-render.ts / approval-profiles.ts).</summary>
public class K05ApprovalDiffTests
{
    const string M = "approval";

    [Fact] public void RenderShapeError() => K05.Check(M, "approvalRenderShapeError", a => Approval.RenderShapeError(a[0]));
    [Fact] public void RenderDigest() => K05.Check(M, "approvalRenderDigest", a => Approval.RenderDigest(a[0]));
    [Fact] public void Challenge() => K05.Check(M, "approvalChallengeB64u", a => Approval.Challenge(a[0], a[1]));
    [Fact] public void BindingWords() => K05.Check(M, "bindingWords", a => Approval.BindingWords(a[0]));
    // no def here carries a signed confirmation: the TS render is always unreviewed (confirmed = false)
    [Fact] public void Render() => K05.Check(M, "renderApproval", a => Approval.Render((D)a[0]!, a.Count > 1 ? a[1] : null, false));
    [Fact] public void ValidateDef() => K05.Check(M, "validateDef", a => Actions.ValidateDef(a[0]));
    [Fact] public void Psd2Linking() => K05.Check(M, "psd2Linking", a => Approval.Psd2Linking((D)a[0]!));

    // typed (long, long) port: a non-integer argument cannot be passed (the TS refuses every one of them)
    [Fact]
    public void MinorToDecimal() => K05.Check(M, "minorToDecimal", a => Approval.MinorToDecimal(K05.Long(a[0]), K05.Long(a[1])),
        skip: c => K05.Args(c).All(K05.IsJsonInt) ? null : "not a JSON integer argument");

    // the challenge is bytes in TS ({$bytes}), the b64url string here
    [Fact]
    public void Batch() => K05.Check(M, "approvalBatch", a =>
    {
        var r = Approval.Batch((L)a[0]!);
        r["challenge"] = new D { ["$bytes"] = r["challenge"] };
        return r;
    });

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "approvalRenderShapeError", "approvalRenderDigest", "approvalChallengeB64u", "bindingWords", "renderApproval", "validateDef",
        "psd2Linking", "minorToDecimal", "approvalBatch",
        // not ported to .NET: the WebAuthn SPC expectation and the CIBA authorization_details builders live only in the TS action kit
        "spcExpectation", "cibaApprovalDetails",
    });
}
