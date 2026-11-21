using AtlasPca.Evidence;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the dispute evidence bundle (shape, normal form, commitments-only form, digest, reference, anchor leaf,
/// grant cap reader, trust-input validators) against the TypeScript reference. verifyEvidenceBundle and the CLI are not part of the oracle.</summary>
public class RefEvidenceTests
{
    const string M = "ref-evidence";

    [Fact] public void BundleShapeError() => Base.Check(M, "bundleShapeError", a => EvidenceBundle.BundleShapeError(a[0]));
    [Fact] public void NormalizeBundle() => Base.Check(M, "normalizeBundle", a => EvidenceBundle.NormalizeBundle(a[0]));
    [Fact] public void BuildEvidenceBundle() => Base.Check(M, "buildEvidenceBundle", a => EvidenceBundle.BuildEvidenceBundle(a[0]));
    [Fact] public void CommitmentForm() => Base.Check(M, "commitmentForm", a => EvidenceBundle.CommitmentForm(a[0]));
    [Fact] public void EvidenceDigest() => Base.Check(M, "evidenceDigest", a => EvidenceBundle.EvidenceDigest(a[0]));
    [Fact] public void EvidenceRef() => Base.Check(M, "evidenceRef", a => EvidenceScitt.EvidenceRef(a[0]));
    [Fact] public void EvidenceAnchorCommit() => Base.Check(M, "evidenceAnchorCommit", a => EvidenceScitt.EvidenceAnchorCommit((string)a[0]!));
    [Fact] public void AnchorCommit() => Base.Check(M, "anchorCommit", a => EvidenceVerify.AnchorCommit((string)a[0]!, (string)a[1]!));
    [Fact] public void CapOf() => Base.Check(M, "capOf", a => EvidenceVerify.CapOf(a[0], (string)a[1]!, (string)a[2]!));
    [Fact] public void PrincipalsTrustError() => Base.Check(M, "principalsTrustError", a => a.Count == 0 ? EvidenceVerify.PrincipalsTrustError() : EvidenceVerify.PrincipalsTrustError(a[0]));
    [Fact] public void AccTrustError() => Base.Check(M, "accTrustError", a => a.Count == 0 ? EvidenceVerify.AccTrustError() : EvidenceVerify.AccTrustError(a[0]));

    [Fact]
    public void Consts() => Base.Check(M, "consts", _ => new D
    {
        ["EVIDENCE_DOMAIN"] = EvidenceBundle.EvidenceDomain,
        ["EVIDENCE_REPORT_DOMAIN"] = EvidenceVerify.EvidenceReportDomain,
        ["EVIDENCE_CONTENT_TYPE"] = EvidenceScitt.EvidenceContentType,
    });

    [Fact]
    public void EveryFnHasATest() { Base.Covers(M, new[]
    {
        "bundleShapeError", "normalizeBundle", "buildEvidenceBundle", "commitmentForm", "evidenceDigest", "evidenceRef", "evidenceAnchorCommit",
        "anchorCommit", "capOf", "principalsTrustError", "accTrustError", "consts",
    }); Assert.Equal(1772, Base.Total(M)); }
}
