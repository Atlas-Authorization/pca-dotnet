using System.Text;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The public constants pinned against the class-scoped constants the verifier already uses (one source of truth) and the reference values.</summary>
public class PcaConstantsTests
{
    [Fact]
    public void ConstantsEqualTheVerifierOnes()
    {
        Assert.Equal(Approval.RenderDomain, PcaConstants.ApprovalRenderDomain);
        Assert.Equal(Approval.ChallengeDomain, PcaConstants.ApprovalChallengeDomain);
        Assert.Equal(ArgProvenance.ReceiptDomain, PcaConstants.ProvReceiptDomain);
        Assert.Equal(ArgProvenance.ReceiptRefDomain, PcaConstants.ProvReceiptRefDomain);
        Assert.Equal(ArgProvenance.ActionDomain, PcaConstants.ProvActionDomain);
        Assert.Equal(ArgProvenance.MaxReceipts, PcaConstants.MaxProvReceipts);
        Assert.Equal(ArgProvenance.MaxContentBytes, PcaConstants.MaxProvContentBytes);
        Assert.Equal(ArgProvenance.MaxLeaves, PcaConstants.MaxProvLeaves);
        Assert.Equal(Escalation.PolicyDomain, PcaConstants.EscalationPolicyDomain);
        Assert.Equal(Escalation.ActionDomain, PcaConstants.EscalationActionDomain);
        Assert.Equal(Escalation.HistoryDomain, PcaConstants.EscalationHistoryDomain);
        Assert.Equal(Escalation.MaxLifetimeMs, PcaConstants.EscalationMaxLifetimeMs);
        Assert.Equal(Forbid.CertKind, PcaConstants.ForbidCertKind);
        Assert.Equal(Forbid.CertVersion, PcaConstants.ForbidCertVersion);
        Assert.Equal(FreshAt.RefDomain, PcaConstants.FreshAtRefDomain);
        Assert.Equal(ReadSide.GrantDomain, PcaConstants.ReadGrantDomain);
        Assert.Equal(ReadSide.ReceiptDomain, PcaConstants.ReadReceiptDomain);
        Assert.Equal(Workflow.ReceiptDomain, PcaConstants.WfReceiptDomain);
        Assert.Equal(PcaGrant.Domain, PcaConstants.PcaGrantDomain);
        Assert.Equal(RevocationFreshness.EpochRefreshMs, PcaConstants.RevocationEpochRefreshMs);
        Assert.Equal(RevocationFreshness.EpochValidityMs, PcaConstants.RevocationEpochValidityMs);
        Assert.Equal(RevocationFreshness.IrreversibleMaxAgeMs, PcaConstants.RevocationIrreversibleMaxAgeMs);
        Assert.Equal(PolicyClasses.Classes.Length, PcaConstants.MaxPolicyClasses);
        Assert.Equal("reversible", PcaConstants.DefaultReversibilityClass);
    }

    [Fact]
    public void ReferenceValues()
    {
        Assert.Equal(1_200_000, PcaConstants.PcactnDefaultTtlMs);
        Assert.Equal(3_600_000 + 2 * 60_000, PcaConstants.ReplayMinRetentionMs);
        Assert.Equal(14, PcaConstants.PcactnRequiredFields.Count);
        Assert.Equal(12, PcaConstants.PcactnOptionalFields.Count);
        Assert.Equal(1_048_576, PcaConstants.MaxJsonBytes);
        Assert.Equal(Pca.ParamsDigest(new JD()), PcaConstants.EmptyParamsDigest);
    }

    [Fact]
    public void HashSuites()
    {
        Assert.True(Equals(HashSuiteOf("sha384"), true));
        Assert.False(AtlasPca.HashSuites.IsHashSuite("md5"));
        Assert.Equal(32, AtlasPca.HashSuites.HashWithSuite(new byte[] { 1 }).Length);
        Assert.Equal(48, AtlasPca.HashSuites.HashWithSuite(new byte[] { 1 }, "sha384").Length);
        Assert.Equal(Pca.HashCanonical(new JD { ["a"] = "b" }), AtlasPca.HashSuites.HashCanonical(new JD { ["a"] = "b" }));
        Assert.Throws<ArgumentOutOfRangeException>(() => AtlasPca.HashSuites.HashWithSuite(new byte[0], "sha1"));
        Assert.Equal(43, AtlasPca.HashSuites.B64uLen(32));
        Assert.Equal(64, AtlasPca.HashSuites.B64uLen(48));
        Assert.True(AtlasPca.HashSuites.IsCanonicalB64u(Pca.B64u(new byte[32]), 32));
        Assert.False(AtlasPca.HashSuites.IsCanonicalB64u("AB==", null));
        Assert.Throws<ArgumentException>(() => AtlasPca.HashSuites.DecodeSig("a b"));
    }

    static bool HashSuiteOf(string s) => AtlasPca.HashSuites.IsHashSuite(s);

    [Fact]
    public void Helpers()
    {
        Assert.Equal("allow", PcaHelpers.MeetAll(new string?[0]));
        Assert.Equal("escalate", PcaHelpers.MeetAll(new string?[] { "allow", "escalate" }));
        Assert.Equal("deny", PcaHelpers.MeetAll(new string?[] { "allow", "deny", "escalate" }));
        Assert.True(PcaHelpers.IsGroupCondition(new JD { ["all_of"] = new JL() }));
        Assert.True(PcaHelpers.IsLeafCondition(new JD { ["field"] = "x" }));
        Assert.False(PcaHelpers.IsLeafCondition(new JD { ["field"] = "x", ["not"] = new JD() }));
        Assert.True(PcaHelpers.IsBudgetAllocCaveat(new JD { ["type"] = "budget_alloc", ["limit"] = new Num("3") }));
        Assert.False(PcaHelpers.IsBudgetAllocCaveat(new JD { ["type"] = "budget_alloc", ["limit"] = new Num("-1") }));
        Assert.False(PcaHelpers.IsBudgetAllocCaveat(new JD { ["type"] = "budget_alloc", ["limit"] = "3" }));
        var commit = Issue.GoalCommit("g", "s");
        Assert.True(PcaHelpers.VerifyGoalCommit(commit, "g", "s"));
        Assert.False(PcaHelpers.VerifyGoalCommit(commit, "g2", "s"));
        Assert.Equal("ab", PcaHelpers.ClipUnits("abc", 2));
        Assert.Equal("a", PcaHelpers.ClipUnits("a\U0001F600", 2)); // never splits a surrogate pair
        var leaf = PcaHelpers.PlanNodeLeaf(new JD { ["id"] = "n1", ["verb"] = "v", ["resource"] = "r" });
        Assert.Equal("reversible", leaf["reversibility_class"]);
        Assert.Equal("n1", leaf["node_id"]);
        Assert.Equal("bad_shape", PcaHelpers.ValidatePcaNeed("x"));
    }
}
