using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the goal core (token-tape codec, digests, normalize, fmt, card, reference semantics, binding, signing).</summary>
public class RefGoalTests
{
    const string M = "ref-goal";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static byte[] Seed(object? o) => Pca.B64uDecode(o) ?? throw new InvalidDataException("seed");

    [Fact] public void EncodeGoal() => Base.Check(M, "encodeGoal", a => GoalCodec.EncodeGoal(O(a[0])));
    [Fact] public void DecodeGoal() => Base.Check(M, "decodeGoal", a => GoalCodec.DecodeGoal(A(a[0])));
    [Fact] public void EncodeOntology() => Base.Check(M, "encodeOntology", a => GoalCodec.EncodeOntology(O(a[0])));
    [Fact] public void EncodeAct() => Base.Check(M, "encodeAct", a => GoalCodec.EncodeAct(O(a[0])));
    [Fact] public void EncodeHist() => Base.Check(M, "encodeHist", a => GoalCodec.EncodeHist(O(a[0])));
    [Fact] public void DecodePolicy() => Base.Check(M, "decodePolicy", a => GoalCodec.DecodePolicy(A(a[0])));
    [Fact] public void GoalDigest() => Base.Check(M, "goalDigest", a => GoalDigests.GoalDigest(a[0]));
    [Fact] public void NlDigest() => Base.Check(M, "nlDigest", a => GoalDigests.NlDigest(S(a[0])));
    [Fact] public void ModelSetDigest() => Base.Check(M, "modelSetDigest", a => GoalDigests.ModelSetDigest(A(a[0]).Select(x => (string)x!).ToList()));
    [Fact] public void ApprovalDigest() => Base.Check(M, "approvalDigest", a => GoalDigests.ApprovalDigest(O(a[0])));
    [Fact] public void CanonicalizeGoal() => Base.Check(M, "canonicalizeGoal", a => GoalNormalize.CanonicalizeGoal(O(a[0])));
    [Fact] public void Stable() => Base.Check(M, "stable", a => GoalNormalize.Stable(a[0]));
    [Fact] public void FmtMoney() => Base.Check(M, "fmtMoney", a => GoalFmt.FmtMoney(S(a[0]), a[1]));
    [Fact] public void FmtQuantity() => Base.Check(M, "fmtQuantity", a => GoalFmt.FmtQuantity(O(a[0])));
    [Fact] public void FmtValue() => Base.Check(M, "fmtValue", a => GoalFmt.FmtValue(O(a[0])));
    [Fact] public void FmtAct() => Base.Check(M, "fmtAct", a => GoalFmt.FmtAct(O(a[0])));
    [Fact] public void RenderCard() => Base.Check(M, "renderCard", a => GoalCard.RenderCard(O(a[0])));
    [Fact] public void RenderCond() => Base.Check(M, "renderCond", a => GoalCard.Cond(O(a[0])));
    [Fact] public void RefExplain() => Base.Check(M, "refExplain", a => GoalRefsem.RefExplain(O(a[0]), O(a[1]), O(a[2]), O(a[3])));
    [Fact] public void RefDecide() => Base.Check(M, "refDecide", a => GoalRefsem.RefDecide(O(a[0]), O(a[1]), O(a[2]), O(a[3])));
    [Fact] public void CanonicalPolicy() => Base.Check(M, "canonicalPolicy", a => GoalCompiler.CanonicalPolicy(O(a[0])));
    [Fact] public void PolicyDigest() => Base.Check(M, "policyDigest", a => GoalCompiler.PolicyDigest(O(a[0])));
    [Fact] public void ActionDigest() => Base.Check(M, "actionDigest", a => GoalBinding.ActionDigest(O(a[0])));
    [Fact] public void BindDecision() => Base.Check(M, "bindDecision", a => GoalBinding.BindDecision(O(a[0]), S(a[1])));
    [Fact] public void GuardExecute() => Base.Check(M, "guardExecute", a => GoalBinding.GuardExecute(O(a[0]), O(a[1])));
    [Fact] public void ClaimGate() => Base.Check(M, "claimGate", a => GoalBinding.ClaimGate(S(a[0]), Dbl(a[1]), a[2] == null ? null : Dbl(a[2])));
    static double Dbl(object? n) => double.Parse(((Num)n!).Raw, System.Globalization.CultureInfo.InvariantCulture);
    [Fact] public void GoalCommit() => Base.Check(M, "goalCommit", a => GoalBinding.GoalCommit(S(a[0]), S(a[1]), S(a[2])));
    [Fact] public void OpenCommit() => Base.Check(M, "openCommit", a => GoalBinding.OpenCommit(S(a[0]), S(a[1]), S(a[2]), S(a[3])));
    [Fact] public void SignPayloadSeed() => Base.Check(M, "signPayloadSeed", a => GoalSign.SignPayload(S(a[0]), a[1], Seed(a[2])));
    [Fact] public void SignGoalArtifactSeed() => Base.Check(M, "signGoalArtifactSeed", a => GoalSign.SignGoalArtifact(S(a[0]), O(a[1]), Seed(a[2])));
    [Fact] public void SignerId() => Base.Check(M, "signerId", a => GoalSign.SignerId(Seed(a[0])));
    [Fact] public void GoalDomain() => Base.Check(M, "goalDomain", a => GoalSign.GoalDomain(S(a[0])));
    [Fact] public void VerifyPayload() => Base.Check(M, "verifyPayload", a => GoalSign.VerifyPayload(a[0] as D, S(a[1]), A(a[2])));
    [Fact] public void VerifyGoalArtifact() => Base.Check(M, "verifyGoalArtifact", a => GoalSign.VerifyGoalArtifact(S(a[0]), a[1], S(a[2]), A(a[3])));

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "encodeGoal", "decodeGoal", "encodeOntology", "encodeAct", "encodeHist", "decodePolicy", "goalDigest", "nlDigest", "modelSetDigest", "approvalDigest",
        "canonicalizeGoal", "stable", "fmtMoney", "fmtQuantity", "fmtValue", "fmtAct", "renderCard", "renderCond", "refExplain", "refDecide", "canonicalPolicy",
        "policyDigest", "actionDigest", "bindDecision", "guardExecute", "claimGate", "goalCommit", "openCommit", "signPayloadSeed", "signGoalArtifactSeed",
        "signerId", "goalDomain", "verifyPayload", "verifyGoalArtifact",
    }); Assert.Equal(2213, Base.Total(M)); }
}
