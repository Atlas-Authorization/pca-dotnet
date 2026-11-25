using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of multi-principal rules, common refinement, layer ceilings, quorum approvals and grant measurement against the TypeScript
/// reference (test-data/ref-intent-layers.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentLayersTests
{
    const string M = "ref-intent-layers";

    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    [Fact] public void NormalizeRuleFn() => Base.Check(M, "normalizeRule", a => IntentMulti.NormalizeRule((D)a[0]!, Strs(a[1])).ToJson());
    [Fact] public void EffectiveVetoersFn() => Base.Check(M, "effectiveVetoers", a => IntentMulti.EffectiveVetoers((D)a[0]!, Strs(a[1])));
    [Fact] public void RuleAdmitsFn() => Base.Check(M, "ruleAdmits", a => IntentMulti.RuleAdmits(IntentMulti.NormalRule.FromJson(a[0]), ((L)a[1]!).Select(x => (bool)x!).ToArray()));
    [Fact] public void JointAcceptanceFn() => Base.Check(M, "jointAcceptance", a => N(IntentMulti.JointAcceptance(IntentMulti.NormalRule.FromJson(a[0]), ((L)a[1]!).Select(Dbl).ToArray())));

    [Fact]
    public void CommonRefinementFn() => Base.Check(M, "commonRefinement", a => IntentOmega.OmegaToJson(IntentMulti.CommonRefinement(((L)a[0]!).Select(OmegaFromJson).ToList())));

    [Fact]
    public void CeilingOfFn() => Base.Check(M, "ceilingOf", a => IntentLayers.CeilingOf(IntentLayers.MakeCeilingAdmitters((D)a[0]!), VerbSpaceFromJson(a[1]), OutcomeFromJson(a[2])));

    [Fact]
    public void AssertAskableFn() => Base.Check(M, "assertAskable", a =>
    {
        IntentLayers.AssertAskable((D)a[0]!, (D)a[1]!);
        return null;
    });

    [Fact]
    public void LayerCellsFn() => Base.Check(M, "layerCells", a => IntentLayers.LayerCells(OmegaFromJson(a[0]), IntentPolicyKit.MakeAdmitter(a[1])));

    [Fact]
    public void OwnerRiskFn() => Base.Check(M, "ownerRisk", a => N(IntentLayers.OwnerRisk(OmegaFromJson(a[0]), ((L)a[1]!).Select(x => (D)x!).ToList(), IntentMetrics.AcceptabilityOf(a[2]))));

    [Fact] public void CellKeyOfFn() => Base.Check(M, "cellKeyOf", a => IntentLayers.CellKeyOf(OmegaFromJson(a[0]), (D)a[1]!));
    [Fact] public void SignLayerApprovalFn() => Base.Check(M, "signLayerApproval", a => IntentLayers.SignLayerApproval((D)a[0]!, Pca.B64uDecode(a[1])!));
    [Fact] public void VerifyQuorumApprovalsFn() => Base.Check(M, "verifyQuorumApprovals", a => IntentLayers.VerifyQuorumApprovals(a[0], a[1], (D)a[2]!, a[3]));

    [Fact]
    public void MeasureGrantExactFn() => Base.Check(M, "measureGrantExact", a => IntentMetrics.MeasureGrantExact(OmegaFromJson(a[0]), a[1], IntentMetrics.AcceptabilityOf(a[2])).ToJson());

    [Fact]
    public void MeasureGrantFn() => Base.Check(M, "measureGrant", a =>
    {
        var opts = (D)a[3]!;
        double samples = opts.ContainsKey("samples") ? Dbl(opts["samples"]) : 20000;
        double seed = opts.ContainsKey("seed") ? Dbl(opts["seed"]) : 1;
        double? hMax = opts.ContainsKey("hMax") ? Dbl(opts["hMax"]) : null;
        return IntentMetrics.MeasureGrant(OmegaFromJson(a[0]), a[1], IntentMetrics.AcceptabilityOf(a[2]), samples, seed, null, hMax).ToJson();
    });

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "normalizeRule", "effectiveVetoers", "ruleAdmits", "jointAcceptance", "commonRefinement", "ceilingOf", "assertAskable", "layerCells", "ownerRisk", "cellKeyOf",
        "signLayerApproval", "verifyQuorumApprovals", "measureGrantExact", "measureGrant",
    }); Assert.Equal(419, Base.Total(M)); }
}
