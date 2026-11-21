using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the approval-render wrappers, facade specs and provenance facts against the TypeScript reference.</summary>
public class RefActionsRenderTests
{
    const string M = "ref-actions-render-facade";

    static Func<D, bool>? Conf(L a, int i) => a.Count > i && a[i] is bool b ? (_ => b) : null;
    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);

    [Fact] public void RenderApproval() => Base.Check(M, "renderApproval", a => ActionApprovals.RenderApproval((D)a[0]!, a[1], Conf(a, 2)));
    [Fact] public void RenderDigestForAction() => Base.Check(M, "renderDigestForAction", a => ActionApprovals.RenderDigestForAction((D)a[0]!, a[1], (D)a[2]!, Conf(a, 3)));
    [Fact] public void ApproverRenderCheck() => Base.Check(M, "approverRenderCheck", a => ActionApprovals.ApproverRenderCheck((D)a[0]!, a[1], a[2], Conf(a, 3)));
    [Fact] public void SingleTapAllowed() => Base.Check(M, "singleTapAllowed", a => ActionApprovals.SingleTapAllowed(a[0]));
    [Fact] public void RenderersFromDefs() => Base.Check(M, "renderersFromDefs", a => ActionApprovals.RenderersFromDefs(Defs(a[0]), Conf(a, 3))((string)a[1]!, "", a[2] as D));

    [Fact]
    public void DefLimitsHaveTheReferenceValues()
    {
        Assert.Equal(new[] { 128, 120, 1024, 64, 16, 32, 16, 16, 8, 512, 1_000_000 }, new[]
        {
            Actions.MaxVerbBytes, Actions.MaxTitleBytes, Actions.MaxDescriptionBytes, Actions.MaxDefParams, Actions.MaxDefAliases, Actions.MaxDefTraits, Actions.MaxDefContext,
            Actions.MaxDefSideEffects, Actions.MaxTraitImpliesDepth, Actions.MaxRegistryTraits, Actions.PpmMax,
        });
    }
    [Fact] public void SpecOfDef() => Base.Check(M, "specOfDef", a => ActionFacade.SpecOfDef((D)a[0]!, null, Conf(a, 2), a[1] is true));
    [Fact] public void FacadeSpecs() => Base.Check(M, "facadeSpecs", a => ActionFacade.FacadeSpecs(Defs(a[0]), null, Conf(a, 2), a[1] is true));
    [Fact] public void ProvenanceInfoOf() => Base.Check(M, "provenanceInfoOf", a => ActionProvenance.ProvenanceInfoOf((D)a[0]!, null, Conf(a, 1)));
    [Fact]
    public void ProvenanceActions() => Base.Check(M, "provenanceActions", a =>
    {
        var f = ActionProvenance.ProvenanceActions(Defs(a[0]), null, Conf(a, 1));
        return ((L)a[2]!).Select(v => (object?)f(new D { ["verb"] = v })).ToList();
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "renderApproval", "renderDigestForAction", "approverRenderCheck", "singleTapAllowed", "renderersFromDefs", "specOfDef", "facadeSpecs", "provenanceInfoOf", "provenanceActions" }); Assert.Equal(864, Base.Total(M)); }
}
