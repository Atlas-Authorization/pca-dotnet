using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the deterministic grant / question / action rendering, the back-translation diff and the boundary witnesses
/// against the TypeScript reference (test-data/ref-intent-render.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentRenderTests
{
    const string M = "ref-intent-render";

    static int[] Idx(object? o) => ((L)o!).Select(x => (int)Dbl(x)).ToArray();
    static L Diffs(IEnumerable<IntentRender.ClaimDiff> ds) => ds.Select(d => (object?)d.ToJson()).ToList();

    [Fact] public void LabelOfFn() => Base.Check(M, "labelOf", a => IntentRender.LabelOf((string)a[0]!));
    [Fact] public void RenderConditionFn() => Base.Check(M, "renderCondition", a => IntentRender.RenderCondition(a[0]));
    [Fact] public void RenderCaveatFn() => Base.Check(M, "renderCaveat", a => IntentRender.RenderCaveat(a[0]));
    [Fact] public void RenderGrantFn() => Base.Check(M, "renderGrant", a => IntentRender.RenderGrant(a[0]));
    [Fact] public void RenderQuestionFn() => Base.Check(M, "renderQuestion", a => IntentRender.RenderQuestion(VerbSpaceFromJson(a[0]), Idx(a[1])));

    [Fact]
    public void RenderActionFn() => Base.Check(M, "renderAction", a =>
        IntentRender.RenderAction(VerbSpaceFromJson(a[0]), ((D)a[1]!).ToDictionary(e => e.Key, e => Value(e.Value))));

    [Fact] public void ClaimsOfFn() => Base.Check(M, "claimsOf", a => IntentRender.ClaimsOf(a[0], OmegaFromJson(a[1])).Select(c => (object?)c.ToJson()).ToList());
    [Fact] public void BackTranslationDiffFn() => Base.Check(M, "backTranslationDiff", a => Diffs(IntentRender.BackTranslationDiff(a[0], a[1], OmegaFromJson(a[2]))));

    [Fact]
    public void ClaimDiffFn() => Base.Check(M, "claimDiff", a => Diffs(a.Count > 3
        ? IntentRender.ClaimDiffOf(a[0], a[1], OmegaFromJson(a[2]), (string)((L)a[3]!)[0]!, (string)((L)a[3]!)[1]!)
        : IntentRender.ClaimDiffOf(a[0], a[1], OmegaFromJson(a[2]))));

    [Fact] public void BoundaryWitnessesFn() => Base.Check(M, "boundaryWitnesses", a => IntentWitnesses.BoundaryWitnesses(a[0], OmegaFromJson(a[1])).Select(w => (object?)w.ToJson()).ToList());

    [Fact]
    public void CheckWitnessesFn() => Base.Check(M, "checkWitnesses", a =>
    {
        var mode = (string)a[1]!;
        var r = IntentWitnesses.CheckWitnesses(((L)a[0]!).Select(IntentWitnesses.Witness.FromJson).ToList(), w => mode switch
        {
            "agree" => w.GrantAllows,
            "flip" => !w.GrantAllows,
            "flip-boundary" => w.Kind == "boundary" ? !w.GrantAllows : w.GrantAllows,
            _ => w.Side == "inside" && w.Kind != "unconstrained",
        });
        return new D { ["questions"] = N(r.Questions), ["mismatches"] = r.Mismatches.Select(w => (object?)w.ToJson()).ToList() };
    });

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "labelOf", "renderCondition", "renderCaveat", "renderGrant", "renderQuestion", "renderAction", "claimsOf", "backTranslationDiff", "claimDiff",
        "boundaryWitnesses", "checkWitnesses",
    }); Assert.Equal(269, Base.Total(M)); }
}
