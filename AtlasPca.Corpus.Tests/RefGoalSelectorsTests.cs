using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the trait selectors and role-addressed parameters (catalog, class verbs, role resolution, expansion, typing, card, carrier form, catalog tape).</summary>
public class RefGoalSelectorsTests
{
    const string M = "ref-goal-selectors";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static D Ont(object? o) => o is string s ? GoalOntology.ToIrOntology(GoalOntologies.Ontology(s)!, null, null) : (D)o!;
    static D Cat(object? o) => o is string s ? GoalOntologies.SelCatalog(s)! : (D)o!;

    [Fact] public void SelCatalogDigest() => Base.Check(M, "selCatalogDigest", a => GoalSelectors.SelCatalogDigest(Cat(a[0])));
    [Fact] public void SelGoalDigest() => Base.Check(M, "selGoalDigest", a => GoalSelectors.SelGoalDigest(O(a[0])));
    [Fact] public void EncodeSelCatalog() => Base.Check(M, "encodeSelCatalog", a => GoalSelectors.EncodeSelCatalog(Cat(a[0])));
    [Fact] public void CatalogOfDomain() => Base.Check(M, "catalogOfDomain", a => GoalSelectors.SelCatalogOfDomain(S(a[0])));
    [Fact] public void SelCatalogOfDomain() => Base.Check(M, "selCatalogOfDomain", a => GoalSelectors.SelCatalogOfDomain(S(a[0])), min: 5);
    [Fact] public void ClassVerbs() => Base.Check(M, "classVerbs", a => GoalSelectors.ClassVerbs(Cat(a[0]), A(a[1]), A(a[2])));
    [Fact] public void AllowClassVerbs() => Base.Check(M, "allowClassVerbs", a => GoalSelectors.AllowClassVerbs(Cat(a[0]), A(a[1]), A(a[2])));
    [Fact] public void FloatClassVerbs() => Base.Check(M, "floatClassVerbs", a => GoalSelectors.FloatClassVerbs(Cat(a[0]), A(a[1]), A(a[2])));
    [Fact] public void ResolveRole() => Base.Check(M, "resolveRole", a => GoalSelectors.ResolveRole(Ont(a[0]), Cat(a[1]), S(a[2]), S(a[3])));
    [Fact] public void SelReasons() => Base.Check(M, "selReasons", a => GoalSelectors.SelReasons(O(a[0]), Ont(a[1]), Cat(a[2])));
    [Fact] public void ExpandSelGoal() => Base.Check(M, "expandSelGoal", a => GoalSelectors.ExpandSelGoal(O(a[0]), Ont(a[1]), Cat(a[2])));
    [Fact] public void SelCarrier() => Base.Check(M, "selCarrier", a => GoalSelectors.SelCarrier(O(a[0])));
    [Fact] public void RenderSelCard() => Base.Check(M, "renderSelCard", a => GoalSelectors.RenderSelCard(O(a[0]), Ont(a[1]), Cat(a[2]), null));
    [Fact] public void WithRoleParams() => Base.Check(M, "withRoleParams", a => GoalSelectors.WithRoleParams(O(a[0]), Cat(a[1])));
    [Fact] public void TraitClosure() => Base.Check(M, "traitClosure", a => GoalSelectors.TraitClosure(A(a[0]), null));
    [Fact]
    public void CompileSelGoal() => Base.Check(M, "compileSelGoal", a =>
        GoalSelectors.CompileSelGoal(O(a[0]), Ont(a[1]), Cat(a[2]), (g, o) => throw new InvalidOperationException("compiler reached")));
    [Fact] public void CatalogOfDefs() => Base.Check(M, "catalogOfDefs", a => GoalSelectors.SelCatalogOfDefs(A(a[0]), null, null));

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "selCatalogDigest", "selGoalDigest", "encodeSelCatalog", "catalogOfDomain", "selCatalogOfDomain", "classVerbs", "allowClassVerbs", "floatClassVerbs", "resolveRole",
        "selReasons", "expandSelGoal", "selCarrier", "renderSelCard", "withRoleParams", "traitClosure", "compileSelGoal", "catalogOfDefs",
    }); Assert.Equal(1397, Base.Total(M)); }
}
