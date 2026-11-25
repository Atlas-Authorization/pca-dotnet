using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the intent ontology (verb resolution, IR projection, checker, template instantiation, amount parsing) and the shipped reference data.</summary>
public class RefGoalOntologyTests
{
    const string M = "ref-goal-ontology";
    static D? O(object? o) => o as D;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static D Ont(object? o) => o is string s ? GoalOntologies.Ontology(s)! : (D)o!;
    static int I(object? o) => (int)double.Parse(o is Num n ? n.Raw : S(o), CultureInfo.InvariantCulture);

    [Fact] public void ShippedOntology() => Base.Check(M, "shippedOntology", a => GoalOntologies.Ontology(S(a[0])));
    [Fact] public void ShippedCatalog() => Base.Check(M, "shippedCatalog", a => GoalOntologies.SelCatalog(S(a[0])));
    [Fact] public void OntologyDigest() => Base.Check(M, "ontologyDigest", a => GoalOntology.OntologyDigest(Ont(a[0])));
    [Fact] public void ResolveVerb() => Base.Check(M, "resolveVerb", a => GoalOntology.ResolveVerb(Ont(a[0]), S(a[1])));
    [Fact] public void GoalCcy() => Base.Check(M, "goalCcy", a => GoalOntology.GoalCcy(O(a[0])!));
    [Fact] public void GoalAnchors() => Base.Check(M, "goalAnchors", a => GoalOntology.GoalAnchors(O(a[0])!));
    [Fact]
    public void ToIrOntology() => Base.Check(M, "toIrOntology", a =>
    {
        var opts = O(a[1]);
        return GoalOntology.ToIrOntology(Ont(a[0]), opts?.GetValueOrDefault("ccy") as string, opts?.GetValueOrDefault("rels") as L);
    });
    [Fact] public void OntologyForGoal() => Base.Check(M, "ontologyForGoal", a => GoalOntology.OntologyForGoal(Ont(a[0]), O(a[1])!, a.Count > 2 ? a[2] as L : null));
    [Fact] public void CheckOntology() => Base.Check(M, "checkOntology", a => GoalOntology.CheckOntology(Ont(a[0])));
    [Fact]
    public void InstantiateTemplate() => Base.Check(M, "instantiateTemplate", a =>
    {
        var opts = O(a[3])!;
        List<string>? src = opts.GetValueOrDefault("sources") is L sl ? sl.Select(x => (string)x!).ToList() : null;
        return GoalOntology.InstantiateTemplate(Ont(a[0]), S(a[1]), O(a[2])!, S(opts["principal"]), S(opts["nl"]), src);
    });
    [Fact] public void SlotLits() => Base.Check(M, "slotLits", a => GoalOntology.SlotLits(Ont(a[0]), O(a[1])!, a[2]));
    [Fact] public void ParseHumanAmount() => Base.Check(M, "parseHumanAmount", a => GoalOntology.ParseHumanAmount(S(a[0]), I(a[1]), a[2] as string));
    [Fact] public void ParseMoney() => Base.Check(M, "parseMoney", a => GoalOntology.ParseMoney(S(a[0]), I(a[1]), a[2] as string));

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "shippedOntology", "shippedCatalog", "ontologyDigest", "resolveVerb", "goalCcy", "goalAnchors", "toIrOntology", "ontologyForGoal",
        "checkOntology", "instantiateTemplate", "slotLits", "parseHumanAmount", "parseMoney",
    }); Assert.Equal(2579, Base.Total(M)); }
}
