using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action derivations (schema, operation, risk, predicates, ontology, card, explanation) against the TypeScript reference.</summary>
public class RefActionsDeriveTests
{
    const string M = "ref-actions-derive";

    static Func<D, bool>? Conf(L a, int i) => a.Count > i && a[i] is bool b ? (_ => b) : null;
    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);
    static D Eff(L a) => ActionEffective.EffectiveWith((D)a[0]!, Actions.CoreRegistry, Conf(a, 1))!;

    [Fact] public void FlattenParams() => Base.Check(M, "flattenParams", a => ActionDerive.FlattenParams((D)a[0]!));
    [Fact] public void ParamByRole() => Base.Check(M, "paramByRole", a => ActionDerive.ParamByRole((D)a[0]!, (string)a[1]!));
    [Fact] public void EffectClass() => Base.Check(M, "effectClass", a => ActionDerive.EffectClass((D)a[0]!));
    [Fact] public void ResourceMatcher() => Base.Check(M, "resourceMatcher", a => ActionDerive.ResourceMatcher((D)a[0]!));
    [Fact] public void ToSchemaVerb() => Base.Check(M, "toSchemaVerb", a => ActionDerive.ToSchemaVerb((D)a[0]!, Actions.CoreRegistry, Conf(a, 1)));
    [Fact] public void CardOf() => Base.Check(M, "cardOf", a => ActionDerive.CardOf((D)a[0]!, Eff(a), Actions.CoreRegistry));
    [Fact] public void EscalationOf() => Base.Check(M, "escalationOf", a => ActionDerive.EscalationOf(Eff(a)));
    [Fact] public void McpAnnotationsOf() => Base.Check(M, "mcpAnnotationsOf", a => ActionDerive.McpAnnotationsOf((D)a[0]!, Eff(a)));
    [Fact] public void ExplainDef() => Base.Check(M, "explainDef", a => ActionExplain.ExplainDef((D)a[0]!, Actions.CoreRegistry, Conf(a, 1)));
    [Fact] public void OperationOf() => Base.Check(M, "operationOf", a => ActionDerive.OperationOf((D)a[0]!, new D { ["params"] = a[1] }));
    [Fact] public void RiskOf() => Base.Check(M, "riskOf", a => ActionDerive.RiskOf((D)a[0]!, Eff(a), a.Count > 2 ? a[2] as D : null, a.Count > 3 ? a[3] as D : null));
    [Fact] public void PredicatesOf() => Base.Check(M, "predicatesOf", a => ActionDerive.PredicatesOf((D)a[0]!, a.Count > 1 ? a[1] as D : null));
    [Fact] public void ReversibilityScore() => Base.Check(M, "REVERSIBILITY_SCORE", a => ActionDerive.ReversibilityScore());
    [Fact]
    public void ToSchemaDoc() => Base.Check(M, "toSchemaDoc", a =>
        ActionDerive.ToSchemaDoc(Defs(a[0]), a[3] is L extra ? Actions.ExtendRegistry(Actions.CoreRegistry, extra) : Actions.CoreRegistry, (D)a[1]!, Conf(a, 2)));
    [Fact] public void ToOntology() => Base.Check(M, "toOntology", a => ActionDerive.ToOntology(Defs(a[0]), Actions.CoreRegistry, Conf(a, 1)));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "flattenParams", "paramByRole", "effectClass", "resourceMatcher", "toSchemaVerb", "cardOf", "escalationOf", "mcpAnnotationsOf", "explainDef", "operationOf", "riskOf", "predicatesOf", "REVERSIBILITY_SCORE", "toSchemaDoc", "toOntology" }); Assert.Equal(1829, Base.Total(M)); }
}
