using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action-kit linter, SARIF/text output and the structural undo helpers against the TypeScript reference.</summary>
public class RefActionsLintTests
{
    const string M = "ref-actions-lint";

    static D Opts(object? o)
    {
        var d = o as D ?? new D();
        var c = new D(d); c.Remove("att");
        return c;
    }

    [Fact] public void LintDefs() => Base.Check(M, "lintDefs", a =>
    {
        var o = a.Count > 1 ? a[1] as D : null;
        Func<D, bool>? att = o != null && o.TryGetValue("att", out var v) && v is bool b ? (_ => b) : null;
        return ActionLint.LintDefs((L)a[0]!, Opts(o), att);
    });
    [Fact] public void LintFails() => Base.Check(M, "lintFails", a => ActionLint.LintFails((L)a[0]!, a.Count > 1 && a[1] is true));
    [Fact] public void LintText() => Base.Check(M, "lintText", a => ActionLint.LintText((L)a[0]!));
    [Fact] public void ToSarif() => Base.Check(M, "toSarif", a => ActionLint.ToSarif((L)a[0]!, a.Count > 1 ? a[1] as D : null));
    [Fact] public void Digest() => Base.Check(M, "lintRulesDigest", a => ActionLint.LintRulesDigest());
    [Fact] public void Rules() => Base.Check(M, "LINT_RULES", a => ActionLintRules.LINT_RULES.Select(r => new L { r.Id, r.Severity, r.Title }).ToList());
    [Fact] public void MayBeReversible() => Base.Check(M, "mayBeReversible", a => ActionUndo.MayBeReversible((D)a[0]!));
    [Fact] public void ReversibilityFor() => Base.Check(M, "reversibilityFor", a => ActionUndo.ReversibilityFor((D)a[0]!, (D)a[1]!));
    [Fact] public void CompensationShape() => Base.Check(M, "compensationShape", a => ActionUndo.CompensationShape((D)a[0]!, (D)a[1]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "lintDefs", "lintFails", "lintText", "toSarif", "lintRulesDigest", "LINT_RULES", "mayBeReversible", "reversibilityFor", "compensationShape" }); Assert.Equal(2231, Base.Total(M)); }
}
