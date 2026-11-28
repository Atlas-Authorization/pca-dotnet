using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the business rules (validation, compile, evaluate, explain, lint, diff, review signature) against the TypeScript reference.</summary>
public class RefActionsRulesTests
{
    const string M = "ref-actions-rules";

    [Fact] public void BusinessRulesError() => Base.Check(M, "businessRulesError", a => ActionBusinessRules.BusinessRulesError((D)a[0]!, a[1]));
    [Fact] public void Compile() => Base.Check(M, "compileBusinessRules", a => ActionBusinessRules.CompileBusinessRules((D)a[0]!, a[1]));
    [Fact] public void Explain() => Base.Check(M, "explainBusinessRules", a => ActionBusinessRules.ExplainBusinessRules((D)a[0]!, a[1]));
    [Fact] public void Lint() => Base.Check(M, "lintBusinessRules", a => ActionBusinessRules.LintBusinessRules((D)a[0]!, a[1]));
    [Fact] public void RunExamples() => Base.Check(M, "runRuleExamples", a => ActionBusinessRules.RunRuleExamples((D)a[0]!, a[1]));
    [Fact] public void MoneyOf() => Base.Check(M, "moneyOf", a => ActionBusinessRules.MoneyOf((D)a[0]!).ToJson());
    [Fact] public void Digest() => Base.Check(M, "businessRulesDigest", a => ActionBusinessRules.BusinessRulesDigest((string)a[0]!, (D)a[1]!));
    [Fact] public void Diff() => Base.Check(M, "diffBusinessRules", a => ActionBusinessRules.DiffBusinessRules((D)a[0]!, a[1], a[2]));
    [Fact] public void Evaluate() => Base.Check(M, "evaluateBusinessRules", a => ActionBusinessRules.EvaluateBusinessRules((D)a[0]!, (D)a[1]!));
    // the instant at the end of the representable range (year 275760) is outside DateTimeOffset: documented shortcut
    [Fact] public void ClockAt() => Base.Check(M, "clockAt", a => ActionBusinessRules.ClockAt(a[0], (string)a[1]!), skip: c => (string)c["name"]! == "clockAt/edge" ? "year 275760 is outside DateTimeOffset" : null);
    [Fact] public void FormatMoney() => Base.Check(M, "formatMoney", a => ActionBusinessRules.FormatMoney(Base.Long(a[0]), (string)a[1]!, Base.Long(a[2])));
    [Fact] public void MinorUnits() => Base.Check(M, "minorUnits", a => ActionBusinessRules.MinorUnits(a[0], Base.Long(a[1]), "x"));
    [Fact] public void ReviewMessage() => Base.Check(M, "rulesReviewMessage", a => ActionBusinessRules.RulesReviewMessage((D)a[0]!));
    [Fact] public void SignReview() => Base.Check(M, "signRulesReview", a => ActionBusinessRules.SignRulesReview((D)a[0]!, Base.Bytes(a[1])));
    [Fact] public void KnownTimeZone() => Base.Check(M, "knownTimeZone", a => ActionBusinessRules.KnownTimeZone(a[0]));

    [Fact]
    public void ResolveParamRef() => Base.Check(M, "resolveParamRef", a =>
    {
        var (name, p) = ActionBusinessRules.ResolveParamRef((D)a[0]!, a[1], (string)a[2]!);
        return new D { ["name"] = name, ["p"] = p };
    });

    [Fact] public void ReviewError() => Base.Check(M, "rulesReviewError", a => ActionBusinessRules.RulesReviewError(a[0], (D)a[1]!, a[2], a[3]));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "businessRulesError", "compileBusinessRules", "explainBusinessRules", "lintBusinessRules", "runRuleExamples", "moneyOf", "businessRulesDigest", "diffBusinessRules", "evaluateBusinessRules", "clockAt", "formatMoney", "minorUnits", "rulesReviewMessage", "signRulesReview", "rulesReviewError", "knownTimeZone", "resolveParamRef" }); Assert.Equal(6934, Base.Total(M)); }
}
