using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the trait selectors and the signed confirmation against the TypeScript reference.</summary>
public class RefActionsSelConfTests
{
    const string M = "ref-actions-sel-conf";

    static HashSet<string> Cl(object? o) => new(((L)o!).Select(x => (string)x!));

    [Fact] public void SelectorHasNot() => Base.Check(M, "selectorHasNot", a => ActionSelectors.SelectorHasNot((D)a[0]!));
    [Fact] public void AllowSelectorError() => Base.Check(M, "allowSelectorError", a => ActionSelectors.AllowSelectorError((D)a[0]!, a[1] is true));
    [Fact] public void SelectorMatches() => Base.Check(M, "selectorMatches", a => ActionSelectors.SelectorMatches((D)a[0]!, Cl(a[1])));
    [Fact] public void SelectorMatchesFor() => Base.Check(M, "selectorMatchesFor", a => ActionSelectors.SelectorMatchesFor((D)a[0]!, (string)a[1]!, Cl(a[2]), a[3] is true));
    [Fact] public void PolicyDecision() => Base.Check(M, "policyDecision", a => ActionSelectors.PolicyDecision((D)a[0]!, (string)a[1]!, Cl(a[2]), a[3] is true));
    [Fact] public void BlankReason() => Base.Check(M, "blankReason", a => ActionConfirmation.BlankReason((string)a[0]!));
    [Fact] public void ReviewMessage() => Base.Check(M, "reviewMessage", a => ActionConfirmation.ReviewMessage((D)a[0]!));
    [Fact] public void SignReview() => Base.Check(M, "signReview", a => ActionConfirmation.SignReview((D)a[0]!, Base.Bytes(a[1])));
    [Fact]
    public void VerbConfirmationError() => Base.Check(M, "verbConfirmationError", a =>
        Actions.VerbConfirmationError((D)a[0]!, a[1] is L extra ? Actions.ExtendRegistry(Actions.CoreRegistry, extra) : Actions.CoreRegistry, a[2] ?? false)); // an explicit null is a pin set that is not an object (only an absent one names no keys)

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "selectorHasNot", "allowSelectorError", "selectorMatches", "selectorMatchesFor", "policyDecision", "blankReason", "reviewMessage", "signReview", "verbConfirmationError" }); Assert.Equal(1266, Base.Total(M)); }
}
