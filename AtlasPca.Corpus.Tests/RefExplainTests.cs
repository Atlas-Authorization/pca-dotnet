using AtlasPca.Explain;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the PCA explainer (cleanText, explainVerification / Decision / Chain and the text renderers) against the TypeScript reference.</summary>
public class RefExplainTests
{
    const string M = "ref-explain";

    static D Chain(L a) { var o = (D)a[1]!; return Explainer.ExplainChain(a[0], o.GetValueOrDefault("verify") is true, o.GetValueOrDefault("expectedRootIssuer") as string); }

    [Fact] public void CleanText() => Base.Check(M, "cleanText", a => Explainer.CleanText(a[0]));
    [Fact] public void ExplainVerification() => Base.Check(M, "explainVerification", a => Explainer.ExplainVerification(a[0], a[1], a[2]));
    [Fact] public void ExplainVerificationText() => Base.Check(M, "explainVerificationText", a => Explainer.VerificationToText(Explainer.ExplainVerification(a[0], a[1], a[2])));
    [Fact] public void ExplainDecision() => Base.Check(M, "explainDecision", a => Explainer.ExplainDecision(a[0], a[1], a[2]));
    [Fact] public void ExplainDecisionText() => Base.Check(M, "explainDecisionText", a => Explainer.DecisionToText(Explainer.ExplainDecision(a[0], a[1], a[2])));
    [Fact] public void ExplainChain() => Base.Check(M, "explainChain", a => Chain(a));
    [Fact] public void ExplainChainText() => Base.Check(M, "explainChainText", a => Explainer.ChainToText(Chain(a)));

    [Fact]
    public void Consts() => Base.Check(M, "consts", _ => new D { ["VERIFY_CHECK_ORDER"] = Explainer.VerifyCheckOrder.Cast<object?>().ToList(), ["MAX_TEXT"] = Explainer.MaxText });

    [Fact]
    public void EveryFnHasATest() { Base.Covers(M, new[]
    {
        "cleanText", "explainVerification", "explainVerificationText", "explainDecision", "explainDecisionText", "explainChain", "explainChainText", "consts",
    }); Assert.Equal(2107, Base.Total(M)); }
}
