using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the frontier signals over test-data/ref-frontier-signals.json.gz: the three result-to-signal functions and the risk-input tightening. A non-finite number is
/// {"$num": text} in the corpus and a double here; a negative zero is significant in the results (min(0, -0) is -0).</summary>
public class RefFrontierSignalsTests
{
    const string M = "ref-frontier-signals";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    [Fact] public void SemanticSignal() => Base.Check(M, "semanticSignal", a => FrontierSignals.SemanticSignal(Nums(a[0])), min: 39);
    [Fact] public void ProgressSignal() => Base.Check(M, "progressSignal", a => FrontierSignals.ProgressSignal(Nums(a[0])), min: 129);
    [Fact] public void ObjectiveSignal() => Base.Check(M, "objectiveSignal", a => FrontierSignals.ObjectiveSignal(Nums(a[0])), min: 182);
    [Fact] public void TightenRiskInputs() => Base.Check(M, "tightenRiskInputs", a => FrontierSignals.TightenRiskInputs(Nums(a[0]), Nums(a[1])), min: 340);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "semanticSignal", "progressSignal", "objectiveSignal", "tightenRiskInputs" });
        Assert.Equal(690, Base.Total(M));
    }
}
