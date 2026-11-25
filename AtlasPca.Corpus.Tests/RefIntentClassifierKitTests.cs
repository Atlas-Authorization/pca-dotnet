using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the classifier-error kit (calibration, card note, risk arrays, classifier-aware risk, jit gate) against the TypeScript
/// reference (test-data/ref-intent-classifier.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentClassifierKitTests
{
    const string M = "ref-intent-classifier";

    [Fact] public void CalibrateFn() => Base.Check(M, "calibrate", a => IntentClassifierKit.CalibrateConfusion((L)a[0]!, (L)a[1]!, a.Count > 2 ? Dbl(a[2]) : null));
    [Fact] public void ConfusionDigestFn() => Base.Check(M, "confusionDigest", a => IntentClassifierKit.ConfusionDigest((D)a[0]!));
    [Fact] public void PublishedErrorRateFn() => Base.Check(M, "publishedErrorRate", a => N(IntentClassifierKit.PublishedErrorRate((D)a[0]!)));
    [Fact] public void ClassifierCardNoteFn() => Base.Check(M, "classifierCardNote", a => IntentClassifierKit.ClassifierCardNote((string)a[0]!, (D)a[1]!));

    [Fact]
    public void RiskArraysFn() => Base.Check(M, "riskArrays", a =>
    {
        var op = (string)a[0]!;
        var arr = (D)a[1]!;
        if (op == "risk") return N(IntentClassifierKit.ClassifierRisk(arr));
        if (op == "sound") return IntentClassifierKit.LabelSound(arr);
        return N(IntentClassifierKit.LabelSoundBound(arr, Dbl(a[2])));
    });

    [Fact] public void AwareScenarioFn() => Base.Check(M, "awareScenario", a => IntentClassifierKit.ClassifierAwareResidualRisk(RefIntentRampTests.Make(a[0], a[1], a[2]), (L)a[3]!));
    [Fact] public void JitScenarioFn() => Base.Check(M, "jitScenario", a => IntentClassifierKit.ClassifierJitCells(RefIntentRampTests.Make(a[0], a[1], a[2]), (D)a[3]!, Dbl(a[4])));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "calibrate", "confusionDigest", "publishedErrorRate", "classifierCardNote", "riskArrays", "awareScenario", "jitScenario" }); Assert.Equal(249, Base.Total(M)); }
}
