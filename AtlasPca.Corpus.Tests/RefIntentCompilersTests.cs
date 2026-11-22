using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the k-compiler pipeline (slot prompt and grounding, panel run, disagreement analysis, committee anchors) against the
/// TypeScript reference (test-data/ref-intent-compilers.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentCompilersTests
{
    const string M = "ref-intent-compilers";

    static IIntentCompiler Compiler(object? so)
    {
        var s = (D)so!;
        var id = s.GetValueOrDefault("id") as string; // a captured compiler without an id takes the default name
        var family = s.GetValueOrDefault("family") as string ?? "";
        switch ((string)s["kind"]!)
        {
            case "captured": return IntentCompilers.CapturedSlotsCompiler(id);
            case "fixed": return IntentCompilers.FixedCompiler(id!, family, _ => s.GetValueOrDefault("policy"));
            case "throws": return IntentCompilers.FixedCompiler(id!, family, _ => throw new InvalidOperationException("boom"));
            case "slots": return IntentCompilers.SlotsCompiler(id!, family, _ => (string)s["raw"]!);
            default: return IntentCompilers.SlotsCompiler(id!, family, _ => throw new InvalidOperationException("llm down"));
        }
    }

    static List<IIntentCompiler> Compilers(object? specs) => ((L)specs!).Select(Compiler).ToList();

    [Fact] public void SlotsPromptFn() => Base.Check(M, "slotsPrompt", a => IntentCompilers.SlotsPrompt((string)a[0]!));
    [Fact] public void ParseSlotsJsonFn() => Base.Check(M, "parseSlotsJSON", a => IntentCompilers.ParseSlotsJson((string)a[0]!));
    [Fact] public void RunScenarioFn() => Base.Check(M, "runScenario", a => IntentCompilers.RunCompilers((D)a[0]!, Compilers(a[1])));
    [Fact] public void AnalyzeFn() => Base.Check(M, "analyze", a => IntentCompilers.AnalyzeDisagreement((L)a[0]!, (D)a[1]!));
    [Fact] public void FlagsFn() => Base.Check(M, "flags", a => IntentCompilers.PanelFlags(IntentCompilers.AnalyzeDisagreement((L)a[0]!, (D)a[1]!)));
    [Fact] public void AnchorsFn() => Base.Check(M, "anchors", a => IntentCompilers.CommitteeAnchors((L)a[0]!, Dbl(a[1])));
    [Fact] public void CompareScenarioFn() => Base.Check(M, "compareScenario", a => IntentCompilers.CompileAndCompare((D)a[0]!, Compilers(a[1]), (D)a[2]!));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "slotsPrompt", "parseSlotsJSON", "runScenario", "analyze", "flags", "anchors", "compareScenario" }); Assert.Equal(237, Base.Total(M)); }
}
