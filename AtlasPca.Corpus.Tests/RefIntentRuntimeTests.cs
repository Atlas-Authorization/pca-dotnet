using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the runtime digests, effect postconditions, ramp parts and question cards against the TypeScript reference
/// (test-data/ref-intent-runtime.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentRuntimeTests
{
    const string M = "ref-intent-runtime";

    static VerbSpace Vs(object? o) => VerbSpaceFromJson(o);
    static Outcome Out(object? o) => OutcomeFromJson(o);
    static VerbSpace VerbOf(object? omega, Outcome o) => VerbSpaceOf(OmegaFromJson(omega), o.Verb)!;
    static int[] Idx(object? o) => ((L)o!).Select(x => (int)Dbl(x)).ToArray();

    [Fact] public void PcactnActionOfFn() => Base.Check(M, "pcactnActionOf", a => IntentRuntime.PcactnActionOf(Vs(a[0]), Out(a[1])));

    [Fact]
    public void JudgeInputOfFn() => Base.Check(M, "judgeInputOf", a =>
    {
        var o = Out(a[1]);
        return IntentRuntime.JudgeInputOf(VerbOf(a[0], o), o, Dbl(a[2]), (D)a[3]!);
    });

    [Fact]
    public void JitConsentRequestFn() => Base.Check(M, "jitConsentRequest", a =>
    {
        var o = Out(a[1]);
        var c = (D)a[3]!;
        return IntentRuntime.JitConsentRequest(VerbOf(a[0], o), o, Dbl(a[2]), c.GetValueOrDefault("intentRef") as string, c.GetValueOrDefault("mapDigest") as string);
    });

    [Fact] public void JitConsentDigestFn() => Base.Check(M, "jitConsentDigest", a => IntentRuntime.JitConsentDigest(a[0]));
    [Fact] public void CalibrationDigestFn() => Base.Check(M, "calibrationDigest", a => IntentRuntime.CalibrationDigest((D)a[0]!));
    [Fact] public void IcAttDigestFn() => Base.Check(M, "icAttDigest", a => IntentRuntime.IcAttDigest(a[0]));
    [Fact] public void FoldSemanticRiskFn() => Base.Check(M, "foldSemanticRisk", a => N(IntentRuntime.FoldSemanticRisk(Dbl(a[0]), (D)a[1]!)));
    [Fact] public void DefaultPostconditionsFn() => Base.Check(M, "defaultPostconditions", a => IntentEffects.DefaultPostconditions);
    [Fact] public void EffectContextFn() => Base.Check(M, "effectContext", a => IntentEffects.EffectContext(Vs(a[0]), Out(a[1]), (D)a[2]!));

    [Fact]
    public void CheckPostconditionsFn() => Base.Check(M, "checkPostconditions", a =>
        IntentEffects.CheckPostconditions(Vs(a[0]), Out(a[1]), (D)a[2]!, a.Count > 3 ? (L)a[3]! : null));

    [Fact] public void SignalLabelFn() => Base.Check(M, "signalLabel", a => N(IntentRamp.SignalLabel(a[0] as string)));

    [Fact]
    public void NarrowStartFn() => Base.Check(M, "narrowStart", a =>
    {
        var o = (D)a[2]!;
        return IntentRamp.NarrowStart(OmegaFromJson(a[0]), a[1], o.ContainsKey("slotNullMass") ? Dbl(o["slotNullMass"]) : null, o.ContainsKey("otherNullMass") ? Dbl(o["otherNullMass"]) : null);
    });

    [Fact]
    public void DriftRunFn() => Base.Check(M, "driftRun", a =>
    {
        var o = (D)a[0]!;
        var dd = new IntentRamp.DriftDetector(o.ContainsKey("rho0") ? Dbl(o["rho0"]) : null, o.ContainsKey("rho1") ? Dbl(o["rho1"]) : null, o.ContainsKey("h") ? Dbl(o["h"]) : null);
        var states = new L();
        foreach (var x in (L)a[1]!) states.Add(dd.Update((bool)x!).ToJson());
        states.Add(dd.State.ToJson());
        dd.Reset();
        states.Add(dd.State.ToJson());
        return states;
    });

    [Fact]
    public void QuestionCardFn() => Base.Check(M, "questionCard", a =>
    {
        var q = (D)a[1]!;
        return IntentUx.QuestionCard(OmegaFromJson(a[0]), (string)q["verb"]!, Idx(q["cell"]));
    });

    [Fact] public void ParseCardAnswerFn() => Base.Check(M, "parseCardAnswer", a => IntentUx.ParseCardAnswer(a[0], a[1]));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "pcactnActionOf", "judgeInputOf", "jitConsentRequest", "jitConsentDigest", "calibrationDigest", "icAttDigest", "foldSemanticRisk", "defaultPostconditions",
        "checkPostconditions", "effectContext", "signalLabel", "narrowStart", "driftRun", "questionCard", "parseCardAnswer",
    }); Assert.Equal(585, Base.Total(M)); }
}
