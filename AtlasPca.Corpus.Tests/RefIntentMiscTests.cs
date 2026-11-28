using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the mixed intent corpus (test-data/ref-intent-misc.json.gz, 35 functions): statements, the compiler panel, classifier calibration and
/// risk, provenance and regret, the schema outcome space, trajectory lifting and stepping, frames, and cell coordinates. Each function is called with the
/// reference's own argument list.</summary>
public class RefIntentMiscTests
{
    const string M = "ref-intent-misc";

    static int[] Ints(object? o) => ((L)o!).Select(x => (int)Dbl(x)).ToArray();

    // ---- statements ----
    [Fact] public void SignIntent() => Base.Check(M, "signIntent", a => IntentStatement.SignIntent((D)a[0]!, Pca.B64uDecode(a[1])!), min: 14);
    [Fact] public void IntentRef() => Base.Check(M, "intentRef", a => IntentStatement.IntentRef(a[0]), min: 3);

    [Fact]
    public void VerifyIntent() => Base.Check(M, "verifyIntent", a =>
    {
        var o = a.Count > 1 ? a[1] as D : null;
        return IntentStatement.VerifyIntent(a[0], o?.GetValueOrDefault("expectedSigner") as string, o?.GetValueOrDefault("pqPins") as D);
    }, min: 280);

    // ---- compiler panel ----
    static IIntentCompiler Compiler(object? so)
    {
        var s = (D)so!;
        var id = (string)s["id"]!;
        var family = s.GetValueOrDefault("family") as string ?? "";
        return (string)s["kind"]! switch
        {
            "captured" => IntentCompilers.CapturedSlotsCompiler(id),
            "throws" => IntentCompilers.FixedCompiler(id, family, _ => throw new InvalidOperationException("boom")),
            _ => IntentCompilers.FixedCompiler(id, family, _ => s.GetValueOrDefault("policy")),
        };
    }

    [Fact] public void ParseSlotsJson() => Base.Check(M, "parseSlotsJSON", a => IntentCompilers.ParseSlotsJson((string)a[0]!), min: 13);
    [Fact] public void SlotsPrompt() => Base.Check(M, "slotsPrompt", a => IntentCompilers.SlotsPrompt((string)a[0]!), min: 3);
    [Fact] public void RunCompilers() => Base.Check(M, "runCompilers", a => IntentCompilers.RunCompilers((D)a[0]!, ((L)a[1]!).Select(Compiler).ToList()), min: 6);
    [Fact] public void AnalyzeDisagreement() => Base.Check(M, "analyzeDisagreement", a => IntentCompilers.AnalyzeDisagreement((L)a[0]!, a.Count > 1 ? a[1] as D : null), min: 20);
    [Fact] public void PanelFlags() => Base.Check(M, "panelFlags", a => IntentCompilers.PanelFlags((D)a[0]!), min: 15);
    [Fact] public void CommitteeAnchors() => Base.Check(M, "committeeAnchors", a => IntentCompilers.CommitteeAnchors((L)a[0]!, Dbl(a[1])), min: 2);

    // ---- schema outcome space ----
    [Fact] public void DeriveOmegaFromSchema() => Base.Check(M, "deriveOmegaFromSchema", a => IntentSchema.DeriveOmegaFromSchema((D)a[0]!).ToJson(), min: 10);
    [Fact] public void CanonValue() => Base.Check(M, "canonValue", a => IntentSchema.CanonValue((D)a[0]!, a[1]), min: 6);

    // ---- provenance and regret ----
    [Fact] public void ProvenanceBanner() => Base.Check(M, "provenanceBanner", a => IntentProvenance.ProvenanceBanner((string)a[0]!, a.Count > 1 ? (string?)a[1] : null), min: 12);
    [Fact] public void ProvenanceFriction() => Base.Check(M, "provenanceFriction", a => IntentProvenance.ProvenanceFriction((string)a[0]!, (string)a[1]!, (string)a[2]!), min: 60);

    // an outcome is admitted when its "ok" value is 1; its utility is its "u" value
    static double Val(Outcome x, string k) => x.Values.TryGetValue(k, out var v) && v is double d ? d : 0;

    [Fact]
    public void RegretReport() => Base.Check(M, "regretReport", a =>
    {
        var cases = ((L)a[0]!).Select(o =>
        {
            var c = (D)o!;
            return new IntentProvenance.RegretCase(((L)c["feasible"]!).Select(OutcomeFromJson).ToList(), OutcomeFromJson(c["chosen"]), x => Val(x, "ok") == 1, x => Val(x, "u"));
        }).ToList();
        return IntentProvenance.RegretReport(cases, a.Count > 1 ? Dbl(a[1]) : 1);
    }, min: 6);

    // ---- classifier kit ----
    [Fact] public void CalibrateConfusion() => Base.Check(M, "calibrateConfusion", a => IntentClassifierKit.CalibrateConfusion((L)a[0]!, (L)a[1]!, a.Count > 2 ? Dbl(a[2]) : null), min: 19);
    [Fact] public void ConfusionDigest() => Base.Check(M, "confusionDigest", a => IntentClassifierKit.ConfusionDigest((D)a[0]!), min: 8);
    [Fact] public void PublishedErrorRate() => Base.Check(M, "publishedErrorRate", a => N(IntentClassifierKit.PublishedErrorRate((D)a[0]!)), min: 8);
    [Fact] public void ClassifierCardNote() => Base.Check(M, "classifierCardNote", a => IntentClassifierKit.ClassifierCardNote((string)a[0]!, (D)a[1]!), min: 8);
    [Fact] public void ClassifierRisk() => Base.Check(M, "classifierRisk", a => N(IntentClassifierKit.ClassifierRisk((D)a[0]!)), min: 4);
    [Fact] public void LabelSound() => Base.Check(M, "labelSound", a => IntentClassifierKit.LabelSound((D)a[0]!), min: 4);
    [Fact] public void LabelSoundBound() => Base.Check(M, "labelSoundBound", a => N(IntentClassifierKit.LabelSoundBound((D)a[0]!, Dbl(a[1]))), min: 4);

    // ---- trajectories ----
    [Fact] public void DimKindOf() => Base.Check(M, "dimKindOf", a => IntentTrajectory.DimKindOf((string)a[0]!), min: 10);

    [Fact]
    public void DescribeAccCell() => Base.Check(M, "describeAccCell", a =>
        IntentTrajectory.DescribeAccCell((NumDim)DimFromJson(a[0]), (int)Dbl(a[1]), (string)a[2]!, a.Count > 3 && a[3] != null ? Dbl(a[3]) : null), min: 8);

    [Fact] public void TrajectoryHarmRange() => Base.Check(M, "trajectoryHarmRange", a => N(IntentTrajectory.TrajectoryHarmRange(Dbl(a[0]), Dbl(a[1]))), min: 7);

    [Fact]
    public void DefaultAccumulators() => Base.Check(M, "defaultAccumulators", a =>
    {
        var o = (D)a[1]!;
        return IntentTrajectory.DefaultAccumulators(a[0], Dbl(o["spendDomainMax"]), o.GetValueOrDefault("questionCap") == null ? null : Dbl(o["questionCap"]), o.GetValueOrDefault("holder") as D);
    }, min: 3);

    [Fact]
    public void AugmentOmega() => Base.Check(M, "augmentOmega", a =>
        OmegaToJson(IntentTrajectory.AugmentOmega(OmegaFromJson(a[0]), (D)a[1]!, a.Count > 2 ? a[2] as D : null)), min: 6);

    // the first argument is already the augmented space
    [Fact]
    public void LiftAction() => Base.Check(M, "liftAction", a =>
        IntentTrajectory.LiftAction(OmegaFromJson(a[0]), (D)a[1]!, (L)a[2]!, (D)a[3]!, a.Count > 4 ? a[4] : null) is { } lifted ? OutcomeToJson(lifted) : null, min: 36);

    [Fact]
    public void StepTrajectory() => Base.Check(M, "stepTrajectory", a =>
    {
        // the grant is "all", "none", or the list of admitted cells
        Func<string, int[], bool> inGrant = a[4] switch
        {
            "all" => (_, _) => true,
            "none" => (_, _) => false,
            _ => (_, c) => ((L)a[4]!).Any(x => Ints(x).SequenceEqual(c)),
        };
        var cand = new D((D)a[3]!) { ["id"] = "new" };
        var s = IntentTrajectory.StepTrajectory(OmegaFromJson(a[0]), (D)a[1]!, (L)a[2]!, cand, inGrant, null);
        return new D { ["admitted"] = s.Admitted, ["history"] = s.History, ["lifted"] = s.Lifted == null ? null : OutcomeToJson(s.Lifted) };
    }, min: 9);

    // ---- frames ----
    [Fact] public void StateDigest() => Base.Check(M, "stateDigest", a => IntentFrames.StateDigest(a.Count > 0 ? a[0] : null), min: 8);
    [Fact] public void SnapshotState() => Base.Check(M, "snapshotState", a => IntentFrames.SnapshotState((D)a[0]!, a.Count < 2 || a[1] is not false), min: 2);

    [Fact]
    public void CheckFrame() => Base.Check(M, "checkFrame", a =>
    {
        // the one-argument oracle runs hand the spec to a fixed action over empty snapshots
        if (a.Count == 1) return IntentFrames.CheckFrame(a[0], new D { ["verb"] = "v", ["resource"] = "r" }, new D(), new D(), null);
        object? At(int i) => a.Count > i ? a[i] : null;
        return IntentFrames.CheckFrame(At(0), At(1), At(2), At(3), At(4) as D);
    }, min: 164);

    [Fact] public void WriteSetOf() => Base.Check(M, "writeSetOf", a => IntentFrames.WriteSetOf((D)a[0]!, (D)a[1]!), min: 9);

    // ---- cells ----
    [Fact] public void CellCoords() => Base.Check(M, "cellCoords", a => IntentJit.CellCoords(VerbSpaceFromJson(a[0]), Ints(a[1])), min: 9);

    [Fact]
    public void CellFromCoords() => Base.Check(M, "cellFromCoords", a =>
        IntentJit.CellFromCoords(VerbSpaceFromJson(a[0]), (D)a[1]!) is { } r ? r.Select(d => (object?)N(d)).ToList() : null, min: 16);

    // the cell is located by the input's own vs and cell members
    [Fact]
    public void IntentRequiredBody() => Base.Check(M, "intentRequiredBody", a =>
    {
        var i = (D)a[0]!;
        return IntentJit.IntentRequiredBody(i, VerbSpaceFromJson(i["vs"]), Ints(i["cell"]));
    }, min: 3);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "signIntent", "intentRef", "verifyIntent", "parseSlotsJSON", "slotsPrompt", "runCompilers", "analyzeDisagreement", "panelFlags", "committeeAnchors",
            "deriveOmegaFromSchema", "canonValue", "provenanceBanner", "provenanceFriction", "regretReport", "calibrateConfusion", "confusionDigest",
            "publishedErrorRate", "classifierCardNote", "classifierRisk", "labelSound", "labelSoundBound", "dimKindOf", "describeAccCell", "trajectoryHarmRange",
            "defaultAccumulators", "augmentOmega", "liftAction", "stepTrajectory", "stateDigest", "snapshotState", "checkFrame", "writeSetOf", "cellCoords",
            "cellFromCoords", "intentRequiredBody",
        });
        Assert.Equal(795, Base.Cases(M).Count);
    }
}
