using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the intent outcome space (omega, derivation, policy plumbing, slots, regions) against the TypeScript reference
/// (test-data/ref-intent-omega.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentOmegaTests
{
    const string M = "ref-intent-omega";

    static VerbSpace Vs(object? o) => VerbSpaceFromJson(o);
    static Dim Dm(object? o) => DimFromJson(o);
    static Outcome Out(object? o) => OutcomeFromJson(o);
    static int I(object? o) => (int)Dbl(o);
    static int[] Idx(object? o) => ((L)o!).Select(I).ToArray();
    static L Ints(IEnumerable<int> xs) => xs.Select(x => (object?)N(x)).ToList();
    static bool Inner(object? o) => (string?)o == "inner";

    [Fact] public void DeriveOmegaFn() => Base.Check(M, "deriveOmega", a => OmegaToJson(IntentDerive.DeriveOmega((D)a[0]!)));
    [Fact] public void HarmMaxFn() => Base.Check(M, "harmMax", a => N(HarmMax(OmegaFromJson(a[0]))));
    [Fact] public void VerbSpaceFn() => Base.Check(M, "verbSpace", a => VerbSpaceOf(OmegaFromJson(a[0]), (string)a[1]!) is { } v ? VerbSpaceToJson(v) : null);
    [Fact] public void VerbCellCountFn() => Base.Check(M, "verbCellCount", a => N(VerbCellCount(Vs(a[0]))));
    [Fact] public void DecodeCellFn() => Base.Check(M, "decodeCell", a => Ints(DecodeCell(Vs(a[0]), Dbl(a[1]))));
    [Fact] public void EncodeCellFn() => Base.Check(M, "encodeCell", a => N(EncodeCell(Vs(a[0]), Idx(a[1]))));
    [Fact] public void CellRepFn() => Base.Check(M, "cellRep", a => OutcomeToJson(CellRep(Vs(a[0]), Idx(a[1]))));
    [Fact] public void SeededFn() => Base.Check(M, "seeded", a => OutcomeToJson(CellRep(Vs(a[0]), Idx(a[1]))));
    [Fact] public void CellStatsFn() => Base.Check(M, "cellStats", a => StatsToJson(CellStats(Vs(a[0]), Idx(a[1]))));
    [Fact] public void CellOfFn() => Base.Check(M, "cellOf", a => CellOf(Vs(a[0]), Out(a[1])) is { } r ? Ints(r) : null);
    [Fact] public void HarmOfFn() => Base.Check(M, "harmOf", a => N(HarmOf(Vs(a[0]), Out(a[1]))));
    [Fact] public void CellCountFn() => Base.Check(M, "cellCount", a => CellCount(Dm(a[0])));
    [Fact]
    public void NumCellsFn() => Base.Check(M, "numCells", a => NumCells((NumDim)Dm(a[0])).Select(c => (object?)new D { ["lo"] = N(c.Lo), ["hi"] = N(c.Hi) }).ToList());
    [Fact] public void NumRepFn() => Base.Check(M, "numRep", a => N(NumRep((NumDim)Dm(a[0]), I(a[1]))));
    [Fact] public void RepValueFn() => Base.Check(M, "repValue", a => RepValue(Dm(a[0]), I(a[1])) is double d ? N(d) : RepValue(Dm(a[0]), I(a[1])));
    [Fact] public void CatRepFn() => Base.Check(M, "catRep", a => CatRep((CatDim)Dm(a[0]), I(a[1])));
    [Fact] public void CatCellOfFn() => Base.Check(M, "catCellOf", a => CatCellOf((CatDim)Dm(a[0]), (string)a[1]!));
    [Fact] public void CellOfValueFn() => Base.Check(M, "cellOfValue", a => CellOfValue(Dm(a[0]), Value(a[1])));
    [Fact] public void DimCellStatsFn() => Base.Check(M, "dimCellStats", a => StatsToJson(DimCellStats(Dm(a[0]), I(a[1]))));
    [Fact] public void IntervalWeightFn() => Base.Check(M, "intervalWeight", a => N(IntervalWeight((NumDim)Dm(a[0]), Dbl(a[1]), Dbl(a[2]))));

    [Fact]
    public void RngSeqFn() => Base.Check(M, "rngSeq", a =>
    {
        var r = Rng(Dbl(a[0]));
        var l = new L();
        for (int k = I(a[1]); k > 0; k--) l.Add(N(r()));
        return l;
    });

    [Fact]
    public void SampleOutcomesFn() => Base.Check(M, "sampleOutcomes", a =>
    {
        var om = OmegaFromJson(a[0]);
        var r = Rng(Dbl(a[1]));
        var l = new L();
        for (int k = I(a[2]); k > 0; k--) l.Add(OutcomeToJson(SampleOutcome(om, r).O));
        return l;
    });

    [Fact] public void NormalizePolicyFn() => Base.Check(M, "normalizePolicy", a => IntentPolicyKit.NormalizePolicy(a[0]));
    [Fact] public void SlotsToPolicyFn() => Base.Check(M, "slotsToPolicy", a => IntentDerive.SlotsToPolicy(a[0]));
    [Fact] public void OutcomeToActionFn() => Base.Check(M, "outcomeToAction", a => IntentPolicyKit.OutcomeToAction(Vs(a[0]), Out(a[1])));
    [Fact] public void AdmitsFn() => Base.Check(M, "admits", a => IntentPolicyKit.MakeAdmitter(a[0]).Admits(Vs(a[1]), Out(a[2])));

    [Fact] public void RegionOfCellFn() => Base.Check(M, "regionOfCell", a => IntentRegion.RegionOfCell(Vs(a[0]), Idx(a[1])).ToJson());
    [Fact] public void RegionCellsFn() => Base.Check(M, "regionCells", a => IntentRegion.RegionCells(Vs(a[0]), IntentRegion.Region.FromJson(a[1]), Inner(a[2])));

    [Fact]
    public void DimCellsInFn() => Base.Check(M, "dimCellsIn", a =>
        IntentRegion.DimCellsIn(Dm(a[0]), a[1] == null ? null : IntentRegion.RegionDim.FromJson(a[1]), Inner(a[2])));

    [Fact]
    public void RestrictRegionFn() => Base.Check(M, "restrictRegion", a =>
        IntentRegion.RestrictRegion(new IntentRegion.Region("v", new Dictionary<string, IntentRegion.RegionDim>()), Dm(a[0]), (D)a[1]!).ToJson());

    [Fact]
    public void ValueInRegionDimFn() => Base.Check(M, "valueInRegionDim", a =>
        IntentRegion.ValueInRegionDim((string)a[0]!, IntentRegion.RegionDim.FromJson(a[1]), Value(a[2])));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "deriveOmega", "harmMax", "verbSpace", "verbCellCount", "decodeCell", "encodeCell", "cellRep", "seeded", "cellStats", "cellOf", "harmOf",
        "cellCount", "numCells", "numRep", "repValue", "catRep", "catCellOf", "cellOfValue", "dimCellStats", "intervalWeight", "rngSeq",
        "sampleOutcomes", "normalizePolicy", "slotsToPolicy", "outcomeToAction", "admits", "regionOfCell", "regionCells", "dimCellsIn",
        "restrictRegion", "valueInRegionDim",
    }); Assert.Equal(5377, Base.Total(M)); }
}
