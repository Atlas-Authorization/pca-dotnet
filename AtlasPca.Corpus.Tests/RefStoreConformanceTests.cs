using AtlasPca;
using AtlasPca.StoreConformancePkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the store conformance kit's pure logic (register model, linearizability search and checker, history parser, report folding,
/// profile inventories) against the TypeScript reference (test-data/ref-store-conformance.json.gz).</summary>
public class RefStoreConformanceTests
{
    const string M = "ref-store-conformance";

    static List<HistoryOp> Ops(object? o) => ((L)o!).Select(HistoryOp.FromJson).ToList();
    static L Json(IEnumerable<HistoryOp> ops) => ops.Select(o => (object?)o.ToJson()).ToList();
    static double Num(object? o) => HistoryOp.DecodeNumber(o);

    static CheckOptions Opts(object? o)
    {
        var m = (D)o!;
        return new CheckOptions { Budget = m.TryGetValue("budget", out var b) ? Num(b) : null, Minimize = m.GetValueOrDefault("minimize") as bool?, MinimizeLimit = m.TryGetValue("minimizeLimit", out var l) ? Num(l) : null };
    }

    [Fact] public void Step() => Base.Check(M, "step", a => RegisterModel.Step(Num(a[0]), HistoryOp.FromJson(a[1])).Select(HistoryOp.EncodeNumber).ToList());

    [Fact]
    public void OverlappingTrues() => Base.Check(M, "overlappingTrues", a =>
    {
        var p = RegisterModel.OverlappingTrues(Ops(a[0]));
        return p == null ? null : new L { p.Value.Item1.ToJson(), p.Value.Item2.ToJson() };
    });

    [Fact] public void Prune() => Base.Check(M, "prune", a => Json(RegisterModel.Prune(Ops(a[0]))));

    [Fact] public void FastCheck() => Base.Check(M, "fastCheck", a => RegisterModel.FastCheck(Ops(a[0])));

    [Fact] public void Search() => Base.Check(M, "search", a => LinearizabilitySearch.Search(Ops(a[0]), Num(a[1])));

    [Fact]
    public void DecideKey() => Base.Check(M, "decideKey", a =>
    {
        var (verdict, method, kept) = HistoryChecker.DecideKey(Ops(a[0]), Num(a[1]));
        return new D { ["verdict"] = verdict, ["method"] = method, ["kept"] = Json(kept) };
    });

    [Fact]
    public void Deletion() => Base.Check(M, "deletion", a =>
    {
        var ops = Ops(a[0]);
        return Json(HistoryChecker.Deletion(ops, ops[(int)Num(a[1])]));
    });

    [Fact] public void Minimize() => Base.Check(M, "minimize", a => Json(HistoryChecker.Minimize(Ops(a[0]), Num(a[1]))));

    [Fact] public void CheckKey() => Base.Check(M, "checkKey", a => HistoryChecker.CheckKey(Ops(a[0]), Opts(a[1])).ToJson());

    [Fact] public void CheckHistory() => Base.Check(M, "checkHistory", a => HistoryChecker.CheckHistory(Ops(a[0]), Opts(a[1])).ToJson());

    [Fact] public void FormatOps() => Base.Check(M, "formatOps", a => HistoryChecker.FormatOps(Ops(a[0])));

    [Fact]
    public void ParseHistory() => Base.Check(M, "parseHistory", a =>
    {
        var (ops, torn, pending) = HistoryRecorder.ParseHistory((string)a[0]!);
        return new D { ["ops"] = Json(ops), ["torn"] = (long)torn, ["pending"] = (long)pending };
    });

    [Fact]
    public void Prng() => Base.Check(M, "prng", a =>
    {
        var r = WorkloadRandom.Prng(Num(a[0]));
        return ((L)a[1]!).Select(n => (object?)r(Num(n))).ToList();
    });

    [Fact]
    public void Overall() => Base.Check(M, "overall", a => a[0] is D rep
        ? KitReports.Overall(KitReport.FromJson(rep).Tests)
        : KitReports.Overall(((L)a[0]!).Select(s => (string)s!)));

    [Fact] public void FormatReport() => Base.Check(M, "formatReport", a => KitReports.Format(KitReport.FromJson(a[0]), (int)Num(a[1])));

    [Fact] public void ReportJson() => Base.Check(M, "reportJson", a => KitReports.Json(KitReport.FromJson(a[0])));

    [Fact] public void Inventory() => Base.Check(M, "inventory", a => StoreInventories.Of((string)a[0]!));

    [Fact]
    public void EveryFnIsCovered() { Base.Covers(M, new[]
    {
        "step", "overlappingTrues", "prune", "fastCheck", "search", "decideKey", "deletion", "minimize", "checkKey", "checkHistory", "formatOps", "parseHistory",
        "prng", "overall", "formatReport", "reportJson", "inventory",
    }); Assert.Equal(2205, Base.Total(M)); }
}
