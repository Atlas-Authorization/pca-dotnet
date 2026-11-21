using Xunit;
using static AtlasPca.Corpus.Tests.RefCoreParityPureTests;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of chain compaction, the receipt, the budget algebra and the standing class approvals against the TypeScript reference
/// (test-data/ref-core-sweep-java.json.gz). The reputation and underwriting, frontier-signal and budget-forecast helpers of that corpus are replayed by their own test classes.</summary>
public class RefCoreSweepTests
{
    const string M = "ref-core-sweep-java";

    [Fact] public void HopsRoot() => Base.Check(M, "hopsRoot", a => ChainCompact.HopsRoot((L)a[0]!));
    [Fact] public void CompactChain() => Base.Check(M, "compactChain", a => ChainCompact.CompactChain((L)a[0]!));
    [Fact] public void HopLeaf() => Base.Check(M, "hopLeaf", a => ChainCompact.HopLeaf(a[0]));
    [Fact] public void CompactChainShapeError() => Base.Check(M, "compactChainShapeError", a => ChainCompact.CompactChainShapeError(a[0]));

    [Fact]
    public void ReceiptFor() => Base.Check(M, "receiptFor", a =>
        ActionReceipts.ReceiptFor((string)a[0]!, N(a[1]), (D)a[2]!, Allow(a[3]), Checks(a[3]), a.Count > 4 && a[4] != null ? N(a[4]) : (long?)null));

    [Fact]
    public void SubBudget() => Base.Check(M, "subBudget", a =>
    {
        var r = Risk.SubBudget(Budget(a[0]), F(a[1]));
        return r.Ok ? new D { ["ok"] = true, ["sub"] = BudgetJson(r.Nodes![0]) } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    // a debited node is the input object with its B replaced ({...b, B}): the members the budget does not model ride along
    static D Spread(object? raw, TrustBudget b)
    {
        var o = BudgetJson(b);
        var merged = new D();
        foreach (var kv in (D)raw!) if (kv.Key is not ("B" or "tau" or "asOf")) merged[kv.Key] = kv.Value;
        foreach (var kv in o) merged[kv.Key] = kv.Value;
        return merged;
    }

    // `have ${node.B}`: the reference prints the member as JavaScript does, a string as it is and a missing member as undefined
    static string JsText(object? raw) => raw switch { null => "null", string s => s, Num n => IntentJs.NormNum(n.Raw).Raw, bool bo => bo ? "true" : "false", _ => "[object Object]" };

    [Fact]
    public void DebitConsolidated() => Base.Check(M, "debitConsolidated", a =>
    {
        var r = Risk.DebitConsolidated(Budget(a[0]), Budget(a[1]), F(a[2]));
        return r.Ok ? new D { ["ok"] = true, ["parent"] = Spread(a[0], r.Nodes![0]), ["sub"] = Spread(a[1], r.Nodes![1]) } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void DebitConsolidatedPath() => Base.Check(M, "debitConsolidatedPath", a =>
    {
        var raws = (L)a[0]!;
        var r = Risk.DebitConsolidatedPath(raws.Select(Budget).ToList(), F(a[1]));
        if (r.Ok) return new D { ["ok"] = true, ["nodes"] = r.Nodes!.Select((b, i) => (object?)Spread(raws[i], b)).ToList() };
        var m = System.Text.RegularExpressions.Regex.Match(r.Reason!, @"^budget node at depth (\d+) insufficient \(need (.*), have NaN\)$");
        var reason = !m.Success ? r.Reason : $"budget node at depth {m.Groups[1].Value} insufficient (need {m.Groups[2].Value}, have {(((D)raws[int.Parse(m.Groups[1].Value)]!).TryGetValue("B", out var rb) ? JsText(rb) : "undefined")})";
        return new D { ["ok"] = false, ["reason"] = reason };
    });

    [Fact] public void RechargeFull() => Base.Check(M, "rechargeFull", a => BudgetJson(Risk.RechargeFull(F(a[0]), F(a[1]))));

    [Fact]
    public void ApproveClass() => Base.Check(M, "approveClass", a =>
        Approvals.ApproveClass(((L)a[0]!).Select(v => (string)v!).ToList(), F(a[1]), (string)a[2]!, F(a[3]), a.Count > 4 ? a[4] as string : null));

    [Fact] public void ClassApprovalCovers() => Base.Check(M, "classApprovalCovers", a => Approvals.ClassApprovalCovers((D)a[0]!, (string)a[1]!, (string)a[2]!, F(a[3])));
    [Fact] public void CoveredByAny() => Base.Check(M, "coveredByAny", a => Approvals.CoveredByAny((L)a[0]!, (string)a[1]!, (string)a[2]!, F(a[3])));
    [Fact] public void RecordDecision() => Base.Check(M, "recordDecision", a => Approvals.RecordDecision((D)a[0]!, (string)a[1]!, (string)a[2]!, F(a[3])));
    [Fact] public void PendingRequests() => Base.Check(M, "pendingRequests", a => Approvals.PendingRequests((L)a[0]!));

    [Fact]
    public void ApplyCosign() => Base.Check(M, "applyCosign", a =>
    {
        var p = (D)a[1]!;
        var policy = new RiskPolicy(0, 0, 0, 0, 0, 0, 0, 0, 1, 0, F(p["rho"]), F(p["bMax"]));
        return BudgetJson(Approvals.ApplyCosign(Budget(a[0]), policy, F(a[2]), a.Count > 3 && a[3] is true));
    });

    [Fact]
    public void EveryFnIsHandledOrNamedAsNotReplayed() { Base.Covers(M, new[]
    {
        "hopsRoot", "compactChain", "hopLeaf", "compactChainShapeError", "receiptFor", "subBudget", "debitConsolidated", "debitConsolidatedPath", "rechargeFull", "approveClass",
        "classApprovalCovers", "coveredByAny", "recordDecision", "pendingRequests", "applyCosign",
        // the chain memo and receipt-chain scripts drive a stateful object through an operation list (replayed through the memo and receipt unit tests); the reputation, underwriting
        // and capital pool scripts are replayed by RefReputationTests, the frontier-signal helpers by RefFrontierSignalsTests and the budget-forecast helpers by RefBudgetForecastTests
        "chainMemo", "receiptChain", "reputation", "priceCoverage", "issueCoverageQuote", "verifyCoverageQuote", "pool", "semanticSignal", "progressSignal", "objectiveSignal",
        "tightenRiskInputs", "recommendPolicy", "autonomyBoundOf",
    }); Assert.Equal(2167, Base.Total(M)); }
}
