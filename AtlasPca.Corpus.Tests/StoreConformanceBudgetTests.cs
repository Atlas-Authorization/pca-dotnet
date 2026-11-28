using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class StoreConformanceBudgetTests
{
    [Fact]
    public void TheMemoryLedgerPassesAndSkipsWhatItDeclaresItCannotDo()
    {
        var r = BudgetLedgerConformance.Run(BudgetLedgerConformance.MemoryLedgerAdapter());
        Assert.True(r.Ok, r.Format());
        Assert.Equal("skip", r.Check("state-survives-reopen").Status);
        Assert.Equal("skip", r.Check("acknowledged-writes-survive-a-crash").Status);
        Assert.Equal(0, r.Count("fail"));
    }

    [Fact]
    public void ADurableKvLedgerPassesEveryCheck()
    {
        var a = BudgetLedgerConformance.KvLedgerAdapter("kv", true, () => { var kv = new MemoryAtomicKv(); return () => kv; }, true);
        var r = BudgetLedgerConformance.Run(a);
        Assert.True(r.Ok, r.Format());
        Assert.Equal(0, r.Count("skip"));
    }

    [Fact]
    public void EveryDefectiveLedgerIsCaught()
    {
        foreach (var (name, make) in BudgetLedgerConformance.ReferenceAdapters())
        {
            var r = BudgetLedgerConformance.Run(make());
            Assert.Equal(!name.StartsWith("bad-"), r.Ok);
        }
    }

    [Fact]
    public void SpecificDefectsFailTheirOwnChecks()
    {
        var d = BudgetLedgerConformance.Defect.NoCap;
        Assert.Equal("fail", BudgetLedgerConformance.Run(BudgetLedgerConformance.DefectiveLedgerAdapter(d)).Check("reservation-counts-at-once-and-cap-is-inclusive").Status);
        Assert.Equal("fail", BudgetLedgerConformance.Run(BudgetLedgerConformance.DefectiveLedgerAdapter(BudgetLedgerConformance.Defect.LateCommit)).Check("a-late-commit-cannot-overspend").Status);
        Assert.Equal("fail", BudgetLedgerConformance.Run(BudgetLedgerConformance.DefectiveLedgerAdapter(BudgetLedgerConformance.Defect.VolatileClaimsDurable)).Check("durable-claim-matches-the-adapter").Status);
        Assert.Equal("fail", BudgetLedgerConformance.Run(BudgetLedgerConformance.DefectiveLedgerAdapter(BudgetLedgerConformance.Defect.SharedKeys)).Check("keys-are-independent").Status);
    }

    [Fact]
    public void ADamagedDocumentFailsClosed()
    {
        var kv = new MemoryAtomicKv();
        var ledger = new KvBudgetLedger(kv, false);
        kv.Update("pca-budget-ledger/v1/principal/x", _ => "{\"v\":1,\"ver\":0,\"events\":[1]}");
        Assert.Equal("store_corrupt", Assert.Throws<BudgetLedgerError>(() => ledger.Snapshot("principal/x")).Code);
        Assert.Throws<ArgumentException>(() => ledger.Snapshot("bad\u0001key"));
        Assert.Equal("store_missing", Assert.Throws<BudgetLedgerError>(() => new KvBudgetLedger(null!, false)).Code);
    }

    [Fact]
    public void ScopeKeysAreInjectiveAndReleasesAreSignedBoundAndAnchored()
    {
        Assert.Equal("principal/a%2Fb%20c", Budgets.ScopeKey("principal", "a/b c"));
        Assert.Equal("invalid", Assert.Throws<BudgetLedgerError>(() => Budgets.ScopeKey("org", "")).Code);
        var key = EdKey.FromSeed(Enumerable.Repeat((byte)3, 32).ToArray());
        var rel = Budgets.SignRelease("principal/alice", "a", "effect_failed", 5, key);
        Assert.True(Budgets.VerifyRelease(rel, key.Id));
        var tampered = new D(rel) { ["id"] = "b" };
        Assert.False(Budgets.VerifyRelease(tampered, key.Id));
        Assert.False(Budgets.VerifyRelease(rel, "someone-else"));
        Assert.Throws<ArgumentException>(() => Budgets.SignRelease("k", "a", "because", 5, key));
        var log = new KvLedgerStore(new MemoryAtomicKv());
        Assert.Equal(0, Budgets.AnchorRelease(log, rel));
        Assert.Equal(1, Budgets.AnchorRelease(log, rel)); // the same release anchored again lands at the next position
        Assert.Equal(2, log.Size());
    }

    static D Acc(string scope) => new()
    {
        ["id"] = "spend", ["agg"] = "sum", ["val"] = "action.params.amount", ["sel"] = new D { ["verbs"] = new List<object?> { "pay" } },
        ["win"] = new D { ["kind"] = "task" }, ["key"] = null, ["domain_max"] = new Num("100"), ["holder"] = new D { ["kind"] = "site_local" }, ["scope"] = scope,
    };

    static D Evt(string id, int amount) => new()
    {
        ["id"] = id, ["verb"] = "pay", ["resource"] = "r", ["params"] = new D { ["amount"] = new Num(amount.ToString()) }, ["t"] = new Num("1000"),
    };

    [Fact]
    public void AdmissionReservesPerScopeKeyAndRefusesPastTheCapOrAVolatileLedger()
    {
        var ledger = new KvBudgetLedger(new MemoryAtomicKv(), true);
        var ids = new Dictionary<string, string> { ["principal"] = "alice" };
        D Allow(D _) => new() { ["allow"] = true };
        var ok = Budgets.AdmitAggregateAction(ledger, ids, new[] { Acc("principal") }, null, Evt("e1", 60), Allow);
        Assert.True(ok.Admitted);
        Assert.Single(ok.Reservations!);
        Assert.Equal("principal/alice", ok.Reservations![0].Key);
        var over = Budgets.AdmitAggregateAction(ledger, ids, new[] { Acc("principal") }, null, Evt("e2", 60), Allow);
        Assert.False(over.Admitted);
        Assert.StartsWith("aggregate: over_cap: spend would reach 120 (cap 100)", over.Reason);
        Assert.True(Budgets.StartAggregate(ledger, ok.Reservations));
        Assert.Equal("settled", Budgets.SettleAggregate(ledger, ok.Reservations, "committed")[0].Outcome);
        var unbound = Budgets.AdmitAggregateAction(ledger, new Dictionary<string, string>(), new[] { Acc("org") }, null, Evt("e3", 1), Allow);
        Assert.False(unbound.Admitted);
        Assert.StartsWith("scope_unbound: ", unbound.Reason);
        var volatileLedger = new KvBudgetLedger(new MemoryAtomicKv(), false);
        Assert.Equal("not_durable", Assert.Throws<BudgetLedgerError>(() => Budgets.AdmitAggregateAction(volatileLedger, ids, new[] { Acc("principal") }, null, Evt("e4", 1), Allow)).Code);
        var denied = Budgets.AdmitAggregateAction(ledger, ids, new[] { Acc("principal") }, null, Evt("e5", 1), _ => new D { ["allow"] = false });
        Assert.Equal("verifier denied", denied.Reason);
    }
}
