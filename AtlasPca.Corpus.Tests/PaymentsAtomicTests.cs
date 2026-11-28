using AtlasPca.Payments;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using Pay = AtlasPca.Payments.Payments;

namespace AtlasPca.Corpus.Tests;

public class PaymentsAtomicTests
{
    static D Mandate()
    {
        var seed = Enumerable.Repeat((byte)5, 32).ToArray();
        return Pay.BuildPaymentMandate(new D
        {
            ["principalSecret"] = seed, ["agentPublic"] = EdKey.FromSeed(Enumerable.Repeat((byte)6, 32).ToArray()).Id, ["merchants"] = new L { "merchant_1" }, ["categories"] = new L(),
            ["currency"] = "USD", ["perTransactionCap"] = new Num("50000"), ["autoApproveThreshold"] = new Num("5000"), ["cumulativeCap"] = new Num("100000"),
            ["goalSalt"] = "c2FsdC0wMDAx", ["now"] = new Num("1800000000000"),
        });
    }

    static D Charge(long amount) => new() { ["merchant"] = "merchant_1", ["amount"] = new Num(amount.ToString()), ["currency"] = "USD", ["now"] = new Num("1800000001000") };
    static long B(D budget) => long.Parse(((Num)budget["B"]!).Raw);

    sealed class FlakyStore(IChargeBudgetStore inner, int failures) : IChargeBudgetStore
    {
        int _left = failures;
        public Task<ChargeBudgetRecord?> GetAsync(string key) => inner.GetAsync(key);
        public Task<bool> CompareAndSetAsync(string key, long? expected, D budget) => _left-- > 0 ? Task.FromResult(false) : inner.CompareAndSetAsync(key, expected, budget);
    }

    sealed class BadStore : IChargeBudgetStore
    {
        public Task<ChargeBudgetRecord?> GetAsync(string key) => Task.FromResult<ChargeBudgetRecord?>(new ChargeBudgetRecord(new D { ["B"] = "x" }, 1));
        public Task<bool> CompareAndSetAsync(string key, long? expected, D budget) => Task.FromResult(true);
    }

    [Fact]
    public async Task ADebitIsCommittedWithACompareAndSet()
    {
        var m = Mandate(); var grant = (D)m["grant"]!;
        var store = new MemoryChargeBudgetStore();
        var key = Pca.HashCanonical(grant);
        var d1 = await Pay.AuthorizeChargeAtomicAsync(m, Charge(3000), grant, store);
        Assert.Equal("auto", d1["outcome"]);
        var rec = (await store.GetAsync(key))!;
        Assert.Equal(1, rec.Version); Assert.Equal(97000, B(rec.Budget));
        var d2 = await Pay.AuthorizeChargeAtomicAsync(m, Charge(2000), grant, store);   // reads the stored budget, not the mandate's
        Assert.Equal("auto", d2["outcome"]);
        Assert.Equal(95000, B((await store.GetAsync(key))!.Budget));
        Assert.Equal(2, (await store.GetAsync(key))!.Version);
        // a step-up is not committed
        var d3 = await Pay.AuthorizeChargeAtomicAsync(m, Charge(20000), grant, store);
        Assert.NotEqual("auto", d3["outcome"]);
        Assert.Equal(2, (await store.GetAsync(key))!.Version);
    }

    [Fact]
    public async Task LosingTheRaceRedecidesAndPersistentContentionDenies()
    {
        var m = Mandate(); var grant = (D)m["grant"]!;
        var inner = new MemoryChargeBudgetStore();
        Assert.Equal("auto", (await Pay.AuthorizeChargeAtomicAsync(m, Charge(1000), grant, new FlakyStore(inner, 3))).GetValueOrDefault("outcome"));
        var denied = await Pay.AuthorizeChargeAtomicAsync(m, Charge(1000), grant, new FlakyStore(new MemoryChargeBudgetStore(), 100));
        Assert.Equal("deny", denied["outcome"]);
        Assert.Equal("budget_store_conflict", ((L)denied["reasons"]!)[0]);
        Assert.Equal(B((D)denied["budgetBefore"]!), B((D)denied["budgetAfter"]!));
        await Assert.ThrowsAsync<ChargeStoreException>(() => Pay.AuthorizeChargeAtomicAsync(m, Charge(1000), grant, new BadStore()));
        await Assert.ThrowsAsync<ChargeStoreException>(() => Pay.AuthorizeChargeAtomicAsync(m, Charge(1000), grant, null!));
    }

    [Fact]
    public async Task CosignRestoresTheBudgetAndNeverSilentlyDrops()
    {
        var m = Mandate(); var grant = (D)m["grant"]!;
        var store = new MemoryChargeBudgetStore();
        await Pay.AuthorizeChargeAtomicAsync(m, Charge(4000), grant, store);
        var next = await Pay.ApplyHumanCosignAtomicAsync(m, grant, store, 1800000002000, full: true);
        Assert.Equal(100000, B(next));
        Assert.Equal(100000, B((await store.GetAsync(Pca.HashCanonical(grant)))!.Budget));
        await Assert.ThrowsAsync<ChargeStoreException>(() => Pay.ApplyHumanCosignAtomicAsync(m, grant, new FlakyStore(new MemoryChargeBudgetStore(), 100), 1, true));
    }
}
