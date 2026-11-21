using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// F11: the store-conformance kits for the atomic key-value store, the trust-budget store and the pin store, run against the in-process stores
// (they pass) and against deliberately broken ones (negative controls: each fails the check that names its defect).
public class K05F11Tests
{
    sealed class LossyKv : IAtomicKv
    {
        readonly Dictionary<string, string> _m = new();
        readonly object _lock = new();
        public string? Get(string key) { lock (_lock) return _m.GetValueOrDefault(key); }
        public void Update(string key, Func<string?, string?> fn)
        {
            var prev = Get(key); // read outside the lock, write after a pause: a concurrent writer's update is lost
            var next = fn(prev);
            Thread.Sleep(1);
            if (next != null) lock (_lock) _m[key] = next;
        }
    }

    sealed class LoweringPins : IPinStore
    {
        readonly Dictionary<string, long> _m = new();
        public long? Pin(string key) => _m.TryGetValue(key, out var v) ? v : null;
        public long RaisePin(string key, long value)
        {
            if (string.IsNullOrEmpty(key) || value < 0) throw new ArgumentException("bad");
            lock (_m) { _m[key] = value; return value; } // sets, never compares
        }
    }

    sealed class AlwaysWinsBudget : IBudgetStore
    {
        readonly Dictionary<string, TrustBudget> _m = new();
        public TrustBudget? Budget(string key) { lock (_m) return _m.GetValueOrDefault(key); }
        public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new) { lock (_m) { _m[key] = @new; return true; } }
    }

    [Fact]
    public void TheInProcessStoresPassEveryCheck()
    {
        var kv = new MemoryAtomicKv();
        var r1 = StoreConformance.RunAtomicKv(new AtomicKvConformance { Name = "memory", Open = () => kv, Shared = true, Durable = false });
        Assert.True(r1.Ok, r1.ToString());
        Assert.Equal("skip", r1.StatusOf("durability"));
        Assert.Equal("pass", r1.StatusOf("update-concurrent"));
        var ms = new MemoryStateStore();
        var r2 = StoreConformance.RunBudgetStore(new BudgetStoreConformance { Name = "memory", Open = () => ms, Shared = true, Durable = true });
        Assert.True(r2.Ok, r2.ToString());
        Assert.Equal("pass", r2.StatusOf("cas-concurrent"));
        var r3 = StoreConformance.RunPinStore(new PinStoreConformance { Name = "memory", Open = () => ms, Shared = true, Durable = true });
        Assert.True(r3.Ok, r3.ToString());
        Assert.Equal("pass", r3.StatusOf("raise-concurrent"));
    }

    [Fact]
    public void ALossyKvFailsTheConcurrentUpdateCheck()
    {
        var kv = new LossyKv();
        var r = StoreConformance.RunAtomicKv(new AtomicKvConformance { Name = "lossy", Open = () => kv, Shared = true });
        Assert.False(r.Ok);
        Assert.Equal("fail", r.StatusOf("update-concurrent"));
        Assert.Equal("pass", r.StatusOf("update-creates-and-replaces"));
    }

    [Fact]
    public void APinStoreThatLowersFailsTheMonotoneCheck()
    {
        var s = new LoweringPins();
        var r = StoreConformance.RunPinStore(new PinStoreConformance { Name = "lowering", Open = () => s, Shared = true });
        Assert.False(r.Ok);
        Assert.Equal("fail", r.StatusOf("raise-monotone"));
    }

    [Fact]
    public void ABudgetStoreThatAlwaysSwapsFailsTheCasChecks()
    {
        var s = new AlwaysWinsBudget();
        var r = StoreConformance.RunBudgetStore(new BudgetStoreConformance { Name = "always", Open = () => s, Shared = true });
        Assert.False(r.Ok);
        Assert.Equal("fail", r.StatusOf("cas-wrong-old"));
        Assert.Equal("fail", r.StatusOf("cas-concurrent"));
    }

    [Fact]
    public void AMissingOpenIsAFailedReport()
    {
        Assert.False(StoreConformance.RunAtomicKv(new AtomicKvConformance()).Ok);
        Assert.False(StoreConformance.RunBudgetStore(new BudgetStoreConformance()).Ok);
        Assert.False(StoreConformance.RunPinStore(new PinStoreConformance()).Ok);
    }

    [Fact]
    public void ADurableClaimIsCheckedAcrossARestart()
    {
        var kv = new MemoryAtomicKv();
        var restarted = 0;
        var r = StoreConformance.RunAtomicKv(new AtomicKvConformance { Name = "memory", Open = () => kv, Durable = true, Restart = () => restarted++ });
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(1, restarted);
    }
}
