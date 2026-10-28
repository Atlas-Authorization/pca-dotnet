using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The reusable store-conformance helper: the in-process stores pass, and the harness catches a non-atomic claim, a non-atomic create
// and stores that forget between handles (negative controls: a helper that cannot fail proves nothing).
public class StoreConformanceTests
{
    static StateStoreConformance MemoryState(bool shared, bool durable)
    {
        var st = new MemoryStateStore();
        return new StateStoreConformance { Name = "memory", Open = () => st, Shared = shared, Durable = durable };
    }

    [Fact]
    public void TheMemoryStatePasses()
    {
        // one process, state dies with it: the durability checks are skipped, never passed
        var r = StoreConformance.RunStateStore(MemoryState(true, false));
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(("pass", "pass", "pass", "skip", "skip"),
            (r.StatusOf("claim-burst"), r.StatusOf("claim-concurrent"), r.StatusOf("retry-after-timeout"), r.StatusOf("claim-durability"), r.StatusOf("crash-after-claim")));
        // reopened against itself, the process-local store keeps its state
        Assert.True(StoreConformance.RunStateStore(MemoryState(true, true)).Ok);
        Assert.True(StoreConformance.RunStateStore(MemoryState(false, false)).Ok);
    }

    /// <summary>A claim that reads, waits and then writes admits many copies of one counter.</summary>
    sealed class RacyStore : IStateStore
    {
        readonly Dictionary<string, long> _last = new();
        readonly object _lock = new();

        public ClaimResult? Claim(string key, long n)
        {
            long? last = null;
            lock (_lock) if (_last.TryGetValue(key, out var l)) last = l;
            if (last is long x && n <= x) return new ClaimResult(false, x);
            Thread.Sleep(1);
            lock (_lock) _last[key] = n;
            return new ClaimResult(true);
        }
    }

    [Fact]
    public void ANonAtomicClaimIsCaught()
    {
        var st = new RacyStore();
        var r = StoreConformance.RunStateStore(new StateStoreConformance { Name = "racy", Open = () => st, Shared = true });
        Assert.False(r.Ok);
        Assert.Equal("fail", r.StatusOf("claim-concurrent"));
        Assert.Equal("pass", r.StatusOf("claim-burst")); // sequentially the racy store is correct
        Assert.Contains("FAIL", r.ToString());
    }

    [Fact]
    public void AStoreThatForgetsIsCaught()
    {
        // every Open is a fresh empty store, yet it claims durability and sharing
        var r = StoreConformance.RunStateStore(new StateStoreConformance { Name = "forgetful", Open = () => new MemoryStateStore(), Shared = true, Durable = true });
        foreach (var name in new[] { "claim-durability", "crash-after-claim", "retry-after-timeout" })
            Assert.True(r.StatusOf(name) == "fail", $"{name} must fail for a store that forgets:\n{r}");
        Assert.False(StoreConformance.RunStateStore(new StateStoreConformance { Name = "no open" }).Ok);
    }

    [Fact]
    public void TheOperationStoresPass()
    {
        var mem = new MemoryOperationStore();
        var r1 = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "memory", Open = () => mem, Shared = true, Durable = true });
        Assert.True(r1.Ok, r1.ToString());
        var kv = new MemoryAtomicKv();
        var r2 = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "kv", Open = () => new KvOperationStore(kv), Shared = true, Durable = true });
        Assert.True(r2.Ok, r2.ToString());
        var r3 = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "memory", Open = () => mem });
        Assert.Equal(("skip", "skip"), (r3.StatusOf("shared"), r3.StatusOf("durability")));
    }

    /// <summary>A create that checks and then writes is not create-if-absent.</summary>
    sealed class RacyOperationStore : IOperationStore
    {
        readonly Dictionary<string, OperationRecord> _m = new();
        readonly object _lock = new();

        public (bool Created, OperationRecord? Existing) Create(OperationRecord record)
        {
            lock (_lock) if (_m.TryGetValue(record.Id, out var cur)) return (false, cur);
            Thread.Sleep(1);
            lock (_lock) _m[record.Id] = record;
            return (true, null);
        }

        public OperationRecord? Get(string id) { lock (_lock) return _m.GetValueOrDefault(id); }

        public bool Transition(string id, string from, OperationRecord next)
        {
            lock (_lock)
            {
                if (!_m.TryGetValue(id, out var cur) || cur.State != from) return false;
                _m[id] = next with { Id = id };
                return true;
            }
        }
    }

    [Fact]
    public void ANonAtomicCreateIsCaughtAndAForgetfulStoreFailsSharedAndDurability()
    {
        var racy = new RacyOperationStore();
        var r = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "racy", Open = () => racy, Shared = true });
        Assert.False(r.Ok);
        Assert.Equal("fail", r.StatusOf("create-once"));
        var f = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "forgetful", Open = () => new MemoryOperationStore(), Shared = true, Durable = true });
        Assert.Equal(("fail", "fail"), (f.StatusOf("shared"), f.StatusOf("durability")));
    }
}
