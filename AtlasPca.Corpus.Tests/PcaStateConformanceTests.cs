using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The pca-state profile: the in-memory reference store passes (one instance), a store only an in-process lock can serialise is refused as a
// multi-instance one, and a check-then-act store is caught by the one-instance race.
public class PcaStateConformanceTests
{
    [Fact]
    public void TheReferenceStorePasses()
    {
        // each open is a clean store: the checks share no claims (a proof one check claimed is not admitted again in the next)
        var r = StoreConformance.RunPcaState(new PcaStateConformance { Name = "memory", Open = () => new MemoryStateStore(), Shared = false, Durable = false });
        Assert.True(r.Ok, r.ToString());
        Assert.Equal("pass", r.StatusOf("one-instance"));
        Assert.Equal("pass", r.StatusOf("retry-after-timeout"));
        Assert.Equal("skip", r.StatusOf("instances"));
        Assert.Equal("skip", r.StatusOf("processes"));
        Assert.Equal("skip", r.StatusOf("crash-after-claim"));
    }

    [Fact]
    public void AProcessScopedStoreIsRefusedMultiInstance()
    {
        var st = new MemoryStateStore();
        var r = StoreConformance.RunPcaState(new PcaStateConformance { Name = "memory", Open = () => st, Shared = true, Durable = false });
        Assert.Equal("fail", r.StatusOf("instances"));
    }

    sealed class RacyStore : IStateStore
    {
        readonly Dictionary<string, long> _last = new();
        readonly object _lock = new();
        public StoreScope Scope => StoreScope.Shared;

        public ClaimResult? Claim(string key, long n)
        {
            long? last = null;
            lock (_lock) if (_last.TryGetValue(key, out var l)) last = l;
            if (last is long x && n <= x) return new ClaimResult(false, x);
            Thread.Sleep(5);
            lock (_lock) _last[key] = n;
            return new ClaimResult(true);
        }
    }

    [Fact]
    public void ACheckThenActStoreIsCaught()
    {
        var st = new RacyStore();
        var r = StoreConformance.RunPcaState(new PcaStateConformance { Name = "racy", Open = () => st, Shared = false, Durable = false, Rounds = 3 });
        Assert.Equal("fail", r.StatusOf("one-instance"));
        Assert.False(r.Ok);
    }
}
