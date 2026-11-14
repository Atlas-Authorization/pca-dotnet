using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.ContractsKillSupport;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for <see cref="LeaseRegistry"/>: the shard hash, construction guards, the pinned shard count in the store, and every store-failure path.</summary>
public class LeaseKillTests2
{
    const long T0 = 1_800_000_000_000L;
    const string Meta = "lease/meta";
    static EdKey Auth => Key(43);

    static JD Mk(string id = "l1") => Sign(new JD
    {
        ["v"] = 1L, ["lease_id"] = id, ["path"] = "svc/" + id, ["grant_ref"] = "g", ["holder"] = "h", ["requester"] = "r", ["approvers"] = new JL { "a" },
        ["justification_digest"] = "j", ["seq"] = 1L, ["issued_at"] = T0, ["renewed_at"] = T0, ["expires_at"] = T0 + 1000, ["max_ttl"] = 86_400_000L, ["authority"] = Auth.Id,
    }, Lease.Domain, Auth);

    static JD Rev(string id = "l1") => Sign(new JD { ["v"] = 1L, ["target"] = "lease", ["value"] = id, ["revoked_at"] = T0 + 5, ["authority"] = Auth.Id }, Lease.RevokeDomain, Auth);

    static LeasePolicy Policy => new(new[] { Auth.Id });

    static LeaseRegistry Reg(IAtomicKv kv, int shards = LeaseRegistry.DefaultShards) => new(Policy, kv, new LeaseRegistryOptions(Shards: shards));

    [Fact]
    public void ShardOfIsTheFirstFourHashBytesBigEndianModTheShardCount()
    {
        var ids = new[] { "L1", "agent", "a", "bg1", "holder-7", "alice", "db/prod/ro", "", "zz9", "lease-0042", "Ωmega", new string('x', 40) };
        var counts = new[] { 7, 4093, 16, 4096 };
        var want = new[]
        {
            new[] { 6, 3374, 6, 1430 }, new[] { 1, 251, 10, 3162 }, new[] { 2, 1178, 2, 274 }, new[] { 3, 2847, 3, 115 },
            new[] { 4, 2522, 1, 721 }, new[] { 0, 213, 9, 1737 }, new[] { 4, 391, 5, 3829 }, new[] { 1, 3431, 2, 1090 },
            new[] { 0, 3292, 7, 1463 }, new[] { 4, 358, 11, 1451 }, new[] { 1, 256, 2, 2962 }, new[] { 4, 477, 6, 4086 },
        };
        for (int i = 0; i < ids.Length; i++)
            for (int j = 0; j < counts.Length; j++)
                Assert.True(LeaseRegistry.ShardOf(ids[i], counts[j]) == want[i][j], $"{ids[i]} / {counts[j]}: {LeaseRegistry.ShardOf(ids[i], counts[j])} vs {want[i][j]}");
        Assert.Equal(0, LeaseRegistry.ShardOf("L1", 1));
    }

    [Fact]
    public void TheConstructorRefusesWhatItCannotRunOn()
    {
        var none = Assert.Throws<ArgumentException>(() => new LeaseRegistry(Policy, null!));
        Assert.StartsWith("LeaseRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)", none.Message);
        foreach (var bad in new[] { 0, -1, 4097 })
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: bad)));
            Assert.Equal("options", e.ParamName);
            Assert.StartsWith("LeaseRegistry: shards must be an integer from 1 to 4096", e.Message);
        }
        Assert.Equal(1, new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 1)).ShardCount);
        Assert.Equal(4096, new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 4096)).ShardCount);
        Assert.Equal(16, new LeaseRegistry(Policy, new MemoryAtomicKv()).ShardCount);
    }

    [Fact]
    public void TheShardCountIsPinnedInTheStoreOnFirstUse()
    {
        var kv = new MemoryAtomicKv();
        Assert.Null(kv.Get(Meta));
        Assert.True(Reg(kv).Accept(Mk()).Ok);
        Assert.Equal("{\"shards\":16,\"v\":1}", kv.Get(Meta));
        var four = new MemoryAtomicKv();
        Assert.True(Reg(four, 4).Accept(Mk()).Ok);
        Assert.Equal("{\"shards\":4,\"v\":1}", four.Get(Meta));
        // a first writer wins: a registry of another count is refused rather than overwriting the pin
        Assert.Equal(new LeaseAccept(false, "store_unreachable"), Reg(four, 8).Accept(Mk("l2")));
        Assert.Equal("{\"shards\":4,\"v\":1}", four.Get(Meta));
    }

    [Fact]
    public void AMismatchedShardCountIsStoreUnreachableEverywhere()
    {
        var kv = new ContractsKillFaultKv();
        kv.Inner.Update(Meta, _ => "{\"shards\":8,\"v\":1}");
        var reg = Reg(kv, 4);
        Assert.Equal(new LeaseAccept(false, "store_unreachable"), reg.Accept(Mk()));
        Assert.Equal(new LeaseRevoke(false, "store_unreachable"), reg.Revoke(Rev()));
        var e = Assert.Throws<InvalidOperationException>(() => reg.Get("l1"));
        Assert.Equal("shard count mismatch", e.Message);
        Assert.Throws<InvalidOperationException>(() => reg.History("l1"));
        Assert.Equal(new LeaseDecision("deny", "store_unreachable", "l1"), Lease.Check(Mk(), reg, IntentJs.OfLong(T0)));
    }

    [Fact]
    public void AStoreThatDoesNothingOrFailsIsNeverAnAcceptance()
    {
        foreach (var skip in new[] { true, false })
        {
            var kv = new ContractsKillFaultKv { Affects = k => k != Meta };
            var reg = Reg(kv);
            Assert.True(reg.Accept(Mk("ok")).Ok);
            kv.UpdateSkips = skip;
            kv.UpdateThrows = !skip;
            Assert.Equal(new LeaseAccept(false, "store_unreachable"), reg.Accept(Mk("l1")));
            Assert.Equal(new LeaseRevoke(skip, skip ? null : "store_unreachable", 0), reg.Revoke(Rev("l1")));
            kv.UpdateSkips = kv.UpdateThrows = false;
            Assert.Null(reg.Get("l1"));
        }
    }

    [Fact]
    public void ARevocationOfOneLeaseWritesOnlyThatShard()
    {
        var kv = new ContractsKillFaultKv();
        var reg = Reg(kv);
        Assert.True(reg.Accept(Mk()).Ok);
        Assert.Equal(new LeaseRevoke(true, null, 1), reg.Revoke(Rev()));
        var home = LeaseRegistry.ShardOf("l1", 16);
        for (int i = 0; i < 16; i++) Assert.Equal(i == home ? 1 : 0, reg.ShardRevocations(i).Count);
    }

    [Fact]
    public void ShardRevocationsBoundsTheIndex()
    {
        var reg = Reg(new MemoryAtomicKv(), 4);
        Assert.Empty(reg.ShardRevocations(0));
        Assert.Empty(reg.ShardRevocations(3));
        foreach (var bad in new[] { -1, 4, 5 })
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => reg.ShardRevocations(bad));
            Assert.Equal("i", e.ParamName);
            Assert.StartsWith("no such shard", e.Message);
        }
    }
}
