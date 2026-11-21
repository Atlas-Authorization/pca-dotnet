using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.ContractsKillSupport;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for <see cref="BreakGlassRegistry"/>: construction guards, the pinned shard count, and every store-failure path.</summary>
public class BreakGlassKillTests2
{
    const long T0 = 1_800_000_000_000L;
    const string Meta = "breakglass/meta";
    static EdKey Auth => Key(51);
    static EdKey Reviewer => Key(52);

    static JD Grant(string id = "bg1", string holder = "agent") => Sign(new JD
    {
        ["v"] = 1L, ["id"] = id, ["holder"] = holder, ["grant_ref"] = "g", ["reason_digest"] = "r", ["max_uses"] = 2L, ["issued_at"] = T0,
        ["expires_at"] = T0 + 3_600_000L, ["review_within"] = 1_800_000L, ["notify_to"] = "ops", ["authority"] = Auth.Id,
    }, BreakGlass.Domain, Auth);

    static JD Review(string id = "bg1") => Sign(new JD
    {
        ["v"] = 1L, ["id"] = id, ["outcome"] = "justified", ["notes_digest"] = "n", ["at"] = T0 + 10, ["reviewer"] = Reviewer.Id,
    }, BreakGlass.ReviewDomain, Reviewer);

    static BreakGlassRegistry Reg(IAtomicKv kv, int shards = LeaseRegistry.DefaultShards) =>
        new(new BreakGlassPolicy(new[] { Auth.Id }, new[] { Reviewer.Id }), kv, shards);

    static object At(long ms) => IntentJs.OfLong(ms);

    [Fact]
    public void TheConstructorRefusesWhatItCannotRunOn()
    {
        var policy = new BreakGlassPolicy(new[] { Auth.Id }, new[] { Reviewer.Id });
        var none = Assert.Throws<ArgumentException>(() => new BreakGlassRegistry(policy, null!));
        Assert.StartsWith("BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)", none.Message);
        foreach (var bad in new[] { 0, -1, 4097 })
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => new BreakGlassRegistry(policy, new MemoryAtomicKv(), bad));
            Assert.Equal("shards", e.ParamName);
            Assert.StartsWith("BreakGlassRegistry: shards must be an integer from 1 to 4096", e.Message);
        }
        Assert.NotNull(new BreakGlassRegistry(policy, new MemoryAtomicKv(), 1));
        // 4096 is the largest valid count and works end to end
        var big = Reg(new MemoryAtomicKv(), 4096);
        Assert.True(big.Accept(Grant(), At(T0)).Ok);
    }

    [Fact]
    public void TheShardCountIsPinnedOnceAndNotRewritten()
    {
        var kv = new MemoryAtomicKv();
        Assert.Null(kv.Get(Meta));
        Assert.True(Reg(kv).Accept(Grant(), At(T0)).Ok);
        Assert.Equal("{\"shards\":16,\"v\":1}", kv.Get(Meta));
        var four = new MemoryAtomicKv();
        Assert.True(Reg(four, 4).Accept(Grant(), At(T0)).Ok);
        Assert.Equal("{\"shards\":4,\"v\":1}", four.Get(Meta));
        // another count does not overwrite the pin and is refused
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), Reg(four, 8).Accept(Grant("bg2"), At(T0)));
        Assert.Equal("{\"shards\":4,\"v\":1}", four.Get(Meta));
    }

    [Fact]
    public void AMismatchedShardCountIsStoreUnreachableAndFrozen()
    {
        var kv = new MemoryAtomicKv();
        kv.Update(Meta, _ => "{\"shards\":8,\"v\":1}");
        var reg = Reg(kv, 4);
        Assert.True(reg.IsFrozen("agent", At(T0)));
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Accept(Grant(), At(T0)));
        Assert.Equal(new BreakGlassDecision("deny", "store_unreachable", "bg1"), reg.Use("bg1", "agent", "act", At(T0), true));
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Review(Review(), "agent", At(T0 + 20)));
        Assert.Empty(reg.Uses("agent", "bg1"));
    }

    [Fact]
    public void AStoreThatDoesNothingOrFailsIsNeverARecordedUse()
    {
        foreach (var skip in new[] { true, false })
        {
            var kv = new ContractsKillFaultKv { Affects = k => k != Meta };
            var reg = Reg(kv);
            Assert.True(reg.Accept(Grant(), At(T0)).Ok);
            Assert.Equal("allow", reg.Use("bg1", "agent", "act-1", At(T0 + 1), true).Decision);
            kv.UpdateSkips = skip;
            kv.UpdateThrows = !skip;
            Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Accept(Grant("bg2"), At(T0)));
            Assert.Equal(new BreakGlassDecision("deny", "store_unreachable", "bg1"), reg.Use("bg1", "agent", "act-2", At(T0 + 2), true));
            Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Review(Review(), "agent", At(T0 + 20)));
            kv.UpdateSkips = kv.UpdateThrows = false;
            // nothing of the failed calls was recorded
            Assert.Equal(new[] { new BreakGlassUseEntry(1, "act-1", T0 + 1) }, reg.Uses("agent", "bg1").ToArray());
            Assert.False(reg.IsFrozen("agent", At(T0 + 3)));
            Assert.Equal("unknown_break_glass", reg.Use("bg2", "agent", "act", At(T0 + 3), true).Code);
            Assert.True(reg.Review(Review(), "agent", At(T0 + 20)).Replaced);
        }
    }

    [Fact]
    public void AStoreThatCannotBeReadIsFrozen()
    {
        var kv = new ContractsKillFaultKv { Affects = k => k != Meta };
        var reg = Reg(kv);
        Assert.True(reg.Accept(Grant(), At(T0)).Ok);
        Assert.False(reg.IsFrozen("agent", At(T0 + 1)));
        kv.GetThrows = true;
        Assert.True(reg.IsFrozen("agent", At(T0 + 1)));
    }

    [Fact]
    public void MalformedInputIsFrozenAndRefused()
    {
        var reg = Reg(new MemoryAtomicKv());
        Assert.True(reg.IsFrozen("", At(T0)));
        Assert.True(reg.IsFrozen(null, At(T0)));
        Assert.True(reg.IsFrozen("agent", "1800000000000"));
        Assert.True(reg.IsFrozen("agent", null));
        Assert.False(reg.IsFrozen("agent", At(T0)));
        Assert.Equal("bad_input", reg.Use("bg1", "agent", "act", At(T0), "yes").Code);
        Assert.Equal("bad_input", reg.Use("bg1", "agent", "act", At(T0), null).Code);
    }
}
