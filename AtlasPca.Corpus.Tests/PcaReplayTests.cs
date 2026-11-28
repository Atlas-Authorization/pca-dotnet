using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The standalone replay guard: the check order, the nonce consumed once, the counter stream, the store failing closed, the in-memory store's contract.</summary>
public class PcaReplayTests
{
    static D Act(long iat = 1000, long exp = 2000, long counter = 1, string? nonce = "n1", string aud = "rs") => new()
    {
        ["aud"] = aud, ["iat"] = iat, ["exp"] = exp, ["counter"] = counter, ["grant_ref"] = "g", ["nonce"] = nonce,
        ["cap_chain"] = new L { new D { ["holder"] = "h" } },
    };

    static ReplayGuardOptions O(double now = 1500, ICounterStore? c = null, bool req = true, double? skew = null) => new("rs", now, skew, req, c);

    sealed class Boom : Events.IReplayStore
    {
        public Task<bool> ConsumeOnce(string key, double retainUntilMs, double nowMs) => throw new InvalidOperationException("down");
    }

    [Fact]
    public async Task AcceptsOnceThenDeniesAReplay()
    {
        var s = new InMemoryReplayStore();
        Assert.True((await PcaReplay.GuardPCActnReplay(s, Act(), O())).Ok);
        var r = await PcaReplay.GuardPCActnReplay(s, Act(), O());
        Assert.False(r.Ok);
        Assert.Equal("replay", r.Code);
        Assert.Equal(1, s.Size);
    }

    [Fact]
    public async Task PreChecksRunBeforeAnyStoreCall()
    {
        var s = new InMemoryReplayStore();
        Assert.Equal("audience", (await PcaReplay.GuardPCActnReplay(s, Act(aud: "other"), O())).Code);
        Assert.Equal("not_yet_valid", (await PcaReplay.GuardPCActnReplay(s, Act(iat: 100000, exp: 101000), O(now: 1000))).Code);
        Assert.Equal("expired", (await PcaReplay.GuardPCActnReplay(s, Act(), O(now: 2001))).Code);
        Assert.Equal("malformed", (await PcaReplay.GuardPCActnReplay(s, Act(iat: 2000, exp: 1000), O())).Code);
        Assert.Equal("malformed", (await PcaReplay.GuardPCActnReplay(s, null, O())).Code);
        Assert.Equal("malformed", (await PcaReplay.GuardPCActnReplay(s, Act(), new ReplayGuardOptions("", 1500))).Code);
        Assert.Equal(0, s.Size);
    }

    [Fact]
    public async Task SkewAllowsAFutureIatUpToTheCeiling()
    {
        var s = new InMemoryReplayStore();
        Assert.True((await PcaReplay.GuardPCActnReplay(s, Act(iat: 1000), O(now: 950, skew: 60))).Ok);
        Assert.Equal("not_yet_valid", (await PcaReplay.GuardPCActnReplay(s, Act(iat: 100000, exp: 101000, nonce: "n2"), O(now: 1000, skew: 1e9))).Code);
    }

    [Fact]
    public async Task ANonceIsRequiredUnlessWaived()
    {
        var s = new InMemoryReplayStore();
        var noNonce = Act();
        noNonce.Remove("nonce");
        Assert.Equal("malformed", (await PcaReplay.GuardPCActnReplay(s, noNonce, O())).Code);
        Assert.True((await PcaReplay.GuardPCActnReplay(s, noNonce, O(req: false))).Ok);
        Assert.Equal("malformed", (await PcaReplay.GuardPCActnReplay(s, Act(nonce: ""), O())).Code);
    }

    [Fact]
    public async Task TheCounterStreamMustRise()
    {
        var s = new InMemoryReplayStore();
        Assert.True((await PcaReplay.GuardPCActnReplay(s, Act(counter: 5, nonce: "a"), O(c: s))).Ok);
        var r = await PcaReplay.GuardPCActnReplay(s, Act(counter: 5, nonce: "b"), O(c: s));
        Assert.Equal("replay", r.Code);
        Assert.True((await PcaReplay.GuardPCActnReplay(s, Act(counter: 6, nonce: "c"), O(c: s))).Ok);
    }

    [Fact]
    public async Task AStoreFailureIsADenial()
    {
        var r = await PcaReplay.GuardPCActnReplay(new Boom(), Act(), O());
        Assert.Equal("store_unavailable", r.Code);
        Assert.Contains("down", r.Reason);
    }

    [Fact]
    public async Task TheInMemoryStoreFailsClosedWhenFullAndPrunesOnlyExpired()
    {
        var s = new InMemoryReplayStore(2);
        Assert.True(await s.ConsumeOnce("a", 100, 10));
        Assert.True(await s.ConsumeOnce("b", 200, 10));
        await Assert.ThrowsAsync<InvalidOperationException>(() => s.ConsumeOnce("c", 300, 10));
        Assert.True(await s.ConsumeOnce("c", 300, 150)); // a expired and was pruned to make room
        Assert.False(await s.ConsumeOnce("b", 400, 150));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => s.ConsumeOnce("", 1, 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => s.ConsumeOnce("x", 1, 2));
        Assert.Equal(1, s.Prune(250));
    }

    [Fact]
    public async Task TheCounterStoreRefusesBadInput()
    {
        var s = new InMemoryReplayStore();
        Assert.True(await s.Advance("k", 0));
        Assert.False(await s.Advance("k", 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => s.Advance("k", -1));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => s.Advance("", 1));
    }

    [Fact]
    public void KeysAreInjectiveAndRefuseLoneSurrogates()
    {
        Assert.NotEqual(PcaReplay.ReplayKey("ns", "ab", "c"), PcaReplay.ReplayKey("ns", "a", "bc"));
        Assert.StartsWith("ns:", PcaReplay.ReplayKey("ns", "x"));
        Assert.Throws<ArgumentException>(() => PcaReplay.ReplayKey("ns", "\ud800"));
        Assert.Equal(3_600_000 + 2 * 60_000, PcaReplay.ReplayMinRetentionMs);
    }
}
