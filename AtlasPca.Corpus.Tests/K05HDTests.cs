using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>0.5 hardening (track D): lease, break-glass and blueprint registries REQUIRE a durable store; a second registry over the same store sees the
/// first one's state; any store failure is store_unreachable; the blueprint admission hook.</summary>
public class K05HDTests
{
    const long T0 = 1_800_000_000_000L, HOUR = 3_600_000L;
    static EdKey Auth => EdKey.FromSeed(Enumerable.Repeat((byte)61, 32).ToArray());
    static EdKey Reviewer => EdKey.FromSeed(Enumerable.Repeat((byte)62, 32).ToArray());

    /// <summary>A store that can be told to fail.</summary>
    sealed class FlakyKv : IAtomicKv
    {
        public readonly MemoryAtomicKv Inner = new();
        public bool Fail;
        public string? Get(string key) => Fail ? throw new InvalidOperationException("store down") : Inner.Get(key);
        public void Update(string key, Func<string?, string?> fn)
        {
            if (Fail) throw new InvalidOperationException("store down");
            Inner.Update(key, fn);
        }
    }

    // ---------------------------------------------------------------- leases

    static D Sign(D body, string domain) { var b = Issue.NormJ(body); return new D(b) { ["sig"] = Issue.SignBody(Auth, domain, b) }; }

    static D Lease(string id, long seq = 1, long issued = T0, long renewed = T0, long expires = T0 + HOUR, string justification = "j1", long maxTtl = 24 * HOUR) => Sign(new D
    {
        ["v"] = 1L, ["lease_id"] = id, ["path"] = "svc/" + id.ToLowerInvariant(), ["grant_ref"] = "g", ["holder"] = "h", ["requester"] = "r", ["approvers"] = new L { "a" }, // the lease path alphabet is lowercase
        ["justification_digest"] = justification, ["seq"] = seq, ["issued_at"] = issued, ["renewed_at"] = renewed, ["expires_at"] = expires, ["max_ttl"] = maxTtl, ["authority"] = Auth.Id,
    }, AtlasPca.Lease.Domain);

    static D Revoke(string target, string value, long at) =>
        Sign(new D { ["v"] = 1L, ["target"] = target, ["value"] = value, ["revoked_at"] = at, ["authority"] = Auth.Id }, AtlasPca.Lease.RevokeDomain);

    static LeasePolicy Policy => new(new[] { Auth.Id });

    [Fact]
    public void ALeaseRegistryWithoutAStoreIsRefused()
    {
        var e = Assert.Throws<ArgumentException>(() => new LeaseRegistry(Policy, null!));
        Assert.StartsWith("LeaseRegistry: a durable key-value store is required (", e.Message);
        Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 4097)));
        Assert.Equal(1, new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 1)).ShardCount);
        Assert.Equal(4096, new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 4096)).ShardCount);
        Assert.Equal(16, new LeaseRegistry(Policy, new MemoryAtomicKv()).ShardCount);
    }

    [Fact]
    public void ARevocationSurvivesANewRegistryOverTheSameStore()
    {
        var kv = new MemoryAtomicKv();
        var first = new LeaseRegistry(Policy, kv);
        var rec = Lease("L1");
        Assert.True(first.Accept(rec).Ok);
        Assert.Equal("allow", AtlasPca.Lease.Check(rec, first, IntentJs.OfLong(T0 + 1)).Decision);
        Assert.Equal(1, first.Revoke(Revoke("lease", "L1", T0 + 2)).Revoked);
        // a "restart": a new registry over the same store still knows the lease and its revocation
        var second = new LeaseRegistry(Policy, kv);
        var d = AtlasPca.Lease.Check(rec, second, IntentJs.OfLong(T0 + 3));
        Assert.Equal("deny", d.Decision);
        Assert.Equal("revoked", d.Code);
        Assert.Equal("L1", d.LeaseId);
        // a record issued at or before the revocation stays covered, on the new registry too
        Assert.Equal("revoked", second.Accept(Lease("L1", 1, T0 + 2, T0 + 2, T0 + 2 + HOUR)).Code);
    }

    [Fact]
    public void APrefixRevocationReachesEveryShard()
    {
        var kv = new MemoryAtomicKv();
        var reg = new LeaseRegistry(Policy, kv, new LeaseRegistryOptions(Shards: 4));
        foreach (var id in new[] { "a", "b", "c", "d", "e", "f" }) Assert.True(reg.Accept(Lease(id)).Ok);
        Assert.Equal(6, reg.Revoke(Revoke("prefix", "svc", T0 + 5)).Revoked);
        for (int i = 0; i < 4; i++) Assert.Single(reg.ShardRevocations(i));
        Assert.Throws<ArgumentOutOfRangeException>(() => reg.ShardRevocations(4));
        Assert.Throws<ArgumentOutOfRangeException>(() => reg.ShardRevocations(-1));
        // a revocation of one lease id is written to that lease's shard only
        var one = new LeaseRegistry(Policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Shards: 4));
        Assert.True(one.Accept(Lease("a")).Ok);
        Assert.Equal(1, one.Revoke(Revoke("lease", "a", T0 + 5)).Revoked);
        Assert.Equal(1, Enumerable.Range(0, 4).Count(i => one.ShardRevocations(i).Count == 1));
    }

    [Fact]
    public void ALeaseStoreThatFailsIsStoreUnreachableNeverAPass()
    {
        var kv = new FlakyKv();
        var reg = new LeaseRegistry(Policy, kv);
        var rec = Lease("L1");
        Assert.True(reg.Accept(rec).Ok);
        kv.Fail = true;
        Assert.Equal(new LeaseAccept(false, "store_unreachable"), reg.Accept(Lease("L2")));
        Assert.Equal(new LeaseRevoke(false, "store_unreachable"), reg.Revoke(Revoke("lease", "L1", T0 + 2)));
        var d = AtlasPca.Lease.Check(rec, reg, IntentJs.OfLong(T0 + 1));
        Assert.Equal(new LeaseDecision("deny", "store_unreachable", "L1"), d);
        Assert.Throws<InvalidOperationException>(() => reg.Get("L1"));
        // a store that answers again is trusted again, and nothing was half-written
        kv.Fail = false;
        Assert.Equal("allow", AtlasPca.Lease.Check(rec, reg, IntentJs.OfLong(T0 + 1)).Decision);
        Assert.Null(reg.Get("L2"));
    }

    [Fact]
    public void AStoreOpenedWithAnotherShardCountIsRefused()
    {
        var kv = new MemoryAtomicKv();
        Assert.True(new LeaseRegistry(Policy, kv, new LeaseRegistryOptions(Shards: 16)).Accept(Lease("L1")).Ok);
        var other = new LeaseRegistry(Policy, kv, new LeaseRegistryOptions(Shards: 8));
        Assert.Equal("store_unreachable", other.Accept(Lease("L2")).Code);
        Assert.Equal("store_unreachable", AtlasPca.Lease.Check(Lease("L1"), other, IntentJs.OfLong(T0 + 1)).Code);
    }

    [Fact]
    public void ConcurrentRenewalsLetExactlyOneWin()
    {
        var reg = new LeaseRegistry(Policy, new MemoryAtomicKv());
        Assert.True(reg.Accept(Lease("L1")).Ok);
        var renewals = Enumerable.Range(0, 8).Select(i => Lease("L1", 2, T0, T0 + 10, T0 + 2 * HOUR + i, "j-renew-" + i)).ToArray();
        var results = new LeaseAccept[renewals.Length];
        Parallel.For(0, renewals.Length, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i => results[i] = reg.Accept(renewals[i]));
        Assert.Equal(1, results.Count(r => r.Ok && r.Replaced));
        Assert.Equal(renewals.Length - 1, results.Count(r => !r.Ok && r.Code == "lease_fork"));
        Assert.Equal(new long[] { 1, 2 }, reg.History("L1").Select(h => h.Seq).ToArray());
    }

    // ---------------------------------------------------------------- break-glass

    static D Bg(string id, string holder = "h", long maxUses = 1, long issued = 1000, long expires = 5000, long reviewWithin = 1000) => Sign(new D
    {
        ["v"] = 1L, ["id"] = id, ["holder"] = holder, ["grant_ref"] = "r", ["reason_digest"] = "d", ["max_uses"] = maxUses, ["issued_at"] = issued, ["expires_at"] = expires,
        ["review_within"] = reviewWithin, ["notify_to"] = "n", ["authority"] = Auth.Id,
    }, BreakGlass.Domain);

    static D BgReview(string id, string outcome, long at) => new D(Issue.NormJ(new D { ["v"] = 1L, ["id"] = id, ["outcome"] = outcome, ["notes_digest"] = "n", ["at"] = at, ["reviewer"] = Reviewer.Id }))
    {
        ["sig"] = Issue.SignBody(Reviewer, BreakGlass.ReviewDomain, Issue.NormJ(new D { ["v"] = 1L, ["id"] = id, ["outcome"] = outcome, ["notes_digest"] = "n", ["at"] = at, ["reviewer"] = Reviewer.Id })),
    };

    static BreakGlassPolicy BgPolicy => new(new[] { Auth.Id }, new[] { Reviewer.Id });

    [Fact]
    public void ABreakGlassRegistryWithoutAStoreIsRefused()
    {
        var e = Assert.Throws<ArgumentException>(() => new BreakGlassRegistry(BgPolicy, null!));
        Assert.StartsWith("BreakGlassRegistry: a durable key-value store is required (", e.Message);
        Assert.Throws<ArgumentOutOfRangeException>(() => new BreakGlassRegistry(BgPolicy, new MemoryAtomicKv(), 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BreakGlassRegistry(BgPolicy, new MemoryAtomicKv(), 4097));
    }

    [Fact]
    public void ASpentBudgetSurvivesANewRegistryOverTheSameStore()
    {
        var kv = new MemoryAtomicKv();
        var first = new BreakGlassRegistry(BgPolicy, kv);
        Assert.True(first.Accept(Bg("g1"), IntentJs.OfLong(1500)).Ok);
        var use = first.Use("g1", "h", "act", IntentJs.OfLong(1600), true);
        Assert.Equal("allow", use.Decision);
        Assert.Equal(1, use.Use);
        Assert.Equal(0, use.Remaining);
        Assert.Equal(1600 + 1000, use.ReviewDue);
        var second = new BreakGlassRegistry(BgPolicy, kv);
        Assert.Equal("budget_exhausted", second.Use("g1", "h", "act", IntentJs.OfLong(1700), true).Code);
        Assert.Equal(new[] { 1L }, second.Uses("h", "g1").Select(u => u.N).ToArray());
        Assert.Equal("act", second.Uses("h", "g1")[0].ActionDigest);
        Assert.Equal(1600, second.Uses("h", "g1")[0].At);
    }

    [Fact]
    public void AnOverdueReviewFreezesTheHolderAcrossRegistries()
    {
        var kv = new MemoryAtomicKv();
        var first = new BreakGlassRegistry(BgPolicy, kv);
        Assert.True(first.Accept(Bg("g1", maxUses: 2), IntentJs.OfLong(1500)).Ok);
        Assert.Equal("allow", first.Use("g1", "h", "act", IntentJs.OfLong(1600), true).Decision);
        var second = new BreakGlassRegistry(BgPolicy, kv);
        Assert.False(second.IsFrozen("h", IntentJs.OfLong(2599)));
        Assert.True(second.IsFrozen("h", IntentJs.OfLong(2600)));
        Assert.Equal("holder_frozen", second.Use("g1", "h", "act", IntentJs.OfLong(2600), true).Code);
        Assert.Equal("holder_frozen", second.Accept(Bg("g2"), IntentJs.OfLong(2600)).Code);
        // a late justified review lifts the freeze, on every registry sharing the store
        Assert.True(second.Review(BgReview("g1", "justified", 1700), "h", IntentJs.OfLong(2700)).Ok);
        Assert.False(first.IsFrozen("h", IntentJs.OfLong(9999)));
    }

    [Fact]
    public void AnotherHoldersGrantInTheSameShardIsWrongHolderNotUnknown()
    {
        var reg = new BreakGlassRegistry(BgPolicy, new MemoryAtomicKv(), 1); // one shard: every holder shares the document
        Assert.True(reg.Accept(Bg("g1", "alice"), IntentJs.OfLong(1500)).Ok);
        Assert.Equal("wrong_holder", reg.Use("g1", "bob", "act", IntentJs.OfLong(1600), true).Code);
        Assert.Equal("unknown_break_glass", reg.Use("nope", "bob", "act", IntentJs.OfLong(1600), true).Code);
        Assert.Equal("unknown_break_glass", reg.Review(BgReview("g1", "justified", 1600), "bob", IntentJs.OfLong(1700)).Code);
        // an id already issued to another holder is a conflict, not a second grant
        Assert.Equal("id_conflict", reg.Accept(Bg("g1", "bob"), IntentJs.OfLong(1500)).Code);
    }

    [Fact]
    public void ABreakGlassStoreThatFailsIsStoreUnreachableAndFrozen()
    {
        var kv = new FlakyKv();
        var reg = new BreakGlassRegistry(BgPolicy, kv);
        Assert.True(reg.Accept(Bg("g1"), IntentJs.OfLong(1500)).Ok);
        kv.Fail = true;
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Accept(Bg("g2"), IntentJs.OfLong(1500)));
        Assert.Equal(new BreakGlassDecision("deny", "store_unreachable", "g1"), reg.Use("g1", "h", "act", IntentJs.OfLong(1600), true));
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Review(BgReview("g1", "justified", 1600), "h", IntentJs.OfLong(1700)));
        Assert.True(reg.IsFrozen("h", IntentJs.OfLong(1600)));
        kv.Fail = false;
        Assert.False(reg.IsFrozen("h", IntentJs.OfLong(1600)));
        Assert.Equal(0, reg.Uses("h", "g1").Count); // nothing was recorded while the store was down
    }

    // ---------------------------------------------------------------- blueprints

    static EdKey Op => EdKey.FromSeed(Enumerable.Repeat((byte)63, 32).ToArray());

    static D Bp(string key, long epoch, string status = "active", object? pins = null)
    {
        var body = new D { ["v"] = 1L, ["id"] = "bot", ["key"] = key, ["ceiling"] = new L(), ["epoch"] = epoch, ["status"] = status, ["issued_at"] = 1L, ["operator"] = Op.Id };
        if (pins != null) body["runtime_pins"] = pins;
        var b = Issue.NormJ(body);
        return new D(b) { ["sig"] = Issue.SignBody(Op, Blueprint.Domain, b) };
    }

    static L Chain() => new() { new D { ["issuer"] = "root", ["holder"] = "bp" }, new D { ["issuer"] = "bp", ["holder"] = "instance" } };
    static L Pins => new() { new D { ["runtime_measurement"] = "m" } };

    sealed class ThrowingStore : IBlueprintStore
    {
        public Dictionary<string, object?>? Get(string key) => throw new InvalidOperationException("store down");
        public void Put(Dictionary<string, object?> blueprint) => throw new InvalidOperationException("store down");
        public long MaxEpoch() => throw new InvalidOperationException("store down");
    }

    [Fact]
    public void ABlueprintRegistryWithoutAStoreIsRefused()
    {
        var e = Assert.Throws<ArgumentException>(() => new BlueprintRegistry(new[] { Op.Id }, null!));
        Assert.StartsWith("BlueprintRegistry: a durable BlueprintStore is required (", e.Message);
    }

    [Fact]
    public void ADisabledBlueprintStaysDisabledAcrossARestart()
    {
        var kv = new MemoryAtomicKv();
        var first = new BlueprintRegistry(new[] { Op.Id }, new AtomicKvBlueprintStore(kv));
        Assert.True(first.Accept(Bp("bp", 4)).Ok);
        Assert.True(first.Accept(Bp("bp", 5, "disabled")).Ok);
        var second = new BlueprintRegistry(new[] { Op.Id }, new AtomicKvBlueprintStore(kv));
        Assert.Equal(new BlueprintAccept(false, false, "stale_epoch"), second.Accept(Bp("bp", 4)));
        Assert.Equal(5, second.Epoch());
        var d = Blueprint.Check(Chain(), second, IntentJs.OfLong(100), "any");
        Assert.Equal("deny", d.Decision);
        Assert.Equal("blueprint_disabled", d.Code);
        // an epoch never goes down in the store
        var third = new AtomicKvBlueprintStore(kv);
        third.Put(Bp("other", 2));
        Assert.Equal(5, third.MaxEpoch());
        Assert.Equal(0, new AtomicKvBlueprintStore(new MemoryAtomicKv()).MaxEpoch());
        Assert.Null(new AtomicKvBlueprintStore(new MemoryAtomicKv()).Get("bp"));
    }

    [Fact]
    public void ABlueprintStoreThatFailsIsStoreUnreachable()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new ThrowingStore());
        Assert.Equal(new BlueprintAccept(false, false, "store_unreachable"), reg.Accept(Bp("bp", 1)));
        var d = Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any");
        Assert.Equal(("deny", "store_unreachable"), (d.Decision, d.Code));
        var e = Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any", minEpoch: 1);
        Assert.Equal(("deny", "store_unreachable"), (e.Decision, e.Code));
    }

    [Fact]
    public void TheAdmissionHookDecidesABlueprintWithRuntimePins()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        Assert.True(reg.Accept(Bp("bp", 1, pins: Pins)).Ok);
        string? seenKey = null; string? seenId = null;
        // no hook: admission_required (unchanged)
        Assert.Equal("admission_required", Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any").Code);
        // hook false: not_admitted
        var no = Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any", admitted: (k, b) => { seenKey = k; seenId = (string)b["id"]!; return false; });
        Assert.Equal(("deny", "not_admitted", "bot"), (no.Decision, no.Code, no.Blueprint));
        Assert.Equal("instance", seenKey);   // the holder of the hop issued by the blueprint key
        Assert.Equal("bot", seenId);
        // hook true: continues to the ceiling (empty here) and allows
        var yes = Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any", admitted: (_, _) => true);
        Assert.Equal("allow", yes.Decision);
        Assert.Equal(new[] { "bot" }, yes.Governed!.ToArray());
        // hook throws: not_admitted
        var boom = Blueprint.Check(Chain(), reg, IntentJs.OfLong(100), "any", admitted: (_, _) => throw new InvalidOperationException("hook down"));
        Assert.Equal(("deny", "not_admitted"), (boom.Decision, boom.Code));
        // a blueprint without pins never calls the hook
        var plain = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        Assert.True(plain.Accept(Bp("bp", 1)).Ok);
        var calls = 0;
        Assert.Equal("allow", Blueprint.Check(Chain(), plain, IntentJs.OfLong(100), "any", admitted: (_, _) => { calls++; return false; }).Decision);
        Assert.Equal(0, calls);
    }
}
