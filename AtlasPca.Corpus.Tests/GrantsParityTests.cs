using System.Globalization;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Parity with the reference: budget_alloc monotonicity (capability.ts:174), blueprint runtime_pins (blueprint.ts:86, :202), registry
/// locking, need scope whitespace (pca-need.ts:69), push token comparison (a2a-auth.ts:273).</summary>
public class GrantsParityTests
{
    static EdKey Op => EdKey.FromSeed(Enumerable.Repeat((byte)51, 32).ToArray());
    static SuiteKey Principal => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)52, 32).ToArray()));
    static SuiteKey Middle => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)53, 32).ToArray()));
    static SuiteKey Leaf => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)54, 32).ToArray()));

    // ---- budget_alloc

    static JD Alloc(object? limit) => new() { ["type"] = "budget_alloc", ["limit"] = limit };
    const string Limit0 = "budget_alloc caveat 0: limit must be a finite number >= 0";

    [Fact]
    public void AllocationsMustBeFiniteNonNegativeAndNonIncreasing()
    {
        Assert.Null(Pca.AllocationsMonotone(new JL()));
        Assert.Null(Pca.AllocationsMonotone(new JL { Alloc(0L) }));
        Assert.Null(Pca.AllocationsMonotone(new JL { Alloc(5L), Alloc(5L) }));
        Assert.Null(Pca.AllocationsMonotone(new JL { Alloc(5L), Alloc(0L) }));
        Assert.Equal("budget_alloc caveat 1: limit must be a finite number >= 0", Pca.AllocationsMonotone(new JL { new JD { ["type"] = "x" }, Alloc(-1L) }));
        Assert.Equal(Limit0, Pca.AllocationsMonotone(new JL { Alloc(double.NaN) }));
        Assert.Equal(Limit0, Pca.AllocationsMonotone(new JL { Alloc(double.PositiveInfinity) }));
        Assert.Equal(Limit0, Pca.AllocationsMonotone(new JL { Alloc("3") }));
        Assert.Equal(Limit0, Pca.AllocationsMonotone(new JL { new JD { ["type"] = "budget_alloc" } }));
        Assert.Equal("budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)",
            Pca.AllocationsMonotone(new JL { Alloc(5L), new JD { ["type"] = "ttl" }, Alloc(6L) }));
        // the previous value moves down
        Assert.StartsWith("budget_alloc caveat 2: allocation 4 widens the parent's carried allocation 3 ", Pca.AllocationsMonotone(new JL { Alloc(5L), Alloc(3L), Alloc(4L) }));
    }

    [Fact]
    public void NullNonObjectAndOtherEntriesAreSkipped() =>
        Assert.Null(Pca.AllocationsMonotone(new JL { null, 7L, "budget_alloc", new JD { ["type"] = "rate", ["limit"] = -3L }, Alloc(2L) }));

    [Fact]
    public void AWideningChildFailsTheChainCheck()
    {
        var root = Issue.MintRoot(Principal, Middle.Id!, null, new JL { Alloc(10L) });
        var ok = Issue.Delegate(root, Leaf.Id!, new JL { Alloc(4L) }, Middle);
        Assert.Equal(("", true), Pca.VerifyChain(new JL { root, ok }, null, false));
        var wide = Issue.Delegate(root, Leaf.Id!, new JL { Alloc(100L) }, Middle);
        Assert.Equal(("budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)", false),
            Pca.VerifyChain(new JL { root, wide }, null, false));
    }

    // ---- blueprints

    static JD Record(string key, long epoch = 1, object? pins = null, string status = "active", string id = "bot")
    {
        var body = new JD
        {
            ["v"] = 1L, ["id"] = id, ["key"] = key, ["ceiling"] = new JL(), ["epoch"] = epoch, ["status"] = status, ["issued_at"] = 1L, ["operator"] = Op.Id,
        };
        if (pins != null) body["runtime_pins"] = pins;
        var b = Issue.NormJ(body);
        return new JD(b) { ["sig"] = Issue.SignBody(Op, Blueprint.Domain, b) };
    }
    static JL Pins(params object?[] p) => new(p);
    static JD Pin(params string[] kv) { var d = new JD(); for (int i = 0; i < kv.Length; i += 2) d[kv[i]] = kv[i + 1]; return d; }
    static JD Hop(string issuer, string holder) => new() { ["issuer"] = issuer, ["holder"] = holder };
    static JL Chain() => new() { Hop("root", "bp"), Hop("bp", "instance") };

    [Fact]
    public void APinnedBlueprintIsAcceptedAndItsInstancesDeny()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        var rec = Record("bp", pins: Pins(Pin("runtime_measurement", "m")));
        Assert.True(Blueprint.Verify(rec));
        Assert.Equal(new BlueprintAccept(true, true, null), reg.Accept(rec));
        var d = Blueprint.Check(Chain(), reg, new Num("100"), "any");
        Assert.Equal("deny", d.Decision);
        Assert.Equal("admission_required", d.Code);
        Assert.Equal("bot", d.Blueprint);
    }

    [Fact]
    public void EveryPinAndEveryPinFieldMustBeGood()
    {
        Assert.True(Blueprint.Verify(Record("bp", pins: Pins(Pin("model_id", "m"), Pin("operator", "o", "spiffe_id", "s")))));
        Assert.False(Blueprint.Verify(Record("bp", pins: Pins(Pin("model_id", "m"), Pin("nope", "x")))));
        Assert.False(Blueprint.Verify(Record("bp", pins: Pins(Pin("nope", "x"), Pin("model_id", "m")))));
        Assert.False(Blueprint.Verify(Record("bp", pins: Pins(Pin("model_id", "m", "nope", "x")))));
        Assert.False(Blueprint.Verify(Record("bp", pins: Pins(Pin("nope", "x", "model_id", "m")))));
        Assert.False(Blueprint.Verify(Record("bp", pins: Pins(Pin("model_id", "m", "operator", "")))));
    }

    [Fact]
    public void AGroupKillOfAPinnedBlueprintIsDisabledFirst()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        Assert.True(reg.Accept(Record("bp", pins: Pins(Pin("model_id", "m")), status: "disabled")).Ok);
        Assert.Equal("blueprint_disabled", Blueprint.Check(Chain(), reg, new Num("100"), "any").Code);
    }

    [Fact]
    public void ThePinsAreSigned()
    {
        var rec = new JD(Record("bp", pins: Pins(Pin("model_id", "m")))) { ["runtime_pins"] = Pins(Pin("model_id", "other")) };
        Assert.False(Blueprint.Verify(rec));
        var dropped = new JD(Record("bp", pins: Pins(Pin("model_id", "m"))));
        dropped.Remove("runtime_pins");
        Assert.False(Blueprint.Verify(dropped));
    }

    [Fact]
    public void MalformedPinsAreRefused()
    {
        foreach (var pins in new object?[]
        {
            "x", new JD(), Pins(), Pins("x"), Pins(new JD()), Pins(Pin("nope", "m")), Pins(Pin("model_id", "")), Pins(Pin("model_id", new string('a', 257))),
            Pins(new JD { ["model_id"] = 1L }), new JL(Enumerable.Repeat<object?>(Pin("model_id", "m"), 17)),
        })
            Assert.False(Blueprint.Verify(Record("bp", pins: pins)));
        foreach (var k in new[] { "runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id" })
            Assert.True(Blueprint.Verify(Record("bp", pins: Pins(Pin(k, new string('a', 256))))));
        Assert.True(Blueprint.Verify(Record("bp", pins: new JL(Enumerable.Repeat<object?>(Pin("model_id", "m"), 16)))));
    }

    [Fact]
    public void ANullPinsMemberIsMalformed()
    {
        var body = new JD { ["v"] = 1L, ["id"] = "bot", ["key"] = "bp", ["ceiling"] = new JL(), ["runtime_pins"] = null, ["epoch"] = 1L, ["status"] = "active", ["issued_at"] = 1L, ["operator"] = Op.Id };
        var b = Issue.NormJ(body);
        Assert.False(Blueprint.Verify(new JD(b) { ["sig"] = Issue.SignBody(Op, Blueprint.Domain, b) }));
    }

    [Fact]
    public void ConcurrentBlueprintCallsKeepTheNewestRecordAndNeverThrow()
    {
        var store = new MemoryBlueprintStore();
        var reg = new BlueprintRegistry(new[] { Op.Id }, store);
        var records = Enumerable.Range(1, 64).Select(e => Record("bp", e)).Concat(Enumerable.Range(0, 400).Select(i => Record("k" + i))).ToArray();
        Parallel.ForEach(records, new ParallelOptions { MaxDegreeOfParallelism = 8 }, r =>
        {
            reg.Accept(r);
            Blueprint.Check(Chain(), reg, new Num("100"), "any");
            reg.Epoch();
        });
        Assert.Equal(64, reg.Epoch());
        Assert.Equal(401, store.Count);
    }

    [Fact]
    public void ConcurrentAcceptsOverASharedAtomicStoreNeverLowerARecord()
    {
        var kv = new MemoryAtomicKv();
        var regs = Enumerable.Range(0, 4).Select(_ => new BlueprintRegistry(new[] { Op.Id }, new AtomicKvBlueprintStore(kv))).ToArray();
        Parallel.ForEach(Enumerable.Range(1, 64), new ParallelOptions { MaxDegreeOfParallelism = 8 }, e => regs[e % 4].Accept(Record("bp", e)));
        Assert.True(Pca.SafeNat(new AtomicKvBlueprintStore(kv).Get("bp")!["epoch"], out var top) && top == 64);
        Assert.Equal(64, regs[0].Epoch());
    }

    [Fact]
    public void AnAtomicStorePutKeepsTheStoredRecordUnlessTheEpochIsHigher()
    {
        var store = new AtomicKvBlueprintStore(new MemoryAtomicKv());
        store.Put(Record("bp", 5, id: "first"));
        store.Put(Record("bp", 3, id: "older"));
        Assert.Equal("first", store.Get("bp")!["id"]);
        store.Put(Record("bp", 5, id: "same-epoch"));
        Assert.Equal("first", store.Get("bp")!["id"]);
        store.Put(Record("bp", 6, id: "newer"));
        Assert.Equal("newer", store.Get("bp")!["id"]);
        Assert.Equal(6, store.MaxEpoch());
        store.Put(Record("other", 1));
        Assert.Equal("bot", store.Get("other")!["id"]);
    }

    // ---- scope whitespace

    static JD Need(string scope) => new()
    {
        ["v"] = new Num("1"), ["kind"] = "scope", ["verb"] = "v", ["resource"] = "r", ["scopes"] = new JL { scope },
    };

    [Theory]
    [InlineData("a\uFEFFb")] // the case char.IsWhiteSpace misses
    [InlineData("a b")]
    [InlineData("a\tb")]
    [InlineData("a\nb")]
    [InlineData("a\u00A0b")]
    [InlineData("a\u2003b")]
    [InlineData("a\u2028b")]
    [InlineData("a\u3000b")]
    public void AJsWhitespaceScopeIsABadField(string scope) => Assert.Equal("bad_field", A2a.NeedError(Need(scope)));

    [Theory]
    [InlineData("ab")]
    [InlineData("a\u0085b")] // whitespace to char.IsWhiteSpace, not to JS \s
    [InlineData("a\u200Bb")]
    public void ANonJsWhitespaceScopeIsAccepted(string scope) => Assert.Null(A2a.NeedError(Need(scope)));

    // ---- push tokens

    [Fact]
    public void ThePushTokenMustMatchExactly()
    {
        var chain = new[] { "c1" };
        var token = A2a.PushToken("t1", chain, "salt-of-sixteen-chars")!;
        var payload = new JD { ["task"] = new JD { ["id"] = "t1" } };
        Assert.Null(A2a.CheckPush("t1", chain, "salt-of-sixteen-chars", token, payload));
        var flipped = (token[0] == 'A' ? 'B' : 'A') + token.Substring(1);
        Assert.Equal("token_mismatch", A2a.CheckPush("t1", chain, "salt-of-sixteen-chars", flipped, payload));
        Assert.Equal("token_mismatch", A2a.CheckPush("t1", chain, "salt-of-sixteen-chars", token + "A", payload));
        Assert.Equal("token_mismatch", A2a.CheckPush("t1", chain, "salt-of-sixteen-chars", token.Substring(1), payload));
    }
}
