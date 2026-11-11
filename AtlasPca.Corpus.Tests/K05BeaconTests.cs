using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Dead-man liveness beacons v2 (Beacons.cs) and the beacon option of Authorize, ported from the reference beacons.ts and server/verify.ts.
public class K05BeaconTests
{
    const long Now = 1_800_000_000_000L;
    const string Inst = "ins_beacon";
    static SuiteKey Issuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x61, 32).ToArray()));
    static SuiteKey Other => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x62, 32).ToArray()));
    static BeaconCheck Check(Action<BeaconCheck>? f = null)
    {
        var c = new BeaconCheck { Issuers = new[] { Issuer.Id! }, Now = Now, Instance = Inst };
        f?.Invoke(c);
        return c;
    }
    static JD Beacon(long seq = 1, long issued = Now - 10_000, string? scope = null, long? validity = null) => Beacons.Mint(Issuer, Inst, seq, issued, scope, validity);

    /// <summary>A signed beacon with hand-set fields (the issuer can sign anything; the verifier must still refuse it).</summary>
    static JD Forge(Action<JD> edit)
    {
        var b = new JD { ["v"] = 2L, ["instance"] = Inst, ["scope"] = "*", ["epoch"] = (Now - 10_000) / 60_000, ["seq"] = 1L, ["issued_at"] = Now - 10_000, ["not_after"] = Now + 290_000, ["issuer"] = Issuer.Id };
        edit(b);
        var n = Issue.NormJ(b);
        var body = new JD(n);
        n["sig"] = Issuer.Sign(IntentJs.Message(Beacons.Domain, body)).Sig;
        return n;
    }

    [Fact]
    public void AGenuineBeaconVerifiesAndEveryDefectIsRefusedWithItsReason()
    {
        Assert.Equal(new BeaconVerdict(true), Beacons.Verify(Beacon(), Check()));
        string? Why(object? b, BeaconCheck? c = null) => Beacons.Verify(b, c ?? Check()).Reason;
        Assert.Equal("malformed beacon", Why(null));
        Assert.Equal("malformed beacon", Why("x"));
        Assert.Equal("malformed beacon", Why(Forge(b => b["v"] = 1L)));
        Assert.Equal("malformed beacon", Why(Forge(b => b["alg"] = "nope")));
        Assert.Equal("wrong instance", Why(Beacon(), Check(c => c.Instance = "other")));
        Assert.Equal("issuer not pinned", Why(Beacon(), Check(c => c.Issuers = new[] { Other.Id! })));
        var tampered = Beacon(); tampered["scope"] = "g1";
        Assert.Equal("bad signature", Why(tampered));
        Assert.Equal("malformed window", Why(Forge(b => b["seq"] = -1L)));
        Assert.Equal("malformed window", Why(Forge(b => b["seq"] = new Num("1.5"))));
        Assert.Equal("validity exceeds the hard maximum", Why(Forge(b => b["not_after"] = Now - 10_000 + 3_600_001L)));
        Assert.Equal("validity exceeds the hard maximum", Why(Forge(b => b["not_after"] = Now - 10_000)));
        Assert.Equal("epoch does not match issued_at", Why(Forge(b => b["epoch"] = 5L)));
        Assert.Equal("not yet valid", Why(Beacon(issued: Now + 30_001)));
        Assert.Equal(new BeaconVerdict(true), Beacons.Verify(Beacon(issued: Now + 30_000), Check()));
        Assert.Equal("expired", Why(Beacon(issued: Now - 400_000)));
        Assert.Equal("scope not covered", Why(Beacon(scope: "g1"), Check(c => c.Scope = "g2")));
        Assert.True(Beacons.Verify(Beacon(scope: "g1"), Check(c => c.Scope = "g1")).Ok);
        Assert.True(Beacons.Verify(Beacon(), Check(c => c.Scope = "g2")).Ok); // '*' covers every grant
    }

    [Fact]
    public void MintingRefusesAnOutOfRangeSeqIssuedAtOrValidity()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, -1, Now));
        Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, 1, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, 1, Now, null, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, 1, Now, null, Beacons.MaxValidityMs + 1));
        Assert.Equal(Now + Beacons.MaxValidityMs, (long)IntentJs.NumOf(Beacons.Mint(Issuer, Inst, 1, Now, null, Beacons.MaxValidityMs)["not_after"])!.Value);
    }

    [Fact]
    public void AcceptIsMonotoneAndFreezeNeedsOneGenuineBeacon()
    {
        Assert.True(Beacons.Accept(null, Beacon(seq: 0)).Ok);
        Assert.True(Beacons.Accept(3, Beacon(seq: 4)).Ok);
        Assert.Equal("replayed beacon: seq 3 <= 3", Beacons.Accept(3, Beacon(seq: 3)).Reason);
        Assert.Equal("replayed beacon: seq 2 <= 3", Beacons.Accept(3, Beacon(seq: 2)).Reason);
        Assert.Equal("malformed beacon", Beacons.Accept(null, null).Reason);
        Assert.Equal("malformed beacon", Beacons.Accept(null, new JD { ["seq"] = new Num("-0") }).Reason);
        Assert.False(Beacons.IsFrozen(new object?[] { Beacon() }, Check()));
        Assert.True(Beacons.IsFrozen(Array.Empty<object?>(), Check()));
        Assert.True(Beacons.IsFrozen(new object?[] { Beacon(issued: Now - 400_000) }, Check()));
    }

    sealed class ThrowingKv : IAtomicKv
    {
        public string? Get(string key) => throw new InvalidOperationException("down");
        public void Update(string key, Func<string?, string?> fn) => throw new InvalidOperationException("down");
    }

    [Fact]
    public void TheDurableAcceptorRemembersTheHighestSeqAndFailsClosed()
    {
        var kv = new MemoryAtomicKv();
        var a = new Beacons.Acceptor(kv);
        Assert.True(a.Accept(Beacon(seq: 5), Check()).Ok);
        Assert.Equal("replayed beacon: seq 5 <= 5", new Beacons.Acceptor(kv).Accept(Beacon(seq: 5), Check()).Reason); // another instance of the process, same store
        Assert.Equal("replayed beacon: seq 4 <= 5", a.Accept(Beacon(seq: 4), Check()).Reason);
        Assert.True(a.Accept(Beacon(seq: 6), Check()).Ok);
        Assert.Equal("wrong instance", a.Accept(Beacon(seq: 9), Check(c => c.Instance = "x")).Reason); // verification runs first and records nothing
        Assert.Equal("beacon state unavailable", new Beacons.Acceptor(new ThrowingKv()).Accept(Beacon(), Check()).Reason);
        var junk = new MemoryAtomicKv();
        junk.Update("beacon-seq/v1/[\"" + Inst + "\",\"*\",\"" + Issuer.Id + "\"]", _ => "junk");
        Assert.Equal("beacon state unavailable", new Beacons.Acceptor(junk).Accept(Beacon(), Check()).Reason);
        Assert.Throws<ArgumentException>(() => new Beacons.Acceptor(null!));
    }

    // ================= through Authorize =================

    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x63, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x64, 32).ToArray()));
    static JD Amt() => new() { ["amount"] = 5L };
    static JD Grant() => Issue.MintGrant(P, Me.Id!, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "beacon").Grant;

    static JD Act(JD grant, string beaconRef, Agent? agent = null) =>
        (agent ?? new Agent(Me, Inst, grant, null, 0) { Clock = () => Now }).Act("pay", "inv/1", Amt(), new JD { ["freshness"] = new JD { ["beacon_ref"] = beaconRef, ["epoch"] = 0L, ["accumulator_witness"] = "" } });

    static AuthorizeResult Run(JD grant, JD pcactn, Action<AuthorizeInput>? cfg, IStateStore store)
    {
        var g = Issue.NormJ(grant);
        var i = new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Inst, ResolveGrant = id => id == (string)g["id"]! ? g : null, StateStore = store,
            IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
        cfg?.Invoke(i);
        return Pca.Authorize(Issue.Encode(pcactn), i.WithProv());
    }

    static Func<string, Dictionary<string, object?>, BeaconPresented?> Presents(JD beacon, long? last = null) =>
        (_, _) => new BeaconPresented(beacon, new[] { Issuer.Id! }, Inst, last);

    [Fact]
    public void NoBeaconOptionIsNotEnforcedAndABoundBeaconPassesAndRaisesThePin()
    {
        var g = Grant();
        var off = Run(g, Act(g, ""), null, new MemoryStateStore());
        Assert.True(off.Allow, off.Reason);
        Assert.Equal("not-enforced", off.Checks["beacon"]);
        var g2 = Grant();
        var b = Beacon(seq: 7, scope: (string)g2["id"]!);
        var store = new MemoryStateStore();
        var on = Run(g2, Act(g2, Beacons.Ref(b)), i => i.Beacon = Presents(b), store);
        Assert.True(on.Allow, on.Reason);
        Assert.Equal("pass", on.Checks["beacon"]);
        Assert.Equal(7, store.Pin((string)g2["id"]! + ":beacon"));
    }

    [Fact]
    public void AnUnboundReplayedOrRejectedBeaconIsRefused()
    {
        var g = Grant();
        var b = Beacon(seq: 3);
        var unbound = Run(g, Act(g, "not-the-ref"), i => i.Beacon = Presents(b), new MemoryStateStore());
        Assert.False(unbound.Allow);
        Assert.Contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon", unbound.Reasons);
        var g2 = Grant();
        var replayed = Run(g2, Act(g2, Beacons.Ref(b)), i => i.Beacon = Presents(b, last: 5), new MemoryStateStore());
        Assert.Contains("beacon: beacon seq 3 is older than the last accepted 5 (replay)", replayed.Reasons);
        var g3 = Grant();
        var expired = Beacon(issued: Now - 400_000);
        var rej = Run(g3, Act(g3, Beacons.Ref(expired)), i => i.Beacon = Presents(expired), new MemoryStateStore());
        Assert.Contains("beacon: expired", rej.Reasons);
    }

    [Fact]
    public void ThePinOfTheStoreMakesAnOlderBeaconAReplayAcrossCalls()
    {
        var g = Grant();
        var store = new MemoryStateStore();
        var agent = new Agent(Me, Inst, g, null, 0) { Clock = () => Now };
        var newer = Beacon(seq: 9);
        Assert.True(Run(g, Act(g, Beacons.Ref(newer), agent), i => i.Beacon = Presents(newer), store).Allow);
        var older = Beacon(seq: 8);
        var r = Run(g, Act(g, Beacons.Ref(older), agent), i => i.Beacon = Presents(older), store);
        Assert.False(r.Allow);
        Assert.Contains("beacon: beacon seq 8 is older than the last accepted 9 (replay)", r.Reasons);
    }

    sealed class NoPins : IStateStore { public ClaimResult? Claim(string key, long counter) => new ClaimResult(true); }

    [Fact]
    public void BeaconReplayProtectionNeedsAStoreThatHoldsPins()
    {
        var g = Grant();
        var b = Beacon();
        var r = Run(g, Act(g, Beacons.Ref(b)), i => i.Beacon = Presents(b), new NoPins());
        Assert.False(r.Allow);
        Assert.Contains("beacon replay protection needs a state store that implements pins", r.Missing!);
    }
}
