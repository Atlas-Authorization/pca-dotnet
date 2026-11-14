using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact checks of the dead-man liveness beacons (Beacons.cs): every refusal reason with its verdict, the window boundaries, the signature suites, minting,
// the monotonic accept and the durable acceptor.
public class BeaconsKillTests2
{
    const long Now = 1_800_000_000_000L; // a whole number of epochs
    const string Inst = "ins_liveness";
    static readonly string[] Fields = { "v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer" };
    static SuiteKey Issuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x71, 32).ToArray()));
    static SuiteKey Other => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x72, 32).ToArray()));
    static SuiteKey Hybrid(byte seed) => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", EdKey.FromSeed(Enumerable.Repeat(seed, 32).ToArray()), PqKey.Generate(Pq.Prim.MlDsa65));

    static BeaconCheck Check(Action<BeaconCheck>? f = null)
    {
        var c = new BeaconCheck { Issuers = new[] { Issuer.Id! }, Now = Now, Instance = Inst };
        f?.Invoke(c);
        return c;
    }

    static JD Beacon(long seq = 1, long issued = Now - 10_000, string? scope = null, long? validity = null) => Beacons.Mint(Issuer, Inst, seq, issued, scope, validity);
    static BeaconVerdict Refused(string reason) => new(false, reason);
    static BeaconVerdict V(object? b, BeaconCheck? c = null) => Beacons.Verify(b, c ?? Check());

    /// <summary>A beacon with hand-set fields, validly signed over its eight signed fields: the verifier must still refuse a bad one.</summary>
    static JD Forge(Action<JD> edit, long issued = Now - 10_000)
    {
        var b = new JD { ["v"] = 2L, ["instance"] = Inst, ["scope"] = "*", ["epoch"] = issued / 60_000, ["seq"] = 1L, ["issued_at"] = issued, ["not_after"] = issued + 300_000, ["issuer"] = Issuer.Id };
        edit(b);
        var n = Issue.NormJ(b);
        var body = new JD();
        foreach (var k in Fields) body[k] = n.GetValueOrDefault(k);
        n["sig"] = Issuer.Sign(IntentJs.Message(Beacons.Domain, body)).Sig;
        return n;
    }

    [Fact]
    public void TheConstantsAndTheDefaultCheckAreFixed()
    {
        Assert.Equal("*", Beacons.GlobalScope);
        Assert.Equal("atlas-pca/beacon/v2\0", Beacons.Domain);
        Assert.Equal(60_000L, Beacons.EpochMs);
        Assert.Equal(3_600_000L, Beacons.MaxValidityMs);
        Assert.Equal(30_000L, Beacons.ClockSkewMs);
        var c = new BeaconCheck();
        Assert.Empty(c.Issuers);
        Assert.Equal(0, c.Now);
        Assert.Equal("", c.Instance);
        Assert.Null(c.Scope);
        Assert.Null(c.PqPins);
        // a beacon for the empty instance verifies against the default instance
        var b = Beacons.Mint(Issuer, "", 1, Now - 10_000);
        Assert.Equal(new BeaconVerdict(true), Beacons.Verify(b, new BeaconCheck { Issuers = new[] { Issuer.Id! }, Now = Now }));
        Assert.Equal(Refused("wrong instance"), Beacons.Verify(b, Check()));
        Assert.Equal(Refused("issuer not pinned"), Beacons.Verify(b, new BeaconCheck { Now = Now }));
    }

    [Fact]
    public void AMalformedBeaconIsRefusedBeforeAnythingElse()
    {
        Assert.Equal(Refused("malformed beacon"), V(null));
        Assert.Equal(Refused("malformed beacon"), V("x"));
        Assert.Equal(Refused("malformed beacon"), V(new JL()));
        Assert.Equal(Refused("malformed beacon"), V(new JD()));
        foreach (var v in new object?[] { 1L, 3L, 0L, "2", null, true })
            Assert.Equal(Refused("malformed beacon"), V(Forge(b => b["v"] = v)));
        Assert.Equal(Refused("malformed beacon"), V(Forge(b => b.Remove("v"))));
        foreach (var alg in new object?[] { "nope", 5L, null, "" })
            Assert.Equal(Refused("malformed beacon"), V(Forge(b => b["alg"] = alg)));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => b["v"] = new Num("2"))));
    }

    [Fact]
    public void TheInstanceAndTheIssuerAreBound()
    {
        Assert.Equal(new BeaconVerdict(true), V(Beacon()));
        Assert.Equal(Refused("wrong instance"), V(Beacon(), Check(c => c.Instance = "other")));
        Assert.Equal(Refused("wrong instance"), V(Beacon(), Check(c => c.Instance = Inst.ToUpperInvariant())));
        Assert.Equal(Refused("wrong instance"), V(Forge(b => b.Remove("instance"))));
        Assert.Equal(Refused("wrong instance"), V(Forge(b => b["instance"] = 5L)));
        Assert.Equal(Refused("issuer not pinned"), V(Beacon(), Check(c => c.Issuers = new[] { Other.Id! })));
        Assert.Equal(Refused("issuer not pinned"), V(Beacon(), Check(c => c.Issuers = Array.Empty<string>())));
        Assert.Equal(Refused("issuer not pinned"), V(Forge(b => b.Remove("issuer"))));
        Assert.Equal(Refused("issuer not pinned"), V(Forge(b => b["issuer"] = 5L)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(), Check(c => c.Issuers = new[] { Other.Id!, Issuer.Id! })));
        // the instance is checked before the issuer
        Assert.Equal(Refused("wrong instance"), V(Beacon(), Check(c => { c.Instance = "other"; c.Issuers = Array.Empty<string>(); })));
    }

    [Fact]
    public void AnyChangeToASignedFieldOrTheSignatureIsABadSignature()
    {
        foreach (var (key, value) in new (string, object?)[] { ("scope", "g1"), ("epoch", 29_999_998L), ("seq", 2L), ("issued_at", Now - 9_999L), ("not_after", Now + 1L) })
        {
            var t = Beacon();
            t[key] = value;
            Assert.Equal(Refused("bad signature"), V(t));
        }
        var noSig = Beacon();
        noSig.Remove("sig");
        Assert.Equal(Refused("bad signature"), V(noSig));
        var nullSig = Beacon();
        nullSig["sig"] = null;
        Assert.Equal(Refused("bad signature"), V(nullSig));
        var swapped = Beacon(seq: 1);
        swapped["sig"] = Beacon(seq: 2)["sig"];
        Assert.Equal(Refused("bad signature"), V(swapped));
        // a signature by another key under the pinned identity
        var forged = Beacon();
        var body = new JD();
        foreach (var k in Fields) body[k] = forged.GetValueOrDefault(k);
        forged["sig"] = Other.Sign(IntentJs.Message(Beacons.Domain, body)).Sig;
        Assert.Equal(Refused("bad signature"), V(forged));
        // a signature over another domain
        var wrongDomain = Beacon();
        wrongDomain["sig"] = Issuer.Sign(IntentJs.Message("atlas-pca/beacon/v1\0", body)).Sig;
        Assert.Equal(Refused("bad signature"), V(wrongDomain));
    }

    [Fact]
    public void ABeaconTheCanonicalFormCannotCarryIsMalformed()
    {
        var b = new JD { ["v"] = 2L, ["instance"] = Inst, ["scope"] = new object(), ["epoch"] = 1L, ["seq"] = 1L, ["issued_at"] = Now, ["not_after"] = Now + 1, ["issuer"] = Issuer.Id, ["sig"] = "AAAA" };
        Assert.Equal(Refused("malformed beacon"), V(b));
    }

    [Fact]
    public void TheWindowFieldsMustBeIntegersAndTheSeqNonNegative()
    {
        foreach (var field in new[] { "epoch", "seq", "issued_at", "not_after" })
        {
            Assert.Equal(Refused("malformed window"), V(Forge(b => b.Remove(field))));
            Assert.Equal(Refused("malformed window"), V(Forge(b => b[field] = new Num("1.5"))));
            Assert.Equal(Refused("malformed window"), V(Forge(b => b[field] = "1")));
            Assert.Equal(Refused("malformed window"), V(Forge(b => b[field] = null)));
        }
        Assert.Equal(Refused("malformed window"), V(Forge(b => b["seq"] = -1L)));
        Assert.Equal(Refused("malformed window"), V(Forge(b => b["seq"] = new Num("-0.5"))));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => b["seq"] = 0L)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(seq: 0)));
    }

    [Fact]
    public void TheValidityIsAtMostAnHourAndAtLeastOneMillisecond()
    {
        long issued = Now - 10_000;
        Assert.Equal(Refused("validity exceeds the hard maximum"), V(Forge(b => b["not_after"] = issued)));
        Assert.Equal(Refused("validity exceeds the hard maximum"), V(Forge(b => b["not_after"] = issued - 1)));
        Assert.Equal(Refused("validity exceeds the hard maximum"), V(Forge(b => b["not_after"] = issued + 3_600_001L)));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => b["not_after"] = issued + 3_600_000L)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(validity: Beacons.MaxValidityMs)));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => { b["issued_at"] = Now; b["epoch"] = Now / 60_000; b["not_after"] = Now + 1; }, Now)));
        // the validity bound is judged before the epoch and the clock
        Assert.Equal(Refused("validity exceeds the hard maximum"), V(Forge(b => { b["epoch"] = 5L; b["not_after"] = issued; })));
    }

    [Fact]
    public void TheEpochMustBeTheIssueMinuteFloor()
    {
        long epoch = Now / 60_000;
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => { b["issued_at"] = Now; b["epoch"] = epoch; b["not_after"] = Now + 300_000; }, Now)));
        Assert.Equal(Refused("epoch does not match issued_at"), V(Forge(b => { b["issued_at"] = Now; b["epoch"] = epoch + 1; b["not_after"] = Now + 300_000; }, Now)));
        Assert.Equal(Refused("epoch does not match issued_at"), V(Forge(b => { b["issued_at"] = Now; b["epoch"] = epoch - 1; b["not_after"] = Now + 300_000; }, Now)));
        // one millisecond before the boundary belongs to the previous epoch
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => { b["issued_at"] = Now - 1; b["epoch"] = epoch - 1; b["not_after"] = Now + 300_000; }, Now - 1)));
        Assert.Equal(Refused("epoch does not match issued_at"), V(Forge(b => { b["issued_at"] = Now - 1; b["epoch"] = epoch; b["not_after"] = Now + 300_000; }, Now - 1)));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => b["epoch"] = (Now - 10_000) / 60_000)));
        Assert.Equal(Refused("epoch does not match issued_at"), V(Forge(b => b["epoch"] = 5L)));
    }

    [Fact]
    public void TheClockWindowIsClosedOnBothEndsWithThirtySecondsOfSkew()
    {
        Assert.Equal(new BeaconVerdict(true), V(Beacon(issued: Now + 30_000)));
        Assert.Equal(Refused("not yet valid"), V(Beacon(issued: Now + 30_001)));
        Assert.Equal(Refused("not yet valid"), V(Beacon(issued: Now + 90_000)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(issued: Now - 300_000))); // not_after == now
        Assert.Equal(Refused("expired"), V(Beacon(issued: Now - 300_001)));
        Assert.Equal(Refused("expired"), V(Beacon(issued: Now - 400_000)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(), Check(c => c.Now = Now - 40_000)));
        Assert.Equal(Refused("not yet valid"), V(Beacon(), Check(c => c.Now = Now - 40_001)));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(), Check(c => c.Now = Now + 290_000)));
        Assert.Equal(Refused("expired"), V(Beacon(), Check(c => c.Now = Now + 290_001)));
    }

    [Fact]
    public void TheScopeMustBeGlobalOrTheGrantBeingExercised()
    {
        Assert.Equal(new BeaconVerdict(true), V(Beacon(scope: "g1"), Check(c => c.Scope = "g1")));
        Assert.Equal(Refused("scope not covered"), V(Beacon(scope: "g1"), Check(c => c.Scope = "g2")));
        Assert.Equal(Refused("scope not covered"), V(Beacon(scope: "g1"), Check(c => c.Scope = "G1")));
        Assert.Equal(Refused("scope not covered"), V(Beacon(scope: "g1"), Check(c => c.Scope = "")));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(scope: "g1"))); // no scope to check
        Assert.Equal(new BeaconVerdict(true), V(Beacon(), Check(c => c.Scope = "g2"))); // '*' covers every grant
        Assert.Equal(new BeaconVerdict(true), V(Beacon(scope: "*"), Check(c => c.Scope = "*")));
        Assert.Equal(new BeaconVerdict(true), V(Beacon(scope: ""), Check(c => c.Scope = "")));
        Assert.Equal(Refused("scope not covered"), V(Forge(b => b["scope"] = 5L), Check(c => c.Scope = "g1")));
        Assert.Equal(Refused("scope not covered"), V(Forge(b => b.Remove("scope")), Check(c => c.Scope = "g1")));
        Assert.Equal(new BeaconVerdict(true), V(Forge(b => b["scope"] = 5L)));
    }

    [Fact]
    public void ASignedHybridBeaconVerifiesOnlyUnderTheVerifiersOwnPqPin()
    {
        var h = Hybrid(0x73);
        var b = Beacons.Mint(h, Inst, 3, Now - 10_000);
        BeaconCheck Pinned(IReadOnlyDictionary<string, string>? pins) => new() { Issuers = new[] { h.Id! }, Now = Now, Instance = Inst, PqPins = pins };
        Assert.Equal("hybrid-ed25519-ml-dsa-65", b["alg"]);
        Assert.Equal(h.PqPk, b["pq_pk"]);
        Assert.IsType<string>(b["pq_sig"]);
        Assert.IsType<string>(b["sig"]);
        Assert.Equal(new BeaconVerdict(true), Beacons.Verify(b, Pinned(h.PqPin())));
        Assert.Equal(Refused("bad signature"), Beacons.Verify(b, Pinned(null)));
        Assert.Equal(Refused("bad signature"), Beacons.Verify(b, Pinned(new Dictionary<string, string>())));
        Assert.Equal(Refused("bad signature"), Beacons.Verify(b, Pinned(new Dictionary<string, string> { [h.Id!] = Hybrid(0x74).PqPk! })));
        var noPq = new JD(b);
        noPq.Remove("pq_sig");
        Assert.Equal(Refused("bad signature"), Beacons.Verify(noPq, Pinned(h.PqPin())));
        var otherPq = new JD(b) { ["pq_sig"] = Beacons.Mint(h, Inst, 4, Now - 10_000)["pq_sig"] };
        Assert.Equal(Refused("bad signature"), Beacons.Verify(otherPq, Pinned(h.PqPin())));
        var noEdSig = new JD(b);
        noEdSig.Remove("sig");
        Assert.Equal(Refused("bad signature"), Beacons.Verify(noEdSig, Pinned(h.PqPin())));
        var noAlg = new JD(b);
        noAlg.Remove("alg");
        Assert.Equal(Refused("bad signature"), Beacons.Verify(noAlg, Pinned(h.PqPin())));
        var noPk = new JD(b);
        noPk.Remove("pq_pk");
        Assert.Equal(Refused("bad signature"), Beacons.Verify(noPk, Pinned(h.PqPin())));
        // a hybrid beacon passes the same window checks
        Assert.Equal(Refused("expired"), Beacons.Verify(Beacons.Mint(h, Inst, 3, Now - 400_000), Pinned(h.PqPin())));
    }

    // ================= Mint =================

    [Fact]
    public void AnEd25519BeaconCarriesExactlyTheEightFieldsAndASignature()
    {
        var issuer = Issuer;
        var b = Beacons.Mint(issuer, Inst, 5, Now + 59_999);
        Assert.Equal(Fields.Append("sig").OrderBy(k => k, StringComparer.Ordinal).ToArray(), b.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal(2.0, IntentJs.NumOf(b["v"]));
        Assert.Equal(Inst, b["instance"]);
        Assert.Equal("*", b["scope"]);
        Assert.Equal((double)(Now / 60_000), IntentJs.NumOf(b["epoch"]));
        Assert.Equal(5.0, IntentJs.NumOf(b["seq"]));
        Assert.Equal((double)(Now + 59_999), IntentJs.NumOf(b["issued_at"]));
        Assert.Equal((double)(Now + 59_999 + 300_000), IntentJs.NumOf(b["not_after"]));
        Assert.Equal(issuer.Id, b["issuer"]);
        Assert.False(b.ContainsKey("alg"));
        Assert.False(b.ContainsKey("pq_pk"));
        Assert.False(b.ContainsKey("pq_sig"));
        Assert.Equal((double)(Now / 60_000 + 1), IntentJs.NumOf(Beacons.Mint(issuer, Inst, 5, Now + 60_000)["epoch"]));
        Assert.Equal("g1", Beacons.Mint(issuer, Inst, 5, Now, "g1")["scope"]);
        Assert.Equal((double)(Now + 1), IntentJs.NumOf(Beacons.Mint(issuer, Inst, 5, Now, null, 1)["not_after"]));
        Assert.Equal((double)(Now + 3_600_000), IntentJs.NumOf(Beacons.Mint(issuer, Inst, 5, Now, null, 3_600_000)["not_after"]));
    }

    [Fact]
    public void MintingAcceptsTheBoundaryValuesAndRefusesTheOutOfRangeOnes()
    {
        var zero = Beacons.Mint(Issuer, Inst, 0, 0);
        Assert.Equal(0.0, IntentJs.NumOf(zero["seq"]));
        Assert.Equal(0.0, IntentJs.NumOf(zero["issued_at"]));
        Assert.Equal(0.0, IntentJs.NumOf(zero["epoch"]));
        Assert.Equal(300_000.0, IntentJs.NumOf(zero["not_after"]));

        var seq = Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, -1, Now));
        Assert.Equal("seq", seq.ParamName);
        Assert.StartsWith("issueLivenessBeacon: seq must be a non-negative integer", seq.Message);
        var issued = Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, 1, -1));
        Assert.Equal("issuedAt", issued.ParamName);
        Assert.StartsWith("issueLivenessBeacon: issuedAt must be an integer", issued.Message);
        foreach (var bad in new long[] { 0, -1, 3_600_001 })
        {
            var v = Assert.Throws<ArgumentOutOfRangeException>(() => Beacons.Mint(Issuer, Inst, 1, Now, null, bad));
            Assert.Equal("validityMs", v.ParamName);
            Assert.StartsWith("issueLivenessBeacon: validity must be in (0, 3600000] ms", v.Message);
        }
        Assert.Equal(1.0, IntentJs.NumOf(Beacons.Mint(Issuer, Inst, 1, 0, null, 1)["not_after"]));
    }

    [Fact]
    public void ABeaconIsBoundToItsDomainAndRefByItsContent()
    {
        var b = Beacon(seq: 4);
        Assert.Equal(Pca.HashCanonical(b), Beacons.Ref(b));
        Assert.Equal(43, Beacons.Ref(b).Length);
        var reordered = new JD();
        foreach (var k in b.Keys.Reverse()) reordered[k] = b[k];
        Assert.Equal(Beacons.Ref(b), Beacons.Ref(reordered));
        Assert.NotEqual(Beacons.Ref(b), Beacons.Ref(Beacon(seq: 5)));
        Assert.NotEqual(Beacons.Ref(b), Beacons.Ref(null));
    }

    // ================= Accept =================

    [Fact]
    public void AcceptRefusesAnythingButASafeNonNegativeIntegerSeq()
    {
        var malformed = Refused("malformed beacon");
        Assert.Equal(malformed, Beacons.Accept(null, null));
        Assert.Equal(malformed, Beacons.Accept(null, "x"));
        Assert.Equal(malformed, Beacons.Accept(null, new JL()));
        Assert.Equal(malformed, Beacons.Accept(null, new JD()));
        foreach (var seq in new object?[] { "5", null, true, -1L, new Num("-1"), new Num("-0"), new Num("1.5"), new Num("9007199254740992"), 9007199254740992L, new Num("1e400") })
            Assert.Equal(malformed, Beacons.Accept(null, new JD { ["seq"] = seq }));
        foreach (var prev in new double?[] { null, 3 })
            Assert.Equal(malformed, Beacons.Accept(prev, new JD { ["seq"] = -1L }));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(null, new JD { ["seq"] = 0L }));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(null, new JD { ["seq"] = 9007199254740991L }));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(null, new JD { ["seq"] = new Num("12") }));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(null, new JD { ["seq"] = new Num("3.0") }));
    }

    [Fact]
    public void AcceptNeedsAStrictlyHigherSeqThanTheStoredOne()
    {
        JD S(long seq) => new() { ["seq"] = seq };
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(null, S(0)));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(-1, S(0)));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(4, S(5)));
        Assert.Equal(Refused("replayed beacon: seq 5 <= 5"), Beacons.Accept(5, S(5)));
        Assert.Equal(Refused("replayed beacon: seq 4 <= 5"), Beacons.Accept(5, S(4)));
        Assert.Equal(Refused("replayed beacon: seq 0 <= 0"), Beacons.Accept(0, S(0)));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(2.5, S(3)));
        Assert.Equal(Refused("replayed beacon: seq 2 <= 2.5"), Beacons.Accept(2.5, S(2)));
        Assert.Equal(new BeaconVerdict(true), Beacons.Accept(9007199254740990, S(9007199254740991)));
        Assert.Equal(Refused("replayed beacon: seq 9007199254740991 <= 9007199254740991"), Beacons.Accept(9007199254740991, S(9007199254740991)));
    }

    [Fact]
    public void ABeaconIsFrozenOnlyWhenNoneVerifies()
    {
        Assert.True(Beacons.IsFrozen(Array.Empty<object?>(), Check()));
        Assert.False(Beacons.IsFrozen(new object?[] { Beacon() }, Check()));
        Assert.True(Beacons.IsFrozen(new object?[] { Beacon(issued: Now - 400_000) }, Check()));
        Assert.True(Beacons.IsFrozen(new object?[] { null, "x", Beacon(), }.Take(2), Check()));
        Assert.False(Beacons.IsFrozen(new object?[] { null, Beacon(issued: Now - 400_000), Beacon() }, Check()));
        Assert.False(Beacons.IsFrozen(new object?[] { Beacon(), null }, Check()));
        Assert.True(Beacons.IsFrozen(new object?[] { Beacon(scope: "g1") }, Check(c => c.Scope = "g2")));
        Assert.False(Beacons.IsFrozen(new object?[] { Beacon(scope: "g1"), Beacon(scope: "g2") }, Check(c => c.Scope = "g2")));
    }

    // ================= Acceptor =================

    static string KeyOf(string scope, string? issuer = null) => "beacon-seq/v1/[\"" + Inst + "\",\"" + scope + "\",\"" + (issuer ?? Issuer.Id) + "\"]";

    sealed class ThrowingKv : IAtomicKv
    {
        public string? Get(string key) => throw new InvalidOperationException("down");
        public void Update(string key, Func<string?, string?> fn) => throw new InvalidOperationException("down");
    }

    /// <summary>A store that retries its callback, as an optimistic one does: the first attempt sees a stale higher value.</summary>
    sealed class RetryingKv : IAtomicKv
    {
        public string? Stored;
        public int Calls;
        public string? Get(string key) => Stored;
        public void Update(string key, Func<string?, string?> fn)
        {
            Calls++;
            fn("9");
            var next = fn(Stored);
            if (next != null) Stored = next;
        }
    }

    [Fact]
    public void TheAcceptorNeedsAStoreAndRecordsTheHighestSeqPerInstanceScopeAndIssuer()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Beacons.Acceptor(null!));
        Assert.Equal("createBeaconAcceptor: a durable key-value store is required", ex.Message);
        var kv = new MemoryAtomicKv();
        var a = new Beacons.Acceptor(kv);
        Assert.Equal(new BeaconVerdict(true), a.Accept(Beacon(seq: 5), Check()));
        Assert.Equal("5", kv.Get(KeyOf("*")));
        Assert.Equal(Refused("replayed beacon: seq 5 <= 5"), a.Accept(Beacon(seq: 5), Check()));
        Assert.Equal(Refused("replayed beacon: seq 4 <= 5"), a.Accept(Beacon(seq: 4), Check()));
        Assert.Equal("5", kv.Get(KeyOf("*")));
        Assert.Equal(new BeaconVerdict(true), a.Accept(Beacon(seq: 6), Check()));
        Assert.Equal("6", kv.Get(KeyOf("*")));
        // another scope and another issuer keep their own highest seq
        Assert.Equal(new BeaconVerdict(true), a.Accept(Beacon(seq: 1, scope: "g1"), Check()));
        Assert.Equal("1", kv.Get(KeyOf("g1")));
        Assert.Equal("6", kv.Get(KeyOf("*")));
        var both = Check(c => c.Issuers = new[] { Issuer.Id!, Other.Id! });
        Assert.Equal(new BeaconVerdict(true), a.Accept(Beacons.Mint(Other, Inst, 2, Now - 10_000), both));
        Assert.Equal("2", kv.Get(KeyOf("*", Other.Id)));
        Assert.Equal("6", kv.Get(KeyOf("*")));
        // a new store sees nothing
        Assert.Equal(new BeaconVerdict(true), new Beacons.Acceptor(new MemoryAtomicKv()).Accept(Beacon(seq: 5), Check()));
    }

    [Fact]
    public void ABeaconThatDoesNotVerifyIsRefusedWithItsOwnReasonAndRecordsNothing()
    {
        var kv = new MemoryAtomicKv();
        var a = new Beacons.Acceptor(kv);
        Assert.Equal(Refused("wrong instance"), a.Accept(Beacon(seq: 9), Check(c => c.Instance = "x")));
        Assert.Equal(Refused("expired"), a.Accept(Beacon(seq: 9, issued: Now - 400_000), Check()));
        Assert.Equal(Refused("malformed beacon"), a.Accept(null, Check()));
        Assert.Equal(Refused("issuer not pinned"), a.Accept(Beacon(seq: 9), Check(c => c.Issuers = Array.Empty<string>())));
        Assert.Null(kv.Get(KeyOf("*")));
        Assert.Equal(new BeaconVerdict(true), a.Accept(Beacon(seq: 1), Check()));
    }

    [Fact]
    public void AStoreThatCannotDecideOrHoldsAMalformedValueRefusesTheBeacon()
    {
        Assert.Equal(Refused("beacon state unavailable"), new Beacons.Acceptor(new ThrowingKv()).Accept(Beacon(), Check()));
        foreach (var junk in new[] { "junk", "", "-3", "+3", " 3", "3 ", "3.0", "1e3", "9007199254740992", "99999999999999999999", "0x10" })
        {
            var kv = new MemoryAtomicKv();
            kv.Update(KeyOf("*"), _ => junk);
            Assert.Equal(Refused("beacon state unavailable"), new Beacons.Acceptor(kv).Accept(Beacon(seq: 5), Check()));
            Assert.Equal(junk, kv.Get(KeyOf("*")));
        }
    }

    [Fact]
    public void AStoredSeqUpToTheSafeIntegerBoundIsWellFormed()
    {
        var max = new MemoryAtomicKv();
        max.Update(KeyOf("*"), _ => "9007199254740991");
        Assert.Equal(Refused("replayed beacon: seq 5 <= 9007199254740991"), new Beacons.Acceptor(max).Accept(Beacon(seq: 5), Check()));
        Assert.Equal("9007199254740991", max.Get(KeyOf("*")));
        var padded = new MemoryAtomicKv();
        padded.Update(KeyOf("*"), _ => "007");
        Assert.Equal(Refused("replayed beacon: seq 5 <= 7"), new Beacons.Acceptor(padded).Accept(Beacon(seq: 5), Check()));
        var zero = new MemoryAtomicKv();
        zero.Update(KeyOf("*"), _ => "0");
        Assert.Equal(Refused("replayed beacon: seq 0 <= 0"), new Beacons.Acceptor(zero).Accept(Beacon(seq: 0), Check()));
        Assert.Equal(new BeaconVerdict(true), new Beacons.Acceptor(zero).Accept(Beacon(seq: 1), Check()));
        Assert.Equal("1", zero.Get(KeyOf("*")));
    }

    [Fact]
    public void ARetriedUpdateJudgesTheBeaconOnTheLastAttemptOnly()
    {
        var kv = new RetryingKv();
        Assert.Equal(new BeaconVerdict(true), new Beacons.Acceptor(kv).Accept(Beacon(seq: 5), Check()));
        Assert.Equal("5", kv.Stored);
        Assert.Equal(1, kv.Calls);
        Assert.Equal(Refused("replayed beacon: seq 5 <= 5"), new Beacons.Acceptor(kv).Accept(Beacon(seq: 5), Check()));
        Assert.Equal("5", kv.Stored);
    }
}
