using System.Security.Cryptography;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.ContractsKillSupport;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for the authorize pipeline gates (beacon, contracts, passport leaf holder, budget release), the memory pin store, the prohibition plane (float order
/// of a ledger, all-of conditions, the type of a stamped time), safety evidence rows, the break-glass / lease / contract-reset failure paths after a store write, the RSA JWK key
/// rules, the namespace declarations of a canonical subtree and the racing threads of the store conformance kit. Wording follows packages/pca/src.</summary>
public class SurvivorKillLaneZTests
{
    // ================= harness =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_z";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x61, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x62, 32).ToArray()));
    static SuiteKey Sub => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x63, 32).ToArray()));

    static JD Amt() => new() { ["amount"] = 5L };

    static JD Env() => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static JD Mint() => Issue.MintGrant(P, Me.Id!, null, Env(), "kill z").Grant;
    static Agent AgentOf(JD grant) => new(Me, Aud, grant, null, 0) { Clock = () => Now };
    static JD Act(JD grant) => AgentOf(grant).Act("pay", "inv/1", Amt());
    static string Wire(JD pcactn) => Issue.Encode(pcactn);
    static JD Expires(long at) => new() { ["type"] = "expires", ["at"] = at };
    static JD MaxUses(string id, long n) => new() { ["type"] = "max_uses", ["id"] = id, ["n"] = n, ["until"] = Now + 3_600_000L };

    static AuthorizeInput Input(JD grant, IStateStore? store = null)
    {
        var g = Issue.NormJ(grant);
        return new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
    }

    static AuthorizeResult Run(string wire, AuthorizeInput i) => Pca.Authorize(wire, i.WithProv());

    /// <summary>A claim-only store that counts the claims it is asked for.</summary>
    sealed class CountingStore : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public int Claims;
        public ClaimResult? Claim(string key, long counter) { Claims++; return _m.Claim(key, counter); }
    }

    // ================= the memory pin store =================

    [Fact]
    public void AMemoryPinRefusesAnEmptyKeyOrANegativeValueWithItsOwnWording()
    {
        const string Msg = "RaisePin needs a non-empty key and a non-negative value";
        var s = new MemoryStateStore();
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => s.RaisePin("", 1)).Message);
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => s.RaisePin(null!, 1)).Message);
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => s.RaisePin("k", -1)).Message);
        Assert.Null(s.Pin("k"));
        Assert.Equal(0, s.RaisePin("k", 0));
    }

    // ================= beacon =================

    [Fact]
    public void ABeaconIsOnlyAskedForAGrantWithAStringId()
    {
        var g = Mint();
        int calls = 0;
        var i = Input(g);
        i.Beacon = (_, _) => { calls++; return null; };
        Run(Wire(Act(g)), i);
        Assert.True(calls > 0);

        var g2 = Mint();
        var odd = new JD(Issue.NormJ(g2)) { ["id"] = 5L };
        int calls2 = 0;
        var i2 = Input(g2);
        i2.ResolveGrant = _ => odd;
        i2.Beacon = (_, _) => { calls2++; return null; };
        Run(Wire(Act(g2)), i2);
        Assert.Equal(0, calls2);
    }

    // ================= contracts =================

    static (EdKey Principal, JD Contract) Signed(params JD[] clauses)
    {
        var principal = EdKey.FromSeed(Enumerable.Repeat((byte)0x64, 32).ToArray());
        var contract = Contracts.Sign(new JD { ["version"] = 1L, ["principal"] = principal.Id, ["clauses"] = clauses.Cast<object?>().ToList() }, principal);
        return (principal, contract);
    }

    static JD Never(string id, string verb, string? resource = null, JL? where = null)
    {
        var p = new JD { ["verb"] = verb };
        if (resource != null) p["resource"] = resource;
        if (where != null) p["where"] = where;
        return new JD { ["id"] = id, ["kind"] = "never", ["p"] = p };
    }

    [Fact]
    public void AContractClauseReadsTheVerbTheResourceAndTheParamsOfTheOperation()
    {
        var big = new JL { new JD { ["field"] = "action.params.amount", ["op"] = "gt", ["value"] = 100L } };
        var (principal, contract) = Signed(Never("no-other", "pay", "other/1"), Never("no-big", "pay", null, big), Never("no-refund", "refund"));
        var g = Mint();
        var i = Input(g);
        i.Contracts = ContractEnforcer.Open(new MemoryAtomicKv(), contract, principal.Id, null, () => Now);
        var r = Run(Wire(Act(g)), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["contract"]);
    }

    [Fact]
    public void ARefusedPeekNamesEveryViolatedClauseAndNeverSpendsTheCounterOrTouchesTheState()
    {
        var (principal, contract) = Signed(Never("no-a", "pay"), Never("no-b", "pay"));
        var enf = ContractEnforcer.Open(new MemoryAtomicKv(), contract, principal.Id, null, () => Now);
        var g = Mint();
        var store = new CountingStore();
        var i = Input(g, store);
        i.Contracts = enf;
        var r = Run(Wire(Act(g)), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["contract"]);
        Assert.Contains("contract: violated (no-a,no-b)", r.Reasons);
        Assert.Equal(0, store.Claims);
        Assert.Null(enf.State());
    }

    sealed class BlindKv : IAtomicKv
    {
        readonly IAtomicKv _inner;
        public BlindKv(IAtomicKv inner) { _inner = inner; }
        public string? Get(string key) => null;
        public void Update(string key, Func<string?, string?> fn) => _inner.Update(key, fn);
    }

    [Fact]
    public void ALatchSeenAtTheCommitNamesEveryViolatedClause()
    {
        var (principal, contract) = Signed(Never("no-a", "delete"), Never("no-b", "delete"));
        var inner = new MemoryAtomicKv();
        var first = ContractEnforcer.Open(inner, contract, principal.Id, null, () => Now);
        Assert.False(first.Check(new JD { ["action"] = new JD { ["verb"] = "delete", ["resource"] = "x", ["params"] = new JD() } }).Allow);
        // the peek reads a blind view of the store (an empty state), the commit sees the latch
        var enf = ContractEnforcer.Open(new BlindKv(inner), contract, principal.Id, null, () => Now);
        var g = Mint();
        var i = Input(g);
        i.Contracts = enf;
        var r = Run(Wire(Act(g)), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["contract"]);
        Assert.Contains("contract: latched (no-a,no-b)", r.Reasons);
    }

    sealed class LateFailKv : IAtomicKv
    {
        readonly IAtomicKv _inner;
        public bool Armed;
        public LateFailKv(IAtomicKv inner) { _inner = inner; }
        public string? Get(string key) => _inner.Get(key);

        /// <summary>Runs the function and writes, then reports a failure (the meta key of a registry is spared).</summary>
        public void Update(string key, Func<string?, string?> fn)
        {
            _inner.Update(key, fn);
            if (Armed && !key.EndsWith("/meta", StringComparison.Ordinal)) throw new InvalidOperationException("late");
        }
    }

    [Fact]
    public void AResetWhoseWriteFailsAfterTheFunctionRanIsNotACleared()
    {
        var principal = Key(71);
        var contract = Contracts.Sign(M("{'version':1,'principal':'" + principal.Id + "','clauses':[{'id':'no-send','kind':'never','p':{'verb':'send'}}]}"), principal);
        var id = (string)contract["id"]!;
        JD Send() => M("{'action':{'verb':'send','resource':'/r'}}");
        var kv = new MemoryAtomicKv();
        var en = ContractEnforcer.Open(kv, contract, principal.Id, "k", () => 1_800_000_000_000.0);
        Assert.False(en.Check(Send()).Allow);
        var sig = ContractEnforcer.SignReset(principal, id, 0);
        var late = new LateFailKv(kv) { Armed = true };
        Assert.False(ContractEnforcer.Open(late, contract, principal.Id, "k", () => 1_800_000_000_000.0).Reset(sig));

        // the same reset against a store that writes cleanly clears
        var kv2 = new MemoryAtomicKv();
        var en2 = ContractEnforcer.Open(kv2, contract, principal.Id, "k", () => 1_800_000_000_000.0);
        Assert.False(en2.Check(Send()).Allow);
        Assert.True(en2.Reset(sig));
    }

    // ================= break-glass and lease failure after the write =================

    const long T0 = 1_800_000_000_000L;
    static EdKey Auth => Key(51);
    static EdKey Reviewer => Key(52);

    static JD Grant() => Sign(new JD
    {
        ["v"] = 1L, ["id"] = "bg1", ["holder"] = "agent", ["grant_ref"] = "g", ["reason_digest"] = "r", ["max_uses"] = 2L, ["issued_at"] = T0,
        ["expires_at"] = T0 + 3_600_000L, ["review_within"] = 1_800_000L, ["notify_to"] = "ops", ["authority"] = Auth.Id,
    }, BreakGlass.Domain, Auth);

    static JD ReviewRec() => Sign(new JD
    {
        ["v"] = 1L, ["id"] = "bg1", ["outcome"] = "justified", ["notes_digest"] = "n", ["at"] = T0 + 10, ["reviewer"] = Reviewer.Id,
    }, BreakGlass.ReviewDomain, Reviewer);

    static object At(long ms) => IntentJs.OfLong(ms);

    [Fact]
    public void ABreakGlassWriteThatFailsAfterTheFunctionRanIsStoreUnreachable()
    {
        var kv = new LateFailKv(new MemoryAtomicKv());
        var reg = new BreakGlassRegistry(new BreakGlassPolicy(new[] { Auth.Id }, new[] { Reviewer.Id }), kv);
        kv.Armed = true;
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Accept(Grant(), At(T0)));
        kv.Armed = false;
        Assert.True(reg.Accept(Grant(), At(T0)).Ok);
        kv.Armed = true;
        Assert.Equal(new BreakGlassDecision("deny", "store_unreachable", "bg1"), reg.Use("bg1", "agent", "act", At(T0), true));
        kv.Armed = false;
        Assert.Equal("allow", reg.Use("bg1", "agent", "act", At(T0), true).Decision);
        kv.Armed = true;
        Assert.Equal(new BreakGlassResult(false, "store_unreachable"), reg.Review(ReviewRec(), "agent", At(T0 + 20)));
        kv.Armed = false;
        Assert.True(reg.Review(ReviewRec(), "agent", At(T0 + 20)).Ok);
    }

    static JD LeaseRec() => Sign(new JD
    {
        ["v"] = 1L, ["lease_id"] = "l1", ["path"] = "svc/l1", ["grant_ref"] = "g", ["holder"] = "h", ["requester"] = "r", ["approvers"] = new JL { "a" },
        ["justification_digest"] = "j", ["seq"] = 1L, ["issued_at"] = T0, ["renewed_at"] = T0, ["expires_at"] = T0 + 1000, ["max_ttl"] = 86_400_000L, ["authority"] = Auth.Id,
    }, Lease.Domain, Auth);

    [Fact]
    public void ALeaseWriteThatFailsAfterTheFunctionRanIsStoreUnreachable()
    {
        var kv = new LateFailKv(new MemoryAtomicKv());
        var reg = new LeaseRegistry(new LeasePolicy(new[] { Auth.Id }), kv);
        kv.Armed = true;
        Assert.Equal(new LeaseAccept(false, "store_unreachable"), reg.Accept(LeaseRec()));
        kv.Armed = false;
        Assert.True(reg.Accept(LeaseRec()).Ok);
    }

    // ================= passport leaf holder =================

    [Fact]
    public void ARequiredPassportOnAnEmptyChainIsASubjectMismatchNotAnError()
    {
        var g = Mint();
        var act = Act(g);
        act["cap_chain"] = new JL();
        var i = Input(g);
        i.RequirePassport = new PassportRequirement(new PassportOptions { TrustedIssuers = new[] { "x" } });
        var r = Run(Wire(act), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["passport"]);
        Assert.Contains("passport: subject_mismatch", r.Reasons);
    }

    // ================= budget release =================

    static Dictionary<string, double> Mid() => new()
    {
        ["semanticDistance"] = 0.1, ["reversibility"] = 0.4, ["blastRadius"] = 0.3, ["taint"] = 0.4, ["confidence"] = 0.5, ["age"] = 0.3,
    };

    static Dictionary<string, double> Tainted()
    {
        var s = ProvHarness.LowRisk.ToDictionary(kv => kv.Key, kv => kv.Value);
        s["taint"] = 1;
        return s;
    }

    static AuthorizeResult Delegated(JL caveats, Dictionary<string, double> risk)
    {
        var g = Mint();
        var child = AgentOf(g).Delegate(Sub, caveats);
        var i = Input(g);
        i.ServerRisk = risk;
        return Run(Wire(child.Act("pay", "inv/1", Amt())), i);
    }

    [Fact]
    public void AFailingDelegatedCaveatKeepsTheActionFromBeingReleased()
    {
        var ok = Delegated(new JL { Expires(Now + 60_000) }, Tainted());
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal(0.8, ok.Budget!.B, 9);

        var bad = Delegated(new JL { Expires(Now - 1) }, Tainted());
        Assert.False(bad.Allow);
        Assert.Equal("fail", bad.Checks["delegated_caveats"]);
        Assert.Equal("pass", bad.Checks["policy"]);
        Assert.Equal(1, bad.Budget!.B, 9); // metered, never debited

        var mid = Delegated(new JL { Expires(Now - 1) }, Mid());
        Assert.Equal(2, mid.RequiredThreshold!.T);
        Assert.DoesNotContain(mid.Reasons, x => x.StartsWith("threshold:", StringComparison.Ordinal));
        var control = Delegated(new JL { Expires(Now + 60_000) }, Mid());
        Assert.Contains(control.Reasons, x => x.StartsWith("threshold: t=2 (", StringComparison.Ordinal));
    }

    [Fact]
    public void AFailingK1CaveatKeepsTheActionFromBeingReleased()
    {
        var bad = Delegated(new JL { MaxUses("u1", 3) }, Tainted()); // no K1 option: the caveat is refused
        Assert.False(bad.Allow);
        Assert.Equal("fail", bad.Checks["k1_caveats"]);
        Assert.Equal("pass", bad.Checks["delegated_caveats"]);
        Assert.Equal("pass", bad.Checks["policy"]);
        Assert.Equal(1, bad.Budget!.B, 9);

        var mid = Delegated(new JL { MaxUses("u1", 3) }, Mid());
        Assert.DoesNotContain(mid.Reasons, x => x.StartsWith("threshold:", StringComparison.Ordinal));
    }

    // ================= prohibition plane =================

    static JD J(params (string K, object? V)[] kv) { var d = new JD(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static JL A(params object?[] x) => x.ToList();
    static JD Ctx(string verb, JD? prms = null)
    {
        var a = J(("verb", verb), ("resource", "/r"));
        if (prms != null) a["params"] = prms;
        return J(("action", a));
    }
    static JD Constitution(params JD[] inv) => J(("version", 1L), ("principal", "p"), ("invariants", inv.Cast<object?>().ToList()));

    [Fact]
    public void ALedgerIsSummedInTimeOrderWhateverOrderItIsStoredIn()
    {
        const long Big = 9_007_199_254_740_992L; // 2^53: adding 1 twice from the large side is lost, from the small side it is not
        var cap = J(("id", "c"), ("kind", "cap"), ("when", J(("verb", "pay"))), ("amount", "action.params.amount"), ("max", Big));
        var st = Prohibitions.EmptyState(1000);
        st["ledger"] = J(("c", A(J(("t", 2L), ("amount", 1L)), J(("t", 3L), ("amount", 1L)), J(("t", 1L), ("amount", Big)))));
        var r = Prohibitions.Check(Ctx("pay", J(("amount", 0L))), Constitution(cap), st);
        Assert.True(r.Ok, string.Join("; ", r.Reasons));
        // the same entries in time order sum the same way
        var sorted = Prohibitions.EmptyState(1000);
        sorted["ledger"] = J(("c", A(J(("t", 1L), ("amount", Big)), J(("t", 2L), ("amount", 1L)), J(("t", 3L), ("amount", 1L)))));
        Assert.True(Prohibitions.Check(Ctx("pay", J(("amount", 0L))), Constitution(cap), sorted).Ok);
    }

    [Fact]
    public void NeverUnlessNeedsEveryUnlessConditionToHold()
    {
        var inv = J(("id", "u"), ("kind", "never_unless"), ("when", J(("verb", "pay"))), ("unless", A(
            J(("field", "action.params.a"), ("op", "eq"), ("value", 1L)),
            J(("field", "action.params.b"), ("op", "eq"), ("value", 2L)))));
        var st = Prohibitions.EmptyState(1000);
        var both = Prohibitions.Check(Ctx("pay", J(("a", 1L), ("b", 2L))), Constitution(inv), st);
        Assert.True(both.Ok, string.Join("; ", both.Reasons));
        var onlyOne = Prohibitions.Check(Ctx("pay", J(("a", 1L), ("b", 3L))), Constitution(inv), st);
        Assert.False(onlyOne.Ok);
        Assert.Equal(new[] { "u: forbidden without required condition" }, onlyOne.Reasons.ToArray());
        var neither = Prohibitions.Check(Ctx("pay", J(("a", 0L), ("b", 3L))), Constitution(inv), st);
        Assert.False(neither.Ok);
    }

    [Fact]
    public void AStampedWholeTimeIsALongAndAFractionalOrHugeOneIsNot()
    {
        var st = Prohibitions.EmptyState(1000);
        Assert.IsType<long>(Prohibitions.Tick(st, 2000.0).State!["now"]);
        Assert.IsNotType<long>(Prohibitions.Tick(st, 2000.5).State!["now"]);

        var cap = J(("id", "c"), ("kind", "cap"), ("when", J(("verb", "pay"))), ("amount", "action.params.amount"), ("max", 100L));
        var req = J(("id", "q"), ("kind", "require_prior"), ("when", J(("verb", "pay"))), ("prior", J(("verb", "pay"))));
        var action = Ctx("pay", J(("amount", 5L)));
        var whole = Prohibitions.AdvanceStrict(action, Constitution(cap, req), st, 2000.0);
        Assert.True(whole.Ok, whole.Reason);
        Assert.IsType<long>(whole.State!["now"]);
        Assert.IsType<long>(((JD)((JL)((JD)whole.State!["ledger"]!)["c"]!)[0]!)["t"]);
        Assert.IsType<long>(((JD)whole.State!["latched"]!)["q"]);

        var frac = Prohibitions.AdvanceStrict(action, Constitution(cap), st, 2000.5);
        Assert.True(frac.Ok, frac.Reason);
        Assert.IsNotType<long>(frac.State!["now"]);

        var huge = Prohibitions.AdvanceStrict(action, Constitution(cap), st, 1e16);
        Assert.True(huge.Ok, huge.Reason);
        Assert.IsNotType<long>(huge.State!["now"]);
    }

    sealed class Odd
    {
        readonly string? _s;
        public Odd(string? s) { _s = s; }
        public override string? ToString() => _s;
    }

    [Fact]
    public void AnOtherwiseUnknownValueIsPrintedByItsToStringOrAsAnEmptyString()
    {
        Assert.Equal("zz", Prohibitions.JsString(new Odd("zz")));
        Assert.Equal("", Prohibitions.JsString(new Odd(null)));
    }

    // ================= safety evidence =================

    [Fact]
    public void AnEvidenceRowCarriesANonStringReasonAsGivenAndAStringOneAsText()
    {
        JD Row(object? description)
        {
            var inv = J(("id", "n"), ("kind", "never"), ("when", J(("verb", "pay"))), ("description", description));
            var ev = SafetyEvidence.Prove(Ctx("pay"), Constitution(inv), Prohibitions.EmptyState(1000));
            return (JD)((JL)ev["evaluated"]!)[0]!;
        }
        Assert.Equal((object)5L, Row(5L)["reason"]);
        Assert.Equal("why", Row("why")["reason"]);
        Assert.IsType<JL>(Row(A("a", "b"))["reason"]);
    }

    [Fact]
    public void BindingIdNamesTheMissingMemberError()
    {
        var ev = SafetyEvidence.Prove(Ctx("pay"), Constitution(J(("id", "n"), ("kind", "never"), ("when", J(("verb", "delete"))))), Prohibitions.EmptyState(1000));
        var missing = new JD(ev);
        missing.Remove("state_digest");
        Assert.Equal("canonicalize: unsupported type undefined", Assert.Throws<InvalidOperationException>(() => SafetyEvidence.BindingId(missing, "signer")).Message);
    }

    // ================= attestation key rules and canonical namespaces =================

    static string B64(params byte[] b) => Pca.B64u(b);

    [Fact]
    public void AnRsaJwkOutsideTheModulusAndExponentRulesIsRefused()
    {
        const string Unsupported = "error:1E08010C:DECODER routines::unsupported";
        static string Refused(Action a) => Assert.Throws<AttestError>(a).Message;
        using var rsa = RSA.Create(2048);
        var n = B64(rsa.ExportParameters(false).Modulus!);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(4)))); // an even exponent
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(1, 0, 0))));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(B64(Enumerable.Repeat((byte)0xff, 32).ToArray()), B64(3)))); // 256 bits
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(B64(Enumerable.Repeat((byte)0xff, 2050).ToArray()), B64(3)))); // 16400 bits
        Assert.Equal("rsa", AttestJws.JwkRsaKey(n, B64(1, 0, 1)).Type);
    }

    [Fact]
    public void TwoAttributesOfOnePrefixDeclareItOnce()
    {
        var b = AttestXml.Parse("<p:a xmlns:p=\"u\" xmlns:q=\"v\"><p:b q:x=\"1\" q:y=\"2\"/></p:a>").Root!.ElementChildren()[0];
        Assert.Equal("<p:b xmlns:p=\"u\" xmlns:q=\"v\" q:x=\"1\" q:y=\"2\"></p:b>", AttestXml.Canonicalize(b, new Dictionary<string, string>(StringComparer.Ordinal), null));
    }

    // ================= store conformance: a racing copy that throws =================

    sealed class ThrowingKv : IAtomicKv
    {
        public string? Get(string key) => null;
        public void Update(string key, Func<string?, string?> fn) => throw new InvalidOperationException("boom");
    }

    [Fact]
    public void ARacingCopyThatThrowsFailsTheCheckInsteadOfEndingTheProcess()
    {
        var r = StoreConformance.RunAtomicKv(new AtomicKvConformance { Open = () => new ThrowingKv(), Shared = true, Rounds = 1, Copies = 4, Handles = 2 });
        Assert.False(r.Ok);
        foreach (var name in new[] { "update-concurrent", "create-once" })
        {
            var c = r.Checks.First(x => x.Name == name);
            Assert.Equal(("fail", "boom"), (c.Status, c.Note));
        }
    }

    [Fact]
    public void ADefaultSizeIsUsedWhenTheConfiguredOneIsNotPositive()
    {
        var kv = new MemoryAtomicKv();
        foreach (var handles in new[] { 0, -2 })
        {
            var r = StoreConformance.RunAtomicKv(new AtomicKvConformance { Open = () => kv, Shared = true, Rounds = 0, Copies = 0, Handles = handles });
            Assert.True(r.Ok, r.ToString());
            Assert.Equal("10 rounds x 16 copies over 4 handle(s)", r.Checks.First(x => x.Name == "update-concurrent").Note);
        }
        var one = StoreConformance.RunAtomicKv(new AtomicKvConformance { Open = () => kv, Shared = false, Rounds = 2, Copies = 3, Handles = 7 });
        Assert.Equal("2 rounds x 3 copies over 1 handle(s)", one.Checks.First(x => x.Name == "update-concurrent").Note);
        var shared = new MemoryStateStore();
        var pins = StoreConformance.RunPinStore(new PinStoreConformance { Open = () => shared, Shared = true, Handles = 0 });
        Assert.True(pins.Ok, pins.ToString());
        Assert.Equal("10 rounds x 16 copies over 4 handle(s)", pins.Checks.First(x => x.Name == "raise-concurrent").Note);
    }
}
