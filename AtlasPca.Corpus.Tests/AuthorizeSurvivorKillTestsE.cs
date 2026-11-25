using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Survivors of Authorize.cs from the assurance requirement to the end of the file: the required-check list, the escalation and undo tail,
/// the replay claim and the stores behind it (budget, beacon and epoch pins, contracts), the risk inputs and the trust budget, the threshold hook,
/// the provenance gate and the envelope predicates. Reference: packages/pca/src/server/authorize.ts. Every store seam is reached with a recording
/// double, every fail-closed catch with a seam that throws.</summary>
public class AuthorizeSurvivorKillTestsE
{
    // ================= harness =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_e";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x71, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x72, 32).ToArray()));
    static SuiteKey Sub => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x73, 32).ToArray()));
    static SuiteKey Issuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x74, 32).ToArray()));

    static JD Amt() => new() { ["amount"] = 5L };

    static JD Env(JL? caveats = null, JL? predicates = null, JD? extra = null)
    {
        var e = new JD
        {
            ["predicates"] = predicates ?? new JL { new JD { ["verb"] = "*" } }, ["caveats"] = caveats ?? new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
        };
        if (extra != null) foreach (var kv in extra) e[kv.Key] = kv.Value;
        return e;
    }

    static JD Mint(JD env) => Issue.MintGrant(P, Me.Id!, null, env, "kill e").Grant;
    static string GrantId(JD grant) => (string)Issue.NormJ(grant)["id"]!;
    static Agent AgentOf(JD grant, long counter = 0) => new(Me, Aud, grant, null, counter) { Clock = () => Now };
    static JD Act(JD grant) => AgentOf(grant).Act("pay", "inv/1", Amt());
    static string Wire(JD pcactn) => Issue.Encode(pcactn);
    static string ActWire(JD grant) => Wire(Act(grant));
    // the action's signed freshness.epoch must be >= the revocation epoch under test
    static string ActFreshWire(JD grant) => Wire(AgentOf(grant).Act("pay", "inv/1", Amt(), new JD { ["freshness"] = new JD { ["beacon_ref"] = "ref", ["epoch"] = 100L, ["accumulator_witness"] = "" } }));

    static JD ActClass(JD grant, string cls)
    {
        var a = AgentOf(grant);
        a.CommitPlan(new[] { new JD { ["id"] = "s1", ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = cls } });
        return a.ActNode("s1", Amt());
    }

    static AuthorizeInput Input(JD grant, IStateStore? store = null)
    {
        var g = Issue.NormJ(grant);
        return new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
    }

    static AuthorizeResult Run(object pcactn, AuthorizeInput i) => Pca.Authorize(pcactn, i.WithProv());

    sealed class Hook : IDisposable
    {
        public Hook(Action<Verdict> h) => Pca.CoreHook = h;
        public void Dispose() => Pca.CoreHook = null;
    }

    /// <summary>One escalate-class core failure (the escalation tail runs).</summary>
    static void EscProbe(Verdict v)
    {
        v.Allow = false;
        v.Checks["esc_probe"] = false;
        v.Reason = "esc_probe: escalate: probe";
        v.Reasons = new List<string> { v.Reason };
    }

    /// <summary>An escalate-class failure of the provenance gate itself.</summary>
    static void ProvenanceProbe(Verdict v)
    {
        v.Allow = false;
        v.Checks["provenance_flow"] = false;
        v.Reason = "provenance_flow: escalate: probe";
        v.Reasons = new List<string> { v.Reason };
    }

    /// <summary>A recording state store over the reference one; every seam can be replaced.</summary>
    sealed class Spy : IStateStore, ILastStore, IPinStore, IBudgetStore
    {
        public readonly MemoryStateStore Inner = new();
        public Func<string, long, ClaimResult?>? OnClaim;
        public Func<int, long?>? OnLast;
        public Func<string, long, long>? OnRaise;
        public Func<string, TrustBudget?>? OnBudget;
        public Func<string, TrustBudget?, TrustBudget, bool>? OnCas;
        public int ClaimCalls, LastCalls;
        public readonly List<(string Key, long Value)> Raised = new();
        public readonly List<(string Key, TrustBudget? Old, TrustBudget New)> Cas = new();

        public ClaimResult? Claim(string key, long counter)
        {
            ClaimCalls++;
            return OnClaim != null ? OnClaim(key, counter) : Inner.Claim(key, counter);
        }

        public long? Last(string key)
        {
            LastCalls++;
            return OnLast != null ? OnLast(LastCalls) : Inner.Last(key);
        }

        public long? Pin(string key) => Inner.Pin(key);

        public long RaisePin(string key, long value)
        {
            Raised.Add((key, value));
            return OnRaise != null ? OnRaise(key, value) : Inner.RaisePin(key, value);
        }

        public TrustBudget? Budget(string key) => OnBudget != null ? OnBudget(key) : Inner.Budget(key);

        public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new)
        {
            Cas.Add((key, old, @new));
            return OnCas != null ? OnCas(key, old, @new) : Inner.BudgetCas(key, old, @new);
        }
    }

    /// <summary>A claim-only store: no history, pins or budget seam.</summary>
    sealed class ClaimOnly : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    sealed class FlakyKv : IAtomicKv
    {
        readonly IAtomicKv _inner;
        public bool BlindGet, FailUpdate;
        public FlakyKv(IAtomicKv inner) { _inner = inner; }
        public string? Get(string key) => BlindGet ? null : _inner.Get(key);

        public void Update(string key, Func<string?, string?> fn)
        {
            if (FailUpdate) throw new InvalidOperationException("kv unavailable");
            _inner.Update(key, fn);
        }
    }

    static AuthorizeResult Decided(Action<Verdict> hook)
    {
        var g = Mint(Env());
        using (new Hook(hook)) return Run(ActWire(g), Input(g));
    }

    // ================= assurance requirement =================

    [Fact]
    public void AnUnmetAssuranceRequirementRefusesBeforeTheReplayClaim()
    {
        var g = Mint(Env());
        var spy = new Spy();
        var i = Input(g, spy);
        i.RequireAssurance = new AssuranceRequirement(Attestation: "hardware");
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal(403, r.Status);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("fail", r.Checks["assurance"]);
        Assert.Single(r.Reasons, x => x.StartsWith("assurance: hardware attestation required but ", StringComparison.Ordinal));
        Assert.Equal(0, spy.ClaimCalls);
    }

    [Fact]
    public void AnEmptyAssuranceRequirementIsMetAndLeavesNoCheck()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.RequireAssurance = new AssuranceRequirement();
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.False(r.Checks.ContainsKey("assurance"));
        Assert.Empty(r.Reasons);
    }

    // ================= required checks =================

    [Fact]
    public void ABeaconOptionThatPresentsNothingIsARequiredCheckThatIsNotEnforced()
    {
        var g = Mint(Env());
        var i = Input(g, new Spy());
        i.Beacon = (_, _) => null;
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["beacon"]);
        Assert.Contains("beacon: required check is not-enforced (default-deny: not enforced by this resource server)", r.Reasons);
        var free = Run(ActWire(g), Input(g, new Spy()));
        Assert.True(free.Allow, free.Reason);
        Assert.Equal("not-enforced", free.Checks["beacon"]);
    }

    [Fact]
    public void CounterInARequireListIsTheReplayCheck()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Require = new[] { "counter" };
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.False(r.Checks.ContainsKey("counter"));
    }

    [Fact]
    public void ANullEntryInARequireListIsSkipped()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Require = new string[] { null!, "replay" };
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
    }

    // ================= decision statuses and the allow result =================

    [Fact]
    public void AnAuthenticationFailureIs401AndAnythingElseIs403()
    {
        var authn = Decided(v => { v.Allow = false; v.Checks["audience"] = false; v.Reason = "audience: x"; v.Reasons = new List<string> { "audience: x" }; });
        Assert.Equal(401, authn.Status);
        Assert.Equal("deny", authn.Decision);
        var other = Decided(v => { v.Allow = false; v.Checks["validity_probe"] = false; v.Reason = "validity_probe: x"; v.Reasons = new List<string> { "validity_probe: x" }; });
        Assert.Equal(403, other.Status);
    }

    [Fact]
    public void ADeniedResultCarriesTheRiskStateAndTheDecisiveReason()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.IsRevoked = (_, _) => true;
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal(403, r.Status);
        Assert.Equal("deny", r.Decision);
        Assert.Null(r.Escalation);
        Assert.Equal("revocation: the grant is revoked", r.Reason);
        Assert.Equal(0, r.RiskScore!.Value, 9);
        Assert.Equal(1, r.RequiredThreshold!.T);
        Assert.Equal(1, r.Budget!.B, 9);
        Assert.NotNull(r.Assurance);
        Assert.NotNull(r.Verdict);
        Assert.NotNull(r.Pcactn);
    }

    [Fact]
    public void AnAllowedResultIsBoundToTheOperationAndTheProof()
    {
        var g = Mint(Env());
        var r = Run(ActWire(g), Input(g));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal(200, r.Status);
        Assert.Equal("allow", r.Decision);
        Assert.Equal("pay", r.Operation!.Verb);
        Assert.Equal("inv/1", r.Operation.Resource);
        Assert.Equal(Pca.ParamsDigest(Amt()), r.Operation.ParamsDigest);
        Assert.Equal(Pca.HashCanonical(r.Pcactn!), r.Operation.Id);
        Assert.Null(r.Escalation);
        Assert.Null(r.Undo);
        Assert.Null(r.Obligations);
        Assert.Equal(0, r.RiskScore!.Value, 9);
        Assert.Equal(1, r.RequiredThreshold!.T);
        Assert.NotNull(r.Budget);
        Assert.NotNull(r.Assurance);
    }

    // ================= provenance gate =================

    [Fact]
    public void AMalformedProvenanceMemberOfTheGrantFailsTheGate()
    {
        // the minting helper refuses a malformed member, so the root is signed by hand
        var env = Env();
        env["type"] = "envelope";
        env["goal_commit"] = Issue.GoalCommit("kill e", "c2FsdHNhbHRzYWx0c2FsdA");
        env["agent_binding"] = new JD();
        env["provenance"] = new JD { ["mode"] = "bogus" };
        var g = Issue.MintRoot(P, Me.Id!, null, new JL { env });
        var r = Run(ActWire(g), Input(g));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Contains("provenance_flow: the grant's provenance member is malformed: provenance.mode must be 'enforce' or 'insecure_off'", r.Reasons);
    }

    [Fact]
    public void AnUnreadableProvenanceBundleFailsTheGate()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.ProvenanceUnreadable = true;
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Contains("provenance_flow: the provenance bundle is unreadable (fail closed)", r.Reasons);
    }

    [Fact]
    public void AThrowingActionResolverFailsTheGate()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.ProvenanceFlow = new ArgProvenanceOptions { Mediators = new[] { ProvHarness.Pin }, Actions = _ => throw new InvalidOperationException("facts") };
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Contains("provenance_flow: the action facts resolver failed (fail closed)", r.Reasons);
    }

    [Fact]
    public void AThrowingObservationSourceFailsTheGate()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.ProvenanceFlow = new ArgProvenanceOptions { Mediators = new[] { ProvHarness.Pin }, Observed = (_, _, _) => throw new InvalidOperationException("seen") };
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Contains("provenance_flow: the observation source failed (fail closed)", r.Reasons);
    }

    [Fact]
    public void TheGrantsOwnMediatorPinsJoinTheConfiguredOnes()
    {
        var none = new ArgProvenanceOptions { Mediators = new ProvMediatorPin[0] };
        var bare = Mint(Env());
        var i0 = Input(bare);
        i0.ProvenanceFlow = none;
        var refused = Run(ActWire(bare), i0);
        Assert.False(refused.Allow);
        Assert.Equal("fail", refused.Checks["provenance_flow"]);

        var g = Mint(Env(extra: new JD { ["provenance"] = new JD { ["mode"] = "enforce", ["mediators"] = new JL { ProvHarness.Pin.ToJson() } } }));
        var i = Input(g);
        i.ProvenanceFlow = none;
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["provenance_flow"]);
    }

    // ================= escalation =================

    [Fact]
    public void AnEscalationIsOfferedForEscalateClassFailuresOnly()
    {
        var g = Mint(Env());
        AuthorizeResult esc;
        using (new Hook(EscProbe)) esc = Run(ActWire(g), Input(g));
        Assert.False(esc.Allow);
        Assert.Equal(403, esc.Status);
        Assert.Equal("escalate", esc.Decision);
        Assert.NotNull(esc.Escalation);
        var g2 = Mint(Env());
        var i = Input(g2);
        i.IsRevoked = (_, _) => true;
        var deny = Run(ActWire(g2), i);
        Assert.Equal("deny", deny.Decision);
        Assert.Null(deny.Escalation);
    }

    [Fact]
    public void ADenyAnswerKeepsTheEscalationAndNamesTheDeny()
    {
        var g = Mint(Env());
        var a = Act(g);
        var rd = Pca.HashCanonical("render");
        var i = Input(g);
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationRender = _ => rd;
        i.EscalationAnswer = Issue.EscalationAnswer(P, Issue.NormJ(g), Issue.NormJ(a), null, false, Now, Now + 60_000, rd);
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(a), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.NotNull(r.Escalation);
        Assert.Contains("escalation: the principal answered deny", r.Reasons);
        Assert.Equal("fail", r.Checks["esc_probe"]);
        Assert.False(r.Checks.ContainsKey("escalation"));
    }

    [Fact]
    public void AnAnswerFromAnUnpinnedPrincipalIsRefusedWithTheVerifiersReason()
    {
        var g = Mint(Env());
        var a = Act(g);
        var rd = Pca.HashCanonical("render");
        var i = Input(g);
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationRender = _ => rd;
        i.EscalationAnswer = Issue.EscalationAnswer(Sub, Issue.NormJ(g), Issue.NormJ(a), null, true, Now, Now + 60_000, rd);
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(a), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.Contains("escalation: the answering principal is not pinned by this verifier", r.Reasons);
    }

    [Fact]
    public void AnAllowAnswerLiftsTheEscalateClassFailuresAndNamesThePrincipal()
    {
        var g = Mint(Env());
        var a = Act(g);
        var rd = Pca.HashCanonical("render");
        var i = Input(g);
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationRender = _ => rd;
        i.EscalationAnswer = Issue.EscalationAnswer(P, Issue.NormJ(g), Issue.NormJ(a), null, true, Now, Now + 60_000, rd);
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(a), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("allow", r.Decision);
        Assert.Equal("pass", r.Checks["esc_probe"]);
        Assert.Equal("pass", r.Checks["escalation"]);
        Assert.Contains("escalation: answered allow by principal " + P.Ed!.Id[..8], r.Reasons);
        Assert.Equal(P.Ed!.Id, r.Escalation!["answered_by"]);
        Assert.Null(r.Undo);
        Assert.Null(r.Obligations);
    }

    [Fact]
    public void AnAnswerWithoutARecomputedRenderIsRefusedUnlessTheOptOutIsSet()
    {
        var g = Mint(Env());
        var a = Act(g);
        var answer = Issue.EscalationAnswer(P, Issue.NormJ(g), Issue.NormJ(a), null, true, Now, Now + 60_000);
        const string NeedsRender = "escalation: an approval render is required and none could be recomputed (set EscalationRender, or InsecureUnboundApproval)";

        var i = Input(g);
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationAnswer = answer;
        AuthorizeResult none;
        using (new Hook(EscProbe)) none = Run(Wire(a), i);
        Assert.False(none.Allow);
        Assert.Equal("escalate", none.Decision);
        Assert.Contains(NeedsRender, none.Reasons);

        var g2 = Mint(Env());
        var a2 = Act(g2);
        var i2 = Input(g2);
        i2.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i2.EscalationRender = _ => throw new InvalidOperationException("render");
        i2.EscalationAnswer = Issue.EscalationAnswer(P, Issue.NormJ(g2), Issue.NormJ(a2), null, true, Now, Now + 60_000);
        AuthorizeResult thrown;
        using (new Hook(EscProbe)) thrown = Run(Wire(a2), i2);
        Assert.False(thrown.Allow);
        Assert.Contains(NeedsRender, thrown.Reasons);

        var g3 = Mint(Env());
        var a3 = Act(g3);
        var i3 = Input(g3);
        i3.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i3.InsecureUnboundApproval = true;
        i3.EscalationAnswer = Issue.EscalationAnswer(P, Issue.NormJ(g3), Issue.NormJ(a3), null, true, Now, Now + 60_000);
        AuthorizeResult optedOut;
        using (new Hook(EscProbe)) optedOut = Run(Wire(a3), i3);
        Assert.True(optedOut.Allow, optedOut.Reason);
        Assert.DoesNotContain(NeedsRender, optedOut.Reasons);
    }

    [Fact]
    public void AHistoryHeadThatCannotBeReadNeverJudgesAnAnswer()
    {
        var g = Mint(Env());
        var spy = new Spy { OnLast = _ => throw new InvalidOperationException("history") };
        var i = Input(g, spy);
        i.InsecureUnboundApproval = true;
        i.EscalationAnswer = new JD();
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.DoesNotContain(r.Reasons, x => x.StartsWith("escalation:", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(5L, true)]
    [InlineData(1L, true)]
    [InlineData(0L, false)]
    [InlineData(-1L, false)]
    public void ACounterTheStreamPassedMeanwhileIsAReplayNotAnEscalation(long headOnTheSecondRead, bool replay)
    {
        // the first read (the replay check) saw no stream; the read that binds the escalation sees the head: the counter (1) must beat it
        var g = Mint(Env());
        var spy = new Spy { OnLast = n => n == 1 || headOnTheSecondRead < 0 ? (long?)null : headOnTheSecondRead };
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(ActWire(g), Input(g, spy));
        Assert.False(r.Allow);
        Assert.Equal(2, spy.LastCalls);
        if (replay)
        {
            Assert.Equal("deny", r.Decision);
            Assert.Null(r.Escalation);
            Assert.Equal("fail", r.Checks["replay"]);
            Assert.Contains($"replay: 1 is not greater than last seen {headOnTheSecondRead} (replay)", r.Reasons);
            Assert.Equal(0, spy.ClaimCalls);
        }
        else
        {
            Assert.Equal("escalate", r.Decision);
            Assert.NotNull(r.Escalation);
            Assert.Equal("pass", r.Checks["replay"]);
            Assert.DoesNotContain(r.Reasons, x => x.StartsWith("replay:", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void AHistoryHeadThatThrowsOnTheSecondReadLeavesTheEscalationStanding()
    {
        var g = Mint(Env());
        var spy = new Spy { OnLast = n => n == 1 ? (long?)null : throw new InvalidOperationException("history") };
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(ActWire(g), Input(g, spy));
        Assert.Equal("escalate", r.Decision);
        Assert.NotNull(r.Escalation);
        Assert.DoesNotContain(r.Reasons, x => x.StartsWith("replay:", StringComparison.Ordinal));
    }

    // ================= undo windows =================

    static UndoAdmission Admission(string verb = "refund", string id = "u1") => new(id, Now + 60_000, new UndoCompensationRef(verb, "inv/1"));

    [Fact]
    public void AnAdmittedUndoWindowRunsTheEscalationNowAndCarriesTheObligation()
    {
        var g = Mint(Env());
        var adm = Admission();
        Operation? seen = null;
        var i = Input(g);
        i.Undo = (_, _, op) => { seen = op; return adm; };
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("allow", r.Decision);
        Assert.Equal("pay", seen!.Verb);
        Assert.Equal("inv/1", seen.Resource);
        Assert.Equal(Pca.ParamsDigest(Amt()), Pca.ParamsDigest(seen.Params));
        Assert.Equal(adm, r.Undo);
        Assert.Null(r.Escalation);
        Assert.Equal("pass", r.Checks["undo_window"]);
        Assert.Equal("pass", r.Checks["esc_probe"]);
        Assert.Contains("undo_window: runs now under a veto window until 1800000060000 (compensation refund)", r.Reasons);
        var ob = Assert.Single(r.Obligations!);
        Assert.Equal("undo_window", ((JD)ob!)["kind"]);
    }

    [Fact]
    public void NoAdmissionLeavesTheEscalationStanding()
    {
        foreach (var mode in new[] { "null", "throw", "empty-verb", "empty-id", "no-compensation" })
        {
            var g = Mint(Env());
            var i = Input(g);
            i.Undo = (_, _, _) => mode switch
            {
                "null" => null,
                "throw" => throw new InvalidOperationException("coordinator"),
                "empty-verb" => Admission(verb: ""),
                "no-compensation" => new UndoAdmission("u1", Now + 60_000, null!),
                _ => Admission(id: ""),
            };
            AuthorizeResult r;
            using (new Hook(EscProbe)) r = Run(ActWire(g), i);
            Assert.False(r.Allow, mode);
            Assert.Equal("escalate", r.Decision);
            Assert.NotNull(r.Escalation);
            Assert.Null(r.Undo);
            Assert.Null(r.Obligations);
            Assert.False(r.Checks.ContainsKey("undo_window"), mode);
            Assert.Equal("fail", r.Checks["esc_probe"]);
        }
    }

    [Fact]
    public void AProvenanceEscalationNeverGetsAnUndoWindow()
    {
        var g = Mint(Env());
        var calls = 0;
        var i = Input(g);
        i.Undo = (_, _, _) => { calls++; return Admission(); };
        AuthorizeResult r;
        using (new Hook(ProvenanceProbe)) r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void ADeniedAnswerNeverGetsAnUndoWindow()
    {
        var g = Mint(Env());
        var a = Act(g);
        var rd = Pca.HashCanonical("render");
        var calls = 0;
        var i = Input(g);
        i.Undo = (_, _, _) => { calls++; return Admission(); };
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationRender = _ => rd;
        i.EscalationAnswer = Issue.EscalationAnswer(P, Issue.NormJ(g), Issue.NormJ(a), null, false, Now, Now + 60_000, rd);
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(a), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.Equal(0, calls);
    }

    // ================= the replay claim =================

    [Fact]
    public void ARefusedClaimNamesTheStoredCounterAndWritesNothingElse()
    {
        var g = Mint(Env());
        var spy = new Spy { OnClaim = (_, _) => new ClaimResult(false, 7) };
        var r = Run(ActWire(g), Input(g, spy));
        Assert.False(r.Allow);
        Assert.Equal(403, r.Status);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("fail", r.Checks["replay"]);
        Assert.Equal(new[] { "replay: 1 is not greater than last seen 7 (replay)" }, r.Reasons.Where(x => x.StartsWith("replay:", StringComparison.Ordinal)).ToArray());
        Assert.Empty(spy.Cas);
        Assert.Empty(spy.Raised);
    }

    [Fact]
    public void AMissingOrThrowingClaimFailsClosedAndAnUnnumberedRefusalWasAlreadyClaimed()
    {
        void Case(Func<string, long, ClaimResult?> claim, string why)
        {
            var g = Mint(Env());
            var spy = new Spy { OnClaim = claim };
            var r = Run(ActWire(g), Input(g, spy));
            Assert.False(r.Allow);
            Assert.Equal("fail", r.Checks["replay"]);
            Assert.Equal(new[] { why }, r.Reasons.Where(x => x.StartsWith("replay:", StringComparison.Ordinal)).ToArray());
            Assert.Empty(spy.Cas);
        }
        Case((_, _) => null, "replay: the replay store failed (fail closed)");
        Case((_, _) => throw new InvalidOperationException("claim"), "replay: the replay store failed (fail closed)");
        Case((_, _) => new ClaimResult(false), "replay: 1 was already claimed (replay)");
    }

    // ================= contracts =================

    static (EdKey Principal, JD Contract) NeverDelete()
    {
        var principal = EdKey.FromSeed(Enumerable.Repeat((byte)0x76, 32).ToArray());
        var contract = Contracts.Sign(new JD
        {
            ["version"] = 1L, ["principal"] = principal.Id,
            ["clauses"] = new JL { new JD { ["id"] = "no-del", ["kind"] = "never", ["p"] = new JD { ["verb"] = "delete" } } },
        }, principal);
        return (principal, contract);
    }

    [Fact]
    public void AnAdmittedActionAdvancesTheContractState()
    {
        var (principal, contract) = NeverDelete();
        var enf = ContractEnforcer.Open(new MemoryAtomicKv(), contract, principal.Id, null, () => Now);
        Assert.Null(enf.State());
        var g = Mint(Env());
        var i = Input(g);
        i.Contracts = enf;
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["contract"]);
        var st = enf.State();
        Assert.NotNull(st);
        Assert.False(st!.Value.Latched);
    }

    [Fact]
    public void AContractThatRefusesAtTheCommitIsNamedWithItsViolations()
    {
        var (principal, contract) = NeverDelete();
        var inner = new MemoryAtomicKv();
        // a violating action latches the stored state
        var first = ContractEnforcer.Open(inner, contract, principal.Id, null, () => Now);
        var bad = first.Check(new JD { ["action"] = new JD { ["verb"] = "delete", ["resource"] = "x", ["params"] = new JD() } });
        Assert.False(bad.Allow);
        // the peek reads a blind view of the store (an empty state), the commit sees the latch
        var blind = new FlakyKv(inner) { BlindGet = true };
        var enf = ContractEnforcer.Open(blind, contract, principal.Id, null, () => Now);
        var g = Mint(Env());
        var spy = new Spy();
        var i = Input(g, spy);
        i.Contracts = enf;
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("fail", r.Checks["contract"]);
        Assert.Contains("contract: latched (no-del)", r.Reasons);
        Assert.Empty(spy.Cas);
        Assert.Empty(spy.Raised);
    }

    [Fact]
    public void AContractStoreThatFailsAtTheCommitDeniesWithoutViolations()
    {
        var (principal, contract) = NeverDelete();
        var kv = new FlakyKv(new MemoryAtomicKv()) { FailUpdate = true };
        var enf = ContractEnforcer.Open(kv, contract, principal.Id, null, () => Now);
        var g = Mint(Env());
        var i = Input(g);
        i.Contracts = enf;
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["contract"]);
        Assert.Equal(new[] { "contract: store-error" }, r.Reasons.Where(x => x.StartsWith("contract:", StringComparison.Ordinal)).ToArray());
    }

    // ================= the trust budget store =================

    static string BudgetKey(JD grant) => $"aud:{Aud}:{GrantId(grant)}:{Me.Id}:budget";

    [Fact]
    public void AnAbsentStoredBudgetStartsFullAndIsPersistedOnlyOnTheAllow()
    {
        var g = Mint(Env());
        var spy = new Spy { OnBudget = _ => null };
        var r = Run(ActWire(g), Input(g, spy));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["budget"]);
        var (key, old, next) = Assert.Single(spy.Cas);
        Assert.Equal(BudgetKey(g), key);
        Assert.Null(old);
        Assert.Equal(new TrustBudget(1, Now, Now), next);
        Assert.Equal(new TrustBudget(1, Now, Now), r.Budget);
    }

    [Fact]
    public void AStoredBudgetIsTheStartAndTheOldValueOfTheCompareAndSet()
    {
        var g = Mint(Env());
        var stored = new TrustBudget(0.5, Now - 1000, Now);
        var spy = new Spy { OnBudget = _ => stored, OnCas = (_, _, _) => true };
        var r = Run(ActWire(g), Input(g, spy));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["budget"]);
        var (_, old, next) = Assert.Single(spy.Cas);
        Assert.Equal(stored, old);
        Assert.Equal(0.5, next.B, 9);
        Assert.Equal(0.5, r.Budget!.B, 9);
    }

    [Fact]
    public void ABudgetTheStoreRefusesOrCannotDecideDeniesAfterTheClaim()
    {
        const string Refused = "budget: the budget store refused the update (changed concurrently or failed): fail closed";
        foreach (var cas in new Func<string, TrustBudget?, TrustBudget, bool>[] { (_, _, _) => false, (_, _, _) => throw new InvalidOperationException("budget") })
        {
            var g = Mint(Env());
            var spy = new Spy { OnCas = cas };
            var r = Run(ActWire(g), Input(g, spy));
            Assert.False(r.Allow);
            Assert.Equal("deny", r.Decision);
            Assert.Equal("fail", r.Checks["budget"]);
            Assert.Contains(Refused, r.Reasons);
            Assert.Equal(1, spy.ClaimCalls);
        }
    }

    [Fact]
    public void ARefusedClaimNeverTouchesTheBudget()
    {
        var g = Mint(Env());
        var spy = new Spy { OnClaim = (_, _) => new ClaimResult(false, 9) };
        var r = Run(ActWire(g), Input(g, spy));
        Assert.False(r.Allow);
        Assert.Empty(spy.Cas);
    }

    [Fact]
    public void ASuppliedBudgetIsUsedAsGivenLeakedAndNeverPersisted()
    {
        var g = Mint(Env());
        var spy = new Spy();
        var i = Input(g, spy);
        i.Context = _ => new JD { ["budget"] = new JD { ["B"] = 0.7, ["tau"] = Now - 10_000, ["asOf"] = Now - 4_000 } };
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["budget"]);
        Assert.Equal(0.698, r.Budget!.B, 9); // leaked for the 4 s since asOf at 0.0005 per s
        Assert.Empty(spy.Cas);
    }

    [Fact]
    public void ABudgetMissingAMemberOrNotAnObjectIsTheDenyMeteredDefault()
    {
        const string Default = "budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge";
        foreach (var supplied in new object?[]
        {
            new JD { ["tau"] = Now, ["asOf"] = Now },
            new JD { ["B"] = 1.0, ["asOf"] = Now },
            "junk",
        })
        {
            var g = Mint(Env());
            var spy = new Spy();
            var i = Input(g, spy);
            i.Context = _ => new JD { ["budget"] = supplied };
            var r = Run(ActWire(g), i);
            Assert.Equal("not-enforced", r.Checks["budget"]);
            Assert.Contains(Default, r.Reasons);
            Assert.Equal(0, r.Budget!.B, 9);
            Assert.Empty(spy.Cas);
        }
    }

    [Fact]
    public void AStoreWithoutABudgetSeamIsTheDenyMeteredDefault()
    {
        var g = Mint(Env());
        var r = Run(ActWire(g), Input(g, new ClaimOnly()));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("not-enforced", r.Checks["budget"]);
        Assert.Contains("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge", r.Reasons);
    }

    // ================= beacon and epoch pins =================

    static JD ActBeacon(JD grant, string beaconRef) =>
        AgentOf(grant).Act("pay", "inv/1", Amt(), new JD { ["freshness"] = new JD { ["beacon_ref"] = beaconRef, ["epoch"] = 0L, ["accumulator_witness"] = "" } });

    static Func<string, Dictionary<string, object?>, BeaconPresented?> Presents(JD beacon) =>
        (_, _) => new BeaconPresented(beacon, new[] { Issuer.Id! }, Aud);

    [Fact]
    public void OnlyAnAcceptedBeaconRaisesItsSequencePin()
    {
        var g = Mint(Env());
        var spy = new Spy();
        var plain = Run(ActWire(g), Input(g, spy));
        Assert.True(plain.Allow, plain.Reason);
        Assert.DoesNotContain(spy.Raised, x => x.Key.EndsWith(":beacon", StringComparison.Ordinal));

        var g2 = Mint(Env());
        var b = Beacons.Mint(Issuer, Aud, 7, Now - 10_000);
        var spy2 = new Spy();
        var i = Input(g2, spy2);
        i.Beacon = Presents(b);
        var r = Run(Wire(ActBeacon(g2, Beacons.Ref(b))), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal(new[] { (GrantId(g2) + ":beacon", 7L) }, spy2.Raised.Where(x => x.Key.EndsWith(":beacon", StringComparison.Ordinal)).ToArray());
    }

    [Fact]
    public void ABeaconPinThatCannotBeRaisedDeniesAfterTheClaim()
    {
        var g = Mint(Env());
        var b = Beacons.Mint(Issuer, Aud, 7, Now - 10_000);
        var spy = new Spy
        {
            OnRaise = (k, v) =>
            {
                if (k.EndsWith(":beacon", StringComparison.Ordinal)) throw new InvalidOperationException("pin");
                return v;
            },
        };
        var i = Input(g, spy);
        i.Beacon = Presents(b);
        var r = Run(Wire(ActBeacon(g, Beacons.Ref(b))), i);
        Assert.False(r.Allow);
        Assert.Equal(403, r.Status);
        Assert.Equal("fail", r.Checks["beacon"]);
        Assert.Contains("beacon: the beacon pin could not be raised (fail closed)", r.Reasons);
        Assert.Equal(1, spy.ClaimCalls);
    }

    static (Spy Spy, AuthorizeInput Input, JD Grant) FreshnessSetup(Func<string, long, long>? onRaise)
    {
        var g = Mint(Env());
        var seed = Enumerable.Repeat((byte)0x75, 32).ToArray();
        var epoch = RevocationFreshness.SignEpoch(seed, new RevocationEpochBody(Aud, GrantId(g), 5, 0, "root", Now - 1000, Now + 300_000));
        var spy = new Spy { OnRaise = onRaise };
        var i = Input(g, spy);
        i.RevocationStaleness = new RevocationStalenessPolicy(300_000);
        i.GuardianPublic = EdKey.FromSeed(seed).Id;
        i.RevocationState = (_, _) => new RevocationState(epoch);
        i.RevocationIds = _ => Array.Empty<string>();
        return (spy, i, g);
    }

    [Fact]
    public void AnAdmittedEpochRaisesTheRollbackPinOnlyOnTheAllow()
    {
        var (spy, i, g) = FreshnessSetup(null);
        var r = Run(ActFreshWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["freshness"]);
        Assert.Equal(new[] { (GrantId(g) + ":epoch", 5L) }, spy.Raised.ToArray());

        var (spy2, i2, g2) = FreshnessSetup(null);
        i2.IsRevoked = (_, _) => true;
        var denied = Run(ActFreshWire(g2), i2);
        Assert.False(denied.Allow);
        Assert.Empty(spy2.Raised);
    }

    [Fact]
    public void AnEpochPinThatCannotBeRaisedDeniesAfterTheClaim()
    {
        var (spy, i, g) = FreshnessSetup((_, _) => throw new InvalidOperationException("pin"));
        var r = Run(ActFreshWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("fail", r.Checks["freshness"]);
        Assert.Contains("freshness: the revocation epoch pin could not be raised (fail closed)", r.Reasons);
        Assert.Equal(1, spy.ClaimCalls);
    }

    // ================= risk inputs =================

    static Dictionary<string, double> Low() => ProvHarness.LowRisk.ToDictionary(kv => kv.Key, kv => kv.Value);

    static AuthorizeResult RiskRun(Action<AuthorizeInput> cfg, JD? grant = null, IStateStore? store = null)
    {
        var g = grant ?? Mint(Env());
        var i = Input(g, store);
        cfg(i);
        return Run(ActWire(g), i);
    }

    [Fact]
    public void EverySourceSpeaksAndThePerInputRiskierValueStands()
    {
        var r = RiskRun(i =>
        {
            i.Context = _ => new JD
            {
                ["risk"] = new JD { ["semanticDistance"] = 0.1, ["reversibility"] = 0.6, ["blastRadius"] = 0.1, ["taint"] = 0.4, ["confidence"] = 0.8, ["age"] = 0.3 },
            };
            i.ServerRisk = new Dictionary<string, double>
            {
                ["semanticDistance"] = 0, ["reversibility"] = 0.9, ["blastRadius"] = 0, ["taint"] = 0.1, ["confidence"] = 0.5, ["age"] = 0,
            };
            i.ServerRiskFor = (_, _, _) => new Dictionary<string, double>
            {
                ["semanticDistance"] = 0, ["reversibility"] = 0.4, ["blastRadius"] = 0.3, ["taint"] = 0.2, ["confidence"] = 1, ["age"] = 0.1,
            };
        });
        // 0.25*0.1 + 0.2*(1-0.4) + 0.2*0.3 + 0.2*0.4 + 0.1*(1-0.5) + 0.05*0.3
        Assert.Equal(0.35, r.RiskScore!.Value, 9);
        Assert.Equal(2, r.RequiredThreshold!.T);
    }

    [Fact]
    public void ANonFiniteInputFromEitherSourceIsTheWorstCaseOfThatInput()
    {
        var ctxNan = RiskRun(i =>
        {
            i.Context = _ => new JD { ["risk"] = new JD { ["taint"] = double.NaN } };
            i.ServerRisk = Low();
        });
        Assert.Contains("policy: risk input(s) missing, assumed worst case: taint", ctxNan.Reasons);
        Assert.Equal(0.2, ctxNan.RiskScore!.Value, 9);

        var serverNan = RiskRun(i =>
        {
            i.Context = _ => new JD { ["risk"] = new JD { ["blastRadius"] = 0.0 } };
            var s = Low();
            s["blastRadius"] = double.NaN;
            i.ServerRisk = s;
        });
        Assert.Contains("policy: risk input(s) missing, assumed worst case: blastRadius", serverNan.Reasons);
        Assert.Equal(0.2, serverNan.RiskScore!.Value, 9);
    }

    [Fact]
    public void ExactlyOneMissingInputIsNamedAndTheAgeIsNeverMissing()
    {
        var one = RiskRun(i => { var s = Low(); s.Remove("taint"); i.ServerRisk = s; });
        Assert.Contains("policy: risk input(s) missing, assumed worst case: taint", one.Reasons);
        Assert.Equal(0.2, one.RiskScore!.Value, 9);
        var noAge = RiskRun(i => { var s = Low(); s.Remove("age"); i.ServerRisk = s; });
        Assert.DoesNotContain(noAge.Reasons, x => x.StartsWith("policy: risk input(s) missing", StringComparison.Ordinal));
        Assert.True(noAge.Allow, noAge.Reason);
    }

    [Fact]
    public void TheAgeComesFromTheBudgetAgainstTheHorizon()
    {
        JD Aged() => new() { ["B"] = 1.0, ["tau"] = Now - 1_800_000, ["asOf"] = Now };
        // default horizon one hour: half an hour is 0.5, weight 0.05
        var byDefault = RiskRun(i => { var s = Low(); s.Remove("age"); i.ServerRisk = s; i.Context = _ => new JD { ["budget"] = Aged() }; });
        Assert.Equal(0.025, byDefault.RiskScore!.Value, 9);
        // the context's own horizon: half an hour is the whole horizon
        var byHorizon = RiskRun(i => { var s = Low(); s.Remove("age"); i.ServerRisk = s; i.Context = _ => new JD { ["budget"] = Aged(), ["age_horizon_ms"] = 1_800_000 }; });
        Assert.Equal(0.05, byHorizon.RiskScore!.Value, 9);
    }

    [Fact]
    public void ALeakIsMeasuredFromTheAsOfTimeNotFromTheTouch()
    {
        var r = RiskRun(i => i.Context = _ => new JD { ["budget"] = new JD { ["B"] = 0.7, ["tau"] = Now - 10_000, ["asOf"] = Now - 4_000 } });
        Assert.Equal(0.698, r.Budget!.B, 9);
        var noAsOf = RiskRun(i => i.Context = _ => new JD { ["budget"] = new JD { ["B"] = 0.7, ["tau"] = Now - 10_000 } });
        Assert.Equal(0.695, noAsOf.Budget!.B, 9); // no asOf: from the touch, 10 s
    }

    [Fact]
    public void TheSemanticDistanceOfAMissingInputComesFromThePlan()
    {
        var s = Low();
        s.Remove("semanticDistance");
        // the single node is its own goal: distance 0, and the input is not reported missing
        var own = RiskRun(i => i.ServerRisk = s);
        Assert.Equal(0, own.RiskScore!.Value, 9);
        Assert.DoesNotContain(own.Reasons, x => x.StartsWith("policy: risk input(s) missing", StringComparison.Ordinal));
        // a goal the plan does not hold is unreachable: the whole distance
        var elsewhere = RiskRun(i => { i.ServerRisk = s; i.Context = _ => new JD { ["goal_node_id"] = "elsewhere" }; });
        Assert.Equal(0.25, elsewhere.RiskScore!.Value, 9);
        // an empty plan has no goal
        var empty = RiskRun(i => { i.ServerRisk = s; i.Context = _ => new JD { ["plan"] = new JL() }; });
        Assert.Equal(0.25, empty.RiskScore!.Value, 9);
        // a supplied distance is never replaced by the plan's
        var supplied = RiskRun(i => { var t = Low(); t["semanticDistance"] = 0.4; i.ServerRisk = t; });
        Assert.Equal(0.1, supplied.RiskScore!.Value, 9);
    }

    [Fact]
    public void OnlyTheFastPathClassesMayBeAcceptedOptimistically()
    {
        foreach (var (cls, optimistic) in new[] { ("reversible", true), ("rate_limited", true), ("costly", true), ("irreversible", false) })
        {
            var g = Mint(Env());
            var r = Run(Wire(ActClass(g, cls)), Input(g));
            Assert.True(r.Allow, cls + ": " + r.Reason);
            Assert.Equal(new RequiredThreshold(1, "claim", optimistic), r.RequiredThreshold);
        }
    }

    [Fact]
    public void TheBudgetIsDebitedOnlyWhenTheActionIsReleased()
    {
        void Taint(AuthorizeInput i) { var s = Low(); s["taint"] = 1; i.ServerRisk = s; }
        var released = RiskRun(Taint);
        Assert.True(released.Allow, released.Reason);
        Assert.Equal(0.8, released.Budget!.B, 9);
        // the policy refuses: the machine-only band is still metered, but nothing is debited
        var refused = RiskRun(Taint, Mint(Env(predicates: new JL { new JD { ["verb"] = "other" } })));
        Assert.False(refused.Allow);
        Assert.Equal(1, refused.Budget!.B, 9);
    }

    // ================= the threshold hook =================

    [Fact]
    public void TheThresholdHooksStatusIsRecordedAsTheThresholdCheck()
    {
        void Case(Func<JD, JD, ThresholdHookResult?> hook, string status, bool allow, string? reason)
        {
            var g = Mint(Env());
            var i = Input(g);
            i.ThresholdHook = hook;
            var r = Run(ActWire(g), i);
            Assert.Equal(status, r.Checks["threshold"]);
            Assert.Equal(allow, r.Allow);
            if (reason != null) Assert.Contains(reason, r.Reasons);
            else Assert.DoesNotContain(r.Reasons, x => x.StartsWith("threshold:", StringComparison.Ordinal));
        }
        Case((_, _) => null, "not-enforced", true, null);
        Case((_, _) => new ThresholdHookResult(false, true, 1), "not-enforced", true, null);
        Case((_, _) => new ThresholdHookResult(true, true, 1), "pass", true, null);
        Case((_, _) => new ThresholdHookResult(true, false, 1, "nope"), "fail", false, "threshold: nope");
        Case((_, _) => new ThresholdHookResult(true, false), "fail", false, "threshold: rejected");
        Case((_, _) => throw new InvalidOperationException("hook"), "fail", false, "threshold: threshold hook error (fail closed)");
    }

    // ================= envelope predicates =================

    static JD ActionCtx() => new() { ["action"] = new JD { ["verb"] = "x", ["resource"] = "r" } };

    [Fact]
    public void NoPredicatesOrNoListGrantsNothing()
    {
        Assert.Equal("envelope grants no predicates", Pca.EnvelopePredicates(null, ActionCtx()));
        Assert.Equal("envelope grants no predicates", Pca.EnvelopePredicates(new JL(), ActionCtx()));
        Assert.Equal("envelope grants no predicates", Pca.EnvelopePredicates("*", ActionCtx()));
    }

    [Fact]
    public void APredicateThatDoesNotMatchNamesTheActionItDidNotPermit()
    {
        Assert.Equal("no predicate permits x on r", Pca.EnvelopePredicates(new JL { new JD { ["verb"] = "other" } }, ActionCtx()));
        Assert.Null(Pca.EnvelopePredicates(new JL { new JD { ["verb"] = "x" } }, ActionCtx()));
    }
}
