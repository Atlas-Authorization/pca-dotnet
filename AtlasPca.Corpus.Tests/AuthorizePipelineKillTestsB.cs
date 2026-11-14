using System.Reflection;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 Stryker survivors of Authorize.cs lines 1100-1509 (plan root / plan state, attestation, reversibility, the policy and
/// caveat contexts, the K1 caveat language, required checks, provenance_flow, the escalation / replay tail, Decisive, NodeLeaf,
/// EnvelopePredicates, V2Env, IsAuthorizedFor) and of FreshAt.cs. PCActns are minted by this SDK's producer; the core verdict is edited
/// through CoreHook, and fail-closed catches are reached with a dictionary whose comparer throws once armed.</summary>
public class AuthorizePipelineKillTestsB
{
    // ================= harness =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_b";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x41, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x42, 32).ToArray()));
    static SuiteKey Sub => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x43, 32).ToArray()));

    static JD Amt() => new() { ["amount"] = 5L };
    static Operation Op() => new("pay", "inv/1", Amt());

    static JD Env(JL? caveats = null, JL? predicates = null, JD? binding = null)
    {
        var e = new JD
        {
            ["predicates"] = predicates ?? new JL { new JD { ["verb"] = "*" } }, ["caveats"] = caveats ?? new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
        };
        if (binding != null) e["agent_binding"] = binding;
        return e;
    }

    static JD Mint(JD env) => Issue.MintGrant(P, Me.Id!, null, env, "kill b").Grant;
    static Agent AgentOf(JD grant, long counter = 0) => new(Me, Aud, grant, null, counter) { Clock = () => Now };
    static JD Act(JD grant) => AgentOf(grant).Act("pay", "inv/1", Amt());
    static string Wire(JD pcactn) => Issue.Encode(pcactn);

    /// <summary>An action on plan node s1 whose signed reversibility class is <paramref name="cls"/>.</summary>
    static JD ActClass(JD grant, string cls)
    {
        var a = AgentOf(grant);
        a.CommitPlan(new[] { new JD { ["id"] = "s1", ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = cls } });
        return a.ActNode("s1", Amt());
    }

    static AuthorizeInput Input(JD grant, Operation? op = null, IStateStore? store = null)
    {
        var g = Issue.NormJ(grant);
        return new AuthorizeInput
        {
            Operation = op ?? Op(), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null, StateStore = store ?? new MemoryStateStore(),
            IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
    }

    static AuthorizeResult Run(object pcactn, AuthorizeInput i) => Pca.Authorize(pcactn, i.WithProv());

    static JD Expires(long at) => new() { ["type"] = "expires", ["at"] = at };
    static JD MaxUses(string id, long n) => new() { ["type"] = "max_uses", ["id"] = id, ["n"] = n, ["until"] = Now + 3_600_000L };

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

    /// <summary>Ordinal string comparer that throws on hashing <see cref="Key"/> once armed: on every hit (ThrowOnHit 0) or on exactly that hit.</summary>
    sealed class Trap : IEqualityComparer<string>
    {
        public string Key = "";
        public bool Armed;
        public int ThrowOnHit;
        int _hits;
        public bool Equals(string? x, string? y) => string.Equals(x, y, StringComparison.Ordinal);
        public int GetHashCode(string s)
        {
            if (Armed && s == Key)
            {
                _hits++;
                if (ThrowOnHit == 0 || _hits == ThrowOnHit) throw new InvalidOperationException("trap: " + s);
            }
            return StringComparer.Ordinal.GetHashCode(s);
        }
    }

    sealed class ClaimOnly : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    sealed class AlreadyClaimed : IStateStore
    {
        public ClaimResult? Claim(string key, long counter) => new(false);
    }

    sealed class ThrowingPins : IReadOnlyList<ProvMediatorPin>
    {
        public ProvMediatorPin this[int index] => throw new InvalidOperationException("pins");
        public int Count => 1;
        public IEnumerator<ProvMediatorPin> GetEnumerator() => throw new InvalidOperationException("pins");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    // ================= baseline: an allowed action (L1182 >=0, L1385) =================

    [Fact]
    public void APlainActionAllowsWithoutK1OrObligations()
    {
        var g = Mint(Env());
        var r = Run(Wire(Act(g)), Input(g));
        Assert.True(r.Allow, r.Reason);
        Assert.False(r.Checks.ContainsKey("k1_caveats")); // no K1 caveat anywhere: no k1 check (L1182)
        Assert.False(r.Checks.ContainsKey(""));
        Assert.Null(r.Obligations); // L1385: no undo obligation
        Assert.Null(r.Degraded);
        Assert.Empty(r.Reasons);
    }

    // ================= plan root (L1119, L1120) =================

    static JD Node(string id) => new()
    {
        ["id"] = id, ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = "reversible",
    };

    [Fact]
    public void AKnownPlanThatDoesNotHashToTheRootIsRefused()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Context = _ => new JD { ["plan"] = new JL { Node("other") }, ["plan_authorized"] = true };
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["plan_root_authorized"]);
        Assert.Contains("plan_root_authorized: known plan does not match plan.root", r.Reasons);
    }

    [Fact]
    public void AKnownPlanNeedsThePrincipalsAuthorization()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Context = _ => new JD { ["plan"] = new JL { Node("n1") }, ["plan_authorized"] = false };
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["plan_root_authorized"]);
        Assert.Contains("plan_root_authorized: the plan root has not been authorized by the principal", r.Reasons);
        Assert.DoesNotContain("plan_root_authorized: known plan does not match plan.root", r.Reasons);
        // the same plan, authorized: the root matches and the action is allowed
        var ok = Input(g);
        ok.Context = _ => new JD { ["plan"] = new JL { Node("n1") }, ["plan_authorized"] = true };
        var a = Run(Wire(Act(g)), ok);
        Assert.True(a.Allow, a.Reason);
        Assert.Equal("pass", a.Checks["plan_root_authorized"]);
    }

    // ================= attestation (L1133) =================

    [Fact]
    public void AnAgentBindingRequiresAnAttestation()
    {
        var g = Mint(Env(binding: new JD { ["operator"] = "op1" }));
        var r = Run(Wire(Act(g)), Input(g));
        Assert.Equal("fail", r.Checks["attestation"]);
        Assert.Contains("attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)", r.Reasons);
    }

    // ================= reversibility (L1135-L1143, L1157) =================

    static AuthorizeResult RunClass(string declared, string server, JL? caveats = null)
    {
        var g = Mint(Env(caveats));
        var i = Input(g);
        i.Context = _ => new JD { ["reversibility_class"] = server };
        return Run(Wire(ActClass(g, declared)), i);
    }

    [Fact]
    public void ADeclaredClassLessRestrictiveThanTheServersFails()
    {
        var r = RunClass("reversible", "costly");
        Assert.Equal("fail", r.Checks["reversibility"]);
        Assert.Contains("reversibility: declared class 'reversible' is less restrictive than the authoritative 'costly'", r.Reasons);
    }

    [Fact]
    public void AnEquallyRestrictiveClassPassesAndTheServersSpellingIsEffective()
    {
        // costly and rate_limited rank equal: pass, and the effective class is the server's (rate_limited <= rate_limited; costly is not in the order)
        var r = RunClass("costly", "rate_limited", new JL { new JD { ["type"] = "reversibility_max", ["class"] = "rate_limited" } });
        Assert.Equal("pass", r.Checks.GetValueOrDefault("reversibility"));
        Assert.Equal("pass", r.Checks["policy"]);
        Assert.True(r.Allow, r.Reason);
    }

    [Fact]
    public void AMoreRestrictiveDeclaredClassPassesAndIsEffective()
    {
        var r = RunClass("irreversible", "reversible", new JL { new JD { ["type"] = "reversibility_max", ["class"] = "reversible" } });
        Assert.Equal("pass", r.Checks["reversibility"]);
        Assert.Equal("fail", r.Checks["policy"]); // effective irreversible > reversible
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", r.Reasons);
    }

    [Fact]
    public void ALessRestrictiveDeclaredClassLeavesTheServersEffective()
    {
        // effective is the server's irreversible (never the declared or the plan node's reversible)
        var r = RunClass("reversible", "irreversible", new JL { new JD { ["type"] = "reversibility_max", ["class"] = "reversible" } });
        Assert.Equal("fail", r.Checks["reversibility"]);
        Assert.Equal("fail", r.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", r.Reasons);
    }

    // ================= policy contexts (L1148-L1162) =================

    [Fact]
    public void EveryContextMemberReachesThePredicatesAndTheStockCaveats()
    {
        var conds = new JL
        {
            new JD { ["field"] = "subject.id", ["op"] = "eq", ["value"] = "alice" },
            new JD { ["field"] = "action.reversibility_class", ["op"] = "eq", ["value"] = "reversible" },
        };
        var g = Mint(Env(
            new JL
            {
                Expires(Now + 60_000), new JD { ["type"] = "max_spend", ["usd"] = 100L }, new JD { ["type"] = "delegation_depth", ["max"] = 0L },
                new JD { ["type"] = "max_blast_radius", ["max"] = 5L }, new JD { ["type"] = "reversibility_max", ["class"] = "reversible" },
                new JD { ["type"] = "rate", ["max"] = 1L, ["per_secs"] = 60L },
            },
            new JL { new JD { ["verb"] = "*", ["where"] = conds } }));
        var i = Input(g);
        i.Context = _ => new JD { ["subject"] = new JD { ["id"] = "alice" }, ["blast_radius"] = 3L, ["recent_action_times"] = new JL() };
        var r = Run(Wire(Act(g)), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["policy"]);
    }

    [Fact]
    public void ADelegatedActionHasDepthOne()
    {
        var g = Mint(Env(new JL { new JD { ["type"] = "delegation_depth", ["max"] = 0L } }));
        var child = AgentOf(g).Delegate(Sub);
        var r = Run(Wire(child.Act("pay", "inv/1", Amt())), Input(g));
        Assert.Equal(new[] { "policy: caveat(s) not satisfied: delegation_depth" }, r.Reasons);
    }

    // ================= policy messages (L1191, L1195, L1197, L1216, L1230, L1257) =================

    [Fact]
    public void AGrantWithoutAnEnvelopeIsRefusedByThePolicy()
    {
        var g = Issue.MintRoot(P, Me.Id!, null, new JL());
        var r = Run(Wire(Act(g)), Input(g));
        Assert.Equal("fail", r.Checks["policy"]);
        Assert.Contains("policy: grant carries no valid envelope", r.Reasons);
    }

    [Fact]
    public void AFailingEnvelopeCaveatIsTheOnlyReason()
    {
        var g = Mint(Env(new JL { Expires(Now - 1) }));
        var r = Run(Wire(Act(g)), Input(g));
        Assert.Equal("fail", r.Checks["policy"]);
        Assert.Equal(new[] { "policy: caveat(s) not satisfied: expires" }, r.Reasons); // no "required check is ..." reason (L1230)
        Assert.False(r.Checks.ContainsKey(""));
    }

    [Fact]
    public void AFailingRootCaveatIsNamed()
    {
        var env = Env();
        env["type"] = "envelope";
        env["goal_commit"] = Issue.GoalCommit("kill b", "c2FsdHNhbHRzYWx0c2FsdA");
        env["agent_binding"] = new JD();
        var g = Issue.MintRoot(P, Me.Id!, null, new JL { env, Expires(Now - 1) });
        var r = Run(Wire(Act(g)), Input(g));
        Assert.Equal(new[] { "policy: root caveat(s) not satisfied: expires" }, r.Reasons);
    }

    [Fact]
    public void AFailingDelegatedCaveatIsNamed()
    {
        var g = Mint(Env());
        var child = AgentOf(g).Delegate(Sub, new JL { Expires(Now - 1) });
        var r = Run(Wire(child.Act("pay", "inv/1", Amt())), Input(g));
        Assert.Equal("fail", r.Checks["delegated_caveats"]);
        Assert.Equal(new[] { "delegated_caveats: delegation caveat(s) not satisfied: expires" }, r.Reasons);
    }

    [Fact]
    public void AFailedRequiredCheckIsNotReportedAgain()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.IsRevoked = (_, _) => true;
        var r = Run(Wire(Act(g)), i);
        Assert.Equal(new[] { "revocation: the grant is revoked" }, r.Reasons);
    }

    // ================= required checks (L1254, L1260) =================

    [Fact]
    public void AnAbsentRequiredCheckIsDefaultDeny()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Require = new[] { "custom_x" };
        var r = Run(Wire(Act(g)), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["custom_x"]);
        Assert.Equal(new[] { "custom_x: required check is absent (default-deny: not enforced by this resource server)" }, r.Reasons);
    }

    // ================= K1 caveat language (L1168-L1222, L1373-L1377) =================

    [Fact]
    public void ConfiguredK1PassesAndTakesK1CaveatsOutOfTheStockLists()
    {
        var g = Mint(Env());
        var child = AgentOf(g).Delegate(Sub, new JL { MaxUses("u1", 3) });
        var i = Input(g);
        i.K1 = _ => new K1Input();
        var r = Run(Wire(child.Act("pay", "inv/1", Amt())), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["k1_caveats"]);
        Assert.Equal("pass", r.Checks["delegated_caveats"]);
    }

    [Fact]
    public void UnconfiguredK1RefusesEveryK1CaveatAndJoinsTheReasons()
    {
        var g = Mint(Env());
        var child = AgentOf(g).Delegate(Sub, new JL { MaxUses("u1", 3), MaxUses("u2", 3) });
        var r = Run(Wire(child.Act("pay", "inv/1", Amt())), Input(g));
        Assert.Equal("fail", r.Checks["k1_caveats"]);
        Assert.Equal("pass", r.Checks["delegated_caveats"]); // the K1 caveats are not left to the stock evaluator
        const string Why = "max_uses (the caveat language is not configured (no k1 input))";
        Assert.Equal(new[] { $"k1_caveats: caveat(s) not satisfied: {Why}; {Why}" }, r.Reasons);
    }

    [Fact]
    public void MaxUsesIsSpentAfterTheClaimAndRefusesWhenExhausted()
    {
        var g = Mint(Env());
        var child = AgentOf(g).Delegate(Sub, new JL { MaxUses("u1", 1) });
        var i = Input(g);
        i.K1 = _ => new K1Input();
        var first = Run(Wire(child.Act("pay", "inv/1", Amt())), i);
        Assert.True(first.Allow, first.Reason);
        var second = Run(Wire(child.Act("pay", "inv/1", Amt())), i);
        Assert.False(second.Allow);
        Assert.Equal("fail", second.Checks["k1_caveats"]);
        Assert.Equal("k1_caveats: max_uses 'u1' is exhausted", second.Reason);
        Assert.Contains("k1_caveats: max_uses 'u1' is exhausted", second.Reasons);
    }

    [Fact]
    public void AThrowingK1CallbackFailsClosed()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.K1 = _ => throw new InvalidOperationException("k1");
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["k1_caveats"]);
        Assert.Equal(new[] { "k1_caveats: the K1 input callback failed (fail closed)" }, r.Reasons);
    }

    [Fact]
    public void TheK1CallbacksInputIsUsed()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.K1 = _ => new K1Input { Narrow = "junk" }; // a present malformed narrow block is refused
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["k1_caveats"]);
    }

    static Func<JD, K1Input?> NarrowWith(JD grant, JL caveats) =>
        _ => new K1Input { Narrow = Issue.Narrow(Me, Issue.NormJ(grant), caveats, null, Now, Now + 60_000) };

    [Fact]
    public void ANarrowBlocksPlainCaveatsJoinTheDelegatedList()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.K1 = NarrowWith(g, new JL { Expires(Now - 1) });
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("pass", r.Checks["k1_caveats"]);
        Assert.Equal("fail", r.Checks["delegated_caveats"]);
        Assert.Contains("delegated_caveats: delegation caveat(s) not satisfied: expires", r.Reasons);
    }

    static string EmptyChain(JD pcactn)
    {
        pcactn["cap_chain"] = new JL();
        return Wire(pcactn);
    }

    [Fact]
    public void ANarrowBlockIsEvaluatedEvenWithAnEmptyChain()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.K1 = NarrowWith(g, new JL { Expires(Now - 1) });
        var r = Run(EmptyChain(Act(g)), i);
        Assert.Equal("fail", r.Checks["delegated_caveats"]);
        Assert.Contains("delegated_caveats: delegation caveat(s) not satisfied: expires", r.Reasons);
    }

    [Fact]
    public void AnEmptyChainHasNoDelegatedCaveatsAndNoHolder()
    {
        var g = Mint(Env());
        var r = Run(EmptyChain(Act(g)), Input(g));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["chain"]);
        Assert.Equal("pass", r.Checks["policy"]); // the full pipeline ran (no "authorize: error" refusal)
        Assert.False(r.Checks.ContainsKey("delegated_caveats"));
    }

    // ================= fail-closed catches (L1227, L1271) =================

    [Fact]
    public void APolicyEvaluationErrorFailsClosed()
    {
        var g = Mint(Env());
        var trap = new Trap { Key = "caveats" };
        var tg = new JD(Issue.NormJ(g), trap);
        var i = Input(g);
        i.ResolveGrant = _ => tg;
        i.K1 = _ => { trap.Armed = true; return new K1Input(); }; // armed after the envelope was read, before the policy step
        var r = Run(EmptyChain(Act(g)), i);
        Assert.Equal("fail", r.Checks["policy"]);
        Assert.Contains("policy: policy evaluation error (fail closed)", r.Reasons);
    }

    [Fact]
    public void AProvenanceGateErrorFailsClosed()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.ProvenanceFlow = new ArgProvenanceOptions { Mediators = new ThrowingPins() };
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Equal(new[] { "provenance_flow: evaluation error (fail closed)" }, r.Reasons);
    }

    [Fact]
    public void ANullObservationListIsEmpty()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.ProvenanceFlow = new ArgProvenanceOptions { Mediators = new[] { ProvHarness.Pin }, Observed = (_, _, _) => null };
        var r = Run(Wire(Act(g)), i);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["provenance_flow"]);
    }

    // ================= assurance (L1242, L1245) =================

    [Fact]
    public void TheConfiguredAssuranceHooksLabelTheReport()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.AssuranceHooks = new AssuranceHooks(Revocation: AssuranceLabels.Set(new object(), new AssuranceLabel("hardware", "acme")));
        var r = Run(Wire(Act(g)), i);
        Assert.True(r.Allow, r.Reason);
        var e = r.Assurance.Get("revocation")!;
        Assert.Equal(("hardware", "acme"), (e.Level, e.Vendor));
    }

    static AuthorizeResult ModelCase(string name)
    {
        var doc = Conf.Load("model-rules-vectors.json");
        var c = Conf.L(doc["cases"]).Select(Conf.D).First(x => (string)x["name"]! == name);
        var grant = Conf.D(c["grant"]);
        var op = Conf.D(c["operation"]);
        var input = new AuthorizeInput
        {
            Audience = (string)doc["audience"]!, Now = Conf.N(doc["now"]), Plan = "single-step", StateStore = new MemoryStateStore(),
            Operation = new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]), ResolveGrant = _ => grant, IsRevoked = (_, _) => false,
        };
        if (c.TryGetValue("intent_v2", out var v2)) input.IntentV2 = IntentV2Context.FromJson(v2);
        if (c.GetValueOrDefault("context") is JD cx) input.Context = _ => new JD { ["env"] = cx.GetValueOrDefault("env") };
        return Pca.Authorize(c["pcactn"], input.WithProv());
    }

    [Fact]
    public void LegacyPolarityDegradesTheTightenEntryOfTheReport()
    {
        var r = ModelCase("legacy-model-path");
        Assert.True(r.Allow, r.Reason);
        var e = r.Assurance.Get("tighten")!;
        Assert.Equal("pass", e.Outcome);
        Assert.True(e.Degraded);
        Assert.Equal(Pca.LegacyPolarityDegraded, e.Reason);
    }

    [Fact]
    public void APassingTightenWithoutLegacyPolarityIsNotDegraded()
    {
        var r = ModelCase("tighten-quiet");
        Assert.True(r.Allow, r.Reason);
        var e = r.Assurance.Get("tighten")!;
        Assert.Equal("pass", e.Outcome);
        Assert.False(e.Degraded);
        Assert.Null(e.Reason);
    }

    // ================= escalation / replay tail (L1295-L1368) =================

    [Fact]
    public void AReplayedCounterUnderAnEscalationIsADeny()
    {
        var g = Mint(Env());
        var store = new MemoryStateStore();
        store.Claim(Pca.StateKey((string)Issue.NormJ(g)["id"]!, Me.Id!), 5);
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(Act(g)), Input(g, store: store));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["replay"]);
        Assert.Contains("replay: 1 is not greater than last seen 5 (replay)", r.Reasons);
    }

    [Fact]
    public void AnAnswerOverTheRecomputedRenderIsAdmitted()
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
        Assert.Equal(P.Ed!.Id, r.Escalation!["answered_by"]);
        Assert.Equal("pass", r.Checks["escalation"]);
    }

    [Fact]
    public void AnEscalationRequestThatCannotBeBuiltIsADeny()
    {
        var g = Mint(Env());
        var trap = new Trap { Key = "id", ThrowOnHit = 1 }; // the request's policy digest is the first grant read after the render
        var tg = new JD(Issue.NormJ(g), trap);
        var i = Input(g);
        i.ResolveGrant = _ => tg;
        i.EscalationRender = _ => { trap.Armed = true; return Pca.HashCanonical("render"); };
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(Act(g)), i);
        Assert.False(r.Allow);
        Assert.Equal("deny", r.Decision);
        Assert.Null(r.Escalation);
        Assert.Equal("fail", r.Checks["esc_probe"]);
    }

    [Fact]
    public void AnAnswerErrorFailsClosed()
    {
        var g = Mint(Env());
        var trap = new Trap { Key = "id", ThrowOnHit = 2 }; // the request digest passes, the answer binding's digest throws
        var tg = new JD(Issue.NormJ(g), trap);
        var i = Input(g);
        i.ResolveGrant = _ => tg;
        i.EscalationPrincipals = new PinnedSigner[] { P.Ed!.Id };
        i.EscalationAnswer = new JD();
        i.EscalationRender = _ => { trap.Armed = true; return Pca.HashCanonical("render"); };
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(Act(g)), i);
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.Contains("escalation: escalation answer error (fail closed)", r.Reasons);
        Assert.DoesNotContain("escalation: the principal answered deny", r.Reasons);
    }

    [Fact]
    public void AStoreWithoutAHistoryHeadNeverJudgesAnAnswer()
    {
        var g = Mint(Env());
        var i = Input(g, store: new ClaimOnly());
        i.InsecureUnboundApproval = true;
        i.EscalationAnswer = new JD();
        AuthorizeResult r;
        using (new Hook(EscProbe)) r = Run(Wire(Act(g)), i);
        Assert.Equal("escalate", r.Decision);
        Assert.DoesNotContain(r.Reasons, x => x.StartsWith("escalation:", StringComparison.Ordinal));
    }

    [Fact]
    public void ANegativeCounterHasNoCounterStream()
    {
        var g = Mint(Env());
        var a = AgentOf(g, counter: -2).Act("pay", "inv/1", Amt()); // counter -1
        AuthorizeResult r;
        using (new Hook(v => { foreach (var k in v.Checks.Keys.ToList()) v.Checks[k] = true; v.Allow = true; v.Reason = ""; v.Reasons = new List<string>(); }))
            r = Run(Wire(a), Input(g));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["replay"]);
        Assert.Equal(new[] { "replay: no counter stream for this proof (fail closed)" }, r.Reasons);
    }

    [Fact]
    public void AClaimRefusedWithoutALastCounterWasAlreadyClaimed()
    {
        var g = Mint(Env());
        var r = Run(Wire(Act(g)), Input(g, store: new AlreadyClaimed()));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["replay"]);
        Assert.Equal(new[] { "replay: 1 was already claimed (replay)" }, r.Reasons.Where(x => !x.StartsWith("budget:")).ToArray()); // a store without a budget seam adds the deny-metered note
    }

    // ================= Decisive (L1447-L1453) =================

    static AuthorizeResult Decided(Action<Verdict> hook)
    {
        var g = Mint(Env());
        using (new Hook(hook)) return Run(Wire(Act(g)), Input(g));
    }

    [Fact]
    public void TheDecisiveReasonIsTheFirstFailingChecksOwn()
    {
        // reasons[0] belongs to a PASSING check: it is never decisive
        var r = Decided(v => { v.Allow = false; v.Checks["validity"] = false; v.Reasons = new List<string> { "audience: decoy", "validity: real" }; v.Reason = "audience: decoy"; });
        Assert.Equal("validity: real", r.Reason);
    }

    [Fact]
    public void AFailingCheckWithoutAReasonFallsBackToTheFirstReason()
    {
        var r = Decided(v => { v.Allow = false; v.Checks["validity"] = false; v.Reasons = new List<string> { "other: first" }; v.Reason = "other: first"; });
        Assert.Equal("validity", r.Checks.Single(kv => kv.Value == "fail").Key);
        Assert.Equal("other: first", r.Reason);
    }

    [Fact]
    public void TheDecisiveReasonMatchesTheCheckNameAndColon()
    {
        var r = Decided(v => { v.Allow = false; v.Checks["validity"] = false; v.Reasons = new List<string> { "validityx: decoy", "validity: real" }; v.Reason = "validityx: decoy"; });
        Assert.Equal("validity: real", r.Reason);
    }

    [Fact]
    public void NoReasonAtAllIsDenied()
    {
        var r = Decided(v => v.Checks["validity"] = false); // allow stays true: no core reason
        Assert.False(r.Allow);
        Assert.Empty(r.Reasons);
        Assert.Equal("denied", r.Reason);
    }

    [Fact]
    public void TheOperationIsDecisiveBeforeEarlierChecks()
    {
        var g = Mint(Env());
        var i = Input(g, new Operation("pay", "inv/1", new JD { ["amount"] = 6L }));
        i.IsRevoked = (_, _) => true;
        var r = Run(Wire(Act(g)), i);
        Assert.Equal("fail", r.Checks["revocation"]);
        Assert.Equal("operation: the proof's params_digest does not match the params of this pay operation", r.Reason);
    }

    [Fact]
    public void ThePlanStateIsDecisiveBeforeLaterChecks()
    {
        var g = Mint(Env());
        var a = AgentOf(g);
        var node = Node("s1");
        var plan = a.CommitPlan(new[] { node });
        var pcactn = a.ActNode("s1", Amt());
        var reg = new PlanRegistry();
        var t = reg.Draft((string)Issue.NormJ(g)["id"]!, new[] { node });
        Assert.True(t.Ok, t.Reason);
        Assert.Equal(plan.Root, t.Record!.Root);
        var i = Input(g);
        i.Plans = reg;
        var r = Run(Wire(pcactn), i);
        Assert.Equal("fail", r.Checks["plan_root_authorized"]);
        Assert.Contains("plan_root_authorized: the plan root has not been authorized by the principal", r.Reasons);
        Assert.Equal($"plan_state: plan {plan.Root} is draft, not authorized", r.Reason);
    }

    // ================= NodeLeaf (L1461, L1462, L1469) =================

    [Fact]
    public void NodeLeafRefusesAMissingIdVerbOrResource()
    {
        Assert.Equal("missing node id", Assert.Throws<InvalidOperationException>(() => Pca.NodeLeaf(new JD { ["verb"] = "v", ["resource"] = "r" })).Message);
        Assert.Equal("missing verb / resource", Assert.Throws<InvalidOperationException>(() => Pca.NodeLeaf(new JD { ["id"] = "n", ["verb"] = "v" })).Message);
        Assert.Equal("missing verb / resource", Assert.Throws<InvalidOperationException>(() => Pca.NodeLeaf(new JD { ["id"] = "n", ["resource"] = "r" })).Message);
    }

    [Fact]
    public void NodeLeafDigestsPreAndPost()
    {
        var pre = new JL { new JD { ["field"] = "action.params.a", ["op"] = "eq", ["value"] = 1L } };
        var post = new JL { new JD { ["field"] = "action.params.b", ["op"] = "eq", ["value"] = 2L } };
        var leaf = Pca.NodeLeaf(new JD { ["id"] = "n", ["verb"] = "v", ["resource"] = "r", ["pre"] = pre, ["post"] = post });
        Assert.Equal(Pca.ConditionsDigest(pre, post), leaf["conditions"]);
        Assert.NotEqual(Pca.ConditionsDigest(null, post), leaf["conditions"]);
        Assert.NotEqual(Pca.ConditionsDigest(pre, null), leaf["conditions"]);
    }

    // ================= EnvelopePredicates (L1479, L1485) =================

    static JD ActionCtx() => new() { ["action"] = new JD { ["verb"] = "x", ["resource"] = "r" } };

    [Fact]
    public void OneMatchingPredicatePermits()
    {
        Assert.Null(Pca.EnvelopePredicates(new JL { new JD { ["verb"] = "other" }, new JD { ["verb"] = "*" } }, ActionCtx()));
    }

    [Fact]
    public void APredicateEvaluationErrorFailsClosed()
    {
        var trap = new Trap { Key = "action" };
        var ctx = new JD(ActionCtx(), trap);
        trap.Armed = true;
        Assert.Equal("predicate evaluation error (fail closed)", Pca.EnvelopePredicates(new JL { new JD { ["verb"] = "*" } }, ctx));
    }

    // ================= V2Env (L1491-L1494) =================

    static readonly string[] V2Keys = { "acc", "mon", "canon", "world", "prov", "class" };
    static readonly MethodInfo V2EnvM = typeof(Pca).GetMethod("V2Env", BindingFlags.NonPublic | BindingFlags.Static)!;

    static JD HostEnv()
    {
        var e = new JD { ["keep"] = "k" };
        foreach (var k in V2Keys) e[k] = "host";
        return e;
    }

    static JD V2Env(JD p, JD grant, IntentV2Context? v2, long now) => (JD)V2EnvM.Invoke(null, new object?[] { p, grant, v2, now, HostEnv() })!;

    /// <summary>TypeScript v2Env: the host env without the six verifier-computed members, then every non-null member the v2 pipeline computed.</summary>
    static void AssertV2Env(JD got, JD p, JD grant, IntentV2Context? v2, long now)
    {
        var want = HostEnv();
        foreach (var k in V2Keys) want.Remove(k);
        foreach (var (k, v) in IntentV2.Decide(p, grant, v2, now).Env) if (v != null) want[k] = v;
        Assert.Equal(want.Keys.OrderBy(k => k, StringComparer.Ordinal), got.Keys.OrderBy(k => k, StringComparer.Ordinal));
        foreach (var (k, v) in want) Assert.True(IntentJs.JsonEquals(v, got[k]), "member " + k);
        // a host value never survives for a verifier-computed member
        foreach (var k in V2Keys) Assert.False(got.TryGetValue(k, out var hv) && hv is "host", "host " + k + " survived");
        Assert.Equal("k", got["keep"]);
    }

    static (JD Case, JD Doc) UnitsMatch()
    {
        var doc = Conf.Load("model-rules-vectors.json");
        return (Conf.L(doc["cases"]).Select(Conf.D).First(x => (string)x["name"]! == "units-match"), doc);
    }

    [Fact]
    public void V2EnvDropsTheHostsVerifierMembers()
    {
        var (c, doc) = UnitsMatch();
        var p = new JD(Conf.D(c["pcactn"])) { ["intent_session"] = 1L }; // a session the v2 pipeline cannot use: it computes nothing
        var grant = Conf.D(c["grant"]);
        var now = Conf.N(doc["now"]);
        AssertV2Env(V2Env(p, grant, null, now), p, grant, null, now);
    }

    [Fact]
    public void V2EnvCarriesTheComputedMembers()
    {
        var (c, doc) = UnitsMatch();
        var op = Conf.D(c["operation"]);
        var v2 = IntentV2Context.FromJson(c["intent_v2"]).WithDefaults(Pca.OperationParamsTree(op["params"]), null);
        var schema = ((JL)v2.Get("schema", "docs")!)[0];
        var p = new JD(Conf.D(c["pcactn"])) { ["intent_session"] = new JD { ["schema"] = ActionSchema.Digest(schema) } };
        var grant = Conf.D(c["grant"]);
        var now = Conf.N(doc["now"]);
        var got = V2Env(p, grant, v2, now);
        AssertV2Env(got, p, grant, v2, now);
        Assert.True(got.TryGetValue("canon", out var canon) && canon != null && canon is not "host", "the schema's canon projection is exported");
        // without an intent_session the host env is returned as is
        var bare = Conf.D(c["pcactn"]);
        var host = HostEnv();
        Assert.Same(host, V2EnvM.Invoke(null, new object?[] { bare, grant, v2, now, host }));
    }

    // ================= IsAuthorizedFor (L1504, L1509) =================

    [Fact]
    public void IsAuthorizedForNeedsAnAllowAndAReadableOperation()
    {
        var prms = new JD { ["a"] = 1L };
        var bound = new AuthorizedOperation("v", "r", Pca.ParamsDigest(prms), "id");
        Assert.True(Pca.IsAuthorizedFor(new AuthorizeResult { Allow = true, Operation = bound }, new Operation("v", "r", prms)));
        Assert.False(Pca.IsAuthorizedFor(new AuthorizeResult { Allow = false, Operation = bound }, new Operation("v", "r", prms)));
        // an operation whose params cannot be read throws inside: false, never true
        Assert.False(Pca.IsAuthorizedFor(new AuthorizeResult { Allow = true, Operation = bound }, new Operation("v", "r", new JD { ["a"] = new object() })));
    }

    // ================= FreshAt.cs =================

    static EdKey Rs => EdKey.FromSeed(Enumerable.Repeat((byte)0x51, 32).ToArray());
    static EdKey Other => EdKey.FromSeed(Enumerable.Repeat((byte)0x52, 32).ToArray());

    /// <summary>A token signed by <see cref="Rs"/> over exactly its (possibly malformed) members.</summary>
    static JD Tok(Action<JD>? tweak = null)
    {
        var b = new JD
        {
            ["v"] = 1L, ["scope"] = "s", ["revocation_epoch"] = 1L, ["ledger_tree_size"] = 1L, ["budget_version"] = 1L, ["policy_revision"] = 1L,
            ["policy_digest"] = "pd", ["issued_at"] = Now, ["signer"] = Rs.Id,
        };
        tweak?.Invoke(b);
        var n = Issue.NormJ(b);
        n["sig"] = Issue.SignBody(Rs, FreshAt.Domain, n);
        return n;
    }

    static FreshAtState Local() => new(1, 1, 1, 1, "pd");

    [Fact]
    public void FreshAtVerifyStringBounds()
    {
        Assert.True(FreshAt.Verify(Tok(), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["scope"] = ""), Rs.Id));
        Assert.True(FreshAt.Verify(Tok(b => b["scope"] = new string('a', 256)), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["scope"] = new string('a', 257)), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["policy_digest"] = ""), Rs.Id));
        Assert.True(FreshAt.Verify(Tok(b => b["policy_digest"] = new string('a', 128)), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["policy_digest"] = new string('a', 129)), Rs.Id));
    }

    [Fact]
    public void FreshAtVerifyRefusesEachMalformedMemberEvenWhenSigned()
    {
        Assert.False(FreshAt.Verify(Tok(b => b["signer"] = Other.Id), Rs.Id)); // signed by the pinned key, but naming another signer
        Assert.False(FreshAt.Verify(Tok(b => b["v"] = 2L), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["issued_at"] = -1L), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["revocation_epoch"] = -1L), Rs.Id));
        Assert.False(FreshAt.Verify(Tok(b => b["policy_revision"] = -1L), Rs.Id));
    }

    [Fact]
    public void FreshAtVerifyFailsClosedOnAnError()
    {
        var trap = new Trap { Key = "v" };
        var t = new JD(Tok(), trap);
        trap.Armed = true;
        Assert.False(FreshAt.Verify(t, Rs.Id));
    }

    [Fact]
    public void FreshAtCheckFailsClosedOnAnErrorAsBadToken()
    {
        Assert.Equal("ok", FreshAt.Check(Tok(), Local(), Rs.Id, "s", Now).Decision);
        var v = FreshAt.Check(Tok(), null!, Rs.Id, "s", Now);
        Assert.Equal(("deny", "bad_token"), (v.Decision, v.Code));
    }

    [Fact]
    public void FreshAtWireErrorMessages()
    {
        Assert.Null(FreshAt.WireError(Tok()));
        Assert.Null(FreshAt.WireError(Tok(b => b["scope"] = new string('a', 256))));
        Assert.Equal("'fresh_at.v' must be 1", FreshAt.WireError(Tok(b => b["v"] = 2L)));
        const string Strs = "'fresh_at' scope and policy_digest must be non-empty strings";
        Assert.Equal(Strs, FreshAt.WireError(Tok(b => b["policy_digest"] = "")));
        Assert.Equal(Strs, FreshAt.WireError(Tok(b => b["scope"] = "")));
        Assert.Equal(Strs, FreshAt.WireError(Tok(b => b["scope"] = new string('a', 257))));
        Assert.Equal("'fresh_at.signer' is not canonical base64url (32 bytes)", FreshAt.WireError(Tok(b => b["signer"] = "abc")));
    }
}
