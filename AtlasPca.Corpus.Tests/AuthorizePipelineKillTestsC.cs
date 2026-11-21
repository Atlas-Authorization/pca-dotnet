using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 survivors of Authorize.cs and FreshAt.cs left by parts A and B: the single-step plan guard, the separators of the joined
/// caveat lists, the plan node's reversibility class (past the wire check only through CoreHook), the fail-closed catches (through their
/// seams) and the required-check statuses of bond and provenance_flow. Wording pinned to packages/pca/src.</summary>
public class AuthorizePipelineKillTestsC
{
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_c";
    const string NotEnforced = "(default-deny: not enforced by this resource server)";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x61, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x62, 32).ToArray()));
    static SuiteKey Sub => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x63, 32).ToArray()));

    static JD Amt() => new() { ["amount"] = 5L };

    static JD Env(JL? caveats = null) => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = caveats ?? new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static JD Mint(JD env) => Issue.MintGrant(P, Me.Id!, null, env, "kill c").Grant;
    static Agent AgentOf(JD grant) => new(Me, Aud, grant, null, 0) { Clock = () => Now };
    static string Wire(JD pcactn) => Issue.Encode(pcactn);
    static string ActWire(JD grant) => Wire(AgentOf(grant).Act("pay", "inv/1", Amt()));

    static AuthorizeInput Input(JD grant)
    {
        var g = Issue.NormJ(grant);
        return new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
    }

    static AuthorizeResult Run(object pcactn, AuthorizeInput i) => Pca.Authorize(pcactn, i.WithProv());

    static JD Expired() => new() { ["type"] = "expires", ["at"] = Now - 1 };
    static JD NotYet() => new() { ["type"] = "not_before", ["at"] = Now + 1 };

    // ================= L1015: single-step never reports an unknown plan (server/authorize.ts:320, plan-lifecycle.test.ts:211) =================

    [Fact]
    public void ASingleStepCallIsNotRefusedForAPlanTheRegistryDoesNotKnow()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Plans = new PlanRegistry();
        var r = Run(ActWire(g), i);
        Assert.True(r.Allow, r.Reason);
        Assert.False(r.Checks.ContainsKey("plan_state"));
    }

    // ================= L1205, L1207, L1226: the joined lists (policy-vm.ts:317, :329; server/verify.ts:497) =================

    [Fact]
    public void TwoFailingEnvelopeCaveatsAreJoined()
    {
        var g = Mint(Env(new JL { Expired(), NotYet() }));
        Assert.Equal(new[] { "policy: caveat(s) not satisfied: expires, not_before" }, Run(ActWire(g), Input(g)).Reasons);
    }

    [Fact]
    public void TwoFailingRootCaveatsAreJoined()
    {
        var env = Env();
        env["type"] = "envelope";
        env["goal_commit"] = Issue.GoalCommit("kill c", "c2FsdHNhbHRzYWx0c2FsdA");
        env["agent_binding"] = new JD();
        var g = Issue.MintRoot(P, Me.Id!, null, new JL { env, Expired(), NotYet() });
        Assert.Equal(new[] { "policy: root caveat(s) not satisfied: expires, not_before" }, Run(ActWire(g), Input(g)).Reasons);
    }

    [Fact]
    public void TwoFailingDelegatedCaveatsAreJoined()
    {
        var g = Mint(Env());
        var child = AgentOf(g).Delegate(Sub, new JL { Expired(), NotYet() });
        var r = Run(Wire(child.Act("pay", "inv/1", Amt())), Input(g));
        Assert.Equal("fail", r.Checks["delegated_caveats"]);
        Assert.Equal(new[] { "delegated_caveats: delegation caveat(s) not satisfied: expires, not_before" }, r.Reasons);
    }

    // ================= L1167-L1168: the class of the plan node the action names (policy-vm.ts:154-159, mutation-kill-policy-vm.test.ts:192-197) =================

    static JD Node(string id, string cls) => new()
    {
        ["id"] = id, ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = cls,
    };

    /// <summary>The agent's action n1 without a signed class. The wire check refuses it, so it goes further only with the verdict lifted.</summary>
    static JD NoClass(JD grant)
    {
        var p = (JD)Pca.ParseStrict(ActWire(grant))!;
        ((JD)p["action"]!).Remove("reversibility_class");
        return p;
    }

    static AuthorizeResult RunLifted(JD grant, JL plan)
    {
        var i = Input(grant);
        i.Context = _ => new JD { ["plan"] = plan, ["plan_authorized"] = true };
        Pca.CoreHook = v =>
        {
            foreach (var k in v.Checks.Keys.ToList()) v.Checks[k] = true;
            v.Allow = true;
            v.Reason = "";
            v.Reasons = new List<string>();
        };
        try { return Run(NoClass(grant), i); }
        finally { Pca.CoreHook = null; }
    }

    static JD MaxReversible() => Mint(Env(new JL { new JD { ["type"] = "reversibility_max", ["class"] = "reversible" } }));

    [Fact]
    public void AnActionWithoutAClassIsAWireFailure()
    {
        var g = MaxReversible();
        var r = Run(NoClass(g), Input(g));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["wire"]);
    }

    [Fact]
    public void TheClassComesFromTheNamedNode()
    {
        var g = MaxReversible();
        var r = RunLifted(g, new JL { Node("n0", "irreversible"), Node("n1", "reversible") });
        Assert.Equal("pass", r.Checks["policy"]);
        Assert.DoesNotContain(r.Reasons, x => x.StartsWith("policy:", StringComparison.Ordinal));
        var other = RunLifted(g, new JL { Node("n0", "reversible"), Node("n1", "irreversible") });
        Assert.Equal("fail", other.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", other.Reasons);
    }

    [Fact]
    public void APlanWithoutTheNamedNodeHasNoClassAndNoErrorEither()
    {
        var r = RunLifted(MaxReversible(), new JL { Node("other", "reversible") });
        Assert.Equal("fail", r.Checks["policy"]); // the pipeline ran: no "authorize: error" refusal
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", r.Reasons);
    }

    // ================= L1194: the K1 check's catch; FreshAt L131: Decide's catch (seams) =================

    [Fact]
    public void AK1CheckErrorFailsClosed()
    {
        var g = Mint(Env());
        AuthorizeResult r;
        Pca.K1CheckHook = () => throw new InvalidOperationException("boom");
        try { r = Run(ActWire(g), Input(g)); }
        finally { Pca.K1CheckHook = null; }
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["k1_caveats"]);
        Assert.Equal(new[] { "k1_caveats: the K1 caveats could not be checked (fail closed)" }, r.Reasons);
    }

    [Fact]
    public void AFreshAtDecideErrorIsABadToken()
    {
        FreshAt.DecideHook = () => throw new InvalidOperationException("boom");
        try { Assert.Equal(new FreshAtCheck("fail", "bad_token"), FreshAt.Decide(null, false, null, Now)); }
        finally { FreshAt.DecideHook = null; }
        Assert.Equal(new FreshAtCheck("none", null), FreshAt.Decide(null, false, null, Now));
    }

    // ================= L1270: a required check that is present but unproved (server/breaking-05.test.ts:158-165) =================

    static JD WithBond(JD grant)
    {
        var p = (JD)Pca.ParseStrict(ActWire(grant))!;
        p["bond_ref"] = "bond-1";
        p.Remove("sig");
        p["sig"] = Me.Sign(Pca.ThresholdMessage(p)).Sig;
        return p;
    }

    [Fact]
    public void ARequiredBondIsNamedUnsupportedEvenWhenAllowed()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.AllowUnsupported = new[] { "bond" };
        i.Require = new[] { "bond" };
        var r = Run(WithBond(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["bond"]);
        Assert.Equal(new[] { $"bond: required check is unsupported {NotEnforced}" }, r.Reasons);
    }

    [Fact]
    public void ARequiredBondThatIsNotAllowedReportsBothReasons()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Require = new[] { "bond" };
        var r = Run(WithBond(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["bond"]);
        Assert.Contains($"bond: required check is unsupported {NotEnforced}", r.Reasons);
        Assert.Contains("bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)", r.Reasons);
    }

    // ================= a required provenance_flow stays refused (server/require-pca.ts:853-868) =================

    static JD OptedOut()
    {
        var env = Env();
        env["provenance"] = new JD { ["mode"] = "insecure_off" };
        return Mint(env);
    }

    [Fact]
    public void ARequiredProvenanceFlowIsNotLiftedByAnUnenforcedGate()
    {
        var g = OptedOut();
        var i = Input(g);
        i.Require = new[] { "provenance_flow" };
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Equal(new[] { $"provenance_flow: required check is absent {NotEnforced}" }, r.Reasons);
        // not required: the principal's signed opt-out is reported and allowed
        var free = Run(ActWire(g), Input(g));
        Assert.True(free.Allow, free.Reason);
        Assert.Equal("not-enforced", free.Checks["provenance_flow"]);
    }

    [Fact]
    public void ARequiredProvenanceFlowIsNotLiftedByAPassingGate()
    {
        var g = Mint(Env());
        var i = Input(g);
        i.Require = new[] { "provenance_flow" };
        var r = Run(ActWire(g), i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Equal(new[] { $"provenance_flow: required check is absent {NotEnforced}" }, r.Reasons);
        var free = Run(ActWire(g), Input(g));
        Assert.True(free.Allow, free.Reason);
        Assert.Equal("pass", free.Checks["provenance_flow"]);
    }
}
