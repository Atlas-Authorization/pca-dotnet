using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The facade (Agent.FromPrincipal) and the agent-side signers' refusals. The exact compile-down and wire are pinned by the producer
// vectors; these pin the handle's behaviour around them.
public class FacadeTests
{
    const string Aud = "rs-test";

    static string Refusal(Action f) => Assert.Throws<ArgumentException>(f).Message;

    static AgentHandle Refunds(SuiteKey? holder = null) => Agent.FromPrincipal(new AgentOptions
    {
        Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = holder ?? SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
        Permissions = new JD { ["stripe"] = new JL { "refund" }, ["gmail"] = new JL { "draft" } },
        Limits = new Dictionary<string, string> { ["refund"] = "$500/day" }, Aud = Aud, Now = 1_000_000,
    });

    static Verdict Verify(JD pcactn, JD grant, long now) => Pca.VerifyPcactnCore(Issue.NormJ(pcactn), Issue.NormJ(grant), now, Aud, planRoots: PlanRootPolicy.Skip);

    [Fact]
    public void ActBuildsOneVerifiableActionPerCall()
    {
        var ag = Refunds();
        ag.Provenance.Principal("refund order 1");
        var r = ag.Act("stripe.refund", "charge:ch_1", new JD { ["amount"] = 125L, ["currency"] = "usd" }, new ActOptions { Now = 2_000_000 });
        var p = r.PCActn;
        Assert.False(p.ContainsKey("nonce")); // the facade signs no nonce nobody asked for
        Assert.Equal("1", Pca.Canonicalize(p["counter"]));
        Assert.Equal("n0", ((JD)p["plan"]!)["node_id"]);
        Assert.Equal((2_000_000 + Issue.DefaultTtlMs).ToString(), Pca.Canonicalize(p["exp"]));
        Assert.Equal("{\"inputs\":{\"blastRadius\":0.25},\"r\":0.25}", Pca.Canonicalize(p["risk_claim"]));
        Assert.Equal("irreversible", ((JD)p["action"]!)["reversibility_class"]);
        Assert.Equal(new DryRunResult(true, null, 1), r.DryRun);
        Assert.Equal(Issue.Header(p), r.Headers["PCA-Action"]);
        Assert.Equal(Issue.Encode(p), r.Encoded);
        Assert.Equal(Pca.B64u(System.Text.Encoding.UTF8.GetBytes(Pca.Canonicalize(r.Provenance))), r.Headers["PCA-Provenance"]);
        Assert.Equal(2, ((JL)r.Provenance["receipts"]!).Count);
        var v = Verify(p, ag.Grant, 2_000_000);
        Assert.True(v.Allow, v.Reason);
        Assert.Equal(Pca.Canonicalize(ag.Grant), ag.EncodeGrant());
        Assert.Equal(500.0, ag.Budget.B);
        Assert.Equal(500.0, ag.AutonomyBound);
    }

    [Fact]
    public void CountersRiskAndDryRun()
    {
        var ag = Refunds();
        var r5 = ag.Act("gmail.draft", "t", null, new ActOptions { Counter = 5, Now = 2_000_000, Nonce = "n" });
        var r6 = ag.Act("gmail.draft", "t", null, new ActOptions { Now = 2_000_000 });
        Assert.Equal("5", Pca.Canonicalize(r5.PCActn["counter"]));
        Assert.Equal("6", Pca.Canonicalize(r6.PCActn["counter"]));
        Assert.Equal("n", r5.PCActn["nonce"]);
        var rr = ag.Act("stripe.refund", "c", new JD { ["amount"] = 1L }, new ActOptions { Risk = 0.7, Now = 2_000_000 });
        Assert.Equal("0.7", Pca.Canonicalize(((JD)rr.PCActn["risk_claim"]!)["r"]));

        var over = ag.DryRun("stripe.refund", "charge:ch_1", new JD { ["amount"] = 600L }, 2_000_000);
        Assert.False(over.Allowed);
        Assert.EndsWith(" not satisfied for stripe.refund on charge:ch_1", over.Reason);
        Assert.Equal(new DryRunResult(false, "caveat(s) failed: expires"), ag.DryRun("stripe.refund", "charge:ch_1", new JD { ["amount"] = 1L }, 1_000_000 + 86_400_000 + 1));
        Assert.Equal(new DryRunResult(false, "no predicate permits github.read on r"), ag.DryRun("github.read", "r", null, 2_000_000));

        var noAud = Agent.FromPrincipal(new AgentOptions { Principal = SuiteKey.Ed25519(EdKey.Generate()), Goal = "g", Permissions = new JD { ["files"] = new JL { "read" } }, Now = 1 });
        Assert.Equal("act: aud (resource-server / instance id) is required (pass ActOptions.Aud or AgentOptions.Aud)", Refusal(() => noAud.Act("files.read", "f")));
        Assert.Equal("agent: principal required", Refusal(() => Agent.FromPrincipal(new AgentOptions { Goal = "g" })));
    }

    [Fact]
    public void SubAgentAddsOneHopAndSharesTheRecorder()
    {
        var ag = Refunds();
        var sub = ag.SubAgent(addedCaveats: new JL { new JD { ["type"] = "sealed" } });
        Assert.Equal(2, sub.Chain.Count);
        Assert.NotEqual(ag.Holder.Ed!.Id, sub.Holder.Ed!.Id);
        Assert.Same(ag.Provenance, sub.Provenance);
        Assert.Equal(sub.Holder.Ed.Id, sub.Chain[1]["holder"]);
        var r = sub.Act("stripe.refund", "charge:ch_2", new JD { ["amount"] = 10L }, new ActOptions { Now = 2_000_000 });
        Assert.Equal("1", Pca.Canonicalize(r.PCActn["counter"])); // the sub-agent has its own counter
        var v = Verify(r.PCActn, sub.Grant, 2_000_000);
        Assert.True(v.Allow, v.Reason);
    }

    [Fact]
    public void PostQuantumSubAgentGetsItsOwnKey()
    {
        const string alg = "hybrid-ed25519-ml-dsa-65";
        var pq = PqKey.Generate(Pq.Prim.MlDsa65);
        var ag = Agent.FromPrincipal(new AgentOptions
        {
            Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Create(alg, EdKey.Generate(), pq), Goal = "g",
            Permissions = new JD { ["files"] = new JL { "read" } }, Aud = Aud, Now = 5,
        });
        var sub = ag.SubAgent();
        var r = sub.Act("files.read", "f", null, new ActOptions { Now = 10 });
        Assert.Equal(alg, r.PCActn["alg"]);
        Assert.NotEqual(pq.PkB64u, r.PCActn["pq_pk"]);
        var v = Verify(r.PCActn, ag.Grant, 10);
        Assert.True(v.Allow, v.Reason);
        var other = SuiteKey.Create("hybrid-ed25519-ml-dsa-87", EdKey.Generate(), PqKey.Generate(Pq.Prim.MlDsa87));
        Assert.Equal("subAgent: the sub-agent's key does not match the suite hybrid-ed25519-ml-dsa-65", Refusal(() => ag.SubAgent(other)));
    }

    [Fact]
    public void CompilePolicyRefusals()
    {
        Assert.Equal("compilePolicy: permissions.stripe must be an array",
            Refusal(() => Facade.CompilePolicy(new PolicyOptions { Permissions = new JD { ["stripe"] = "refund" }, Now = 1 })));
        Assert.StartsWith("compilePolicy: derived risk policy invalid: ",
            Refusal(() => Facade.CompilePolicy(new PolicyOptions { Permissions = new JD { ["files"] = new JL { "read" } }, RiskPolicy = new JD { ["kappa"] = -1L }, Now = 1 })));
        Assert.Equal("parseLimit: cannot parse limit '$-5'", Refusal(() => Facade.ParseLimit("$-5")));
        // a forced risk model keeps the default policy even with a dollar limit; an override merges member by member
        var p = Facade.CompilePolicy(new PolicyOptions
        {
            Permissions = new JD { ["files"] = new JL { "read" } }, Limits = new Dictionary<string, string> { ["read"] = "5/min" },
            RiskPolicy = new JD { ["weights"] = new JD { ["alpha"] = 0L } }, Now = 1,
        });
        Assert.Equal("risk", p.BudgetModel);
        Assert.Equal("0", Pca.Canonicalize(((JD)p.RiskPolicy["weights"]!)["alpha"]));
        Assert.Equal("0.2", Pca.Canonicalize(((JD)p.RiskPolicy["weights"]!)["beta"]));
        Assert.Equal("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"},{\"at\":60001,\"type\":\"expires\"},{\"max\":5,\"per_secs\":60,\"type\":\"rate\"}]",
            Pca.Canonicalize(p.Caveats));
    }

    [Fact]
    public void CatalogResolvesAliasesAndFallsBackConservatively()
    {
        var c = Catalog.Default;
        Assert.Equal("stripe.refund", c.SpecFor("stripe.issue_refund").Verb);
        var u = c.SpecFor("crm.export.all");
        Assert.Equal(("crm", "export.all", "irreversible", 0.8, "(uncatalogued) crm.export.all"), (u.Connector, u.Action, u.Reversibility, u.BlastRadius, u.Description));
        Assert.Null(c.Resolve("stripe", "nonsense"));
    }

    static JD IntentRequiredBody()
    {
        foreach (var x in Conf.L(Conf.Load("producer-vectors.json")["cases"]))
            if ((string)Conf.D(x)["op"]! == "sign_intent_required") return Conf.D(Conf.D(Conf.D(x)["args"])["body"]);
        throw new InvalidOperationException("no intent-required vector");
    }

    [Fact]
    public void IntentRequiredAndProgressStepRefusals()
    {
        var k = SuiteKey.Ed25519(EdKey.Generate());
        static JD Coords(JD b) => (JD)((JD)b["cell"]!)["coords"]!;
        var cases = new (Action<JD> Edit, string Want)[]
        {
            (b => b["extra"] = true, "unknown member 'extra'"),
            (b => b["kind"] = "pca-labels", "not a pca-intent-required v1"),
            (b => b["v"] = new Num("2"), "not a pca-intent-required v1"),
            (b => b["schema"] = "abc", "schema must be canonical base64url (32 bytes)"),
            (b => b["cell"] = new JD { ["verb"] = "", ["coords"] = new JD() }, "cell must be {verb, coords}"),
            (b => ((JD)b["cell"]!)["coords"] = new JD(), "coords must be an object of 1..64 dimensions"),
            (b => Coords(b)["action.params.amount_cents"] = new JL { new Num("5"), new Num("1") }, "coords 'action.params.amount_cents': need 0 <= lo <= hi"),
            (b => Coords(b)["action.params.currency"] = new JL { "USD", "USD" }, "coords 'action.params.currency': values must be distinct"),
            (b => Coords(b)["action.params.currency"] = new JL(), "coords 'action.params.currency': an index range [lo, hi] or a value set"),
            (b => Coords(b)[new string('x', 257)] = new JL { "a" }, "a coordinate path must be 1..256 characters"),
            (b => b["reason"] = "sure", "reason must be 'uncertain'"),
            (b => b["question_id"] = "q 1", "question_id must match [A-Za-z0-9_-]{1,64}"),
            (b => b["friction"] = "swipe", "unknown friction tier"),
            (b => b["delivered_to"] = "email", "delivered_to must be 'wallet' or 'agent'"),
            (b => b["expires_at"] = new Num("-1"), "expires_at must be a non-negative safe integer"),
            (b => b["sig"] = new JD(), "an unsigned body must not carry sig"),
        };
        foreach (var (edit, want) in cases)
        {
            var b = IntentRequiredBody();
            edit(b);
            Assert.Equal("signIntentRequired: " + want, Refusal(() => Signers.SignIntentRequired(b, "site-k1", k)));
        }
        Assert.Equal("signProgressStep: step.digest is required",
            Refusal(() => Signers.SignProgressStep(new JD { ["goal_commitment"] = "g", ["action_digest"] = "a", ["before_digest"] = "b", ["after_digest"] = "c", ["seq"] = 0L, ["prev"] = null }, k.Ed!)));
    }
}
