using AtlasPca;
using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The OpenAI Agents SDK guard (signature-only mode and the guardrails; full mode is the native authorize pipeline, covered by its own suite).</summary>
public class OpenAiAgentsGuardTests
{
    const string Aud = "rs-test";

    static (AgentHandle Agent, ActResult Act) Refund()
    {
        var ag = Agent.FromPrincipal(new AgentOptions
        {
            Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
            Permissions = new D { ["stripe"] = new L { "refund" } }, Aud = Aud, Now = 1_000_000,
        });
        return (ag, ag.Act("stripe.refund", "charge:c1", new D { ["id"] = "c1" }, new ActOptions { Now = 2_000_000 }));
    }

    static VerifyGrant Grant(AgentHandle ag) => new() { Grant = (D)Issue.NormJ(ag.Grant)!, Now = () => 2_000_000, PlanRoots = PlanRootPolicy.Skip };

    static D Ctx(object proof) => new() { ["context"] = new D { ["pca"] = proof } };

    static WithPcaToolOptions Sig(AgentHandle ag, string? verb = null) => new() { Mode = "signature-only", Verify = Grant(ag), Audience = Aud, Verb = verb };

    [Fact]
    public async Task AValidProofRunsTheToolAndRecordsItsResult()
    {
        var (ag, act) = Refund();
        var ran = 0;
        var seenVerified = false;
        var rec = ag.Provenance;
        var tool = OpenAiAgentsGuard.WithPcaTool("refund", (i, c) => { ran++; return Task.FromResult<object?>("ok"); },
            Sig(ag, "stripe.refund") with { Recorder = rec, OnVerified = (p, i) => seenVerified = true });
        Assert.Equal("ok", await tool(new D { ["id"] = "c1" }, Ctx(act.Encoded)));
        Assert.Equal(1, ran);
        Assert.True(seenVerified);
        Assert.Equal("tool", rec.Receipts()[^1]["origin"]);
        // the PCA-Action header form of the same proof is accepted too
        Assert.Equal("ok", await tool(new D { ["id"] = "c1" }, Ctx(act.Headers["PCA-Action"])));
    }

    [Fact]
    public async Task AMissingMalformedOrMisboundProofNeverRunsTheTool()
    {
        var (ag, act) = Refund();
        var ran = false;
        PcaToolDenied? denied = null;
        Func<D, D?, Task<object?>> run = (i, c) => { ran = true; return Task.FromResult<object?>(null); };
        var tool = OpenAiAgentsGuard.WithPcaTool("refund", run, Sig(ag, "stripe.refund") with { OnDeny = (e, i) => denied = e });
        var e1 = await Assert.ThrowsAsync<PcaToolDenied>(() => tool(new D(), new D()));
        Assert.Equal("missing", e1.Kind);
        Assert.Equal("missing", denied!.Kind);
        var e2 = await Assert.ThrowsAsync<PcaToolDenied>(() => tool(new D(), Ctx("not a proof!")));
        Assert.Equal("malformed", e2.Kind);
        var other = OpenAiAgentsGuard.WithPcaTool("refund", run, Sig(ag, "stripe.other"));
        var e3 = await Assert.ThrowsAsync<PcaToolDenied>(() => other(new D(), Ctx(act.Encoded)));
        Assert.Equal("binding", e3.Kind);
        // a proof for another audience fails verification
        var wrongAud = OpenAiAgentsGuard.WithPcaTool("refund", run, Sig(ag) with { Audience = "someone-else" });
        var e4 = await Assert.ThrowsAsync<PcaToolDenied>(() => wrongAud(new D(), Ctx(act.Encoded)));
        Assert.Equal("verify", e4.Kind);
        Assert.False(ran);
    }

    [Fact]
    public void AnIncompleteConfigurationIsRefusedAtConstruction()
    {
        var (ag, _) = Refund();
        Func<D, D?, Task<object?>> run = (i, c) => Task.FromResult<object?>(null);
        Assert.Throws<ArgumentException>(() => OpenAiAgentsGuard.WithPcaTool("t", run, new WithPcaToolOptions { Audience = Aud })); // full mode needs Authorize
        Assert.Throws<ArgumentException>(() => OpenAiAgentsGuard.WithPcaTool("t", run, Sig(ag) with { Audience = null }));
        Assert.Throws<ArgumentException>(() => OpenAiAgentsGuard.WithPcaTool("t", run, new WithPcaToolOptions { Mode = "signature-only", Audience = Aud }));
        Assert.Throws<ArgumentException>(() => OpenAiAgentsGuard.WithPcaTool("t", run, new WithPcaToolOptions { Mode = "bogus", Audience = Aud }));
    }

    [Fact]
    public async Task FullModeWithoutAReplayStoreOrOperationIsRefused()
    {
        var (ag, act) = Refund();
        var tool = OpenAiAgentsGuard.WithPcaTool("refund", (i, c) => Task.FromResult<object?>("x"), new WithPcaToolOptions { Audience = Aud, Authorize = (i, c) => new AuthorizeInput() });
        var e = await Assert.ThrowsAsync<PcaToolDenied>(() => tool(new D(), Ctx(act.Encoded)));
        Assert.Equal("config", e.Kind);
    }

    [Fact]
    public async Task PcaToolsGuardsEverythingExceptTheOnlyList()
    {
        var (ag, act) = Refund();
        var tools = new Dictionary<string, Func<D, D?, Task<object?>>>
        {
            ["a"] = (i, c) => Task.FromResult<object?>("a"), ["b"] = (i, c) => Task.FromResult<object?>("b"),
        };
        var guarded = OpenAiAgentsGuard.PcaTools(tools, Sig(ag), only: new[] { "a" });
        Assert.Same(tools["b"], guarded["b"]);
        await Assert.ThrowsAsync<PcaToolDenied>(() => guarded["a"](new D(), new D()));
        Assert.Equal("a", await guarded["a"](new D(), Ctx(act.Encoded)));
    }

    [Fact]
    public async Task GuardrailsTripWithoutAValidProof()
    {
        var (ag, act) = Refund();
        var g = OpenAiAgentsGuard.PcaInputGuardrail(new PcaGuardrailOptions { Verify = Grant(ag), Audience = Aud });
        Assert.Equal("pca-input-guardrail", g.Name);
        var bad = await g.Execute(new D { ["context"] = new D() });
        Assert.True(bad.TripwireTriggered);
        Assert.Equal("missing", bad.OutputInfo["kind"]);
        var ok = await g.Execute(new D { ["context"] = Ctx(act.Encoded) });
        Assert.False(ok.TripwireTriggered);
        Assert.Equal("stripe.refund", ok.OutputInfo["verb"]);
        Assert.Throws<ArgumentException>(() => OpenAiAgentsGuard.PcaToolGuard(new PcaGuardrailOptions { Audience = Aud }));
    }
}
