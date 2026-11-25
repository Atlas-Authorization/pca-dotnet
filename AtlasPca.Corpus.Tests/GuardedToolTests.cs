using AtlasPca;
using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The generic structural tool wrapper: the proof is built and handed over before the tool runs, a failing dry run never reaches it.</summary>
public class GuardedToolTests
{
    sealed class Refund : IPcaTool
    {
        public int Runs;
        public ToolMetadata Metadata { get; } = new("refund", "Refund a charge");
        public Task<object?> Call(D input) { Runs++; return Task.FromResult<object?>(new D { ["ok"] = true }); }
    }

    static AgentHandle Agent1() => Agent.FromPrincipal(new AgentOptions
    {
        Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
        Permissions = new D { ["stripe"] = new L { "refund" } }, Aud = "rs-test", Now = 1_000_000,
    });

    static GuardSpec Spec(string verb) => new() { Verb = verb, Resource = a => "charge:" + a["id"] };

    [Fact]
    public async Task RunsTheToolWithTheProofAndKeepsTheMetadata()
    {
        var ag = Agent1(); var tool = new Refund(); PcaCall? got = null; D? seen = null;
        var g = GuardedTool.WithPca(ag, Spec("stripe.refund"), tool, (p, a) => { got = p; seen = a; });
        var r = await g.Call(new D { ["id"] = "c1" }, new ActOptions { Now = 2_000_000 });
        Assert.Equal("{\"ok\":true}", AtlasPca.Js.JsJson.Stringify(r));
        Assert.Equal(1, tool.Runs);
        Assert.Same(tool.Metadata, g.Metadata);
        Assert.True(got!.Headers.ContainsKey("PCA-Action"));
        Assert.Equal("c1", seen!["id"]);
        Assert.Equal("tool", ag.Provenance.Receipts()[^1]["origin"]);
    }

    [Fact]
    public async Task AFailingDryRunNeverReachesTheTool()
    {
        var ag = Agent1(); var tool = new Refund();
        var g = GuardedTool.WithPca(ag, Spec("stripe.payout"), tool);
        await Assert.ThrowsAsync<PcaDenied>(() => g.Call(new D { ["id"] = "c1" }, new ActOptions { Now = 2_000_000 }));
        Assert.Equal(0, tool.Runs);
    }
}
