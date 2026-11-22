using AtlasPca;
using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The structural AI adapters (Anthropic tool_use, OpenAI chat tool_calls): no vendor package, so plain unit tests.</summary>
public class AiAdaptersTests
{
    static AgentHandle Agent1() => Agent.FromPrincipal(new AgentOptions
    {
        Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
        Permissions = new D { ["stripe"] = new L { "refund" } }, Aud = "rs-test", Now = 1_000_000,
    });

    static (string Verb, string Resource)? Map(AgentToolCall c) => c.Name == "refund" ? ("stripe.refund", "charge:" + c.Arguments["id"]) : null;
    static readonly ActOptions At = new() { Now = 2_000_000 };

    // ---- Anthropic ----

    [Fact]
    public async Task AnthropicRunsTheHandlerWithTheProofAndRecordsTheResult()
    {
        var ag = Agent1();
        PcaCall? got = null;
        var handlers = new Dictionary<string, AgentToolHandler> { ["refund"] = (input, pca) => { got = pca; return Task.FromResult<object?>(new D { ["ok"] = true }); } };
        var r = await AnthropicAdapter.HandleToolUse(ag, new ToolUseBlock("tu1", "refund", new D { ["id"] = "c1" }), Map, handlers, At);
        Assert.False(r.IsError);
        Assert.Equal("{\"ok\":true}", r.Content);
        Assert.Equal("tu1", r.ToTree()["tool_use_id"]);
        Assert.NotNull(got);
        Assert.True(got!.Headers.ContainsKey("PCA-Action"));
        Assert.Equal("tool", ag.Provenance.Receipts()[^1]["origin"]);
    }

    [Fact]
    public async Task AnthropicRefusesWithAnErrorResultAndNeverRunsAnUnmappedOrHandlerlessTool()
    {
        var ag = Agent1();
        var ran = false;
        var handlers = new Dictionary<string, AgentToolHandler> { ["wipe"] = (i, p) => { ran = true; return Task.FromResult<object?>(null); } };
        var unmapped = await AnthropicAdapter.HandleToolUse(ag, new ToolUseBlock("a", "wipe", new D()), Map, handlers, At);
        Assert.True(unmapped.IsError);
        Assert.Contains("No proof-carrying authority is mapped", unmapped.Content);
        var none = await AnthropicAdapter.HandleToolUse(ag, new ToolUseBlock("b", "refund", new D { ["id"] = "c" }), Map, new Dictionary<string, AgentToolHandler>(), At);
        Assert.True(none.IsError);
        Assert.Contains("No handler registered", none.Content);
        Assert.False(ran);
        Assert.Equal(true, none.ToTree()["is_error"]);
    }

    [Fact]
    public async Task AnthropicTurnsAThrowingHandlerIntoAnErrorResult()
    {
        var ag = Agent1();
        var handlers = new Dictionary<string, AgentToolHandler> { ["refund"] = (i, p) => throw new InvalidOperationException("boom") };
        var r = await AnthropicAdapter.HandleToolUse(ag, new ToolUseBlock("t", "refund", new D { ["id"] = "c" }), Map, handlers, At);
        Assert.True(r.IsError);
        Assert.Equal("boom", r.Content);
        Assert.Equal("tool", ag.Provenance.Receipts()[^1]["origin"]);
    }

    [Fact]
    public void AnthropicExtractsOnlyToolUseBlocksAndRecordsMessages()
    {
        var content = new L
        {
            new D { ["type"] = "text", ["text"] = "hi" },
            new D { ["type"] = "tool_use", ["id"] = "x", ["name"] = "refund", ["input"] = new D { ["id"] = "c" } },
            new D { ["type"] = "tool_use", ["name"] = 5L },
        };
        var uses = AnthropicAdapter.ExtractToolUses(content);
        Assert.Equal(2, uses.Count);
        Assert.Equal("x", uses[0].Id);
        Assert.Equal("", uses[1].Name); // not a string: kept empty so the mapping declines it

        var ag = Agent1();
        var create = AnthropicAdapter.WithPcaMessages<string>(ag, p => "sent");
        Assert.Equal("sent", create(new D { ["messages"] = new L { new D { ["role"] = "user", ["content"] = "refund c1" } } }));
        var rs = ag.Provenance.Receipts();
        Assert.Single(rs);
        Assert.Equal("principal", rs[0]["origin"]);
    }

    // ---- OpenAI chat ----

    [Fact]
    public async Task OpenAiDispatchesAndFallsBackToTheEncodedProofWithoutAHandler()
    {
        var ag = Agent1();
        var call = OpenAIToolCall.FromTree(new D { ["id"] = "call_1", ["type"] = "function", ["function"] = new D { ["name"] = "refund", ["arguments"] = " {\"id\":\"c1\",\"n\":2.5} " } })!;
        D? seen = null;
        var handlers = new Dictionary<string, AgentToolHandler> { ["refund"] = (a, p) => { seen = a; return Task.FromResult<object?>("done"); } };
        var m = await OpenAiAdapter.DispatchToolCall(ag, call, Map, handlers, At);
        Assert.Equal("\"done\"", m.Content);
        Assert.Equal("call_1", m.ToTree()["tool_call_id"]);
        Assert.Equal("tool", m.ToTree()["role"]);
        Assert.Equal("c1", seen!["id"]);
        var bare = await OpenAiAdapter.DispatchToolCall(ag, call, Map, new Dictionary<string, AgentToolHandler>(), At);
        Assert.StartsWith("{\"pca\":\"", bare.Content);
    }

    [Fact]
    public async Task OpenAiRefusesAnUnmappedToolAndNonObjectArguments()
    {
        var ag = Agent1();
        var handlers = new Dictionary<string, AgentToolHandler>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => OpenAiAdapter.DispatchToolCall(ag, new OpenAIToolCall("1", "wipe", "{}"), Map, handlers, At));
        await Assert.ThrowsAsync<InvalidOperationException>(() => OpenAiAdapter.DispatchToolCall(ag, new OpenAIToolCall("1", "refund", "[1]"), Map, handlers, At));
        Assert.Empty(OpenAiAdapter.ParseArguments("  "));
        Assert.Empty(OpenAiAdapter.ParseArguments(null));
        Assert.Null(OpenAIToolCall.FromTree(new D { ["function"] = new D() }));
    }

    [Fact]
    public async Task OpenAiGivesEachCallInABatchItsOwnCounter()
    {
        var ag = Agent1();
        var counters = new List<string>();
        var handlers = new Dictionary<string, AgentToolHandler> { ["refund"] = (a, p) => { counters.Add(Pca.Canonicalize(p.PCActn["counter"])); return Task.FromResult<object?>(null); } };
        var calls = new[] { new OpenAIToolCall("1", "refund", "{\"id\":\"a\"}"), new OpenAIToolCall("2", "refund", "{\"id\":\"b\"}") };
        var ms = await OpenAiAdapter.DispatchToolCalls(ag, calls, Map, handlers, new ActOptions { Now = 2_000_000, Counter = 5 });
        Assert.Equal(2, ms.Count);
        Assert.Equal(new[] { "5", "6" }, counters);
    }
}
