using Xunit;
using McpApi = AtlasPca.Mcp.Mcp;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the MCP adapter's pure surface against the TypeScript reference (test-data/ref-mcp.json.gz).</summary>
public class RefMcpTests
{
    const string M = "ref-mcp";

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["MCP_CLIENT_REVISIONS"] = McpApi.McpClientRevisions.Cast<object?>().ToList(),
        ["MCP_AUTH_CLIENT_ROWS"] = McpApi.McpAuthClientRows(),
    });

    [Fact] public void ParseChallenges() => Base.Check(M, "parseChallenges", a => McpApi.ParseChallenges(a[0]));
    [Fact] public void PcaNeedProblem() => Base.Check(M, "pcaNeedProblem", a => McpApi.PcaNeedProblem(a[0]));
    [Fact] public void PlanStepUp() => Base.Check(M, "planStepUp", a => McpApi.PlanStepUp(a[0], a[1], (D)a[2]!));
    [Fact] public void CheckIss() => Base.Check(M, "checkAuthorizationResponseIss", a => McpApi.CheckAuthorizationResponseIss((D)a[0]!));
    [Fact] public void GuardToolResult() => Base.Check(M, "guardToolResult", a => McpApi.GuardToolResult(a[0], a[1]));
    [Fact] public void PcaHeaders() => Base.Check(M, "pcaHeaders", a => McpApi.PcaHeaders((string)a[0]!));
    [Fact] public void Draft() => Base.Check(M, "draftActionSchemaFromMcp", a => McpApi.DraftActionSchemaFromMcp((L)a[0]!, (D)a[1]!));
    [Fact] public void ApplyDecisions() => Base.Check(M, "applySchemaDecisions", a => McpApi.ApplySchemaDecisions(a[0], (D)a[1]!));
    [Fact] public void VerbOfTool() => Base.Check(M, "verbOfTool", a => McpApi.VerbOfTool(a[0], a[1]));
    [Fact] public void ConformToolCall() => Base.Check(M, "conformToolCall", a => McpApi.ConformToolCall(a[0], (string)a[1]!, a[2]));

    [Fact]
    public void ToolCallOfReadsOnlyToolsCall()
    {
        var c = McpApi.ToolCallOf("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":{\"a\":1}}}");
        Assert.NotNull(c);
        Assert.Equal("pay", c!["name"]);
        Assert.Single((D)c["arguments"]!);
        Assert.Empty((D)McpApi.ToolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":[1]}}")!["arguments"]!);
        Assert.Null(McpApi.ToolCallOf("{\"method\":\"tools/list\"}"));
        Assert.Null(McpApi.ToolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":5}}"));
        Assert.Null(McpApi.ToolCallOf("not json"));
        Assert.Null(McpApi.ToolCallOf("[]"));
        Assert.Null(McpApi.ToolCallOf(null));
    }

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "parseChallenges", "pcaNeedProblem", "planStepUp", "checkAuthorizationResponseIss", "guardToolResult", "pcaHeaders",
        "draftActionSchemaFromMcp", "applySchemaDecisions", "verbOfTool", "conformToolCall",
    }); Assert.Equal(2749, Base.Total(M)); }
}
