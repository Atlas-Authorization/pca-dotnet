using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of importActionDefsFromMcp (import an MCP tool list, then the rule-based suggestions unless turned off) against the reference
/// (test-data/ref-mcp-import.json.gz): the arguments are the tool list and the options as the reference takes them.</summary>
public class RefMcpImportTests
{
    const string M = "ref-mcp-import";

    [Fact]
    public void ImportActionDefsFromMcp() => Base.Check(M, "importActionDefsFromMcp", a => Mcp.Mcp.ImportActionDefsFromMcp((L)a[0]!, (D)a[1]!), min: 1258);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "importActionDefsFromMcp" });
        Assert.Equal(1258, Base.Cases(M).Count);
    }
}
