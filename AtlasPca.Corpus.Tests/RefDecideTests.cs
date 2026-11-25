using AtlasPca.Authzen;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the Policy VM decision (release of the guardian share, required threshold, risk, budget admission and the
/// budget afterwards) against the TypeScript reference, over signed grants and chains.</summary>
public class RefDecideTests
{
    const string M = "ref-decide-java";

    [Fact] public void Decide() => Base.Check(M, "decide", a => PolicyVmDecide.Decide(a[0]));

    [Fact]
    public void DeriveDecideInputRequiresTheStoredGrant()
    {
        var p = new D { ["action"] = new D { ["verb"] = "read", ["resource"] = "doc:1" }, ["plan"] = new D { ["node_id"] = "n1" }, ["cap_chain"] = new L() };
        var ex = Assert.Throws<DecideInputGrantRequiredException>(() => PolicyVmDecide.DeriveDecideInput(p, new D { ["risk"] = new D() }));
        Assert.Equal("grant_required", ex.Code);
        var grant = new D { ["id"] = "g" };
        var input = PolicyVmDecide.DeriveDecideInput(p, new D { ["grant"] = grant, ["now"] = new Num("5") });
        Assert.Same(grant, input["grant"]);
        Assert.Same(grant, input["trustedRoot"]);
        Assert.Equal("n1", input["nodeId"]);
        Assert.Equal("read", (string)((D)((D)input["action"]!)["action"]!)["verb"]!);
    }

    [Fact] public void Covers() { Base.Covers(M, new[] { "decide" }); Assert.Equal(226, Base.Total(M)); }
}
