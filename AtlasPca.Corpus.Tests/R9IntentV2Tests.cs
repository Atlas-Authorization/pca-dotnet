using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Round-r9 kills for IntentV2.cs (the helpers of IntentV2KillTests are private to it, hence the partial class).</summary>
public partial class IntentV2KillTests
{
    [Fact]
    public void R9AccumulatorContextIsJudgedBeforeTheSchemaContext()
    {
        var p = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        var d = Decide(G0, p, IntentV2Context.FromJson(Ctx("acc", M("state", "x"), "schema", M("docs", "x", "keys", Li()))));
        Assert.Equal("acc.state must be an object", ReasonOf(d, "accumulators"));
    }

    [Fact]
    public void R9WorldProvenanceFaultFailsTheFactsCheckClosed()
    {
        var p = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        p["intent_session"] = ThrowingOn("facts", (D)p["intent_session"]!);
        var d = Decide(G0, p, IntentV2Context.FromJson(Ctx("wb", M("policy", M("provenance", M("params", M()))))));
        var facts = d.Checks.Where(c => c.Name == "facts").ToList();
        Assert.Single(facts);
        Assert.False(facts[0].Ok);
        Assert.Equal("W-B error (fail closed): InvalidOperationException", facts[0].Reason);
    }
}
