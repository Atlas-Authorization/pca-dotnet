using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>AccPost refuses (null = the reference's throw 'accPost: unknown agg') an agg outside sum / count / max / distinct
/// before any key or pre-state work, selected or not, keyed or not. Mirrors packages/pca/src/mutation-kill-r13-g2-history.test.ts
/// "refuses an agg outside sum / count / max / distinct" (TS 80ad8c7ff).</summary>
public class AccPostUnknownAggTests
{
    const string Sum = "{\"id\":\"spend\",\"agg\":\"sum\",\"val\":\"action.params.total\",\"sel\":{\"verbs\":[\"pay\"]},\"win\":{\"kind\":\"task\"},\"key\":null,\"holder\":{\"kind\":\"site_local\"}}";
    static D Decl() => (D)Pca.ParseStrict(Sum)!;
    static L History() => (L)Pca.ParseStrict("[{\"id\":\"e1\",\"verb\":\"pay\",\"resource\":\"r\",\"params\":{\"total\":10,\"k\":\"x\",\"to\":\"p\"},\"t\":1000000,\"status\":\"committed\"}]")!;
    static D Params() => (D)Pca.ParseStrict("{\"total\":5}")!;
    static readonly object T = Pca.ParseStrict("1000000")!;

    [Fact]
    public void AKnownAggCombines() => Assert.Equal(15L, IntentHistory.AccPost(Decl(), History(), "pay", Params(), T, null));

    [Fact]
    public void AnUnknownAggIsRefusedFirst()
    {
        foreach (var agg in new object?[] { "SUM", "tVm", "", "avg", null, 1L, "missing" })
        {
            var bad = Decl();
            if (agg is "missing") bad.Remove("agg"); else bad["agg"] = agg;
            foreach (var verb in new[] { "pay", "look" })
                Assert.Null(IntentHistory.AccPost(bad, History(), verb, Params(), T, null));
            var keyed = new D(bad) { ["key"] = "action.params.k" };
            Assert.Null(IntentHistory.AccPost(keyed, History(), "pay", Params(), T, null));
        }
    }
}
