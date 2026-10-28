using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Decision obligations, replaying packages/pca/conformance/obligations-vectors.json. A missing file fails.
public class ObligationsVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();
    static string Canon(IEnumerable<object?> xs) => Pca.Canonicalize(xs.ToList());

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("obligations-vectors.json");
        Assert.True(L(doc["validate"]).Count >= 15);
        foreach (var x in L(doc["validate"]))
        {
            var c = D(x);
            Assert.True((bool)D(c["expect"])["ok"]! == (Obligations.ObligationsError(c.GetValueOrDefault("input")) == null), $"validate {c["name"]}");
        }
        Assert.True(L(doc["merge"]).Count >= 5);
        foreach (var x in L(doc["merge"]))
        {
            var c = D(x); var e = D(c["expect"]);
            var got = Obligations.Merge(L(c["inputs"]));
            Assert.True(got.Ok == (bool)e["ok"]!, $"merge {c["name"]}: {got.Reason}");
            if (got.Ok) Assert.True(Canon(L(e["obligations"])) == Canon(got.Obligations), $"merge {c["name"]}: obligations");
        }
        Assert.True(L(doc["gate"]).Count >= 10);
        foreach (var x in L(doc["gate"]))
        {
            var c = D(x); var e = D(c["expect"]); var name = c["name"];
            var got = Obligations.PepObligationGate((string)c["decision"]!, c.GetValueOrDefault("answered") is true, c.GetValueOrDefault("obligations"), c.GetValueOrDefault("supported"));
            Assert.True(got.Decision == (string)e["decision"]!, $"gate {name}: decision {got.Decision}");
            Assert.True(Canon(L(e["perform"])) == Canon(got.Perform), $"gate {name}: perform");
            Assert.True(Strs(e["unsupported"]).SequenceEqual(got.Unsupported), $"gate {name}: unsupported");
        }
        Assert.True(L(doc["outcome"]).Count >= 8);
        foreach (var x in L(doc["outcome"]))
        {
            var c = D(x); var e = D(c["expect"]); var name = c["name"];
            var got = Obligations.Outcome(c.GetValueOrDefault("obligations"), c.GetValueOrDefault("fulfilled"), c.GetValueOrDefault("now"));
            Assert.True(got.Outcome == (string)e["outcome"]!, $"outcome {name}: {got.Outcome}");
            Assert.True(L(e["overdue"]).Select(i => (int)N(i)).SequenceEqual(got.Overdue), $"outcome {name}: overdue");
            Assert.True(got.Status == e.GetValueOrDefault("status") as string, $"outcome {name}: status");
        }
    }
}
