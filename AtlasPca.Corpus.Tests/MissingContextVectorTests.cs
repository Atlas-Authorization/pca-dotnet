using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// Typed missing context and the stored-wins merge, replaying packages/pca/conformance/missing-context-vectors.json. A missing file fails.
public class MissingContextVectorTests
{
    [Fact]
    public void Decide()
    {
        var doc = Load("missing-context-vectors.json");
        Assert.True(L(doc["decide"]).Count >= 20);
        foreach (var x in L(doc["decide"]))
        {
            var v = D(x); var name = (string)v["name"]!; var e = D(v["expect"]);
            var got = MissingContext.DecideWithMissing(v["where"], v["bound"], v.GetValueOrDefault("supplied"), v.GetValueOrDefault("suppliers"));
            Assert.True(got.Decision == (string)e["decision"]!, $"{name}: decision {got.Decision} {got.Reason}");
            Assert.True(got.Reason == e.GetValueOrDefault("reason") as string, $"{name}: reason {got.Reason}");
            var want = L(e["missing"]);
            Assert.True(want.Count == got.Missing.Count, $"{name}: missing count");
            for (int i = 0; i < want.Count; i++)
                Assert.True(got.Missing[i].Path == (string)D(want[i])["path"]! && got.Missing[i].Supplier == (string)D(want[i])["supplier"]!, $"{name}: missing {i}");
        }
    }

    [Fact]
    public void Bind()
    {
        var doc = Load("missing-context-vectors.json");
        Assert.True(L(doc["bind"]).Count >= 8);
        foreach (var x in L(doc["bind"]))
        {
            var v = D(x); var name = (string)v["name"]!; var e = D(v["expect"]);
            var table = v.ContainsKey("suppliers") ? D(v["suppliers"]) : new JD();
            var got = MissingContext.BindContext(D(v["bound"]), v.GetValueOrDefault("supplied"), table);
            Assert.True(IntentJs.JsonEquals(e["context"], got.Context), $"{name}: context");
            Assert.True(got.Conflicts.SequenceEqual(L(e["conflicts"]).Select(o => (string)o!)), $"{name}: conflicts");
            Assert.True(got.Dropped.SequenceEqual(L(e["dropped"]).Select(o => (string)o!)), $"{name}: dropped");
        }
    }
}
