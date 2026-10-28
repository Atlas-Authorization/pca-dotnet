using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Policy classes, replaying packages/pca/conformance/policy-classes-vectors.json. A missing file fails.
public class PolicyClassesVectorTests
{
    [Fact]
    public void Validate()
    {
        var doc = Load("policy-classes-vectors.json");
        Assert.True(L(doc["validate"]).Count >= 10);
        foreach (var x in L(doc["validate"]))
        {
            var v = D(x);
            Assert.True((bool)D(v["expect"])["ok"]! == (PolicyClasses.ClassVerdictsError(v["input"]) == null), (string)v["name"]!);
        }
    }

    [Fact]
    public void Decide()
    {
        var doc = Load("policy-classes-vectors.json");
        Assert.True(L(doc["decide"]).Count >= 9);
        foreach (var x in L(doc["decide"]))
        {
            var v = D(x); var name = (string)v["name"]!; var e = D(v["expect"]);
            var got = PolicyClasses.DecideClasses(v["input"]);
            Assert.True(got.Decision == (string)e["decision"]!, $"{name}: decision {got.Decision}");
            Assert.True(got.Reason == e.GetValueOrDefault("reason") as string, $"{name}: reason {got.Reason}");
            Assert.True(got.DeniedBy.SequenceEqual(L(e["denied_by"]).Select(o => (string)o!)), $"{name}: denied_by");
            Assert.True(got.EscalatedBy.SequenceEqual(L(e["escalated_by"]).Select(o => (string)o!)), $"{name}: escalated_by");
            var want = L(e["classes"]);
            Assert.True(want.Count == got.Classes.Count, $"{name}: classes count");
            for (int i = 0; i < want.Count; i++)
            {
                var w = D(want[i]); var g = got.Classes[i];
                Assert.True(g.Class == (string)w["class"]! && g.Revision == N(w["revision"]) && g.Digest == (string)w["digest"]! && g.Decision == (string)w["decision"]!, $"{name}: class {i}");
            }
        }
    }
}
