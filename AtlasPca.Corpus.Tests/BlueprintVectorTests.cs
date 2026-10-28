using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Agent blueprints, replaying packages/pca/conformance/blueprint-vectors.json (decided by the TypeScript reference).
public class BlueprintVectorTests
{
    [Fact]
    public void EveryScenarioDecidesLikeTheReference()
    {
        var doc = Load("blueprint-vectors.json");
        var recs = L(doc["records"]);
        Assert.Equal(9, recs.Count);
        for (var i = 0; i < recs.Count; i++) Assert.True(Blueprint.Verify(recs[i]) == (i != 8), $"record {i}");
        foreach (var x in L(doc["scenarios"]))
        {
            var s = D(x);
            var reg = new BlueprintRegistry(new[] { (string)doc["operator"]! });
            foreach (var y in L(s["steps"]))
            {
                var st = D(y);
                var e = D(st["expect"]);
                var name = (string)s["name"]!;
                if ((string)st["op"]! == "accept")
                {
                    var g = reg.Accept(recs[(int)N(st["record"])]);
                    Assert.True(g.Ok == (bool)e["ok"]!, $"{name}: ok");
                    if (g.Ok) Assert.True(g.Replaced == (bool)e["replaced"]!, $"{name}: replaced");
                    else Assert.True(g.Code == (string)e["code"]!, $"{name}: code {g.Code}");
                    continue;
                }
                var o = D(st["opts"]);
                long? min = o.TryGetValue("minEpoch", out var m) ? N(m) : null;
                var d = Blueprint.Check(st["chain"], reg, o["now"], (string)o["mode"]!, min);
                Assert.True(d.Decision == (string)e["decision"]!, $"{name}: decision {d.Decision}");
                if (e.TryGetValue("code", out var c)) Assert.True(d.Code == (string)c!, $"{name}: code {d.Code}");
                if (e.TryGetValue("blueprint", out var b)) Assert.True(d.Blueprint == (string)b!, $"{name}: blueprint");
                if (e.TryGetValue("governed", out var gv)) Assert.True((d.Governed ?? Array.Empty<string>()).SequenceEqual(L(gv).Select(q => (string)q!)), $"{name}: governed");
                if ((string)e["decision"]! == "escalate") Assert.True(d.Have == N(e["have"]) && d.Need == N(e["need"]), $"{name}: have/need");
            }
        }
    }
}
