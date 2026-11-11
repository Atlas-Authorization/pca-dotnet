using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
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
        Assert.Equal(26, recs.Count);
        // record 8 has a forged signature; 14-21 and 24 are validly signed but carry malformed runtime_pins
        var bad = new HashSet<int> { 8, 14, 15, 16, 17, 18, 19, 20, 21, 24 };
        for (var i = 0; i < recs.Count; i++) Assert.True(Blueprint.Verify(recs[i]) == !bad.Contains(i), $"record {i}");
        foreach (var x in L(doc["scenarios"]))
        {
            var s = D(x);
            var reg = new BlueprintRegistry(new[] { (string)doc["operator"]! }, new MemoryBlueprintStore());
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
                Func<string, JD, bool>? adm = !o.TryGetValue("admitted", out var av) ? null
                    : av is string asel ? (asel == "all" ? (_, _) => true : (_, _) => false)
                    : (h, _) => L(av).Any(q => (string)q! == h);
                var d = Blueprint.Check(st["chain"], reg, o["now"], (string)o["mode"]!, min, adm);
                Assert.True(d.Decision == (string)e["decision"]!, $"{name}: decision {d.Decision}");
                if (e.TryGetValue("code", out var c)) Assert.True(d.Code == (string)c!, $"{name}: code {d.Code}");
                if (e.TryGetValue("blueprint", out var b)) Assert.True(d.Blueprint == (string)b!, $"{name}: blueprint");
                if (e.TryGetValue("governed", out var gv)) Assert.True((d.Governed ?? Array.Empty<string>()).SequenceEqual(L(gv).Select(q => (string)q!)), $"{name}: governed");
                if ((string)e["decision"]! == "escalate") Assert.True(d.Have == N(e["have"]) && d.Need == N(e["need"]), $"{name}: have/need");
            }
        }
    }
}
