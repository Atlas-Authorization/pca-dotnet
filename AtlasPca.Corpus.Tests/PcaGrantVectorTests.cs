using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// The `pca_grant` authorization-details type, replaying packages/pca/conformance/pca-grant-vectors.json (decided by the TypeScript reference).
public class PcaGrantVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("pca-grant-vectors.json");
        Assert.Equal(1L, N(doc["format"]));
        foreach (var x in L(doc["digest"])) Assert.Equal((string)D(x)["digest"]!, PcaGrant.ChainDigest(Strs(D(x)["ids"])));
        Assert.True(L(doc["detail"]).Count >= 40);
        foreach (var x in L(doc["detail"]))
        {
            var v = D(x);
            var code = PcaGrant.Validate(v["input"]);
            var e = D(v["expect"]);
            Assert.True((bool)e["ok"]! == (code == null), $"{v["name"]}: ok ({code})");
            if (code != null) Assert.True((string)e["code"]! == code, $"{v["name"]}: code {code}");
        }
        foreach (var x in L(doc["array"]))
        {
            var v = D(x);
            var r = PcaGrant.Parse(v["input"]);
            var e = D(v["expect"]);
            Assert.True((bool)e["ok"]! == (r.Code == null), $"{v["name"]}: ok ({r.Code})");
            if (r.Code == null) Assert.True(N(e["count"]) == r.Details.Count, $"{v["name"]}: count");
            else Assert.True((string)e["code"]! == r.Code, $"{v["name"]}: code {r.Code}");
        }
        foreach (var x in L(doc["presentation"]))
        {
            var v = D(x);
            var p = D(v["presented"]);
            var r = PcaGrant.Check(L(v["details"]).Select(d => D(d)).ToList(), (string)p["resource"]!, Strs(p["chain_ids"]), (bool)p["proof_verified"]!);
            var e = D(v["expect"]);
            Assert.True((bool)e["allow"]! == (r.Code == null), $"{v["name"]}: allow ({r.Code})");
            if (r.Code == null) Assert.True(N(e["index"]) == r.Index, $"{v["name"]}: index {r.Index}");
            else Assert.True((string)e["code"]! == r.Code, $"{v["name"]}: code {r.Code}");
        }
    }
}
