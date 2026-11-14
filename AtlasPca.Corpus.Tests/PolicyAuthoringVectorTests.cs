using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// forbid-certificate-vectors.json (table) and policy-link-vectors.json (shared with the TypeScript reference, Python, Go, Ruby, PHP,
// Rust and Swift). Exact outcomes; a reason is compared byte for byte.
public class PolicyAuthoringVectorTests
{
    [Fact]
    public void ForbidCertificateTable()
    {
        var table = L(Load("forbid-certificate-vectors.json")["table"]);
        Assert.True(table.Count >= 19);
        foreach (var x in table)
        {
            var v = D(x);
            var prec = v.TryGetValue("options", out var o) && D(o).TryGetValue("precedence", out var p) ? L(p).Cast<string>().ToList() : new List<string>();
            Assert.True((bool)D(v["expect"])["consistent"]! == PolicyAuthoring.ForbidCertificateConsistent(v["certificate"], prec), (string)v["name"]!);
        }
        foreach (var bad in new object?[] { null, "x", new List<object?>(), new Dictionary<string, object?>() })
            Assert.False(PolicyAuthoring.ForbidCertificateConsistent(bad));
    }

    [Fact]
    public void PolicyLink()
    {
        var doc = Load("policy-link-vectors.json");
        var def = D(doc["template"])["def"];
        Assert.Equal((string)D(doc["template"])["digest"]!, PolicyAuthoring.TemplateDigest(def));
        foreach (var x in L(doc["def_errors"]))
        {
            var v = D(x);
            Assert.True((string?)v["expect"] == PolicyAuthoring.TemplateDefError(v["def"]), (string)v["name"]!);
        }
        var inst = L(doc["instantiate"]);
        Assert.True(inst.Count >= 14);
        foreach (var x in inst)
        {
            var v = D(x);
            var (policy, reason) = PolicyAuthoring.InstantiateTemplate(def, v["slots"]);
            var e = D(v["expect"]);
            if ((bool)e["ok"]!) Assert.True(policy != null && IntentJs.JsonEquals(policy, e["policy"]), $"{v["name"]}: {reason}");
            else Assert.True(policy == null && reason == (string)e["reason"]!, $"{v["name"]}: {reason}");
        }
        foreach (var x in L(doc["verify"]))
        {
            var v = D(x);
            var trusted = L(v["trusted"]).Cast<string>().ToList();
            var r = (string)v["kind"]! == "template" ? PolicyAuthoring.VerifyTemplate(v["signed"], trusted) : PolicyAuthoring.VerifyTighten(v["signed"], trusted);
            var e = D(v["expect"]);
            Assert.True((r == null) == (bool)e["ok"]!, (string)v["name"]!);
            if (r != null) Assert.True(r == (string)e["reason"]!, $"{v["name"]}: {r}");
        }
        foreach (var x in L(doc["ref_errors"]))
        {
            var v = D(x);
            Assert.True((string?)v["expect"] == PolicyAuthoring.TemplateRefError(v["ref"]), (string)v["name"]!);
        }
        foreach (var x in L(doc["resolve"]))
        {
            var v = D(x);
            var (policy, overlays, reason) = PolicyAuthoring.ResolveLink(v["ref"], v["registry"]);
            var e = D(v["expect"]);
            if ((bool)e["ok"]!)
            {
                Assert.True(policy != null && IntentJs.JsonEquals(policy, e["policy"]) && overlays == (int)IntentJs.Lng(e["overlays"]), $"{v["name"]}: {reason}");
            }
            else Assert.True(policy == null && reason == (string)e["reason"]!, $"{v["name"]}: {reason}");
        }
    }
}
