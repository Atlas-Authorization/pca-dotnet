using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// K4: escalation pricing, network-token binding and the ERC-7715 check, replaying packages/pca/conformance/k4-vectors.json.
public class K4VectorTests
{
    [Fact]
    public void Escalation()
    {
        var esc = D(Load("k4-vectors.json")["escalation"]);
        Assert.True(L(esc["config_cases"]).Count >= 6);
        foreach (var x in L(esc["config_cases"])) Assert.True(K4.PricingConfigError(D(x)["config"]) == (string?)D(x)["expect"], $"config {D(x)["name"]}");
        Assert.True(L(esc["decisions"]).Count >= 14);
        foreach (var x in L(esc["decisions"]))
        {
            var g = K4.Decide(esc["config"], D(x)["calibration"], D(x)["risk"]);
            var e = D(D(x)["expect"]);
            Assert.True(g.Ask == (bool)e["ask"]! && g.Reason == (string)e["reason"]!, $"decision {g}");
        }
        foreach (var x in L(esc["calibration"]))
        {
            var c = D(x);
            var start = D(c["start"]);
            var risks = D(c["risks"]);
            var g = K4.UpdateCalibration(c["config"], N(start["multiplierPpm"]), L(start["seen"]).Select(q => (string)q!).ToList(), L(c["answers"]), risks);
            var e = D(c["expect"]);
            Assert.True(g.MultiplierPpm == N(e["multiplierPpm"]) && g.Seen.SequenceEqual(L(e["seen"]).Select(q => (string)q!)), $"calibration {c["name"]}");
        }
    }

    [Fact]
    public void Binding()
    {
        var cs = L(D(Load("k4-vectors.json")["network_binding"])["cases"]);
        Assert.True(cs.Count >= 15);
        foreach (var x in cs)
        {
            var c = D(x);
            var e = D(c["expect_in"]);
            Assert.True(K4.VerifyBinding(c["binding"], e["grant"], (string)e["holder"]!, (string)e["issuer_nonce"]!, e.TryGetValue("provider", out var p) ? (string?)p : null) == (string?)c["expect"], $"binding {c["name"]}");
        }
    }

    [Fact]
    public void Erc7715()
    {
        var cs = L(D(Load("k4-vectors.json")["erc7715"])["cases"]);
        Assert.True(cs.Count >= 24);
        foreach (var x in cs)
        {
            var c = D(x);
            var o = D(c["opts"]);
            var ctx = o.TryGetValue("contexts", out var cx) ? D(cx) : new Dictionary<string, object?>();
            var got = K4.VerifyGranted(c["envelope"], c["sent"], c["got"], L(o["allowedManagers"]).Select(q => (string)q!).ToList(), k => ctx.TryGetValue(k, out var v) ? (string?)v : null);
            Assert.True(got == (string?)c["expect"], $"erc7715 {c["name"]}: {got}");
        }
    }
}
