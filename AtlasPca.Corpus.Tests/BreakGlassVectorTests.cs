using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// Break-glass grants, replaying packages/pca/conformance/break-glass-vectors.json (decided by the TypeScript reference). A missing file fails.
public class BreakGlassVectorTests
{
    [Fact]
    public void EveryScenarioDecidesLikeTheReference()
    {
        var doc = Load("break-glass-vectors.json");
        var grants = L(doc["grants"]); var reviews = L(doc["reviews"]);
        var authority = (string)doc["authority"]!; var reviewer = (string)doc["reviewer"]!;
        Assert.True(L(doc["scenarios"]).Count >= 10);
        foreach (var x in L(doc["scenarios"]))
        {
            var s = D(x); var name = (string)s["name"]!;
            var reviewers = new List<string> { reviewer };
            if (s.ContainsKey("extra_reviewers")) reviewers.AddRange(L(s["extra_reviewers"]).Select(r => (string)r!));
            var reg = new BreakGlassRegistry(new BreakGlassPolicy(new[] { authority }, reviewers));
            var i = 0;
            foreach (var y in L(s["steps"]))
            {
                var st = D(y); var e = st["expect"]; var at = $"{name} step {i++}";
                switch ((string)st["op"]!)
                {
                    case "accept":
                    case "review":
                        var ed = D(e);
                        var r = (string)st["op"]! == "accept"
                            ? reg.Accept(grants[(int)N(st["grant"])], st["now"])
                            : reg.Review(reviews[(int)N(st["review"])], st["holder"], st["now"]);
                        Assert.True(r.Ok == (bool)ed["ok"]!, $"{at}: ok {r.Code}");
                        if (r.Ok) Assert.True(r.Replaced == (bool)ed["replaced"]!, $"{at}: replaced");
                        else Assert.True(r.Code == (string)ed["code"]!, $"{at}: code {r.Code}");
                        break;
                    case "use":
                        var ud = D(e);
                        var u = reg.Use(st["id"], st["holder"], st["action_digest"], st["now"], st["notified"]);
                        Assert.True(u.Decision == (string)ud["decision"]! && u.Code == ud.GetValueOrDefault("code") as string && u.Id == ud.GetValueOrDefault("id") as string, $"{at}: {u}");
                        if (u.Decision == "allow")
                            Assert.True(u.Use == N(ud["use"]) && u.Remaining == N(ud["remaining"]) && u.ReviewDue == N(ud["review_due"]), $"{at}: {u}");
                        break;
                    case "frozen":
                        Assert.True(reg.IsFrozen(st["holder"], st["now"]) == (bool)e!, $"{at}: frozen");
                        break;
                    default:
                        throw new Xunit.Sdk.XunitException($"{at}: unknown op {st["op"]}");
                }
            }
        }
    }
}
