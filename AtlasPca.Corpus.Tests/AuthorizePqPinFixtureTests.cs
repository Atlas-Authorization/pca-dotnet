using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// Server-side PQ pins end to end through Authorize: packages/pca/conformance/authorize-pq-pin-fixtures.json.
public class AuthorizePqPinFixtureTests
{
    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("authorize-pq-pin-fixtures.json");
        var op = D(doc["operation"]);
        var cases = L(doc["cases"]);
        Assert.Equal(9, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var grant = D(c["grant"]);
            var input = new AuthorizeInput
            {
                Operation = new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]), Audience = (string)doc["audience"]!, Now = N(doc["now"]),
                ResolveGrant = id => id == (string)grant["id"]! ? grant : null, StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = "single-step",
                ServerRisk = ProvHarness.LowRisk,
                PqPins = c["pq_pins"] is JD p ? p.ToDictionary(kv => kv.Key, kv => (string?)kv.Value ?? "") : null,
            };
            var r = Pca.Authorize(c["pcactn"], input);
            Assert.True(r.Allow == (bool)e["allow"]!, $"{name}: allow {r.Allow} {r.Reason}");
            Assert.True(r.Decision == (string)e["decision"]!, $"{name}: decision {r.Decision}");
            Assert.True(r.Status == (int)N(e["status"]), $"{name}: status {r.Status}");
            var want = (string)D(e["checks"])["pq_pin"]!;
            var got = r.Checks.TryGetValue("pq_pin", out var st) ? st : "absent";
            Assert.True(got == want, $"{name}: pq_pin {got}");
            if (e.TryGetValue("reason", out var rs)) Assert.True(r.Reason == (string)rs!, $"{name}: reason '{r.Reason}'");
            var failing = r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).ToList();
            foreach (var f in L(e["failed_includes"])) Assert.Contains((string)f!, failing);
        }
    }
}
