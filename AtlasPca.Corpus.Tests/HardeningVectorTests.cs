using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// The 0.5 hardening vectors decided by the TypeScript reference: budget_alloc monotonicity, the core plan_root_authorized check and the
// server-side PQ pins (packages/pca/conformance/{budget-alloc,plan-root,pq-pin}-vectors.json). A file that loses a case FAILS.
public class HardeningVectorTests
{
    static D Vec(string name)
    {
        foreach (var x in L(Load("vectors.json")["vectors"])) if ((string)D(x)["name"]! == name) return D(x);
        throw new InvalidOperationException("vectors.json has no vector " + name);
    }

    [Fact]
    public void BudgetAllocMonotonicity()
    {
        var cases = L(Load("budget-alloc-vectors.json")["budget_alloc"]);
        Assert.Equal(24, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var e = D(c["expect"]); var name = (string)c["name"]!;
            var got = Pca.AllocationsMonotone(c["caveats"]);
            if ((bool)e["ok"]!) Assert.True(got == null, $"{name}: {got}");
            else Assert.True(got == (string)e["reason"]!, $"{name}: {got}");
        }
    }

    [Fact]
    public void PlanRootAuthorizedAtTheCore()
    {
        var cases = L(Load("plan-root-vectors.json")["plan_root_authorized"]);
        Assert.Equal(9, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]); var o = D(c["options"]);
            var v = Vec((string)c["vector"]!);
            var root = (string)D(D(v["pcactn"])["plan"])["root"]!;
            var ctx = D(v["context"]);
            IReadOnlyList<string>? roots = o.TryGetValue("authorizedPlanRoots", out var r) ? L(r).Select(q => (string)q! == "$plan_root" ? root : (string)q!).ToList() : null;
            var skip = o.TryGetValue("insecureSkipPlanRootCheck", out var s) && (bool)s!;
            var got = Pca.VerifyPcactnCore(v["pcactn"], D(v["grant"]), N(ctx["now"]), (string)ctx["aud"]!, planRoots: new PlanRootPolicy(roots, skip));
            Assert.True(got.PlanRootAuthorized == (string)e["check"]!, $"{name}: check {got.PlanRootAuthorized}");
            Assert.True(got.Allow == (bool)e["allow"]!, $"{name}: allow");
            if (e.TryGetValue("reason", out var reason)) Assert.True(got.Reason == (string)reason!, $"{name}: reason {got.Reason}");
            else Assert.True(got.Reason == "", $"{name}: reason {got.Reason}");
        }
    }

    [Fact]
    public void ServerSidePqPins()
    {
        var cases = L(Load("pq-pin-vectors.json")["pq_pin"]);
        Assert.Equal(9, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var v = Vec((string)c["vector"]!);
            var grant = D(v["grant"]); var ctx = D(v["context"]);
            string Sub(string t) => t switch
            {
                "$grant.issuer" => (string)grant["issuer"]!,
                "$grant.pq_pk" => (string)grant["pq_pk"]!,
                "$grant.pq_pk[0:20]" => ((string)grant["pq_pk"]!)[..20],
                _ => t,
            };
            Dictionary<string, string>? pins = c["pq_pins"] is null ? null : D(c["pq_pins"]).ToDictionary(kv => Sub(kv.Key), kv => Sub((string)kv.Value!));
            var input = new AuthorizeInput
            {
                Operation = new Operation("v", "r", new D()), Audience = (string)ctx["aud"]!, ResolveGrant = _ => grant, StateStore = new MemoryStateStore(),
                IsRevoked = (_, _) => false, Now = N(ctx["now"]), Plan = "single-step", PqPins = pins,
            };
            var got = Pca.Authorize(v["pcactn"], input);
            var want = (string)e["check"]!;
            if (want == "fail") Assert.False(got.Allow, name + ": a failed pq_pin must deny");
            if (want == "absent") Assert.False(got.Checks.ContainsKey("pq_pin"), name);
            else Assert.True(got.Checks.TryGetValue("pq_pin", out var st) && st == want, $"{name}: {string.Join(",", got.Checks.Select(kv => kv.Key + "=" + kv.Value))}");
            if (e.TryGetValue("reason", out var reason)) Assert.Contains((string)reason!, got.Reasons);
            else Assert.DoesNotContain(got.Reasons, q => q.StartsWith("pq_pin:"));
        }
    }
}
