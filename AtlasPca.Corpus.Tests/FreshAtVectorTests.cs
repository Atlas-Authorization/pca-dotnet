using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// The `fresh_at` consistency token as a SIGNED PCActn member and the verifier's `fresh_at` check, replaying
// packages/pca/conformance/fresh-at-vectors.json (decided by the TypeScript reference). The check is reported after the intent checks, only
// when the PCActn carries the member, a side-carried token is read, or the policy requires one; a stale verifier is an escalate.
public class FreshAtVectorTests
{
    static readonly string[] CheckOrder = { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "fresh_at" };

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("fresh-at-vectors.json");
        Assert.Equal(1L, N(doc["format"]));
        Assert.True(L(doc["check_order"]).Cast<string>().SequenceEqual(CheckOrder), "check_order changed");
        var cases = L(doc["vectors"]);
        Assert.True(cases.Count >= 28, $"only {cases.Count} cases");
        var decisions = new HashSet<string>();
        foreach (var x in cases)
        {
            var c = D(x);
            var name = (string)c["name"]!;
            var e = D(c["expect"]);
            var ctx = D(c["context"]);
            FreshAtPolicy? policy = null;
            if (ctx.TryGetValue("fresh_at", out var po))
            {
                policy = FreshAtPolicy.FromJson(po);
                Assert.True(policy != null, $"{name}: malformed fresh_at policy in the vector");
            }
            var v = Pca.VerifyPcactnCore(c["pcactn"], D(c["grant"]), N(ctx["now"]), (string)ctx["aud"]!, null, null, null, policy);

            Assert.True(v.Allow == (bool)e["allow"]!, $"{name}: allow={v.Allow} ({v.Reason})");
            var wantChecks = D(e["checks"]);
            var gotChecks = v.Checks.Where(kv => kv.Key != "fresh_at").ToList();
            Assert.True(gotChecks.Count == wantChecks.Count, $"{name}: checks [{string.Join(",", gotChecks.Select(kv => kv.Key))}]");
            foreach (var (k, w) in wantChecks) Assert.True(v.Checks.TryGetValue(k, out var g) && g == (bool)w!, $"{name}: check {k}");

            var wantFresh = (string)e["fresh_at"]!;
            var gotFresh = v.Checks.TryGetValue("fresh_at", out var fv) ? (fv ? "pass" : "fail") : "absent";
            Assert.True(gotFresh == wantFresh, $"{name}: fresh_at {gotFresh}, want {wantFresh}");

            if (e.TryGetValue("reason", out var wantReason))
            {
                // `fresh_at:` and `wire:` reasons are pinned exactly; another check's wording is that check's own vectors' business
                var wr = (string)wantReason!;
                bool exact = wr.StartsWith("fresh_at: ", StringComparison.Ordinal) || wr.StartsWith("wire: ", StringComparison.Ordinal);
                bool same = exact ? v.Reason == wr : (v.Reason ?? "").Split(new[] { ": " }, StringSplitOptions.None)[0] == wr.Split(new[] { ": " }, StringSplitOptions.None)[0];
                Assert.True(same, $"{name}: reason '{v.Reason}', want '{wantReason}'");
            }

            var decision = PcaDecision.DecisionOf(new Dictionary<string, object?>
            {
                ["allow"] = v.Allow,
                ["checks"] = v.Checks.ToDictionary(kv => kv.Key, kv => (object?)(kv.Value ? "pass" : "fail")),
                ["reasons"] = v.Reasons.Cast<object?>().ToList(),
            });
            Assert.True(decision == (string)e["decision"]!, $"{name}: decision {decision}, want {e["decision"]}");
            decisions.Add(decision);
        }
        foreach (var d in new[] { "allow", "escalate", "deny" }) Assert.True(decisions.Contains(d), $"no {d} case in the vectors");
    }

    [Fact]
    public void ABareVerdictWithoutAMemberOrPolicyHasNoFreshAtEntry()
    {
        var doc = Load("fresh-at-vectors.json");
        var c = L(doc["vectors"]).Select(o => D(o)).First(x => (string)x["name"]! == "no-member-no-policy");
        var ctx = D(c["context"]);
        var v = Pca.VerifyPcactnCore(c["pcactn"], D(c["grant"]), N(ctx["now"]), (string)ctx["aud"]!);
        Assert.True(v.Allow);
        Assert.False(v.Checks.ContainsKey("fresh_at"));
    }
}

// Pca.Authorize forwards AuthorizeInput.FreshAt to the core verifier. The vectors' PCActns are not bound to an operation, so the whole
// decision is a deny; the point is the reported `fresh_at` check and its reason.
public class FreshAtAuthorizeTests
{
    static AuthorizeResult Run(string name, bool withPolicy)
    {
        var c = L(Load("fresh-at-vectors.json")["vectors"]).Select(o => D(o)).First(x => (string)x["name"]! == name);
        var ctx = D(c["context"]);
        var grant = D(c["grant"]);
        return Pca.Authorize(c["pcactn"], new AuthorizeInput
        {
            Audience = (string)ctx["aud"]!, Now = N(ctx["now"]), Plan = "single-step", StateStore = new MemoryStateStore(),
            Operation = new Operation("x.y", "z", new Dictionary<string, object?>()), ResolveGrant = _ => grant, IsRevoked = (_, _) => false,
            FreshAt = withPolicy ? FreshAtPolicy.FromJson(ctx["fresh_at"]) : null,
        }.WithProv());
    }

    [Fact] public void SideCarriedTokenOkPassesTheCheck() => Assert.Equal("pass", Run("side-carried-ok", true).Checks["fresh_at"]);

    [Fact] public void StaleStateEscalates()
    {
        var r = Run("member-stale-revocation_epoch", true);
        Assert.Equal("fail", r.Checks["fresh_at"]);
        Assert.Contains(r.Reasons, x => x.Contains("escalate: stale_state"));
    }

    [Fact] public void NoPolicyRefusesAPCActnThatCarriesTheMember()
    {
        var r = Run("member-equal-state", false);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["fresh_at"]);
        Assert.Contains(r.Reasons, x => x.Contains("no fresh_at policy"));
    }
}
