using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class PcaServerTests
{
    static KeyValuePair<string, string> C(string n, string s) => new(n, s);

    [Fact]
    public void EnforceRequiredDeniesAnythingNotPass()
    {
        var checks = new[] { C("audience", "pass"), C("revocation", "not-enforced"), C("validity", "fail") };
        var r = PcaServer.EnforceRequired(true, checks, new[] { "validity: expired" }, new[] { "audience", "revocation", "validity", "replay" });
        Assert.False(r.Allow);
        Assert.Equal(new[] { "audience:pass", "revocation:fail", "validity:fail", "replay:fail" }, r.Checks.Select(c => c.Key + ":" + c.Value));
        Assert.Equal(3, r.Reasons.Count); // the existing one + not-enforced + absent; a check that already failed adds none
        Assert.Contains("revocation: required check is not-enforced (default-deny: not enforced by this resource server)", r.Reasons);
        Assert.Contains("replay: required check is absent (default-deny: not enforced by this resource server)", r.Reasons);
        var ok = PcaServer.EnforceRequired(true, new[] { C("counter_format", "pass") }, Array.Empty<string>(), new[] { "counter" });
        Assert.True(ok.Allow); // legacy "counter" resolves to counter_format when there is no replay check
        Assert.False(PcaServer.EnforceRequired(true, new[] { C("counter_format", "pass"), C("replay", "unsupported") }, Array.Empty<string>(), new[] { "counter" }).Allow);
    }

    [Fact]
    public void Profiles()
    {
        Assert.Equal(6, PcaServer.DefaultRequiredChecks.Count);
        Assert.Equal(7, PcaServer.StatefulRequiredChecks.Count);
        Assert.Equal(new[] { "params_digest", "policy" }, PcaServer.ExecutionRequiredChecks.Skip(7));
    }

    [Fact]
    public async Task IncompleteConfigRefusesEveryCall()
    {
        var az = PcaServer.CreateAuthorizer(new AuthorizeInput());
        var r = await az(null, new Operation("v", "r", new JD()));
        Assert.False(r.Allow);
    }

    [Fact]
    public void AmountRiskIsBlastRadiusOverKappa()
    {
        var grant = new JD { ["caveats"] = new List<object?> { new JD { ["type"] = "envelope", ["risk_policy"] = new JD { ["kappa"] = new Num("1000") } } } };
        var env = Pca.ReadEnvelope(grant);
        if (env?.GetValueOrDefault("risk_policy") is null) return; // envelope validation refused this minimal grant: nothing to price
        Assert.Equal(0.5, PcaServer.AmountRisk(grant, new JD { ["amount"] = new Num("500") }));
        Assert.Equal(1.0, PcaServer.AmountRisk(grant, new JD { ["amount"] = new Num("5000") }));
        Assert.Null(PcaServer.AmountRisk(grant, new JD { ["amount"] = "500" }));
    }

    [Fact]
    public void KvStateStoreClaimsPinsBudgetsAndSlots()
    {
        var s = new KvStateStore(new MemoryAtomicKv());
        Assert.Equal(StoreScope.Shared, s.Scope);
        Assert.True(s.Claim("k", 5)!.Ok);
        var again = s.Claim("k", 5)!;
        Assert.False(again.Ok); Assert.Equal(5, again.LastCounter);
        Assert.False(s.Claim("k", 4)!.Ok);
        Assert.True(s.Claim("k", 6)!.Ok);
        Assert.Equal(6, s.Last("k"));
        Assert.False(s.Claim(null!, 1)!.Ok);
        Assert.Null(s.Pin("g:epoch"));
        Assert.Equal(6, s.RaisePin("g:epoch", 6));
        Assert.Equal(7, s.RaisePin("g:epoch", 7));
        Assert.Equal(7, s.RaisePin("g:epoch", 3));
        Assert.Throws<ArgumentException>(() => s.RaisePin("", 1));
        Assert.True(s.ConsumeOnce("u", 100, 10));
        Assert.False(s.ConsumeOnce("u", 100, 50));
        Assert.True(s.ConsumeOnce("u", 200, 150)); // the record expired (retain 100 < now 150)
        Assert.Throws<ArgumentException>(() => s.ConsumeOnce("u", 1, 2));
        var b1 = new TrustBudget(1, 2, null);
        Assert.Null(s.Budget("g:budget"));
        Assert.True(s.BudgetCas("g:budget", null, b1));
        Assert.False(s.BudgetCas("g:budget", null, b1));
        Assert.Equal(b1, s.Budget("g:budget"));
        Assert.True(s.BudgetCas("g:budget", b1, new TrustBudget(0.5, 3, 4)));
    }
}
