using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// End to end through Authorize: a failing 0.5 check must reach the verdict (deny with its reason), never be computed and dropped.
public class K05E2eChecksTests
{
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_e2e";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x81, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x82, 32).ToArray()));
    static JD Amt() => new() { ["amount"] = 5L };
    static JD Grant() => Issue.MintGrant(P, Me.Id!, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "e2e").Grant;

    static AuthorizeResult Run(Action<AuthorizeInput> cfg)
    {
        var grant = Grant();
        var g = Issue.NormJ(grant);
        var pc = new Agent(Me, Aud, grant, null, 0) { Clock = () => Now }.Act("pay", "inv/1", Amt());
        var i = new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step",
        };
        cfg(i);
        return Pca.Authorize(Issue.Encode(pc), i.WithProv());
    }

    [Fact]
    public void ABaselineAllows() => Assert.True(Run(_ => { }).Allow);

    [Fact]
    public void ATaintGateFailureDenies()
    {
        var r = Run(i => i.EnforceTaint = new TaintGate(new TaintContext(new InMemoryTrustedInputRegistry()), 0));
        Assert.False(r.Allow);
        Assert.Contains("taint_gate: information-flow taint 1 exceeds policy max 0", r.Reasons);
    }

    [Fact]
    public void AFreshnessAnchorFailureDenies()
    {
        var r = Run(i => i.EnforceFreshness = new FreshnessGate(1000));
        Assert.False(r.Allow);
        Assert.Contains("freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)", r.Reasons);
    }

    [Fact]
    public void APassportFailureDenies()
    {
        var r = Run(i => i.RequirePassport = new PassportRequirement(new PassportOptions { TrustedIssuers = new[] { "x" } }));
        Assert.False(r.Allow);
        Assert.Contains("passport: malformed", r.Reasons);
    }

    [Fact]
    public void AContractViolationDenies()
    {
        var principal = EdKey.FromSeed(Enumerable.Repeat((byte)0x83, 32).ToArray());
        var contract = Contracts.Sign(new JD { ["version"] = 1L, ["principal"] = principal.Id, ["clauses"] = new JL { new JD { ["id"] = "no-pay", ["kind"] = "never", ["p"] = new JD { ["verb"] = "pay" } } } }, principal);
        var r = Run(i => i.Contracts = ContractEnforcer.Open(new MemoryAtomicKv(), contract, principal.Id, null, () => Now));
        Assert.False(r.Allow);
        Assert.Contains("contract: violated (no-pay)", r.Reasons);
    }

    [Fact]
    public void ABadPlanRootDenies()
    {
        var r = Run(i => i.Plan = null);
        Assert.False(r.Allow);
        Assert.Contains(r.Reasons, x => x.StartsWith("plan_root_authorized:"));
    }
}
