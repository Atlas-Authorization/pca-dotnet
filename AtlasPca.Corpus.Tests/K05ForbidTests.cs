using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The forbid-wins clause policy and its certificate (Forbid.cs) replaying the clause and certificate sections of
// packages/pca/conformance/prohibition-vectors.json (the constitution and monitor sections belong to the prohibition plane, which this SDK does not carry),
// and the forbid / requireLinkedTemplate options of Authorize.
public class K05ForbidTests
{
    static ClauseOptions? Opts(object? o)
    {
        if (o is not JD d) return null;
        IReadOnlyList<string>? L2(string k) => d.TryGetValue(k, out var v) ? L(v).Select(x => (string)x!).ToList() : null;
        return new ClauseOptions(L2("precedence"), L2("permitSigners"));
    }

    [Fact]
    public void ClauseListsDecideLikeTheReference()
    {
        var cases = L(Load("prohibition-vectors.json")["clauses"]);
        Assert.Equal(20, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var ctx = c["action"] as JD;
            Assert.True((string?)Forbid.Error(c["clauses"]) == (string?)e["error"], $"{name}: error {Forbid.Error(c["clauses"])}");
            var d = Forbid.Decide(c["clauses"], ctx, Opts(c.GetValueOrDefault("options")));
            Assert.True(d.Decision == (string)e["decision"]!, $"{name}: decision {d.Decision}");
            var w = D(e["winner"]);
            Assert.True(d.WinnerKind == (string)w["kind"]! && d.WinnerId == (string?)w["id"], $"{name}: winner {d.WinnerKind} {d.WinnerId}");
            Assert.True(d.Shadowed.SequenceEqual(L(e["shadowed"]).Select(q => (string)q!)), $"{name}: shadowed");
            var rows = L(e["values"]).Select(D).ToList();
            Assert.True(d.Values.Count == rows.Count, $"{name}: values count");
            for (int i = 0; i < rows.Count; i++)
                Assert.True(d.Values[i].Id == (string)rows[i]["id"]! && d.Values[i].Kind == (string)rows[i]["kind"]! && d.Values[i].Value == (string)rows[i]["value"]!, $"{name}: row {i}");
        }
    }

    [Fact]
    public void CertificatesAreRecomputedNeverTrusted()
    {
        var cases = L(Load("prohibition-vectors.json")["check"]);
        Assert.Equal(11, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var got = Forbid.Check(c["certificate"], c["clauses"], c["action"] as JD, Opts(c.GetValueOrDefault("options")));
            Assert.True(got.Ok == (bool)e["ok"]!, $"{name}: ok {got.Ok} {got.Reason}");
            Assert.True(got.Reason == (e.TryGetValue("reason", out var r) ? (string?)r : null), $"{name}: reason {got.Reason}");
        }
    }

    // ================= through Authorize =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_forbid";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x71, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x72, 32).ToArray()));
    static JD Amt() => new() { ["amount"] = 5L };
    static JD Grant() => Issue.MintGrant(P, Me.Id!, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "forbid").Grant;
    static JD Act(JD grant) => new Agent(Me, Aud, grant, null, 0) { Clock = () => Now }.Act("pay", "inv/1", Amt());

    static AuthorizeResult Run(JD grant, Action<AuthorizeInput> cfg)
    {
        var g = Issue.NormJ(grant);
        var i = new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null, StateStore = new MemoryStateStore(),
            IsRevoked = (_, _) => false, Now = Now, Plan = "single-step",
        };
        cfg(i);
        return Pca.Authorize(Issue.Encode(Act(grant)), i.WithProv());
    }

    static JD Clause(string id, string kind, string verb = "pay", string? signer = null)
    {
        var c = new JD { ["id"] = id, ["kind"] = kind, ["when"] = new JD { ["verb"] = verb } };
        if (signer != null) c["signer"] = signer;
        return c;
    }

    [Fact]
    public void AForbidBeatsEveryPermitAndRefusesBeforeTheCounterIsSpent()
    {
        var g = Grant();
        var denied = Run(g, i => i.Forbid = new ForbidOptions((_, _) => new JL { Clause("allow-pay", "permit"), Clause("no-pay", "forbid") }));
        Assert.False(denied.Allow);
        Assert.Equal("fail", denied.Checks["forbid"]);
        Assert.Contains("forbid: deny by forbid no-pay", denied.Reasons);
        var g2 = Grant();
        var none = Run(g2, i => i.Forbid = new ForbidOptions((_, _) => new JL { Clause("other", "permit", "refund") }));
        Assert.Contains("forbid: deny by none", none.Reasons);
        var g3 = Grant();
        var esc = Run(g3, i => i.Forbid = new ForbidOptions((_, _) => new JL { Clause("a", "permit"), Clause("review", "escalate") }));
        Assert.Contains("forbid: escalate by escalate review", esc.Reasons);
        var g4 = Grant();
        var ok = Run(g4, i => { i.ServerRisk = ProvHarness.LowRisk; i.Forbid = new ForbidOptions((_, _) => new JL { Clause("a", "permit") }); });
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["forbid"]);
        Assert.Equal("permit", (string)D(ok.ForbidCertificate!["winner"])["kind"]!);
    }

    [Fact]
    public void ARequiredCertificateMustBePresentedAndMatch()
    {
        var clauses = new JL { Clause("a", "permit") };
        var ctx = new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = "inv/1", ["params"] = Amt() } };
        var good = Forbid.Certify(clauses, ctx);
        ForbidOptions Need() => new((_, _) => clauses, RequireCertificate: true);
        var g = Grant();
        Assert.Contains("forbid: the call carries no certificate (fail closed)", Run(g, i => { i.ServerRisk = ProvHarness.LowRisk; i.Forbid = Need(); }).Reasons);
        var g2 = Grant();
        Assert.True(Run(g2, i => { i.ServerRisk = ProvHarness.LowRisk; i.Forbid = Need(); i.ForbidCertificate = Issue.Norm(good); }).Allow);
        var g3 = Grant();
        var bad = Forbid.Certify(clauses, new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = "inv/2" } });
        Assert.Contains("forbid: certificate refused (certificate does not match the recomputed decision)", Run(g3, i => { i.ServerRisk = ProvHarness.LowRisk; i.Forbid = Need(); i.ForbidCertificate = Issue.Norm(bad); }).Reasons);
    }

    [Fact]
    public void AThrowingClauseSourceIsRefusedFailClosed()
    {
        var g = Grant();
        var r = Run(g, i => i.Forbid = new ForbidOptions((_, _) => throw new InvalidOperationException("x")));
        Assert.False(r.Allow);
        Assert.Contains("forbid: the clause policy could not be evaluated (fail closed)", r.Reasons);
    }

    [Fact]
    public void ALinkedTemplateIsRequiredWhenAskedFor()
    {
        var g = Grant();
        var r = Run(g, i => { i.ServerRisk = ProvHarness.LowRisk; i.RequireLinkedTemplate = () => new JD(); });
        Assert.False(r.Allow);
        Assert.Contains("template: the grant carries no template_ref", r.Reasons);
        var g2 = Grant();
        var thrown = Run(g2, i => { i.ServerRisk = ProvHarness.LowRisk; i.RequireLinkedTemplate = () => throw new InvalidOperationException("x"); });
        Assert.False(thrown.Allow);
        Assert.Equal("fail", thrown.Checks["template"]);
        Assert.False(Run(Grant(), i => i.ServerRisk = ProvHarness.LowRisk).Checks.ContainsKey("template")); // off by default
    }
}
