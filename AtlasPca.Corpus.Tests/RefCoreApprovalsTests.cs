using System.Security.Cryptography;
using System.Text;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the agent-facing half of approvals (review, goal lineage, batch review, time-boxing) against the TypeScript reference.</summary>
public class RefCoreApprovalsTests
{
    const string M = "ref-core-approvals-java";

    static SuiteKey Key(object? label) =>
        SuiteKey.Ed25519(EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/approvals/" + (string)label!))));

    static AgentHandle Build(object? specO)
    {
        var s = (D)specO!;
        var o = new AgentOptions
        {
            Principal = Key(s["principal"]), Holder = Key(s["holder"]), Goal = (string)s["goal"]!, GoalSalt = (string)s["goalSalt"]!,
            Permissions = (D)s["permissions"]!, Now = Base.Long(s["now"]),
        };
        if (s.GetValueOrDefault("limits") is D lim) o.Limits = lim.ToDictionary(e => e.Key, e => (string)e.Value!);
        if (s.GetValueOrDefault("riskPolicy") is D rp) o.RiskPolicy = rp;
        if (s.GetValueOrDefault("budgetModel") is string bm) o.BudgetModel = bm;
        if (s.GetValueOrDefault("aud") is string aud) o.Aud = aud;
        return Agent.FromPrincipal(o);
    }

    static Func<string, string, D?, D> Renderer(string mode) => (verb, resource, _) =>
    {
        if (mode == "throw") throw new InvalidOperationException("boom");
        if (mode == "badshape") return new D { ["v"] = 2L };
        return new D
        {
            ["v"] = 1L, ["kind"] = "pca-approval-render", ["verb"] = verb, ["def_digest"] = new string('A', 43), ["unreviewed"] = true,
            ["fields"] = new L { new D { ["id"] = "resource", ["class"] = "param", ["value"] = resource } },
        };
    };

    static ReviewOptions Opts(object? o)
    {
        var r = new ReviewOptions();
        if (o is not D m) return r;
        if (m.GetValueOrDefault("now") != null) r.Now = Base.Long(m["now"]);
        if (m.GetValueOrDefault("goal") is string g) r.Goal = g;
        if (m.GetValueOrDefault("standing") is L st) r.Standing = st;
        if (m.GetValueOrDefault("renderer") is string rn) r.Renderer = Renderer(rn);
        r.InsecureUnboundApproval = m.GetValueOrDefault("insecure") is true;
        return r;
    }

    [Fact] public void ReviewAction() => Base.Check(M, "reviewAction", a => Approvals.ReviewAction(Build(a[0]), (string)a[1]!, (string)a[2]!, a[3] as D, Opts(a[4])));

    [Fact]
    public void BuildGoalLineage() => Base.Check(M, "buildGoalLineage", a =>
        Approvals.BuildGoalLineage(Build(a[0]), (string)a[1]!, (string)a[2]!, a[3] as D, (a[4] as D)?.GetValueOrDefault("goal") as string));

    [Fact] public void DescribeGoalLineage() => Base.Check(M, "describeGoalLineage", a => Approvals.DescribeGoalLineage(a[0] as D));

    [Fact]
    public void BatchReview() => Base.Check(M, "batchReview", a =>
        Approvals.BatchReview(Build(a[0]), ((L)a[1]!).Select(c => (D)c!), Opts(a[2])));

    [Fact]
    public void TimeBox() => Base.Check(M, "timeBox", a =>
        Approvals.TimeBox((D)a[0]!, Key(a[1]), IntentJs.NumOf(a[2])!.Value, IntentJs.NumOf(a[3])!.Value));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "reviewAction", "buildGoalLineage", "describeGoalLineage", "batchReview", "timeBox" }); Assert.Equal(2211, Base.Total(M)); }
}
