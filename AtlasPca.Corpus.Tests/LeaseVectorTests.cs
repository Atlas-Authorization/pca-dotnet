using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// Leases, replaying packages/pca/conformance/lease-vectors.json (decided by the TypeScript reference). A missing file fails.
public class LeaseVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();

    [Fact]
    public void EveryScenarioDecidesLikeTheReference()
    {
        var doc = Load("lease-vectors.json");
        var records = L(doc["records"]); var revocations = L(doc["revocations"]);
        var authority = (string)doc["authority"]!;
        Assert.True(L(doc["scenarios"]).Count >= 20);
        foreach (var x in L(doc["scenarios"]))
        {
            var s = D(x); var name = (string)s["name"]!;
            var p = s.ContainsKey("policy") ? D(s["policy"]) : new JD();
            var policy = new LeasePolicy(
                new[] { authority },
                p.ContainsKey("minApprovals") ? N(p["minApprovals"]) : 1,
                p.ContainsKey("eligibleApprovers") ? Strs(p["eligibleApprovers"]) : null,
                !p.ContainsKey("freshJustification") || (bool)p["freshJustification"]!);
            var reg = new LeaseRegistry(policy);
            var i = 0;
            foreach (var y in L(s["steps"]))
            {
                var st = D(y); var e = D(st["expect"]); var at = $"{name} step {i++}";
                switch ((string)st["op"]!)
                {
                    case "accept":
                        var a = reg.Accept(records[(int)N(st["record"])], st.ContainsKey("chain") ? Strs(st["chain"]) : null);
                        Assert.True(a.Ok == (bool)e["ok"]!, $"{at}: ok {a.Code}");
                        if (a.Ok) Assert.True(a.Replaced == (bool)e["replaced"]! && a.Seq == N(e["seq"]), $"{at}: replaced/seq");
                        else Assert.True(a.Code == (string)e["code"]!, $"{at}: code {a.Code}");
                        break;
                    case "revoke":
                        var r = reg.Revoke(revocations[(int)N(st["revocation"])]);
                        Assert.True(r.Ok == (bool)e["ok"]!, $"{at}: ok {r.Code}");
                        if (r.Ok) Assert.True(r.Revoked == N(e["revoked"]), $"{at}: revoked {r.Revoked}");
                        else Assert.True(r.Code == (string)e["code"]!, $"{at}: code {r.Code}");
                        break;
                    case "check":
                        var c = Lease.Check(records[(int)N(st["record"])], reg, st["now"]);
                        Assert.True(c.Decision == (string)e["decision"]! && c.Code == e.GetValueOrDefault("code") as string && c.LeaseId == e.GetValueOrDefault("lease_id") as string
                            && c.ExpiresAt == (e.ContainsKey("expires_at") ? (long?)N(e["expires_at"]) : null), $"{at}: {c}");
                        break;
                    default:
                        throw new Xunit.Sdk.XunitException($"{at}: unknown op {st["op"]}");
                        break;
                }
            }
        }
    }

    [Fact]
    public void PathUnderAndSod()
    {
        Assert.True(Lease.PathUnder("db/prod/ro", "db/prod"));
        Assert.True(Lease.PathUnder("db/prod", "db/prod"));
        Assert.False(Lease.PathUnder("db/production", "db/prod"));
        Assert.Null(Lease.SodError("alice", "agent", new[] { "bob" }));
        Assert.Equal("the requester may not approve their own request", Lease.SodError("alice", "agent", new[] { "alice" }));
    }
}
