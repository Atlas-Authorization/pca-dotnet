using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Goal binding v3 (approved_goal): replays goal-commit-vectors.json (commit, invalid, binding) and pins the closed-object / fail-closed
// rules of the policy. A missing vector file FAILS (Conf.Load throws).
public class GoalCommitV3Tests
{
    const string G = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw";
    const string P = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo";

    static List<D> Rows(D doc, string table, int expected)
    {
        Assert.True(doc.ContainsKey(table), $"{table}: missing table");
        var rows = L(doc[table]).Cast<D>().ToList();
        Assert.True(rows.Count == expected, $"{table}: {rows.Count} rows, this runner pins {expected}");
        return rows;
    }

    static ApprovedGoalRef RefOf(D v) => new((string)v["goal_digest"]!, (string)v["policy_digest"]!);

    [Fact]
    public void CommitVectorsReproduce()
    {
        var doc = Load("goal-commit-vectors.json");
        Assert.Equal(doc["goal_prefix"], Pca.IntentGoalV3Prefix);
        foreach (var v in Rows(doc, "commit", 7))
        {
            Assert.True(Pca.IntentGoalV3(RefOf(v)) == (string)v["goal"]!, $"{v["name"]}: goal");
            Assert.True(Pca.IntentGoalCommitV3(RefOf(v), (string)v["salt"]!) == (string)v["commit"]!, $"{v["name"]}: commit");
        }
    }

    [Fact]
    public void InvalidDigestsAreRefused()
    {
        foreach (var v in Rows(Load("goal-commit-vectors.json"), "invalid", 4))
        {
            Assert.False(RefOf(v).IsValid, $"{v["name"]}: accepted");
            Assert.Throws<ArgumentException>(() => Pca.IntentGoalV3(RefOf(v)));
            Assert.Throws<ArgumentException>(() => Pca.IntentGoalCommitV3(RefOf(v), "s"));
        }
    }

    [Fact]
    public void BindingVectorsReproduce()
    {
        foreach (var v in Rows(Load("goal-commit-vectors.json"), "binding", 16))
        {
            D? grant = v["grant_commit"] is string gc ? new D { ["caveats"] = new L { new D { ["type"] = "envelope", ["goal_commit"] = gc } } } : new D();
            var policy = IntentPolicy.FromJson(v["policy"]);
            var got = Pca.DecideIntent(v["intent"], v["intent"] != null, grant, policy, v.GetValueOrDefault("session") as string, null);
            var res = got == null ? "absent" : got == "" ? "pass" : "fail";
            Assert.True(res == (string)v["expect"]!, $"{v["name"]}: got {res} ({got}) want {v["expect"]}");
        }
    }

    [Fact]
    public void MisconfiguredApprovedGoalFailsClosedAndActivatesThePolicy()
    {
        foreach (var json in new[]
        {
            $"{{\"approved_goal\":{{\"goal_digest\":\"{G}\",\"policy_digest\":\"{P}\",\"x\":1}}}}",
            $"{{\"approved_goal\":{{\"goal_digest\":\"{G}\"}}}}",
            $"{{\"approved_goal\":{{\"goal_digest\":\"{G}\",\"policy_digest\":5}}}}",
            "{\"approved_goal\":null}",
            "{\"approved_goal\":[]}",
        })
        {
            var pol = IntentPolicy.FromJsonText(json);
            Assert.True(pol is { IsActive: true }, json);
            var why = Pca.DecideIntent(null, false, new D(), pol);
            Assert.True(why is { Length: > 0 }, $"{json}: {why}");
            Assert.Contains("approved_goal", why);
        }
        var short1 = new IntentPolicy(ApprovedGoal: new ApprovedGoalRef("AAAA", P));
        Assert.Contains("approved_goal", Pca.DecideIntent(null, false, new D(), short1));
        // a well-formed approved_goal alone is active: an absent intent is a refusal, never "not evaluated"
        var ok = IntentPolicy.FromJsonText($"{{\"approved_goal\":{{\"goal_digest\":\"{G}\",\"policy_digest\":\"{P}\"}}}}");
        Assert.Equal("this verifier requires an intent binding but the PCActn carries none", Pca.DecideIntent(null, false, new D(), ok));
    }
}
