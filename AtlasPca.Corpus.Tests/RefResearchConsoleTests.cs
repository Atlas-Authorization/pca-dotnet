using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.Research;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the console, the kill switch, the multi-agent session and the policy simulator / linter over test-data/ref-core-research-java.json.gz (the other
/// functions of that corpus are replayed by the immune, DLP and reputation tests). A session case is a script of operations over named agents and sessions; an operation
/// that throws records {"$err": "Error"}. Agent keys are the seeds "research/&lt;label&gt;".</summary>
public class RefResearchConsoleTests
{
    const string R = "ref-core-research-java";

    static byte[] Seed(object? label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/research/" + (string)label!));
    static SuiteKey Key(object? label) => SuiteKey.Ed25519(EdKey.FromSeed(Seed(label)));
    static double Dbl(object? o) => AtlasPca.Analyzer.Jx.ToNumber(o);

    [Fact] public void BuildConsole() => Base.Check(R, "buildConsole", a => AgentConsole.BuildConsole(a[0]), min: 13);
    [Fact] public void Anomalies() => Base.Check(R, "anomalies", a => AgentConsole.Anomalies(AgentConsole.BuildConsole(a[0])), min: 7);
    [Fact] public void EventFromPCActn() => Base.Check(R, "eventFromPCActn", a => AgentConsole.EventFromPCActn(a[0], a[1], a[2] == null ? null : Dbl(a[2])), min: 12);
    [Fact] public void FreezeAgent() => Base.Check(R, "freezeAgent", a => AgentConsole.FreezeAgent(a[0], a[1]), min: 72);
    [Fact] public void UnfreezeAgent() => Base.Check(R, "unfreezeAgent", a => AgentConsole.UnfreezeAgent(a[0], a[1]), min: 72);
    [Fact] public void IsFrozen() => Base.Check(R, "isFrozen", a => AgentConsole.IsFrozen(a[0], a[1]), min: 72);

    static AgentHandle AgentOf(object? specO)
    {
        var s = (D)specO!;
        return Agent.FromPrincipal(new AgentOptions
        {
            Principal = Key(s["principal"]), Holder = Key(s["holder"]), Goal = (string)s["goal"]!, GoalSalt = (string?)s["goalSalt"],
            Permissions = (D)s["permissions"]!, Now = (long)Dbl(s["now"]),
        });
    }

    static T Need<T>(Dictionary<string, T> m, object? name) where T : class => m.TryGetValue((string)name!, out var v) ? v : throw new KeyNotFoundException((string)name!);
    static D Err() => new() { ["$err"] = "Error" };

    [Fact]
    public void Session() => Base.Check(R, "session", a =>
    {
        var ags = new Dictionary<string, AgentHandle>();
        var sess = new Dictionary<string, AgentSession>();
        var res = new L();
        foreach (var oo in (L)a[0]!)
        {
            var op = (L)oo!;
            try
            {
                object? v;
                switch ((string)op[0]!)
                {
                    case "agent": { var h = AgentOf(op[2]); ags[(string)op[1]!] = h; v = h.Holder.Ed!.Id; break; }
                    case "start": { var s = AgentSession.Start(Need(ags, op[2])); sess[(string)op[1]!] = s; v = s.GoalCommit; break; }
                    case "mk":
                    {
                        var ms = ((L)op[2]!).Select(n => Need(ags, n)).ToList();
                        var goal = op[3] != null ? (string)op[3]! : ms.Count == 0 ? "" : Pca.ReadEnvelope(ms[0].Grant) is { } env && env.GetValueOrDefault("goal_commit") is string g ? g : "";
                        var s = new AgentSession(ms.Count == 0 ? null : ms[0], ms, goal);
                        sess[(string)op[1]!] = s;
                        v = s.GoalCommit;
                        break;
                    }
                    case "add":
                    {
                        var r = AgentSession.AddMember(Need(sess, op[2]), op[3] == null ? null : Key(op[3]), op[4] == null ? null : op[4] is string cs ? cs.Select(ch => (object?)ch.ToString()).ToList() : (L)op[4]!); // a string is spread into its characters
                        sess[(string)op[1]!] = r.Session;
                        v = r.Member.Holder.Ed!.Id;
                        break;
                    }
                    case "agents": v = AgentSession.Agents(Need(sess, op[1])); break;
                    case "depth": v = (long)AgentSession.Depth(Need(sess, op[1])); break;
                    case "shares": v = AgentSession.SharesGoal(Need(sess, op[1])); break;
                    case "goal": v = Need(sess, op[1]).GoalCommit; break;
                    case "console": v = AgentSession.ConsoleOf(Need(sess, op[1]), op[2]); break;
                    default: throw new InvalidOperationException("op");
                }
                res.Add(v);
            }
            catch (Exception) { res.Add(Err()); }
        }
        return res;
    }, min: 5);

    internal static CompiledPolicy Compile(object? specO)
    {
        var s = (D)specO!;
        return Facade.CompilePolicy(new PolicyOptions
        {
            Permissions = (D)s["permissions"]!,
            Limits = s.GetValueOrDefault("limits") is D lim ? lim.ToDictionary(e => e.Key, e => (string)e.Value!) : null,
            BudgetModel = s.GetValueOrDefault("budgetModel") as string,
            RiskPolicy = s.GetValueOrDefault("riskPolicy") as D,
            Now = (long)Dbl(s["now"]),
        });
    }

    [Fact] public void Simulate() => Base.Check(R, "simulate", a => PolicySim.Simulate(Compile(a[0]), (L)a[1]!, null, a[2] == null ? 0.0 : Dbl(a[2])), min: 189);
    [Fact] public void LintPolicy() => Base.Check(R, "lintPolicy", a => PolicySim.LintPolicy(Compile(a[0])), min: 9);

    [Fact]
    public void Covers()
    {
        // the other functions of the corpus are replayed by RefImmuneTests (immune read side), RefDlpTests (DLP) and RefReputationTests (settlement disputes)
        Base.Covers(R, new[]
        {
            "buildConsole", "anomalies", "eventFromPCActn", "freezeAgent", "unfreezeAgent", "isFrozen", "session", "simulate", "lintPolicy",
            "assess", "validateImmuneState", "observe", "updateBaseline", "baselineStd", "evaluateDlp", "defaultDlpPolicy", "disputesFromSettlements",
        });
        Assert.Equal(6188, Base.Total(R));
    }
}
