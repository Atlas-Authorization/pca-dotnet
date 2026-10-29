using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Plan lifecycle (T10): replays plan-vectors.json scenario by scenario against one fresh registry each (the roots are Merkle roots of the
// plan-node leaves, so a match proves the commitment equals the reference's), then the concurrency and tamper properties. A missing
// vector file FAILS.
public class PlanVectorTests
{
    static string S(object? o) => (string)o!;
    static string C(object? v) => Pca.Canonicalize(v);

    static List<D> NodesOf(object? v) => L(v).Cast<D>().ToList();

    static PlanApproval? ApprovalOf(object? v)
    {
        if (v is not D m) return null;
        double? exp = m.TryGetValue("expiresAt", out var x) ? IntentJs.NumOf(x) ?? double.NaN : null; // a present non-number (null) is not a time
        return new PlanApproval(m.GetValueOrDefault("by") as string ?? "", exp);
    }

    [Fact]
    public void ScenariosReplay()
    {
        var scs = L(Load("plan-vectors.json")["scenarios"]);
        Assert.True(scs.Count == 12, $"{scs.Count} scenarios, this runner pins 12");
        foreach (var sc in scs.Cast<D>())
        {
            long now = 0;
            var opts = new PlanRegistryOptions { Now = () => now };
            switch (sc.GetValueOrDefault("validator") as string)
            {
                case "accept": opts.Validator = _ => new PlanValidation(true); break;
                case "refuse": opts.Validator = _ => new PlanValidation(false, "node outside the grant"); break;
                case "throw": opts.Validator = _ => throw new InvalidOperationException("policy down"); break;
            }
            var reg = new PlanRegistry(opts);
            var steps = L(sc["steps"]); var expect = L(sc["expect"]);
            Assert.Equal(steps.Count, expect.Count);
            for (int i = 0; i < steps.Count; i++)
            {
                var s = D(steps[i]);
                now = N(s["at"]);
                string grant = s.GetValueOrDefault("grant") as string ?? "", root = s.GetValueOrDefault("root") as string ?? "";
                object? got;
                switch (S(s["op"]))
                {
                    case "draft": got = reg.Draft(grant, NodesOf(s["nodes"])).ToJson(); break;
                    case "validate": got = reg.Validate(grant, root).ToJson(); break;
                    case "commit": got = reg.Commit(grant, root).ToJson(); break;
                    case "authorize": got = reg.Authorize(grant, root, ApprovalOf(s["approval"])).ToJson(); break;
                    case "revoke": got = reg.Revoke(grant, root, S(s["reason"])).ToJson(); break;
                    case "status": got = reg.Status(grant, root, now).ToJson(); break;
                    case "check":
                        {
                            var o = new PlanCheckOptions { Now = now, NodeId = s.GetValueOrDefault("node_id") as string };
                            if (s.GetValueOrDefault("operation") is D op) o.Operation = new Operation(S(op["verb"]), S(op["resource"]), op.GetValueOrDefault("params"));
                            got = reg.Check(grant, root, o).ToJson();
                            break;
                        }
                    case "is_plan_authorized": got = reg.IsPlanAuthorized(grant, root); break;
                    case "context": got = reg.Context(grant, root, now)?.ToJson(); break;
                    default: throw new InvalidOperationException("op " + s["op"]);
                }
                Assert.True(C(got) == C(expect[i]), $"{sc["name"]} step {i} ({s["op"]}):\n got  {C(got)}\n want {C(expect[i])}");
            }
        }
    }

    static List<D> Demo() => new() { new D { ["id"] = "n1", ["verb"] = "orders.read", ["resource"] = "/orders/1" } };

    // Of N concurrent claims of one transition exactly one wins; the rest see the new state.
    [Fact]
    public async Task ConcurrentClaimsOfOneTransitionHaveOneWinner()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => 1000 });
        var d = reg.Draft("g", Demo());
        Assert.True(d.Ok, d.Reason);
        var root = d.Record!.Root;
        Assert.True(reg.Validate("g", root).Ok);
        Assert.True(reg.Commit("g", root).Ok);
        var steps = new Dictionary<string, Func<PlanTransition>>
        {
            ["authorize"] = () => reg.Authorize("g", root, new PlanApproval("p")),
            ["revoke"] = () => reg.Revoke("g", root, "x"),
        };
        foreach (var (name, step) in steps)
        {
            var wins = (await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(step)))).Count(t => t.Ok);
            Assert.True(wins == 1, $"{name}: {wins} winners, want exactly 1");
        }
        var s = reg.Status("g", root);
        Assert.Equal((PlanStates.Revoked, false), (s.State, s.Executable));
    }

    [Fact]
    public async Task ConcurrentDraftsOfOnePlanHaveOneWinner()
    {
        var reg = new PlanRegistry();
        var wins = (await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => reg.Draft("g", Demo()))))).Count(t => t.Ok);
        Assert.Equal(1, wins);
    }

    // A tampered stored plan is never executable: the nodes must still hash to the root.
    [Fact]
    public void StatusDetectsTamperedNodes()
    {
        var kv = new MemoryAtomicKv();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => 5 });
        var root = reg.Draft("g", Demo()).Record!.Root;
        reg.Validate("g", root); reg.Commit("g", root); reg.Authorize("g", root, new PlanApproval("p"));
        Assert.True(reg.Status("g", root).Executable);
        var key = "pca-plan:g:" + root;
        kv.Update(key, prev => prev!.Replace("/orders/1", "/orders/2"));
        var s = reg.Status("g", root);
        Assert.False(s.Executable);
        Assert.Equal($"plan {root}: the stored nodes no longer hash to the root", s.Reason);
    }

    [Fact]
    public void AStoreThatThrowsFailsClosed()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = new ThrowingKv() });
        var d = reg.Draft("g", Demo());
        Assert.False(d.Ok);
        Assert.StartsWith("the plan store failed (fail closed): ", d.Reason);
        Assert.False(reg.Status("g", "r").Executable);
        Assert.False(reg.IsPlanAuthorized("g", "r"));
    }

    sealed class ThrowingKv : IAtomicKv
    {
        public string? Get(string key) => throw new InvalidOperationException("down");
        public void Update(string key, Func<string?, string?> fn) => throw new InvalidOperationException("down");
    }
}
