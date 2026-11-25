using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// The stateful layer: packages/pca/conformance/stateful-vectors.json, 20 sequences of presentations and revocations against ONE replay and budget store.
public class StatefulVectorTests
{
    sealed class ClaimOnlyStore : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    [Fact]
    public void EverySequenceDecidesLikeTheReference()
    {
        var doc = Load("stateful-vectors.json");
        var seqs = L(doc["stateful"]);
        Assert.Equal(20, seqs.Count);
        foreach (var sx in seqs)
        {
            var s = D(sx); var name = (string)s["name"]!; var setup = D(s["setup"]);
            var aud = (string)setup["audience"]!;
            var grants = L(setup["grants"]).Select(D).ToList();
            var plan = setup["plan_nodes"];
            var risk = D(setup["risk"]).ToDictionary(kv => kv.Key, kv => IntentJs.NumOf(kv.Value)!.Value);
            var revoked = new HashSet<string>(L(setup["revoked"]).Select(x => (string)x!));
            var mem = new MemoryStateStore();
            IStateStore store = setup.TryGetValue("initial_budget", out var ib) && ib != null ? mem : new ClaimOnlyStore();
            var steps = L(s["steps"]);
            for (int i = 0; i < steps.Count; i++)
            {
                var st = D(steps[i]);
                if ((string)st["op"]! == "revoke") { revoked.Add((string)st["id"]!); continue; }
                var pc = D(st["pcactn"]);
                var grant = grants.First(g => (string)g["id"]! == (string)pc["grant_ref"]!);
                var holder = (string?)D(L(pc["cap_chain"])[^1])["holder"];
                if (ib != null && store is MemoryStateStore ms)
                {
                    var key = $"aud:{Uri.EscapeDataString(aud)}:{grant["id"]}:{holder}:budget";
                    if (ms.Budget(key) == null)
                    {
                        var b = D(ib);
                        ms.BudgetCas(key, null, new TrustBudget(IntentJs.NumOf(b["B"])!.Value, IntentJs.NumOf(b["tau"])!.Value));
                    }
                }
                var prm = st["params"];
                var verb = (string)D(pc["action"])["verb"]!; var res = (string)D(pc["action"])["resource"]!;
                var input = new AuthorizeInput
                {
                    Operation = new Operation(verb, res, prm), Audience = aud, ResolveGrant = id => grants.FirstOrDefault(g => (string)g["id"]! == id), StateStore = store,
                    IsRevoked = (_, g) => revoked.Contains((string)g["id"]!) || L(pc["cap_chain"]).Any(h => revoked.Contains((string)D(h)["id"]!)), Now = N(st["now"]),
                    Context = _ => new JD { ["plan"] = plan, ["plan_authorized"] = true, ["risk"] = risk.ToDictionary(kv => kv.Key, kv => (object?)kv.Value) },
                    ProvenanceFlow = ProvHarness.Options,
                };
                input.Provenance = ProvHarness.Bundle(input.Operation);
                var r = Pca.Authorize(pc, input);
                var e = D(st["expect"]);
                Assert.True(r.Allow == (bool)e["allow"]!, $"{name} step {i}: allow {r.Allow} {r.Reason}");
                var failed = r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).Where(k => k is not ("budget" or "threshold" or "policy" or "provenance_flow")).ToList();
                var want = L(e["failed"]).Select(x => (string)x!).ToList();
                // the reference names a refused step by the checks of the proof itself; budget and threshold step-ups are named threshold
                if (want.Contains("threshold")) Assert.Equal("fail", r.Checks["threshold"]);
                else Assert.True(want.OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(failed.OrderBy(x => x, StringComparer.Ordinal)), $"{name} step {i}: failed [{string.Join(",", failed)}] want [{string.Join(",", want)}]");
            }
        }
    }
}
