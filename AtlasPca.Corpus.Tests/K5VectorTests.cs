using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// K5: workflow (DAG) admission, read-side authorization, the tokenisation vault and aggregate reads, replaying packages/pca/conformance/{workflow,readside,vault-aggregate}-vectors.json
// (decided by the TypeScript reference). A missing file fails (Conf.Load throws).
public class K5VectorTests
{
    static string Str(object? o) => (string)o!;
    static void Same(JD got, object? expect, string name) => Assert.True(Pca.Canonicalize(got) == Pca.Canonicalize(expect), $"{name}: got {Pca.Canonicalize(got)} want {Pca.Canonicalize(expect)}");

    static AdmitInput Admit(JD doc, JD c) => new(D(doc["workflows"])[Str(c["workflow"])], Str(c["principal"]), Str(c["rs_signer"]), c["receipts"], N(c["now"]), c["request"]);

    [Fact]
    public void WorkflowAdmissionDecidesLikeTheReference()
    {
        var W = Load("workflow-vectors.json");
        var main = D(D(D(W["workflows"])["main"])["body"]);
        Assert.Equal(Str(D(W["digests"])["workflow"]), Workflow.WorkflowDigest(main));
        foreach (var x in L(D(W["digests"])["values"])) { var v = D(x); Assert.Equal(Str(v["digest"]), Workflow.ValueDigest(v["value"])); }
        Assert.Equal(4, L(D(W["digests"])["receipt_refs"]).Count);
        var seen = new HashSet<string>();
        Assert.True(L(W["admit"]).Count >= 60 && L(W["bind"]).Count >= 5 && L(W["plan_root"]).Count >= 8);
        foreach (var (table, bind) in new[] { ("admit", false), ("bind", true) })
            foreach (var x in L(W[table]))
            {
                var c = D(x);
                var got = bind ? Workflow.BindPromises(Admit(W, c)) : Workflow.AdmitStep(Admit(W, c));
                Same(got.ToJson(), c["expect"], $"{table}: {c["name"]}");
                if (D(c["expect"])["code"] is string code) seen.Add(code);
            }
        foreach (var x in L(W["plan_root"]))
        {
            var c = D(x);
            Assert.True(Workflow.PlanRootAuthorized(D(W["workflows"])[Str(c["workflow"])], Str(c["principal"]), N(c["now"]), Str(c["root"])) == (bool)c["expect"]!, $"plan_root: {c["name"]}");
        }
        foreach (var code in new[] { "bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate" })
            Assert.True(seen.Contains(code), code);
        // never throws on hostile input
        var keys = D(W["keys"]);
        foreach (var h in new object?[] { null, new Num("1"), "x", new List<object?>(), new JD(), new JD { ["body"] = null }, new JD { ["body"] = new JD(), ["sig"] = new Num("1") } })
            Assert.Equal("deny", Workflow.AdmitStep(new(h, Str(keys["principal"]), Str(keys["rs"]), new List<object?>(), 1, h)).Decision);
        Assert.Equal("deny", Workflow.AdmitStep(new(D(W["workflows"])["main"], Str(keys["principal"]), Str(keys["rs"]), "x", 1, new JD())).Decision);
    }

    [Fact]
    public void ReadSideDecidesLikeTheReference()
    {
        var R = Load("readside-vectors.json");
        var grants = D(R["grants"]);
        Assert.Equal(Str(D(R["digests"])["grant"]), ReadSide.ReadGrantDigest(D(D(grants["main"])["body"])));
        Assert.True(L(R["redact"]).Count >= 28 && L(R["sinks"]).Count >= 16);
        foreach (var x in L(R["redact"]))
        {
            var c = D(x); var i = D(c["input"]);
            var got = ReadSide.RedactRead(new(grants[Str(c["grant"])], i["principal"], i["now"], i["verb"], i["resource"], i["purpose"], i["schema"], i["record"], i["tighten"], i["salt"], i["counts"]));
            Same(got.ToJson(), c["expect"], $"redact: {c["name"]}");
        }
        foreach (var x in L(R["sinks"]))
        {
            var c = D(x);
            var got = ReadSide.CheckSink(new(grants[Str(c["grant"])], c["principal"], c["rs_signer"], c["now"], c["sink"], c["receipts"]));
            Same(got.ToJson(), c["expect"], $"sink: {c["name"]}");
        }
        var chain = D(L(R["sinks"]).First(s => Str(D(s)["name"]) == "chain-of-two-public-reads"));
        var cl = ReadSide.ReadChainLabels(chain["receipts"], Str(D(R["keys"])["rs"]), Str(D(R["digests"])["grant"]), 1_800_000_000_000);
        Assert.Equal(L(D(D(R["digests"])["chain_labels"])["labels"]).Select(Str).ToList(), cl.Labels);
        // the masked view never contains a dropped value
        var text = Pca.Canonicalize(D(D(L(R["redact"]).First(s => Str(D(s)["name"]) == "support-view"))["expect"])["view"]);
        foreach (var secret in new[] { "sk_live_x", "123-45-6789", "dev-1", "c_77", "not in the schema" }) Assert.DoesNotContain(secret, text);
    }

    [Fact]
    public void VaultAndAggregateDecideLikeTheReference()
    {
        var V = Load("vault-aggregate-vectors.json");
        var keys = D(V["keys"]);
        var vg = D(D(V["grants"])["vault"]);
        var ag = D(D(V["grants"])["aggregate"]);
        var sampler = D(V["sampler"]);
        Assert.True(L(V["vault"]).Count >= 13 && L(V["aggregate"]).Count >= 10 && L(sampler["uniform"]).Count >= 2 && L(sampler["laplace"]).Count >= 4);
        foreach (var x in L(sampler["uniform"]))
        {
            var u = D(x);
            var d = ReadVault.SeededDraws(Str(u["seed"]));
            var got = new List<long>();
            foreach (var b in L(u["bounds"])) got.Add(d.Uniform(N(b)));
            Assert.Equal(L(u["draws"]).Select(v => N(v)).ToList(), got);
        }
        foreach (var x in L(sampler["laplace"]))
        {
            var l = D(x);
            var d = ReadVault.SeededDraws(Str(l["seed"]));
            var got = new List<long>();
            for (var i = 0; i < L(l["values"]).Count; i++) got.Add(ReadVault.DiscreteLaplace(d, N(l["s"]), N(l["t"])));
            Assert.Equal(L(l["values"]).Select(v => N(v)).ToList(), got);
        }
        foreach (var x in L(V["vault"]))
        {
            var c = D(x); var r = D(c["redact"]); var dt = D(c["detok"]);
            var store = new MemoryVault();
            var red = ReadVault.RedactReadWithVault(new(vg[Str(c["redact_grant"])], r["principal"], r["now"], r["verb"], r["resource"], r["purpose"], r["schema"], r["record"], r["tighten"], r["salt"], r["counts"]), store);
            var token = c.GetValueOrDefault("token") ?? (c.GetValueOrDefault("field") is string f ? red.View.GetValueOrDefault(f) : null);
            var got = ReadVault.Detokenize(new(vg[Str(c["detok_grant"])], dt["principal"], dt["now"], dt["sink"], token, store));
            Same(got.ToJson(), c["expect"], $"vault: {c["name"]}");
        }
        foreach (var x in L(V["aggregate"]))
        {
            var c = D(x);
            object? state = c["initial_state"];
            foreach (var so in L(c["steps"]))
            {
                var s = D(so); var inp = D(s["input"]);
                object? G(string k, object? dflt) => inp.TryGetValue(k, out var v) ? v : dflt;
                var values = new List<object?> { new Num("10"), new Num("20"), new Num("500"), new Num("-900") };
                var r = ReadVault.AggregateRead(new(ag[inp.TryGetValue("grant", out var gn) ? Str(gn) : "main"], G("principal", keys["principal"]), G("now", new Num("1800000000000")), G("verb", "orders.stats"),
                    G("resource", "orders/eu"), G("purpose", "analytics"), G("fn", "sum"), G("values", values), G("salt", "a-per-read-secret-salt"), G("noise", "seeded"), state));
                Same(r.ToJson(), s["expect"], $"aggregate: {c["name"]}");
                state = r.State;
            }
        }
        // hostile input never throws: a bad state is the one refusal that returns the EMPTY state
        var bad = ReadVault.AggregateRead(new(ag["main"], keys["principal"], new Num("1800000000000"), "orders.stats", "orders/eu", "analytics", "sum", new List<object?>(), "a-per-read-secret-salt", "seeded", "x"));
        Assert.Equal(("deny", "bad_request"), (bad.Decision, bad.Code));
        Assert.Equal(Pca.Canonicalize(ReadVault.EmptyAggregateState()), Pca.Canonicalize(bad.State));
        Assert.Equal("bad_request", ReadVault.Detokenize(new(null, null, null, null, null, new MemoryVault())).Code);
    }

    [Fact]
    public void SecureNoiseIsFreshPerCall()
    {
        // the production setting draws a fresh OS-CSPRNG seed per call: only that two calls differ is pinned (never the values)
        List<long> Take() { var d = ReadVault.SecureDraws(); var o = new List<long>(); for (var i = 0; i < 8; i++) o.Add(d.Uniform(1L << 47)); return o; }
        Assert.NotEqual(Take(), Take());
        var V = Load("vault-aggregate-vectors.json");
        var inp = new AggregateInput(D(D(V["grants"])["aggregate"])["main"], D(V["keys"])["principal"], new Num("1800000000000"), "orders.stats", "orders/eu", "analytics", "count",
            new List<object?> { new Num("1"), new Num("2"), new Num("3") }, "a-per-read-secret-salt", "secure", ReadVault.EmptyAggregateState());
        var r = ReadVault.AggregateRead(inp);
        Assert.Equal("allow", r.Decision);
        Assert.Equal(500000L, r.ChargedMicro);
    }
}
