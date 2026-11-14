using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The reverse direction: this SDK's own post-quantum and agent-side output, checked here and (PCA_PRODUCER_OUT set, in CI) written
// for the reference implementation to verify. Randomised keys cannot be byte vectors, so the reference checks them instead.
public class ProducerNativeOutputTests
{
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_producer_test";

    static JD Envelope() => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } },
        ["caveats"] = new JL(),
        ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static void Verifies(JD pcactn, JD grant, string what)
    {
        var v = Pca.VerifyRaw(Issue.Encode(pcactn), Issue.NormJ(grant), Now, Aud, planRoots: PlanRootPolicy.Skip);
        Assert.True(v.Allow, $"{what}: {v.Reason}");
    }

    /// <summary>A fresh copy of the args of the first non-refusal producer vector of <paramref name="op"/>.</summary>
    static JD VectorArgs(string op)
    {
        foreach (var c in L(Load("producer-vectors.json")["cases"]))
        {
            var v = D(c);
            if ((string)v["op"]! == op && !D(v["expect"]).ContainsKey("error")) return D(v["args"]);
        }
        throw new InvalidOperationException("no vector for " + op);
    }

    static JD Pin(EdKey k, params (string K, object? V)[] more)
    {
        var p = new JD { ["pk"] = k.Id };
        foreach (var (key, val) in more) p[key] = val;
        return p;
    }

    static JD Artifact(string kind, string alg, JD artifact, JD pins) => new() { ["kind"] = kind, ["alg"] = alg, ["artifact"] = artifact, ["pins"] = pins };

    /// <summary>One of each artifact kind the reference checks, over the vector bodies (their times bracket the file's now) re-pointed at
    /// fresh keys: the escalation answer and the revocation epoch under a hybrid suite, the rest Ed25519.</summary>
    static IEnumerable<object?> NativeArtifacts()
    {
        const string alg = "hybrid-ed25519-ml-dsa-65";
        var pq = PqKey.Generate(Pq.Prim.MlDsa65);

        var k = EdKey.Generate();
        var b = D(VectorArgs("sign_escalation_answer")["body"]);
        b["principal"] = k.Id;
        yield return Artifact("escalation_answer", alg, Issue.SignEscalationAnswer(b, SuiteKey.Create(alg, k, pq)), Pin(k, ("pq_pk", pq.PkB64u)));

        k = EdKey.Generate();
        b = D(VectorArgs("sign_revocation_epoch")["body"]);
        var epoch = new RevocationEpochBody((string)b["instance_id"]!, (string)b["grant_ref"]!, N(b["epoch"]), N(b["set_size"]), (string)b["root"]!, N(b["issued_at"]), N(b["not_after"]));
        yield return Artifact("revocation_epoch", alg, RevocationFreshness.SignEpoch(epoch, SuiteKey.Create(alg, k, pq)), Pin(k, ("pq_pk", pq.PkB64u)));

        k = EdKey.Generate();
        b = D(VectorArgs("sign_session_root")["body"]);
        b["principals"] = new JL { new JD { ["key"] = k.Id } };
        yield return Artifact("session_root", "ed25519", Signers.SignSessionRoot(b, SuiteKey.Ed25519(k)), Pin(k));

        k = EdKey.Generate();
        var a = VectorArgs("sign_action_schema");
        yield return Artifact("action_schema", "ed25519", Signers.SignActionSchema(D(a["doc"]), (string)a["kid"]!, SuiteKey.Ed25519(k)),
            Pin(k, ("kid", a["kid"]), ("alg", "ed25519")));

        k = EdKey.Generate();
        b = D(VectorArgs("sign_labels")["body"]);
        yield return Artifact("labels", "ed25519", Signers.SignLabels(b, SuiteKey.Ed25519(k)),
            Pin(k, ("kid", b.GetValueOrDefault("kid") as string ?? ""), ("site", b.GetValueOrDefault("site") as string ?? "")));

        k = EdKey.Generate();
        a = VectorArgs("sign_intent_required");
        yield return Artifact("intent_required", "ed25519", Signers.SignIntentRequired(D(a["body"]), (string)a["kid"]!, SuiteKey.Ed25519(k)),
            Pin(k, ("kid", a["kid"]), ("alg", "ed25519")));

        k = EdKey.Generate();
        yield return Artifact("fact", "ed25519", Signers.SignFact(D(VectorArgs("sign_fact")["body"]), SuiteKey.Ed25519(k)), Pin(k));

        k = EdKey.Generate();
        b = D(VectorArgs("sign_caution")["body"]);
        b["holder"] = k.Id;
        yield return Artifact("caution", "ed25519", Signers.SignCaution(b, k), Pin(k));

        k = EdKey.Generate();
        yield return Artifact("pq_binding", "ed25519", Signers.SignPqBinding(k, pq.PkB64u, 1, Aud), Pin(k));
    }

    // One PCActn per suite this SDK signs, a post-quantum sub-agent's PCActn (two suites), a facade act with params, and the artifacts.
    [Fact]
    public void EveryNativeOutputVerifiesAndIsWritten()
    {
        var cases = new JL();
        var suites = new (string Alg, Pq.Prim Prim)[]
        {
            ("ml-dsa-65", Pq.Prim.MlDsa65), ("hybrid-ed25519-ml-dsa-65", Pq.Prim.MlDsa65), ("hybrid-nested-ed25519-ml-dsa-65", Pq.Prim.MlDsa65),
            ("ml-dsa-87", Pq.Prim.MlDsa87), ("hybrid-ed25519-ml-dsa-87", Pq.Prim.MlDsa87), ("slh-dsa-sha2-128f", Pq.Prim.Slh128f),
            ("hybrid-ed25519-slh-dsa-sha2-128f", Pq.Prim.Slh128f), ("slh-dsa-sha2-256s", Pq.Prim.Slh256s), ("hybrid-ed25519-slh-dsa-sha2-256s", Pq.Prim.Slh256s),
        };
        foreach (var (alg, prim) in suites)
        {
            var principal = SuiteKey.Ed25519(EdKey.Generate());
            var ed = EdKey.Generate();
            var pq = PqKey.Generate(prim);
            var me = SuiteKey.Create(alg, ed, pq);
            var g = Issue.MintGrant(principal, ed.Id, pq.PkB64u, Envelope(), "refund");
            var agent = new Agent(me, Aud, g.Grant) { Clock = () => Now };
            var p = agent.Act("refund", "orders/1", new JD { ["amount"] = 5L });
            Assert.Equal(alg, p["alg"]);
            Verifies(p, g.Grant, alg);
            cases.Add(new JD { ["kind"] = "pcactn", ["alg"] = alg, ["grant"] = Issue.Norm(g.Grant), ["pcactn"] = Issue.Norm(p) });
            if (alg is "hybrid-ed25519-ml-dsa-65" or "slh-dsa-sha2-128f")
            {
                var child = agent.Delegate(SuiteKey.Create(alg, EdKey.Generate(), PqKey.Generate(prim)), new JL { new JD { ["type"] = "sealed" } });
                var sp = child.Act("refund", "orders/1", new JD { ["amount"] = 5L });
                Assert.NotEqual(p["pq_pk"], sp["pq_pk"]);
                Verifies(sp, g.Grant, alg + " sub-agent");
                cases.Add(new JD { ["kind"] = "pcactn", ["alg"] = alg + " (sub-agent)", ["grant"] = Issue.Norm(g.Grant), ["pcactn"] = Issue.Norm(sp) });
            }
        }
        var fa = Agent.FromPrincipal(new AgentOptions
        {
            Principal = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund", Permissions = new JD { ["stripe"] = new JL { "refund" } },
            Limits = new Dictionary<string, string> { ["refund"] = "$500" }, Aud = Aud, Now = Now,
        });
        var r = fa.Act("stripe.refund", "charge:ch_1", new JD { ["amount"] = 42L, ["currency"] = "usd" }, new ActOptions { Now = Now });
        Verifies(r.PCActn, fa.Grant, "facade act");
        cases.Add(new JD { ["kind"] = "pcactn", ["alg"] = "ed25519 (facade act)", ["grant"] = Issue.Norm(fa.Grant), ["pcactn"] = Issue.Norm(r.PCActn) });
        foreach (var x in NativeArtifacts()) cases.Add(Issue.Norm(x));
        Assert.Equal(9 + 2 + 1 + 9, cases.Count);

        var outPath = Environment.GetEnvironmentVariable("PCA_PRODUCER_OUT");
        if (string.IsNullOrEmpty(outPath)) return;
        File.WriteAllText(outPath, Pca.Canonicalize(new JD { ["lang"] = "dotnet", ["aud"] = Aud, ["now"] = Now, ["cases"] = cases }) + "\n");
    }
}
