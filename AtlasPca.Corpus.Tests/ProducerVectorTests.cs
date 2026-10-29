using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Replays producer-vectors.json: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519 is deterministic).
public class ProducerVectorTests
{
    static readonly JD Doc = Load("producer-vectors.json");

    static EdKey Key(object? name) => EdKey.FromSeed(Pca.B64uDecode(D(D(Doc["keys"])[(string)name!])["seed"], 32)!);
    static SuiteKey Suite(object? name) => SuiteKey.Ed25519(Key(name));
    static string Canon(object? o) => Pca.Canonicalize(o);
    static List<JD> Nodes(object? o) => L(o).Select(D).ToList();

    static object? Run(string op, JD a)
    {
        switch (op)
        {
            case "ed25519_sign":
                {
                    var k = EdKey.FromSeed(Pca.B64uDecode(a["seed"], 32)!);
                    return new JD { ["public"] = k.Id, ["sig"] = Pca.B64u(k.Sign(Encoding.UTF8.GetBytes((string)a["message_utf8"]!))) };
                }
            case "goal_commit": return new JD { ["commit"] = Issue.GoalCommit((string)a["goal"]!, (string)a["salt"]!) };
            case "params_digest": return new JD { ["digest"] = Pca.ParamsDigest(a["params"]) };
            case "plan_commit":
                {
                    var nodes = Nodes(a["nodes"]);
                    var p = Issue.CommitPlan(nodes);
                    var proofs = new JD();
                    foreach (var n in nodes) proofs[(string)n["id"]!] = p.ProofFor((string)n["id"]!);
                    return new JD { ["root"] = p.Root, ["proofs"] = proofs };
                }
            case "mint_grant":
                {
                    var g = Issue.MintGrant(Suite(a["principal"]), Key(a["holder"]).Id, null, D(a["envelope"]), (string)a["goal"]!, (string)a["salt"]!);
                    return new JD { ["grant"] = g.Grant, ["goal_commit"] = g.GoalCommit, ["goal_salt"] = g.GoalSalt };
                }
            case "delegate":
                {
                    var parent = D(a["parent"]);
                    var to = a["to_holder"] == null ? (string)parent["holder"]! : Key(a["to_holder"]).Id;
                    return Issue.Delegate(parent, to, L(a["added_caveats"]), Suite(a["signer"]));
                }
            case "act":
                {
                    var s = new ActSpec
                    {
                        Grant = D(a["grant"]), Chain = L(a["chain"]), Plan = Issue.CommitPlan(Nodes(a["plan"])), NodeId = (string)a["node_id"]!,
                        Params = a.ContainsKey("params") ? D(a["params"]) : null, Counter = N(a["counter"]), Signer = Suite(a["signer"]), Aud = (string)a["aud"]!,
                        Iat = N(a["iat"]), Exp = N(a["exp"]), Nonce = a.GetValueOrDefault("nonce") as string, Caution = a.GetValueOrDefault("caution"),
                        RationaleCommitment = a.GetValueOrDefault("rationale_commitment") as string, ToolBinding = a.GetValueOrDefault("tool_binding") as string,
                        FreshAt = a.ContainsKey("fresh_at") ? D(a["fresh_at"]) : null,
                    };
                    var p = Issue.BuildPCActn(s);
                    return new JD { ["pcactn"] = p, ["threshold_message"] = Pca.B64u(Pca.ThresholdMessage(p)), ["header"] = Issue.Header(p) };
                }
            case "fresh_at": return Issue.SignFreshAt(Key(a["signer"]), (string)a["scope"]!, D(a["state"]), N(a["issued_at"]));
            case "escalation_digests":
                return new JD
                {
                    ["policy_digest"] = Escalation.PolicyDigest(D(a["grant"])), ["action_digest"] = Escalation.ActionDigest(D(a["pcactn"])),
                    ["history_head"] = Escalation.HistoryHead(a["last_counter"] == null ? null : N(a["last_counter"])),
                };
            case "sign_escalation_answer": return Issue.SignEscalationAnswer(D(a["body"]), Suite(a["signer"]));
            case "sign_discharge": return Issue.SignDischarge(D(a["body"]), Suite(a["signer"]));
            case "discharge_digest": return new JD { ["digest"] = CaveatLang.DischargeDigest(a["discharge"]) };
            case "sign_narrow": return Issue.SignNarrow(D(a["body"]), Suite(a["signer"]));
            case "sign_passport":
                {
                    var pp = Issue.IssuePassport(D(a["identity"]));
                    var signed = Issue.SignPassport(pp, Suite(a["issuer"]), Key(a["subject"]).Id, N(D(a["identity"])["issued_at"]), N(a["exp"]));
                    return new JD { ["passport"] = pp, ["signed"] = signed };
                }
            case "sign_workflow": return Issue.SignWorkflow(Key(a["signer"]), D(a["body"]));
            case "sign_step_receipt":
                return Issue.SignStepReceipt(Key(a["signer"]), D(a["workflow"]), (string)a["step"]!, (string)a["outcome"]!, (string)a["params_digest"]!, D(a["outputs"]), N(a["issued_at"]), a["prev"] == null ? null : D(a["prev"]));
            case "sign_read_grant": return Issue.SignReadGrant(Key(a["signer"]), D(a["body"]));
            case "sign_aggregate_grant": return Issue.SignAggregateGrant(Key(a["signer"]), D(a["body"]));
            default: throw new InvalidOperationException("unknown op " + op);
        }
    }

    [Fact]
    public void EveryCaseIsReproducedByteForByte()
    {
        var cases = L(Doc["cases"]);
        Assert.True(cases.Count >= 30, $"the corpus shrank: {cases.Count}");
        foreach (var c in cases)
        {
            var v = D(c);
            Assert.True(Canon(v["expect"]) == Canon(Run((string)v["op"]!, D(v["args"]))), (string)v["name"]!);
        }
    }

    // Cross-verification: the TS-produced PCActns pass THIS SDK's verifier.
    [Fact]
    public void ReferenceActionsVerify()
    {
        var n = 0;
        foreach (var c in L(Doc["cases"]))
        {
            var v = D(c);
            var a = D(v["args"]);
            if ((string)v["op"]! != "act" || a.ContainsKey("fresh_at")) continue; // fresh_at is refused without a fresh_at policy (fail closed)
            var d = Pca.VerifyPcactnCore(D(D(v["expect"])["pcactn"]), D(a["grant"]), N(a["iat"]) + 1000, (string)a["aud"]!);
            Assert.True(d.Allow, $"{v["name"]}: {d.Reason}");
            n++;
        }
        Assert.True(n >= 4);
    }
}
