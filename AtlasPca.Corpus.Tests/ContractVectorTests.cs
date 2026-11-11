using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The prohibition plane (constitution, monitor) and the temporal contracts: packages/pca/conformance/{prohibition,contracts}-vectors.json.
public class ContractVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();
    static JD? Act(object? o) => o as JD;

    static void SameEvaluated(string name, IReadOnlyList<InvariantEval> got, object? want)
    {
        var w = L(want).Select(D).ToList();
        Assert.True(got.Count == w.Count, $"{name}: evaluated count");
        for (int i = 0; i < w.Count; i++)
            Assert.True(got[i].Id == (string)w[i]["id"]! && got[i].Kind == (string)w[i]["kind"]! && got[i].Result == (string)w[i]["result"]! && got[i].Reason == (w[i].TryGetValue("reason", out var r) ? (string?)r : null), $"{name}: evaluated {i}");
    }

    [Fact]
    public void ConstitutionsAreValidatedAndCheckedInVetoPolarity()
    {
        var cases = L(Load("prohibition-vectors.json")["constitution"]);
        Assert.Equal(33, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            Assert.True(Prohibitions.ValidateConstitution(c["constitution"]).SequenceEqual(Strs(e["problems"])), $"{name}: problems");
            var r = Prohibitions.Check(Act(c["action"]), c["constitution"], c["state"]);
            var want = D(e["result"]);
            Assert.True(r.Ok == (bool)want["ok"]!, $"{name}: ok");
            Assert.True(r.Violated.SequenceEqual(Strs(want["violated"])), $"{name}: violated {string.Join(",", r.Violated)}");
            Assert.True(r.Reasons.SequenceEqual(Strs(want["reasons"])), $"{name}: reasons {string.Join("|", r.Reasons)}");
            SameEvaluated(name, r.Evaluated, want["evaluated"]);
        }
    }

    [Fact]
    public void SignedSafetyEvidenceVerifiesLikeTheReference()
    {
        var cases = L(Load("prohibition-vectors.json")["evidence"]);
        Assert.Equal(13, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var got = SafetyEvidence.VerifySigned(c["signed"], c["expected"]);
            Assert.True(got.Ok == (bool)e["ok"]!, $"{name}: ok {got.Ok} {got.Reason}");
            Assert.True(got.Reason == (e.TryGetValue("reason", out var r) ? (string?)r : null), $"{name}: reason '{got.Reason}'");
        }
    }

    [Fact]
    public void MonitorSequencesAdvanceLikeTheReference()
    {
        var cases = L(Load("prohibition-vectors.json")["monitor"]);
        Assert.Equal(5, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!;
            var st = Prohibitions.EmptyState(N(c["genesis_now"]));
            foreach (var sx in L(c["steps"]))
            {
                var s = D(sx); var e = D(s["expect"]);
                var cur = st;
                if (s.TryGetValue("now", out var now))
                {
                    var t = Prohibitions.Tick(st, N(now));
                    if (!t.Ok)
                    {
                        Assert.True(!(bool)e["allow"]! && (string)e["decidedBy"]! == "clock" && t.Reason == (string)e["reason"]!, $"{name}: clock {t.Reason}");
                        continue;
                    }
                    cur = t.State!;
                }
                var r = Prohibitions.CheckAndAdvance(true, Act(s["action"]), c["constitution"], cur);
                Assert.True(r.Allow == (bool)e["allow"]!, $"{name}: allow {r.Allow} {r.Reason}");
                Assert.True(r.DecidedBy == (string)e["decidedBy"]!, $"{name}: decidedBy {r.DecidedBy}");
                Assert.True(r.Prohibition.Violated.SequenceEqual(Strs(e["violated"])), $"{name}: violated");
                Assert.True((long)IntentJs.NumOf(r.Next!["seq"])!.Value == N(e["seq"]), $"{name}: seq");
                st = r.Allow ? r.Next! : cur;
            }
        }
    }

    [Fact]
    public void ContractsValidateCheckAndAdvanceLikeTheReference()
    {
        var doc = Load("contracts-vectors.json");
        var validate = L(doc["validate"]);
        Assert.Equal(21, validate.Count);
        foreach (var x in validate)
        {
            var c = D(x);
            Assert.True(Contracts.Validate(c["contract"]).SequenceEqual(Strs(D(c["expect"])["problems"])), $"validate {c["name"]}");
        }
        foreach (var x in L(doc["check"]))
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var r = Contracts.Check(Act(c["action"]), c["contract"], c["state"]);
            Assert.True(r.Ok == (bool)e["ok"]!, $"check {name}: ok");
            Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"check {name}: violated/reasons");
            SameEvaluated("check " + name, r.Evaluated, e["evaluated"]);
        }
        foreach (var x in L(doc["advance"]))
        {
            var c = D(x); var name = (string)c["name"]!;
            var st = Prohibitions.EmptyState(N(c["genesis_now"]));
            var genesisDigest = Prohibitions.StateDigest(st);
            foreach (var sx in L(c["steps"]))
            {
                var s = D(sx); var e = D(s["expect"]);
                var o = s.TryGetValue("options", out var ov) ? D(ov) : new JD();
                var r = Contracts.Advance(st, Act(s["action"]), c["contract"], o.TryGetValue("expectedSeq", out var es) ? N(es) : null, o.ContainsKey("stale_digest_of_genesis") ? genesisDigest : null, o.TryGetValue("now", out var nw) ? N(nw) : null);
                Assert.True(r.Ok == (bool)e["ok"]! && r.DecidedBy == (string)e["decidedBy"]!, $"advance {name}: {r.Ok} {r.DecidedBy}");
                Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"advance {name}: violated/reasons {string.Join("|", r.Reasons)}");
                Assert.True((long)IntentJs.NumOf(r.Next["seq"])!.Value == N(e["seq"]), $"advance {name}: seq");
                var dl = r.Next.GetValueOrDefault("deadlines") as JD ?? new JD();
                Assert.True(Pca.Canonicalize(dl) == Pca.Canonicalize(e["deadlines"]), $"advance {name}: deadlines");
                Assert.True(((JD)r.Next["latched"]!).Keys.OrderBy(k => k, StringComparer.Ordinal).SequenceEqual(Strs(e["latched"])), $"advance {name}: latched");
                Assert.True(Prohibitions.StateDigest(r.Next) == (string)e["state_digest"]!, $"advance {name}: digest");
                if (r.Ok) st = r.Next;
            }
        }
        foreach (var x in L(doc["verify"]))
        {
            var c = D(x); var e = D(c["expect"]);
            var r = Contracts.Verify(c["contract"], c.TryGetValue("principal", out var p) ? (string?)p : null);
            Assert.True(r.Ok == (bool)e["ok"]! && r.Reason == (e.TryGetValue("reason", out var rs) ? (string?)rs : null), $"verify {c["name"]}: {r.Reason}");
        }
    }

    [Fact]
    public void TheEnforcerDecidesOverADurableStore()
    {
        var all = L(Load("contracts-vectors.json")["enforcer"]);
        var head = D(all[0]);
        var contract = D(head["contract"]); var principal = (string)head["principal"]!; double clock = N(head["clock"]);
        foreach (var sx in all.Skip(1))
        {
            var s = D(sx); var name = (string)s["name"]!;
            var kv = new MemoryAtomicKv();
            double wall = clock;
            var latch = !(s.TryGetValue("options", out var op) && D(op).TryGetValue("latchOnViolation", out var lv) && lv is false);
            var enf = ContractEnforcer.Open(kv, contract, principal, null, () => wall, latch);
            if (s.TryGetValue("stored_document", out var sd)) kv.Update($"contract/{(string)contract["id"]!}", _ => Pca.Canonicalize(sd));
            foreach (var stx in L(s["steps"]))
            {
                var st = D(stx); var e = st["expect"];
                switch ((string)st["op"]!)
                {
                    case "check":
                        {
                            wall = st.TryGetValue("wall", out var w) ? N(w) : clock;
                            var r = enf.Check(Act(st["action"]), !st.TryGetValue("permitted", out var pm) || pm is not false);
                            var ee = D(e);
                            Assert.True(r.Allow == (bool)ee["allow"]! && r.Reason == (string)ee["reason"]! && r.Seq == N(ee["seq"]), $"{name}: check {r.Allow} {r.Reason} {r.Seq}");
                            Assert.True(r.Violated.SequenceEqual(Strs(ee["violated"])) && r.Reasons.SequenceEqual(Strs(ee["reasons"])), $"{name}: check reasons {string.Join("|", r.Reasons)}");
                            break;
                        }
                    case "peek":
                        {
                            var r = enf.Peek(Act(st["action"])); var ee = D(e);
                            Assert.True(r.Allow == (bool)ee["allow"]! && r.Reason == (string)ee["reason"]! && r.Seq == N(ee["seq"]) && r.Violated.SequenceEqual(Strs(ee["violated"])) && r.Reasons.SequenceEqual(Strs(ee["reasons"])), $"{name}: peek {r.Reason}");
                            break;
                        }
                    case "state":
                        {
                            var r = enf.State();
                            if (e == null) { Assert.Null(r); break; }
                            var ee = D(e);
                            Assert.True(r != null && (long)IntentJs.NumOf(r.Value.State["seq"])!.Value == N(ee["seq"]) && N(r.Value.State["now"]) == N(ee["now"]) && r.Value.Latched == (bool)ee["latched"]! && Prohibitions.StateDigest(r.Value.State) == (string)ee["state_digest"]!, $"{name}: state");
                            break;
                        }
                    default:
                        Assert.True(enf.Reset((string)st["sig"]!) == (bool)D(e)["cleared"]!, $"{name}: reset");
                        break;
                }
            }
        }
    }
}
