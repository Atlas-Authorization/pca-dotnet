using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The prohibition plane (constitution and monitor sections of prohibition-vectors.json) and temporal contracts (contracts-vectors.json): every row replayed.
public class K05ContractsTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();
    static JD? Act(object? o) => o as JD;

    static void SameEval(string name, IReadOnlyList<InvariantEval> got, object? want)
    {
        var w = L(want).Select(D).ToList();
        Assert.True(got.Count == w.Count, $"{name}: evaluated count {got.Count} vs {w.Count}");
        for (int i = 0; i < w.Count; i++)
        {
            Assert.True(got[i].Id == (string)w[i]["id"]! && got[i].Kind == (string)w[i]["kind"]! && got[i].Result == (string)w[i]["result"]!, $"{name}: row {i} {got[i]}");
            Assert.True(got[i].Reason == (w[i].TryGetValue("reason", out var r) ? (string?)r : null), $"{name}: row {i} reason {got[i].Reason}");
        }
    }

    [Fact]
    public void ConstitutionsAreValidatedAndCheckedInVetoPolarity()
    {
        var cases = L(Load("prohibition-vectors.json")["constitution"]);
        Assert.Equal(33, cases.Count);
        foreach (var x in cases)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            Assert.True(Prohibitions.ValidateConstitution(c["constitution"]).SequenceEqual(Strs(e["problems"])), $"{name}: problems [{string.Join("; ", Prohibitions.ValidateConstitution(c["constitution"]))}]");
            var r = Prohibitions.Check(Act(c["action"]), c["constitution"], c["state"]);
            var w = D(e["result"]);
            Assert.True(r.Ok == (bool)w["ok"]!, $"{name}: ok");
            Assert.True(r.Violated.SequenceEqual(Strs(w["violated"])), $"{name}: violated [{string.Join(",", r.Violated)}]");
            Assert.True(r.Reasons.SequenceEqual(Strs(w["reasons"])), $"{name}: reasons [{string.Join(",", r.Reasons)}]");
            SameEval(name, r.Evaluated, w["evaluated"]);
        }
    }

    [Fact]
    public void MonitorScenariosAdvanceTheStateLikeTheReference()
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
                if (s.TryGetValue("now", out var nowv))
                {
                    var t = Prohibitions.Tick(st, N(nowv));
                    if (!t.Ok)
                    {
                        Assert.True((string)e["decidedBy"]! == "clock" && t.Reason == (string)e["reason"]!, $"{name}: tick {t.Reason}");
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
            var c = D(x); var name = (string)c["name"]!;
            var got = Contracts.Validate(c["contract"]);
            Assert.True(got.SequenceEqual(Strs(D(c["expect"])["problems"])), $"{name}: [{string.Join("; ", got)}]");
        }
        var check = L(doc["check"]);
        Assert.Equal(11, check.Count);
        foreach (var x in check)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var r = Contracts.Check(Act(c["action"]), c["contract"], c["state"]);
            Assert.True(r.Ok == (bool)e["ok"]!, $"{name}: ok");
            Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"{name}: violated/reasons [{string.Join(",", r.Reasons)}]");
            SameEval(name, r.Evaluated, e["evaluated"]);
        }
        var advance = L(doc["advance"]);
        Assert.Equal(7, advance.Count);
        foreach (var x in advance)
        {
            var c = D(x); var name = (string)c["name"]!;
            var st = Prohibitions.EmptyState(N(c["genesis_now"]));
            foreach (var sx in L(c["steps"]))
            {
                var s = D(sx); var e = D(s["expect"]);
                long? expSeq = null; string? expDigest = null; double? now = null;
                if (s.TryGetValue("options", out var ov))
                {
                    var o = D(ov);
                    if (o.TryGetValue("now", out var nv)) now = N(nv);
                    if (o.TryGetValue("expectedSeq", out var sv)) expSeq = N(sv);
                    if (o.TryGetValue("stale_digest_of_genesis", out var gv) && gv is true) expDigest = Prohibitions.StateDigest(Prohibitions.EmptyState(N(c["genesis_now"])));
                }
                var r = Contracts.Advance(st, Act(s["action"]), c["contract"], expSeq, expDigest, now);
                Assert.True(r.Ok == (bool)e["ok"]!, $"{name}: ok {r.Ok} [{string.Join(",", r.Reasons)}]");
                Assert.True(r.DecidedBy == (string)e["decidedBy"]!, $"{name}: decidedBy {r.DecidedBy}");
                Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"{name}: violated/reasons");
                Assert.True((long)IntentJs.NumOf(r.Next["seq"])!.Value == N(e["seq"]), $"{name}: seq");
                Assert.Equal(Pca.Canonicalize(e["deadlines"]), Pca.Canonicalize(r.Next.GetValueOrDefault("deadlines") ?? new JD()));
                Assert.True(((JD)r.Next["latched"]!).Keys.OrderBy(k => k, StringComparer.Ordinal).SequenceEqual(Strs(e["latched"])), $"{name}: latched");
                Assert.True(Prohibitions.StateDigest(r.Next) == (string)e["state_digest"]!, $"{name}: state digest");
                if (r.Ok) st = r.Next;
            }
        }
    }

    [Fact]
    public void ContractSignaturesAreVerifiedUnderThePinnedPrincipal()
    {
        var verify = L(Load("contracts-vectors.json")["verify"]);
        Assert.Equal(7, verify.Count);
        foreach (var x in verify)
        {
            var c = D(x); var name = (string)c["name"]!; var e = D(c["expect"]);
            var got = Contracts.Verify(c["contract"], c.TryGetValue("principal", out var p) ? (string?)p : null);
            Assert.True(got.Ok == (bool)e["ok"]!, $"{name}: ok {got.Reason}");
            Assert.True(got.Reason == (e.TryGetValue("reason", out var r) ? (string?)r : null), $"{name}: reason {got.Reason}");
        }
    }

    [Fact]
    public void TheEnforcerAdmitsLatchesPeeksAndResets()
    {
        var all = L(Load("contracts-vectors.json")["enforcer"]);
        Assert.Equal(9, all.Count);
        var head = D(all[0]);
        var contract = D(head["contract"]); var principal = (string)head["principal"]!;
        foreach (var x in all.Skip(1))
        {
            var sc = D(x); var name = (string)sc["name"]!;
            var kv = new MemoryAtomicKv();
            double wall = N(head["clock"]);
            var latch = !(sc.TryGetValue("options", out var op) && D(op).TryGetValue("latchOnViolation", out var lv) && lv is false);
            var enf = ContractEnforcer.Open(kv, contract, principal, now: () => wall, latchOnViolation: latch);
            if (sc.TryGetValue("stored_document", out var sd)) kv.Update($"contract/{contract["id"]}", _ => Pca.Canonicalize(sd));
            foreach (var sx in L(sc["steps"]))
            {
                var s = D(sx); var e = D(s["expect"]); var opn = (string)s["op"]!;
                if (opn == "check")
                {
                    wall = s.TryGetValue("wall", out var w) ? N(w) : N(head["clock"]);
                    var r = enf.Check(Act(s["action"]), !s.TryGetValue("permitted", out var pm) || pm is not false);
                    Assert.True(r.Allow == (bool)e["allow"]! && r.Reason == (string)e["reason"]! && r.Seq == N(e["seq"]), $"{name}: check {r}");
                    Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"{name}: check lists");
                }
                else if (opn == "peek")
                {
                    var r = enf.Peek(Act(s["action"]));
                    Assert.True(r.Allow == (bool)e["allow"]! && r.Reason == (string)e["reason"]! && r.Seq == N(e["seq"]), $"{name}: peek {r}");
                    Assert.True(r.Violated.SequenceEqual(Strs(e["violated"])) && r.Reasons.SequenceEqual(Strs(e["reasons"])), $"{name}: peek lists");
                }
                else if (opn == "state")
                {
                    var st = enf.State();
                    if (e == null) Assert.Null(st);
                    else
                    {
                        Assert.NotNull(st);
                        Assert.True((long)IntentJs.NumOf(st!.Value.State["seq"])!.Value == N(e["seq"]) && st.Value.Latched == (bool)e["latched"]! && Prohibitions.StateDigest(st.Value.State) == (string)e["state_digest"]!, $"{name}: state");
                    }
                }
                else Assert.True(enf.Reset((string)s["sig"]!) == (bool)e["cleared"]!, $"{name}: reset");
            }
        }
    }
}
