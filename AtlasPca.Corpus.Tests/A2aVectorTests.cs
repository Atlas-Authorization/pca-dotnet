using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// The A2A binding, replaying packages/pca/conformance/a2a-vectors.json (decided by the TypeScript reference).
public class A2aVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("a2a-vectors.json");
        Assert.True(L(doc["need"]).Count >= 20);
        foreach (var x in L(doc["need"]))
        {
            var c = D(x);
            var input = c["input"] is Num n ? n.Raw : c["input"];
            var (need, code) = A2a.DecodeNeed(input);
            var e = D(c["expect"]);
            Assert.True((bool)e["ok"]! == (code == null), $"{c["name"]}: {code}");
            if (code == null) Assert.True(A2a.NeedDigest(need!) == (string)e["digest"]!, $"{c["name"]}: digest");
            else Assert.True(code == (string)e["code"]!, $"{c["name"]}: code {code}");
        }
        var push = D(doc["push"]);
        foreach (var x in L(push["tokens"])) { var t = D(x); Assert.Equal((string)t["token"]!, A2a.PushToken((string)t["task_id"]!, Strs(t["chain_ids"]), t["salt"])); }
        foreach (var s in L(push["weak_salts"])) Assert.Null(A2a.PushToken("t", new[] { "a" }, s));
        foreach (var x in L(push["checks"]))
        {
            var c = D(x); var e = D(c["expected"]); var d = D(c["delivered"]); var exp = D(c["expect"]);
            var got = A2a.CheckPush((string)e["task_id"]!, Strs(e["chain_ids"]), (string)e["salt"]!, d["token"], d["payload"]);
            Assert.True((got == null) == (bool)exp["ok"]! && (got == null || got == (string)exp["reason"]!), $"push {c["name"]}: {got}");
        }
        foreach (var x in L(doc["chains"]))
        {
            var c = D(x); var exp = D(c["expect"]);
            var got = A2a.CheckChainExtension(L(c["chains"]).Select(l => (IReadOnlyList<string>)Strs(l)).ToList());
            Assert.True(got.Ok == (bool)exp["ok"]! && (got.Ok || (got.Reason == (string)exp["reason"]! && got.FailedHop == N(exp["failedHop"]))), $"chains {c["name"]}");
        }
        foreach (var x in L(doc["resume"]))
        {
            var c = D(x);
            var got = A2a.ResumeGate(c["state"], c["need_encoded"], c["answer_need_digest"], c["proof_action"]);
            Assert.True(got == c["expect"] as string, $"resume {c["name"]}: {got}");
        }
        var R = D(doc["receipts"]);
        var signer = (string)R["signer"]!; var recs = L(R["records"]);
        foreach (var v in L(R["verify"])) { var m = D(v); Assert.True(A2a.VerifyReceipt(recs[(int)N(m["record"])], signer) == (bool)m["ok"]!, $"verify {N(m["record"])}"); }
        foreach (var d in L(R["digests"])) { var m = D(d); Assert.Equal((string)m["digest"]!, A2a.ReceiptDigest(recs[(int)N(m["record"])])); }
        foreach (var x in L(R["scenarios"]))
        {
            var s = D(x); var exp = D(s["expect"]);
            var list = L(s["indices"]).Select(i => recs[(int)N(i)]).ToList();
            var got = A2a.CheckReceiptChain(list, signer, (string)s["task_id"]!, Strs(s["chain_ids"]));
            var name = (string)s["name"]!;
            Assert.True(got.Ok == (bool)exp["ok"]!, $"{name}: {got}");
            if (got.Ok) Assert.True(got.Terminal == (bool)exp["terminal"]! && got.LastState == (string)exp["last_state"]!, $"{name}: terminal/state");
            else Assert.True(got.Code == (string)exp["code"]! && (!exp.ContainsKey("at") || got.At == N(exp["at"])), $"{name}: {got.Code}@{got.At}");
            Assert.True(A2a.MayTriggerNext(list, signer, (string)s["task_id"]!, Strs(s["chain_ids"])) == (bool)s["may_trigger_next"]!, $"{name}: may");
        }
    }
}
