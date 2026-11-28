using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.A2aPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the A2A adapter against the TypeScript reference (test-data/ref-a2a.json.gz). A reason that quotes the JOSE library
/// ("signature N did not verify: ...", "could not resolve verification key: ...") is compared up to the first colon, as the oracle does.</summary>
public class RefA2aTests
{
    const string M = "ref-a2a";

    static D Norm(D r)
    {
        if (r.GetValueOrDefault("reason") is string reason)
        {
            var m = Regex.Match(reason, @"^(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): ");
            if (m.Success) return new D(r) { ["reason"] = m.Groups[1].Value };
        }
        return r;
    }

    static List<string> Strs(object? o) => ((L)o!).Select(e => (string)e!).ToList();

    static A2aPca.VerifyOptions Opts(L a, int i)
    {
        var x = a.Count > i ? (D)a[i]! : new D(); // an omitted options argument has no members (undefined)
        var v = new A2aPca.VerifyOptions { Aud = x.GetValueOrDefault("aud") as string };
        if (x.GetValueOrDefault("now") != null) v.Now = IntentJs.Lng(x["now"]);
        v.Grant = x.GetValueOrDefault("grant") as D;
        v.ExpectedRootIssuer = x.GetValueOrDefault("expectedRootIssuer") as string;
        v.RequireProof = x.GetValueOrDefault("require") is not false;
        if (x.GetValueOrDefault("humanSignerSet") is L hs) v.HumanSignerSet = hs;
        if (x.ContainsKey("context")) { var ctx = (D)x["context"]!; v.Context = _ => ctx; }
        return v;
    }

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["PCA_A2A_EXTENSION_URI"] = A2aPca.PcaA2aExtensionUri,
        ["TASK_STATE_AUTH_REQUIRED"] = A2aPca.TaskStateAuthRequired,
        ["TASK_STATE_INPUT_REQUIRED"] = A2aPca.TaskStateInputRequired,
        ["A2A_AP2_CONTEXT"] = A2aPca.A2aAp2Context.Cast<object?>().ToList(),
        ["A2A_RECEIPT_DOMAIN"] = A2aPca.A2aReceiptDomain,
        ["RECEIPT_KEY"] = A2aPca.ReceiptKey,
    });

    [Fact] public void JcsBytes() => Base.Check(M, "jcsBytes", a => A2aPca.JcsBytes(a[0]));
    [Fact] public void ValidateAgentCard1() => Base.Check(M, "validateAgentCard1", a => A2aPca.ValidateAgentCard1(a[0]));
    [Fact] public void AttachTask() => Base.Check(M, "attachPcaToA2ATask", a => A2aPca.AttachPcaToA2ATask(a[0], a[1]));
    [Fact] public void AttachMessage() => Base.Check(M, "attachPcaToA2AMessage", a => A2aPca.AttachPcaToA2AMessage(a[0], a[1]));
    [Fact] public void ExtractPca() => Base.Check(M, "extractPca", a => A2aPca.ExtractPca(a[0]));
    [Fact] public void ExtractPcaFromMessage() => Base.Check(M, "extractPcaFromMessage", a => A2aPca.ExtractPcaFromMessage(a[0]));

    [Fact] public void VerifyTask() => Base.Check(M, "verifyA2ATask", a => A2aPca.VerifyA2ATask(a[0], Opts(a, 1)).ToMap());
    [Fact] public void Middleware() => Base.Check(M, "middleware", a => A2aPca.PcaA2AMiddleware(Opts(a, 1))(a[0]).ToMap());
    [Fact] public void ResumeAuthRequired() => Base.Check(M, "resumeAuthRequired", a => A2aPca.ResumeAuthRequired(a[0], a[1], Opts(a, 2)));
    [Fact] public void AuthRequiredStatus() => Base.Check(M, "authRequiredStatus", a => A2aPca.AuthRequiredStatus((D)a[0]!, (D)a[1]!));
    [Fact] public void AnswerMessage() => Base.Check(M, "answerMessage", a => A2aPca.AnswerMessage(a[0], a[1], a[2]));
    [Fact] public void ReadAuthRequiredNeed() => Base.Check(M, "readAuthRequiredNeed", a => A2aPca.ReadAuthRequiredNeed(a[0]));
    [Fact] public void IsAuthRequired() => Base.Check(M, "isAuthRequired", a => A2aPca.IsAuthRequired(a[0]));

    [Fact]
    public void ResumeGate() => Base.Check(M, "resumeGate", a =>
    {
        var x = (D)a[0]!;
        return A2aPca.ResumeGate(x.GetValueOrDefault("state"), x.GetValueOrDefault("needEncoded"), x.GetValueOrDefault("answerNeedDigest"),
            x.ContainsKey("proofAction") ? x["proofAction"] : A2aPca.NoProof);
    });

    [Fact] public void PcaExtensionDeclaration() => Base.Check(M, "pcaExtensionDeclaration", a => a.Count > 1 ? A2aPca.PcaExtensionDeclaration(a[0], (bool)a[1]!) : A2aPca.PcaExtensionDeclaration(a[0]));
    [Fact] public void ReadPcaExtension() => Base.Check(M, "readPcaExtension", a => A2aPca.ReadPcaExtension(a[0]));
    [Fact] public void ClientOptsIntoPca() => Base.Check(M, "clientOptsIntoPca", a => A2aPca.ClientOptsIntoPca(a[0]));
    [Fact] public void CheckChainExtension() => Base.Check(M, "checkChainExtension", a => A2aPca.CheckChainExtension(a[0]));
    [Fact] public void ChainExtends() => Base.Check(M, "chainExtends", a => A2aPca.ChainExtends((L)a[0]!, (L)a[1]!));

    [Fact]
    public void VerifyDelegation() => Base.Check(M, "verifyA2ADelegation", a =>
        A2aPca.VerifyA2ADelegation(((L)a[0]!).Select(h => new A2aPca.Hop(((D)h!)["task"], Opts(new L { ((D)h)["opts"] }, 0))).ToList()));

    [Fact] public void PushToken() => Base.Check(M, "pcaPushToken", a => A2aPca.PcaPushToken(a[0], Strs(a[1]), a[2]));

    [Fact]
    public void CheckPush() => Base.Check(M, "checkPushNotification", a =>
    {
        var e = (D)a[0]!; var d = (D)a[1]!;
        return A2aPca.CheckPushNotification((string)e["taskId"]!, Strs(e["chainIds"]), e.GetValueOrDefault("salt"), d.GetValueOrDefault("token"), d.GetValueOrDefault("payload"));
    });

    [Fact] public void UniformTaskNotFound() => Base.Check(M, "uniformTaskNotFound", _ => A2aPca.UniformTaskNotFound());

    [Fact]
    public void SignTaskReceipt() => Base.Check(M, "signTaskReceipt", a =>
    {
        var o = (D)a[1]!;
        return A2aPca.SignTaskReceipt(Seed((string)a[0]!), o.GetValueOrDefault("taskId"), o.GetValueOrDefault("state"), Strs(o["chainIds"]), o.GetValueOrDefault("issuedAt"), o.GetValueOrDefault("prev") as D);
    });

    [Fact] public void VerifyTaskReceipt() => Base.Check(M, "verifyTaskReceipt", a => A2aPca.VerifyTaskReceipt(a[0], (string)a[1]!));
    [Fact] public void ReceiptDigest() => Base.Check(M, "receiptDigest", a => A2aPca.ReceiptDigest(a[0]));

    [Fact]
    public void CheckReceiptChain() => Base.Check(M, "checkReceiptChain", a =>
    {
        var o = (D)a[1]!;
        return A2aPca.CheckReceiptChain(a[0], (string)o["signer"]!, (string)o["taskId"]!, Strs(o["chainIds"]));
    });

    [Fact]
    public void MayTriggerNext() => Base.Check(M, "mayTriggerNext", a =>
    {
        var o = (D)a[1]!;
        return A2aPca.MayTriggerNext(a[0], (string)o["signer"]!, (string)o["taskId"]!, Strs(o["chainIds"]));
    });

    [Fact] public void AttachReceipt() => Base.Check(M, "attachReceipt", a => A2aPca.AttachReceipt(a[0], a[1]));
    [Fact] public void ReceiptOfPayload() => Base.Check(M, "receiptOfPayload", a => A2aPca.ReceiptOfPayload(a[0]));
    [Fact] public void ExtendedAgentCard() => Base.Check(M, "extendedAgentCard", a => A2aPca.ExtendedAgentCard(a[0], (D)a[1]!));

    [Fact]
    public void IssueSignedAgentCard() => Base.Check(M, "issueSignedAgentCard", a =>
    {
        var io = new A2aPca.IssueOptions();
        if (a.Count > 2)
        {
            var o = (D)a[2]!;
            io.Alg = o.GetValueOrDefault("alg") as string;
            io.Kid = o.GetValueOrDefault("kid") as string;
            io.Profile = o.GetValueOrDefault("profile") as string;
            io.Schema = o.GetValueOrDefault("schema") as string;
            io.Passport = o.GetValueOrDefault("passport") as D;
        }
        return A2aPca.IssueSignedAgentCard(a[0], a[1], io);
    });

    [Fact]
    public void VerifyAgentCard() => Base.Check(M, "verifyAgentCard", a =>
    {
        var o = (D)a[1]!;
        var vo = new A2aPca.VerifyCardOptions
        {
            Jwks = o.GetValueOrDefault("jwks"), HasKey = o.ContainsKey("key"), Key = o.GetValueOrDefault("key"),
            Alg = o.GetValueOrDefault("alg") as string, Schema = o.GetValueOrDefault("schema") as string,
        };
        return Norm(A2aPca.VerifyAgentCard(a[0], vo));
    });

    [Fact] public void PaymentMandateFromPca() => Base.Check(M, "a2aPaymentMandateFromPca", a => A2aPca.A2aPaymentMandateFromPca(a[0], (D)a[1]!));
    [Fact] public void PcaBindingFromMandate() => Base.Check(M, "pcaBindingFromA2APaymentMandate", a => A2aPca.PcaBindingFromA2APaymentMandate(a[0]));
    [Fact] public void VerifyPaymentMandate() => Base.Check(M, "verifyA2APaymentMandate", a => Norm(A2aPca.VerifyA2APaymentMandate(a[0], a[1], Opts(a, 2)).ToMap()));

    /// <summary>What the oracle cannot reach: a PCActn that gets to the verifier is refused without a revocation predicate, a plug-in verifier decides,
    /// and a throwing verifier is a refusal.</summary>
    [Fact]
    public void VerifierPlugAndFailClosed()
    {
        var pca = new D { ["cap_chain"] = new L { new D { ["id"] = "g1", ["issuer"] = "ROOT", ["holder"] = "H1" } } };
        var task = new D { ["metadata"] = new D { [A2aPca.PcaA2aExtensionUri] = pca } };
        var o = new A2aPca.VerifyOptions { Aud = "rs", Now = 1, ExpectedRootIssuer = "ROOT" };
        Assert.False(A2aPca.VerifyA2ATask(task, o).Ok); // the core verifier refuses a PCActn with no signature
        o.Verifier = (p, r) => new A2aPca.Outcome(true, new Dictionary<string, string>(), new List<string>());
        Assert.True(A2aPca.VerifyA2ATask(task, o).Ok);
        o.Verifier = (p, r) => throw new InvalidOperationException("boom");
        Assert.False(A2aPca.VerifyA2ATask(task, o).Ok);
    }

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "jcsBytes", "validateAgentCard1", "attachPcaToA2ATask", "attachPcaToA2AMessage", "extractPca", "extractPcaFromMessage",
        "verifyA2ATask", "middleware", "resumeAuthRequired", "authRequiredStatus", "answerMessage", "readAuthRequiredNeed", "isAuthRequired", "resumeGate",
        "pcaExtensionDeclaration", "readPcaExtension", "clientOptsIntoPca", "checkChainExtension", "chainExtends", "verifyA2ADelegation", "pcaPushToken",
        "checkPushNotification", "uniformTaskNotFound", "signTaskReceipt", "verifyTaskReceipt", "receiptDigest", "checkReceiptChain", "mayTriggerNext",
        "attachReceipt", "receiptOfPayload", "extendedAgentCard", "issueSignedAgentCard", "verifyAgentCard", "a2aPaymentMandateFromPca",
        "pcaBindingFromA2APaymentMandate", "verifyA2APaymentMandate",
    }); Assert.Equal(6337, Base.Total(M)); }
}
