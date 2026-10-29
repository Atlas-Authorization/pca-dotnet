using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// Escalation (goal-to-decision T2, C-51) through the guard: an escalate-class failure is surfaced as decision "escalate" with
// the request, refused without an answer, admitted only by a principal answer bound to this grant, this PCActn and the holder's
// history head, spent by the replay claim, never upgrading a deny. The core verdict is edited through the per-thread CoreHook seam
// (an escalate-class check failure cannot be produced by a signed fixture without the Intent Layer v2 state).
public class EscalationTests
{
    static readonly string Root = FindConformance();
    static string FindConformance()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var c = Path.Combine(dir.FullName, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "keys.json"))) return c;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("packages/pca/conformance/keys.json not found above " + AppContext.BaseDirectory);
    }

    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly JD Keys = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(Root, "keys.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);

    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);

    static string PrincipalPub => (string)((JD)Keys["principal"]!)["public"]!;
    static string Holder => (string)((JD)((JL)Pcactn["cap_chain"]!).Last()!)["holder"]!;
    static string StateKey => Pca.StateKey((string)Grant["id"]!, Holder);

    static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    static JD SignAnswer(JD grant, JD pcactn, long? last, Action<JD>? over = null, string? seedOf = null)
    {
        var body = new JD
        {
            ["v"] = N(1), ["kind"] = "pca-escalation-answer", ["principal"] = PrincipalPub, ["policy_digest"] = Escalation.PolicyDigest(grant),
            ["action_digest"] = Escalation.ActionDigest(pcactn), ["history_head"] = Escalation.HistoryHead(last), ["decision"] = "allow",
            ["iat"] = N(Now - 1_000), ["expires_at"] = N(Now + 600_000), ["nonce"] = "CQkJCQkJCQkJCQkJCQkJCQ",
        };
        over?.Invoke(body);
        var seed = Pca.B64uDecode(((JD)Keys[seedOf ?? "principal"]!)["seed"], 32)!;
        var msg = IntentJs.Message(Escalation.AnswerDomain, body);
        var sig = new byte[64];
        Ed25519.Sign(seed, 0, msg, 0, msg.Length, sig, 0);
        body["sig"] = Pca.B64u(sig);
        return body;
    }

    static AuthorizeInput Input(IStateStore store, object? answer, params PinnedSigner[] principals) => new AuthorizeInput
    {
        Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = store, IsRevoked = (_, _) => false,
        Now = Now, Plan = "single-step", EscalationAnswer = answer, EscalationPrincipals = principals, InsecureUnboundApproval = true,
    }.WithProv();

    static IDisposable Hook(params string[] failing)
    {
        Pca.CoreHook = core =>
        {
            foreach (var c in failing) core.Checks[c] = false;
            core.Allow = false;
            core.Reason = "provenance: intent_required: a question is required";
        };
        return new Reset();
    }
    sealed class Reset : IDisposable { public void Dispose() => Pca.CoreHook = null; }

    /// <summary>A store that only claims (no Last): it cannot bind an answer to the holder's history.</summary>
    sealed class BareStore : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    [Fact]
    public void EscalateIsSurfacedAndRefusedWithoutAnAnswer()
    {
        using var _ = Hook("provenance");
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), null));
        Assert.False(r.Allow);
        Assert.Equal(("escalate", 403), (r.Decision, r.Status));
        Assert.Equal("pca-escalation-request", r.Escalation!["kind"]);
        Assert.Equal(Escalation.PolicyDigest(Grant), r.Escalation["policy_digest"]);
        Assert.Equal(Escalation.ActionDigest(Pcactn), r.Escalation["action_digest"]);
        Assert.Equal(Escalation.HistoryHead(null), r.Escalation["history_head"]);
        Assert.Equal("payments.send", r.Escalation["verb"]);
        Assert.Equal("fail", r.Checks["provenance"]);
        Assert.Equal("provenance: intent_required: a question is required", r.Reason);
    }

    [Fact]
    public void AHardFailureIsDenyNotEscalate()
    {
        using var _ = Hook("provenance", "leaf_signature");
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), null));
        Assert.False(r.Allow);
        Assert.Equal("deny", r.Decision);
        Assert.Null(r.Escalation);
    }

    [Fact]
    public void UnboundApprovalIsRefusedByDefault()
    {
        using var _ = Hook("provenance");
        var a = SignAnswer(Grant, Pcactn, null);
        var strict = Input(new MemoryStateStore(), a, PrincipalPub);
        strict.InsecureUnboundApproval = false;
        var r = Pca.Authorize(Pcactn, strict);
        Assert.False(r.Allow);
        Assert.Contains(r.Reasons, x => x.Contains("approval render is required"));
        Assert.True(Pca.Authorize(Pcactn, Input(new MemoryStateStore(), a, PrincipalPub)).Allow);
    }

    [Fact]
    public void APrincipalAnswerAdmitsAProvenanceFlowEscalation()
    {
        // no provenance bundle: provenance_flow escalates (no CoreHook); a principal-signed answer admits exactly this call
        var store = new MemoryStateStore();
        AuthorizeInput Unlabelled(object? answer) { var i = Input(store, answer, PrincipalPub); i.Provenance = null; return i; }
        var asked = Pca.Authorize(Pcactn, Unlabelled(null));
        Assert.Equal(("escalate", "fail"), (asked.Decision, asked.Checks["provenance_flow"]));
        Assert.Null(store.Last(StateKey));
        var r = Pca.Authorize(Pcactn, Unlabelled(SignAnswer(Grant, Pcactn, null)));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal(("pass", "pass"), (r.Checks["provenance_flow"], r.Checks["escalation"]));
        Assert.Equal(PrincipalPub, r.Escalation!["answered_by"]);
    }

    [Fact]
    public void AValidAnswerAdmitsOnceAndTheCounterSpendsIt()
    {
        using var _ = Hook("provenance");
        var store = new MemoryStateStore();
        var r = Pca.Authorize(Pcactn, Input(store, SignAnswer(Grant, Pcactn, null), PrincipalPub));
        Assert.True(r.Allow);
        Assert.Equal(("allow", 200), (r.Decision, r.Status));
        Assert.Equal(PrincipalPub, r.Escalation!["answered_by"]);
        Assert.Equal("pass", r.Checks["escalation"]);
        Assert.Equal("pass", r.Checks["provenance"]);
        Assert.Contains("escalation: answered allow by principal " + PrincipalPub[..8], r.Reasons);
        long? last = store.Last(StateKey);
        Assert.Equal(1L, last);
        // the same PCActn again: the replay claim refuses it, an answer bound to the new history head does not help
        var again = Pca.Authorize(Pcactn, Input(store, SignAnswer(Grant, Pcactn, last), PrincipalPub));
        Assert.False(again.Allow);
        Assert.Equal("fail", again.Checks["replay"]);
    }

    [Fact]
    public void BadAnswersStayEscalate()
    {
        using var _ = Hook("provenance");
        var zero = Pca.B64u(new byte[32]);
        var cases = new Dictionary<string, JD>
        {
            ["deny"] = SignAnswer(Grant, Pcactn, null, b => b["decision"] = "deny"),
            ["policy"] = SignAnswer(Grant, Pcactn, null, b => b["policy_digest"] = zero),
            ["action"] = SignAnswer(Grant, Pcactn, null, b => b["action_digest"] = zero),
            ["history"] = SignAnswer(Grant, Pcactn, 99, null),
            ["expired"] = SignAnswer(Grant, Pcactn, null, b => { b["iat"] = N(1); b["expires_at"] = N(2); }),
            ["unsigned"] = new JD { ["junk"] = N(1) },
            ["wrong-key"] = SignAnswer(Grant, Pcactn, null, null, "rogue"),
        };
        foreach (var (name, ans) in cases)
        {
            var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), ans, PrincipalPub));
            Assert.False(r.Allow, name);
            Assert.Equal("escalate", r.Decision);
            Assert.NotNull(r.Escalation);
        }
        // no pinned principal: a valid answer is not an answer
        var none = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), SignAnswer(Grant, Pcactn, null)));
        Assert.False(none.Allow);
        Assert.Equal("escalate", none.Decision);
    }

    [Fact]
    public void AnAnswerNeverUpgradesADeny()
    {
        using var _ = Hook("provenance", "leaf_signature");
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), SignAnswer(Grant, Pcactn, null), PrincipalPub));
        Assert.False(r.Allow);
        Assert.Equal("deny", r.Decision);
    }

    [Fact]
    public void AStoreWithoutLastIsAConfigurationErrorWhenPrincipalsArePinned()
    {
        using var _ = Hook("provenance");
        var i = Input(new BareStore(), SignAnswer(Grant, Pcactn, null), PrincipalPub);
        var r = Pca.Authorize(Pcactn, i);
        Assert.False(r.Allow);
        Assert.Equal((false, 403, "authorize_config"), (r.Allow, r.Status, r.Checks.Keys.Single()));
        Assert.Equal(new[] { "StateStore.Last (required by EscalationPrincipals)" }, r.Missing);
        // without principals a claim-only store is fine
        Assert.True(Pca.Authorize(Pcactn, Input(new BareStore(), null)).Decision == "escalate");
    }

    [Fact]
    public void AllowAndPlainDenyCarryTheirDecision()
    {
        var ok = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), null));
        Assert.True(ok.Allow);
        Assert.Equal("allow", ok.Decision);
        Assert.Null(ok.Escalation);
        var other = Input(new MemoryStateStore(), null);
        other.Operation = Op with { Verb = "payments.refund" };
        var refused = Pca.Authorize(Pcactn, other);
        Assert.False(refused.Allow);
        Assert.Equal("deny", refused.Decision);
        Assert.Null(refused.Escalation);
    }

    // ---- the ASP.NET Core middleware: refusal body + header / body answer

    static PcaMiddleware Mw(IStateStore store, Action onNext, params PinnedSigner[] principals) => new(_ => { onNext(); return Task.CompletedTask; }, new PcaOptions
    {
        Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null),
        Authorize = new PcaAuthorizeOptions { StateStore = store, IsRevoked = (_, _) => false, Operation = _ => Task.FromResult<Operation?>(Op), EscalationPrincipals = principals, InsecureUnboundApproval = true, ProvenanceFlow = ProvHarness.Options },
    });

    static DefaultHttpContext Ctx(string? answerHeader = null, string? body = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        if (body != null) ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        else ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        if (answerHeader != null) ctx.Request.Headers["PCA-Escalation-Answer"] = answerHeader;
        ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        return ctx;
    }

    static JsonElement BodyOf(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return JsonDocument.Parse(new StreamReader(ctx.Response.Body).ReadToEnd()).RootElement;
    }

    [Fact]
    public async Task MiddlewareRefusalBodyCarriesTheDecisionAndTheRequest()
    {
        using var _ = Hook("provenance");
        bool ran = false;
        var ctx = Ctx();
        await Mw(new MemoryStateStore(), () => ran = true).InvokeAsync(ctx);
        Assert.False(ran);
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        var b = BodyOf(ctx);
        Assert.Equal("escalate", b.GetProperty("decision").GetString());
        Assert.Equal("pca-escalation-request", b.GetProperty("escalation").GetProperty("kind").GetString());
        Assert.Equal(1, b.GetProperty("escalation").GetProperty("v").GetInt32());
    }

    [Fact]
    public async Task MiddlewareAdmitsAnAnswerFromTheHeaderOrTheBody()
    {
        using var _ = Hook("provenance");
        var answer = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(SignAnswer(Grant, Pcactn, null))));
        bool ran = false;
        var ctx = Ctx(answerHeader: answer);
        await Mw(new MemoryStateStore(), () => ran = true, PrincipalPub).InvokeAsync(ctx);
        Assert.True(ran);
        Assert.Equal("allow", ((PcaAuthResult)ctx.Items["pca"]!).Authorization!.Decision);

        ran = false;
        var env = "{\"pcactn\":" + Pca.Canonicalize(Pcactn) + ",\"escalation_answer\":" + Pca.Canonicalize(SignAnswer(Grant, Pcactn, null)) + "}";
        var bctx = Ctx(body: env);
        await Mw(new MemoryStateStore(), () => ran = true, PrincipalPub).InvokeAsync(bctx);
        Assert.True(ran);

        // an unreadable answer is no answer; a malformed header does not break the request into a 500
        ran = false;
        var junk = Ctx(answerHeader: "!!not-base64url!!");
        await Mw(new MemoryStateStore(), () => ran = true, PrincipalPub).InvokeAsync(junk);
        Assert.False(ran);
        Assert.Equal("escalate", BodyOf(junk).GetProperty("decision").GetString());
    }
}
