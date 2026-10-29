using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// The optional undo admission hook (AuthorizeInput.Undo): called only for an unanswered, non-provenance escalation; an admission turns
// it into an allow under a veto window (every escalate-class failure passes, undo_window passes, the undo_window obligation rides on
// the result). A provenance escalation (provenance_flow or rule 17 `provenance`), an answer, a deny or a throwing hook never admit.
// Escalate-class failures are produced through the CoreHook seam, as in EscalationTests.
public class UndoAuthorizeTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    static readonly UndoAdmission Admission = new("op_1", Now + 900_000, new UndoCompensationRef("payments.refund", "payments/acme"));

    static IDisposable Hook(string reason, params string[] failing)
    {
        Pca.CoreHook = core =>
        {
            foreach (var c in failing) core.Checks[c] = false;
            core.Allow = false;
            core.Reason = reason;
        };
        return new Reset();
    }
    sealed class Reset : IDisposable { public void Dispose() => Pca.CoreHook = null; }

    const string Tighten = "tighten: escalate: the principal must confirm a step outside the tightened envelope";

    sealed class Spy
    {
        public int Calls;
        public (JD Pcactn, JD Grant, Operation Op)? Seen;
        public Func<UndoAdmission?> Answer = () => Admission;
        public UndoAdmission? Call(JD p, JD g, Operation o) { Calls++; Seen = (p, g, o); return Answer(); }
    }

    static AuthorizeInput Input(Spy spy, object? answer = null, bool provenance = true)
    {
        var i = new AuthorizeInput
        {
            Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = new MemoryStateStore(),
            IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", EscalationAnswer = answer, InsecureUnboundApproval = true, Undo = spy.Call,
            ProvenanceFlow = ProvHarness.Options,
        };
        if (provenance) i.Provenance = ProvHarness.Bundle(Op);
        return i;
    }

    [Fact]
    public void AnEscalateClassRuleIsAdmittedUnderAVetoWindow()
    {
        using var _ = Hook(Tighten, "tighten");
        var spy = new Spy();
        var r = Pca.Authorize(Pcactn, Input(spy));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal(("allow", 200), (r.Decision, r.Status));
        Assert.Equal(1, spy.Calls);
        Assert.Equal((Op.Verb, Op.Resource), (spy.Seen!.Value.Op.Verb, spy.Seen.Value.Op.Resource));
        Assert.Equal(Grant["id"], spy.Seen.Value.Grant["id"]);
        Assert.Equal(("pass", "pass", "pass"), (r.Checks["tighten"], r.Checks["undo_window"], r.Checks["provenance_flow"]));
        Assert.DoesNotContain("fail", r.Checks.Values);
        Assert.Contains($"undo_window: runs now under a veto window until {(Now + 900_000).ToString(CultureInfo.InvariantCulture)} (compensation payments.refund)", r.Reasons);
        Assert.Null(r.Escalation);
        Assert.Same(Admission, r.Undo);
        var ob = Assert.Single(r.Obligations!);
        Assert.Equal(Pca.Canonicalize(new JD { ["kind"] = "undo_window", ["params"] = new JD { ["id"] = "op_1", ["window_end"] = Now + 900_000 }, ["due"] = Now + 900_000 }), Pca.Canonicalize(ob));
        Assert.Null(Obligations.ObligationsError(new JL(r.Obligations!)));
        // without the hook the same call is an escalation
        var plain = Input(spy);
        plain.Undo = null;
        Assert.Equal("escalate", Pca.Authorize(Pcactn, plain).Decision);
    }

    [Fact]
    public void AProvenanceFlowEscalationNeverCallsTheHook()
    {
        using var _ = Hook(Tighten, "tighten");
        var spy = new Spy();
        var r = Pca.Authorize(Pcactn, Input(spy, provenance: false));
        Assert.Equal(("escalate", "fail"), (r.Decision, r.Checks["provenance_flow"]));
        Assert.Equal(0, spy.Calls);
        Assert.Null(r.Undo);
        // provenance_flow alone, no other failure
        Pca.CoreHook = null;
        var only = Pca.Authorize(Pcactn, Input(spy, provenance: false));
        Assert.Equal("escalate", only.Decision);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public void ARule17ProvenanceFailureNeverCallsTheHook()
    {
        using var _ = Hook("provenance: intent_required: a question is required", "provenance");
        var spy = new Spy();
        var r = Pca.Authorize(Pcactn, Input(spy));
        Assert.Equal(("escalate", "fail", "pass"), (r.Decision, r.Checks["provenance"], r.Checks["provenance_flow"]));
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public void APresentedAnswerNeverCallsTheHook()
    {
        using var _ = Hook(Tighten, "tighten");
        var spy = new Spy();
        var r = Pca.Authorize(Pcactn, Input(spy, answer: new JD { ["kind"] = "pca-escalation-answer" }));
        Assert.False(r.Allow);
        Assert.Equal(0, spy.Calls);
        Assert.Null(r.Undo);
    }

    [Fact]
    public void AThrowingHookIsNoAdmission()
    {
        using var _ = Hook(Tighten, "tighten");
        var spy = new Spy { Answer = () => throw new InvalidOperationException("ledger down") };
        var r = Pca.Authorize(Pcactn, Input(spy));
        Assert.Equal(("escalate", 1), (r.Decision, spy.Calls));
        Assert.False(r.Checks.ContainsKey("undo_window"));
        Assert.NotNull(r.Escalation);
        // null and a malformed admission (its obligation fails validation) are no admission either
        foreach (var bad in new UndoAdmission?[] { null, Admission with { Id = new string('i', 129) }, Admission with { Id = "" }, Admission with { WindowEnd = -1 } })
        {
            var s = new Spy { Answer = () => bad };
            var b = Pca.Authorize(Pcactn, Input(s));
            Assert.Equal(("escalate", 1), (b.Decision, s.Calls));
            Assert.Null(b.Obligations);
        }
    }

    [Fact]
    public void ADenyNeverCallsTheHook()
    {
        using var _ = Hook(Tighten, "tighten", "leaf_signature");
        var spy = new Spy();
        var r = Pca.Authorize(Pcactn, Input(spy));
        Assert.Equal("deny", r.Decision);
        Assert.Equal(0, spy.Calls);
        // an allow does not call it either
        Pca.CoreHook = null;
        Assert.True(Pca.Authorize(Pcactn, Input(spy)).Allow);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task TheMiddlewarePassesTheHookThrough()
    {
        using var _ = Hook(Tighten, "tighten");
        HttpContext? seen = null;
        var ran = false;
        var mw = new PcaMiddleware(c => { ran = true; return Task.CompletedTask; }, new PcaOptions
        {
            Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null),
            Authorize = new PcaAuthorizeOptions
            {
                StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options,
                Undo = (ctx, _, _, _) => { seen = ctx; return Admission; },
            },
        });
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();
        http.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        http.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        await mw.InvokeAsync(http);
        Assert.True(ran);
        Assert.Same(http, seen);
        var az = ((PcaAuthResult)http.Items["pca"]!).Authorization!;
        Assert.Same(Admission, az.Undo);
    }
}
