using System.Text.RegularExpressions;
using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the reference's OpenAI Agents adapter logic: proof sources, the guard pipeline, per-tool option merging and guardrails. Tools, verifiers and
/// hooks are rebuilt from the declarative descriptors of the corpus. Deliberate differences, not compared: a tool is a delegate (no name / extra / needsApproval
/// properties), a build error is any <see cref="ArgumentException"/> (the reference splits TypeError from Error and words the text differently), the audience
/// is required here (an absent one is replaced by a fixed id, which the stub verifiers ignore), and full-mode components are checked per call here, not when the tool is wrapped.</summary>
public class RefOpenAiAgentsGuardTests
{
    const string M = "ref-openai-agents";
    const string Aud = "rs";

    static D O(object? o) => o as D ?? new D();
    static string? Str(object? o) => o as string;

    // ---- proof sources ----
    [Fact]
    public void ProofFromRunContext() => Base.Check(M, "proofFromRunContext", a =>
    {
        var x = O(a[0]);
        return OpenAiAgentsGuard.ProofFromRunContext(O(x.GetValueOrDefault("input")), O(x.GetValueOrDefault("runContext")));
    });

    [Fact] public void GuardrailProof() => Base.Check(M, "guardrailProofFromContext", a => OpenAiAgentsGuard.GuardrailProofFromContext(O(O(a[0])["args"])));

    [Fact]
    public void Provenance() => Base.Check(M, "provenanceFromRunContext", a => OpenAiAgentsGuard.ProvenanceFromRunContext(new D(), O(O(a[0])["runContext"])));

    [Fact]
    public void InputHeaders() => Base.Check(M, "proofFromInputHeaders", a =>
    {
        var x = O(a[0]);
        return OpenAiAgentsGuard.ProofFromInputHeaders(Str(x.GetValueOrDefault("field")) ?? "headers", Str(x.GetValueOrDefault("header")) ?? "PCA-Action")(O(x.GetValueOrDefault("input")), new D());
    });

    // ---- descriptors -> native objects ----
    static string Norm(string? m) => Regex.Replace(m ?? "", @"proof could not be decoded: [\s\S]*$", "proof could not be decoded: ");

    static VerifyOutcome StubOutcome(D d, bool allow) =>
        new(allow, d.ContainsKey("reason") ? Str(d["reason"]) : null, new Dictionary<string, string> { ["sig"] = allow ? "pass" : "fail" });

    static Func<D, VerifyOutcome> Stub(D d, L calls) => p =>
    {
        calls.Add(new L { "verify", d["stub"], (p.GetValueOrDefault("action") as D)?.GetValueOrDefault("verb") });
        if (d.GetValueOrDefault("throws") is string t) throw new InvalidOperationException(t);
        return StubOutcome(d, d["allow"] is true);
    };

    sealed class Rec(L calls) : IToolOutputRecorder
    {
        public D Tool(string name, object? output) { calls.Add(new L { "recorded", name, output }); return new D(); }
    }

    static Func<D, D, object?>? Require(D d)
    {
        if (d.GetValueOrDefault("require") is not D r) return null;
        if (r.ContainsKey("headers"))
        {
            var h = (L)r["headers"]!;
            return OpenAiAgentsGuard.ProofFromInputHeaders(h.Count > 0 ? (string)h[0]! : "headers", h.Count > 1 ? (string)h[1]! : "PCA-Action");
        }
        var c = r["const"];
        return (_, _) => c;
    }

    static WithPcaToolOptions Opts(D d, L calls, bool shared)
    {
        var o = new WithPcaToolOptions
        {
            Mode = Str(d.GetValueOrDefault("mode")), Verb = Str(d.GetValueOrDefault("verb")), Require = Require(d),
            Audience = d.ContainsKey("audience") ? Str(d["audience"]) ?? (shared ? Aud : null) : shared ? Aud : null,
        };
        if (d.GetValueOrDefault("verify") is D v) o = o with { VerifyFn = Stub(v, calls) };
        if (d.ContainsKey("authorize") && d["authorize"] != null) o = o with { Authorize = (_, _) => new AuthorizeInput() };
        if (d.GetValueOrDefault("onDeny") != null && d["onDeny"] is not false) o = o with { OnDeny = (e, i) => calls.Add(new L { "onDeny", e.Kind, i }) };
        if (d.GetValueOrDefault("onVerified") != null && d["onVerified"] is not false)
            o = o with { OnVerified = (p, i) => calls.Add(new L { "onVerified", true, (p.GetValueOrDefault("action") as D)?.GetValueOrDefault("verb"), i }) };
        if (d.GetValueOrDefault("recorder") != null && d["recorder"] is not false) o = o with { Recorder = new Rec(calls) };
        return o;
    }

    static Func<D, D?, Task<object?>> Tool(D td, L calls)
    {
        var name = Str(td.GetValueOrDefault("name"));
        if (td.GetValueOrDefault("noExecute") is true) return (_, _) => throw new InvalidOperationException("with_pca_tool: the wrapped tool has no execute()");
        return (input, _) =>
        {
            calls.Add(new L { "exec", name, input });
            if (td.GetValueOrDefault("throws") is string t) throw new InvalidOperationException(t);
            return Task.FromResult<object?>(new D { ["echo"] = input, ["tool"] = name });
        };
    }

    static D ErrOf(Exception e, L calls)
    {
        var o = new D { ["err"] = e is PcaToolDenied ? "PcaToolDenied" : "Error", ["message"] = Norm(e.Message), ["calls"] = calls };
        if (e is PcaToolDenied p)
        {
            o["kind"] = p.Kind; o["verb"] = p.Verb;
            if (p.Checks != null) o["checks"] = p.Checks.ToDictionary(c => c.Key, c => (object?)c.Value);
        }
        return o;
    }

    static D BuildErr(L calls) => new() { ["err"] = "Error", ["calls"] = calls, ["build"] = true };

    static async Task<D> Outcome(Func<D, D?, Task<object?>> t, object? input, D? rc, L calls)
    {
        try { return new D { ["ok"] = true, ["out"] = await t(O(input), rc), ["calls"] = calls }; }
        catch (Exception e) { return ErrOf(e, calls); }
    }

    // the reference's expectation with the properties a delegate cannot carry removed and the messages cut like Norm
    static object? Clean(object? v)
    {
        switch (v)
        {
            case D d when d.GetValueOrDefault("build") is true: return BuildErr((L)d["calls"]!);
            case D d:
                var o = new D();
                foreach (var (k, x) in d)
                {
                    if ((k == "name" && !d.ContainsKey("result")) || k is "extra" or "hasNeedsApproval") continue; // a guardrail result names its guardrail: compared
                    o[k] = k == "message" && x is string s ? Norm(s) : Clean(x);
                }
                return o;
            case L l: return l.Select(Clean).ToList();
            case string s when s.StartsWith("PCA tool denied", StringComparison.Ordinal): return Norm(s);
            default: return v;
        }
    }

    static Func<D, object?, bool> Same => (c, have) => Base.Show(Clean(c["out"])) == Base.Show(Clean(Base.Json(have)));

    static Func<D, string?> SkipFullMode => c =>
        c["out"] is D o && o.GetValueOrDefault("build") is true && Str(o.GetValueOrDefault("message")) is { } m && m.Contains("full policy mode is missing")
            ? "full-mode components are checked per call here" : null;

    [Fact]
    public void WithPcaTool() => Base.Check(M, "withPcaTool", a =>
    {
        var x = O(a[0]);
        var calls = new L();
        Func<D, D?, Task<object?>> t;
        try { t = OpenAiAgentsGuard.WithPcaTool(Str(O(x["tool"]).GetValueOrDefault("name")), Tool(O(x["tool"]), calls), Opts(O(x["options"]), calls, true)); }
        catch (ArgumentException) { return BuildErr(calls); }
        var rc = x.GetValueOrDefault("noRunContext") is true ? null : O(x.GetValueOrDefault("runContext"));
        return Outcome(t, x.GetValueOrDefault("input"), rc, calls).GetAwaiter().GetResult();
    }, Same, SkipFullMode);

    [Fact]
    public void PcaTools() => Base.Check(M, "pcaTools", a =>
    {
        var x = O(a[0]);
        var calls = new L();
        var tools = O(x["tools"]).ToDictionary(e => e.Key, e => Tool(O(e.Value), calls));
        var o = O(x["options"]);
        var per = o.GetValueOrDefault("per") is D p ? p.ToDictionary(e => e.Key, e => Opts(O(e.Value), calls, false)) : null;
        var only = o.GetValueOrDefault("only") is L ol ? ol.Select(v => (string)v!).ToList() : null;
        Dictionary<string, Func<D, D?, Task<object?>>> g;
        try { g = OpenAiAgentsGuard.PcaTools(tools, Opts(o, calls, true), per, only); }
        catch (ArgumentException) { return BuildErr(calls); }
        var res = new D();
        foreach (var (k, t) in g)
        {
            var r = Outcome(t, x.GetValueOrDefault("input"), O(x.GetValueOrDefault("runContext")), calls).GetAwaiter().GetResult();
            r["same"] = ReferenceEquals(t, tools[k]);
            res[k] = r;
        }
        return res;
    }, Same, SkipFullMode);

    [Fact]
    public void Guardrail() => Base.Check(M, "guardrail", a =>
    {
        var x = O(a[0]);
        var calls = new L();
        var d = O(x["options"]);
        var wo = Opts(d, calls, true);
        var go = new PcaGuardrailOptions
        {
            VerifyFn = wo.VerifyFn, Audience = wo.Audience, Verb = wo.Verb, Name = Str(d.GetValueOrDefault("name")),
            Require = wo.Require == null ? null : args => wo.Require(args, new D()),
        };
        var g = (string)x["kind"]! == "input" ? OpenAiAgentsGuard.PcaInputGuardrail(go) : OpenAiAgentsGuard.PcaToolGuard(go);
        try
        {
            var r = g.Execute(O(x["args"])).GetAwaiter().GetResult();
            var info = new D(r.OutputInfo);
            if (info.GetValueOrDefault("checks") == null) info.Remove("checks");
            return new D { ["name"] = g.Name, ["result"] = new D { ["tripwireTriggered"] = r.TripwireTriggered, ["outputInfo"] = info }, ["calls"] = calls };
        }
        catch (Exception e) { return new D { ["err"] = "Error", ["message"] = Norm(e.Message), ["calls"] = calls }; }
    }, Same);

    // the step-up half of this corpus (reviewToolCall, pendingStepUps, needsApproval) is replayed by RefOpenAiAgentsStepUpTests
    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "proofFromRunContext", "guardrailProofFromContext", "provenanceFromRunContext", "proofFromInputHeaders", "withPcaTool", "pcaTools", "guardrail", "reviewToolCall",
            "pendingStepUps", "needsApproval",
        });
        Assert.Equal(192, Base.Total(M));
    }
}
