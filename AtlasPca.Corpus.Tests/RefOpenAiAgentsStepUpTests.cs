using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the step-up helpers of the OpenAI Agents adapter (tool review, pending step-ups, needsApproval) against the TypeScript
/// reference. The reference corpus drives them with an intent that always answers "unguarded", so no agent is consulted. The proof-source, guard
/// pipeline and guardrail cases of the same corpus are replayed by RefOpenAiAgentsGuardTests.</summary>
public class RefOpenAiAgentsStepUpTests
{
    const string M = "ref-openai-agents";

    static ToolIntent Recording(L calls) => (t, i) => { calls.Add(new L { "intent", t, i }); return null; };

    [Fact]
    public void ReviewToolCall() => Base.Check(M, "reviewToolCall", a =>
    {
        var x = (D)a[0]!;
        var calls = new L();
        var r = OpenAiAgentsGuard.ReviewToolCall(null!, (string)x["tool"]!, x.GetValueOrDefault("input") as D, new StepUpOptions { Intent = Recording(calls) });
        return new D { ["r"] = new D { ["tool"] = r.Tool, ["review"] = r.Review }, ["calls"] = calls };
    });

    [Fact]
    public void PendingStepUps() => Base.Check(M, "pendingStepUps", a =>
        OpenAiAgentsGuard.PendingStepUps(((L)a[0]!).Select(r => { var d = (D)r!; return new ToolReview((string)d["tool"]!, (D)d["review"]!); }))
            .Select(p => new D { ["tool"] = p.Tool, ["request"] = p.Request }).ToList());

    // the reference also reports properties of the wrapped tool object (name, extra, hasExecute): a delegate has none, so only the verdict and the intent calls are compared
    [Fact]
    public void NeedsApproval() => Base.Check(M, "needsApproval", a =>
    {
        var x = (D)a[0]!;
        var calls = new L();
        var opts = new PcaNeedsApprovalOptions { Intent = Recording(calls), ToolName = x.GetValueOrDefault("toolName") as string };
        var f = (string)x["via"]! == "direct"
            ? OpenAiAgentsGuard.PcaNeedsApproval(null!, opts)
            : OpenAiAgentsGuard.WithApproval((x["tool"] as D)?.GetValueOrDefault("name") as string, null!, opts);
        var value = f(new D(), (D)x["input"]!);
        return new D { ["value"] = value, ["calls"] = calls };
    }, eq: (c, have) => Base.Show(((D)c["out"]!).Where(e => e.Key is "value" or "calls").ToDictionary(e => e.Key, e => e.Value)) == Base.Show(Base.Json(have)));
}
