using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the interpreters: candidate extraction, slot fill, rule/form/model interpreters, prompt, grounding, vendor completions, typed form.</summary>
public class RefGoalInterpretTests
{
    const string M = "ref-goal-interpret";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string? S(object? o) => (string?)o;
    static D Ont(object? o) => o is string s ? GoalOntologies.Ontology(s)! : O(o);

    static D ByKey(object? list, string key, object? val)
    {
        foreach (var x in A(list)) if (Equals(val, O(x).GetValueOrDefault(key))) return O(x);
        throw new InvalidOperationException("not found " + val);
    }

    static D Req(D ont, object? text, object? sources, object? form)
    {
        var r = new D { ["principal"] = "p1", ["text"] = text, ["ontology"] = ont };
        if (sources != null) r["sources"] = sources;
        if (form != null) r["form"] = form;
        return r;
    }

    static D Prompt(GoalInterpret.Prompt p) => new() { ["system"] = p.system, ["user"] = p.user };

    [Fact] public void SourceDigest() => Base.Check(M, "sourceDigest", a => GoalInterpret.SourceDigest(S(a[0])!));
    [Fact] public void SlotStemsOf() => Base.Check(M, "slotStemsOf", a => GoalInterpret.SlotStems(O(a[0])));
    [Fact] public void ExtractCandidates() => Base.Check(M, "extractCandidates", a => GoalInterpret.ExtractCandidates(S(a[1])!, Ont(a[0]), S(a[2])).ToJson());

    [Fact]
    public void FillTemplateById() => Base.Check(M, "fillTemplateById", a =>
    {
        var o = Ont(a[0]);
        return GoalInterpret.FillTemplate(ByKey(o["templates"], "id", a[1]), o, S(a[2])!, S(a[3]));
    });

    [Fact] public void BuildPromptOf() => Base.Check(M, "buildPromptOf", a => Prompt(GoalInterpret.BuildPrompt(Req(Ont(a[0]), a[1], a[2], null), a[3] is true)));
    [Fact] public void PromptKeyOf() => Base.Check(M, "promptKeyOf", a => GoalInterpret.PromptKey(S(a[1])!, new GoalInterpret.Prompt(S(a[2])!, S(a[3])!)));

    [Fact]
    public void ReplayLookup() => Base.Check(M, "replayLookup", a =>
    {
        var rec = new Dictionary<string, string>();
        foreach (var e in O(a[2])) rec[e.Key] = (string)e.Value!;
        return GoalInterpret.ReplayCompletion(S(a[1])!, rec)(new GoalInterpret.Prompt(S(a[3])!, S(a[4])!));
    });

    [Fact] public void ParseTemplateJSON() => Base.Check(M, "parseTemplateJSON", a => GoalInterpret.ParseTemplateJSON(S(a[0])!));

    [Fact]
    public void GroundedOf() => Base.Check(M, "groundedOf", a =>
    {
        var o = Ont(a[0]);
        var t = ByKey(o["templates"], "id", a[1]);
        return GoalInterpret.Grounded(ByKey(t["slots"], "name", a[2]), a[3], GoalInterpret.ExtractCandidates(S(a[4])!, o, null));
    });

    [Fact] public void InterpretRule() => Base.Check(M, "interpretRule", a => GoalInterpret.RuleInterpreter("rule", S(a[3])).Interpret(Req(Ont(a[0]), a[1], a[2], null)));
    [Fact] public void InterpretForm() => Base.Check(M, "interpretForm", a => GoalInterpret.FormInterpreter("form").Interpret(Req(Ont(a[0]), a[2], (a[2] as string) == "form text" ? new L { "s" } : null, a[1]))); // the oracle passes the source "s" with the example form (text "form text") and none otherwise

    [Fact]
    public void InterpretLlm() => Base.Check(M, "interpretLlm", a =>
    {
        var mode = O(a[3]);
        GoalInterpret.Completion c = p =>
        {
            if (mode.ContainsKey("throw")) throw new Exception("boom");
            return (string)mode["raw"]!;
        };
        return GoalInterpret.LlmInterpreter("m", "f", c, a[4] is true, S(a[5])).Interpret(Req(Ont(a[0]), a[1], a[2], null));
    });

    [Fact]
    public void Vendor() => Base.Check(M, "vendor", a =>
    {
        var kind = S(a[1]);
        var cfg = O(a[2]); var fk = O(a[3]);
        var rq = new D();
        GoalInterpret.Fetch fetch = (url, method, headers, body) =>
        {
            rq["url"] = url; rq["method"] = method;
            var hs = new D();
            foreach (var h in headers) hs[h.Key] = h.Value;
            rq["headers"] = hs; rq["body"] = body;
            if (fk.GetValueOrDefault("throwMsg") != null) throw new Exception((string)fk["throwMsg"]!);
            // the oracle's two fixed-answer runs (an empty fake): the provider's own minimal success body
            if (!fk.ContainsKey("ok")) return new GoalInterpret.Fetched(true, 200, kind == "anthropic" ? "{\"content\":[{\"type\":\"text\",\"text\":\"x\"}]}" : "{\"choices\":[{\"message\":{\"content\":\"x\"}}]}");
            return new GoalInterpret.Fetched(fk.GetValueOrDefault("ok") is true, int.Parse(((Num)fk["status"]!).Raw, CultureInfo.InvariantCulture),
                fk.GetValueOrDefault("body") == null ? "null" : Pca.Canonicalize(fk["body"]));
        };
        int? mt = cfg.GetValueOrDefault("maxTokens") == null ? null : int.Parse(((Num)cfg["maxTokens"]!).Raw, CultureInfo.InvariantCulture);
        var c = kind == "anthropic"
            ? GoalInterpret.AnthropicCompletion(S(cfg["apiKey"])!, S(cfg["model"])!, fetch, mt)
            : GoalInterpret.OpenaiCompletion(S(cfg["apiKey"])!, S(cfg["model"])!, S(cfg.GetValueOrDefault("baseUrl")), fetch);
        var outp = new D();
        try { outp["text"] = c(new GoalInterpret.Prompt(S(a[4])!, S(a[5])!)); } catch (Exception e) { outp["error"] = e.Message; }
        outp["req"] = rq;
        return outp;
    });

    [Fact] public void InterpretRefundForm() => Base.Check(M, "interpretRefundForm", a => GoalInterpret.InterpretForm(a[0], O(a[1]), S(a[2])));
    [Fact] public void LexicalCompare() => Base.Check(M, "lexicalCompare", a => GoalInterpret.LexicalComparator(Ont(a[0]))(S(a[1])!, S(a[2])!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "sourceDigest", "slotStemsOf", "extractCandidates", "fillTemplateById", "buildPromptOf", "promptKeyOf", "replayLookup",
        "parseTemplateJSON", "groundedOf", "interpretRule", "interpretForm", "interpretLlm", "vendor", "interpretRefundForm", "lexicalCompare" }); Assert.Equal(4859, Base.Total(M)); }
}
