using System.Security.Cryptography;
using System.Text;
using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the suggestion rules, model assist and provider adapters of the importers against the TypeScript reference.</summary>
public class RefActionsImportSuggestTests
{
    const string M = "ref-actions-import-suggest";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    static D RulesOf(object? x) => x is "default" ? ImportRules.DefaultRules : (D)x!;
    static Dictionary<string, D> RegOf(object? x) => Actions.CoreRegistry;
    static Dictionary<string, D>? RegOrNone(object? x) => x is "core" ? Actions.CoreRegistry : null;

    sealed class SpecAdapter : IImportModelAdapter
    {
        readonly D spec;
        public SpecAdapter(D spec) { this.spec = spec; }
        public string Id => (string)spec["id"]!;
        public string? Version => spec.GetValueOrDefault("version") as string;
        public string Complete(D req)
        {
            if (spec.ContainsKey("throws")) throw new InvalidOperationException((string)spec["throws"]!);
            return !spec.ContainsKey("answer") ? "undefined" : spec["answer"] is string s ? s : AtlasPca.Js.JsJson.ToJsString(spec["answer"]);
        }
    }

    sealed class FakeResponse : ImportProviders.IFetchResponse
    {
        readonly D spec;
        public FakeResponse(D spec) { this.spec = spec; }
        public bool Ok => spec.GetValueOrDefault("ok") is not false;
        public int Status => spec.ContainsKey("status") ? (int)Base.Long(spec["status"]) : 200;
        public object? Json()
        {
            if (spec.GetValueOrDefault("badjson") is true) throw new InvalidOperationException("bad json");
            return spec.GetValueOrDefault("json");
        }
    }

    [Fact] public void Stem() => Base.Check(M, "stem", a => ImportSuggest.Stem((string)a[0]!));
    [Fact] public void FactsOf() => Base.Check(M, "factsOf", a => ImportSuggest.FactsOf((D)a[0]!).ToJson());
    [Fact] public void DefaultRules() => Base.Check(M, "DEFAULT_RULES", a => ImportRules.DefaultRules);
    [Fact] public void DefaultRulesDigest() => Base.Check(M, "DEFAULT_RULES_SEALED_DIGEST", a => ImportRules.DefaultRulesSealed["digest"]);

    [Fact]
    public void SuggestRulesError() => Base.Check(M, "suggestRulesError", a =>
        ImportSuggest.SuggestRulesError(a[0] is "default" ? ImportRules.DefaultRules : a[0], a.Count > 1 && a[1] is L k ? new HashSet<string>(k.Select(x => (string)x!)) : null));

    [Fact] public void RulesDigest() => Base.Check(M, "rulesDigest", a => ImportSuggest.RulesDigest(RulesOf(a[0])));
    [Fact] public void SealRules() => Base.Check(M, "sealRules", a => ImportSuggest.SealRules((D)a[0]!));
    [Fact] public void SignRules() => Base.Check(M, "signRules", a => ImportSuggest.SignRules((D)a[0]!, (string)a[1]!, Seed((string)a[2]!)));
    [Fact] public void VerifyRules() => Base.Check(M, "verifyRules", a => ImportSuggest.VerifyRules(a[0], ((L)a[1]!).Select(x => (D)x!)));

    [Fact]
    public void SuggestWithRules() => Base.Check(M, "suggestWithRules", a =>
        ImportSuggest.SuggestWithRules((D)a[0]!, RulesOf(a[1]), a.Count > 2 ? RegOrNone(a[2]) : null));

    [Fact] public void ApplySuggestion() => Base.Check(M, "applySuggestion", a => ImportSuggest.ApplySuggestion((D)a[0]!, (D)a[1]!, (D)a[2]!));
    [Fact] public void UnionSuggestions() => Base.Check(M, "unionSuggestions", a => ImportSuggest.UnionSuggestions((D)a[0]!, (D)a[1]!));
    [Fact] public void Vocabulary() => Base.Check(M, "vocabulary", a => ImportModel.Vocabulary(RegOf(a[0])));
    [Fact] public void PromptDigest() => Base.Check(M, "promptDigest", a => ImportModel.PromptDigest(RegOf(a[0])));
    [Fact] public void BuildRequest() => Base.Check(M, "buildRequest", a => ImportModel.BuildRequest((D)a[0]!, Actions.CoreRegistry));
    [Fact] public void ParseTraitList() => Base.Check(M, "parseTraitList", a => ImportModel.ParseTraitList((string)a[0]!, Actions.CoreRegistry));

    [Fact]
    public void SuggestWithModels() => Base.Check(M, "suggestWithModels", a =>
        ImportModel.SuggestWithModels((D)a[0]!, ((L)a[1]!).Select(x => (IImportModelAdapter)new SpecAdapter((D)x!)), Actions.CoreRegistry));

    [Fact] public void ModelConfigFromEnv() => Base.Check(M, "modelConfigFromEnv", a => ImportProviders.ModelConfigFromEnv((D)a[0]!, a[1] as D).ToMap());

    [Fact]
    public void ProviderAdapterComplete() => Base.Check(M, "providerAdapterComplete", a =>
    {
        var cfg = (D)a[0]!; var spec = (D)a[1]!; var req = (D)a[2]!;
        D? call = null;
        ImportProviders.IFetchResponse Fetch(string url, Dictionary<string, string> headers, string body, long timeoutMs)
        {
            call = new D { ["url"] = url, ["headers"] = headers.ToDictionary(kv => kv.Key, kv => (object?)kv.Value), ["body"] = body };
            if (spec.ContainsKey("throws")) throw new InvalidOperationException((string)spec["throws"]!);
            return new FakeResponse(spec);
        }
        var adapter = ImportProviders.ProviderAdapter(new ImportProviders.ModelEnvConfig((string)cfg["provider"]!, (string)cfg["model"]!, (string)cfg["apiKey"]!), Fetch);
        try { var text = adapter.Complete(req); return new D { ["call"] = null, ["text"] = text }; } // the oracle records the request only for a refusal
        catch (Exception e) { return new D { ["call"] = call, ["error"] = e.Message }; }
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "stem", "factsOf", "DEFAULT_RULES", "DEFAULT_RULES_SEALED_DIGEST", "suggestRulesError", "rulesDigest", "sealRules", "signRules", "verifyRules",
        "suggestWithRules", "applySuggestion", "unionSuggestions", "vocabulary", "promptDigest", "buildRequest", "parseTraitList", "suggestWithModels", "modelConfigFromEnv", "providerAdapterComplete" }); Assert.Equal(1236, Base.Total(M)); }
}
