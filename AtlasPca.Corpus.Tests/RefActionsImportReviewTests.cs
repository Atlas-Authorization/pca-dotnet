using System.Security.Cryptography;
using System.Text;
using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the import pipeline, the confirmation flow and the suggestion evaluation against the TypeScript reference.</summary>
public class RefActionsImportReviewTests
{
    const string M = "ref-actions-import-review";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    static IEnumerable<D> Defs(object? xs) => ((L)xs!).Select(x => (D)x!);

    sealed class SpecAdapter : IImportModelAdapter
    {
        readonly D spec;
        public SpecAdapter(D spec) { this.spec = spec; }
        public string Id => (string)spec["id"]!;
        public string? Version => spec.GetValueOrDefault("version") as string;
        public string Complete(D req)
        {
            if (spec.ContainsKey("throws")) throw new InvalidOperationException((string)spec["throws"]!);
            return spec.GetValueOrDefault("answer") as string ?? "null";
        }
    }

    static ImportPipeline.SuggestOpts SuggestOptsOf(D so)
    {
        var o = new ImportPipeline.SuggestOpts { Mode = so.GetValueOrDefault("mode") as string, Registry = Actions.CoreRegistry };
        if (so.GetValueOrDefault("rules") is "default")
        {
            var r = new D(ImportRules.DefaultRules) { ["rules"] = new L(((L)ImportRules.DefaultRules["rules"]!).Take(20)) };
            o.Rules = r;
        }
        if (so.GetValueOrDefault("models") is L ms) o.Models = ms.Select(x => (IImportModelAdapter)new SpecAdapter((D)x!)).ToList();
        return o;
    }

    // ---- eval ----
    [Fact] public void ParseHandTsv() => Base.Check(M, "parseHandTsv", a => ImportEval.ParseHandTsv((string)a[0]!));
    [Fact] public void ParseCorpusJsonl() => Base.Check(M, "parseCorpusJsonl", a => ImportEval.ParseCorpusJsonl((string)a[0]!));
    [Fact] public void RealSplit() => Base.Check(M, "realSplit", a => ImportEval.RealSplit(a.Count == 0 ? null : a[0]));
    [Fact] public void ImportCorpus() => Base.Check(M, "importCorpus", a => ImportEval.ImportCorpus((L)a[0]!));

    [Fact]
    public void EvalSuggest() => Base.Check(M, "evalSuggest", a =>
        ImportEval.EvalSuggest((L)a[0]!, (a.Count > 1 && a[1] is not "default") ? (D)a[1]! : null, Actions.CoreRegistry, a.Count > 2 ? IntentJs.NumOf(a[2]) : null));

    [Fact] public void RenderEvalMarkdown() => Base.Check(M, "renderEvalMarkdown", a => ImportEval.RenderEvalMarkdown((D)a[0]!));
    [Fact] public void FloorFailures() => Base.Check(M, "floorFailures", a => ImportEval.FloorFailures((D)a[0]!, (D)a[1]!));

    // ---- pipeline ----
    [Fact] public void ImportActions() => Base.Check(M, "importActions", a => ImportPipeline.ImportActions((string)a[0]!, a[1], (D)a[2]!));
    [Fact] public void Importers() => Base.Check(M, "IMPORTERS", a =>
        ImportPipeline.Importers.TryGetValue((string)a[0]!, out var f) ? f(a[1], (D)a[2]!) : throw new ArgumentException("no importer '" + a[0] + "'"));

    [Fact]
    public void TheRegistryHoldsEverySourceKind() =>
        Assert.Equal(new[] { "asyncapi", "graphql", "grpc", "jsonschema", "mcp", "openapi" }, ImportPipeline.Importers.Keys.OrderBy(k => k, StringComparer.Ordinal));
    [Fact] public void SuggestDefs() => Base.Check(M, "suggestDefs", a => ImportPipeline.SuggestDefs(Defs(a[0]), a.Count > 1 ? SuggestOptsOf((D)a[1]!) : null));
    [Fact] public void ImportAndSuggest() => Base.Check(M, "importAndSuggest", a => ImportPipeline.ImportAndSuggest((string)a[0]!, a[1], (D)a[2]!, SuggestOptsOf((D)a[3]!)));
    [Fact] public void DefsToJsonl() => Base.Check(M, "defsToJsonl", a => ImportPipeline.DefsToJsonl(Defs(a[0])));
    [Fact] public void JsonlToDefs() => Base.Check(M, "jsonlToDefs", a => ImportPipeline.JsonlToDefs((string)a[0]!));

    // ---- review ----
    [Fact] public void VerifyAttestation() => Base.Check(M, "verifyAttestation", a => ImportReview.VerifyAttestation((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void ReviewStatus() => Base.Check(M, "reviewStatus", a => ImportReview.ReviewStatus((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void RevertStale() => Base.Check(M, "revertStale", a => ImportReview.RevertStale((D)a[0]!, (D)a[1]!, Reg(a.Count > 2 ? a[2] : null)));
    [Fact] public void ReviewPriority() => Base.Check(M, "reviewPriority", a => ImportReview.ReviewPriority((D)a[0]!, Actions.CoreRegistry));
    [Fact] public void ReviewQueueOrder() => Base.Check(M, "reviewQueueOrder", a => ImportReview.ReviewQueueOrder(Defs(a[0]), Actions.CoreRegistry),
        // the full-registry case is generated as the verbs of the ordered defs
        eq: (c, have) => Base.Eq(c["out"], c["name"] is string n && n.EndsWith("/all") && have is IEnumerable<D> ds ? ds.Select(d => (object?)d["verb"]).ToList() : have));
    [Fact] public void PrepareReview() => Base.Check(M, "prepareReview", a => ImportReview.PrepareReview((D)a[0]!, Actions.CoreRegistry, a.Count > 1 ? (D)a[1]! : null));

    static Dictionary<string, D> Reg(object? rd) => rd == null ? Actions.CoreRegistry : Actions.ExtendRegistry(Actions.CoreRegistry, (L)rd);

    [Fact]
    public void ConfirmDef() => Base.Check(M, "confirmDef", a =>
    {
        var c = (D)a[1]!;
        // the other lane's shape: the seed is bytes, pins and dismissed may be empty (absent), and the registry carries custom definitions
        return ImportReview.ConfirmDef((D)a[0]!, Reg(c.GetValueOrDefault("regDefs")), (string)c["kid"]!, c["seed"] is string sd ? Seed(sd) : Base.Bytes(c["seed"]),
            c.GetValueOrDefault("pins") is D { Count: > 0 } pins ? pins : null, (L)c["finalTraits"]!, c.GetValueOrDefault("dismissed") is L { Count: > 0 } dis ? dis : null, c["ts"]);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "parseHandTsv", "parseCorpusJsonl", "realSplit", "importCorpus", "evalSuggest", "renderEvalMarkdown", "floorFailures", "importActions", "IMPORTERS",
        "suggestDefs", "importAndSuggest", "defsToJsonl", "jsonlToDefs", "verifyAttestation", "reviewStatus", "revertStale", "reviewPriority", "reviewQueueOrder", "prepareReview", "confirmDef" }); Assert.Equal(564, Base.Total(M)); }
}
