// import then suggest as one call, the importer registry of the command line, and the text forms the CLI prints and reads (JSON Lines of defs). Pure: no
// file system, no network (the caller fetches and writes). YAML is not handled here: a YAML source is parsed by the caller and passed in as the
// already-parsed JSON tree.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ImportPipeline
{
    /// <summary>Kept for callers of the first importer: the default operation bound.</summary>
    public const int MaxImportOps = 20_000;

    /// <summary>Import one source of the given kind. Every def is unreviewed. opts: the common options (plus verb etc. for jsonschema).</summary>
    public static D ImportActions(string? kind, object? source, D opts)
    {
        string Kinds() => string.Join(", ", ImportCommon.ImportKinds);
        if (kind == null) throw new ActionKitError("bad_kind", "unknown import kind 'null' (one of " + Kinds() + ")");
        return kind switch
        {
            "openapi" => OpenApiImporter.ImportOpenApi(source, opts),
            "mcp" => McpImporter.ImportMcp(source, opts),
            "graphql" => GraphqlImporter.ImportGraphql(source, opts),
            "grpc" => GrpcImporter.ImportGrpc(source, opts),
            "asyncapi" => AsyncApiImporter.ImportAsyncApi(source, opts),
            "jsonschema" => JsonSchemaImporter.ImportJsonSchema(source, opts),
            _ => throw new ActionKitError("bad_kind", "unknown import kind '" + kind + "' (one of " + Kinds() + ")"),
        };
    }

    /// <summary>The command-line importer shape: {defs, todo: ["where: message"]}. A JSON Schema import needs verb in the options.</summary>
    public static D RunImporter(string kind, object? doc, D opts)
    {
        if (!ImportCommon.ImportKinds.Contains(kind)) throw new ArgumentException("no importer '" + kind + "'");
        if (kind == "jsonschema" && !ImportJx.Truthy(opts.GetValueOrDefault("verb"))) throw new ArgumentException("a JSON Schema import needs --verb <ns.noun.action>");
        var r = ImportActions(kind, doc, opts);
        var todo = new L();
        foreach (var t in (L)r["todo"]!) todo.Add(ImportJx.JsStr(ImportJx.Get(t, "where")) + ": " + ImportJx.JsStr(ImportJx.Get(t, "message")));
        return ImportJx.Obj(("defs", r["defs"]), ("todo", todo));
    }

    /// <summary>The importer registry of the command line, by source kind (mcp, openapi, graphql, grpc, asyncapi, jsonschema): each entry is
    /// <c>(document, options) -> {defs, todo: ["where: message"]}</c> as <see cref="RunImporter"/>.</summary>
    public static IReadOnlyDictionary<string, Func<object?, D, D>> Importers { get; } =
        ImportCommon.ImportKinds.ToDictionary(k => k, k => (Func<object?, D, D>)((doc, opts) => RunImporter(k, doc, opts)));

    /// <summary>What SuggestDefs reads: mode (rules default, model, none), rule set, registry, model adapters.</summary>
    public sealed class SuggestOpts
    {
        public string? Mode;
        public D? Rules;
        public Dictionary<string, D>? Registry;
        public IEnumerable<IImportModelAdapter>? Models;
    }

    /// <summary>Suggest for already imported defs. Returns {defs (state suggested), errors: [{verb, model, error}]}.</summary>
    public static D SuggestDefs(IEnumerable<D> defs, SuggestOpts? o = null)
    {
        var so = o ?? new SuggestOpts();
        var mode = so.Mode ?? "rules";
        if (mode == "none") return ImportJx.Obj(("defs", new L(defs)), ("errors", new L()));
        var registry = so.Registry ?? Actions.CoreRegistry;
        var rules = so.Rules ?? ImportRules.DefaultRules;
        var digest = ReferenceEquals(rules, ImportRules.DefaultRules) ? (string)ImportRules.DefaultRulesSealed["digest"]! : ImportSuggest.RulesDigest(rules);
        var output = new L(); var errors = new L();
        foreach (var d in defs)
        {
            var s = ImportSuggest.SuggestWithRules(d, rules, registry);
            L? models = null;
            if (mode == "model")
            {
                var run = ImportModel.SuggestWithModels(d, so.Models ?? new List<IImportModelAdapter>(), registry);
                foreach (var e in (L)run["errors"]!) { var m = new D { ["verb"] = d.GetValueOrDefault("verb") }; ImportJx.PutAll(m, (D)e!); errors.Add(m); }
                var tr = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var t in (L)s["traits"]!) tr.Add((string)t!);
                foreach (var t in (L)((D)run["suggestion"]!)["traits"]!) tr.Add((string)t!);
                s = ImportJx.Obj(("traits", Ak.ToL(tr)), ("roles", s["roles"]), ("tags", s["tags"]), ("fired", s["fired"]));
                models = (L)run["models"]!;
            }
            var by = ImportJx.Obj(("rules", ImportJx.Obj(("version", rules.GetValueOrDefault("version")), ("digest", digest), ("fired", s["fired"]))));
            if (models != null && models.Count > 0) by["models"] = models;
            output.Add(ImportSuggest.ApplySuggestion(d, s, by));
        }
        return ImportJx.Obj(("defs", output), ("errors", errors));
    }

    /// <summary>Import then suggest: the import report with defs replaced by the suggested defs, plus suggestErrors.</summary>
    public static D ImportAndSuggest(string kind, object? source, D opts, SuggestOpts? suggest)
    {
        var r = ImportActions(kind, source, opts);
        var defs = ((L)r["defs"]!).Select(d => (D)d!).ToList();
        var s = SuggestDefs(defs, suggest);
        var o = new D(r) { ["defs"] = s["defs"], ["suggestErrors"] = s["errors"] };
        return o;
    }

    // ---- JSON Lines ----

    /// <summary>One def per line, strict canonical JSON, sorted by verb: byte-reproducible.</summary>
    public static string DefsToJsonl(IEnumerable<D> defs)
    {
        var all = defs.ToList();
        var sorted = all.OrderBy(d => (string)d["verb"]!, StringComparer.Ordinal).ToList();
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < sorted.Count; i++) { if (i > 0) sb.Append('\n'); sb.Append(Pca.Canonicalize(sorted[i])); }
        if (all.Count > 0) sb.Append('\n');
        return sb.ToString();
    }

    /// <summary>Parse and validate a JSONL file of defs. Throws ActionKitError bad_defs naming the first bad line.</summary>
    public static List<D> JsonlToDefs(string text)
    {
        var o = new List<D>();
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var l = ImportJx.JsTrim(lines[i]);
            if (l.Length == 0) continue;
            object? v;
            try { v = Pca.ParseJson(l); } catch (Exception) { throw new ActionKitError("bad_defs", "line " + (i + 1) + ": not JSON"); }
            var bad = Actions.ValidateDef(v);
            if (bad != null) throw new ActionKitError("bad_defs", "line " + (i + 1) + ": " + bad);
            o.Add((D)v!);
        }
        return o;
    }
}
