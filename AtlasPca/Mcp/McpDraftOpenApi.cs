using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mcp;

/// <summary>The v1 draft of a site action schema from an OpenAPI document: one verb per operation with an operationId (<c>x-pca-verb</c> names it, else the id). The parameters are the operation's path and query parameters
/// (path-item parameters included, the operation's own winning) plus the properties of its JSON request body; local $refs are followed. Header and cookie parameters are not action parameters and are noted in <c>todo</c>,
/// as is any name two sources share (the body declaration is kept). Every write verb is drafted irreversible unless the operation says otherwise.</summary>
internal static partial class McpDraft
{
    static Regex JsonMediaRe => Rx.Get(@"^application/[^;]*\+json(;|$)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>The schema of the JSON media type of a request body: <c>application/json</c> first, else any <c>application/*+json</c>.</summary>
    static object? OpenApiBodySchema(object? b)
    {
        if (Get(b, "content") is not D content) return Undef;
        var keys = content.Keys.ToList();
        keys.Sort(IntentJs.CompareUtf8);
        foreach (var k in keys) if (k.ToLowerInvariant() == "application/json") return Get(content[k], "schema");
        foreach (var k in keys) if (JsonMediaRe.IsMatch(k)) return Get(content[k], "schema");
        return Undef;
    }

    internal static D DraftOpenApi(object? doc, object? siteO)
    {
        if (siteO is not D site) throw JsX.TypeError("draftSchemaFromOpenApi: site must be an object");
        var todo = new L();
        var c = new Ctx(doc, todo);
        var verbs = new List<D>();
        object? Deref(object? x)
        {
            if (x is not D) return Undef;
            if (Get(x, "$ref") is not string rf) return x;
            var t = Pointer(doc, rf);
            if (t == null)
            {
                todo.Add($"reference '{(rf.Length > 120 ? rf[..120] : rf)}' is not a local reference that resolves");
                return Undef;
            }
            return t;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var paths = Get(doc, "paths") as D ?? new D();
        var pathKeys = paths.Keys.ToList();
        pathKeys.Sort(IntentJs.CompareUtf8);
        foreach (var path in pathKeys)
        {
            if (paths[path] is not D ops) continue;
            var shared = ops.GetValueOrDefault("parameters") as L ?? new L();
            var methods = ops.Keys.ToList();
            methods.Sort(IntentJs.CompareUtf8);
            foreach (var method in methods)
            {
                if (ops[method] is not D op || !JsX.Truthy(op.GetValueOrDefault("operationId"))) continue;
                var opId = JsX.Str(op["operationId"]);
                c.Left = MaxRefNodes;
                bool read;
                var kindO = op.GetValueOrDefault("x-pca-kind");
                if (JsX.Truthy(kindO)) read = kindO is string ks && ks == "read";
                else { var m = method.ToLowerInvariant(); read = m == "get" || m == "head"; }
                var verb = op.GetValueOrDefault("x-pca-verb") is { } vo ? JsX.Str(vo) : opId;
                if (seen.Contains(verb)) todo.Add($"{verb}: declared by more than one operation; give each a distinct x-pca-verb");
                seen.Add(verb);
                var pars = new D();
                void AddName(string name, object? sch, bool required, string source)
                {
                    if (!NameRe.IsMatch(name)) { todo.Add($"{opId}: parameter '{name}' is not a schema name; rename it"); return; }
                    var key = "action.params." + name;
                    if (pars.ContainsKey(key)) { todo.Add($"{opId}: '{name}' is declared by both the {source} and another source; kept the first"); return; }
                    pars[key] = DeclOf(name, sch, required, c);
                }
                // the request body first (it wins a name clash), then the operation's own parameters over the path item's
                var body = Flatten(OpenApiBodySchema(Deref(op.GetValueOrDefault("requestBody"))), c, opId + ": request body");
                var bprops = body.GetValueOrDefault("properties");
                var breq = new HashSet<string>(StringComparer.Ordinal);
                if (body.GetValueOrDefault("required") is { } r) foreach (var x in Iter(r)) if (x is string xs) breq.Add(xs);
                var names = JsX.Keys(bprops ?? new D());
                names.Sort(IntentJs.CompareUtf8);
                foreach (var name in names) AddName(name, JsX.ValueOf(bprops, name), breq.Contains(name), "request body");
                var merged = new Dictionary<string, D>(StringComparer.Ordinal);
                var own = op.GetValueOrDefault("parameters") as L ?? new L();
                foreach (var raw in shared.Concat(own))
                {
                    if (Deref(raw) is not D q || q.GetValueOrDefault("name") is not string qn || q.GetValueOrDefault("in") is not string qi) continue;
                    merged[qi + ":" + qn] = q;
                }
                var mkeys = merged.Keys.ToList();
                mkeys.Sort(IntentJs.CompareUtf8);
                foreach (var key in mkeys)
                {
                    var q = merged[key];
                    var inn = (string)q["in"]!;
                    var name = (string)q["name"]!;
                    if (inn != "path" && inn != "query")
                    {
                        todo.Add($"{opId}: {inn} parameter '{name}' is not an action parameter (the schema sees path, query and body parameters only)");
                        continue;
                    }
                    var sch = JsX.Spread(q.GetValueOrDefault("schema"));
                    if (JsX.Truthy(q.GetValueOrDefault("description")) && !JsX.Truthy(sch.GetValueOrDefault("description"))) sch["description"] = q["description"];
                    AddName(name, sch, inn == "path" || q.GetValueOrDefault("required") is true, inn + " parameters");
                }
                var rO = op.GetValueOrDefault("x-pca-reversibility");
                object? rev = rO ?? (read ? "reversible" : "irreversible");
                if (!read && !JsX.Truthy(rO)) todo.Add($"{verb}: reversibility (drafted irreversible)");
                var entry = new D { ["verb"] = verb, ["kind"] = read ? "read" : "write", ["params"] = pars, ["reversibility"] = rev, ["openapi"] = new D { ["operationId"] = op["operationId"] } };
                if (JsX.Truthy(op.GetValueOrDefault("description"))) entry["description"] = Slice1024(op["description"]);
                verbs.Add(entry);
            }
        }
        var sorted = verbs.OrderBy(x => (string)x["verb"]!, Comparer<string>.Create(IntentJs.CompareUtf8)).Cast<object?>().ToList();
        var schema = new D { ["v"] = new Num("1"), ["kind"] = ActionSchema.ActionSchemaKind };
        foreach (var k in new[] { "site", "aud", "version" }) if (site.ContainsKey(k)) schema[k] = site[k];
        schema["verbs"] = sorted;
        return new D { ["schema"] = schema, ["todo"] = todo };
    }
}
