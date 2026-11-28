// The OpenAPI 3.x / Swagger 2, MCP tools/list, JSON Schema and AsyncAPI importers: foreign descriptions to unreviewed draft action defs.
using System.Text.RegularExpressions;
using static AtlasPca.ActionsKit.ImportCommon;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

/// <summary>OpenAPI 3.x and Swagger 2 to drafts: one def per operation; the method gives the initial effects.</summary>
public static class OpenApiImporter
{
    static readonly string[] Methods = { "get", "put", "post", "delete", "options", "head", "patch", "trace" };
    static readonly Dictionary<string, string> EffectOf = new() { ["get"] = "read", ["head"] = "read", ["options"] = "read", ["trace"] = "read", ["post"] = "create", ["put"] = "update", ["patch"] = "update", ["delete"] = "delete" };
    static readonly HashSet<string> Natural = new() { "get", "head", "options", "trace", "put", "delete" };
    static readonly string[] BodyTypes = { "application/json", "application/x-www-form-urlencoded", "multipart/form-data" };
    static readonly Regex Versionish = new("\\A(?:v[0-9]+(?:\\.[0-9]+)?|api|rest|public|latest)\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    static readonly Regex JsonSuffix = new("^application/[^;]*\\+json(?:;|\\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    static readonly Regex XVerb = new("\\A[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}\\z", RegexOptions.CultureInvariant);

    /// <summary>Follow a $ref chain (local only, bounded); returns the target (object or array), or null after noting why.</summary>
    static object? Deref(Ctx c, object? x, string where)
    {
        if (x is not D) return null;
        if (ImportJx.Get(x, "$ref") is not string) return x;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var cur = x;
        while (cur is D && ImportJx.Get(cur, "$ref") is string rf)
        {
            if (seen.Contains(rf) || seen.Count > c.Lim.MaxRefDepth) { AddTodo(c, where, "cyclic_ref", "a reference chain is cyclic or too deep"); return null; }
            seen.Add(rf);
            var t = Pointer(c.Root, rf);
            if (t == null) { AddTodo(c, where, "unresolved_ref", "reference '" + Clip(rf, 120) + "' does not resolve locally"); return null; }
            cur = t;
        }
        return cur;
    }

    static bool EndsWithParam(string seg)
    {
        if (seg.Length < 3 || seg[0] != '{' || seg[^1] != '}') return false;
        for (int i = 1; i < seg.Length - 1; i++) { var ch = seg[i]; if (ch == '\n' || ch == '\r' || ch == '\u2028' || ch == '\u2029') return false; }
        return true;
    }

    static (List<string> Nouns, bool Ewp) PathFacts(string path)
    {
        var segs = path.Split('/').Where(s => s.Length > 0).ToList();
        bool ewp = segs.Count > 0 && EndsWithParam(segs[^1]);
        var nouns = new List<string>();
        foreach (var s in segs) if (s.IndexOf('{') < 0 && s.IndexOf('}') < 0 && !Versionish.IsMatch(s)) nouns.AddRange(TokensOf(s));
        return (nouns, ewp);
    }

    /// <summary>A Swagger 2 parameter in the OpenAPI 3 shape the rest of the importer reads.</summary>
    static D Swagger2Param(D p)
    {
        if (p.ContainsKey("schema") || p.GetValueOrDefault("in") is "body") return p;
        var sch = new D(p);
        var o = new D();
        foreach (var k in new[] { "name", "in", "required", "description" }) { if (p.ContainsKey(k)) o[k] = p[k]; sch.Remove(k); }
        o["schema"] = sch;
        return o;
    }

    static string LowerTrimType(string k)
    {
        var l = k.ToLowerInvariant();
        int i = l.IndexOf(';');
        return ImportJx.JsTrim(i < 0 ? l : l.Substring(0, i));
    }

    /// <summary>The request body schema: ImportJx.Undef when there is none to declare.</summary>
    static object? BodySchemaOf(Ctx c, D op, List<D> parms, bool swagger, string where)
    {
        if (swagger)
        {
            foreach (var q in parms) if (q.GetValueOrDefault("in") is "body") return ImportJx.GetU(q, "schema");
            return ImportJx.Undef;
        }
        var rb = Deref(c, ReferenceEquals(ImportJx.GetU(op, "requestBody"), ImportJx.Undef) ? null : op["requestBody"], where);
        if (ImportJx.Get(rb, "content") is not D content) return ImportJx.Undef;
        var keys = new List<string>(content.Keys);
        keys.Sort(IntentJs.CompareUtf8);
        string? pick = null;
        foreach (var t in BodyTypes)
        {
            foreach (var k in keys) if (LowerTrimType(k) == t) { pick = k; break; }
            if (pick != null) break;
        }
        if (pick == null) foreach (var k in keys) if (JsonSuffix.IsMatch(k)) { pick = k; break; }
        if (pick == null)
        {
            if (keys.Count > 0)
            {
                var f = keys.Take(3).Select(k => Clip(k, 40));
                AddTodo(c, where, "body_type", "request body media types (" + string.Join(", ", f) + ") are not form or JSON; the body is not declared");
            }
            return ImportJx.Undef;
        }
        return ImportJx.GetU(content[pick], "schema");
    }

    static bool IsIdemKey(string name) => name.Length == 15 && name.ToLowerInvariant() == "idempotency-key" && name.All(ch => ch <= 0x7f);

    public static D ImportOpenApi(object? source, D opts)
    {
        var c = NewCtx("openapi", source, opts);
        if (source is not D src) throw new ActionKitError("bad_source", "an OpenAPI document must be an object");
        bool swagger = src.GetValueOrDefault("swagger") is string sw && sw.StartsWith("2", StringComparison.Ordinal);
        bool v3 = src.GetValueOrDefault("openapi") is string oa && oa.StartsWith("3.", StringComparison.Ordinal);
        if (!swagger && !v3) throw new ActionKitError("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')");
        var paths = src.GetValueOrDefault("paths") as D ?? new D();
        var globalSecurity = src.GetValueOrDefault("security") as L;
        var ns = (string)opts["ns"]!;
        var pathKeys = new List<string>(paths.Keys);
        pathKeys.Sort(IntentJs.CompareUtf8);
        foreach (var path in pathKeys)
        {
            var item0 = Deref(c, paths[path], path);
            if (item0 == null) continue;
            var shared = ImportJx.Get(item0, "parameters") as L ?? new L();
            foreach (var method in Methods)
            {
                if (ImportJx.Get(item0, method) is not D op) continue;
                var where = method.ToUpperInvariant() + " " + Clip(path, 120);
                var oid = op.GetValueOrDefault("operationId");
                string? operationId = oid is string os && os.Length > 0 && os.Length <= 200 ? os : null;
                var (nouns, ewp) = PathFacts(path);
                string? nameRaw = op.GetValueOrDefault("x-pca-verb") is string xv && c.Ext.Contains("x-pca-verb") ? xv : null;
                string verb;
                if (nameRaw != null && XVerb.IsMatch(nameRaw) && nameRaw.StartsWith(ns + ".", StringComparison.Ordinal)) verb = nameRaw;
                else if (operationId != null) verb = VerbOf(ns, operationId);
                else
                {
                    var w = new List<string>(nouns.GetRange(Math.Max(0, nouns.Count - 2), Math.Min(2, nouns.Count)));
                    w.Add(method == "get" && !ewp ? "list" : method);
                    verb = VerbOf(ns, string.Join(" ", w));
                }
                c.Root = source;
                var bud = NewBudget(c);
                // parameters: the operation's own win over the path item's (by in+name)
                var merged = new Dictionary<string, D>();
                var raws = new L(shared);
                if (op.GetValueOrDefault("parameters") is L opParams) raws.AddRange(opParams);
                foreach (var raw in raws)
                {
                    if (Deref(c, raw, where) is not D q0) continue;
                    if (q0.GetValueOrDefault("name") is not string || q0.GetValueOrDefault("in") is not string) continue;
                    var q = swagger ? Swagger2Param(q0) : q0;
                    merged[q["in"] + ":" + q["name"]] = q;
                }
                var all = merged.Values.ToList();
                var parms = new D();
                string? idemParam = null;
                var body = BodySchemaOf(c, op, all, swagger, where);
                if (!ReferenceEquals(body, ImportJx.Undef))
                {
                    var bsch = ResolveSchema(body, c, bud, where + ": request body");
                    if (bsch.GetValueOrDefault("type") is "object" || bsch.GetValueOrDefault("properties") is D) FlattenObject(bsch, c, bud, where, parms);
                    else AddTodo(c, where, "body_shape", "the request body is not an object schema; it is not declared");
                }
                var sorted = new List<D>(all);
                sorted.Sort((x, y) => IntentJs.CompareUtf8(x["in"] + ":" + x["name"], y["in"] + ":" + y["name"]));
                foreach (var q in sorted)
                {
                    var name = (string)q["name"]!;
                    var inLoc = q["in"];
                    if (inLoc is "header" && IsIdemKey(name)) { idemParam = "idempotency_key"; continue; }
                    if (inLoc is "body") continue;
                    if (inLoc is not "path" && inLoc is not "query" && inLoc is not "formData")
                    {
                        AddTodo(c, where, "param_location", Clip(inLoc, 12) + " parameter '" + Clip(name, 60) + "' is not an action parameter (path, query and body only)");
                        continue;
                    }
                    var sname = ParamSeg(name);
                    if (sname != name) AddTodo(c, where + ": " + name, "renamed_param", "parameter '" + Clip(name, 80) + "' is declared as '" + sname + "'");
                    bool taken = parms.ContainsKey(sname);
                    if (!taken) foreach (var k in parms.Keys) if (k.StartsWith(sname + ".", StringComparison.Ordinal)) { taken = true; break; }
                    if (taken)
                    {
                        AddTodo(c, where + ": " + name, "skipped_param", "'" + sname + "' is declared by the body and by a " + inLoc + " parameter; kept the body's");
                        continue;
                    }
                    if (parms.Count >= 64) { AddTodo(c, where, "too_many_params", "more than 64 parameters; the rest are dropped"); break; }
                    var merge = new D();
                    var qs = q.GetValueOrDefault("schema");
                    ImportJx.Spread(merge, qs ?? new D());
                    var qsDesc = qs == null ? null : ImportJx.Get(qs, "description");
                    if (ImportJx.Truthy(q.GetValueOrDefault("description")) && !ImportJx.Truthy(qsDesc)) merge["description"] = q["description"];
                    var sch = ResolveSchema(merge, c, bud, where + ": " + name);
                    parms[sname] = LeafParam(sch, inLoc is "path" || q.GetValueOrDefault("required") is true, c, bud, where + ": " + name);
                }
                if (idemParam != null && !parms.ContainsKey(idemParam)) parms[idemParam] = ImportJx.Obj(("type", "string"), ("required", false), ("max_len", ImportJx.N(255)));
                else idemParam = null;
                var scope = ewp || method == "post" ? "one" : "set";
                bool natural = Natural.Contains(method);
                // security scopes are a note, not a field
                var sec = op.GetValueOrDefault("security") as L ?? globalSecurity;
                var scopes = new List<string>();
                if (sec != null)
                {
                    var u = new List<string>();
                    foreach (var r in sec) if (r is D rd) foreach (var v in rd.Values) if (v is L vl) foreach (var x in vl) if (x is string xs && !u.Contains(xs)) u.Add(xs);
                    scopes.AddRange(u);
                    scopes.Sort(IntentJs.CompareUtf8);
                }
                if (scopes.Count > 0) AddTodo(c, where, "required_scope", "requires scope: " + string.Join(", ", scopes.Take(12).Select(s => Clip(s, 60))));
                if (op.GetValueOrDefault("deprecated") is true) AddTodo(c, where, "deprecated", "the operation is marked deprecated");
                foreach (var k in ImportJx.Keys(op)) if (k.StartsWith("x-", StringComparison.Ordinal) && !c.Ext.Contains(k)) { AddTodo(c, where, "extension_ignored", "extension '" + Clip(k, 60) + "' is ignored (not allow-listed)"); break; }
                var d = new Draft
                {
                    Name = operationId != null ? operationId : where,
                    NoAlias = operationId == null,
                    Verb = verb,
                    Title = op.GetValueOrDefault("summary") is string sm && sm.Length > 0 ? sm : operationId,
                    Description = op.GetValueOrDefault("description") is string ds ? ds : op.GetValueOrDefault("summary") is string sm2 ? sm2 : null,
                    Effects = new List<string> { EffectOf[method] },
                    Scope = scope,
                    Params = parms,
                };
                if (idemParam != null) d.Idempotency = ImportJx.Obj(("mode", "key_param"), ("param", idemParam));
                else if (natural) d.Idempotency = ImportJx.Obj(("mode", "natural"));
                d.Bindings = ImportJx.Obj(("openapi", ImportJx.Obj(("operationId", operationId != null ? operationId : Clip(method + "_" + path, 200)), ("method", method.ToUpperInvariant()), ("path", Clip(path, 240)))));
                EmitDef(c, d);
            }
        }
        return Finish(c);
    }
}

/// <summary>MCP tools/list to drafts. The annotations are hints from the tool's own server and are untrusted: they can only add restriction (destructive,
/// network egress) or describe a harmless-looking shape; every output is unreviewed.</summary>
public static class McpImporter
{
    /// <summary>tools/list result {tools: [...]}, or the tool array itself.</summary>
    public static D ImportMcp(object? source, D opts)
    {
        var c = NewCtx("mcp", source, opts);
        var tools = source as L ?? (source is D sd ? sd.GetValueOrDefault("tools") as L : null);
        if (tools == null) throw new ActionKitError("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in tools)
        {
            if (raw is not D t || t.GetValueOrDefault("name") is not string name || name.Length == 0 || name.Length > 256)
            {
                AddTodo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped");
                continue;
            }
            if (seen.Contains(name)) { AddTodo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept"); continue; }
            seen.Add(name);
            c.Root = t.GetValueOrDefault("inputSchema");
            var bud = NewBudget(c);
            var input = ResolveSchema(t.GetValueOrDefault("inputSchema"), c, bud, name + ": inputSchema");
            var parms = new D();
            FlattenObject(input, c, bud, name, parms);
            var a = t.GetValueOrDefault("annotations") as D ?? new D();
            // readOnly claims safety, so it is honoured only when nothing contradicts it
            bool read = a.GetValueOrDefault("readOnlyHint") is true && a.GetValueOrDefault("destructiveHint") is not true;
            var effects = read ? new List<string> { "read" } : a.GetValueOrDefault("destructiveHint") is true ? new List<string> { "update", "delete" } : new List<string> { "update" };
            var d = new Draft
            {
                Name = name,
                Title = a.GetValueOrDefault("title") is string at && at.Length > 0 ? at : t.GetValueOrDefault("title"),
                Description = t.GetValueOrDefault("description"),
                Effects = effects,
                Scope = "one",
                Params = parms,
            };
            if (a.GetValueOrDefault("idempotentHint") is true) d.Idempotency = ImportJx.Obj(("mode", "natural"));
            if (a.GetValueOrDefault("openWorldHint") is true) d.Traits = WithTrait(null, "pca.network_egress");
            d.Bindings = ImportJx.Obj(("mcp", ImportJx.Obj(("tool", Clip(name, 256)))));
            EmitDef(c, d);
        }
        return Finish(c);
    }
}

/// <summary>"I have a function signature": one JSON Schema plus a verb the caller gives, to one def.</summary>
public static class JsonSchemaImporter
{
    /// <summary>opts: the common import options plus verb (required, in the namespace), title, description, effects (default update).</summary>
    public static D ImportJsonSchema(object? schema, D opts)
    {
        var c = NewCtx("jsonschema", schema, opts);
        var verbO = opts.GetValueOrDefault("verb");
        var ns = (string)opts["ns"]!;
        if (verbO is not string verb || !VerbRe.IsMatch(verb) || !verb.StartsWith(ns + ".", StringComparison.Ordinal)) throw new ActionKitError("bad_verb", "verb must be a valid verb in namespace '" + ns + "'");
        var effO = opts.GetValueOrDefault("effects") ?? ImportJx.List("update");
        if (effO is not L effL || effL.Count == 0 || !effL.All(e => e is string es && Ak.Effects.Contains(es))) throw new ActionKitError("bad_effects", "effects must be 1+ known effects");
        var effects = effL.Select(e => (string)e!).ToList();
        if (schema is not D) throw new ActionKitError("bad_source", "a JSON Schema must be an object");
        var bud = NewBudget(c);
        var root = ResolveSchema(schema, c, bud, verb);
        var parms = new D();
        if (root.GetValueOrDefault("type") is "object" || root.GetValueOrDefault("properties") is D) FlattenObject(root, c, bud, verb, parms);
        else AddTodo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters");
        var parts = verb.Split('.');
        var d = new Draft
        {
            Name = string.Join("_", parts.Skip(1)),
            Verb = verb,
            Title = opts.GetValueOrDefault("title") ?? (root.GetValueOrDefault("title") is string rt ? rt : null),
            Description = opts.GetValueOrDefault("description") ?? Clip(root.GetValueOrDefault("description"), 600),
            Effects = effects,
            Scope = "one",
            Params = parms,
            Bindings = new D(),
        };
        EmitDef(c, d);
        return Finish(c);
    }
}

/// <summary>AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect send, receiving is read; the message payload becomes the params. A broker publish
/// leaves the trust domain, so it stays send unless the channel carries the allow-listed x-pca-internal: true.</summary>
public static class AsyncApiImporter
{
    static readonly Regex Version = new("^[23]\\.", RegexOptions.CultureInvariant);

    static D? Deref(Ctx c, object? x, string where, int depth = 0)
    {
        if (x is not D m) return null;
        if (m.GetValueOrDefault("$ref") is not string rf) return m;
        if (depth > c.Lim.MaxRefDepth) { AddTodo(c, where, "ref_depth", "a reference chain is too deep"); return null; }
        var t = Pointer(c.Root, rf);
        if (t == null) { AddTodo(c, where, "unresolved_ref", "reference '" + Clip(rf, 120) + "' does not resolve locally"); return null; }
        return Deref(c, t, where, depth + 1);
    }

    static void PayloadParams(Ctx c, L msgs, string where, D parms, Budget bud)
    {
        var resolved = new List<D>();
        foreach (var m in msgs) { var r = Deref(c, m, where); if (r != null) resolved.Add(r); }
        if (resolved.Count == 0) return;
        if (resolved.Count > 1) AddTodo(c, where, "message_variants", resolved.Count + " message variants: only the first is declared");
        var payload = ImportJx.GetU(resolved[0], "payload");
        if (ReferenceEquals(payload, ImportJx.Undef)) return;
        var s = ResolveSchema(payload, c, bud, where + ": payload");
        if (s.GetValueOrDefault("type") is "object" || s.GetValueOrDefault("properties") is D) FlattenObject(s, c, bud, where, parms);
        else AddTodo(c, where, "payload_shape", "the message payload is not an object schema; it is not declared");
    }

    static void ChannelParams(Ctx c, D ch, string where, D parms)
    {
        var ps = Deref(c, ch.GetValueOrDefault("parameters"), where);
        if (ps == null) return;
        var names = new List<string>(ps.Keys);
        names.Sort(IntentJs.CompareUtf8);
        foreach (var name in names)
        {
            var s = ParamSeg(name);
            if (parms.ContainsKey(s)) continue;
            parms[s] = ImportJx.Obj(("type", "string"), ("max_len", ImportJx.N(256)));
        }
    }

    static void Emit(Ctx c, D source, string ns, string? opName, string chName, D ch, string action, D op, L msgs)
    {
        var where = action + " " + Clip(chName, 100);
        var bud = NewBudget(c);
        c.Root = source;
        var parms = new D();
        ChannelParams(c, ch, where, parms);
        PayloadParams(c, msgs, where, parms, bud);
        bool internalCh = c.Ext.Contains("x-pca-internal") && ch.GetValueOrDefault("x-pca-internal") is true;
        var d = new Draft
        {
            Name = opName != null ? opName : where,
            NoAlias = opName == null,
            Verb = opName == null ? VerbOf(ns, chName + " " + action) : null,
            Title = op.GetValueOrDefault("summary") as string,
            Description = op.GetValueOrDefault("description") as string,
            Effects = new List<string> { action == "receive" ? "read" : internalCh ? "create" : "send" },
            Scope = "one",
            Params = parms,
            Bindings = ImportJx.Obj(("asyncapi", ImportJx.Obj(("channel", Clip(chName, 250)), ("op", action)))),
        };
        EmitDef(c, d);
    }

    public static D ImportAsyncApi(object? source, D opts)
    {
        var c = NewCtx("asyncapi", source, opts);
        if (source is not D src || src.GetValueOrDefault("asyncapi") is not string av || !Version.IsMatch(av))
            throw new ActionKitError("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')");
        var ns = (string)opts["ns"]!;
        bool v3 = av.StartsWith("3", StringComparison.Ordinal);
        var channels = src.GetValueOrDefault("channels") as D ?? new D();
        if (v3)
        {
            var ops = src.GetValueOrDefault("operations") as D ?? new D();
            var ids = new List<string>(ops.Keys);
            ids.Sort(IntentJs.CompareUtf8);
            foreach (var id in ids)
            {
                var op = Deref(c, ops[id], id);
                if (op == null || (op.GetValueOrDefault("action") is not "send" && op.GetValueOrDefault("action") is not "receive")) { AddTodo(c, id, "skipped_op", "an operation without action send|receive is skipped"); continue; }
                var chRef = Deref(c, op.GetValueOrDefault("channel"), id);
                if (chRef == null) continue;
                string chName;
                if (chRef.GetValueOrDefault("address") is string addr) chName = addr;
                else if (op.GetValueOrDefault("channel") is D chd && chd.GetValueOrDefault("$ref") is string chRefStr)
                {
                    var p = chRefStr.Split('/');
                    chName = p[^1];
                }
                else chName = id;
                L msgs;
                if (op.GetValueOrDefault("messages") is L ml && ml.Count > 0) msgs = ml;
                else if (chRef.GetValueOrDefault("messages") is D cm)
                {
                    var ks = new List<string>(cm.Keys);
                    ks.Sort(IntentJs.CompareUtf8);
                    msgs = new L();
                    foreach (var k in ks) msgs.Add(cm[k]);
                }
                else msgs = new L();
                Emit(c, src, ns, id, chName, chRef, (string)op["action"]!, op, msgs);
            }
        }
        else
        {
            var chNames = new List<string>(channels.Keys);
            chNames.Sort(IntentJs.CompareUtf8);
            foreach (var chName in chNames)
            {
                var ch = Deref(c, channels[chName], chName);
                if (ch == null) continue;
                // 2.x: publish is what a client does to the channel (a send); subscribe is what a client receives
                foreach (var (key, act) in new[] { ("publish", "send"), ("subscribe", "receive") })
                {
                    var op = Deref(c, ch.GetValueOrDefault(key), chName);
                    if (op == null) continue;
                    var m = Deref(c, op.GetValueOrDefault("message"), chName);
                    L msgs = m != null && m.GetValueOrDefault("oneOf") is L oneOf ? oneOf : m != null ? ImportJx.List(m) : new L();
                    string? oid = op.GetValueOrDefault("operationId") is string os && os.Length > 0 ? os : null;
                    Emit(c, src, ns, oid, chName, ch, act, op, msgs);
                }
            }
        }
        return Finish(c);
    }
}
