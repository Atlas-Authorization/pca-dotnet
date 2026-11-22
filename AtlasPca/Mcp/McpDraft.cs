using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mcp;

/// <summary>The v1 draft of a site action schema from an MCP tool list: JSON Schema flattening (local $ref, allOf, anyOf / oneOf), the
/// parameter declaration of each property and the verb of each tool. Pure over parsed JSON. Whatever cannot be represented is flagged
/// in <c>todo</c> and drafted as a string, which rejects every non-string value, so the draft fails closed until refined.</summary>
internal static partial class McpDraft
{
    const int MaxRefDepth = 8;
    const int MaxRefNodes = 20_000;
    static Regex NameRe => Rx.Get(@"^[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    static Regex IndexRe => Rx.Get(@"^(?:0|[1-9][0-9]{0,8})\z", RegexOptions.CultureInvariant);

    sealed class Ctx
    {
        public readonly object? Root;
        public readonly L Todo;
        public int? Left;
        public Ctx(object? root, L todo) { Root = root; Todo = todo; }
    }

    /// <summary>JavaScript <c>undefined</c> as opposed to JSON null.</summary>
    static readonly object Undef = AtlasPca.InteropJs.JsX.Undef; // one sentinel for every JS-semantics helper (JsX.Truthy reads it)

    static object? Get(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : null;
    static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);

    /// <summary><c>[...x]</c> of a schema member: absent or null is empty, a list copies, a string spreads by code point, else not iterable.</summary>
    static L Iter(object? x)
    {
        if (x == null) return new L();
        if (x is L l) return new L(l);
        if (x is string s)
        {
            var o = new L();
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(s.Substring(i, 2)); i++; }
                else o.Add(s[i].ToString());
            }
            return o;
        }
        throw JsX.TypeError("not iterable");
    }

    /// <summary>Follow a local <c>#/a/b</c> pointer in root; null when absent, not local, or not an object.</summary>
    internal static object? Pointer(object? root, string rf)
    {
        if (!rf.StartsWith("#/", StringComparison.Ordinal)) return null;
        var cur = root;
        foreach (var raw in rf[2..].Split('/'))
        {
            var seg = raw.Replace("~1", "/").Replace("~0", "~");
            if (cur is D m)
            {
                if (!m.TryGetValue(seg, out var nx)) return null;
                cur = nx;
            }
            else if (cur is L l)
            {
                if (!IndexRe.IsMatch(seg) || int.Parse(seg) >= l.Count) return null;
                cur = l[int.Parse(seg)];
            }
            else return null;
        }
        return cur is D || cur is L ? cur : null;
    }

    static bool TypeIsNull(object? m)
    {
        var t = Get(m, "type");
        if (t is string s) return s == "null";
        if (t is L l) return l.All(x => x is string xs && xs == "null");
        return false;
    }

    static L? StringEnum(object? m)
    {
        var e = Get(m, "enum");
        return e is L l && l.All(x => x is string) ? l : null;
    }

    static D Flatten(object? s, Ctx c, string where, int depth = 0)
    {
        if (s is not D && s is not L) return new D();
        c.Left = (c.Left ?? MaxRefNodes) - 1;
        if (c.Left < 0)
        {
            if (c.Left == -1) c.Todo.Add($"{where}: schema expansion stopped after {MaxRefNodes} nodes (declared string; refine or drop)");
            return new D();
        }
        if (depth > MaxRefDepth)
        {
            c.Todo.Add($"{where}: schema nesting or reference chain deeper than {MaxRefDepth} (declared string; refine or drop)");
            return new D();
        }
        var cur = JsX.Spread(s);
        if (Get(s, "$ref") is string rf)
        {
            var target = Pointer(c.Root, rf);
            if (target == null)
            {
                c.Todo.Add($"{where}: reference '{(rf.Length > 120 ? rf[..120] : rf)}' is not a local reference that resolves (declared string; refine or drop)");
                return new D();
            }
            var siblings = JsX.Spread(s);
            siblings.Remove("$ref");
            var merged = new D(Flatten(target, c, where, depth + 1));
            foreach (var (k, v) in siblings) merged[k] = v;
            cur = merged;
        }
        if (cur.GetValueOrDefault("allOf") is L allOf)
        {
            var rest = new D(cur);
            rest.Remove("allOf");
            var parts = new List<D>();
            foreach (var m in allOf) parts.Add(Flatten(m, c, where, depth + 1));
            var acc = new D();
            foreach (var m in parts)
            {
                var next = new D(acc);
                foreach (var (k, v) in m) next[k] = v;
                var props = JsX.Spread(acc.GetValueOrDefault("properties"));
                foreach (var (k, v) in JsX.Spread(m.GetValueOrDefault("properties"))) props[k] = v;
                next["properties"] = props;
                var req = Iter(acc.GetValueOrDefault("required"));
                req.AddRange(Iter(m.GetValueOrDefault("required")));
                next["required"] = req;
                acc = next;
            }
            cur = new D(acc);
            foreach (var (k, v) in rest) cur[k] = v;
        }
        var alts = cur.GetValueOrDefault("anyOf") ?? cur.GetValueOrDefault("oneOf");
        if (alts is L altList)
        {
            var rest = new D(cur);
            rest.Remove("anyOf");
            rest.Remove("oneOf");
            var live = new List<D>();
            foreach (var m in altList) { var f = Flatten(m, c, where, depth + 1); if (!TypeIsNull(f)) live.Add(f); }
            if (live.Count == 1)
            {
                var one = new D(live[0]);
                foreach (var (k, v) in rest) one[k] = v;
                return one;
            }
            var consts = new List<L?>();
            bool allConst = true;
            foreach (var m in live)
            {
                if (m.GetValueOrDefault("const") is string cs) consts.Add(new L { cs });
                else { var e = StringEnum(m); if (e == null) allConst = false; consts.Add(e); }
            }
            if (live.Count > 1 && allConst)
            {
                var uniq = new L();
                foreach (var l in consts) foreach (var x in l!) if (!uniq.Contains(x)) uniq.Add(x);
                var o = new D(rest) { ["type"] = "string", ["enum"] = uniq };
                return o;
            }
            c.Todo.Add($"{where}: a union of {live.Count} schemas has no schema representation (declared string; refine or drop)");
            return rest;
        }
        if (cur.ContainsKey("const") && !cur.ContainsKey("enum") && cur["const"] is string cst)
        {
            var o = new D(cur) { ["enum"] = new L { cst } };
            cur = o;
        }
        return cur;
    }

    /// <summary><c>Array.isArray(t) ? t.find(x =&gt; x !== 'null') : t</c> for the type member.</summary>
    static object? TypeOf(D s)
    {
        if (!s.ContainsKey("type")) return Undef;
        var t = s["type"];
        if (t is L l) { foreach (var x in l) if (!(x is string xs && xs == "null")) return x; return Undef; }
        return t;
    }

    /// <summary><c>description.slice(0, 1024)</c>: a string or array slices; any other truthy value has no slice (TypeError).</summary>
    static object? Slice1024(object? d)
    {
        if (d is string s) return s.Length > 1024 ? s[..1024] : s;
        if (d is L l) return new L(l.Take(1024));
        throw JsX.TypeError("slice is not a function");
    }

    static D DeclOf(string name, object? schema, bool required, Ctx c)
    {
        var s = Flatten(schema, c, "action.params." + name);
        var t = TypeOf(s);
        var bas = new D
        {
            ["semantic"] = s.GetValueOrDefault("x-pca-semantic") ?? "unknown",
            ["sensitivity"] = s.GetValueOrDefault("x-pca-sensitivity") ?? "material",
        };
        if (!required) bas["required"] = false;
        if (JsX.Truthy(s.GetValueOrDefault("description"))) bas["description"] = Slice1024(s["description"]);
        if (!JsX.Truthy(s.GetValueOrDefault("x-pca-semantic"))) c.Todo.Add($"action.params.{name}: semantic type");
        var enumStrings = StringEnum(s);
        var o = new D();
        void Base() { foreach (var (k, v) in bas) o[k] = v; }
        object? G(string k) => s.GetValueOrDefault(k);
        if (t is string ts)
        {
            if (ts == "integer")
            {
                o["type"] = "integer";
                Base();
                if (JsX.SafeInt(G("minimum"))) o["min"] = G("minimum");
                else if (JsX.SafeInt(G("exclusiveMinimum"))) o["min"] = JsX.Number(JsX.NumOf(G("exclusiveMinimum"))!.Value + 1);
                if (JsX.SafeInt(G("maximum"))) o["max"] = G("maximum");
                else if (JsX.SafeInt(G("exclusiveMaximum"))) o["max"] = JsX.Number(JsX.NumOf(G("exclusiveMaximum"))!.Value - 1);
                if (JsX.Truthy(G("x-pca-unit"))) o["unit"] = G("x-pca-unit");
                if (JsX.Truthy(G("x-pca-accumulates-into"))) o["accumulates_into"] = G("x-pca-accumulates-into");
                return o;
            }
            if (ts == "boolean") { o["type"] = "boolean"; Base(); return o; }
            if (ts == "string" && G("format") is string fmt && fmt == "date") { o["type"] = "date"; Base(); return o; }
            if (ts == "string")
            {
                o["type"] = "string";
                Base();
                if (enumStrings != null) o["values"] = enumStrings;
                if (JsX.SafeInt(G("maxLength")) && JsX.NumOf(G("maxLength"))!.Value > 0) o["max_len"] = G("maxLength");
                return o;
            }
            if (ts == "array")
            {
                var it = Flatten(G("items"), c, $"action.params.{name}[]");
                var itEnum = StringEnum(it);
                if (JsX.Truthy(G("uniqueItems")) && itEnum != null)
                {
                    o["type"] = "set";
                    Base();
                    o["values"] = itEnum;
                    if (JsX.SafeInt(G("minItems"))) o["min_items"] = G("minItems");
                    if (JsX.SafeInt(G("maxItems"))) o["max_items"] = G("maxItems");
                    return o;
                }
                var itRaw = it.GetValueOrDefault("type");
                object? itT = itRaw is L il ? (il.Count == 0 ? Undef : il[0]) : itRaw;
                o["type"] = "array";
                Base();
                if (itT is string its && its == "integer") o["items"] = "integer";
                if (JsX.SafeInt(G("maxItems"))) o["max_items"] = G("maxItems");
                if (JsX.SafeInt(G("minItems"))) o["min_items"] = G("minItems");
                return o;
            }
        }
        c.Todo.Add($"action.params.{name}: type '{(ReferenceEquals(t, Undef) ? "undefined" : JsX.Str(t))}' has no schema representation (declared string; refine or drop)");
        o["type"] = "string";
        Base();
        return o;
    }

    internal static D Draft(L tools, D site)
    {
        var todo = new L();
        var verbs = new List<D>();
        foreach (var t in tools)
        {
            if (t == null) throw JsX.TypeError("cannot read properties of null (reading 'inputSchema')");
            var c = new Ctx(Get(t, "inputSchema"), todo);
            var tname = JsX.Str(Has(t, "name") ? Get(t, "name") : "undefined");
            var input = Flatten(Get(t, "inputSchema"), c, tname + ": inputSchema");
            var props = input.GetValueOrDefault("properties") ?? new D();
            var req = Iter(input.GetValueOrDefault("required"));
            var pars = new D();
            var names = JsX.Keys(props);
            names.Sort(IntentJs.CompareUtf8);
            foreach (var name in names)
            {
                if (!NameRe.IsMatch(name))
                {
                    todo.Add($"{tname}: parameter '{name}' is not a schema name ([A-Za-z0-9_]{{1,64}}); rename it");
                    continue;
                }
                pars["action.params." + name] = DeclOf(name, JsX.ValueOf(props, name), req.Any(x => x is string xs && xs == name), c);
            }
            var ann = Get(t, "annotations");
            bool read = ann is D ad && ad.GetValueOrDefault("readOnlyHint") is bool b && b;
            var prefix = site.GetValueOrDefault("verbPrefix") ?? "";
            var verb = JsX.Str(prefix) + tname;
            if (!read) todo.Add($"{verb}: reversibility (drafted irreversible)");
            var v = new D { ["verb"] = verb, ["kind"] = read ? "read" : "write", ["params"] = pars, ["reversibility"] = read ? "reversible" : "irreversible" };
            var mcp = new D();
            if (Has(t, "name")) mcp["tool"] = Get(t, "name");
            v["mcp"] = mcp;
            if (JsX.Truthy(Get(t, "description"))) v["description"] = Slice1024(Get(t, "description"));
            verbs.Add(v);
        }
        var sorted = verbs.OrderBy(x => (string)x["verb"]!, Comparer<string>.Create(IntentJs.CompareUtf8)).Cast<object?>().ToList();
        var schema = new D { ["v"] = new Num("1"), ["kind"] = ActionSchema.ActionSchemaKind };
        foreach (var k in new[] { "site", "aud", "version" }) if (site.ContainsKey(k)) schema[k] = site[k];
        schema["verbs"] = sorted;
        return new D { ["schema"] = schema, ["todo"] = todo };
    }
}
