// GraphQL SDL or introspection JSON to drafts. Query fields are reads, Mutation fields are writes, Subscription fields are streaming reads; arguments and input
// objects are flattened to dotted params. There is no method signal; everything stays unreviewed.
using System.Text;
using static AtlasPca.ActionsKit.ImportCommon;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class GraphqlImporter
{
    // ---- model ----

    /// <summary>named (Name), list (Of) or nonnull (Of).</summary>
    public sealed class GqlType
    {
        public readonly string K; public readonly string? Name; public readonly GqlType? Of;
        internal GqlType(string k, string? name, GqlType? of) { K = k; Name = name; Of = of; }
        internal static GqlType Named(string n) => new("named", n, null);
        internal D ToJson() => K == "named" ? ImportJx.Obj(("k", K), ("name", Name)) : ImportJx.Obj(("k", K), ("of", Of!.ToJson()));
    }

    public sealed class GqlArg
    {
        public readonly string Name; public readonly string? Desc; public readonly GqlType Type;
        internal GqlArg(string name, GqlType type, string? desc) { Name = name; Type = type; Desc = desc; }
        internal D ToJson() { var m = ImportJx.Obj(("name", Name), ("type", Type.ToJson())); if (Desc != null) m["desc"] = Desc; return m; }
    }

    public sealed class GqlField
    {
        public readonly string Name; public readonly string? Desc; public readonly List<GqlArg> Args; public readonly GqlType Type; public readonly bool Deprecated;
        internal GqlField(string name, List<GqlArg> args, GqlType type, bool deprecated, string? desc) { Name = name; Args = args; Type = type; Deprecated = deprecated; Desc = desc; }
        internal D ToJson()
        {
            var m = ImportJx.Obj(("name", Name), ("args", new L(Args.Select(a => (object?)a.ToJson()))), ("type", Type.ToJson()), ("deprecated", Deprecated));
            if (Desc != null) m["desc"] = Desc;
            return m;
        }
    }

    public sealed class GqlTypeDef
    {
        public readonly string Kind, Name; public readonly List<GqlField> Fields; public readonly List<string> Values;
        internal GqlTypeDef(string kind, string name, List<GqlField> fields, List<string> values) { Kind = kind; Name = name; Fields = fields; Values = values; }
    }

    public sealed class GqlSchema
    {
        public readonly Dictionary<string, GqlTypeDef> Types = new();
        public string? Query, Mutation, Subscription;

        /// <summary>{types: [[name, {kind, name, fields, values}]...], query?, mutation?, subscription?}.</summary>
        public D ToJson()
        {
            var ts = new L();
            foreach (var (key, td) in Types)
                ts.Add(ImportJx.List(key, ImportJx.Obj(("kind", td.Kind), ("name", td.Name), ("fields", new L(td.Fields.Select(f => (object?)f.ToJson()))), ("values", Ak.ToL(td.Values)))));
            var m = ImportJx.Obj(("types", ts));
            if (Query != null) m["query"] = Query;
            if (Mutation != null) m["mutation"] = Mutation;
            if (Subscription != null) m["subscription"] = Subscription;
            return m;
        }
    }

    // ---- SDL lexer ----

    sealed class Tok
    {
        public readonly string T, V;
        public Tok(string t, string v) { T = t; V = v; }
    }

    static bool NameStart(char c) => c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    static bool NameChar(char c) => NameStart(c) || (c >= '0' && c <= '9');

    static List<Tok> Lex(string src, int maxTokens)
    {
        var o = new List<Tok>();
        int i = 0, n = src.Length;
        while (i < n)
        {
            char ch = src[i];
            Tok push;
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',' || ch == '﻿') { i++; continue; }
            if (ch == '#') { while (i < n && src[i] != '\n') i++; continue; }
            if (ch == '"')
            {
                if (string.CompareOrdinal(src, i, "\"\"\"", 0, 3) == 0)
                {
                    int j = i + 3;
                    var s = new StringBuilder();
                    while (j < n && string.CompareOrdinal(src, j, "\"\"\"", 0, 3) != 0)
                    {
                        if (string.CompareOrdinal(src, j, "\\\"\"\"", 0, 4) == 0) { s.Append("\"\"\""); j += 4; } else s.Append(src[j++]);
                    }
                    if (j >= n) throw new ActionKitError("bad_source", "unterminated GraphQL block string");
                    push = new Tok("str", s.ToString());
                    i = j + 3;
                }
                else
                {
                    int j = i + 1;
                    var s = new StringBuilder();
                    while (j < n && src[j] != '"')
                    {
                        if (src[j] == '\n') throw new ActionKitError("bad_source", "unterminated GraphQL string");
                        if (src[j] == '\\') { if (j + 1 < n) s.Append(src[j + 1]); j += 2; } else s.Append(src[j++]);
                    }
                    if (j >= n) throw new ActionKitError("bad_source", "unterminated GraphQL string");
                    push = new Tok("str", s.ToString());
                    i = j + 1;
                }
            }
            else if (NameStart(ch))
            {
                int j = i + 1;
                while (j < n && NameChar(src[j])) j++;
                push = new Tok("name", src.Substring(i, j - i));
                i = j;
            }
            else if (ch == '-' || (ch >= '0' && ch <= '9'))
            {
                int j = i + 1;
                while (j < n && (src[j] == '-' || src[j] == '+' || src[j] == '.' || (src[j] >= '0' && src[j] <= '9') || src[j] == 'e' || src[j] == 'E')) j++;
                push = new Tok("int", src.Substring(i, j - i));
                i = j;
            }
            else if (string.CompareOrdinal(src, i, "...", 0, 3) == 0) { push = new Tok("punct", "..."); i += 3; }
            else if ("!$&():=@[]{|}".IndexOf(ch) >= 0) { push = new Tok("punct", ch.ToString()); i++; }
            else throw new ActionKitError("bad_source", "unexpected character in GraphQL source at offset " + i);
            if (o.Count >= maxTokens) throw new ActionKitError("import_limit", "the GraphQL source has too many tokens");
            o.Add(push);
        }
        if (o.Count >= maxTokens) throw new ActionKitError("import_limit", "the GraphQL source has too many tokens");
        o.Add(new Tok("eof", ""));
        return o;
    }

    // ---- SDL parser (type system definitions only; executable documents are rejected) ----

    sealed class P
    {
        int i = 0;
        readonly List<Tok> toks;
        readonly GqlSchema schema;
        readonly int maxDepth;
        public P(List<Tok> toks, GqlSchema schema, int maxDepth) { this.toks = toks; this.schema = schema; this.maxDepth = maxDepth; }

        Tok Cur() => toks[i];
        Tok Next() { var t = toks[i]; if (t.T != "eof") i++; return t; }
        bool Is(string v) => Cur().T != "str" && Cur().V == v;
        bool Eat(string v) { if (Is(v)) { i++; return true; } return false; }
        void Expect(string v) { if (!Eat(v)) throw new ActionKitError("bad_source", "GraphQL parse error: expected '" + v + "' near '" + Clip(Cur().V, 30) + "'"); }
        string Name() { var t = Next(); if (t.T != "name") throw new ActionKitError("bad_source", "GraphQL parse error: expected a name near '" + Clip(t.V, 30) + "'"); return t.V; }
        string? Desc() => Cur().T == "str" ? Next().V : null;
        public bool Eof() => Cur().T == "eof";

        GqlType Type(int depth)
        {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "GraphQL type nesting is too deep");
            GqlType t;
            if (Eat("[")) { t = new GqlType("list", null, Type(depth + 1)); Expect("]"); } else t = GqlType.Named(Name());
            return Eat("!") ? new GqlType("nonnull", null, t) : t;
        }

        /// <summary>Skip a constant value (default values, directive arguments).</summary>
        void Value(int depth)
        {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "GraphQL value nesting is too deep");
            var t = Cur();
            if (t.T == "str") { i++; return; }
            if (t.T == "int" || t.T == "name") { i++; return; }
            if (Eat("[")) { while (!Is("]") && !Eof()) Value(depth + 1); Expect("]"); return; }
            if (Eat("{")) { while (!Is("}") && !Eof()) { Name(); Expect(":"); Value(depth + 1); } Expect("}"); return; }
            if (Eat("$")) { Name(); return; }
            throw new ActionKitError("bad_source", "GraphQL parse error: unexpected '" + Clip(t.V, 30) + "'");
        }

        bool Directives()
        {
            bool deprecated = false;
            while (Eat("@"))
            {
                var n = Name();
                if (n == "deprecated") deprecated = true;
                if (Eat("(")) { while (!Is(")") && !Eof()) { Name(); Expect(":"); Value(0); } Expect(")"); }
            }
            return deprecated;
        }

        List<GqlArg> Args()
        {
            var o = new List<GqlArg>();
            if (!Eat("(")) return o;
            while (!Is(")"))
            {
                if (Eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated argument list");
                var desc = Desc();
                if (desc != null && desc.Length == 0) desc = null;
                var name = Name();
                Expect(":");
                var type = Type(0);
                if (Eat("=")) Value(0);
                Directives();
                o.Add(new GqlArg(name, type, desc));
            }
            Expect(")");
            return o;
        }

        List<GqlField> Fields(bool input)
        {
            var o = new List<GqlField>();
            if (!Eat("{")) return o;
            while (!Is("}"))
            {
                if (Eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated field list");
                var desc = Desc();
                if (desc != null && desc.Length == 0) desc = null;
                var name = Name();
                var args = input ? new List<GqlArg>() : Args();
                Expect(":");
                var type = Type(0);
                if (input && Eat("=")) Value(0);
                var dep = Directives();
                o.Add(new GqlField(name, args, type, dep, desc));
            }
            Expect("}");
            return o;
        }

        public void Def()
        {
            Desc();
            var kw = Name();
            if (kw == "extend") { Def(); return; }
            if (kw == "schema")
            {
                Directives();
                Expect("{");
                while (!Is("}"))
                {
                    if (Eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated schema block");
                    var op = Name(); Expect(":"); var ty = Name();
                    if (op == "query") schema.Query = ty; else if (op == "mutation") schema.Mutation = ty; else if (op == "subscription") schema.Subscription = ty;
                }
                Expect("}");
                return;
            }
            if (kw == "scalar") { var n = Name(); Directives(); Merge(new GqlTypeDef("scalar", n, new List<GqlField>(), new List<string>())); return; }
            if (kw == "directive")
            {
                Expect("@"); Name(); Args();
                if (Cur().V == "repeatable") i++;
                if (Cur().V == "on") i++;
                Eat("|");
                Name();
                while (Eat("|")) Name();
                return;
            }
            if (kw == "type" || kw == "interface" || kw == "input")
            {
                var n = Name();
                if (Cur().V == "implements") { i++; Eat("&"); Name(); while (Eat("&")) Name(); }
                Directives();
                Merge(new GqlTypeDef(kw == "type" ? "object" : kw == "input" ? "input" : "interface", n, Fields(kw == "input"), new List<string>()));
                return;
            }
            if (kw == "union")
            {
                var n = Name(); Directives();
                if (Eat("=")) { Eat("|"); Name(); while (Eat("|")) Name(); }
                Merge(new GqlTypeDef("union", n, new List<GqlField>(), new List<string>()));
                return;
            }
            if (kw == "enum")
            {
                var n = Name(); Directives();
                var values = new List<string>();
                if (Eat("{"))
                {
                    while (!Is("}"))
                    {
                        if (Eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated enum");
                        Desc(); values.Add(Name()); Directives();
                    }
                    Expect("}");
                }
                Merge(new GqlTypeDef("enum", n, new List<GqlField>(), values));
                return;
            }
            throw new ActionKitError("bad_source", "GraphQL parse error: unsupported definition '" + Clip(kw, 30) + "' (only type-system definitions are imported)");
        }

        void Merge(GqlTypeDef d)
        {
            if (!schema.Types.TryGetValue(d.Name, out var old)) { schema.Types[d.Name] = d; return; }
            old.Fields.AddRange(d.Fields);
            old.Values.AddRange(d.Values);
        }
    }

    public static GqlSchema ParseGraphqlSdl(string src, int maxTokens = 2_000_000)
    {
        var toks = Lex(src, maxTokens);
        var schema = new GqlSchema();
        var p = new P(toks, schema, 32);
        while (!p.Eof()) p.Def();
        return schema;
    }

    // ---- introspection to model ----

    static GqlType IntrospectType(object? t, int depth)
    {
        if (depth > 16 || t is not D m) throw new ActionKitError("bad_source", "malformed introspection type reference");
        if (m.GetValueOrDefault("kind") is "NON_NULL") return new GqlType("nonnull", null, IntrospectType(m.GetValueOrDefault("ofType"), depth + 1));
        if (m.GetValueOrDefault("kind") is "LIST") return new GqlType("list", null, IntrospectType(m.GetValueOrDefault("ofType"), depth + 1));
        if (m.GetValueOrDefault("name") is not string nm) throw new ActionKitError("bad_source", "malformed introspection type reference");
        return GqlType.Named(nm);
    }

    static string? RootName(D s, string k) => s.GetValueOrDefault(k) is D o && o.GetValueOrDefault("name") is string n ? n : null;

    static GqlField? FieldOf(object? f)
    {
        if (f is not D m || m.GetValueOrDefault("name") is not string fname) return null;
        var args = new List<GqlArg>();
        if (m.GetValueOrDefault("args") is L al)
            foreach (var a in al)
            {
                if (a is not D ad || ad.GetValueOrDefault("name") is not string an) continue;
                args.Add(new GqlArg(an, IntrospectType(ad.GetValueOrDefault("type"), 0), ad.GetValueOrDefault("description") as string));
            }
        var type = !m.ContainsKey("type") ? GqlType.Named("String") : IntrospectType(m["type"], 0);
        return new GqlField(fname, args, type, m.GetValueOrDefault("isDeprecated") is true, m.GetValueOrDefault("description") as string);
    }

    static readonly Dictionary<string, string> Kinds = new() { ["OBJECT"] = "object", ["INPUT_OBJECT"] = "input", ["ENUM"] = "enum", ["SCALAR"] = "scalar", ["INTERFACE"] = "interface", ["UNION"] = "union" };

    public static GqlSchema FromIntrospection(object? doc)
    {
        var root = doc is D dd && dd.GetValueOrDefault("data") is D data ? data : doc;
        var s = root is D rd && rd.GetValueOrDefault("__schema") is D sch ? sch : null;
        if (s == null || s.GetValueOrDefault("types") is not L typeList) throw new ActionKitError("bad_source", "not a GraphQL introspection result (no __schema.types)");
        var schema = new GqlSchema();
        string? q = RootName(s, "queryType"), mu = RootName(s, "mutationType"), sub = RootName(s, "subscriptionType");
        if (!string.IsNullOrEmpty(q)) schema.Query = q;
        if (!string.IsNullOrEmpty(mu)) schema.Mutation = mu;
        if (!string.IsNullOrEmpty(sub)) schema.Subscription = sub;
        foreach (var to in typeList)
        {
            if (to is not D t) continue;
            if (t.GetValueOrDefault("name") is not string name || t.GetValueOrDefault("kind") is not string tk) continue;
            if (name.StartsWith("__", StringComparison.Ordinal)) continue;
            if (!Kinds.TryGetValue(tk, out var kind)) continue;
            var fieldsRaw = kind == "input" ? t.GetValueOrDefault("inputFields") : t.GetValueOrDefault("fields");
            var fields = new List<GqlField>();
            if (fieldsRaw is L fl) foreach (var f in fl) { var g = FieldOf(f); if (g != null) fields.Add(g); }
            var values = new List<string>();
            if (t.GetValueOrDefault("enumValues") is L evl) foreach (var e in evl) if (e is D ed && ed.GetValueOrDefault("name") is string en) values.Add(en);
            schema.Types[name] = new GqlTypeDef(kind, name, fields, values);
        }
        return schema;
    }

    // ---- model to JSON-schema-like to params ----

    static D? Scalar(string name) => name switch
    {
        "Int" => ImportJx.Obj(("type", "integer"), ("format", "int32")),
        "String" or "ID" => ImportJx.Obj(("type", "string")),
        "Boolean" => ImportJx.Obj(("type", "boolean")),
        "Float" => ImportJx.Obj(("type", "number")),
        "Date" => ImportJx.Obj(("type", "string"), ("format", "date")),
        "DateTime" => ImportJx.Obj(("type", "string"), ("format", "date-time")),
        "Email" => ImportJx.Obj(("type", "string"), ("format", "email")),
        "UUID" => ImportJx.Obj(("type", "string"), ("format", "uuid")),
        "URL" or "URI" => ImportJx.Obj(("type", "string"), ("format", "url")),
        _ => null,
    };

    sealed class R
    {
        public readonly D S; public readonly bool Nonnull;
        public R(D s, bool nonnull) { S = s; Nonnull = nonnull; }
    }

    /// <summary>A GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget.</summary>
    static R SchemaOf(GqlType t, GqlSchema gs, Ctx c, Budget bud, List<string> stack, string where)
    {
        bool nonnull = false;
        var cur = t;
        while (cur.K == "nonnull") { nonnull = true; cur = cur.Of!; }
        if (cur.K == "list") return new R(ImportJx.Obj(("type", "array"), ("items", SchemaOf(cur.Of!, gs, c, bud, stack, where).S)), nonnull);
        var name = cur.Name!;
        if (bud.Left-- <= 0)
        {
            if (!bud.Exhausted) { bud.Exhausted = true; AddTodo(c, where, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)"); }
            return new R(new D(), nonnull);
        }
        var sc = Scalar(name);
        if (sc != null) return new R(sc, nonnull);
        if (!gs.Types.TryGetValue(name, out var def))
        {
            AddTodo(c, where, "unknown_type", "type '" + Clip(name, 60) + "' is not defined in the schema (declared string)");
            return new R(new D(), nonnull);
        }
        if (def.Kind == "enum") return new R(ImportJx.Obj(("type", "string"), ("enum", Ak.ToL(def.Values.Distinct(StringComparer.Ordinal)))), nonnull);
        if (def.Kind == "scalar") return new R(ImportJx.Obj(("type", "string")), nonnull);
        if (def.Kind == "input")
        {
            if (stack.Contains(name)) { AddTodo(c, where, "cyclic_ref", "input type '" + Clip(name, 60) + "' is recursive (declared string; refine or drop)"); return new R(new D(), nonnull); }
            var properties = new D();
            var required = new L();
            var ns = new List<string>(stack) { name };
            foreach (var f in def.Fields)
            {
                var r = SchemaOf(f.Type, gs, c, bud, ns, where);
                var p = new D(r.S);
                if (ImportJx.Truthy(f.Desc)) p["description"] = f.Desc;
                PutProp(properties, f.Name, p);
                if (r.Nonnull) required.Add(f.Name);
            }
            return new R(ImportJx.Obj(("type", "object"), ("properties", properties), ("required", required)), nonnull);
        }
        AddTodo(c, where, "output_type", "type '" + Clip(name, 60) + "' is an output type and cannot be an argument (declared string)");
        return new R(new D(), nonnull);
    }

    public static D ImportGraphql(object? source, D opts)
    {
        var c = NewCtx("graphql", source, opts);
        var gs = source is string text ? ParseGraphqlSdl(text) : FromIntrospection(source);
        var roots = new[] { (gs.Query ?? "Query", "query"), (gs.Mutation ?? "Mutation", "mutation"), (gs.Subscription ?? "Subscription", "subscription") };
        foreach (var (rootName, op) in roots)
        {
            if (!gs.Types.TryGetValue(rootName, out var rt)) continue;
            var fs = rt.Fields.OrderBy(x => x.Name, Comparer<string>.Create(IntentJs.CompareUtf8)).ToList();
            foreach (var f in fs)
            {
                var where = op + " " + Clip(f.Name, 80);
                c.Root = null;
                var bud = NewBudget(c);
                var properties = new D();
                var required = new L();
                foreach (var a in f.Args)
                {
                    var r = SchemaOf(a.Type, gs, c, bud, new List<string>(), where + "(" + a.Name + ")");
                    var p = new D(r.S);
                    if (ImportJx.Truthy(a.Desc)) p["description"] = a.Desc;
                    PutProp(properties, a.Name, p);
                    if (r.Nonnull) required.Add(a.Name);
                }
                var parms = new D();
                FlattenObject(ImportJx.Obj(("type", "object"), ("properties", properties), ("required", required)), c, bud, where, parms);
                if (f.Deprecated) AddTodo(c, where, "deprecated", "the field is marked @deprecated");
                var d = new Draft
                {
                    Name = f.Name,
                    Title = ImportJx.Truthy(f.Desc) ? f.Desc!.Split('\n')[0] : f.Name,
                    Description = f.Desc,
                    Effects = new List<string> { op == "mutation" ? "update" : "read" },
                    Scope = "one",
                    Params = parms,
                };
                if (op == "subscription") d.Traits = WithTrait(null, "pca.bulk");
                if (op != "mutation") d.Idempotency = ImportJx.Obj(("mode", "natural"));
                d.Bindings = ImportJx.Obj(("graphql", ImportJx.Obj(("op", op), ("field", Clip(f.Name, 200)))));
                EmitDef(c, d);
            }
        }
        return Finish(c);
    }
}
