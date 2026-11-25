// What every importer shares: result shapes, text hygiene, verb naming, the bounded $ref resolver, the JSON Schema to parameter flattening, and the
// single place a draft def is assembled (always unreviewed). Sources, reports and defs are JSON trees (Dictionary / List / string / bool / Num / null).
using System.Text;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ImportCommon
{
    public static readonly string[] ImportKinds = { "openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema" };
    public static readonly string[] DefaultExtensions = { "x-pca-verb", "x-pca-role", "x-pca-internal" };

    static Regex Full(string p) => new("\\A(?:" + p + ")\\z", RegexOptions.CultureInvariant);
    internal static readonly Regex NsRe = Full("[a-z][a-z0-9_]{0,31}");
    internal static readonly Regex VerbRe = Full("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}");
    internal static readonly Regex AliasRe = Full("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}");
    static readonly Regex IdRoleRe = Full("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}");
    static readonly Regex XRoleRe = Full("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}");
    static readonly Regex RtypeRe = Full("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}");
    static readonly Regex IndexRe = Full("0|[1-9][0-9]{0,9}");
    const int MaxTitleBytes = 120, MaxDescriptionBytes = 1024, MaxDefParams = 64, MaxParamPathDepth = 3;

    /// <summary>Per-import state: the namespace, limits, notes, source reference and what is already emitted.</summary>
    public sealed class Ctx
    {
        public readonly string Ns, Kind;
        public readonly ImportLimits Lim;
        public readonly L Todo = new();
        public readonly D Source;
        public readonly HashSet<object?> Ext;
        /// <summary>Parsed-source root that #/... references resolve in.</summary>
        public object? Root;
        internal readonly HashSet<string> Verbs = new();
        internal readonly Dictionary<string, string> Aliases = new();
        internal readonly L Defs = new();

        internal Ctx(string ns, string kind, ImportLimits lim, D source, HashSet<object?> ext, object? root)
        {
            Ns = ns; Kind = kind; Lim = lim; Source = source; Ext = ext; Root = root;
        }
    }

    /// <summary>The expansion budget of one operation: every schema node visited costs one.</summary>
    public sealed class Budget
    {
        public int Left;
        public bool Exhausted;
        internal Budget(int left) { Left = left; }
    }

    public static Budget NewBudget(Ctx c) => new((int)c.Lim.MaxRefNodes);

    public static Ctx NewCtx(string kind, object? source, D opts)
    {
        var nso = opts.GetValueOrDefault("ns");
        if (nso is not string ns || !NsRe.IsMatch(ns)) throw new ActionKitError("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}");
        var lim = ImportLimits.Resolve(opts.GetValueOrDefault("limits"));
        string digest;
        if (source is string text)
        {
            lim.TextSizeCheck(text);
            digest = ImportJx.Sha256B64u(ImportJx.Utf8(text));
        }
        else if (source is byte[] bytes)
        {
            if (bytes.Length > lim.MaxBytes) throw new ActionKitError("import_limit", "the source is larger than " + lim.MaxBytes + " bytes");
            digest = ImportJx.Sha256B64u(bytes);
        }
        else
        {
            lim.CheckParsed(source);
            digest = HashSuites.HashCanonicalLenient(source) ?? ImportJx.Sha256B64u(ImportJx.Utf8(Pca.Canonicalize(source))); // the reference hashes the lenient form
        }
        var now = opts.GetValueOrDefault("now") ?? ImportJx.N(0);
        if (!ImportJx.IsSafe(now) || ImportJx.Dbl(now)! < 0) throw new ActionKitError("bad_opts", "now must be a non-negative integer");
        var uri = opts.GetValueOrDefault("uri") ?? ("source:" + kind);
        var lic = opts.GetValueOrDefault("licence") ?? "unknown";
        var src = ImportJx.Obj(("kind", kind), ("uri", Clip(uri, 2048)), ("spec_digest", digest), ("licence", Clip(lic, 128)), ("imported_at", now));
        var ext = new HashSet<object?>();
        var ae = opts.GetValueOrDefault("allowExtensions");
        if (ae == null) foreach (var x in DefaultExtensions) ext.Add(x);
        else foreach (var x in ImportJx.SpreadList(ae)) ext.Add(x);
        return new Ctx(ns, kind, lim, src, ext, source);
    }

    public static void AddTodo(Ctx c, string where, string code, string message)
    {
        // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
        if (c.Todo.Count < 5000) c.Todo.Add(ImportJx.Obj(("where", Clip(where, 200)), ("code", code), ("message", Clip(message, 400))));
        else if (c.Todo.Count == 5000) c.Todo.Add(ImportJx.Obj(("where", "*"), ("code", "todo_truncated"), ("message", "further notes omitted")));
    }

    public static D Finish(Ctx c) => ImportJx.Obj(("defs", c.Defs), ("todo", c.Todo), ("source", c.Source));

    // ---- text hygiene ----

    static bool Ctrl(char c) =>
        c <= 8 || c == 0x0B || c == 0x0C || (c >= 0x0E && c <= 0x1F) || (c >= 0x7F && c <= 0x9F) || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069);

    static int U8cp(int cp) => cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;

    /// <summary>NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to maxBytes at a code point.</summary>
    public static string Clip(object? o, int maxBytes)
    {
        if (o is not string s) return "";
        var b = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c)) { if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { b.Append(c).Append(s[++i]); } continue; }
            if (char.IsLowSurrogate(c)) continue;
            b.Append(Ctrl(c) ? ' ' : c);
        }
        var n = b.ToString().Normalize(NormalizationForm.FormC);
        var w = new StringBuilder(n.Length);
        bool inSp = false;
        foreach (var c in n)
        {
            if (ImportJx.JsSpace(c)) { if (!inSp) w.Append(' '); inSp = true; } else { w.Append(c); inSp = false; }
        }
        var t = ImportJx.JsTrim(w.ToString());
        if (ImportJx.U8(t) <= maxBytes) return t;
        var o2 = new StringBuilder();
        int used = 0;
        for (int i = 0; i < t.Length;)
        {
            int cp = char.ConvertToUtf32(t, i);
            if (used + U8cp(cp) > maxBytes) break;
            used += U8cp(cp);
            o2.Append(char.ConvertFromUtf32(cp));
            i += cp >= 0x10000 ? 2 : 1;
        }
        return ImportJx.JsTrim(o2.ToString());
    }

    /// <summary>First non-empty of the arguments, clipped.</summary>
    public static string FirstText(int max, params object?[] xs)
    {
        foreach (var x in xs) { var t = Clip(x, max); if (t.Length > 0) return t; }
        return "";
    }

    // ---- tokens and verbs ----

    static readonly Regex Camel1 = new("([a-z0-9])([A-Z])", RegexOptions.CultureInvariant), Camel2 = new("([A-Z]+)([A-Z][a-z])", RegexOptions.CultureInvariant);

    /// <summary>Lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike.</summary>
    public static List<string> TokensOf(object? name)
    {
        var s = ImportJx.NoLone(ImportJx.JsStr(name)).Normalize(NormalizationForm.FormKD);
        var b = new StringBuilder(s.Length);
        foreach (var c in s) if (c < 0x300 || c > 0x36F) b.Append(c);
        s = Camel2.Replace(Camel1.Replace(b.ToString(), "$1 $2"), "$1 $2").ToLowerInvariant();
        var o = new List<string>();
        int start = -1;
        for (int i = 0; i <= s.Length; i++)
        {
            bool ok = i < s.Length && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9'));
            if (ok && start < 0) start = i;
            if (!ok && start >= 0) { o.Add(s.Substring(start, i - start)); start = -1; }
        }
        return o;
    }

    /// <summary>Words that name an action; they lead or trail a name and become the last verb segment.</summary>
    public static readonly HashSet<string> ActionWords = new()
    {
        "get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
        "delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
        "enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer",
    };

    static string Seg(IList<string> toks)
    {
        var s = string.Join("_", toks);
        if (s.Length <= 32) return s;
        var h = Regex.Replace(ImportJx.Sha256B64u(ImportJx.Utf8(s)), "[^A-Za-z0-9]", "").ToLowerInvariant();
        h = h.Length > 4 ? h.Substring(0, 4) : h;
        var pad = new StringBuilder(h);
        while (pad.Length < 4) pad.Append('0');
        return s.Substring(0, 27) + "_" + pad;
    }

    /// <summary>A verb ns.noun....action from a raw operation name.</summary>
    public static string VerbOf(string ns, object? raw)
    {
        var r = ImportJx.JsStr(raw);
        var parts = new List<List<string>>();
        var cur = new StringBuilder();
        for (int i = 0; i <= r.Length; i++)
        {
            if (i == r.Length || r[i] == '.' || r[i] == '/' || r[i] == ':' || ImportJx.JsSpace(r[i]))
            {
                var t0 = TokensOf(cur.ToString());
                if (t0.Count > 0) parts.Add(t0);
                cur.Clear();
            }
            else cur.Append(r[i]);
        }
        var segs = new List<string>();
        if (parts.Count >= 2) { foreach (var p in parts) segs.Add(Seg(p)); }
        else
        {
            var t = parts.Count == 0 ? new List<string> { "op" } : parts[0];
            if (t.Count >= 2 && ActionWords.Contains(t[0])) { segs.Add(Seg(t.GetRange(1, t.Count - 1))); segs.Add(Seg(new[] { t[0] })); }
            else if (t.Count >= 2 && ActionWords.Contains(t[^1])) { segs.Add(Seg(t.GetRange(0, t.Count - 1))); segs.Add(Seg(new[] { t[^1] })); }
            else segs.Add(Seg(t));
        }
        if (segs.Count > 5) { var k = new List<string>(segs.GetRange(0, 2)); k.AddRange(segs.GetRange(segs.Count - 3, 3)); segs = k; }
        var v = ns + "." + string.Join(".", segs);
        if (!VerbRe.IsMatch(v) || ImportJx.U8(v) > 128) return ns + ".op";
        return v;
    }

    /// <summary>The short NL-layer alias of a raw name (snake tokens), or null when it is not a valid alias or equals the verb.</summary>
    public static string? AliasOf(object? raw, string verb)
    {
        var a = string.Join("_", TokensOf(raw));
        return a.Length > 0 && a.Length <= 64 && AliasRe.IsMatch(a) && a != verb ? a : null;
    }

    /// <summary>"createCustomer" to "Create customer": the title when the source gave none.</summary>
    public static string Humanize(object? name)
    {
        var t = TokensOf(name);
        if (t.Count == 0) return "";
        var b = new StringBuilder(t[0].Substring(0, 1).ToUpperInvariant()).Append(t[0].Substring(1));
        for (int i = 1; i < t.Count; i++) b.Append(' ').Append(t[i]);
        return b.ToString();
    }

    /// <summary>Make verb unique inside the import (_2, _3 on the last segment), noting the collision.</summary>
    public static string UniqueVerb(Ctx c, string verb, string where)
    {
        if (!c.Verbs.Contains(verb)) return verb;
        for (int n = 2; n < 100_000; n++)
        {
            var sfx = "_" + n;
            int dot = verb.LastIndexOf('.');
            var last = verb.Substring(dot + 1);
            var cand = verb.Substring(0, dot + 1) + last.Substring(0, Math.Min(last.Length, 32 - sfx.Length)) + sfx;
            if (!c.Verbs.Contains(cand) && VerbRe.IsMatch(cand))
            {
                AddTodo(c, where, "duplicate_verb", "verb '" + verb + "' is taken by an earlier operation; this one is '" + cand + "'");
                return cand;
            }
        }
        throw new ActionKitError("import_limit", "too many operations map to one verb");
    }

    // ---- JSON Schema: bounded resolution ----

    internal static bool IsObj(object? v) => v is D;

    /// <summary>Follow a local #/a/b JSON pointer in root; null when absent, not local, or not an object.</summary>
    public static object? Pointer(object? root, object? refO)
    {
        if (refO is not string rf || !rf.StartsWith("#/", StringComparison.Ordinal)) return null;
        var cur = root;
        var rest = rf.Substring(2);
        int from = 0;
        while (true)
        {
            int j = rest.IndexOf('/', from);
            var raw = j < 0 ? rest.Substring(from) : rest.Substring(from, j - from);
            var s = raw.Replace("~1", "/").Replace("~0", "~");
            var seg = ImportJx.DecodeUriComponent(s) ?? s;
            if (cur is D cd)
            {
                if (!cd.ContainsKey(seg)) return null;
                cur = cd[seg];
            }
            else if (cur is L cl)
            {
                // an array's own "length" is a number: no object results either way
                if (!IndexRe.IsMatch(seg) || long.Parse(seg) >= cl.Count) return null;
                cur = cl[int.Parse(seg)];
            }
            else return null;
            if (j < 0) break;
            from = j + 1;
        }
        return cur is D || cur is L ? cur : null;
    }

    static D MergeAll(D a, D m)
    {
        var o = new D(a);
        ImportJx.PutAll(o, m);
        var props = new D();
        ImportJx.Spread(props, a.GetValueOrDefault("properties"));
        ImportJx.Spread(props, m.GetValueOrDefault("properties"));
        var req = new L();
        if (a.GetValueOrDefault("required") != null) req.AddRange(ImportJx.SpreadList(a["required"]));
        if (m.GetValueOrDefault("required") != null) req.AddRange(ImportJx.SpreadList(m["required"]));
        o["properties"] = props;
        o["required"] = req;
        return o;
    }

    static D Without(D m, params string[] ks)
    {
        var o = new D(m);
        foreach (var k in ks) o.Remove(k);
        return o;
    }

    static bool IsNullType(object? t)
    {
        if (t is "null") return true;
        if (t is L l && l.Count > 0) { foreach (var x in l) if (x is not "null") return false; return true; }
        return false;
    }

    public static D ResolveSchema(object? s, Ctx c, Budget bud, string where) => ResolveSchema(s, c, bud, where, new List<string>(), 0);

    /// <summary>Resolve what a parameter declaration cannot carry: follow local $refs, merge allOf, collapse anyOf/oneOf to the single non-null variant or to a
    /// union of string constants. What stays unrepresentable is noted in the todo list and left as {}.</summary>
    public static D ResolveSchema(object? s, Ctx c, Budget bud, string where, List<string> chain, int depth)
    {
        if (s is not D sd) return new D();
        if (bud.Left <= 0)
        {
            if (!bud.Exhausted)
            {
                bud.Exhausted = true;
                AddTodo(c, where, "ref_budget", "schema expansion stopped after " + c.Lim.MaxRefNodes + " nodes (declared string; refine or drop)");
            }
            return new D();
        }
        bud.Left--;
        if (depth > c.Lim.MaxRefDepth)
        {
            AddTodo(c, where, "ref_depth", "schema nesting or reference chain deeper than " + c.Lim.MaxRefDepth + " (declared string; refine or drop)");
            return new D();
        }
        var cur = sd;
        if (cur.GetValueOrDefault("$ref") is string rf)
        {
            if (chain.Contains(rf))
            {
                AddTodo(c, where, "cyclic_ref", "reference '" + Clip(rf, 120) + "' is cyclic (declared string; refine or drop)");
                return new D();
            }
            var target = Pointer(c.Root, rf);
            if (target == null)
            {
                AddTodo(c, where, "unresolved_ref", "reference '" + Clip(rf, 120) + "' is not a local reference that resolves (declared string; refine or drop)");
                return new D();
            }
            var nc = new List<string>(chain) { rf };
            var merged = new D(ResolveSchema(target, c, bud, where, nc, depth + 1));
            ImportJx.PutAll(merged, Without(cur, "$ref"));
            cur = merged;
        }
        if (cur.GetValueOrDefault("allOf") is L allOf)
        {
            var rest = Without(cur, "allOf");
            var rs = new List<D>();
            foreach (var m in allOf) rs.Add(ResolveSchema(m, c, bud, where, chain, depth + 1));
            var acc = new D();
            foreach (var m in rs) acc = MergeAll(acc, m);
            var n = new D(acc);
            ImportJx.PutAll(n, rest);
            cur = n;
        }
        var alts = cur.GetValueOrDefault("anyOf") as L ?? cur.GetValueOrDefault("oneOf") as L;
        if (alts != null)
        {
            var rest = Without(cur, "anyOf", "oneOf");
            var live = new List<D>();
            var all = new List<D>();
            foreach (var m in alts) all.Add(ResolveSchema(m, c, bud, where, chain, depth + 1));
            foreach (var m in all) if (!IsNullType(m.GetValueOrDefault("type"))) live.Add(m);
            if (live.Count == 1) { var o1 = new D(live[0]); ImportJx.PutAll(o1, rest); return o1; }
            var consts = new List<L?>();
            bool allConst = true;
            foreach (var m in live)
            {
                L? k = null;
                if (m.GetValueOrDefault("const") is string cs) k = new L { cs };
                else if (m.GetValueOrDefault("enum") is L el && el.All(x => x is string)) k = el;
                if (k == null) allConst = false;
                consts.Add(k);
            }
            if (live.Count > 1 && allConst)
            {
                var o2 = new D(rest) { ["type"] = "string" };
                var u = new L();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var k in consts) foreach (var x in k!) if (seen.Add((string)x!)) u.Add(x);
                o2["enum"] = u;
                return o2;
            }
            AddTodo(c, where, "union", "a union of " + live.Count + " schemas has no representation (declared string; refine or drop)");
            return rest;
        }
        if (cur.GetValueOrDefault("const") is string cst && !cur.ContainsKey("enum"))
        {
            var n = new D(cur) { ["enum"] = new L { cst } };
            cur = n;
        }
        return cur;
    }

    // ---- JSON Schema to params ----

    /// <summary>Param name segment hygiene: [A-Za-z0-9_]{1,64}; anything else is replaced by _.</summary>
    public static string ParamSeg(string raw)
    {
        var b = new StringBuilder(raw.Length);
        bool allUs = true;
        foreach (var c in raw)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            b.Append(ok ? c : '_');
            if (c != '_' && ok) allUs = false;
        }
        var s = allUs ? "" : b.ToString();
        if (s.Length > 64) s = s.Substring(0, 64);
        return s.Length == 0 ? "p" : s;
    }

    static readonly Dictionary<string, string> Formats = new() { ["email"] = "email", ["uuid"] = "uuid", ["uri"] = "url", ["url"] = "url", ["idn-email"] = "email", ["semver"] = "semver" };
    static readonly HashSet<string> Reserved = new() { "__proto__", "constructor", "prototype" };
    static readonly HashSet<string> IntRoles = new() { "money.amount", "money.fee", "count.limit", "bytes.size" };

    static bool IsRoleOk(string r) => Actions.IsRole(r) || IdRoleRe.IsMatch(r) || XRoleRe.IsMatch(r);

    static bool PlainStr(object? x)
    {
        if (x is not string s) return false;
        if (s.Length == 0 || ImportJx.U8(s) > 256) return false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
            if (char.IsSurrogate(c)) return false;
        }
        return s.IsNormalized(NormalizationForm.FormC);
    }

    static L? EnumStrOf(object? en)
    {
        if (en is not L l) return null;
        if (l.Count == 0 || l.Count > 256) return null;
        foreach (var x in l) if (!PlainStr(x)) return null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var o = new L();
        foreach (var x in l) if (seen.Add((string)x!)) o.Add(x);
        return o;
    }

    static object? FirstNonNull(object? t)
    {
        if (t is L l) { foreach (var x in l) if (x is not "null") return x; return null; }
        return t;
    }

    /// <summary>A leaf schema to a param def. Unrepresentable shapes become string placeholders, noted.</summary>
    public static D LeafParam(D s, bool required, Ctx c, Budget bud, string where)
    {
        var t0 = FirstNonNull(s.GetValueOrDefault("type"));
        var enumStr = EnumStrOf(s.GetValueOrDefault("enum"));
        object? t = t0 != null ? t0 : enumStr != null ? "string" : (s.GetValueOrDefault("items") is L || s.GetValueOrDefault("items") is D) ? "array" : null;
        var bs = new D { ["type"] = "string" };
        if (!required) bs["required"] = false;
        var desc = Clip(s.GetValueOrDefault("description"), 280);
        if (desc.Length > 0) bs["description"] = desc;
        string? roleExt = c.Ext.Contains("x-pca-role") && s.GetValueOrDefault("x-pca-role") is string rs ? rs : null;
        D WithRole(D p)
        {
            if (roleExt == null) return p;
            if (!IsRoleOk(roleExt) || (IntRoles.Contains(roleExt) && p.GetValueOrDefault("type") is not "integer"))
            {
                AddTodo(c, where, "role_ignored", "x-pca-role '" + Clip(roleExt, 64) + "' is not valid for a " + ImportJx.JsStr(p.GetValueOrDefault("type")) + " parameter");
                return p;
            }
            var q = new D(p) { ["role"] = roleExt };
            return q;
        }
        var fmt = s.GetValueOrDefault("format");
        if (t is "integer" || (t is "number" && (fmt is "int32" || fmt is "int64")))
        {
            var p = new D(bs) { ["type"] = "integer" };
            var mn = s.GetValueOrDefault("minimum"); var mx = s.GetValueOrDefault("maximum");
            var exMin = s.GetValueOrDefault("exclusiveMinimum"); var exMax = s.GetValueOrDefault("exclusiveMaximum");
            if (ImportJx.IsInt(mn) && exMin is not true) p["min"] = mn;
            else if (ImportJx.IsInt(exMin)) p["min"] = ImportJx.NumOfDouble(ImportJx.Dbl(exMin)!.Value + 1);
            else if (ImportJx.IsInt(mn) && exMin is true) p["min"] = ImportJx.NumOfDouble(ImportJx.Dbl(mn)!.Value + 1);
            if (ImportJx.IsInt(mx) && exMax is not true) p["max"] = mx;
            else if (ImportJx.IsInt(exMax)) p["max"] = ImportJx.NumOfDouble(ImportJx.Dbl(exMax)!.Value - 1);
            else if (ImportJx.IsInt(mx) && exMax is true) p["max"] = ImportJx.NumOfDouble(ImportJx.Dbl(mx)!.Value - 1);
            if (p.ContainsKey("min") && p.ContainsKey("max") && ImportJx.Dbl(p["min"])! > ImportJx.Dbl(p["max"])!) { p.Remove("min"); p.Remove("max"); }
            return WithRole(p);
        }
        if (t is "boolean") { var p = new D(bs) { ["type"] = "boolean" }; return WithRole(p); }
        if (t is "string")
        {
            var f = fmt as string ?? "";
            var p = new D(bs);
            if (f == "date") { p["type"] = "date"; return WithRole(p); }
            if (f == "date-time") { p["type"] = "datetime"; return WithRole(p); }
            if (enumStr != null) p["values"] = enumStr;
            else if (s.GetValueOrDefault("enum") is L el && el.Count > 0) AddTodo(c, where, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)");
            if (Formats.TryGetValue(f, out var ff)) p["format"] = ff;
            var ml = s.GetValueOrDefault("maxLength");
            if (ImportJx.IsInt(ml) && ImportJx.Dbl(ml)! > 0 && ImportJx.Dbl(ml)! <= 16_777_216) p["max_len"] = ml;
            return WithRole(p);
        }
        if (t is "array")
        {
            var it = ResolveSchema(s.GetValueOrDefault("items"), c, bud, where + "[]");
            var itEnum = EnumStrOf(it.GetValueOrDefault("enum"));
            var lim = new D();
            var mi = s.GetValueOrDefault("maxItems"); var ni = s.GetValueOrDefault("minItems");
            if (ImportJx.IsInt(mi) && ImportJx.Dbl(mi)! >= 0) lim["max_items"] = mi;
            if (ImportJx.IsInt(ni) && ImportJx.Dbl(ni)! >= 0) lim["min_items"] = ni;
            if (lim.ContainsKey("min_items") && lim.ContainsKey("max_items") && ImportJx.Dbl(lim["min_items"])! > ImportJx.Dbl(lim["max_items"])!) { lim.Remove("min_items"); lim.Remove("max_items"); }
            if (s.GetValueOrDefault("uniqueItems") is true && itEnum != null)
            {
                var p = new D(bs) { ["type"] = "set", ["values"] = itEnum };
                ImportJx.PutAll(p, lim);
                return WithRole(p);
            }
            var itT = FirstNonNull(it.GetValueOrDefault("type"));
            string? items = itT is "integer" ? "integer" : itT is "string" ? "string" : itT is "boolean" ? "boolean" : null;
            if (items == null && itT != null) AddTodo(c, where, "array_items", "array items of type '" + Clip(ImportJx.JsStr(itT), 40) + "' are not declared (items left open)");
            var p2 = new D(bs) { ["type"] = "array" };
            if (items != null) p2["items"] = items;
            ImportJx.PutAll(p2, lim);
            return WithRole(p2);
        }
        if (t is "number") AddTodo(c, where, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)");
        else AddTodo(c, where, "unsupported_type", "type '" + Clip(t == null ? "none" : ImportJx.JsStr(t), 40) + "' has no representation (declared string; refine or drop)");
        var p3 = new D(bs) { ["type"] = "string" };
        return WithRole(p3);
    }

    /// <summary>Assign a schema property the way obj[name] = v does: the engine's __proto__ setter keeps no member.</summary>
    internal static void PutProp(D m, string name, object? v) { if (name != "__proto__") m[name] = v; }

    /// <summary>Flatten an object schema into params: nested objects become dotted names up to three segments; an object below that (or without properties) is a
    /// string placeholder; a child of an optional parent is optional. At most 64 params; the rest are dropped, noted.</summary>
    public static void FlattenObject(D schema, Ctx c, Budget bud, string where, D output) => FlattenObject(schema, c, bud, where, output, new List<string>(), true);

    internal static void FlattenObject(D schema, Ctx c, Budget bud, string where, D output, List<string> prefix, bool parentRequired)
    {
        var props = schema.GetValueOrDefault("properties") as D ?? new D();
        var req = new HashSet<string>(StringComparer.Ordinal);
        if (schema.GetValueOrDefault("required") is L rl) foreach (var x in rl) if (x is string xs) req.Add(xs);
        var names = new List<string>(props.Keys);
        names.Sort(IntentJs.CompareUtf8);
        foreach (var name in names)
        {
            if (Reserved.Contains(name)) { AddTodo(c, where + ": " + name, "skipped_param", "parameter name '" + name + "' is reserved; dropped"); continue; }
            var child = ResolveSchema(props[name], c, bud, where + ": " + name);
            if (child.GetValueOrDefault("readOnly") is true) continue;
            var sname = ParamSeg(name);
            if (sname != name) AddTodo(c, where + ": " + name, "renamed_param", "parameter '" + Clip(name, 80) + "' is declared as '" + sname + "'");
            var path = new List<string>(prefix) { sname };
            var full = string.Join(".", path);
            bool required = parentRequired && req.Contains(name);
            bool isObject = child.GetValueOrDefault("type") is "object" || (!child.ContainsKey("type") && IsObj(child.GetValueOrDefault("properties")));
            if (isObject && child.GetValueOrDefault("properties") is D cp && cp.Count > 0 && path.Count < MaxParamPathDepth)
            {
                FlattenObject(child, c, bud, where + ": " + full, output, path, required);
                continue;
            }
            if (output.Count >= MaxDefParams) { AddTodo(c, where, "too_many_params", "more than " + MaxDefParams + " parameters; '" + full + "' and the rest are dropped"); return; }
            bool clash = output.ContainsKey(full);
            if (!clash) foreach (var k in output.Keys) if (k.StartsWith(full + ".", StringComparison.Ordinal) || full.StartsWith(k + ".", StringComparison.Ordinal)) { clash = true; break; }
            if (clash) { AddTodo(c, where + ": " + full, "skipped_param", "parameter '" + full + "' collides with another; kept the first"); continue; }
            output[full] = isObject ? PlaceholderObject(child, required, c, where + ": " + full) : LeafParam(child, required, c, bud, where + ": " + full);
        }
    }

    static D PlaceholderObject(D s, bool required, Ctx c, string where)
    {
        AddTodo(c, where, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)");
        var p = new D { ["type"] = "string" };
        if (!required) p["required"] = false;
        var d = Clip(s.GetValueOrDefault("description"), 280);
        if (d.Length > 0) p["description"] = d;
        return p;
    }

    // ---- assembling a draft def ----

    /// <summary>A draft operation: what the importer knows before the def is assembled.</summary>
    public sealed class Draft
    {
        /// <summary>Raw operation name (operationId, tool name, field, rpc, ...).</summary>
        public object? Name;
        public string? Verb;
        public object? Title, Description;
        public List<string> Effects = new();
        public string Scope = "one";
        public D Params = new();
        public D? Idempotency;
        public List<string>? Traits;
        public bool NoAlias;
        public D? Bindings;
    }

    /// <summary>Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted). Returns the def or null.</summary>
    public static D? EmitDef(Ctx c, Draft d)
    {
        if (c.Defs.Count >= c.Lim.MaxOps) throw new ActionKitError("import_limit", "more than " + c.Lim.MaxOps + " operations");
        var rawVerb = d.Verb ?? VerbOf(c.Ns, d.Name);
        var verb = UniqueVerb(c, VerbRe.IsMatch(rawVerb) ? rawVerb : VerbOf(c.Ns, d.Name), ImportJx.JsStr(d.Name));
        var segs = verb.Split('.');
        var rtype = segs.Length > 2 ? string.Join(".", segs.Take(segs.Length - 1)) : segs[0];
        var title = FirstText(MaxTitleBytes, d.Title, Humanize(d.Name), verb);
        var description = Clip(d.Description, Math.Min(MaxDescriptionBytes, 600));
        var alias = d.NoAlias ? null : AliasOf(d.Name, verb);
        var def = new D { ["v"] = ImportJx.N(1), ["kind"] = "pca-action-def", ["verb"] = verb };
        if (alias != null && !c.Aliases.ContainsKey(alias) && !c.Verbs.Contains(alias)) def["aliases"] = new L { alias };
        def["title"] = title.Length == 0 ? verb : title;
        if (description.Length > 0) def["description"] = description;
        def["effects"] = Ak.ToL(Ak.SortUniq(d.Effects));
        def["resource"] = ImportJx.Obj(("type", RtypeRe.IsMatch(rtype) ? rtype : segs[0]),
            ("id", ImportJx.Obj(("prefix", ""), ("class", "any_safe"), ("len", ImportJx.List(ImportJx.N(1), ImportJx.N(128))))), ("scope", d.Scope));
        def["params"] = d.Params;
        if (d.Idempotency != null) def["idempotency"] = d.Idempotency;
        if (d.Traits != null && d.Traits.Count > 0) def["traits"] = Ak.ToL(Ak.SortUniq(d.Traits));
        def["bindings"] = d.Bindings;
        def["review"] = ImportJx.Obj(("state", "unreviewed"));
        def["source"] = ImportJx.Obj(("kind", c.Source["kind"]), ("uri", c.Source["uri"]), ("spec_digest", c.Source["spec_digest"]), ("licence", c.Source["licence"]), ("imported_at", c.Source["imported_at"]));
        var bad = Actions.ValidateDef(def);
        if (bad != null)
        {
            AddTodo(c, ImportJx.JsStr(d.Name), "invalid_def", "not emitted: " + bad);
            return null;
        }
        c.Verbs.Add(verb);
        if (def.GetValueOrDefault("aliases") is L al) c.Aliases[(string)al[0]!] = verb;
        c.Defs.Add(def);
        return def;
    }

    /// <summary>Add a declared trait to a draft (used for hint-derived traits such as network egress).</summary>
    public static List<string> WithTrait(List<string>? traits, string t)
    {
        var s = new List<string>(traits ?? new List<string>());
        if (!s.Contains(t)) s.Add(t);
        return s;
    }
}
