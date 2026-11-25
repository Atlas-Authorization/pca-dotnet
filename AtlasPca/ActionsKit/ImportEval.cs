// Measure the suggestion rules against a labeled corpus. Every corpus entry is turned into a source document of its own kind, run through the REAL importer
// and the REAL suggestion engine, and the traits the system flags are compared with the labels. Precision and recall per trait, with an exact
// Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as what they are, never as a safety guarantee.
using System.Globalization;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ImportEval
{
    public static readonly Dictionary<string, string> LabelShort = new()
    {
        ["money"] = "money_moving", ["destr"] = "destructive", ["comm"] = "external_communication", ["priv"] = "privilege_change", ["exp"] = "data_export", ["exec"] = "code_execution",
        ["cred"] = "credential_access", ["bulk"] = "bulk", ["pii"] = "pii_access", ["pub"] = "public_exposure", ["pers"] = "persistence", ["infra"] = "infra_mutation", ["cost"] = "cost_incurring",
        ["legal"] = "legal_binding", ["imp"] = "impersonation", ["egress"] = "network_egress", ["fin"] = "financial_data_read", ["reg"] = "regulated_data", ["sched"] = "scheduled", ["spawn"] = "agent_spawning",
    };

    static L SplitList(string s, string sep) => new(s.Split(sep).Cast<object?>());

    static string Pad4(int n) { var s = n.ToString(CultureInfo.InvariantCulture); return new string('0', Math.Max(0, 4 - s.Length)) + s; }

    /// <summary>The hand-labeled TSV: kind, name, location, params, labels, description per line. Throws on a short line or an unknown label.</summary>
    public static L ParseHandTsv(string text)
    {
        var o = new L();
        int n = 0;
        foreach (var line in text.Split('\n'))
        {
            if (ImportJx.JsTrim(line).Length == 0 || line.StartsWith('#')) continue;
            var c = line.Split('\t');
            if (c.Length < 6) throw new ArgumentException("hand corpus line needs 6 columns: " + (line.Length > 80 ? line.Substring(0, 80) : line));
            string kind = c[0], name = c[1], loc = c[2], parms = c[3], labels = c[4], description = c[5];
            var e = new D
            {
                ["id"] = "hand-" + Pad4(++n), ["src"] = "hand", ["kind"] = kind, ["name"] = name,
                ["params"] = parms == "-" ? new L() : SplitList(parms, ","),
            };
            var ls = new L();
            if (labels != "-") foreach (var l in SplitList(labels, ",")) ls.Add(LabelShort.TryGetValue((string)l!, out var full) ? full : l);
            e["labels"] = ls;
            e["description"] = description;
            if (kind == "openapi")
            {
                int sp = loc.IndexOf(' ');
                e["method"] = sp < 0 ? loc : loc.Substring(0, sp);
                e["path"] = sp < 0 ? "" : loc.Substring(sp + 1);
            }
            foreach (var l in ls) if (!LabelShort.ContainsValue((string)l!)) throw new ArgumentException("unknown label '" + l + "' in " + name);
            o.Add(e);
        }
        return o;
    }

    /// <summary>One JSON entry per non-blank line.</summary>
    public static L ParseCorpusJsonl(string text)
    {
        var o = new L();
        foreach (var l in text.Split('\n')) if (ImportJx.JsTrim(l).Length > 0) o.Add(Pca.ParseJson(l));
        return o;
    }

    // ---- entries to source documents ----

    static readonly Regex SpecRe = new("^[^:]+:([a-z]+)(?::(.+))?\\z", RegexOptions.CultureInvariant);
    static readonly Regex TypeRe = new("^[^:]+:([a-z]+)", RegexOptions.CultureInvariant);

    static D SchemaOf(string spec)
    {
        var m = SpecRe.Match(spec);
        string? type = null, format = null;
        if (m.Success) { type = m.Groups[1].Value; format = m.Groups[2].Success ? m.Groups[2].Value : null; }
        if (type == "array") return ImportJx.Obj(("type", "array"), ("items", ImportJx.Obj(("type", "string"))));
        var o = ImportJx.Obj(("type", type == "number" ? "number" : (type ?? "string")));
        if (!string.IsNullOrEmpty(format)) o["format"] = format;
        return o;
    }

    /// <summary>spec.slice(0, spec.indexOf(':')): with no colon the slice drops the last character.</summary>
    static string Pname(string spec)
    {
        int i = spec.IndexOf(':');
        int end = i < 0 ? spec.Length - 1 : i;
        return end <= 0 ? "" : spec.Substring(0, end);
    }

    static readonly HashSet<string> ReadFirst = new()
    {
        "get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate",
        "convert", "format", "compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open",
    };
    static readonly Regex FirstWordRe = new("^[A-Za-z][a-z0-9]*", RegexOptions.CultureInvariant);
    static readonly Regex Plural = new("\\A[a-z]+s?\\z", RegexOptions.CultureInvariant);
    static readonly Regex PathParam = new("\\{([^}]+)\\}", RegexOptions.CultureInvariant);

    static string FirstWord(string n)
    {
        var m = FirstWordRe.Match(n);
        return (m.Success ? m.Value : n).ToLowerInvariant();
    }

    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    static D OpenapiDoc(List<D> es)
    {
        var paths = new D();
        foreach (var e in es)
        {
            var method = (e.GetValueOrDefault("method") != null ? (string)e["method"]! : "get").ToLowerInvariant();
            bool body = method is "post" or "put" or "patch";
            var props = new D();
            var ps = Strs(e["params"]);
            foreach (var p in ps) ImportCommon.PutProp(props, Pname(p), SchemaOf(p));
            var pathParams = new L();
            var ppNames = new List<string>();
            foreach (Match pm in PathParam.Matches(e.GetValueOrDefault("path") != null ? (string)e["path"]! : ""))
            {
                ppNames.Add(pm.Groups[1].Value);
                pathParams.Add(ImportJx.Obj(("name", pm.Groups[1].Value), ("in", "path"), ("required", true), ("schema", ImportJx.Obj(("type", "string")))));
            }
            var op = new D();
            if (ImportJx.Truthy(e.GetValueOrDefault("name"))) op["operationId"] = e["name"];
            if (ImportJx.Truthy(e.GetValueOrDefault("description"))) op["summary"] = e["description"];
            var parameters = new L(pathParams);
            if (!body) foreach (var p in ps) if (!ppNames.Contains(Pname(p))) parameters.Add(ImportJx.Obj(("name", Pname(p)), ("in", "query"), ("schema", SchemaOf(p))));
            op["parameters"] = parameters;
            if (body && ps.Count > 0)
                op["requestBody"] = ImportJx.Obj(("content", ImportJx.Obj(("application/json", ImportJx.Obj(("schema", ImportJx.Obj(("type", "object"), ("properties", props), ("required", new L()))))))));
            var path = (string)e["path"]!;
            if (!paths.TryGetValue(path, out var item)) paths[path] = item = new D();
            ((D)item!)[method] = op;
        }
        return ImportJx.Obj(("openapi", "3.0.3"), ("info", ImportJx.Obj(("title", "corpus"), ("version", "1"))), ("paths", paths));
    }

    static string GqlType(string spec)
    {
        var m = TypeRe.Match(spec);
        var t = m.Success ? m.Groups[1].Value : "string";
        return t switch { "string" => "String", "integer" => "Int", "boolean" => "Boolean", "array" => "[String]", _ => "String" };
    }

    static string GraphqlSdl(List<D> es)
    {
        var q = new List<string>(); var m = new List<string>();
        foreach (var e in es)
        {
            var name = (string)e["name"]!;
            var ps = Strs(e["params"]);
            var args = "";
            if (ps.Count > 0) args = "(" + string.Join(", ", ps.Select(p => Pname(p) + ": " + GqlType(p))) + ")";
            ((ReadFirst.Contains(FirstWord(name)) || Plural.IsMatch(name)) ? q : m).Add("  \"" + ((string)e["description"]!).Replace("\"", "'") + "\"\n  " + name + args + ": String");
        }
        return (q.Count == 0 ? "" : "type Query {\n" + string.Join("\n", q) + "\n}\n") + (m.Count == 0 ? "" : "type Mutation {\n" + string.Join("\n", m) + "\n}\n");
    }

    static string ProtoType(string spec)
    {
        var m = TypeRe.Match(spec);
        var t = m.Success ? m.Groups[1].Value : "string";
        return t switch { "string" => "string", "integer" => "int64", "boolean" => "bool", "array" => "repeated string", _ => "string" };
    }

    static string ProtoText(List<D> es)
    {
        var svcs = new Dictionary<string, List<D>>();
        var order = new List<string>();
        foreach (var e in es)
        {
            var sn = ((string)e["name"]!).Split('/')[0];
            if (!svcs.TryGetValue(sn, out var list)) { svcs[sn] = list = new List<D>(); order.Add(sn); }
            list.Add(e);
        }
        var msgs = new List<string> { "message Empty {}" };
        var output = new List<string>();
        foreach (var sn in order)
        {
            var rpcs = new List<string>();
            foreach (var e in svcs[sn])
            {
                var parts = ((string)e["name"]!).Split('/');
                var mname = parts.Length > 1 ? parts[1] : "undefined";
                var ps = Strs(e["params"]);
                var fs = new List<string>();
                for (int i = 0; i < ps.Count; i++) fs.Add("  " + ProtoType(ps[i]) + " " + Pname(ps[i]) + " = " + (i + 1) + ";");
                msgs.Add("message " + mname + "Request {\n" + string.Join("\n", fs) + "\n}");
                rpcs.Add("  rpc " + mname + "(" + mname + "Request) returns (Empty);");
            }
            output.Add("service " + sn + " {\n" + string.Join("\n", rpcs) + "\n}");
        }
        return "syntax = \"proto3\";\npackage corpus;\n" + string.Join("\n", msgs) + "\n" + string.Join("\n", output) + "\n";
    }

    static D AsyncDoc(List<D> es)
    {
        var channels = new D();
        foreach (var e in es)
        {
            var props = new D();
            foreach (var p in Strs(e["params"])) ImportCommon.PutProp(props, Pname(p), SchemaOf(p));
            channels[(string)e["name"]!] = ImportJx.Obj(("publish", ImportJx.Obj(("summary", e.GetValueOrDefault("description")),
                ("message", ImportJx.Obj(("payload", ImportJx.Obj(("type", "object"), ("properties", props))))))));
        }
        return ImportJx.Obj(("asyncapi", "2.6.0"), ("info", ImportJx.Obj(("title", "corpus"), ("version", "1"))), ("channels", channels));
    }

    static L McpDoc(List<D> es)
    {
        var o = new L();
        foreach (var e in es)
        {
            var props = new D();
            foreach (var p in Strs(e["params"])) ImportCommon.PutProp(props, Pname(p), SchemaOf(p));
            o.Add(ImportJx.Obj(("name", e.GetValueOrDefault("name")), ("description", e.GetValueOrDefault("description")), ("inputSchema", ImportJx.Obj(("type", "object"), ("properties", props)))));
        }
        return o;
    }

    static string KeyOf(D e) =>
        (e.GetValueOrDefault("kind") is "openapi")
            ? (e.GetValueOrDefault("method") != null ? ImportJx.JsStr(e["method"]).ToUpperInvariant() : "GET") + " " + ImportJx.JsStr(e.GetValueOrDefault("path"))
            : ImportJx.JsStr(e.GetValueOrDefault("name"));

    static string DefKey(D d)
    {
        var b = d.GetValueOrDefault("bindings");
        var oa = ImportJx.Get(b, "openapi");
        if (ImportJx.Truthy(ImportJx.Get(oa, "path"))) return ImportJx.JsStr(ImportJx.Get(oa, "method")) + " " + ImportJx.JsStr(ImportJx.Get(oa, "path"));
        if (ImportJx.Get(oa, "operationId") != null) return ImportJx.JsStr(ImportJx.Get(oa, "operationId"));
        if (ImportJx.Get(ImportJx.Get(b, "mcp"), "tool") != null) return ImportJx.JsStr(ImportJx.Get(ImportJx.Get(b, "mcp"), "tool"));
        if (ImportJx.Get(ImportJx.Get(b, "graphql"), "field") != null) return ImportJx.JsStr(ImportJx.Get(ImportJx.Get(b, "graphql"), "field"));
        var g = ImportJx.Get(b, "grpc");
        if (ImportJx.Truthy(g)) { var sv = ImportJx.JsStr(ImportJx.Get(g, "service")).Split('.'); return sv[^1] + "/" + ImportJx.JsStr(ImportJx.Get(g, "method")); }
        if (ImportJx.Get(ImportJx.Get(b, "asyncapi"), "channel") != null) return ImportJx.JsStr(ImportJx.Get(ImportJx.Get(b, "asyncapi"), "channel"));
        return "";
    }

    /// <summary>Import every entry with the real importer of its kind. Returns {defs: {id: def}, todo: n} (an entry whose def was not emitted is absent).</summary>
    public static D ImportCorpus(L entries)
    {
        var defs = new D();
        long todo = 0;
        var groups = new Dictionary<string, List<D>>();
        var order = new List<string>();
        foreach (var eo in entries)
        {
            var e = (D)eo!;
            var g = ImportJx.JsStr(e.GetValueOrDefault("kind")) + "|" + (e.GetValueOrDefault("spec") != null ? ImportJx.JsStr(e["spec"]) : "");
            if (!groups.TryGetValue(g, out var list)) { groups[g] = list = new List<D>(); order.Add(g); }
            list.Add(e);
        }
        var opts = ImportJx.Obj(("ns", "corpus"), ("limits", ImportJx.Obj(("max_ops", ImportJx.N(50_000)), ("max_nodes", ImportJx.N(20_000_000)), ("max_bytes", ImportJx.N(200_000_000)))));
        foreach (var gk in order)
        {
            var kind = gk.Split('|')[0];
            var es = groups[gk];
            object src = kind == "openapi" ? OpenapiDoc(es) : kind == "mcp" ? McpDoc(es) : kind == "graphql" ? GraphqlSdl(es) : kind == "grpc" ? ProtoText(es) : AsyncDoc(es);
            var r = ImportPipeline.ImportActions(kind, src, opts);
            todo += ((L)r["todo"]!).Count;
            var byKey = new Dictionary<string, object?>();
            foreach (var d in (L)r["defs"]!) byKey[DefKey((D)d!)] = d;
            foreach (var e in es) if (byKey.TryGetValue(KeyOf(e), out var d) && d != null) defs[(string)e["id"]!] = d;
        }
        return ImportJx.Obj(("defs", defs), ("todo", ImportJx.N(todo)));
    }

    // ---- scoring ----

    /// <summary>Deterministic split of the real corpus by specification: rules are tuned on tune specs only; holdout specs are never looked at when editing rules.</summary>
    public static string RealSplit(object? spec)
    {
        var s = spec == null ? "" : ImportJx.JsStr(spec);
        long h = 2166136261L;
        for (int i = 0; i < s.Length;)
        {
            int code = s[i]; // charCodeAt(0) of the code point: its first UTF-16 unit
            i += char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
            int x = unchecked((int)h) ^ code; // ToInt32(h) ^ code
            h = unchecked((long)(x * 16777619)) & 0xFFFFFFFFL; // Math.imul, then >>> 0
        }
        return ((h >> 7) % 2) == 0 ? "tune" : "holdout";
    }

    static string SourceOf(D e) => (e.GetValueOrDefault("src") is "real") ? "real/" + RealSplit(e.GetValueOrDefault("spec")) : ImportJx.JsStr(e.GetValueOrDefault("src"));

    static D Stat(string trait, List<(bool Label, bool Pred)> rows, double alpha)
    {
        int tp = 0, fp = 0, fn = 0;
        foreach (var (label, pred0) in rows) { if (label && pred0) tp++; else if (pred0) fp++; else if (label) fn++; }
        int pos = tp + fn, pred = tp + fp;
        var o = new D
        {
            ["trait"] = trait, ["positives"] = ImportJx.N(pos), ["predicted"] = ImportJx.N(pred), ["tp"] = ImportJx.N(tp), ["fp"] = ImportJx.N(fp), ["fn"] = ImportJx.N(fn),
            ["precision"] = pred == 0 ? null : ImportJx.NumOfDouble((double)tp / pred),
            ["recall"] = pos == 0 ? null : ImportJx.NumOfDouble((double)tp / pos),
            ["recall_lower"] = pos == 0 ? null : ImportJx.NumOfDouble(1 - AtlasPca.IntentPkg.IntentStats.ClopperPearsonUpper(fn, pos, alpha)),
            // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
            ["precision_lower"] = pred == 0 || pred > 600 ? null : ImportJx.NumOfDouble(1 - AtlasPca.IntentPkg.IntentStats.ClopperPearsonUpper(fp, pred, alpha)),
        };
        return o;
    }

    static string StripPca(string t) => t.StartsWith("pca.", StringComparison.Ordinal) ? t.Substring(4) : t;

    static L Score(List<D> es, Dictionary<string, HashSet<string>> pred, List<string> traitNames, double alpha)
    {
        var o = new L();
        foreach (var t in traitNames)
        {
            var rows = new List<(bool, bool)>();
            foreach (var e in es)
            {
                pred.TryGetValue(ImportJx.JsStr(e.GetValueOrDefault("id")), out var p);
                rows.Add((((L)e["labels"]!).Contains(t), p != null && p.Contains(t)));
            }
            var s = Stat(t, rows, alpha);
            if (ImportJx.Dbl(s["positives"])! > 0 || ImportJx.Dbl(s["predicted"])! > 0) o.Add(s);
        }
        return o;
    }

    /// <summary>EvalSuggest: rules and registry default to the shipped ones; alpha to 0.05.</summary>
    public static D EvalSuggest(L entriesO, D? rulesIn, Dictionary<string, D>? registryIn, double? alphaIn)
    {
        var rules = rulesIn ?? ImportRules.DefaultRules;
        var registry = registryIn ?? Actions.CoreRegistry;
        double alpha = alphaIn ?? 0.05;
        var entries = entriesO.Select(e => (D)e!).ToList();
        var defs = (D)ImportCorpus(entriesO)["defs"]!;
        var names = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var t in registry.Keys) if (t != "pca.unreviewed" && t != "pca.irreversible") names.Add(StripPca(t));
        var traitNames = names.ToList();
        var flagged = new Dictionary<string, HashSet<string>>(); var added = new Dictionary<string, HashSet<string>>();
        foreach (var e in entries)
        {
            var id = ImportJx.JsStr(e.GetValueOrDefault("id"));
            if (!defs.TryGetValue(id, out var dObj) || dObj == null) continue;
            var d = (D)dObj;
            var s = ImportSuggest.SuggestWithRules(d, rules, registry);
            var sd = ImportSuggest.ApplySuggestion(d, s, ImportJx.Obj(("rules", ImportJx.Obj(("version", rules.GetValueOrDefault("version")), ("digest", ""), ("fired", s["fired"])))));
            var fl = new HashSet<string>(StringComparer.Ordinal);
            foreach (var t in Actions.Closure(registry, Actions.HintTraits(sd).Cast<object?>())) if (t != "pca.unreviewed") fl.Add(StripPca(t));
            flagged[id] = fl;
            var ad = new HashSet<string>(StringComparer.Ordinal);
            foreach (var t in (L)s["traits"]!) ad.Add(StripPca((string)t!));
            added[id] = ad;
        }
        var sources = new SortedSet<string>(StringComparer.Ordinal);
        bool anyReal = false;
        foreach (var e in entries) { sources.Add(SourceOf(e)); if (e.GetValueOrDefault("src") is "real") anyReal = true; }
        if (anyReal) sources.Add("real");
        var bySource = new D();
        foreach (var s in sources)
        {
            var es = entries.Where(e => s == "real" ? (e.GetValueOrDefault("src") is "real") : SourceOf(e) == s).ToList();
            bySource[s] = ImportJx.Obj(("entries", ImportJx.N(es.Count)), ("flagged", Score(es, flagged, traitNames, alpha)));
        }
        return new D
        {
            ["alpha"] = ImportJx.NumOfDouble(alpha), ["entries"] = ImportJx.N(entries.Count), ["mapped"] = ImportJx.N(defs.Count), ["rules_version"] = rules.GetValueOrDefault("version"),
            ["flagged"] = Score(entries, flagged, traitNames, alpha), ["suggested"] = Score(entries, added, traitNames, alpha), ["by_source"] = bySource,
        };
    }

    static string Pct(object? x)
    {
        if (x == null) return "-";
        double d = ImportJx.Dbl(x)!.Value * 100;
        return ToFixed1(d) + "%";
    }

    // Number.prototype.toFixed(1): exact, with a tie going up (.NET formats an exact tie to even)
    static string ToFixed1(double r)
    {
        if (!double.IsFinite(r) || r < 0) return r.ToString("F1", CultureInfo.InvariantCulture);
        long bits = BitConverter.DoubleToInt64Bits(r);
        int exp = (int)((bits >> 52) & 0x7FF);
        var m = new System.Numerics.BigInteger(exp == 0 ? bits & 0xFFFFFFFFFFFFFL : (bits & 0xFFFFFFFFFFFFFL) | (1L << 52));
        int e = (exp == 0 ? 1 : exp) - 1075;
        System.Numerics.BigInteger n = e >= 0 ? (m << e) * 10 : ((m * 20) + (System.Numerics.BigInteger.One << -e)) >> (1 - e);
        return $"{n / 10}.{(int)(n % 10)}";
    }

    static string Table(L stats)
    {
        var rows = new List<string> { "| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|" };
        foreach (var so in stats)
        {
            var s = (D)so!;
            rows.Add("| " + s["trait"] + " | " + ImportJx.JsStr(s["positives"]) + " | " + ImportJx.JsStr(s["predicted"]) + " | " + Pct(s["recall"]) + " | " + Pct(s["recall_lower"]) + " | " + Pct(s["precision"]) + " | "
                + ImportJx.JsStr(s["fn"]) + " | " + ImportJx.JsStr(s["fp"]) + " |");
        }
        return string.Join("\n", rows);
    }

    public static string RenderEvalMarkdown(D r)
    {
        var parts = new List<string>
        {
            "# Suggestion rules " + ImportJx.JsStr(r.GetValueOrDefault("rules_version")) + ": measured on a labeled corpus",
            "",
            ImportJx.JsStr(r.GetValueOrDefault("entries")) + " labeled operations (" + ImportJx.JsStr(r.GetValueOrDefault("mapped")) + " imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = " + ImportJx.JsStr(r.GetValueOrDefault("alpha")) + ".",
            "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
            "",
            "## What a reviewer is shown (importer facts plus suggestions)", "", Table((L)r["flagged"]!), "",
            "## What the suggestion rules added", "", Table((L)r["suggested"]!), "",
        };
        foreach (var (key, val) in (D)r["by_source"]!)
        {
            parts.Add("## Source: " + key + " (" + ImportJx.JsStr(ImportJx.Get(val, "entries")) + " operations)");
            parts.Add("");
            parts.Add(Table((L)ImportJx.Get(val, "flagged")!));
            parts.Add("");
        }
        return string.Join("\n", parts);
    }

    static object? FindTrait(object? flagged, string t)
    {
        if (flagged is not L l) return null;
        foreach (var x in l) if (ImportJx.Get(x, "trait") is string xt && xt == t) return x;
        return null;
    }

    /// <summary>Empty when the report meets the floors; else one line per failure.</summary>
    public static List<string> FloorFailures(D r, D f)
    {
        var o = new List<string>();
        var bySource = (D)r["by_source"]!;
        var real = bySource.GetValueOrDefault("real/holdout");
        var fr = (D)f["real"]!;
        double minEntries = ImportJx.Dbl(fr["min_entries"])!.Value;
        if (real == null || ImportJx.Dbl(ImportJx.Get(real, "entries"))! < minEntries)
            o.Add("the real-spec hold-out has " + (real == null ? "0" : ImportJx.JsStr(ImportJx.Get(real, "entries"))) + " operations, fewer than the required " + ImportJx.JsStr(fr["min_entries"]));
        if (ImportJx.Dbl(r["mapped"])! < ImportJx.Dbl(r["entries"])!) o.Add((long)(ImportJx.Dbl(r["entries"])!.Value - ImportJx.Dbl(r["mapped"])!.Value) + " corpus operations were not imported");
        foreach (var (t, floorVal) in (D)fr["recall_lower"]!)
        {
            var s = real == null ? null : FindTrait(ImportJx.Get(real, "flagged"), t);
            var needO = ((D)fr["min_positives"]!).GetValueOrDefault(t);
            var need = needO == null ? "0" : ImportJx.JsStr(needO);
            double needN = needO == null ? 0 : ImportJx.Dbl(needO)!.Value;
            if (s == null || ImportJx.Dbl(ImportJx.Get(s, "positives"))! < needN) o.Add(t + ": " + (s == null ? "0" : ImportJx.JsStr(ImportJx.Get(s, "positives"))) + " real labeled positives, fewer than the " + need + " the floor needs");
            else if (ImportJx.Get(s, "recall_lower") == null || ImportJx.Dbl(ImportJx.Get(s, "recall_lower"))! < ImportJx.Dbl(floorVal)!)
                o.Add(t + ": hold-out recall lower bound " + Pct(ImportJx.Get(s, "recall_lower")) + " is below the recorded floor " + Pct(floorVal));
        }
        var syn = bySource.GetValueOrDefault("syn");
        foreach (var (t, floorVal) in (D)((D)f["regression"]!)["recall_lower"]!)
        {
            var s = syn == null ? null : FindTrait(ImportJx.Get(syn, "flagged"), t);
            if (s == null || ImportJx.Get(s, "recall_lower") == null || ImportJx.Dbl(ImportJx.Get(s, "recall_lower"))! < ImportJx.Dbl(floorVal)!)
                o.Add(t + ": regression-set recall lower bound " + Pct(s == null ? null : ImportJx.Get(s, "recall_lower")) + " is below " + Pct(floorVal));
        }
        return o;
    }
}
