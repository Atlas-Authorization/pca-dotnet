using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mcp;

/// <summary>The Model Context Protocol adapter for Proof-Carrying Authority: wrap a tool handler so every call carries a fresh PCActn,
/// derive a site action schema from the tools an MCP server lists and check a tool call against it, attach the proof to a client
/// transport request, and the client half of MCP authorization step-up. Values are parsed JSON (D, L, string, bool, Num, null).
/// This does not authorize: it attaches a proof-carrying action; the resource server's verifier decides.</summary>
public static class Mcp
{
    /// <summary>Key under which a tool result carries the encoded PCActn in its <c>_meta</c>.</summary>
    public const string ResultMetaKey = "x-pca-action";

    public static readonly IReadOnlyList<string> McpClientRevisions = new[] { "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft" };

    // ---- handlers ----

    /// <summary>An MCP tool handler: (args, extra) -> a result map (<c>content</c>, optional <c>isError</c>).</summary>
    public delegate D ToolHandler(D args, object? extra);

    /// <summary>Which PCA action a tool is: the catalog verb, the resource (fixed, or derived from the args) and the optional proof receiver.</summary>
    public sealed class GuardToolSpec
    {
        public string Verb { get; set; } = "";
        public string Resource { get; set; } = "";
        public Func<D, string>? ResourceOf { get; set; }
        /// <summary>Receives the PCActn so the proof can be forwarded (for example as a request header) to the resource server.</summary>
        public Action<D, D>? OnProof { get; set; }
    }

    /// <summary>The tool error <see cref="WithPca"/> returns when the proof cannot be built: a text content item and <c>isError: true</c>.</summary>
    public static D DeniedResult(string text) => new()
    {
        ["content"] = new L { new D { ["type"] = "text", ["text"] = text } },
        ["isError"] = true,
    };

    /// <summary>Wrap a tool handler so each call builds a PCActn before the original handler runs. When the agent refuses to build the
    /// proof (it throws ArgumentException or InvalidOperationException) the wrapper returns an MCP error result so the model sees it.</summary>
    public static ToolHandler WithPca(Agent agent, GuardToolSpec spec, ToolHandler handler) => (args, extra) =>
    {
        D pca;
        try
        {
            var resource = spec.ResourceOf != null ? spec.ResourceOf(args) : spec.Resource;
            pca = agent.Act(spec.Verb, resource, args);
        }
        catch (Exception e) when (e is ArgumentException || e is InvalidOperationException)
        {
            return DeniedResult(string.IsNullOrEmpty(e.Message) ? "denied" : e.Message);
        }
        spec.OnProof?.Invoke(pca, args);
        return handler(args, extra);
    };

    /// <summary>Attach the encoded PCActn into a result's <c>_meta</c> so a downstream gateway or resource server can read the proof off
    /// the tool result. Additive: existing members and <c>_meta</c> keys are kept. <paramref name="pca"/>: an object with <c>encoded</c>.</summary>
    public static D GuardToolResult(object? pca, object? result)
    {
        if (pca == null) throw JsX.TypeError("cannot read properties of null (reading 'encoded')");
        if (result == null) throw JsX.TypeError("cannot read properties of null (reading '_meta')");
        var hasEncoded = pca is D pd && pd.ContainsKey("encoded");
        var encoded = pca is D pe ? pe.GetValueOrDefault("encoded") : null;
        var prev = result is D rd ? rd.GetValueOrDefault("_meta") : null;
        var meta = JsX.Truthy(prev) && (prev is D || prev is L) ? JsX.Spread(prev) : new D();
        if (hasEncoded) meta[ResultMetaKey] = encoded;
        else meta.Remove(ResultMetaKey); // the reference writes undefined over any existing key, and JSON drops it
        var o = JsX.Spread(result);
        o["_meta"] = meta;
        return o;
    }

    /// <summary>The request headers a proof travels in: <c>PCA-Action</c> = base64url of the UTF-8 encoded PCActn JSON (no provenance header).</summary>
    public static Dictionary<string, string> PcaHeaders(string encoded) => new() { [Agent.Header] = Pca.B64u(Encoding.UTF8.GetBytes(encoded)) };

    // ---- client transport ----

    /// <summary>Which PCA action an MCP tool call is: (verb, resource); null = send the call without a proof.</summary>
    public delegate (string Verb, string Resource)? ToolActionMap(string tool, D args);

    /// <summary>The <c>tools/call</c> a JSON-RPC body carries: <c>{name, arguments}</c> (arguments an object, <c>{}</c> when absent or not an object), else null.</summary>
    public static D? ToolCallOf(object? body)
    {
        if (body is not string text) return null;
        object? msg;
        try { msg = Pca.ParseJson(text); } catch (Exception) { return null; }
        if (msg is not D m || m.GetValueOrDefault("method") as string != "tools/call") return null;
        var prms = m.GetValueOrDefault("params");
        var name = prms is D pd ? pd.GetValueOrDefault("name") : null;
        var args = prms is D pa ? pa.GetValueOrDefault("arguments") : null;
        if (name is not string) return null;
        return new D { ["name"] = name, ["arguments"] = args is D ? args : new D() };
    }

    /// <summary>The agent side of an MCP server that requires a PCActn per tool call: for a JSON-RPC <c>tools/call</c> body, build a fresh
    /// proof for that call and return the headers to add (empty for any other request). It decides nothing: the server's verifier does.</summary>
    public static Dictionary<string, string> ProofHeaders(Agent agent, ToolActionMap toolAction, string? body)
    {
        var call = ToolCallOf(body);
        if (call == null) return new();
        var args = (D)call["arguments"]!;
        var act = toolAction((string)call["name"]!, args);
        if (act == null) return new();
        return new Dictionary<string, string> { [Agent.Header] = Agent.HeaderValue(agent.Act(act.Value.Verb, act.Value.Resource, args)) };
    }

    // ---- site action schema ----

    /// <summary>Anything that lists tools like an MCP client or server (tools/list): the result carries <c>tools</c>.</summary>
    public delegate D ToolLister();

    /// <summary>Draft an action schema from an MCP tool list. <paramref name="site"/>: site, aud, version, optional verbPrefix. Every write
    /// verb is drafted irreversible (the fail-closed default); the result is <c>{schema, todo}</c>.</summary>
    public static D DraftActionSchemaFromMcp(L tools, D site) => McpDraft.Draft(tools, site);

    public static D DraftActionSchemaFromMcp(ToolLister source, D site) => McpDraft.Draft((L)source().GetValueOrDefault("tools")!, site);

    /// <summary>Import an MCP tool list as action-kit definitions: typed params with roles, nested bodies flattened, annotations kept as untrusted hints, every def
    /// <c>unreviewed</c> until a pinned reviewer signs it. <paramref name="opts"/>: <c>ns</c> (required), <c>uri</c>, <c>licence</c>, <c>now</c>, <c>suggest</c> (<c>rules</c> by
    /// default, or <c>none</c>). Returns <c>{defs, todo, source}</c>.</summary>
    public static D ImportActionDefsFromMcp(L tools, D opts)
    {
        var rest = new D(opts);
        rest.Remove("suggest");
        var r = ActionsKit.McpImporter.ImportMcp(new D { ["tools"] = tools }, rest);
        var mode = opts.GetValueOrDefault("suggest") is string m && m.Length > 0 ? m : "rules";
        var s = ActionsKit.ImportPipeline.SuggestDefs(((L)r["defs"]!).Select(d => (D)d!), new ActionsKit.ImportPipeline.SuggestOpts { Mode = mode });
        return new D { ["defs"] = s["defs"], ["todo"] = r["todo"], ["source"] = r["source"] };
    }

    /// <summary><see cref="ImportActionDefsFromMcp(L, D)"/> over anything that lists tools (<c>tools/list</c>).</summary>
    public static D ImportActionDefsFromMcp(ToolLister source, D opts) => ImportActionDefsFromMcp((L)source().GetValueOrDefault("tools")!, opts);

    /// <summary><c>Object.entries(o)</c> order (JavaScript: array-index keys ascending, then insertion order); null throws.</summary>
    static List<KeyValuePair<string, object?>> Entries(object? o)
    {
        if (o == null) throw JsX.TypeError("cannot convert undefined or null to object");
        return JsX.Keys(o).Select(k => new KeyValuePair<string, object?>(k, JsX.ValueOf(o, k))).ToList();
    }

    /// <summary><c>JSON.parse(JSON.stringify(v))</c> for parsed JSON: a deep copy where -0 becomes 0.</summary>
    static object? Copy(object? v) => v switch
    {
        D m => m.ToDictionary(e => e.Key, e => Copy(e.Value)),
        L l => l.Select(Copy).ToList(),
        Num n when n.Raw == "-0" => new Num("0"),
        _ => v,
    };

    /// <summary>Record the developer's decisions on a draft (a new object). <paramref name="d"/>: <c>verbs</c> (per verb <c>reversibility</c> and
    /// <c>params</c>: a partial declaration per parameter path), optional <c>units</c>. A decision about a verb or parameter the draft does not
    /// have throws: the schema is closed, so a typo must not silently publish a looser schema.</summary>
    public static D ApplySchemaDecisions(object? draft, D d)
    {
        var copied = Copy(draft);
        if (copied is not D @out) throw JsX.TypeError("cannot read properties of a non-object draft");
        if (JsX.Truthy(d.GetValueOrDefault("units")))
        {
            var merged = JsX.Spread(@out.GetValueOrDefault("units") ?? new D());
            foreach (var (k, v) in JsX.Spread(d["units"])) merged[k] = v;
            @out["units"] = merged;
        }
        var verbs = @out.GetValueOrDefault("verbs");
        foreach (var e in Entries(d.GetValueOrDefault("verbs")))
        {
            var verb = e.Key;
            var dv = e.Value;
            if (verbs is not L vl) throw JsX.TypeError("out.verbs.find is not a function");
            D? v = null;
            foreach (var x in vl)
            {
                if (x == null) throw JsX.TypeError("cannot read properties of null (reading 'verb')");
                if (x is D xd && xd.GetValueOrDefault("verb") is string xv && xv == verb) { v = xd; break; }
            }
            if (v == null) throw new InvalidOperationException($"applySchemaDecisions: the draft has no verb '{verb}'");
            if (dv == null) throw JsX.TypeError("cannot read properties of null (reading 'reversibility')");
            var rev = dv is D dvd ? dvd.GetValueOrDefault("reversibility") : null;
            if (JsX.Truthy(rev)) v["reversibility"] = rev;
            var dp = dv is D dpd ? dpd.GetValueOrDefault("params") : null;
            foreach (var pe in Entries(dp ?? new D()))
            {
                var prms = v.GetValueOrDefault("params");
                var p = prms is D pm ? pm.GetValueOrDefault(pe.Key) : null;
                if (!JsX.Truthy(p)) throw new InvalidOperationException($"applySchemaDecisions: verb '{verb}' has no parameter '{pe.Key}'");
                if (p is D pdict) foreach (var (k, val) in JsX.Spread(pe.Value)) pdict[k] = val;
            }
        }
        return @out;
    }

    /// <summary>The first verb entry that maps a tool (<c>mcp.tool</c>), or null. A verbs member that is not an array throws, as the reference does.</summary>
    static D? EntryOfTool(object? schema, object? toolName)
    {
        if (schema == null) throw JsX.TypeError("cannot read properties of null (reading 'verbs')");
        var verbs = schema is D sd ? sd.GetValueOrDefault("verbs") : null;
        if (verbs is not L vl) throw JsX.TypeError("schema.verbs.find is not a function");
        foreach (var v in vl)
        {
            if (v == null) throw JsX.TypeError("cannot read properties of null (reading 'mcp')");
            var mcp = v is D vd ? vd.GetValueOrDefault("mcp") : null;
            var tool = mcp is D md ? md.GetValueOrDefault("tool") : null;
            if (tool != null && tool.Equals(toolName)) return v as D;
        }
        return null;
    }

    /// <summary>The schema verb an MCP tool maps to (by <c>mcp.tool</c>), or null.</summary>
    public static string? VerbOfTool(object? schema, object? toolName) => EntryOfTool(schema, toolName)?.GetValueOrDefault("verb") as string;

    /// <summary>Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb):
    /// <c>{ok:true, verb}</c> or <c>{ok:false, code, path?, reason}</c>.</summary>
    public static D ConformToolCall(object? schema, string toolName, object? args)
    {
        var verb = VerbOfTool(schema, toolName);
        if (verb == null) return new D { ["ok"] = false, ["code"] = "unknown_verb", ["reason"] = $"MCP tool '{toolName}' is not declared by the site schema" };
        var c = ActionSchema.ConformAction(schema, verb, args);
        if (c.Ok) return new D { ["ok"] = true, ["verb"] = ActionSchema.SchemaVerb(schema, verb) };
        var o = new D { ["ok"] = false, ["code"] = c.Code };
        if (c.Path != null) o["path"] = c.Path;
        o["reason"] = c.Reason;
        return o;
    }

    // ---- authorization step-up (client) ----

    // ECMAScript \s (no U+0085), plus the comma
    const string JsWs = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    static Regex NeedParam => Rx.Get("(?:^|[" + JsWs + ",])pca_need=\"([^\"\\\\]*)\"", RegexOptions.CultureInvariant);

    /// <summary>The need a <c>pca_need</c> auth-param carries, decoded (<c>{ok:true, need}</c> or <c>{ok:false, code}</c>); null when the header names none.</summary>
    public static D? PcaNeedFromChallenge(object? header)
    {
        if (header is not string h) return null;
        var m = NeedParam.Match(h);
        if (!m.Success) return null;
        var (need, code) = A2a.DecodeNeed(m.Groups[1].Value);
        return need != null ? new D { ["ok"] = true, ["need"] = need } : new D { ["ok"] = false, ["code"] = code };
    }

    /// <summary>Parse the value of a <c>WWW-Authenticate</c> header into its challenges (<c>scheme</c> lower-cased; <c>params</c> names lower-cased,
    /// quoted values unescaped, a repeated name keeps its first value). Never throws.</summary>
    public static L ParseChallenges(object? headerO)
    {
        var o = new L();
        if (headerO is not string h) return o;
        int n = h.Length, i = 0;
        void Ws() { while (i < n && (h[i] == ' ' || h[i] == '\t' || h[i] == ',')) i++; }
        string Token() { int s = i; while (i < n && " \t,=\"".IndexOf(h[i]) < 0) i++; return h.Substring(s, i - s); }
        D? cur = null;
        Ws();
        while (i < n)
        {
            var name = Token();
            if (name.Length == 0) { i++; continue; } // a stray quote or equals sign: skip it
            while (i < n && (h[i] == ' ' || h[i] == '\t')) i++;
            if (i < n && h[i] == '=')
            {
                i++;
                while (i < n && (h[i] == ' ' || h[i] == '\t')) i++;
                var val = new StringBuilder();
                if (i < n && h[i] == '"')
                {
                    i++;
                    while (i < n && h[i] != '"')
                    {
                        if (h[i] == '\\' && i + 1 < n) i++;
                        val.Append(h[i]);
                        i++;
                    }
                    i++; // closing quote
                }
                else val.Append(Token());
                var key = ObjectiveRisk.ToLowerJs(name);
                // the reference keeps params in a plain object: names it already inherits are never (re)written
                if (cur != null && cur["params"] is D ps && !ps.ContainsKey(key) && key != "constructor" && key != "__proto__") ps[key] = val.ToString();
            }
            else
            {
                cur = new D { ["scheme"] = ObjectiveRisk.ToLowerJs(name), ["params"] = new D() };
                o.Add(cur);
            }
            Ws();
        }
        return o;
    }

    static List<string> SplitScopes(object? s) => s is string t ? t.Split(' ').Where(x => x.Length > 0).ToList() : new List<string>();

    static double NumOr(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    static D GiveUp(string reason) => new() { ["action"] = "give_up", ["reason"] = reason };

    /// <summary>What to do with a response. Only 403 with <c>error="insufficient_scope"</c> on a Bearer challenge is a step-up. The new scope list is
    /// the UNION of what was requested before and what the challenge names, sorted; with <c>pcaAware</c> a valid <c>pca_need</c> hands the typed
    /// requirement to the approval flow and still carries the scope union as the fallback; a union that adds nothing (and no usable need) gives up
    /// instead of looping. The attempt counter bounds every path. <paramref name="state"/>: requested, attempts, optional maxAttempts (default 3), pcaAware.</summary>
    public static D PlanStepUp(object? status, object? wwwAuthenticate, D state)
    {
        double max = state.GetValueOrDefault("maxAttempts") != null ? NumOr(state["maxAttempts"]) : 3;
        D? bearer = null;
        if (IntentJs.NumOf(status) is double st && st == 403.0)
            foreach (var c in ParseChallenges(wwwAuthenticate)) if (((D)c!)["scheme"] as string == "bearer") { bearer = (D)c!; break; }
        var bparams = (D?)bearer?["params"];
        if (bearer == null || bparams!.GetValueOrDefault("error") as string != "insufficient_scope") return GiveUp("not_insufficient_scope");
        double attemptsIn = NumOr(state.GetValueOrDefault("attempts"));
        if (!(double.IsFinite(attemptsIn) && attemptsIn < max)) return GiveUp("retry_limit");
        var requested = state.GetValueOrDefault("requested") as L ?? throw JsX.TypeError("state.requested is not iterable");
        var had = new HashSet<string>(requested.Select(JsX.Str));
        var u = new List<string>();
        foreach (var r in requested) { var s = JsX.Str(r); if (!u.Contains(s)) u.Add(s); }
        foreach (var s in SplitScopes(bparams.GetValueOrDefault("scope"))) if (!u.Contains(s)) u.Add(s);
        u.Sort(string.CompareOrdinal);
        var attempts = JsX.Number(attemptsIn + 1);
        if (state.GetValueOrDefault("pcaAware") is bool pa && pa)
        {
            var r = wwwAuthenticate is string ? PcaNeedFromChallenge(wwwAuthenticate) : null;
            if (r != null && r["ok"] is true)
                return new D { ["action"] = "pca", ["need"] = r["need"], ["fallbackScopes"] = u.Cast<object?>().ToList(), ["attempts"] = attempts };
            // a missing or malformed pca_need is not an error: it falls through to the stock behaviour below
        }
        if (u.All(had.Contains)) return GiveUp("no_new_scope");
        return new D { ["action"] = "scope", ["scopes"] = u.Cast<object?>().ToList(), ["attempts"] = attempts };
    }

    /// <summary>The reason a present-but-unusable <c>pca_need</c> was ignored (for client logs), or null.</summary>
    public static string? PcaNeedProblem(object? wwwAuthenticate)
    {
        var r = PcaNeedFromChallenge(wwwAuthenticate);
        return r != null && r["ok"] is false ? r["code"] as string : null;
    }

    /// <summary>RFC 9207 section 2.4 as tabulated in the MCP authorization specification: compare a present <c>iss</c> with the recorded issuer by
    /// plain string comparison (no normalization); reject an absent <c>iss</c> only when the server advertised
    /// <c>authorization_response_iss_parameter_supported: true</c>. Without a recorded issuer nothing can be checked and the response is refused.
    /// An absent <c>iss</c> and a null one differ: null never equals the recorded issuer.</summary>
    public static D CheckAuthorizationResponseIss(D a)
    {
        D Res(bool proceed, string? reason) { var m = new D { ["proceed"] = proceed }; if (reason != null) m["reason"] = reason; return m; }
        if (a.GetValueOrDefault("recordedIssuer") is not string rec || rec.Length == 0) return Res(false, "no_recorded_issuer");
        if (!a.ContainsKey("iss")) return a.GetValueOrDefault("issParameterSupported") is true ? Res(false, "iss_missing") : Res(true, null);
        return a["iss"] is string iss && iss == rec ? Res(true, null) : Res(false, "iss_mismatch");
    }

    // ---- conformance matrix (client side of step-up) ----

    static D Row(string id, string requirement, string section, params string[] levels)
    {
        var lv = new D();
        for (int i = 0; i < McpClientRevisions.Count; i++) lv[McpClientRevisions[i]] = levels[i];
        return new D { ["id"] = id, ["requirement"] = requirement, ["levels"] = lv, ["section"] = section };
    }

    /// <summary>The MCP authorization conformance matrix for the client side of step-up: one row per requirement, the level per revision.</summary>
    public static L McpAuthClientRows() => new()
    {
        Row("parse-www-authenticate", "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "Protected Resource Metadata Discovery Requirements", "n/a", "MUST", "MUST", "MUST", "MUST"),
        Row("step-up-on-insufficient-scope", "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "Step-Up Authorization Flow", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"),
        Row("scope-union", "The new scope set is the union of the previously requested set and the challenge scopes.", "Step-Up Authorization Flow, step 2", "n/a", "n/a", "n/a", "SHOULD", "SHOULD"),
        Row("retry-limit", "Retry no more than a few times and track upgrade attempts per resource and operation.", "Step-Up Authorization Flow, step 4", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"),
        Row("iss-validation-table", "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "Authorization Response Validation", "n/a", "n/a", "n/a", "MUST", "MUST"),
        Row("pca-need-ignored-by-stock-client", "A client that does not know pca_need behaves exactly as without it.", "RFC 9110 section 11.2 (unknown auth-params are ignored)", "EXT", "EXT", "EXT", "EXT", "EXT"),
    };
}
