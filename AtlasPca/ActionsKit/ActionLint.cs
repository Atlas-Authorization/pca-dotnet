// The 24 stable lint rules over action definitions, SARIF output and the digest of the rule list. Pure: defs in, findings out,
// deterministic order. A def that fails ValidateDef is reported as LD-000 and not linted further.
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionLintRules
{
    public static readonly (string Id, string Severity, string Title)[] LINT_RULES =
    {
        ("LD-001", "error", "a destroy-like verb whose effects do not delete"),
        ("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
        ("LD-003", "error", "a numeric parameter without min and max"),
        ("LD-004", "error", "a money-moving action without idempotency"),
        ("LD-005", "error", "personal data can leave without the matching effect"),
        ("LD-006", "error", "a declared reversibility or blast below the effective floor"),
        ("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
        ("LD-008", "error", "resource id '*' with scope one"),
        ("LD-009", "error", "a duplicate verb or alias collision"),
        ("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
        ("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
        ("LD-012", "error", "a structural param rule that the effective traits require is violated"),
        ("LD-013", "error", "a read-only action that can mutate or handles credentials"),
        ("LD-014", "error", "one binding in two defs"),
        ("LW-001", "warning", "description missing or too long, or title not imperative"),
        ("LW-002", "warning", "a string parameter without max_len"),
        ("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
        ("LW-004", "warning", "an unreviewed def in a stable pack"),
        ("LW-005", "warning", "a dismissed suggested trait without a reason"),
        ("LW-006", "warning", "an array parameter without max_items"),
        ("LW-007", "warning", "a critical parameter without provenance_min"),
        ("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
        ("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
        ("LW-010", "warning", "since is missing"),
    };
    public static readonly (string Id, string Severity, string Title) NOTE_RULE = ("LN-001", "note", "an informational note from the loader");
    public static readonly (string Id, string Severity, string Title) STRUCTURE_RULE = ("LD-000", "error", "the def is not well formed and cannot be loaded");
}

public static class ActionLint
{
    public const string LintRulesDigestDomain = "atlas-pca/action-lint-rules/v1";

    /// <summary>The digest policy-ci pins: the ordered (id, severity, title) list.</summary>
    public static string LintRulesDigest() => Pca.HashCanonical(new D
    {
        ["d"] = LintRulesDigestDomain,
        ["rules"] = new L(ActionLintRules.LINT_RULES.Select(r => (object?)new D { ["id"] = r.Id, ["severity"] = r.Severity, ["title"] = r.Title })),
    });

    static bool Destroy(string s) => Starts(s, "delete", "destroy", "remove", "purge", "drop", "erase", "wipe", "revoke", "terminate", "truncate");
    static bool Send(string s) => Starts(s, "send", "email", "notify", "sms", "message", "post_to", "broadcast", "invite");
    static bool Export(string s) => Starts(s, "export", "download", "dump", "backup", "extract");
    static bool Starts(string s, params string[] words) => words.Any(w => s == w || s.StartsWith(w + "_", StringComparison.Ordinal));
    static string LastSeg(string verb) => verb.Split('.')[^1];

    static List<string> BindingKeys(D d)
    {
        var b = Ak.G(d, "bindings");
        var o = new List<string>();
        if (Ak.G(b, "mcp") is D mcp) o.Add("mcp:" + Ak.JsStr(Ak.G(mcp, "tool")));
        if (Ak.G(b, "openapi") is D oa) o.Add("openapi:" + Ak.JsStr(Ak.G(oa, "operationId")));
        if (Ak.G(b, "http") is D h) o.Add($"http:{((string)h["method"]!).ToUpperInvariant()} {h["path"]}");
        if (Ak.G(b, "graphql") is D g) o.Add($"graphql:{g["op"]}.{g["field"]}");
        if (Ak.G(b, "grpc") is D rp) o.Add($"grpc:{rp["service"]}/{rp["method"]}");
        if (Ak.G(b, "asyncapi") is D a) o.Add($"asyncapi:{a["op"]} {a["channel"]}");
        return o;
    }

    static readonly string[][] NameGroups = { new[] { "create_", "new_", "add_", "make_" }, new[] { "delete_", "remove_", "destroy_" } };

    static List<string> VocabularyIssues(object? x, Dictionary<string, D> reg)
    {
        var o = new List<string>();
        if (x is not D xd) return o;
        if (Ak.G(xd, "effects") is L effs)
            foreach (var e in effs) if (!(e is string es && Ak.Effects.Contains(es))) o.Add($"unknown effect '{Ak.JsStr(e)}'");
        if (Ak.G(xd, "params") is D ps)
            foreach (var (n, q) in ps)
            {
                if (q is not D qd) continue;
                if (qd.TryGetValue("role", out var role) && !Actions.IsRole(role)) o.Add($"{n}: unknown role '{Ak.JsStr(role)}'");
                if (qd.TryGetValue("format", out var fmt) && !Actions.IsFormat(fmt)) o.Add($"{n}: unknown format '{Ak.JsStr(fmt)}'");
            }
        if (Ak.G(xd, "context") is L ctx)
            foreach (var c in ctx) if (!Actions.IsContextKey(c)) o.Add($"unknown context key '{Ak.JsStr(c)}' (known: {string.Join(", ", Ak.ContextKeys)}, session_taint_max:<level>)");
        if (Ak.G(xd, "traits") is L trs)
            foreach (var t in trs) if (t is string ts && !reg.ContainsKey(ts)) o.Add($"unknown trait '{ts}'");
        return o;
    }

    /// <summary>Lint a pack's defs (raw values, so a malformed one is still reported). opts: {customTraits?, stability?, ns?}. Sorted by verb, rule, param, message.</summary>
    public static L LintDefs(L raw, D? opts = null, Func<D, bool>? attestationVerified = null)
    {
        opts ??= new D();
        var outp = new List<D>();
        void Add(string rule, string? verb, string message, string? param = null)
        {
            var f = new D { ["rule"] = rule, ["severity"] = rule == ActionLintRules.STRUCTURE_RULE.Id ? "error" : ActionLintRules.LINT_RULES.First(r => r.Id == rule).Severity };
            if (verb != null) f["verb"] = verb;
            if (param != null) f["param"] = param;
            f["message"] = message;
            outp.Add(f);
        }

        var reg = Actions.CoreRegistry;
        if (Ak.G(opts, "customTraits") is L ct && ct.Count > 0)
        {
            try { reg = Actions.ExtendRegistry(reg, ct); }
            catch (Exception e) { Add("LD-007", null, "invalid custom traits: " + e.Message); }
        }

        var defs = new List<D>();
        foreach (var x in raw)
        {
            var verb = x is D xd && xd.TryGetValue("verb", out var vv) && vv is string vs ? vs : null;
            var vocab = VocabularyIssues(x, reg);
            if (vocab.Count > 0) { foreach (var v in vocab) Add("LD-007", verb, v); continue; }
            var bad = Actions.ValidateDef(x);
            if (bad != null) { Add(ActionLintRules.STRUCTURE_RULE.Id, verb, bad); continue; }
            defs.Add((D)x!);
        }

        // ---- pack-level rules
        var byVerb = new Dictionary<string, D>();
        var names = new Dictionary<string, string>();
        foreach (var d in defs)
        {
            var dv = (string)d["verb"]!;
            if (byVerb.ContainsKey(dv)) Add("LD-009", dv, $"verb '{dv}' is defined twice");
            byVerb[dv] = d;
        }
        foreach (var d in defs)
        {
            var dv = (string)d["verb"]!;
            foreach (var n in new[] { dv }.Concat(Ak.Strs(Ak.G(d, "aliases"))))
            {
                if (names.TryGetValue(n, out var owner) && owner != dv) Add("LD-009", dv, $"'{n}' is also a name of '{owner}'");
                else if (!names.ContainsKey(n)) names[n] = dv;
            }
        }
        var bound = new Dictionary<string, string>();
        foreach (var d in defs)
        {
            var dv = (string)d["verb"]!;
            foreach (var k in BindingKeys(d))
            {
                if (bound.TryGetValue(k, out var owner) && owner != dv) Add("LD-014", dv, $"binding {k} is also bound by '{owner}'");
                else bound[k] = dv;
            }
        }
        foreach (var grp in NameGroups)
        {
            var used = new Dictionary<string, int>();
            foreach (var d in defs)
            {
                var g = grp.FirstOrDefault(p => LastSeg((string)d["verb"]!).StartsWith(p, StringComparison.Ordinal));
                if (g != null) used[g] = used.GetValueOrDefault(g) + 1;
            }
            if (used.Count > 1)
            {
                var win = used.OrderBy(kv => -kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).First().Key;
                foreach (var d in defs)
                {
                    var g = grp.FirstOrDefault(p => LastSeg((string)d["verb"]!).StartsWith(p, StringComparison.Ordinal));
                    if (g != null && g != win) Add("LW-008", (string)d["verb"]!, $"uses '{g}' where its siblings use '{win}'");
                }
            }
        }
        if (Ak.G(opts, "ns") is string ns)
            foreach (var d in defs)
            {
                var dv = (string)d["verb"]!;
                if (dv.Split('.')[0] != ns) Add("LW-008", dv, $"verb namespace '{dv.Split('.')[0]}' differs from the file namespace '{ns}'");
            }

        // ---- per-def rules
        var traitsDigest = Actions.TraitsDigest(reg);
        foreach (var d in defs)
        {
            var dv = (string)d["verb"]!;
            var n = Actions.Normalize(d);
            var np = (D)n["params"]!;
            var pnames = np.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
            var eff = ActionEffective.EffectiveWith(d, reg, attestationVerified);
            var hint = (D)eff["hint"]!;
            var tset = new HashSet<string>(Ak.Strs(hint["traits"]));
            var cl = new HashSet<string>(Ak.Strs(hint["closure"]));
            var effects = Ak.Strs(d["effects"]);
            List<string> Params(Func<D, bool> pred) => pnames.Where(k => pred((D)np[k]!)).ToList();
            bool Tag(D q, string t) => Ak.Strs(Ak.G(q, "tags")).Contains(t);
            var review = (D)d["review"]!;
            var state = (string)review["state"]!;

            if (Destroy(LastSeg(dv)) && !effects.Contains("delete")) Add("LD-001", dv, $"the verb says '{LastSeg(dv)}' but effects do not include delete");
            foreach (var k in Params(q => Ak.S(q, "role") is "money.amount" or "money.fee"))
            {
                var u = Ak.G(np[k], "unit");
                if (u is not D ud || Ak.S(ud, "kind") != "money") Add("LD-002", dv, "a money parameter needs a unit of kind money with a currency", k);
                else if (ud["ccy"] is not string)
                {
                    var frm = Ak.S(ud["ccy"], "from");
                    var c = frm != null && np.TryGetValue(frm, out var cv) ? (D?)cv : null;
                    if (c == null || Ak.S(c, "role") != "money.currency" || Ak.S(c, "format") != "iso_currency")
                        Add("LD-002", dv, $"the currency parameter '{frm}' needs role money.currency and format iso_currency", k);
                }
            }
            foreach (var k in Params(q => Ak.S(q, "role") == "money.currency"))
                if (Ak.S(np[k], "format") != "iso_currency") Add("LD-002", dv, "a currency parameter needs the iso_currency format", k);
            foreach (var k in Params(q => Ak.S(q, "type") is "integer" or "duration"))
            {
                var pq = (D)np[k]!;
                var role = Ak.S(pq, "role");
                if (role != null && role.StartsWith("id.", StringComparison.Ordinal)) continue;
                if (role == "count.limit" && pq.ContainsKey("max")) continue;
                if (!pq.ContainsKey("min") || !pq.ContainsKey("max"))
                    Add("LD-003", dv, $"a numeric parameter needs both min and max (has {(!pq.ContainsKey("min") ? "no min" : "min")}, {(!pq.ContainsKey("max") ? "no max" : "max")})", k);
            }
            if ((effects.Contains("pay") || tset.Contains("pca.money_moving")) && Ak.S(n["idempotency"], "mode") == "none")
                Add("LD-004", dv, "a money-moving action needs idempotency key_param or natural");
            var pii = Params(q => Tag(q, "pii") || (Ak.S(q, "role") is string r && (r.StartsWith("contact.", StringComparison.Ordinal) || r.StartsWith("person.", StringComparison.Ordinal))));
            if (pii.Count > 0)
            {
                var expected = new HashSet<string>();
                foreach (var s in Ak.Lst(d, "side_effects")) if (Ak.S(s, "kind") is "send" or "export") expected.Add(Ak.S(s, "kind")!);
                if (Send(LastSeg(dv))) expected.Add("send");
                if (Export(LastSeg(dv))) expected.Add("export");
                foreach (var e in expected.OrderBy(x => x, StringComparer.Ordinal))
                    if (!effects.Contains(e)) Add("LD-005", dv, $"personal data can {(e == "send" ? "be sent" : "be exported")} ({string.Join(", ", pii)}) but effects do not include {e}");
            }
            foreach (var c in (L)eff["clamps"]!)
                Add("LD-006", dv, $"declared {(Ak.S(c, "field") == "rev" ? "reversibility" : "blast")} {Ak.JsStr(Ak.G(c, "declared"))} is below the floor {Ak.JsStr(Ak.G(c, "floor"))}");
            var res = (D)n["resource"]!;
            if (Ak.G(res, "id") is string rid && rid == "*" && Ak.S(res, "scope") == "one") Add("LD-008", dv, "resource id '*' with scope one names every resource at once");
            if (!Ak.IsReadOnly(effects) && ActionUndo.MayBeReversible(d))
            {
                var comp = Ak.G(d, "compensates");
                if (comp == null) Add("LD-010", dv, "a write declared reversible must name its compensating action (compensates)");
                else if (comp is not string cs || !byVerb.ContainsKey(cs)) Add("LD-010", dv, $"compensates '{Ak.JsStr(comp)}', which is not in the pack");
                else
                {
                    var s = ActionUndo.CompensationShape(d, byVerb[cs]);
                    if (s["ok"] is not true) Add("LD-010", dv, $"compensates '{cs}', which cannot undo it: {s["reason"]}");
                }
            }
            var att = Ak.G(review, "attestation");
            if (state == "confirmed")
            {
                if (att == null) Add("LD-011", dv, "confirmed without an attestation");
                else if (Ak.G(att, "def_digest") is not string dd || dd != Actions.DefDigest(d)) Add("LD-011", dv, "the attestation covers a different digest of this def");
                else if (Ak.G(att, "traits_digest") is not string td || td != traitsDigest) Add("LD-011", dv, "the attestation was made against a different trait registry");
                else if (attestationVerified != null ? !attestationVerified(d) : !Ak.Has(att, "sig")) Add("LD-011", dv, "the attestation is not signed by a pinned reviewer");
            }
            var dismissedNames = new HashSet<string>(state == "confirmed" ? Ak.Lst(att, "dismissed").Select(x => Ak.S(x, "trait")).OfType<string>() : Enumerable.Empty<string>());
            foreach (var t in Ak.Strs(Ak.G(Ak.G(review, "provenance"), "union")))
                if (!cl.Contains(t) && !dismissedNames.Contains(t)) Add("LD-011", dv, $"the union-added trait {t} was removed without a signed dismissal");
            var own = new[] { "money_has_currency", "money_amount_bounded", "pay_has_idempotency" };
            foreach (var r in ActionEffective.PrulesViolations(d, Ak.Strs(((D)hint["eff"]!)["prules"])))
                if (!own.Contains(r)) Add("LD-012", dv, $"structural rule {r} is required by the action's traits and violated");
            if (Ak.IsReadOnly(effects))
            {
                var enforced = Ak.Strs(Ak.G(d, "context")).Contains("sandbox_attested");
                foreach (var k in Params(q => Ak.S(q, "role") is "code.command" or "query.sql"))
                    if (!enforced) Add("LD-013", dv, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k);
                foreach (var k in Params(q => Tag(q, "credential"))) Add("LD-013", dv, "a read-only action handles a credential", k);
            }

            // ---- warnings
            if (!d.ContainsKey("description")) Add("LW-001", dv, "description is missing");
            else if (Ak.U8((string)d["description"]!) > 400) Add("LW-001", dv, "description is longer than 400 bytes");
            var title = (string)d["title"]!;
            var cut = title.ToList().FindIndex(JsJson.IsJsSpace);
            var first = (cut < 0 ? title : title[..cut]).ToLowerInvariant();
            if (first.EndsWith("ing", StringComparison.Ordinal) || first.EndsWith("ed", StringComparison.Ordinal)
                || (first.Length >= 2 && first[^1] == 's' && first[^2] != 's' && !(first.EndsWith("us", StringComparison.Ordinal) || first.EndsWith("is", StringComparison.Ordinal)))
                || first is "a" or "an" or "the")
                Add("LW-001", dv, $"title '{title}' is not imperative");
            foreach (var k in Params(q => Ak.S(q, "type") == "string" && !q.ContainsKey("max_len") && !q.ContainsKey("values")))
                Add("LW-002", dv, "a string parameter without max_len (the default is 1024; say it)", k);
            if (cl.Contains("pca.external_communication"))
                foreach (var k in Params(q => Ak.S(q, "type") == "string" && !q.ContainsKey("values") && !q.ContainsKey("format") && (Ak.S(q, "role") is not string r || r.StartsWith("text.", StringComparison.Ordinal)) && !Tag(q, "free_text_outbound")))
                    if (k != Ak.S(n["idempotency"], "param")) Add("LW-003", dv, "free text flows into an outbound action without tags: [free_text_outbound]", k);
            if (Ak.G(opts, "stability") is string stab && stab == "stable" && state is "unreviewed" or "suggested") Add("LW-004", dv, $"a {state} def in a stable pack");
            foreach (var x in Ak.Lst(att, "dismissed"))
                if (Ak.U16(Ak.S(x, "reason")!.Trim(Actions.JsSpace)) < 5) Add("LW-005", dv, $"dismissed trait {Ak.S(x, "trait")} has no reason");
            foreach (var k in Params(q => Ak.S(q, "type") == "array" && Ak.G(q, "max_items") == null)) Add("LW-006", dv, "an array parameter without max_items", k);
            foreach (var k in Params(q => Ak.SensRank(Ak.S(q, "sensitivity")!) >= Ak.SensRank("critical") && !q.ContainsKey("provenance_min"))) Add("LW-007", dv, "a critical parameter without provenance_min", k);
            if ((tset.Contains("pca.money_moving") || tset.Contains("pca.destructive") || tset.Contains("pca.privilege_change")) && Ak.Lst(d, "examples").Count == 0)
                Add("LW-009", dv, "no example for a money-moving, destructive or privilege-changing action");
            if (!d.ContainsKey("since")) Add("LW-010", dv, "since is missing");
        }

        string K(D f, string k) => Ak.S(f, k) ?? "";
        return new L(outp.OrderBy(f => K(f, "verb"), StringComparer.Ordinal).ThenBy(f => K(f, "rule"), StringComparer.Ordinal)
            .ThenBy(f => K(f, "param"), StringComparer.Ordinal).ThenBy(f => K(f, "message"), StringComparer.Ordinal));
    }

    /// <summary>Does the run fail? Errors always; warnings under strict.</summary>
    public static bool LintFails(L fs, bool strict = false) => fs.Any(f => Ak.S(f, "severity") == "error" || (strict && Ak.S(f, "severity") == "warning"));

    static bool Truthy(object? v) => v is string s ? s.Length > 0 : v != null && !(v is bool b && !b);

    /// <summary>Plain text, one line per finding.</summary>
    public static string LintText(L fs)
    {
        if (fs.Count == 0) return "0 errors, 0 warnings";
        var e = fs.Count(f => Ak.S(f, "severity") == "error");
        var w = fs.Count(f => Ak.S(f, "severity") == "warning");
        var lines = fs.Select(f =>
        {
            var loc = "";
            if (Ak.G(f, "file") is string file && file.Length > 0)
                loc = file + (Ak.G(f, "line") != null ? $":{Ak.JsStr(Ak.G(f, "line"))}:{(Ak.G(f, "column") != null ? Ak.JsStr(Ak.G(f, "column")) : "1")}" : "") + ": ";
            var v = Ak.G(f, "verb"); var p = Ak.G(f, "param");
            var vs = v == null ? "" : Ak.JsStr(v);
            var ps = Truthy(p) ? Ak.JsStr(p) : "";
            return $"{Ak.S(f, "severity")!.PadRight(7)} {Ak.S(f, "rule")}  {loc}{vs}{(ps.Length > 0 ? $" [{ps}]" : "")}{(vs.Length > 0 || ps.Length > 0 ? ": " : "")}{Ak.JsStr(Ak.G(f, "message"))}";
        });
        var notes = fs.Count - e - w;
        return $"{string.Join("\n", lines)}\n{e} error{(e == 1 ? "" : "s")}, {w} warning{(w == 1 ? "" : "s")}{(notes > 0 ? $", {notes} note{(notes == 1 ? "" : "s")}" : "")}";
    }

    static string Level(string? s) => s == "error" ? "error" : s == "warning" ? "warning" : "note";

    /// <summary>SARIF 2.1.0, so findings appear as pull request annotations.</summary>
    public static D ToSarif(L fs, D? tool = null)
    {
        var rules = new[] { ActionLintRules.STRUCTURE_RULE, ActionLintRules.NOTE_RULE }.Concat(ActionLintRules.LINT_RULES).ToList();
        var driver = new D { ["name"] = Ak.G(tool, "name") ?? "pca actions lint" };
        if (Truthy(Ak.G(tool, "version"))) driver["version"] = Ak.G(tool, "version");
        driver["rules"] = new L(rules.Select(r => (object?)new D
        {
            ["id"] = r.Id, ["shortDescription"] = new D { ["text"] = r.Title }, ["defaultConfiguration"] = new D { ["level"] = Level(r.Severity) },
        }));
        var results = new L();
        foreach (var f in fs)
        {
            var loc = new D();
            if (Ak.G(f, "file") is string file && file.Length > 0)
            {
                var pl = new D { ["artifactLocation"] = new D { ["uri"] = file } };
                if (Ak.G(f, "line") != null) pl["region"] = new D { ["startLine"] = Ak.G(f, "line"), ["startColumn"] = Ak.G(f, "column") ?? new Num("1") };
                loc["physicalLocation"] = pl;
            }
            var v = Ak.G(f, "verb");
            if (Truthy(v)) loc["logicalLocations"] = new L { new D { ["name"] = v, ["kind"] = "member" } };
            var p = Ak.G(f, "param");
            var prefix = Truthy(v) ? $"{Ak.JsStr(v)}{(Truthy(p) ? $" [{Ak.JsStr(p)}]" : "")}: " : "";
            results.Add(new D
            {
                ["ruleId"] = Ak.G(f, "rule"), ["level"] = Level(Ak.S(f, "severity")),
                ["message"] = new D { ["text"] = prefix + Ak.JsStr(Ak.G(f, "message")) }, ["locations"] = new L { loc },
            });
        }
        return new D
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json", ["version"] = "2.1.0",
            ["runs"] = new L { new D { ["tool"] = new D { ["driver"] = driver }, ["results"] = results } },
        };
    }
}
