// Everything an ActionDef yields: the signed schema verb and document, the operation binding, risk inputs, policy predicates, ontology
// terms, the policy card, the escalation tier, MCP annotations and the plain-language explanation. attestationVerified is the caller's
// confirmation verifier.
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionDerive
{
    public const int MaxParamPathDepth = 3;
    public static readonly string[] EscTiers = { "auto", "confirm", "cosign", "stepup" };
    public static readonly string[] RiskNames = { "low", "elevated", "high", "critical" };
    public const string CoreNamespace = "pca.";

    /// <summary>The reversibility score table.</summary>
    public static D ReversibilityScore() => new() { ["reversible"] = 1.0, ["rate_limited"] = 0.4, ["irreversible"] = 0.0 };
    static double RevScore(string r) => r switch { "reversible" => 1.0, "rate_limited" => 0.4, _ => 0.0 };

    // ---- flattened params + role lookup
    /// <summary>Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf.</summary>
    public static D FlattenParams(D parameters)
    {
        var o = new D();
        void Walk(string prefix, int depth, object? v)
        {
            if (v is D m && depth < MaxParamPathDepth && m.Count > 0)
                foreach (var k in IntentJs.JsKeys(m.Keys)) Walk(prefix == "" ? k : prefix + "." + k, depth + 1, m[k]);
            else o[prefix] = v;
        }
        foreach (var k in IntentJs.JsKeys(parameters.Keys)) Walk(k, 1, parameters[k]);
        return o;
    }

    /// <summary>The unique param carrying <paramref name="role"/>, or throws no_param / ambiguous_param.</summary>
    public static string ParamByRole(D d, string role)
    {
        var ps = (D)d["params"]!;
        var hits = ps.Keys.Where(n => Ak.S(ps[n], "role") == role).OrderBy(x => x, StringComparer.Ordinal).ToList();
        if (hits.Count == 0) throw new ActionKitError("no_param", $"'{d["verb"]}' has no parameter with role {role}");
        if (hits.Count > 1) throw new ActionKitError("ambiguous_param", $"'{d["verb"]}' has several parameters with role {role}");
        return hits[0];
    }

    /// <summary>The one adapter to the Goal IR's 4 classes: read | reversible | external_send | irreversible.</summary>
    public static string EffectClass(D d)
    {
        var n = Actions.Normalize(d);
        var effects = Ak.Strs(n["effects"]);
        if (Ak.IsReadOnly(effects)) return "read";
        if (Actions.WorstReversibility(n["reversibility"], ActionDiff.ParamsOf(n)) == "irreversible") return "irreversible";
        if (effects.Any(e => e is "send" or "publish" or "export")) return "external_send";
        return "reversible";
    }

    // ---- signed schema (v2)
    static string? UnitId(D p)
    {
        if (Ak.G(p, "unit") is not D u) return null;
        var kind = (string)u["kind"]!;
        if (kind != "money") return kind;
        return u.GetValueOrDefault("ccy") is string c ? "money." + c.ToLowerInvariant() : null;
    }

    static D? UnitDecl(D p)
    {
        if (Ak.G(p, "unit") is not D u) return null;
        if ((string)u["kind"]! != "money") return new D { ["kind"] = u["kind"] };
        if (u.GetValueOrDefault("ccy") is not string c) return null;
        var o = new D { ["kind"] = "money", ["currency"] = c };
        if (u.ContainsKey("exp")) o["exponent"] = u["exp"];
        return o;
    }

    static D ToParamDecl(D n)
    {
        var d = new D { ["type"] = n["type"], ["semantic"] = Ak.G(n, "role") ?? "generic." + (string)n["type"]!, ["sensitivity"] = n["sensitivity"] };
        if (!(n["required"] is true)) d["required"] = false;
        if (n.ContainsKey("values")) d["values"] = new L((L)n["values"]!);
        foreach (var k in new[] { "min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description" })
            if (n.ContainsKey(k)) d[k] = Ak.Copy(n[k]);
        var uid = UnitId(n);
        if (uid != null) d["unit"] = uid;
        if (n.ContainsKey("accumulates")) d["accumulates_into"] = new L((L)n["accumulates"]!);
        if (n.ContainsKey("role")) d["role"] = n["role"];
        if (n.ContainsKey("tags")) d["tags"] = new L((L)n["tags"]!);
        return d;
    }

    /// <summary>{verb, units}: the signed v2 verb declaration of a def (effects, traits, def digest, materialized floors) and the units it needs.</summary>
    public static D ToSchemaVerb(D d, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null)
    {
        var n = Actions.Normalize(d);
        var eff = ActionEffective.EffectiveWith(d, reg, attestationVerified);
        var ps = new D(); var units = new D();
        foreach (var (name, po) in (D)n["params"]!)
        {
            var p = (D)po!;
            ps["action.params." + name] = ToParamDecl(p);
            var uid = UnitId(p);
            if (uid != null) units[uid] = UnitDecl(p);
        }
        var effects = Ak.Strs(n["effects"]);
        var v = new D
        {
            ["verb"] = n["verb"], ["kind"] = Ak.IsReadOnly(effects) ? "read" : "write", ["params"] = ps, ["effects"] = new L((L)n["effects"]!),
            ["traits"] = eff["traits"], ["def"] = Actions.DefDigest(d), ["floors"] = eff["eff"],
        };
        var att = Ak.G(Ak.G(d, "review"), "attestation");
        if (eff["confirmed"] is true && att is D ad && ad.ContainsKey("sig")) v["confirmation"] = att;
        var r = n["reversibility"];
        if (r is string rs) v["reversibility"] = rs;
        else
        {
            var by = new D { ["param"] = "action.params." + (string)Ak.G(r, "by")!, ["map"] = new D((D)Ak.G(r, "map")!) };
            if (Ak.Has(r, "default")) by["default"] = Ak.G(r, "default");
            v["reversibility_by"] = by;
        }
        var b = n["bindings"];
        if (Ak.G(b, "mcp") is D mcp) v["mcp"] = mcp.ContainsKey("tool") ? new D { ["tool"] = mcp["tool"] } : new D();
        if (Ak.G(b, "openapi") is D oa) v["openapi"] = oa.ContainsKey("operationId") ? new D { ["operationId"] = oa["operationId"] } : new D();
        if (n.ContainsKey("description")) v["description"] = n["description"];
        return new D { ["verb"] = v, ["units"] = units };
    }

    /// <summary>The unsigned v2 schema document of a set of defs (verbs sorted; units merged, a conflicting redefinition refused).</summary>
    public static D ToSchemaDoc(IEnumerable<D> defs, Dictionary<string, D> reg, D meta, Func<D, bool>? attestationVerified = null)
    {
        var verbs = new L(); var units = new D(); var seen = new HashSet<string>();
        foreach (var d in defs.OrderBy(x => (string)x["verb"]!, StringComparer.Ordinal))
        {
            var dv = (string)d["verb"]!;
            if (!seen.Add(dv)) throw new ActionKitError("duplicate_verb", $"verb '{dv}' appears twice");
            var o = ToSchemaVerb(d, reg, attestationVerified);
            verbs.Add(o["verb"]);
            foreach (var (uid, u) in (D)o["units"]!)
            {
                if (units.TryGetValue(uid, out var prev) && prev != null && (!SameMember(prev, u, "kind") || !SameMember(prev, u, "currency") || !SameMember(prev, u, "exponent")))
                    throw new ActionKitError("unit_conflict", $"unit '{uid}' is declared with two different definitions");
                units[uid] = u;
            }
        }
        var custom = reg.Values.Where(t => !((string)t["id"]!).StartsWith(CoreNamespace, StringComparison.Ordinal)).OrderBy(t => (string)t["id"]!, StringComparer.Ordinal).ToList();
        var doc = new D { ["v"] = 2L, ["kind"] = "pca-action-schema", ["site"] = meta["site"], ["aud"] = meta["aud"], ["version"] = meta["version"] };
        if (units.Count > 0) doc["units"] = units;
        doc["verbs"] = verbs;
        doc["traits_digest"] = Actions.TraitsDigest(reg);
        if (custom.Count > 0) doc["trait_defs"] = new L(custom);
        if (Ak.G(meta, "pack") != null) doc["pack"] = meta["pack"];
        return doc;
    }
    static bool SameMember(object? a, object? b, string k) => IntentJs.JsonEquals(Ak.G(a, k), Ak.G(b, k));

    // ---- operation binding
    /// <summary>{ok:true, op:{verb, resource, params}} or {ok:false, reason}: refuses (never guesses) a missing or non-matching id.</summary>
    public static D OperationOf(D d, D call)
    {
        var flat = FlattenParams((D)call["params"]!);
        var dps = (D)d["params"]!;
        var declared = dps.Keys.OrderBy(x => x, StringComparer.Ordinal).ToList();
        var ps = new D();
        foreach (var k in declared) if (flat.TryGetValue(k, out var fv)) ps[k] = fv;
        var res = (D)d["resource"]!;
        var rtype = (string)res["type"]!; var rid = res["id"]; var scope = (string)res["scope"]!;
        string resource;
        if (!(rid is string rs && rs == "*") && rid is D rd && rd.ContainsKey("exact")) resource = $"{rtype}:{rd["exact"]}";
        else
        {
            var idParam = declared.FirstOrDefault(n => Ak.S(dps[n], "role") == "id." + rtype);
            var val = idParam != null ? ps.GetValueOrDefault(idParam) : null;
            if (val is string sv)
            {
                if (!ActionIdPattern.IdMatches(rid, sv)) return new D { ["ok"] = false, ["reason"] = $"the id '{sv}' does not match the resource pattern of {d["verb"]}" };
                resource = $"{rtype}:{sv}";
            }
            else if (scope != "one") resource = rtype + ":*";
            else return new D { ["ok"] = false, ["reason"] = $"{d["verb"]} needs a parameter with role id.{rtype} to name its resource" };
        }
        return new D { ["ok"] = true, ["op"] = new D { ["verb"] = d["verb"], ["resource"] = resource, ["params"] = ps } };
    }

    // ---- risk
    static double Unit01(double x) => Math.Min(1, Math.Max(0, x));

    /// <summary>Risk inputs for a call: reversibility score and blast from the effective profile; a money.amount param makes the blast amount/kappa from the signed kappa (missing or invalid: 1, the worst case).</summary>
    public static D RiskOf(D d, D eff, D? parameters = null, D? opts = null)
    {
        var e = (D)eff["eff"]!;
        var blast = Unit01(Ak.I(e["blast_ppm"]) / 1_000_000.0);
        var dps = (D)d["params"]!;
        var money = dps.Keys.Where(n => Ak.S(dps[n], "role") == "money.amount").OrderBy(x => x, StringComparer.Ordinal).ToList();
        if (money.Count > 0)
        {
            var flat = parameters != null && parameters.Count > 0 ? FlattenParams(parameters) : new D();
            var amount = IntentJs.NumOf(flat.GetValueOrDefault(money[0]));
            var kappa = IntentJs.NumOf(Ak.G(opts, "kappa"));
            blast = amount is double a && double.IsFinite(a) && a >= 0 && kappa is double k && k > 0 ? Unit01(a / k) : 1;
        }
        var outp = new D { ["reversibility"] = RevScore((string)e["rev"]!), ["blastRadius"] = blast, ["confidence"] = 1L };
        if (IntentJs.NumOf(Ak.G(opts, "taint")) is double t && double.IsFinite(t)) outp["taint"] = Unit01(t);
        return outp;
    }

    // ---- predicates
    /// <summary>"type:prefix*", "type:exact" or "type:*".</summary>
    public static string ResourceMatcher(D d)
    {
        var res = (D)d["resource"]!;
        var rtype = (string)res["type"]!; var rid = res["id"];
        if (rid is string s && s == "*") return rtype + ":*";
        var m = (D)rid!;
        return m.ContainsKey("exact") ? $"{rtype}:{m["exact"]}" : $"{rtype}:{m["prefix"]}*";
    }

    /// <summary>The policy predicate scaffold; a money limit on a def with no money.amount parameter throws (never silently unbounded).</summary>
    public static D PredicatesOf(D d, D? limits = null)
    {
        var o = new D { ["verb"] = d["verb"], ["resource"] = ResourceMatcher(d) };
        if (limits != null && limits.ContainsKey("max_amount"))
        {
            var m = limits["max_amount"];
            if (!IntentJs.IsSafeInteger(m) || IntentJs.NumOf(m)!.Value < 0) throw new ActionKitError("bad_limit", "max_amount must be a non-negative safe integer");
            var name = ParamByRole(d, "money.amount");
            o["where"] = new L
            {
                new D { ["field"] = "action.params." + name, ["op"] = "lte", ["value"] = m },
                new D { ["field"] = "action.params." + name, ["op"] = "gte", ["value"] = 0L },
            };
        }
        return o;
    }

    // ---- Goal IR ontology terms
    static L SortedU16(IEnumerable<object?> xs) => new(xs.Select(x => (string)x!).OrderBy(x => x, StringComparer.Ordinal));

    static D OntParam(D d, D p)
    {
        if (Ak.G(p, "unit") is D u)
        {
            var kind = (string)u["kind"]!;
            if (kind == "money")
            {
                var c = u["ccy"];
                if (c is string cs) return new D { ["kind"] = "money", ["ccys"] = new L { cs } };
                var cp = Ak.G(((D)d["params"]!), Ak.S(c, "from") ?? "") as D;
                return new D { ["kind"] = "money", ["ccys"] = cp != null && Ak.G(cp, "values") is L vs ? SortedU16(vs) : new L() };
            }
            return new D { ["kind"] = kind == "duration" ? "duration" : kind == "bytes" ? "bytes" : kind == "ratio" ? "ratio" : "count" };
        }
        var role = Ak.S(p, "role"); var fmt = Ak.S(p, "format");
        if (role != null && role.StartsWith("id.", StringComparison.Ordinal)) return new D { ["kind"] = "id", ["of"] = role[3..] };
        if (fmt != null && fmt.StartsWith("id:", StringComparison.Ordinal)) return new D { ["kind"] = "id", ["of"] = fmt[3..] };
        switch ((string)p["type"]!)
        {
            case "duration": return new D { ["kind"] = "duration" };
            case "datetime": case "date": return new D { ["kind"] = "instant" };
            case "integer": return new D { ["kind"] = "count" };
            case "boolean": return new D { ["kind"] = "enum", ["values"] = new L { "false", "true" } };
            case "set": return new D { ["kind"] = "enum", ["values"] = SortedU16(Ak.Lst(p, "values")) };
            case "string": return Ak.G(p, "values") is L sv ? new D { ["kind"] = "enum", ["values"] = SortedU16(sv) } : new D { ["kind"] = "text" };
            default: return new D { ["kind"] = "text" };
        }
    }

    /// <summary>Ontology terms for a set of defs; effect is derived (EffectClass), never overridden.</summary>
    public static D ToOntology(IEnumerable<D> defs, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null)
    {
        var types = new D(); var units = new D(); var verbs = new L(); var aliases = new D(); var traits = new D();
        foreach (var d in defs.OrderBy(x => (string)x["verb"]!, StringComparer.Ordinal))
        {
            var res = (D)d["resource"]!; var rid = res["id"];
            var prefix = rid is string || (rid is D rd0 && rd0.ContainsKey("exact")) ? "" : (string)((D)rid!)["prefix"]!;
            var rtype = (string)res["type"]!;
            if (!types.ContainsKey(rtype)) types[rtype] = prefix;
            var ps = new D();
            var dps = (D)d["params"]!;
            foreach (var name in dps.Keys.OrderBy(x => x, StringComparer.Ordinal))
            {
                var p = (D)dps[name]!;
                ps[name] = OntParam(d, p);
                if (Ak.G(p, "unit") is D u)
                {
                    if ((string)u["kind"]! == "money" && u.GetValueOrDefault("ccy") is string ccy)
                        units[ccy] = u.ContainsKey("exp") ? new D { ["kind"] = "money", ["exponent"] = u["exp"] } : new D { ["kind"] = "money" };
                    else if ((string)u["kind"]! != "money") units[(string)u["kind"]!] = new D { ["kind"] = u["kind"] };
                }
            }
            var dv = (string)d["verb"]!;
            verbs.Add(new D { ["id"] = dv, ["effect"] = EffectClass(d), ["resource_type"] = rtype, ["params"] = ps });
            foreach (var a in Ak.Lst(d, "aliases"))
            {
                var al = (string)a!;
                if (aliases.TryGetValue(al, out var ex) && (string?)ex != dv) throw new ActionKitError("alias_collision", $"alias '{al}' names two verbs");
                aliases[al] = dv;
            }
            traits[dv] = ActionEffective.EffectiveWith(d, reg, attestationVerified)["traits"];
        }
        return new D { ["types"] = new L(types.Select(kv => (object?)new D { ["id"] = kv.Key, ["id_prefix"] = kv.Value })), ["units"] = units, ["verbs"] = verbs, ["aliases"] = aliases, ["traits"] = traits };
    }

    // ---- policy card + escalation + MCP annotations
    static string Sentence(string s) => s != "" && (s[^1] is '.' or '!' or '?') ? s : s + ".";
    static string JoinList(List<string> xs) => xs.Count <= 1 ? (xs.Count > 0 ? xs[0] : "") : string.Join(", ", xs.Take(xs.Count - 1)) + " and " + xs[^1];

    /// <summary>The deterministic policy card: the title and the phrases of the trait closure, riskiest first.</summary>
    public static D CardOf(D d, D eff, Dictionary<string, D> reg)
    {
        var ordered = Actions.Closure(reg, Ak.Strs(eff["traits"])).Select(i => reg[i]).OrderBy(t => -Ak.I(((D)t["floor"]!)["risk"])).ThenBy(t => (string)t["id"]!, StringComparer.Ordinal).ToList();
        var phrases = ordered.Select(t => (string)t["card_phrase"]!).Distinct(StringComparer.Ordinal).ToList();
        var e = (D)eff["eff"]!;
        var title = (string)d["title"]!;
        var second = eff["confirmed"] is true
            ? (phrases.Count > 0 ? $"This action {JoinList(phrases)}." : "This action only reads.")
            : $"This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it {JoinList(phrases)}.";
        return new D
        {
            ["verb"] = d["verb"], ["title"] = title, ["text"] = Sentence(title) + " " + second, ["risk"] = RiskNames[(int)Ak.I(e["risk"])],
            ["escalation"] = EscTiers[(int)Ak.I(e["esc"])], ["reversibility"] = e["rev"], ["blast_ppm"] = e["blast_ppm"],
            ["needs"] = new L((L)e["caveats"]!), ["context"] = new L((L)e["context"]!),
        };
    }

    /// <summary>The minimum escalation tier of the effective profile.</summary>
    public static D EscalationOf(D eff)
    {
        var esc = ((D)eff["eff"]!)["esc"];
        return new D { ["tier"] = esc, ["name"] = EscTiers[(int)Ak.I(esc)] };
    }

    /// <summary>Advisory MCP tool annotations; an unreviewed def's own claim of safety is never advertised.</summary>
    public static D McpAnnotationsOf(D d, D eff)
    {
        var cl = new HashSet<string>(Ak.Strs(eff["closure"]));
        var idem = Ak.S(Ak.G(d, "idempotency"), "mode") ?? "none";
        var ro = Ak.IsReadOnly(Ak.Strs(d["effects"]));
        var confirmed = eff["confirmed"] is true;
        return new D
        {
            ["readOnlyHint"] = confirmed && ro, ["destructiveHint"] = cl.Contains("pca.destructive"),
            ["idempotentHint"] = confirmed && (idem != "none" || ro), ["openWorldHint"] = cl.Contains("pca.network_egress") || cl.Contains("pca.external_communication"),
        };
    }
}

public static class ActionExplain
{
    static string BlastText(long ppm) => ppm % 1000 == 0 ? $"{ppm / 1000}k" : $"{ppm}ppm";

    /// <summary>The plain-language profile of one def: card, effective profile, what a grant must carry, traits and review state.</summary>
    public static string ExplainDef(D d, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null)
    {
        var eff = ActionEffective.EffectiveWith(d, reg, attestationVerified);
        var card = ActionDerive.CardOf(d, eff, reg);
        var e = (D)eff["eff"]!;
        var r = (string)e["rev"]!;
        var rev = r == "irreversible" ? "irreversible" : r == "rate_limited" ? "rate limited" : "reversible";
        var needs = Ak.Strs(card["needs"]); var ctx = Ak.Strs(card["context"]);
        var lines = new List<string>
        {
            (string)card["text"]!,
            $"effective: risk {Ak.I(e["risk"])}, {rev}, blast {BlastText(Ak.I(e["blast_ppm"]))}, escalation: {card["escalation"]}",
            "grant must carry: " + (needs.Count > 0 ? string.Join(", ", needs) : "nothing"),
        };
        if (ctx.Count > 0) lines.Add("call must carry: " + string.Join(", ", ctx));
        var closure = Ak.Strs(eff["closure"]);
        lines.Add("traits: " + (closure.Count > 0 ? string.Join(", ", closure) : "none"));
        var state = (string)((D)d["review"]!)["state"]!;
        var confirmed = eff["confirmed"] is true;
        lines.Add("review: " + (confirmed ? state : $"{state}, not confirmed by a signed review"));
        if (!confirmed)
        {
            var h = (D)eff["hint"]!; var he = (D)h["eff"]!; var hc = Ak.Strs(h["closure"]);
            lines.Add($"until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk {Ak.I(he["risk"])}, escalation tier {Ak.I(he["esc"])}, traits: {(hc.Count > 0 ? string.Join(", ", hc) : "none")}");
        }
        return string.Join("\n", lines);
    }
}
