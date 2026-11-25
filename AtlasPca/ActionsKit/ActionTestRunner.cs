// "pca actions test": every def's executable examples run through the real pipeline in process (derive the schema, conform the params,
// expand the floors, decide), plus the generic property checks of the pack: monotonicity over trait additions and subsets, digest stability
// across the JSON and YAML forms, and the schema round trip (the example conforms; every mutation of it is refused). The example policy
// (under) is a small allow selector evaluated here; it can only pre-authorize. Examples describe the action AS REVIEWED (its hint view):
// they are authoring tests, not enforcement.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionTestRunner
{
    static readonly string[] SelKeys = { "trait", "verb", "where", "caveats", "context" };
    static readonly string[] CaveatKinds = { "amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap" };
    const string UnderMsg = "under must be {allow: selector | [selector]}";
    const string SelMsg = "an allow selector has trait, verb, where, caveats, context";

    static D HintOf(D d, Dictionary<string, D> reg)
    {
        var e = ActionEffective.EffectiveWith(d, reg);
        var o = new D(e);
        foreach (var (k, v) in (D)e["hint"]!) o[k] = v;
        o["confirmed"] = true;
        return o;
    }

    /// <summary>The example policy as a list of selectors, or the reason it is malformed (a string).</summary>
    static object ParseUnder(object? under, bool present)
    {
        if (!present) return new List<D>();
        if (under is not D u) return UnderMsg;
        foreach (var k in u.Keys) if (k != "allow") return UnderMsg;
        var allow = u.GetValueOrDefault("allow");
        var list = allow is L l ? l : new L { allow };
        var outp = new List<D>();
        foreach (var s in list)
        {
            if (s is not D m || m.Keys.Any(k => !SelKeys.Contains(k))) return SelMsg;
            if (m.ContainsKey("trait") == m.ContainsKey("verb")) return "an allow selector names exactly one of trait and verb";
            if (m.ContainsKey("where") && m["where"] is not D) return "where must be an object";
            if (m.ContainsKey("caveats") && !(m["caveats"] is L cv && cv.All(c => c is string cs && CaveatKinds.Contains(cs)))) return "caveats must be known caveat kinds";
            outp.Add(m);
        }
        return outp;
    }

    static string DomainOf(string v) => v[(v.LastIndexOf('@') + 1)..].ToLowerInvariant();

    /// <summary>The caveats of the grant a matching allow selector stands for, or null when it does not match this call.</summary>
    static List<string>? GrantOf(D sel, D d, D flat, D eff)
    {
        if (sel.ContainsKey("trait"))
        {
            var t = Ak.JsStr(sel["trait"]);
            if (!Ak.Strs(eff["closure"]).Contains(t.Contains('.') ? t : "pca." + t)) return null;
        }
        if (sel.ContainsKey("verb") && !IntentJs.JsonEquals(sel["verb"], d["verb"])) return null;
        var caveats = new List<string>();
        void Add(string c) { if (!caveats.Contains(c)) caveats.Add(c); }
        if (sel.GetValueOrDefault("caveats") is L cv) foreach (var c in cv) Add((string)c!);
        if (sel.GetValueOrDefault("where") is D wh)
            foreach (var (key, cond) in wh)
            {
                var dom = key.EndsWith(".domain", StringComparison.Ordinal);
                var name = dom ? key[..^".domain".Length] : key;
                if (!((D)d["params"]!).TryGetValue(name, out var pdo) || pdo is not D pd) return null;
                if (!flat.TryGetValue(name, out var v)) return null;
                if (cond is L cl)
                {
                    if (v is not string vs || !cl.Any(c => c is string cs && cs == (dom ? DomainOf(vs) : vs))) return null;
                }
                else if (cond is D cm)
                {
                    if (IntentJs.NumOf(v) is not double n || (cm.ContainsKey("max") && cm["max"] != null && n > Ak.Dbl(cm["max"])) || (cm.ContainsKey("min") && cm["min"] != null && n < Ak.Dbl(cm["min"]))) return null;
                }
                else return null;
                var role = Ak.S(pd, "role") ?? "";
                if (role.StartsWith("contact.", StringComparison.Ordinal) || role == "party.payee") Add("recipient_scope");
                else if (role == "money.amount") Add("amount_cap");
                else if (role == "count.limit") Add("count_cap");
                else if (role.StartsWith("id.", StringComparison.Ordinal)) Add("resource_scope");
            }
        return caveats;
    }

    static D Meta() => new() { ["site"] = "https://example.invalid", ["aud"] = "example", ["version"] = "0" };

    /// <summary>Decide one example: {got, why}.</summary>
    public static D DecideExample(D d, D ex, Dictionary<string, D> reg, IEnumerable<D> defs)
    {
        var doc = ActionDerive.ToSchemaDoc(defs, reg, Meta());
        var flat = ActionDerive.FlattenParams((D)ex["params"]!);
        var c = ActionSchema.ConformAction(doc, (string)d["verb"]!, flat);
        if (!c.Ok) return new D { ["got"] = "deny", ["why"] = $"schema_violation {c.Code}{(!string.IsNullOrEmpty(c.Path) ? $" ({c.Path})" : "")}" };
        var op = ActionDerive.OperationOf(d, new D { ["params"] = ex["params"] });
        if (op["ok"] is not true) return new D { ["got"] = "deny", ["why"] = op["reason"] };
        var sels = ParseUnder(ex.GetValueOrDefault("under"), ex.ContainsKey("under"));
        if (sels is string bad) return new D { ["got"] = "deny", ["why"] = $"bad example policy: {bad}" };
        var eff = HintOf(d, reg);
        var callCtx = new List<string>();
        void Ctx(string k) { if (!callCtx.Contains(k)) callCtx.Add(k); }
        var idem = Ak.G(d, "idempotency");
        if (Ak.S(idem, "mode") == "natural") Ctx("idempotency");
        if (Ak.S(idem, "mode") == "key_param" && Ak.G(idem, "param") is string ip && flat.ContainsKey(ip)) Ctx("idempotency");
        var grantCaveats = new List<string>();
        long pre = 0;
        foreach (var s in (List<D>)sels)
        {
            var g = GrantOf(s, d, flat, eff);
            if (g == null) continue;
            pre = 3;
            foreach (var x in g) if (!grantCaveats.Contains(x)) grantCaveats.Add(x);
            if (s.GetValueOrDefault("context") is L cx) foreach (var k in cx) Ctx(Ak.JsStr(k));
        }
        var rho = (D)eff["eff"]!;
        var got = Actions.FloorDecision(new D { ["caveats"] = Ak.ToL(grantCaveats), ["max_esc"] = 3L, ["preauth_esc"] = pre }, new D { ["context"] = Ak.ToL(callCtx) }, rho);
        string why;
        if (got == "allow") why = "floor satisfied";
        else
        {
            var need = Ak.Strs(rho["caveats"]).Where(k => !grantCaveats.Contains(k)).Concat(Ak.Strs(rho["context"]).Where(k => !callCtx.Contains(k))).ToList();
            why = "floor needs " + (need.Count > 0 ? string.Join(", ", need) : $"escalation tier {Ak.JsStr(rho["esc"])}");
        }
        return new D { ["got"] = got, ["why"] = why };
    }

    static List<(string Name, D Params)> Mutations(D d, D flat)
    {
        var outp = new List<(string, D)>();
        var extra = new D(flat) { ["zz_undeclared"] = "x" };
        outp.Add(("extra param", extra));
        var ps = (D)d["params"]!;
        foreach (var k in flat.Keys.OrderBy(x => x, StringComparer.Ordinal))
        {
            if (!ps.TryGetValue(k, out var pdo) || pdo is not D pd) continue;
            if (!(Ak.G(pd, "required") is false)) { var w = new D(flat); w.Remove(k); outp.Add(($"missing {k}", w)); }
            var v = flat[k];
            var sw = new D(flat) { [k] = v is string ? new Num("12345") : (IntentJs.NumOf(v) != null || v is bool) ? "x" : new D() };
            outp.Add(($"type swap {k}", sw));
            if (IntentJs.NumOf(v) != null && Ak.S(pd, "type") == "integer")
            {
                if (pd.ContainsKey("max")) outp.Add(($"above max {k}", new D(flat) { [k] = IntentJs.OfLong((long)Ak.Dbl(pd["max"]) + 1) }));
                if (pd.ContainsKey("min")) outp.Add(($"below min {k}", new D(flat) { [k] = IntentJs.OfLong((long)Ak.Dbl(pd["min"]) - 1) }));
            }
            if (v is string && Ak.S(pd, "type") == "string")
            {
                if (Ak.G(pd, "values") != null) outp.Add(($"outside values {k}", new D(flat) { [k] = "not_a_listed_value_zz" }));
                if (pd.ContainsKey("max_len")) outp.Add(($"too long {k}", new D(flat) { [k] = new string('x', (int)Ak.Dbl(pd["max_len"]) + 1) }));
            }
        }
        return outp;
    }

    static bool DigestOk(D r, string want) =>
        ((L)r["errors"]!).Count == 0 && ((L)r["defs"]!).Count > 0 && Actions.DefDigest((D)((L)r["defs"]!)[0]!) == want;

    static string FirstMessage(D r) => ((L)r["errors"]!).Count == 0 ? "digest differs" : Ak.JsStr(Ak.G(((L)r["errors"]!)[0], "message"));

    /// <summary>Run examples and property checks for a set of defs (one pack). <paramref name="propLimit"/> bounds the trait subsets tried per def (null = 256).
    /// The YAML round trip of the digest property is the identity on the value (no YAML front end here). Returns {examples, props, ok}.</summary>
    public static D RunDefTests(IEnumerable<D> defsIn, Dictionary<string, D> reg, long? propLimit = null)
    {
        var defs = defsIn.ToList();
        var examples = new L(); var props = new L();
        var limit = propLimit ?? 256;
        foreach (var d in defs)
        {
            var verb = (string)d["verb"]!;
            var exs = d.GetValueOrDefault("examples") as L ?? new L();
            for (int index = 0; index < exs.Count; index++)
            {
                var ex = (D)exs[index]!;
                var r = DecideExample(d, ex, reg, defs);
                examples.Add(new D { ["verb"] = verb, ["index"] = (long)index, ["expect"] = ex["expect"], ["got"] = r["got"], ["ok"] = IntentJs.JsonEquals(r["got"], ex["expect"]), ["why"] = r["why"] });
            }
            // monotonicity: adding any core trait never lowers the effective profile
            var eff = HintOf(d, reg);
            var effP = (D)eff["eff"]!;
            var lowered = Actions.CoreRegistry.Keys.Where(t => !Actions.Leq(effP, ActionEffective.EffWithTrait(d, t, reg))).ToList();
            props.Add(new D { ["verb"] = verb, ["name"] = "adding a trait never lowers the profile", ["ok"] = lowered.Count == 0, ["detail"] = string.Join(", ", lowered) });

            // monotonicity over subsets of the def's own traits (bounded): F(S) <= F(T)
            var ts = Ak.Strs(eff["traits"]);
            long bad = 0;
            long total = Math.Min(1L << Math.Min(ts.Count, 20), limit);
            var top = Actions.FloorOf(reg, ts);
            for (long mask = 0; mask < total; mask++)
            {
                var sub = ts.Where((_, i) => (((int)mask >> (i & 31)) & 1) != 0).ToList();
                if (!Actions.Leq(Actions.FloorOf(reg, sub), top)) bad++;
            }
            props.Add(new D { ["verb"] = verb, ["name"] = "floors are monotone over trait subsets", ["ok"] = bad == 0, ["detail"] = $"{total} subsets, {bad} violations" });

            // one digest across the JSON and YAML forms
            var want = Actions.DefDigest(d);
            var viaJson = ActionAuthor.LoadActionsValue(d);
            var viaYaml = ActionAuthor.LoadActionsValue(new D { ["ns"] = verb.Split('.')[0], ["actions"] = new L { d } });
            bool okJ = DigestOk(viaJson, want), okY = DigestOk(viaYaml, want);
            props.Add(new D { ["verb"] = verb, ["name"] = "one digest across JSON and YAML forms", ["ok"] = okJ && okY, ["detail"] = okJ && okY ? "" : $"json {(okJ ? "ok" : FirstMessage(viaJson))}; yaml {(okY ? "ok" : FirstMessage(viaYaml))}" });

            // schema round trip: each example conforms, every mutation is refused
            if (exs.Count == 0)
            {
                props.Add(new D { ["verb"] = verb, ["name"] = "schema round trip", ["ok"] = true, ["detail"] = "skipped: no examples" });
                continue;
            }
            var doc = ActionDerive.ToSchemaDoc(defs, reg, Meta());
            var accepted = new List<string>();
            long tried = 0;
            foreach (var exo in exs)
            {
                var flat = ActionDerive.FlattenParams((D)((D)exo!)["params"]!);
                if (!ActionSchema.ConformAction(doc, verb, flat).Ok) continue; // a deliberately non-conforming example is a deny example
                foreach (var (name, mp) in Mutations(d, flat))
                {
                    tried++;
                    if (ActionSchema.ConformAction(doc, verb, mp).Ok && !accepted.Contains(name)) accepted.Add(name);
                }
            }
            props.Add(new D { ["verb"] = verb, ["name"] = "schema round trip", ["ok"] = accepted.Count == 0, ["detail"] = accepted.Count == 0 ? $"{tried} mutations refused" : $"accepted: {string.Join(", ", accepted)}" });
        }
        var ok = examples.All(e => Ak.G(e, "ok") is true) && props.All(q => Ak.G(q, "ok") is true);
        return new D { ["examples"] = examples, ["props"] = props, ["ok"] = ok };
    }

    /// <summary>The report as plain lines, one PASS or FAIL per example and property, then a count.</summary>
    public static string TestText(D r)
    {
        var lines = new List<string>();
        foreach (var e in (L)r["examples"]!)
            lines.Add($"{(Ak.G(e, "ok") is true ? "PASS" : "FAIL")}  {Ak.JsStr(Ak.G(e, "verb"))} example {Ak.I(Ak.G(e, "index")) + 1}: expected {Ak.JsStr(Ak.G(e, "expect"))}, got {Ak.JsStr(Ak.G(e, "got"))} ({Ak.JsStr(Ak.G(e, "why"))})");
        foreach (var q in (L)r["props"]!)
        {
            var detail = Ak.G(q, "detail");
            lines.Add($"{(Ak.G(q, "ok") is true ? "PASS" : "FAIL")}  {Ak.JsStr(Ak.G(q, "verb"))} {Ak.JsStr(Ak.G(q, "name"))}{(Ak.JsTruthy(detail) ? ": " + Ak.JsStr(detail) : "")}");
        }
        var f = lines.Count(l => l.StartsWith("FAIL", StringComparison.Ordinal));
        lines.Add($"{lines.Count - f} passed, {f} failed");
        return string.Join("\n", lines);
    }
}
