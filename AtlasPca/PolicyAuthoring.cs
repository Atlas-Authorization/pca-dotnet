// Forbid-wins certificate check (security contract C-241) and linked policy templates (C-242, C-243): a port of
// `certificateConsistent` in packages/pca/src/forbid-certificate.ts and of packages/pca/src/policy-link.ts (the TypeScript is
// authoritative; same reason strings). Every function is total and never throws; anything malformed fails closed. Values are the
// library's JSON values (Dictionary<string, object?>, List<object?>, string, bool, Num, null).
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class PolicyAuthoring
{
    const string TemplateSigDomain = "atlas-pca/policy-template/v1\0";
    const string TightenSigDomain = "atlas-pca/template-tighten/v1\0";
    const string NameSource = "^[a-z][a-z0-9_]{0,63}$";
    static readonly Regex NameRe = new(@"\A[a-z][a-z0-9_]{0,63}\z", RegexOptions.CultureInvariant);

    static bool IsOne(object? v) => IntentJs.IsNumber(v) && IntentJs.NumOf(v) == 1.0;
    static int U16(string s) => s.Length; // .NET strings are UTF-16
    static bool NameOk(object? s) => s is string t && NameRe.IsMatch(t);
    static object? G(object? o, string k) => IntentJs.Get(o, k);

    // ---- forbid-wins certificate ----------------------------------------------------------------

    /// <summary>Whether the certificate's own table entails its decision, winner and shadowed list (no predicate evaluator needed).</summary>
    public static bool ForbidCertificateConsistent(object? cert, IReadOnlyList<string>? precedence = null)
    {
        try
        {
            if (cert is not JD c || !IsOne(G(c, "v")) || G(c, "kind") is not "forbid-wins" || G(c, "clauses") is not JL rows
                || G(c, "winner") is not JD winner || G(c, "shadowed") is not JL shadowed) return false;
            if (G(winner, "kind") is "malformed")
                return rows.Count == 0 && G(c, "decision") is "deny" && winner.ContainsKey("id") && G(winner, "id") == null && shadowed.Count == 0;
            var prec = precedence ?? Array.Empty<string>();
            var table = new List<(string Id, string Kind, string Value, string? Signer)>();
            foreach (var r in rows)
            {
                if (r is not JD o || G(o, "id") is not string id || G(o, "kind") is not string kind || G(o, "value") is not string value) return false;
                if (kind is not ("permit" or "forbid" or "escalate") || value is not ("true" or "false" or "unknown")) return false;
                table.Add((id, kind, value, G(o, "signer") as string));
            }
            int Rank((string Id, string Kind, string Value, string? Signer) r)
            {
                var i = r.Signer == null ? -1 : prec.ToList().IndexOf(r.Signer);
                return i < 0 ? prec.Count : i; // an unlisted (or absent) signer ranks last
            }
            List<(string Id, string Kind, string Value, string? Signer)> Hit(string kind) => table.Where(r => r.Kind == kind && r.Value != "false").ToList();
            var forbids = Hit("forbid").OrderBy(Rank).ThenBy(r => r.Id, StringComparer.Ordinal).ToList();
            var permits = Hit("permit");
            var escalates = Hit("escalate");
            (string Id, string Kind, string Value, string? Signer)? win;
            string decision, kind2;
            if (forbids.Count > 0) { win = forbids[0]; decision = "deny"; kind2 = "forbid"; }
            else if (permits.Count == 0) { win = null; decision = "deny"; kind2 = "none"; }
            else if (escalates.Count > 0) { win = escalates[0]; decision = "escalate"; kind2 = "escalate"; }
            else { win = permits[0]; decision = "allow"; kind2 = "permit"; }
            var others = new List<string>();
            foreach (var r in forbids.Concat(permits).Concat(escalates))
                if (win == null || !(r.Id == win.Value.Id && r.Kind == win.Value.Kind)) others.Add(r.Id);
            var idOk = win == null ? G(winner, "id") == null : G(winner, "id") is string wid && wid == win.Value.Id;
            return G(c, "decision") is string d && d == decision && G(winner, "kind") is string wk && wk == kind2 && idOk
                && shadowed.Count == others.Count && shadowed.Select((s, i) => s is string ss && ss == others[i]).All(x => x);
        }
        catch (Exception) { return false; }
    }

    // ---- linked templates -------------------------------------------------------------------------

    static string JsString(object? x) => x switch { null => "null", string s => s, bool b => b ? "true" : "false", Num n => n.Raw, _ => "object" };

    static string? Scan(object? v, JD decl, HashSet<string> used)
    {
        if (v is JL a)
        {
            foreach (var x in a) { var e = Scan(x, decl, used); if (e != null) return e; }
            return null;
        }
        if (v is not JD o) return null;
        foreach (var k in o.Keys) if (k is "__proto__" or "constructor" or "prototype") return $"body has the forbidden key '{k}'";
        if (o.ContainsKey("$slot"))
        {
            foreach (var k in o.Keys) if (k != "$slot" && k != "pre" && k != "post") return $"placeholder has unknown member '{k}'";
            if (o["$slot"] is not string name || !decl.ContainsKey(name)) return $"placeholder names undeclared slot '{JsString(o["$slot"])}'";
            foreach (var k in new[] { "pre", "post" }) if (o.ContainsKey(k) && o[k] is not string) return $"placeholder {k} must be a string";
            used.Add(name);
            return null;
        }
        foreach (var k in o.Keys) { var e = Scan(o[k], decl, used); if (e != null) return e; }
        return null;
    }

    /// <summary>null for a well-formed template definition, else the first problem.</summary>
    public static string? TemplateDefError(object? def)
    {
        if (def is not JD d) return "template must be an object";
        if (!IsOne(G(d, "v")) || G(d, "kind") is not "pca-policy-template") return "template v / kind mismatch";
        if (!NameOk(G(d, "id"))) return $"template id must match {NameSource}";
        if (G(d, "version") is not string ver || ver.Length == 0 || U16(ver) > 64) return "template version must be a string of 1..64 characters";
        if (G(d, "slots") is not JD slots) return "slots must be an object";
        if (slots.Count > 32) return "more than 32 slots";
        foreach (var (n, s) in slots)
        {
            if (!NameRe.IsMatch(n)) return $"slot name '{n}' must match {NameSource}";
            if (s is not JD so) return $"slot '{n}' must be an object";
            var ty = G(so, "type") as string ?? "";
            if (ty is not ("string" or "integer" or "set")) return $"slot '{n}'.type must be string, integer or set";
            if (ty == "set" && G(so, "values") is not JL) return $"set slot '{n}' needs a closed values list";
            if (so.ContainsKey("values") && !(so["values"] is JL vl && vl.Count <= 64 && vl.All(x => x is string))) return $"slot '{n}'.values must be a list of strings";
            if (ty == "integer")
                foreach (var k in new[] { "min", "max" }) if (so.ContainsKey(k) && !IntentJs.IsSafeInteger(so[k])) return $"slot '{n}'.{k} must be a safe integer";
        }
        if (G(d, "body") is not JD body || G(body, "predicates") is not JL) return "body.predicates must be an array";
        if (body.ContainsKey("caveats") && body["caveats"] is not JL) return "body.caveats must be an array";
        var used = new HashSet<string>();
        var err = Scan(body, slots, used);
        if (err != null) return err;
        foreach (var n in slots.Keys) if (!used.Contains(n)) return $"slot '{n}' is declared but never used";
        return null;
    }

    /// <summary>hashCanonical of the definition.</summary>
    public static string TemplateDigest(object? def) => Pca.HashCanonical(def);

    static byte[] Message(string domain, string digest) => Encoding.UTF8.GetBytes(domain).Concat(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(digest))).ToArray();

    /// <summary>Verify a signed template <c>{def, signer, sig}</c>: null when it verifies, else the reason.</summary>
    public static string? VerifyTemplate(object? t, IReadOnlyList<string> trusted)
    {
        try
        {
            var e = TemplateDefError(G(t, "def"));
            if (e != null) return e;
            if (G(t, "signer") is not string signer || !trusted.Contains(signer)) return "template signer is not trusted";
            if (!IntentJs.VerifyEd(signer, Message(TemplateSigDomain, TemplateDigest(G(t, "def"))), G(t, "sig"))) return "bad template signature";
            return null;
        }
        catch (Exception) { return "template verification error (fail closed)"; }
    }

    /// <summary>null for a well-formed tighten overlay: it may only add <c>where</c> conditions and caveats.</summary>
    public static string? TightenOverlayError(object? o)
    {
        if (o is not JD m) return "overlay must be an object";
        if (!IsOne(G(m, "v")) || G(m, "kind") is not "pca-template-tighten") return "overlay v / kind mismatch";
        foreach (var k in m.Keys)
            if (k is not ("v" or "kind" or "template_id" or "version_digest" or "add_where" or "add_caveats"))
                return $"overlay has unknown member '{k}' (an overlay can only add where conditions and caveats)";
        if (!NameOk(G(m, "template_id"))) return "overlay template_id invalid";
        if (G(m, "version_digest") is not string vd || vd.Length == 0) return "overlay version_digest invalid";
        if (m.ContainsKey("add_where") && !(m["add_where"] is JL w && w.All(c => c is JD))) return "overlay add_where must be a list of conditions";
        if (m.ContainsKey("add_caveats") && !(m["add_caveats"] is JL cv && cv.All(c => c is JD && G(c, "type") is string))) return "overlay add_caveats must be a list of caveats";
        return null;
    }

    /// <summary>Verify a signed overlay <c>{overlay, signer, sig}</c>: null when it verifies, else the reason.</summary>
    public static string? VerifyTighten(object? t, IReadOnlyList<string> trusted)
    {
        try
        {
            var e = TightenOverlayError(G(t, "overlay"));
            if (e != null) return e;
            if (G(t, "signer") is not string signer || !trusted.Contains(signer)) return "overlay signer is not trusted";
            if (!IntentJs.VerifyEd(signer, Message(TightenSigDomain, Pca.HashCanonical(G(t, "overlay"))), G(t, "sig"))) return "bad overlay signature";
            return null;
        }
        catch (Exception) { return "overlay verification error (fail closed)"; }
    }

    static string? SlotValueError(string name, JD d, object? v)
    {
        var values = (G(d, "values") as JL)?.OfType<string>().ToList();
        switch (G(d, "type") as string ?? "")
        {
            case "string":
                if (v is not string s || s.Length == 0 || U16(s) > 256) return $"slot '{name}' must be a string of 1..256 characters";
                if (values != null && !values.Contains(s)) return $"slot '{name}' is outside its closed value set";
                return null;
            case "integer":
                if (!IntentJs.IsSafeInteger(v)) return $"slot '{name}' must be a safe integer";
                var n = IntentJs.Lng(v);
                if (d.ContainsKey("min") && IntentJs.IsSafeInteger(d["min"]) && n < IntentJs.Lng(d["min"])) return $"slot '{name}' is below its minimum";
                if (d.ContainsKey("max") && IntentJs.IsSafeInteger(d["max"]) && n > IntentJs.Lng(d["max"])) return $"slot '{name}' is above its maximum";
                return null;
            default:
                if (v is not JL a || a.Count == 0 || a.Count > 64 || !a.All(x => x is string)) return $"slot '{name}' must be a non-empty list of strings";
                var strs = a.Cast<string>().ToList();
                if (strs.Distinct().Count() != strs.Count) return $"slot '{name}' has duplicate members";
                if (values != null && strs.Any(x => !values.Contains(x))) return $"slot '{name}' has a member outside its closed set";
                return null;
        }
    }

    sealed class Refusal : Exception { public Refusal(string m) : base(m) { } }

    static object? Fill(object? v, JD slots, string? key)
    {
        if (v is JL a) return a.Select(x => Fill(x, slots, key)).ToList();
        if (v is not JD o) return v;
        if (o.ContainsKey("$slot") && o["$slot"] is string name)
        {
            var val = slots.TryGetValue(name, out var sv) ? sv : null;
            if (key is "verb" or "resource")
            {
                foreach (var x in val is JL vl ? vl : new JL { val })
                    if (x is string xs && (xs.Contains('*') || xs.StartsWith("re:", StringComparison.Ordinal)))
                        throw new Refusal($"slot '{name}' would inject a wildcard or regex matcher into a verb or resource");
            }
            var pre = o.TryGetValue("pre", out var p) && p is string ps ? ps : "";
            var post = o.TryGetValue("post", out var q) && q is string qs ? qs : "";
            if (pre.Length == 0 && post.Length == 0) return val;
            if (val is not string s || s.Contains('*') || s.Contains('\0')) throw new Refusal($"slot '{name}' cannot be spliced into a string (wildcard or non-string)");
            var outS = pre + s + post;
            if (pre.Length == 0 && outS.StartsWith("re:", StringComparison.Ordinal)) throw new Refusal($"slot '{name}' would inject a regex matcher");
            return outS;
        }
        var m = new JD();
        foreach (var (k, x) in o) m[k] = Fill(x, slots, k);
        return m;
    }

    /// <summary>Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots and any value that would inject a
    /// wildcard or a regex into a verb or resource. On success the policy is <c>{predicates, caveats}</c>.</summary>
    public static (JD? Policy, string? Reason) InstantiateTemplate(object? def, object? slots)
    {
        try
        {
            var e = TemplateDefError(def);
            if (e != null) return (null, e);
            if (slots is not JD sl) return (null, "slots must be an object");
            var decl = (JD)G(def, "slots")!;
            foreach (var k in sl.Keys) if (!decl.ContainsKey(k)) return (null, $"slot '{k}' is not declared by the template");
            foreach (var (n, d) in decl)
            {
                if (!sl.ContainsKey(n)) return (null, $"slot '{n}' is not filled");
                var se = SlotValueError(n, (JD)d!, sl[n]);
                if (se != null) return (null, se);
            }
            var body = (JD)Fill(G(def, "body"), sl, null)!;
            return (new JD { ["predicates"] = body["predicates"], ["caveats"] = body.TryGetValue("caveats", out var cv) ? cv : new JL() }, null);
        }
        catch (Refusal r) { return (null, r.Message); }
        catch (Exception) { return (null, "instantiation error (fail closed)"); }
    }

    /// <summary>null for a well-formed reference <c>{template_id, version_digest, slots}</c>.</summary>
    public static string? TemplateRefError(object? r)
    {
        if (r is not JD m) return "template_ref must be an object";
        foreach (var k in m.Keys) if (k is not ("template_id" or "version_digest" or "slots" or "bind_params_digest")) return $"template_ref has unknown member '{k}'";
        if (!NameOk(G(m, "template_id"))) return "template_ref.template_id invalid";
        if (G(m, "version_digest") is not string vd || vd.Length == 0 || Encoding.UTF8.GetByteCount(vd) > 128) return "template_ref.version_digest invalid";
        if (m.ContainsKey("slots") && m.ContainsKey("bind_params_digest")) return "template_ref has both slots and bind_params_digest";
        if (m.ContainsKey("bind_params_digest"))
            return m["bind_params_digest"] is string b && b.Length > 0 && Encoding.UTF8.GetByteCount(b) <= 128 ? null : "template_ref.bind_params_digest invalid";
        if (G(m, "slots") is not JD) return "template_ref.slots must be an object";
        return null;
    }

    /// <summary>Rebuild the policy a reference denotes from a registry <c>{templates, overlays?, trusted}</c>.</summary>
    public static (JD? Policy, int Overlays, string? Reason) ResolveLink(object? reference, object? reg)
    {
        try
        {
            var e = TemplateRefError(reference);
            if (e != null) return (null, 0, e);
            var trusted = (G(reg, "trusted") as JL)?.OfType<string>().ToList() ?? new List<string>();
            var digest = (string)G(reference, "version_digest")!;
            if (G(reg, "templates") is not JD templates || !templates.TryGetValue(digest, out var t)) return (null, 0, "template version is not in the registry");
            var v = VerifyTemplate(t, trusted);
            if (v != null) return (null, 0, v);
            var def = G(t, "def");
            if (TemplateDigest(def) != digest) return (null, 0, "registry entry does not match its digest");
            if (!IntentJs.JsonEquals(G(def, "id"), G(reference, "template_id"))) return (null, 0, "template id does not match the reference");
            var slots = G(reference, "slots");
            if (G(reference, "bind_params_digest") is string bd)
            {
                object? bound = null;
                if (G(reg, "params") is JD ps) ps.TryGetValue(bd, out bound);
                if (bound is not JD) return (null, 0, "parameter object is not available");
                if (Pca.HashCanonical(bound) != bd) return (null, 0, "parameter object does not match bind_params_digest");
                slots = bound;
            }
            var inst = InstantiateTemplate(def, slots);
            if (inst.Policy == null) return (null, 0, inst.Reason);
            var predicates = ((JL)inst.Policy["predicates"]!).ToList();
            var caveats = ((JL)inst.Policy["caveats"]!).ToList();
            var applied = 0;
            foreach (var o in G(reg, "overlays") as JL ?? new JL())
            {
                var ov = G(o, "overlay");
                if (ov is not JD || !IntentJs.JsonEquals(G(ov, "version_digest"), G(reference, "version_digest")) || !IntentJs.JsonEquals(G(ov, "template_id"), G(reference, "template_id"))) continue;
                var vv = VerifyTighten(o, trusted);
                if (vv != null) return (null, 0, vv);
                var add = G(ov, "add_where") as JL ?? new JL();
                predicates = predicates.Select(p =>
                {
                    var m = new JD((JD)p!);
                    m["where"] = (G(p, "where") as JL ?? new JL()).Concat(add).ToList();
                    return (object?)m;
                }).ToList();
                caveats = caveats.Concat(G(ov, "add_caveats") as JL ?? new JL()).ToList();
                applied++;
            }
            return (new JD { ["predicates"] = predicates, ["caveats"] = caveats }, applied, null);
        }
        catch (Exception) { return (null, 0, "link resolution error (fail closed)"); }
    }
}
