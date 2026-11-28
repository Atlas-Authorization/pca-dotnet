// Semantic diff of two versions of one ActionDef. ActionDiff.DiffDefs is the grant-pin form (equal|narrow|widen|incomparable, never
// optimistic); ActionDefDiff is the authoring-CLI form.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionDiff
{
    const double DefaultMaxLen = 1024, DefaultMaxItems = 64;
    static readonly string[] ProvenanceLevels = { "first_party", "tool", "agent" };
    internal static int ScopeRank(string s) => s switch { "one" => 0, "set" => 1, "tenant" => 2, _ => 3 };
    static int IdemRank(string s) => s switch { "none" => 0, "natural" => 1, _ => 2 };

    /// <summary>o[k] ?? default: an absent or null member takes the default.</summary>
    static double Gd(D o, string k, double dflt) => o.TryGetValue(k, out var v) && v != null ? Ak.Dbl(v) : dflt;
    static string Gs(D o, string k, string dflt) => o.TryGetValue(k, out var v) && v != null ? (string)v : dflt;
    /// <summary>JSON.stringify(o[k]); an absent member is "undefined".</summary>
    static string Sj(D o, string k) => o.TryGetValue(k, out var v) ? SortedJson(v) : "undefined";

    /// <summary>Key order is not meaning: object keys sorted recursively (array order kept), then JSON.stringify.</summary>
    internal static object? SortKeys(object? v) => v switch
    {
        L l => l.Select(SortKeys).ToList(),
        D d => d.Keys.OrderBy(k => k, StringComparer.Ordinal).ToDictionary(k => k, k => SortKeys(d[k])),
        _ => v,
    };
    internal static string SortedJson(object? v) => JsJson.Stringify(SortKeys(v));
    static bool In(object? x, L? xs) => xs != null && xs.Any(y => IntentJs.JsonEquals(x, y));

    internal static string SetRel(IEnumerable<string> old, IEnumerable<string> nw)
    {
        var o = new HashSet<string>(old); var n = new HashSet<string>(nw);
        var added = n.Any(x => !o.Contains(x)); var removed = o.Any(x => !n.Contains(x));
        return added && removed ? "inc" : added ? "narrow" : removed ? "widen" : "eq";
    }
    /// <summary>More restrictive = larger.</summary>
    internal static string RankRel(double o, double n) => n == o ? "eq" : n > o ? "narrow" : "widen";

    static bool DomainContains(D outer, D inner)
    {
        var t = (string)outer["type"]!;
        if (t != (string)inner["type"]!) return false;
        switch (t)
        {
            case "string":
            case "object_ref":
                if (Gd(inner, "max_len", DefaultMaxLen) > Gd(outer, "max_len", DefaultMaxLen)) return false;
                if (outer.TryGetValue("values", out var ov0) && ov0 != null && !(inner.TryGetValue("values", out var iv0) && iv0 is L ivl && ivl.All(v => In(v, ov0 as L)))) return false;
                return !outer.TryGetValue("format", out var fmt) || fmt == null || IntentJs.JsonEquals(Ak.G(inner, "format"), fmt);
            case "integer":
                return Gd(inner, "min", double.NegativeInfinity) >= Gd(outer, "min", double.NegativeInfinity) && Gd(inner, "max", double.PositiveInfinity) <= Gd(outer, "max", double.PositiveInfinity);
            case "duration":
                return Math.Max(Gd(inner, "min", 0), 0) >= Math.Max(Gd(outer, "min", 0), 0) && Gd(inner, "max", double.PositiveInfinity) <= Gd(outer, "max", double.PositiveInfinity);
            case "set":
                {
                    var ov = Ak.G(outer, "values") as L ?? new L();
                    var iv = Ak.G(inner, "values") as L ?? new L();
                    if (!iv.All(v => In(v, ov))) return false;
                    var oMax = Math.Min(Gd(outer, "max_items", ov.Count), ov.Count);
                    var iMax = Math.Min(Gd(inner, "max_items", iv.Count), iv.Count);
                    return Gd(inner, "min_items", 0) >= Gd(outer, "min_items", 0) && iMax <= oMax;
                }
            case "array":
                if (Gs(outer, "items", "string") != Gs(inner, "items", "string")) return false;
                if (Gd(inner, "min_items", 0) < Gd(outer, "min_items", 0) || Gd(inner, "max_items", DefaultMaxItems) > Gd(outer, "max_items", DefaultMaxItems)) return false;
                if (Ak.S(outer, "items") == "integer")
                    return Gd(inner, "min", double.NegativeInfinity) >= Gd(outer, "min", double.NegativeInfinity) && Gd(inner, "max", double.PositiveInfinity) <= Gd(outer, "max", double.PositiveInfinity);
                return Gd(inner, "max_len", DefaultMaxLen) <= Gd(outer, "max_len", DefaultMaxLen);
            default:
                return true; // boolean, date, datetime: no domain members
        }
    }

    static bool CallsContained(D outer, D inner)
    {
        foreach (var (name, ip) in inner)
            if (!outer.TryGetValue(name, out var op) || !DomainContains((D)op!, (D)ip!)) return false;
        foreach (var (name, op) in outer)
        {
            if (!(Ak.G(op, "required") is true)) continue;
            if (!inner.TryGetValue(name, out var ip) || !(Ak.G(ip, "required") is true)) return false;
        }
        return true;
    }

    static string CallSetRel(D oldP, D newP)
    {
        var sub = CallsContained(oldP, newP); var sup = CallsContained(newP, oldP);
        return sub && sup ? "eq" : sub ? "narrow" : sup ? "widen" : "inc";
    }

    static int ProvRank(object? p) => p == null ? ProvenanceLevels.Length - 1 : Array.IndexOf(ProvenanceLevels, (string)p);

    static bool Absent(D o, string k) => !o.ContainsKey(k);
    static bool SameOpt(D o, D n, string k) => Absent(o, k) || Absent(n, k) ? Absent(o, k) && Absent(n, k) : IntentJs.JsonEquals(o[k], n[k]);

    static List<(string, string)> ParamAttrRels(D o, D n)
    {
        var o2 = new List<(string, string)>();
        if (!IntentJs.JsonEquals(Ak.G(o, "role"), Ak.G(n, "role"))) o2.Add(("role", "inc"));
        o2.Add(("sensitivity", RankRel(Ak.SensRank((string)o["sensitivity"]!), Ak.SensRank((string)n["sensitivity"]!))));
        o2.Add(("tags", SetRel(Ak.Strs(Ak.G(o, "tags")), Ak.Strs(Ak.G(n, "tags")))));
        o2.Add(("provenance_min", RankRel(-ProvRank(Ak.G(o, "provenance_min")), -ProvRank(Ak.G(n, "provenance_min")))));
        if (Sj(o, "unit") != Sj(n, "unit")) o2.Add(("unit", "inc"));
        o2.Add(("accumulates", SetRel(Ak.Strs(Ak.G(o, "accumulates")), Ak.Strs(Ak.G(n, "accumulates")))));
        if (Sj(o, "default") != Sj(n, "default") || !SameOpt(o, n, "principal_neutral_default")) o2.Add(("default", "inc"));
        return o2;
    }

    static bool TextDiffers(D o, D n) => new[] { "title", "description", "compensates" }.Any(k => !SameOpt(o, n, k));

    internal static Dictionary<string, D> ParamsOf(D n) => ((D)n["params"]!).ToDictionary(kv => kv.Key, kv => (D)kv.Value!);

    /// <summary>The semantic diff of <paramref name="nxt"/> against <paramref name="prev"/> (two versions of one verb): {class, reasons}. Throws diff_verb for two different verbs.</summary>
    public static D DiffDefs(D prev, D nxt, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null)
    {
        reg ??= Actions.CoreRegistry;
        if ((string)prev["verb"]! != (string)nxt["verb"]!)
            throw new ActionKitError("diff_verb", $"diff compares two versions of one verb, not '{prev["verb"]}' and '{nxt["verb"]}'");
        var o = Actions.Normalize(prev); var n = Actions.Normalize(nxt);
        var rels = new List<(string, string)>();
        var text = TextDiffers(o, n);
        rels.Add(("effects", SetRel(Ak.Strs(o["effects"]), Ak.Strs(n["effects"]))));
        var op = (D)o["params"]!; var np = (D)n["params"]!;
        rels.Add(("params.accepted_calls", CallSetRel(op, np)));
        foreach (var name in op.Keys.OrderBy(k => k, StringComparer.Ordinal))
            if (np.ContainsKey(name))
                foreach (var (k, r) in ParamAttrRels((D)op[name]!, (D)np[name]!)) rels.Add(($"params.{name}.{k}", r));
        var eo = ActionEffective.EffectiveWith(prev, reg, attestationVerified);
        var en = ActionEffective.EffectiveWith(nxt, reg, attestationVerified);
        string ProfRel(D a, D b) => Actions.Leq(a, b) ? (Actions.Leq(b, a) ? "eq" : "narrow") : (Actions.Leq(b, a) ? "widen" : "inc");
        var ho = (D)eo["hint"]!; var hn = (D)en["hint"]!;
        rels.Add(("traits", SetRel(Actions.Closure(reg, Ak.Strs(ho["traits"])), Actions.Closure(reg, Ak.Strs(hn["traits"])))));
        rels.Add(("profile", ProfRel((D)ho["eff"]!, (D)hn["eff"]!)));
        rels.Add(("confirmation", RankRel((eo["confirmed"] is true) ? 0 : 1, (en["confirmed"] is true) ? 0 : 1)));
        rels.Add(("effective.traits", SetRel(Actions.Closure(reg, Ak.Strs(eo["traits"])), Actions.Closure(reg, Ak.Strs(en["traits"])))));
        rels.Add(("effective.profile", ProfRel((D)eo["eff"]!, (D)en["eff"]!)));
        rels.Add(("reversibility", RankRel(Ak.RevRank(Actions.WorstReversibility(o["reversibility"], ParamsOf(o))), Ak.RevRank(Actions.WorstReversibility(n["reversibility"], ParamsOf(n))))));
        rels.Add(("blast", RankRel(Ak.I(((D)o["blast"]!)["ppm"]), Ak.I(((D)n["blast"]!)["ppm"]))));
        var oi = (D)o["idempotency"]!; var ni = (D)n["idempotency"]!;
        var idem = Ak.S(oi, "mode") == "key_param" && Ak.S(ni, "mode") == "key_param" && !IntentJs.JsonEquals(Ak.G(oi, "param"), Ak.G(ni, "param")) ? "inc" : RankRel(IdemRank(Ak.S(oi, "mode")!), IdemRank(Ak.S(ni, "mode")!));
        rels.Add(("idempotency", idem));
        rels.Add(("context", SetRel(Ak.Strs(o["context"]), Ak.Strs(n["context"]))));
        rels.Add(("side_effects", SetRel(Ak.Lst(o, "side_effects").Select(s => $"{Ak.S(s, "target")}|{Ak.S(s, "kind")}"), Ak.Lst(n, "side_effects").Select(s => $"{Ak.S(s, "target")}|{Ak.S(s, "kind")}"))));
        var orr = (D)o["resource"]!; var nrr = (D)n["resource"]!;
        string resId = SortedJson(orr["id"]) == SortedJson(nrr["id"]) ? "eq"
            : ActionIdPattern.IdPatternContains(orr["id"], nrr["id"]) ? "narrow"
            : ActionIdPattern.IdPatternContains(nrr["id"], orr["id"]) ? "widen" : "inc";
        rels.Add(("resource.id", Ak.S(orr, "type") != Ak.S(nrr, "type") ? "inc" : resId));
        rels.Add(("resource.scope", RankRel(-ScopeRank(Ak.S(orr, "scope")!), -ScopeRank(Ak.S(nrr, "scope")!))));
        var ar = SetRel(Ak.Strs(o["aliases"]), Ak.Strs(n["aliases"])); // new aliases widen what natural language can reach
        rels.Add(("aliases", ar == "narrow" ? "widen" : ar == "widen" ? "narrow" : ar));
        rels.Add(("bindings", SortedJson(o["bindings"]) == SortedJson(n["bindings"]) ? "eq" : "inc"));

        var diffs = rels.Where(x => x.Item2 != "eq").ToList();
        var reasons = diffs.Select(x => $"{x.Item1}: {(x.Item2 == "inc" ? "incomparable" : x.Item2)}").OrderBy(s => s, StringComparer.Ordinal).ToList();
        if (text) reasons.Add("text: title, description or compensates changed");
        reasons = reasons.OrderBy(s => s, StringComparer.Ordinal).ToList();
        bool Has(string r) => diffs.Any(x => x.Item2 == r);
        var cls = Has("inc") || (Has("narrow") && Has("widen")) ? "incomparable" : Has("widen") ? "widen" : Has("narrow") ? "narrow" : "equal";
        return new D { ["class"] = cls, ["reasons"] = Ak.ToL(reasons) };
    }

    /// <summary>Does a pin follow this change on its own (no principal)?</summary>
    public static bool DiffIsFree(string c) => c is "equal" or "narrow";
}

public static class ActionDefDiff
{
    static string NumStr(object? v) => v == null ? "undefined" : Ak.JsStr(v);

    static void ParamDiff(string k, D x, D y, List<string> wide, List<string> narrow, List<string> incomp)
    {
        void Rng(string f, bool lowerIsWider)
        {
            var o = Ak.G(x, f); var n = Ak.G(y, f);
            if (IntentJs.JsonEquals(o, n)) return;
            double Rank(object? v) => v == null ? (lowerIsWider ? double.NegativeInfinity : double.PositiveInfinity) : Ak.Dbl(v);
            var widerNew = lowerIsWider ? Rank(n) < Rank(o) : Rank(n) > Rank(o);
            (widerNew ? wide : narrow).Add($"param {k}: {f} {NumStr(o)} to {NumStr(n)}");
        }
        if ((string)x["type"]! != (string)y["type"]!) incomp.Add($"param {k}: type changed");
        Rng("min", true); Rng("max", false); Rng("max_len", false); Rng("max_items", false); Rng("min_items", true);
        if (JsJson.Stringify(Ak.G(x, "unit")) != JsJson.Stringify(Ak.G(y, "unit")) || x.ContainsKey("unit") != y.ContainsKey("unit")) incomp.Add($"param {k}: unit changed");
        var vo = Ak.G(x, "values") as L; var vn = Ak.G(y, "values") as L;
        if (vo != null || vn != null)
        {
            if (vo == null) narrow.Add($"param {k}: values restricted");
            else if (vn == null) wide.Add($"param {k}: values unrestricted");
            else
            {
                var added = vn.Where(v => !vo.Any(w => IntentJs.JsonEquals(v, w))).ToList();
                var removed = vo.Where(v => !vn.Any(w => IntentJs.JsonEquals(v, w))).ToList();
                if (added.Count > 0) wide.Add($"param {k}: values added ({string.Join(", ", added.Select(Ak.JsStr))})");
                if (removed.Count > 0) narrow.Add($"param {k}: values removed ({string.Join(", ", removed.Select(Ak.JsStr))})");
            }
        }
        var xr = Ak.G(x, "required") is true; var yr = Ak.G(y, "required") is true;
        if (xr && Ak.G(y, "required") is false) wide.Add($"param {k}: required to optional");
        if (Ak.G(x, "required") is false && yr) narrow.Add($"param {k}: optional to required");
        string[] pls = { "first_party", "tool", "agent" };
        int Pl(object? v) => v == null ? pls.Length : v is string s ? Array.IndexOf(pls, s) : -1;
        var px = Pl(Ak.G(x, "provenance_min")); var py = Pl(Ak.G(y, "provenance_min"));
        if (py > px) wide.Add($"param {k}: provenance_min loosened");
        else if (py < px) narrow.Add($"param {k}: provenance_min tightened");
        var sx = Ak.SensRank(AkSens.Effective(x)); var sy = Ak.SensRank(AkSens.Effective(y));
        if (sy < sx) wide.Add($"param {k}: sensitivity lowered");
        else if (sy > sx) narrow.Add($"param {k}: sensitivity raised");
        if (!IntentJs.JsonEquals(Ak.G(x, "role"), Ak.G(y, "role")))
        {
            var fy = AkSens.RoleFloorRank(Ak.G(y, "role")); var fx = AkSens.RoleFloorRank(Ak.G(x, "role"));
            if (fy < fx) wide.Add($"param {k}: role changed to a lower-floor role");
            else if (fy > fx) narrow.Add($"param {k}: role changed to a higher-floor role");
            else incomp.Add($"param {k}: role changed");
        }
    }

    /// <summary>{class, breaking, reasons}: anything not shown to be no wider is widening. A renamed verb is a breaking widen.</summary>
    public static D DiffDefs(D a, D b, Dictionary<string, D> reg)
    {
        if ((string)a["verb"]! != (string)b["verb"]!)
            return new D { ["class"] = "widen", ["breaking"] = true, ["reasons"] = new L { "verb renamed: removed + added (grants on the old verb do not follow)" } };
        var wide = new List<string>(); var narrow = new List<string>(); var incomp = new List<string>();
        var breaking = false;
        var na = Actions.Normalize(a); var nb = Actions.Normalize(b);
        var ea = (D)ActionEffective.EffectiveWith(a, reg)["hint"]!;
        var eb = (D)ActionEffective.EffectiveWith(b, reg)["hint"]!;
        if (!Actions.Leq((D)ea["eff"]!, (D)eb["eff"]!)) wide.Add("the effective profile is not at least the old one");
        else if (!ActionEffective.ProfileEq((D)ea["eff"]!, (D)eb["eff"]!)) narrow.Add("the effective profile rose");
        var nae = Ak.Strs(na["effects"]); var nbe = Ak.Strs(nb["effects"]);
        foreach (var e in nae) if (!nbe.Contains(e)) wide.Add($"effect {e} removed");
        foreach (var e in nbe) if (!nae.Contains(e)) narrow.Add($"effect {e} added");
        var nat = Ak.Strs(na["traits"]); var nbt = Ak.Strs(nb["traits"]);
        foreach (var t in nat) if (!nbt.Contains(t)) wide.Add($"declared trait {t} removed");
        foreach (var t in nbt) if (!nat.Contains(t)) narrow.Add($"declared trait {t} added");
        var pa = ActionDiff.ParamsOf(na); var pb = ActionDiff.ParamsOf(nb);
        var ra = Actions.WorstReversibility(na["reversibility"], pa); var rb = Actions.WorstReversibility(nb["reversibility"], pb);
        if (Ak.RevRank(rb) < Ak.RevRank(ra)) wide.Add($"reversibility lowered ({ra} to {rb})");
        else if (Ak.RevRank(rb) > Ak.RevRank(ra)) narrow.Add($"reversibility raised ({ra} to {rb})");
        var ba = Ak.I(((D)na["blast"]!)["ppm"]); var bb = Ak.I(((D)nb["blast"]!)["ppm"]);
        if (bb < ba) wide.Add("blast lowered"); else if (bb > ba) narrow.Add("blast raised");
        int Idem(object? n) => Ak.S(n, "mode") == "none" ? 0 : 1;
        var ia = Idem(na["idempotency"]); var ib = Idem(nb["idempotency"]);
        if (ib < ia) wide.Add("idempotency loosened"); else if (ib > ia) narrow.Add("idempotency added");
        var rsa = (D)na["resource"]!; var rsb = (D)nb["resource"]!;
        if (Ak.S(rsa, "type") != Ak.S(rsb, "type")) incomp.Add("resource type changed");
        var sa = ActionDiff.ScopeRank((string)rsa["scope"]!); var sb = ActionDiff.ScopeRank((string)rsb["scope"]!);
        if (sb > sa) wide.Add("resource scope widened"); else if (sb < sa) narrow.Add("resource scope narrowed");
        var inOld = ActionIdPattern.IdPatternContains(rsa["id"], rsb["id"]);
        var inNew = ActionIdPattern.IdPatternContains(rsb["id"], rsa["id"]);
        if (!inOld) wide.Add("the resource id pattern is not contained in the old one");
        else if (!inNew) narrow.Add("the resource id pattern is narrower");
        foreach (var k in pa.Keys)
        {
            var x = pa[k];
            if (!pb.TryGetValue(k, out var y)) { narrow.Add($"param {k} removed"); breaking = true; continue; }
            ParamDiff(k, x, y, wide, narrow, incomp);
            if (Ak.G(x, "required") is false && Ak.G(y, "required") is true) breaking = true;
        }
        foreach (var k in pb.Keys)
        {
            if (pa.ContainsKey(k)) continue;
            if (Ak.G(pb[k], "required") is true) { narrow.Add($"required param {k} added"); breaking = true; }
            else wide.Add($"optional param {k} added");
        }
        if (Ak.S(a["review"], "state") == "confirmed" && Ak.S(b["review"], "state") != "confirmed") narrow.Add("review state left confirmed");
        var cls = incomp.Count > 0 || (wide.Count > 0 && narrow.Count > 0) ? "incomparable" : wide.Count > 0 ? "widen" : narrow.Count > 0 ? "narrow" : "equal";
        var cmpEq = cls == "equal" && Actions.DefDigest(a) != Actions.DefDigest(b);
        var reasons = wide.Select(r => "widen: " + r).Concat(narrow.Select(r => "narrow: " + r)).Concat(incomp.Select(r => "incomparable: " + r))
            .Concat(cmpEq ? new[] { "equal: only title or description changed" } : Array.Empty<string>()).ToList();
        return new D { ["class"] = cls, ["breaking"] = breaking, ["reasons"] = Ak.ToL(reasons) };
    }

    /// <summary>Per-verb diff of two sets of defs. A removed verb is "removed"; a new verb is "added".</summary>
    public static L DiffPacks(IEnumerable<D> olds, IEnumerable<D> news, Dictionary<string, D> reg)
    {
        var o = new Dictionary<string, D>(); foreach (var d in olds) o[(string)d["verb"]!] = d;
        var n = new Dictionary<string, D>(); foreach (var d in news) n[(string)d["verb"]!] = d;
        var outp = new L();
        foreach (var v in o.Keys.Union(n.Keys).OrderBy(x => x, StringComparer.Ordinal))
        {
            if (!o.TryGetValue(v, out var x)) outp.Add(new D { ["verb"] = v, ["class"] = "added", ["breaking"] = false, ["reasons"] = new L() });
            else if (!n.TryGetValue(v, out var y)) outp.Add(new D { ["verb"] = v, ["class"] = "removed", ["breaking"] = true, ["reasons"] = new L { "verb removed" } });
            else { var e = new D { ["verb"] = v }; foreach (var (k, val) in DiffDefs(x, y, reg)) e[k] = val; outp.Add(e); }
        }
        return outp;
    }
}
