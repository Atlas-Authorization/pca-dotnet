using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * The intent-fidelity ontology: the signed authoring vocabulary (types, units, relations, verbs, aliases, templates), its
 * well-formedness checker, the projection onto the Goal IR ontology, template instantiation and locale-aware amount parsing.
 * An ontology, a template and a slot value are parsed-JSON maps (numbers are Num), like the reference objects.
 */
public static class GoalOntology {

    public static readonly List<string> EFFECT_CLASSES = G.lst("read", "reversible", "external_send", "irreversible");

    private static readonly System.Text.RegularExpressions.Regex INVISIBLE = new System.Text.RegularExpressions.Regex("[\\u200B-\\u200F\\u2060\\uFEFF]");
    private static readonly System.Text.RegularExpressions.Regex NON_PRINTABLE = new System.Text.RegularExpressions.Regex("[^\\x20-\\x7e]");
    private static readonly System.Text.RegularExpressions.Regex ID_TAIL = new System.Text.RegularExpressions.Regex(@"^(?:[A-Za-z0-9_-]+)\z");
    private const long FOREVER = G.MAX_SAFE;

    private static D mm(object? o) { return G.m(o); }

    private static string norm(string s) { return INVISIBLE.Replace(s.Normalize(NormalizationForm.FormKC).ToLowerInvariant(), ""); }

    private static bool hasOwn(object? m, string k) { return m is D && ((D)m).containsKey(k); }

    // for (x of o): an array, or a string by its characters; anything else is not iterable (a TypeError)
    private static L list(object? o) {
        if (o is string str) return str.Select(ch => (object?) ch.ToString()).ToList();
        return G.arr(o, "");
    }

    // a property read on o: null/undefined is a TypeError, any other scalar has no members (undefined)
    private static D mv(object? o) {
        if (o is D d) return d;
        if (o == null) throw new IrError("cannot read properties of null");
        return new D();
    }

    // Object.entries(o): an object's members, an array's or string's indices; null throws; any other scalar has none
    private static IEnumerable<KeyValuePair<string, object?>> entries(object? o) {
        if (o is D d) return d;
        if (o is L l) return l.Select((x, i) => new KeyValuePair<string, object?>(i.ToString(System.Globalization.CultureInfo.InvariantCulture), x));
        if (o is string s) return s.Select((ch, i) => new KeyValuePair<string, object?>(i.ToString(System.Globalization.CultureInfo.InvariantCulture), (object?) ch.ToString()));
        if (o == null) throw new IrError("cannot convert undefined or null to object");
        return Enumerable.Empty<KeyValuePair<string, object?>>();
    }

    private static string strOf(object? o) {
        if (!(o is string)) throw new IrError("string expected");
        return (string) o;
    }

    // ---------------- digest and signing ----------------

    public static string OntologyDigest(D o) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-intent-ontology/v1", "ontology", o)); }

    public static D SignOntology(D o, byte[] seed) { return GoalSign.SignPayload("ontology", o, seed); }

    public static bool VerifyOntology(D s, IEnumerable<object?> pins) { return GoalSign.VerifyPayload(s, "ontology", pins); }

    /** The declared canonical verb for {@code word} (the word itself when it is a verb id, else its alias); null when neither. Case and homoglyph variants are NOT guessed. */
    public static string ResolveVerb(D o, string word) {
        string w = G.jsTrim(word);
        foreach (object? v in list(o.get("verbs"))) if (w.equals(G.get(v, "id"))) return w;
        D al = mm(o.get("aliases"));
        if (al != null && al.containsKey(w)) { object? hit = al.get(w); return hit is string ? (string) hit : null; }
        return null;
    }

    // ---------------- projection onto the IR ontology ----------------

    /** The currency a goal is written in: the first money quantity in its conditions or bound caps (null for a goal without money). */
    public static string GoalCcy(D g) {
        string[] found = {null};
        foreach (object? gr in list(g.get("grants"))) condCcy(mm(G.get(gr, "cond")), found);
        foreach (object? p in list(g.get("prohibits"))) condCcy(mm(G.get(p, "cond")), found);
        foreach (object? c in list(g.get("escalateOn"))) condCcy(mm(c), found);
        foreach (object? b in list(g.get("bounds"))) {
            if (found[0] == null) {
                D u = mm(G.get(G.get(b, "cap"), "u"));
                if (u != null && "money".equals(u.get("k"))) found[0] = (string) u.get("ccy");
            }
        }
        return found[0];
    }

    private static void termCcy(D x, string[] found) {
        if (x == null || !"lit".equals(x.get("k"))) return;
        D v = mm(x.get("v"));
        L items = "set".equals(G.kind(v)) ? list(v.get("items")) : G.list(v);
        foreach (object? it in items) {
            if (found[0] == null && "q".equals(G.kind(it))) {
                D u = mm(G.get(G.get(it, "q"), "u"));
                if (u != null && "money".equals(u.get("k"))) found[0] = (string) u.get("ccy");
            }
        }
    }

    private static void condCcy(D x, string[] found) {
        string k = G.kind(x);
        if (k.equals("cmp")) { termCcy(mm(x.get("l")), found); termCcy(mm(x.get("r")), found); }
        else if (k.equals("and") || k.equals("or")) { condCcy(mm(x.get("a")), found); condCcy(mm(x.get("b")), found); }
        else if (k.equals("not")) condCcy(mm(x.get("c")), found);
    }

    private static D paramTy(D p, string ccy) {
        object? kind = p.get("kind");
        if ("id".equals(kind) || "enum".equals(kind) || "text".equals(kind)) return G.map("k", "s");
        if ("money".equals(kind)) {
            L ccys = G.l(p.get("ccys"));
            if (ccys == null) throw new IrError("money parameter lists no currency");
            object? c = ccy != null && ccys.contains(ccy) ? ccy : ccys.contains("USD") ? "USD" : ccys.Count > 0 ? ccys[0] : null; // an empty list has no first member (undefined)
            return G.map("k", "q", "u", G.map("k", "money", "ccy", c));
        }
        return G.map("k", "q", "u", G.map("k", kind));
    }

    /** The Goal IR ontology (verbs with effect class and typed parameters, relation tables) of an intent ontology. {@code ccy} and {@code rels} may be null. */
    public static D ToIrOntology(D o, string ccy, L rels) {
        L verbs = new();
        foreach (object? vo in list(o.get("verbs"))) {
            D v = mm(vo);
            D prm = mm(v.get("params"));
            List<string> keys = new(prm.keySet());
            keys.sort(string.CompareOrdinal);
            L ps = new();
            foreach (string path in keys) ps.add(G.map("path", path, "ty", paramTy(mm(prm.get(path)), ccy)));
            verbs.add(G.map("verb", v.get("id"), "cls", v.get("effect"), "params", ps));
        }
        return G.map("verbs", verbs, "rels", rels != null ? rels : new L());
    }

    /** The IR ontology a goal is typed and decided against: money parameters in the goal's own currency. */
    public static D OntologyForGoal(D o, D g, L rels) {
        return ToIrOntology(o, GoalCcy(g), rels);
    }

    /** Relation anchors a goal mentions, declared with no members. */
    public static L GoalAnchors(D g) {
        Dictionary<string, D> outp = new();
        foreach (object? gr in list(g.get("grants"))) anchorSel(mm(G.get(gr, "res")), outp);
        foreach (object? p in list(g.get("prohibits"))) anchorSel(mm(G.get(p, "res")), outp);
        List<string> keys = new(outp.keySet());
        keys.sort(string.CompareOrdinal);
        L r = new();
        foreach (string k in keys) r.add(outp.get(k));
        return r;
    }

    private static void anchorSel(D s, Dictionary<string, D> outp) {
        string k = G.kind(s);
        if (k.equals("related")) outp.put(G.jsStr(s.get("rel")) + "\0" + G.jsStr(s.get("anchor")), G.map("rel", s.get("rel"), "anchor", s.get("anchor"), "members", new L()));
        else if (k.equals("all_of")) foreach (object? p in list(s.get("parts"))) anchorSel(mm(p), outp);
    }

    // ---------------- template references ----------------

    private static List<string> d(string x) { return x.startsWith("$") ? G.lst(x.substring(1)) : G.lst(); }

    private static List<string> refsRes(D s) {
        string k = G.kind(s);
        List<string> outp = new();
        if (k.equals("exact")) outp.addAll(d(strOf(s.get("id"))));
        else if (k.equals("oneof")) foreach (object? i in list(s.get("ids"))) outp.addAll(d(strOf(i)));
        else if (k.equals("related")) outp.addAll(d(strOf(s.get("anchor"))));
        else if (k.equals("all_of")) foreach (object? p in list(s.get("parts"))) outp.addAll(refsRes(mm(p)));
        return outp;
    }

    private static List<string> refsTerm(D x) { return "slot".equals(G.kind(x)) ? G.lst(strOf(x.get("slot"))) : G.lst(); }

    private static List<string> refsCond(D c) {
        string k = G.kind(c);
        List<string> outp = new();
        if (k.equals("cmp")) { outp.addAll(refsTerm(mm(c.get("l")))); outp.addAll(refsTerm(mm(c.get("r")))); }
        else if (k.equals("and") || k.equals("or")) { outp.addAll(refsCond(mm(c.get("a")))); outp.addAll(refsCond(mm(c.get("b")))); }
        else if (k.equals("not")) outp.addAll(refsCond(mm(c.get("c"))));
        return outp;
    }

    private static List<string> refsGrant(D g) { List<string> r = refsRes(mm(g.get("res"))); r.addAll(refsCond(mm(g.get("cond")))); return r; }

    private static List<string> refsBound(D b) {
        object? cs = b.get("cap_slot");
        return G.truthy(cs) ? G.lst(G.jsStr(cs)) : G.lst();
    }

    private static List<string> slotRefs(D t) {
        List<string> r = new();
        foreach (object? g in list(t.get("grants"))) r.addAll(refsGrant(mm(g)));
        foreach (object? p in list(t.get("prohibits"))) r.addAll(refsGrant(mm(p)));
        foreach (object? b in list(t.get("bounds"))) r.addAll(refsBound(mm(b)));
        return r;
    }

    // ---------------- the well-formedness checker ----------------

    private static void bad(L I, string code, object? where, string msg) { I.add(where == null ? G.map("code", code, "msg", msg) : G.map("code", code, "where", where, "msg", msg)); } // an undefined where is left out

    private static bool isInteger(object? v) {
        double? x = G.dbl(v);
        return x != null && !double.IsNaN(x.Value) && !double.IsInfinity(x.Value) && x.Value == Math.Floor(x.Value);
    }

    private static D findBy(object? listO, string key, object? val) {
        foreach (object? x in list(listO)) if (x is D && object.Equals(((D)x).get(key), val)) return mm(x);
        return null;
    }

    private static bool strIncludes(object? listO, object? v) { L l = G.l(listO); return l != null && l.contains(v); }

    private static bool nonEmpty(object? listO) { L l = G.l(listO); return l != null && !l.isEmpty(); }

    /** Every defect of an intent ontology as {code, where, msg}; an empty list means well formed. */
    public static L CheckOntology(D o) {
        L I = new();
        HashSet<object?> typeIds = new();
        HashSet<object?> prefixes = new();
        foreach (object? to in list(o.get("types"))) {
            D t = mv(to);
            if (typeIds.contains(t.get("id"))) bad(I, "dup_type", t.get("id"), "duplicate type id");
            typeIds.add(t.get("id"));
            object? pre = t.get("id_prefix");
            if (!G.truthy(pre) || prefixes.contains(pre)) bad(I, "dup_prefix", t.get("id"), "id prefix empty or reused");
            prefixes.add(pre);
        }
        object? unitsRaw = o.get("units"); D units = mv(unitsRaw); // Object.entries(o.units) throws on null; a scalar has no entries
        foreach (KeyValuePair<string, object?> e in entries(unitsRaw)) {
            string u = e.Key;
            D dd = mv(e.Value);
            bool money = "money".equals(dd.get("kind"));
            if (money) {
                object? ex = dd.get("exponent");
                double? x = G.dbl(ex);
                if (!(isInteger(ex) && x >= 0 && x <= 4)) bad(I, "unit_exponent", u, "money unit needs an integer exponent 0..4");
            }
            if (!money && dd.containsKey("exponent")) bad(I, "unit_exponent", u, "only money units carry an exponent");
        }
        HashSet<object?> relIds = new();
        foreach (object? ro in list(o.get("relations"))) {
            D r = mv(ro);
            if (relIds.contains(r.get("id"))) bad(I, "dup_relation", G.jsStr(r.get("id")), "duplicate relation");
            relIds.add(r.get("id"));
            if (!typeIds.contains(r.get("from")) || !typeIds.contains(r.get("to"))) bad(I, "relation_type", G.jsStr(r.get("id")), "relation endpoint type is not declared");
        }
        HashSet<object?> verbIds = new();
        Dictionary<string, D> verbs = new();
        foreach (object? vo in list(o.get("verbs"))) {
            D v = mv(vo);
            string vid = G.jsStr(v.get("id"));
            if (verbIds.contains(v.get("id"))) bad(I, "dup_verb", vid, "duplicate verb");
            verbIds.add(v.get("id"));
            verbs.put(G.key(v.get("id")), v);
            if (!EFFECT_CLASSES.contains(v.get("effect"))) bad(I, "no_effect_class", vid, "verb has no valid effect class");
            if (!typeIds.contains(v.get("resource_type"))) bad(I, "verb_resource_type", vid, "resource type is not declared");
            foreach (KeyValuePair<string, object?> pe in entries(v.get("params"))) {
                string p = pe.Key;
                D pt = mm(pe.Value);
                object? kind = pt.get("kind");
                if ("money".equals(kind)) {
                    if (!nonEmpty(pt.get("ccys"))) bad(I, "param_ccy", vid + "." + p, "money parameter lists no currency");
                    L cs = G.l(pt.get("ccys"));
                    if (cs != null) foreach (object? c in cs) {
                        D ud = c is string ? mm(units.get(c)) : null;
                        if (ud == null || !"money".equals(ud.get("kind"))) bad(I, "unit_unknown", vid + "." + p, "currency " + G.jsStr(c) + " is not a declared money unit");
                    }
                } else if ("enum".equals(kind)) { if (!nonEmpty(pt.get("values"))) bad(I, "param_enum", vid + "." + p, "enum parameter has no values"); }
                else if ("id".equals(kind)) { if (!G.truthy(pt.get("of")) || !typeIds.contains(pt.get("of"))) bad(I, "param_type", vid + "." + p, "id parameter type is not declared"); }
                else if (!"text".equals(kind)) {
                    bool any = false;
                    foreach (object? ud in units.Values) if (object.Equals(G.get(ud, "kind"), kind)) any = true;
                    if (!any) bad(I, "unit_unknown", vid + "." + p, "no declared unit of kind " + G.jsStr(kind));
                }
            }
        }
        // Alias map: a function, keys normalized and collision-free, targets canonical, no chains or cycles.
        object? aliasesRaw = o.get("aliases"); D aliases = mv(aliasesRaw);
        Dictionary<string, string> seen = new();
        foreach (KeyValuePair<string, object?> e in entries(aliasesRaw)) {
            string k = e.Key;
            object? target = e.Value;
            if (!k.equals(norm(k)) || (NON_PRINTABLE.IsMatch(k) && !k.equals(k.Normalize(NormalizationForm.FormKC)))) bad(I, "alias_key", k, "alias key is not in normalized form");
            if (INVISIBLE.IsMatch(k)) bad(I, "alias_key", k, "alias key contains invisible characters");
            string n = norm(k);
            if (seen.containsKey(n) && !seen.get(n).equals(k)) bad(I, "alias_collision", k, "collides with " + seen.get(n) + " after normalization");
            seen.put(n, k);
            if (!verbIds.contains(target)) bad(I, "alias_target", k, "alias target is not a canonical verb");
            if (target is string && aliases.containsKey(target)) bad(I, "alias_chain", k, "alias target is itself an alias (chain or cycle)");
            if (verbIds.contains(k) && !k.equals(target)) bad(I, "alias_shadow", k, "alias shadows a canonical verb");
        }
        // Templates.
        HashSet<object?> tids = new();
        foreach (object? to in list(o.get("templates"))) {
            D t = mv(to);
            string w = "template:" + G.jsStr(t.get("id"));
            if (tids.contains(t.get("id"))) bad(I, "dup_template", w, "duplicate template id");
            tids.add(t.get("id"));
            L slots = list(t.get("slots"));
            HashSet<object?> slotNames = new();
            foreach (object? s in slots) slotNames.add(G.get(s, "name"));
            if (slotNames.size() != slots.size()) bad(I, "dup_slot", w, "duplicate slot");
            List<string> refs = slotRefs(t);
            foreach (string r in refs) if (!slotNames.contains(r)) bad(I, "slot_undeclared", w, "slot " + r + " is used but not declared");
            foreach (object? so in slots) {
                D s = mv(so);
                string sw = w + "." + G.jsStr(s.get("name"));
                object? sk = s.get("kind");
                if (("id".equals(sk) || "id_list".equals(sk)) && (!G.truthy(s.get("of")) || !typeIds.contains(s.get("of")))) bad(I, "slot_type", sw, "id slot type is not declared");
                if ("money".equals(sk)) {
                    object? cc = s.get("ccy");
                    D ud = cc is string ? mm(units.get(cc)) : mm(units.get(""));
                    if (cc == null) ud = mm(units.get(""));
                    if (ud == null || !"money".equals(ud.get("kind"))) bad(I, "slot_ccy", sw, "money slot currency is not a declared unit");
                }
                if (("enum".equals(sk) || "enum_list".equals(sk)) && !nonEmpty(s.get("values"))) bad(I, "slot_enum", sw, "enum slot has no values");
                if (!G.truthy(s.get("mandatory")) && !s.containsKey("default")) bad(I, "slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)");
                if (!refs.contains(G.jsStr(s.get("name")))) bad(I, "slot_unused", sw, "declared slot is never used");
            }
            L tgrants = list(t.get("grants"));
            if (tgrants.isEmpty()) bad(I, "empty_allow", w, "template has no grant (empty Allow set)");
            HashSet<object?> gids = new();
            foreach (object? g in tgrants) gids.add(G.get(g, "gid"));
            if (gids.size() != tgrants.size()) bad(I, "dup_gid", w, "duplicate grant id");
            foreach (object? go in tgrants) {
                D g = mv(go);
                D v = verbs.get(G.key(g.get("verb")));
                string gw = w + "." + G.jsStr(g.get("gid"));
                if (v == null) { bad(I, "grant_verb", gw, "grant verb is not in the ontology"); continue; }
                checkResource(o, mm(g.get("res")), v, gw, I);
                checkCond(mm(g.get("cond")), v, t, gw, I);
                D gres = mm(g.get("res"));
                if ("any".equals(G.kind(gres)) && !("read".equals(v.get("effect")) && !list(t.get("bounds")).isEmpty())) bad(I, "unbounded", gw, "wildcard resource in a template");
                if (!"read".equals(v.get("effect")) && "related".equals(G.kind(gres)) && list(t.get("bounds")).isEmpty()) bad(I, "unbounded", gw, "non-read grant on a related set needs an aggregate bound");
            }
            foreach (object? po in list(t.get("prohibits"))) {
                D p = mv(po);
                D tg = mm(p.get("target"));
                string pw = w + "." + G.jsStr(p.get("pid"));
                if ("verb".equals(G.kind(tg)) && !verbs.containsKey(G.key(tg.get("verb")))) bad(I, "prohibit_verb", pw, "prohibit verb is not in the ontology");
                if ("effect".equals(G.kind(tg)) && !EFFECT_CLASSES.contains(tg.get("cls"))) bad(I, "prohibit_effect", pw, "unknown effect class");
            }
            foreach (object? bo in list(t.get("bounds"))) {
                D b = mv(bo);
                string bw = w + "." + G.jsStr(b.get("bid"));
                object? over = b.get("over");
                if (!"all".equals(over)) {
                    bool unknown = false;
                    foreach (object? x in list(over)) if (!gids.contains(x)) unknown = true;
                    if (unknown) bad(I, "bound_over", bw, "bound selects an unknown grant");
                }
                object? cslot = b.get("cap_slot");
                if (G.truthy(cslot) && !slotNames.contains(cslot)) bad(I, "slot_undeclared", w, "cap slot " + G.jsStr(cslot) + " is not declared");
                if (G.truthy(cslot)) {
                    D cs = findBy(slots, "name", cslot);
                    object? ck = cs == null ? null : cs.get("kind");
                    object? agg = b.get("agg");
                    if (cs != null && !("money".equals(ck) || "count".equals(ck))) bad(I, "bound_cap", bw, "cap slot must be money or count");
                    if (cs != null && "count".equals(agg) && !"count".equals(ck)) bad(I, "bound_cap", bw, "count bound needs a count slot");
                    if (cs != null && "sum".equals(agg) && !"money".equals(ck)) bad(I, "bound_cap", bw, "sum bound over money needs a money slot");
                }
                if ("sum".equals(b.get("agg")) && !G.truthy(b.get("param"))) bad(I, "bound_value", bw, "sum bound has no value parameter");
            }
            // non-empty and bounded after instantiation with the declared example
            D gi = InstantiateTemplate(o, strOf(t.get("id")), mm(t.get("example")), "p", "", null);
            L holes = list(gi.get("holes"));
            if (!holes.isEmpty()) {
                List<string> hs = new();
                foreach (object? h in holes) hs.add(G.jsStr(G.get(h, "hid")));
                bad(I, "example_holes", w, "example leaves holes: " + string.Join(",", hs));
            } else if (list(gi.get("grants")).size() != tgrants.size()) bad(I, "empty_allow", w, "example instantiation dropped a grant");
            else if (!hasAllowWitness(o, gi)) bad(I, "empty_allow", w, "instantiated template has an empty Allow set");
        }
        return I;
    }

    private static string prefixOf(D o, object? typeId) {
        D t = findBy(o.get("types"), "id", typeId);
        return t == null ? null : (string) t.get("id_prefix");
    }

    private static bool idOk(string id, string pre) { return id.startsWith("$") || (pre != null && id.startsWith(pre)); }

    private static void checkResource(D o, D s, D v, string w, L I) {
        string prefix = prefixOf(o, v.get("resource_type"));
        string k = G.kind(s);
        if (k.equals("exact") && !idOk(strOf(s.get("id")), prefix)) bad(I, "resource_type", w, "exact resource id has the wrong type prefix");
        else if (k.equals("oneof")) {
            L ids = list(s.get("ids"));
            if (ids.isEmpty()) bad(I, "resource_empty", w, "one_of is empty");
            foreach (object? i in ids) if (!idOk(strOf(i), prefix)) bad(I, "resource_type", w, "one_of member has the wrong type prefix");
        } else if (k.equals("related")) {
            D r = findBy(o.get("relations"), "id", s.get("rel"));
            if (r == null) bad(I, "relation_unknown", w, "relation " + G.jsStr(s.get("rel")) + " is not declared");
            else {
                if (!object.Equals(r.get("to"), v.get("resource_type"))) bad(I, "relation_type", w, "relation target type differs from the verb resource type");
                string anchorPre = prefixOf(o, r.get("from"));
                if (!idOk(strOf(s.get("anchor")), anchorPre)) bad(I, "resource_type", w, "relation anchor has the wrong type prefix");
            }
        } else if (k.equals("all_of")) {
            L parts = list(s.get("parts"));
            if (parts.size() < 2) bad(I, "all_of_arity", w, "all_of needs at least two parts");
            foreach (object? x in parts) checkResource(o, mm(x), v, w, I);
        }
    }

    private static void checkCond(D c, D v, D t, string w, L I) {
        string k = G.kind(c);
        if (k.equals("and") || k.equals("or")) { checkCond(mm(c.get("a")), v, t, w, I); checkCond(mm(c.get("b")), v, t, w, I); return; }
        if (k.equals("not")) { checkCond(mm(c.get("c")), v, t, w, I); return; }
        if (!k.equals("cmp")) return;
        D l = mm(c.get("l"));
        D p = "param".equals(G.kind(l)) ? mm(mm(v.get("params")).get(l.get("path"))) : null;
        if (!"param".equals(G.kind(l)) || p == null) { bad(I, "cond_param", w, "left side of a comparison must be a declared parameter of the verb"); return; }
        object? op = c.get("op");
        bool ordered = "lt".equals(op) || "lte".equals(op) || "gt".equals(op) || "gte".equals(op);
        object? pk = p.get("kind");
        if (ordered && ("text".equals(pk) || "enum".equals(pk) || "id".equals(pk))) bad(I, "cond_order", w, "ordering on a text/enum/id parameter");
        D x = mm(c.get("r"));
        string xk = G.kind(x);
        bool inOp = "in".equals(op) || "nin".equals(op);
        if (xk.equals("slot")) {
            D s = findBy(t.get("slots"), "name", x.get("slot"));
            if (s == null) return;
            object? sk = s.get("kind");
            bool okKind = "money".equals(pk) ? "money".equals(sk)
                : object.Equals(pk, sk) || ("enum".equals(pk) && ("enum".equals(sk) || "enum_list".equals(sk))) || ("id".equals(pk) && ("id".equals(sk) || "id_list".equals(sk))) || ("text".equals(pk) && "text_list".equals(sk));
            if (!okKind) bad(I, "cond_type", w, "slot " + G.jsStr(s.get("name")) + " (" + G.jsStr(sk) + ") does not type-check against parameter kind " + G.jsStr(pk));
            if ("money".equals(pk) && "money".equals(sk) && !strIncludes(p.get("ccys"), s.get("ccy") == null ? "" : s.get("ccy"))) bad(I, "cond_unit", w, "slot currency is not accepted by the parameter");
            bool isList = "id_list".equals(sk) || "enum_list".equals(sk) || "text_list".equals(sk);
            if (isList != inOp) bad(I, "cond_type", w, "list slots pair with in/nin and scalar slots with the other operators");
        } else if (xk.equals("lit")) {
            D lv = mm(x.get("v"));
            if ("set".equals(G.kind(lv))) {
                L items = list(lv.get("items"));
                if (items.isEmpty()) bad(I, "cond_type", w, "empty literal list");
                foreach (object? i in items) litCheck(mm(i), p, w, I);
                if (!inOp) bad(I, "cond_type", w, "a literal set pairs with in/nin");
            } else {
                litCheck(lv, p, w, I);
                if (inOp) bad(I, "cond_type", w, "in/nin needs a list");
            }
        } else bad(I, "cond_term", w, "unsupported right-hand term");
    }

    private static void litCheck(D l, D p, string w, L I) {
        string k = G.kind(l);
        object? pk = p.get("kind");
        if (k.equals("q")) {
            D u = mm(G.get(l.get("q"), "u"));
            if (!object.Equals(u.get("k"), pk)) bad(I, "cond_type", w, "literal kind differs from the parameter kind");
            if ("money".equals(u.get("k")) && !strIncludes(p.get("ccys"), u.get("ccy"))) bad(I, "cond_unit", w, "literal currency is not accepted by the parameter");
        } else if (k.equals("s")) {
            if (!"enum".equals(pk) && !"id".equals(pk) && !"text".equals(pk)) bad(I, "cond_type", w, "literal kind differs from the parameter kind");
            if ("enum".equals(pk) && !strIncludes(p.get("values"), l.get("s"))) bad(I, "cond_enum", w, "enum literal is not a member");
        } else bad(I, "cond_type", w, "nested literal set");
    }

    private static bool hasAllowWitness(D o, D g) {
        D ont = OntologyForGoal(o, g, null);
        foreach (object? gr in list(g.get("grants"))) if (GoalExamples.AllowWitness(g, mm(gr), ont) == null) return false;
        return true;
    }

    // ---------------- template instantiation ----------------

    private static D quantityOf(D s, object? v) {
        if (v is string || v is L) return null;
        if (!(v is D)) throw new IrError("slot value is not an object");
        D m = mm(v);
        object? kind = s.get("kind");
        if (m.containsKey("minor") && "money".equals(kind) && object.Equals(m.get("ccy"), s.get("ccy"))) {
            long? n = G.safeInt(m.get("minor"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "money", "ccy", m.get("ccy")), "n", G.num(n.Value));
        }
        if (m.containsKey("n") && "count".equals(kind)) {
            long? n = G.safeInt(m.get("n"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "count"), "n", G.num(n.Value));
        }
        if (m.containsKey("ms") && "duration".equals(kind)) {
            long? n = G.safeInt(m.get("ms"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "duration"), "n", G.num(n.Value));
        }
        if (m.containsKey("epoch_ms") && "instant".equals(kind)) {
            long? n = G.safeInt(m.get("epoch_ms"));
            if (n != null) return G.map("u", G.map("k", "instant"), "n", G.num(n.Value));
        }
        return null;
    }

    private static D sv(object? s) { return G.map("k", "s", "s", s); }

    private static bool idLike(string v) { return ID_TAIL.IsMatch(v); }

    private static bool noInvisible(string x) { return x.equals(x.Normalize(NormalizationForm.FormKC)) && !INVISIBLE.IsMatch(x); }

    /** Typed value(s) of a slot (a List of values), or a reason string when it is missing or invalid (the slot then becomes a Hole). */
    public static object? SlotLits(D o, D s, object? v) {
        if (v == null) return "missing";
        string kind = G.jsStr(s.get("kind"));
        switch (kind) {
            case "money": case "count": case "duration": case "instant": {
                D q = quantityOf(s, v);
                if (q == null) return "ill-typed";
                double? max = s.get("max") == null ? null : G.dbl(s.get("max"));
                if (max != null) {
                    double qn = kind.equals("instant") ? 0 : G.toNum(q.get("n"));
                    if (qn > max) return "above the template maximum";
                }
                return G.list(G.map("k", "q", "q", q));
            }
            case "id": {
                string pre = prefixOf(o, s.get("of"));
                return v is string && pre != null && !pre.isEmpty() && ((string) v).startsWith(pre) && ((string) v).Length > pre.Length && idLike((string) v) ? G.list(sv(v)) : "ill-typed";
            }
            case "id_list": {
                string pre = prefixOf(o, s.get("of"));
                if (!(v is L) || ((L)v).isEmpty()) return "ill-typed";
                L outp = new();
                foreach (object? x in (L) v) {
                    string xs = strOf(x);
                    if (!(pre != null && !pre.isEmpty() && xs.startsWith(pre) && idLike(xs))) return "ill-typed";
                    outp.add(sv(x));
                }
                return outp;
            }
            case "enum": return v is string && strIncludes(s.get("values"), v) ? G.list(sv(v)) : "ill-typed";
            case "enum_list": {
                if (!(v is L) || ((L)v).isEmpty()) return "ill-typed";
                L outp = new();
                foreach (object? x in (L) v) { if (!strIncludes(s.get("values"), x)) return "ill-typed"; outp.add(sv(x)); }
                return outp;
            }
            case "text_list": {
                if (!(v is L) || ((L)v).isEmpty()) return "ill-typed";
                L outp = new();
                foreach (object? x in (L) v) {
                    if (!(x is string) || ((string) x).isEmpty() || !noInvisible((string) x)) return "ill-typed";
                    outp.add(sv(x));
                }
                return outp;
            }
            default: return null;
        }
    }

    private static bool isListSlot(D t, string name) {
        D s = findBy(t.get("slots"), "name", name);
        return s != null && s.get("kind") is string && ((string) s.get("kind")).endsWith("_list");
    }

    /**
     * Template -&gt; Goal (canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a hole
     * is dropped (the most restrictive completion). {@code sources} may be null.
     */
    public static D InstantiateTemplate(D o, string templateId, D values, string principal, string nl, List<string> sources) {
        D t = findBy(o.get("templates"), "id", templateId);
        if (t == null) throw new IrError("unknown template " + templateId);
        Dictionary<string, L> bound = new();
        L holes = new();
        foreach (object? so in list(t.get("slots"))) {
            D s = mm(so);
            string name = G.jsStr(s.get("name"));
            object? val = values == null ? null : values.get(name);
            if (val == null) val = s.get("default");
            object? r = SlotLits(o, s, val);
            if (r is string) {
                holes.add(G.map("hid", name, "q", "What is the " + name.replace("_", " ") + " (" + G.jsStr(s.get("kind")) + (G.truthy(s.get("ccy")) ? " " + G.jsStr(s.get("ccy")) : "") + ")? (" + r + ")",
                    "domain", new L(), "affects", new L(), "global", false));
            } else {
                L rl = (L) r;
                bound.put(name, rl);
            }
        }
        Dictionary<string, D> verbOf = new();
        foreach (object? vo in list(o.get("verbs"))) verbOf.put(G.key(G.get(vo, "id")), mm(vo));
        Inst inst = new Inst(o, t, bound, verbOf);
        HashSet<string> dropped = new();
        L grants = new();
        L tbounds = list(t.get("bounds"));
        L keepBound = new();
        foreach (object? b in tbounds) if (inst.deps(refsBound(mm(b)))) keepBound.add(b);
        foreach (object? bo in tbounds) {
            if (keepBound.contains(bo)) continue;
            D b = mm(bo);
            foreach (object? go in list(t.get("grants"))) {
                object? gid = G.get(go, "gid");
                if ("all".equals(b.get("over")) || list(b.get("over")).contains(gid)) dropped.add(G.jsStr(gid));
            }
        }
        foreach (object? go in list(t.get("grants"))) {
            D g = mm(go);
            string gid = G.jsStr(g.get("gid"));
            if (dropped.contains(gid) || !inst.deps(refsGrant(g))) dropped.add(gid);
            else grants.add(G.map("gid", g.get("gid"), "verb", g.get("verb"), "res", inst.subRes(mm(g.get("res"))), "cond", inst.subCond(mm(g.get("cond")), (string) g.get("verb"))));
        }
        L prohibits = new();
        foreach (object? po in list(t.get("prohibits"))) {
            D p = mm(po);
            D tg = mm(p.get("target"));
            string verb;
            if ("verb".equals(G.kind(tg))) verb = (string) tg.get("verb");
            else {
                verb = null;
                foreach (object? vo in list(o.get("verbs"))) if (object.Equals(G.get(vo, "effect"), tg.get("cls"))) { verb = (string) G.get(vo, "id"); break; }
            }
            if (inst.deps(refsGrant(p))) prohibits.add(G.map("pid", p.get("pid"), "target", tg, "res", inst.subRes(mm(p.get("res"))), "cond", inst.subCond(mm(p.get("cond")), verb)));
            else prohibits.add(G.map("pid", p.get("pid"), "target", tg, "res", G.map("k", "any", "reason", "hole"), "cond", G.map("k", "true")));
        }
        HashSet<string> kept = new();
        foreach (object? g in grants) kept.add(G.jsStr(G.get(g, "gid")));
        L bounds = new();
        foreach (object? bo in keepBound) {
            D b = mm(bo);
            L gids = new();
            if ("all".equals(b.get("over"))) foreach (object? g in grants) gids.add(G.get(g, "gid"));
            else foreach (object? x in list(b.get("over"))) if (kept.contains(G.jsStr(x))) gids.add(x);
            if (gids.isEmpty()) continue;
            object? capSlot = b.get("cap_slot");
            D capLit = G.truthy(capSlot) ? inst.single(G.jsStr(capSlot)) : null;
            D cap = capLit != null && "q".equals(G.kind(capLit)) ? mm(capLit.get("q")) : mm(b.get("cap"));
            string verb = null;
            foreach (object? g in grants) if (object.Equals(G.get(g, "gid"), gids.get(0))) { verb = (string) G.get(g, "verb"); break; }
            if (verb == null) throw new IrError("bound without a surviving grant");
            D value;
            if ("sum".equals(b.get("agg"))) {
                if (!(b.get("param") is string)) throw new IrError("parameter undefined is not declared by any verb");
                D cu = mm(cap.get("u"));
                value = G.map("k", "param", "path", b.get("param"), "ty", inst.tyOf(verb, (string) b.get("param"), "money".equals(cu.get("k")) ? (string) cu.get("ccy") : null));
            } else value = G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", G.map("k", "count"), "n", G.num(1))));
            bounds.add(G.map("bid", b.get("bid"), "sel", G.map("k", "gids", "gids", gids), "agg", b.get("agg"), "value", value, "key", "",
                "window", G.map("k", "lifetime"), "scope", G.map("k", "session"), "cap", cap, "onExceed", b.get("onExceed")));
        }
        L srcs = new();
        if (sources != null) srcs.addAll(sources);
        return GoalNormalize.CanonicalizeGoal(G.map(
            "v", G.num(1), "principal", principal, "ontDigest", OntologyDigest(o), "nlDigest", GoalDigests.NlDigest(nl), "sources", srcs,
            "grants", grants, "prohibits", prohibits, "bounds", bounds,
            "validity", G.map("notBefore", G.num(0), "notAfter", G.num(FOREVER), "maxIdle", G.num(0)),
            "deleg", G.map("maxDepth", G.num(0), "narrowOnly", true, "mayTouch", new L()),
            "escalateOn", new L(), "wildcardAck", new L(), "holes", holes));
    }

    /** The substitution state of one instantiation. */
    private sealed class Inst {
        internal D o, t;
        internal Dictionary<string, L> bound;
        internal Dictionary<string, D> verbOf;

        internal Inst(D o, D t, Dictionary<string, L> bound, Dictionary<string, D> verbOf) { this.o = o; this.t = t; this.bound = bound; this.verbOf = verbOf; }

        internal bool deps(List<string> refs) { foreach (string r in refs) if (!bound.containsKey(r)) return false; return true; }

        internal D single(string name) { return mm(bound.get(name).get(0)); }

        internal string sub(string id) { return id.startsWith("$") ? (string) single(id.substring(1)).get("s") : id; }

        internal D subPart(D r) {
            string k = G.kind(r);
            if (k.equals("exact")) return G.map("k", "exact", "id", sub(strOf(r.get("id"))));
            if (k.equals("oneof")) { L ids = new(); foreach (object? i in list(r.get("ids"))) ids.add(sub(strOf(i))); return G.map("k", "oneof", "ids", ids); }
            D c = new(r);
            c.put("anchor", sub(strOf(r.get("anchor"))));
            return c;
        }

        internal D subRes(D r) {
            string k = G.kind(r);
            if (k.equals("any")) return r;
            if (k.equals("all_of")) { L ps = new(); foreach (object? p in list(r.get("parts"))) ps.add(subPart(mm(p))); return G.map("k", "all_of", "parts", ps); }
            return subPart(r);
        }

        internal D tyOf(string verb, string path, string ccy) {
            D p = null;
            D v = verb != null ? verbOf.get(G.key(verb)) : null;
            if (v != null) p = mm(mm(v.get("params")).get(path));
            if (p == null) foreach (object? vo in list(o.get("verbs"))) { D x = mm(mm(G.get(vo, "params")).get(path)); if (x != null) { p = x; break; } }
            if (p == null) throw new IrError("parameter " + path + " is not declared by any verb");
            return paramTy(p, ccy);
        }

        internal D lit(D x) {
            string k = G.kind(x);
            if (k.equals("slot")) {
                string slot = strOf(x.get("slot"));
                L l = bound.get(slot);
                return G.map("k", "lit", "v", isListSlot(t, slot) ? G.map("k", "set", "items", l) : l.get(0));
            }
            return k.equals("lit") ? G.map("k", "lit", "v", x.get("v")) : null;
        }

        internal string ccyOf(D x) {
            if (x != null && "lit".equals(x.get("k"))) {
                D v = mm(x.get("v"));
                if ("q".equals(G.kind(v))) { D u = mm(G.get(v.get("q"), "u")); if (u != null && "money".equals(u.get("k"))) return (string) u.get("ccy"); }
            }
            return null;
        }

        internal D term(D x, D v, string verb, string hint) {
            if (v != null) return v;
            string path = strOf(x.get("path"));
            return G.map("k", "param", "path", path, "ty", tyOf(verb, path, hint));
        }

        internal D subCond(D c, string verb) {
            string k = G.kind(c);
            if (k.equals("true")) return c;
            if (k.equals("and")) return G.map("k", "and", "a", subCond(mm(c.get("a")), verb), "b", subCond(mm(c.get("b")), verb));
            if (k.equals("or")) return G.map("k", "or", "a", subCond(mm(c.get("a")), verb), "b", subCond(mm(c.get("b")), verb));
            if (k.equals("not")) return G.map("k", "not", "c", subCond(mm(c.get("c")), verb));
            D l = mm(c.get("l")), r = mm(c.get("r"));
            D lv = lit(l), rv = lit(r);
            string hint = ccyOf(lv);
            if (hint == null) hint = ccyOf(rv);
            D tl = term(l, lv, verb, hint);
            D tr = term(r, rv, verb, hint);
            return G.map("k", "cmp", "op", c.get("op"), "l", tl, "r", tr);
        }
    }

    // ---------------- locale-aware human number parsing ----------------

    private static D amountFail(string reason) { return G.map("ok", false, "reason", reason); }

    private static readonly System.Text.RegularExpressions.Regex NOT_AMOUNT_CHAR = new System.Text.RegularExpressions.Regex("[^0-9.,]");
    private static readonly System.Text.RegularExpressions.Regex AMOUNT = new System.Text.RegularExpressions.Regex(@"^(?:[0-9][0-9.,]*)\z");
    private static readonly System.Text.RegularExpressions.Regex DOUBLE_SEP = new System.Text.RegularExpressions.Regex("[.,]{2}");
    private static readonly System.Text.RegularExpressions.Regex DIGITS = new System.Text.RegularExpressions.Regex(@"^(?:[0-9]+)\z");

    private static int count(string t, char sep) { int n = 0; for (int i = 0; i < t.Length; i++) if (t[i] == sep) n++; return n; }

    /**
     * "1,000.50", "1.000,50", "$20", "20 dollars": {ok: true, minor} or {ok: false, reason}. Ambiguous literals ("1,000" with no locale
     * hint, "1.000") are NOT guessed. {@code locale} is "en" (',' is thousands), "de" ('.' is thousands) or null.
     */
    public static D ParseHumanAmount(string text, int exponent, string locale) {
        string t = NOT_AMOUNT_CHAR.Replace(G.jsTrim(text.Normalize(NormalizationForm.FormKC)), "");
        if (!AMOUNT.IsMatch(t) || DOUBLE_SEP.IsMatch(t)) return amountFail("not a number");
        int lastDot = t.lastIndexOf('.'), lastComma = t.lastIndexOf(',');
        char? dec = null, thou = null;
        if (lastDot >= 0 && lastComma >= 0) { dec = lastDot > lastComma ? '.' : ','; thou = dec == '.' ? ',' : '.'; }
        else if (lastDot >= 0 || lastComma >= 0) {
            char sep = lastDot >= 0 ? '.' : ',';
            string[] parts = t.Split(sep);
            bool groupLike = parts.Length > 2 || parts[parts.Length - 1].Length == 3;
            if (!groupLike) dec = sep;
            else if (parts.Length > 2) thou = sep;
            else if (locale != null && !locale.isEmpty()) { if (locale.equals("en") == (sep == ',')) thou = sep; else dec = sep; }
            else return amountFail("ambiguous separator");
        }
        string intPart = t, frac = "";
        if (dec != null) { int i = t.lastIndexOf(dec.Value); intPart = t.substring(0, i); frac = t.substring(i + 1); }
        if (thou != null) {
            string[] groups = intPart.Split(thou.Value);
            bool badGroup = false;
            for (int i = 1; i < groups.Length; i++) if (groups[i].Length != 3) badGroup = true;
            if (badGroup || groups[0].Length == 0 || groups[0].Length > 3) return amountFail("malformed grouping");
            intPart = string.Join("", groups);
        }
        if (frac.Length > exponent) return amountFail("more decimals than the currency allows");
        System.Text.StringBuilder sb = new System.Text.StringBuilder(intPart).Append(frac);
        for (int i = frac.Length; i < exponent; i++) sb.Append('0');
        string digits = sb.ToString();
        if (!DIGITS.IsMatch(digits)) return amountFail("out of range");
        BigInteger v = BigInteger.Parse(digits);
        if (v > G.MAX_SAFE) return amountFail("out of range");
        return G.map("ok", true, "minor", G.num((long)v));
    }

    private const string JSWS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
    private static readonly System.Text.RegularExpressions.Regex LEAD_SYMBOL = new System.Text.RegularExpressions.Regex("^[$€£]" + JSWS + "*");

    /**
     * The strict front-end contract over {@link #parseHumanAmount}: {minor} | {hole: "AMBIGUOUS_NUMBER"} | {error: "BAD_NUMBER"}.
     * Only digits, '.' and ',' after one optional leading currency symbol; a decimal separator that contradicts the locale is refused.
     */
    public static D ParseMoney(string text, int exponent, string locale) {
        string t = LEAD_SYMBOL.Replace(G.jsTrim(text), "", 1);
        if (!AMOUNT.IsMatch(t)) return G.map("error", "BAD_NUMBER");
        bool both = t.indexOf('.') >= 0 && t.indexOf(',') >= 0;
        if (locale != null && both && t[Math.Max(t.lastIndexOf('.'), t.lastIndexOf(','))] != (locale.equals("en") ? '.' : ',')) return G.map("error", "BAD_NUMBER");
        if (locale == null && !both && count(t, '.') + count(t, ',') > 1) return G.map("hole", "AMBIGUOUS_NUMBER");
        D r = ParseHumanAmount(t, exponent, locale);
        if (r.get("ok") is true) return G.map("minor", r.get("minor"));
        return "ambiguous separator".equals(r.get("reason")) ? G.map("hole", "AMBIGUOUS_NUMBER") : G.map("error", "BAD_NUMBER");
    }
}
