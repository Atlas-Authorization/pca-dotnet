using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * Trait selectors and role-addressed parameters for the Goal IR. A selector goal (SelGoal) names a verb selector (a verb, or a class: every
 * verb of the pinned catalog with all of the traits and none of the excluded ones) in its grants, may select by trait in prohibitions and
 * bounds, and may name a parameter by ROLE. {@link #expandSelGoal} lowers it, against the PINNED catalog, to an ordinary Goal (one grant per
 * verb, each with that verb's own parameter path); the proved core compiler then does the rest.
 *
 * <p>Fail-closed: a grant verb with no unique parameter of a role the condition names is DROPPED (reported); a prohibition whose role term
 * is unresolved for a verb applies to that verb UNCONDITIONALLY; a bound whose role-addressed value cannot be resolved for every selected
 * verb is a type error; an allow selector is positive (no {@code none_of}, at least one trait); an UNCONFIRMED verb carries the marker
 * {@code pca.unreviewed}: a class ALLOW never covers it, a class PROHIBITION or a bound over a trait selector ALWAYS covers it; an unknown
 * trait id is a type error. A catalog is {known, verbs: [{verb, traits, roles}]}.
 */
public static class GoalSelectors {

    /** The marker trait every unconfirmed verb carries. */
    public const string UNREVIEWED = "pca.unreviewed";
    /** Ids are {@code [0-9A-Za-z_]}: the expanded id {@code <gid>.<verb>} then sorts exactly as (gid, verb). */
    public static readonly System.Text.RegularExpressions.Regex SEL_ID_RE = new System.Text.RegularExpressions.Regex(@"^[0-9A-Za-z_]{1,64}\z");

    private static D mm(object? o) { return G.m(o); }

    private static L list(object? o) { return G.arr(o, ""); }

    private static bool has(L xs, object? x) { return xs.contains(x); }

    // ---------------- the pinned catalog ----------------

    /**
     * The catalog of a pack of action defs (verb ids and parameter paths are the defs' own). {@code reg} null: the core registry;
     * {@code pins} (the review pins) may be null.
     */
    public static D SelCatalogOfDefs(L defs, Dictionary<string, D> reg, D pins) {
        Dictionary<string, D> r = reg != null ? reg : Actions.CoreRegistry;
        L verbs = new();
        foreach (object? dO in defs) {
            D d = mm(dO);
            D prm = mm(d.get("params"));
            List<string> names = new(prm.keySet());
            names.sort(string.CompareOrdinal);
            D roles = new();
            foreach (string name in names) {
                object? role = G.get(prm.get(name), "role");
                if (role != null) {
                    string rk = G.jsStr(role);
                    if (!roles.TryGetValue(rk, out var rv)) roles[rk] = rv = new L();
                    ((L)rv!).add(name);
                }
            }
            verbs.add(G.map("verb", d.get("verb"), "traits", new L(list(Actions.Effective(d, r, pins).get("closure"))), "roles", roles));
        }
        verbs.sort((a, b) => G.cmp((string) G.get(a, "verb"), (string) G.get(b, "verb")));
        return G.map("known", SortedKeys(r), "verbs", verbs);
    }

    /** The catalog of a shipped domain ontology (core registry, no review pins); null for an unknown domain. */
    static L SortedKeys(Dictionary<string, D> r) { var ks = new List<string>(r.Keys); ks.Sort(string.CompareOrdinal); return new L(ks); }

    public static D SelCatalogOfDomain(string domain) { return GoalOntologies.SelCatalog(domain); }

    /** Digest of the catalog (what {@code catDigest} of a SelGoal must equal). */
    public static string SelCatalogDigest(D c) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-sel-catalog/v1", "catalog", c)); }

    /** Digest of the whole signed selector goal. */
    public static string SelGoalDigest(D g) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-ir-sel/v1", "goal", g)); }

    // ---------------- the verbs of a class selector ----------------

    private static bool hasAll(L ts, L req) { foreach (object? t in req) if (!ts.contains(t)) return false; return true; }

    private static bool hasNone(L ts, L ex) { foreach (object? t in ex) if (ts.contains(t)) return false; return true; }

    /** The verbs of the catalog, in catalog order, whose trait closure contains every {@code allOf} trait and none of the {@code noneOf} traits. */
    public static L ClassVerbs(D cat, L allOf, L noneOf) {
        L outp = new();
        foreach (object? vo in list(cat.get("verbs"))) {
            D v = mm(vo);
            L ts = list(v.get("traits"));
            if (hasAll(ts, allOf) && hasNone(ts, noneOf)) outp.add(v.get("verb"));
        }
        return outp;
    }

    /** The verbs a class ALLOW covers: the class, minus every unconfirmed verb. */
    public static L AllowClassVerbs(D cat, L allOf, L noneOf) {
        L none = new(noneOf);
        none.add(UNREVIEWED);
        return ClassVerbs(cat, allOf, none);
    }

    /** The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says. */
    public static L FloatClassVerbs(D cat, L allOf, L noneOf) {
        L outp = new();
        foreach (object? vo in list(cat.get("verbs"))) {
            D v = mm(vo);
            L ts = list(v.get("traits"));
            if (ts.contains(UNREVIEWED) || (hasAll(ts, allOf) && hasNone(ts, noneOf))) outp.add(v.get("verb"));
        }
        return outp;
    }

    // ---------------- role resolution ----------------

    private static D declOf(D ont, object? verb) {
        foreach (object? v in list(ont.get("verbs"))) if (object.Equals(G.get(v, "verb"), verb)) return mm(v);
        return null;
    }

    private static D infoOf(D cat, object? verb) {
        foreach (object? v in list(cat.get("verbs"))) if (object.Equals(G.get(v, "verb"), verb)) return mm(v);
        return null;
    }

    /** The one parameter of {@code verb} carrying {@code role}, as {path, ty}; none, several or undeclared: null. */
    public static D ResolveRole(D ont, D cat, string verb, string role) {
        D info = infoOf(cat, verb);
        D decl = declOf(ont, verb);
        if (info == null || decl == null) return null;
        D roles = mm(info.get("roles"));
        L paths = roles.containsKey(role) ? list(roles.get(role)) : new L();
        if (paths.size() != 1) return null;
        foreach (object? p in list(decl.get("params"))) if (object.Equals(G.get(p, "path"), paths.get(0))) return G.map("path", G.get(p, "path"), "ty", G.get(p, "ty"));
        return null;
    }

    private static D resolveTerm(D ont, D cat, string verb, D t) {
        switch (G.kind(t)) {
            case "param": return G.map("k", "param", "path", t.get("path"), "ty", t.get("ty"));
            case "lit": return G.map("k", "lit", "v", t.get("v"));
            case "hist": return G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u"));
            case "role": { D r = ResolveRole(ont, cat, verb, G.jsStr(t.get("role"))); return r == null ? null : G.map("k", "param", "path", r.get("path"), "ty", r.get("ty")); }
            default: return null;
        }
    }

    /** null as soon as one role term is unresolved for the verb. */
    private static D resolveCond(D ont, D cat, string verb, D c) {
        string k = G.kind(c);
        switch (k) {
            case "true": return G.map("k", "true");
            case "cmp": {
                D l = resolveTerm(ont, cat, verb, mm(c.get("l")));
                D r = resolveTerm(ont, cat, verb, mm(c.get("r")));
                return l != null && r != null ? G.map("k", "cmp", "op", c.get("op"), "l", l, "r", r) : null;
            }
            case "and": case "or": {
                D a = resolveCond(ont, cat, verb, mm(c.get("a")));
                D b = resolveCond(ont, cat, verb, mm(c.get("b")));
                return a != null && b != null ? G.map("k", k, "a", a, "b", b) : null;
            }
            case "not": { D a = resolveCond(ont, cat, verb, mm(c.get("c"))); return a != null ? G.map("k", "not", "c", a) : null; }
            default: return null;
        }
    }

    // ---------------- the expansion ----------------

    /** An expanded grant with the source grant id it came from. */
    private sealed class EG {
        internal object? src;
        internal D g;

        internal EG(object? src, D g) { this.src = src; this.g = g; }
    }

    private static L grantVerbs(D cat, D s) {
        return "verb".equals(G.kind(s)) ? G.list(s.get("verb")) : AllowClassVerbs(cat, list(s.get("all_of")), list(s.get("none_of")));
    }

    private static List<EG> expandGrants(D ont, D cat, L gs, L report) {
        List<EG> outp = new();
        foreach (object? gro in gs) {
            D gr = mm(gro);
            D sel = mm(gr.get("sel"));
            L verbs = grantVerbs(cat, sel);
            L dropped = new();
            foreach (object? vo in verbs) {
                string v = (string) vo;
                D c = resolveCond(ont, cat, v, mm(gr.get("cond")));
                if (c == null) { dropped.add(G.map("verb", v, "reason", "role_unresolved")); continue; }
                string gid = "class".equals(G.kind(sel)) ? G.jsStr(gr.get("gid")) + "." + v : G.jsStr(gr.get("gid"));
                outp.add(new EG(gr.get("gid"), G.map("gid", gid, "verb", v, "res", gr.get("res"), "cond", c)));
            }
            if (report != null) report.add(G.map("gid", gr.get("gid"), "verbs", verbs, "dropped", dropped));
        }
        return outp;
    }

    private static L prohVerbs(D ont, D cat, D t) {
        string k = G.kind(t);
        L outp = new();
        if (k.equals("verb")) outp.add(t.get("verb"));
        else if (k.equals("effect")) { foreach (object? v in list(ont.get("verbs"))) if (object.Equals(G.get(v, "cls"), t.get("cls"))) outp.add(G.get(v, "verb")); }
        else outp = FloatClassVerbs(cat, list(t.get("all_of")), list(t.get("none_of")));
        return outp;
    }

    private static L expandProhibits(D ont, D cat, L ps, L report) {
        L outp = new();
        foreach (object? po in ps) {
            D p = mm(po);
            D target = mm(p.get("target"));
            L verbs = prohVerbs(ont, cat, target);
            L unconditional = new();
            foreach (object? vo in verbs) {
                string v = (string) vo;
                D c = resolveCond(ont, cat, v, mm(p.get("cond")));
                if (c == null) unconditional.add(v);
                outp.add(G.map("pid", "verb".equals(G.kind(target)) ? p.get("pid") : G.jsStr(p.get("pid")) + "." + v, "target", G.map("k", "verb", "verb", v), "res", p.get("res"), "cond", c != null ? c : G.map("k", "true")));
            }
            if (report != null) report.add(G.map("pid", p.get("pid"), "verbs", verbs, "unconditional", unconditional));
        }
        return outp;
    }

    private static L idsOf(List<EG> es, L srcs) { L r = new(); foreach (EG e in es) if (srcs.contains(e.src)) r.add(e.g.get("gid")); return r; }

    private static L gidsOfVerbs(List<EG> es, L vs) { L r = new(); foreach (EG e in es) if (vs.contains(e.g.get("verb"))) r.add(e.g.get("gid")); return r; }

    private static L verbsOfGids(List<EG> es, L gids) { L r = new(); foreach (EG e in es) if (gids.contains(e.g.get("gid"))) r.add(e.g.get("verb")); return r; }

    /** The verbs a bound's role-addressed value must resolve for. */
    private static L boundRoleVerbs(D ont, D cat, List<EG> es, D s) {
        string k = G.kind(s);
        if (k.equals("gids")) return verbsOfGids(es, idsOf(es, list(s.get("gids"))));
        if (k.equals("effect")) { L r = new(); foreach (object? v in list(ont.get("verbs"))) if (object.Equals(G.get(v, "cls"), s.get("cls"))) r.add(G.get(v, "verb")); return r; }
        if (k.equals("trait")) return verbsOfGids(es, gidsOfVerbs(es, FloatClassVerbs(cat, list(s.get("all_of")), list(s.get("none_of")))));
        return new();
    }

    /** One value term for the whole bound: the shared path when every verb agrees; the role key {@code @<role>} when the paths differ but the type is one. {term, how} or null. */
    private static D boundValue(D ont, D cat, L vs, D t) {
        switch (G.kind(t)) {
            case "param": return G.map("term", G.map("k", "param", "path", t.get("path"), "ty", t.get("ty")), "how", "literal");
            case "lit": return G.map("term", G.map("k", "lit", "v", t.get("v")), "how", "literal");
            case "hist": return G.map("term", G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u")), "how", "literal");
            case "role": {
                List<D> rs = new();
                foreach (object? v in vs) { D r = ResolveRole(ont, cat, (string) v, G.jsStr(t.get("role"))); if (r == null) return null; rs.add(r); }
                if (rs.isEmpty()) return null;
                bool samePath = true, sameTy = true;
                string ty0 = G.stringify(rs.get(0).get("ty"));
                foreach (D r in rs) {
                    if (!object.Equals(r.get("path"), rs.get(0).get("path"))) samePath = false;
                    if (!G.stringify(r.get("ty")).equals(ty0)) sameTy = false;
                }
                if (samePath && sameTy) return G.map("term", G.map("k", "param", "path", rs.get(0).get("path"), "ty", rs.get(0).get("ty")), "how", "shared_path");
                if (sameTy) return G.map("term", G.map("k", "param", "path", "@" + G.jsStr(t.get("role")), "ty", rs.get(0).get("ty")), "how", "role_key");
                return null;
            }
            default: return null;
        }
    }

    private static L expandBounds(D ont, D cat, List<EG> es, L bs, L report) {
        L outp = new();
        foreach (object? bo in bs) {
            D b = mm(bo);
            D sel = mm(b.get("sel"));
            D bv = boundValue(ont, cat, boundRoleVerbs(ont, cat, es, sel), mm(b.get("value")));
            if (bv == null) continue; // a type error (selReasons), never reached when the goal is well typed
            string k = G.kind(sel);
            L gids = null;
            if (k.equals("gids")) gids = idsOf(es, list(sel.get("gids")));
            else if (k.equals("trait")) gids = gidsOfVerbs(es, FloatClassVerbs(cat, list(sel.get("all_of")), list(sel.get("none_of"))));
            if (k.equals("effect")) {
                outp.add(mkBound(b, bv, G.map("k", "effect", "cls", sel.get("cls"))));
                if (report != null) report.add(G.map("bid", b.get("bid"), "gids", new L(), "dropped", false, "value", bv.get("how")));
                continue;
            }
            if (gids == null || gids.isEmpty()) {
                if (gids == null) throw new IrError("unknown bound selector");
                if (report != null) report.add(G.map("bid", b.get("bid"), "gids", new L(), "dropped", true, "value", bv.get("how")));
                continue;
            }
            outp.add(mkBound(b, bv, G.map("k", "gids", "gids", gids)));
            if (report != null) report.add(G.map("bid", b.get("bid"), "gids", gids, "dropped", false, "value", bv.get("how")));
        }
        return outp;
    }

    private static D mkBound(D b, D bv, D sel) {
        return G.map("bid", b.get("bid"), "sel", sel, "agg", b.get("agg"), "value", bv.get("term"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed"));
    }

    /** Lower a selector goal to an ordinary Goal against the PINNED catalog: {goal, report}. Pure and total; typing is {@link #selReasons} plus the core typechecker. */
    public static D ExpandSelGoal(D sg, D ont, D cat) {
        L gReport = new(), pReport = new(), bReport = new();
        List<EG> es = expandGrants(ont, cat, list(sg.get("grants")), gReport);
        L prohibits = expandProhibits(ont, cat, list(sg.get("prohibits")), pReport);
        L bounds = expandBounds(ont, cat, es, list(sg.get("bounds")), bReport);
        L grants = new();
        foreach (EG e in es) grants.add(e.g);
        D deleg = new(mm(sg.get("deleg")));
        deleg.put("mayTouch", idsOf(es, list(deleg.get("mayTouch"))));
        L holes = new();
        foreach (object? ho in list(sg.get("holes"))) { D h = new(mm(ho)); h.put("affects", idsOf(es, list(h.get("affects")))); holes.add(h); }
        D goal = G.map("v", G.num(1), "principal", sg.get("principal"), "ontDigest", sg.get("ontDigest"), "nlDigest", sg.get("nlDigest"), "sources", sg.get("sources"),
            "grants", grants, "prohibits", prohibits, "bounds", bounds, "validity", sg.get("validity"), "deleg", deleg, "escalateOn", sg.get("escalateOn"),
            "wildcardAck", idsOf(es, list(sg.get("wildcardAck"))), "holes", holes);
        return G.map("goal", goal, "report", G.map("grants", gReport, "prohibits", pReport, "bounds", bReport));
    }

    // ---------------- typing of the selector layer ----------------

    private static bool allKnown(L known, L ids) {
        foreach (object? i in ids) if (!(i is string) || ((string) i).isEmpty() || !known.contains(i)) return false;
        return true;
    }

    private static bool grantSelOk(D cat, D g) {
        D s = mm(g.get("sel"));
        return "verb".equals(G.kind(s)) || (!list(s.get("all_of")).isEmpty() && list(s.get("none_of")).isEmpty() && allKnown(list(cat.get("known")), list(s.get("all_of"))));
    }

    private static bool prohSelOk(D cat, D p) {
        D t = mm(p.get("target"));
        return !"trait".equals(G.kind(t)) || (allKnown(list(cat.get("known")), list(t.get("all_of"))) && allKnown(list(cat.get("known")), list(t.get("none_of"))));
    }

    private static bool boundSelOk(D cat, L gs, D b) {
        D s = mm(b.get("sel"));
        string k = G.kind(s);
        if (k.equals("gids")) { foreach (object? i in list(s.get("gids"))) { bool found = false; foreach (object? g in gs) if (object.Equals(G.get(g, "gid"), i)) found = true; if (!found) return false; } return true; }
        if (k.equals("effect")) return true;
        return allKnown(list(cat.get("known")), list(s.get("all_of"))) && allKnown(list(cat.get("known")), list(s.get("none_of")));
    }

    /**
     * The type reasons of the selector layer, in the order of the formal model, preceded by the checks about the wire rather than the
     * semantics: the pin ({@code catalog_digest_mismatch}) and the id grammar ({@code bad_id}). An empty list is well typed at this layer.
     */
    public static L SelReasons(D sg, D ont, D cat) {
        L outp = new();
        if (!object.Equals(sg.get("catDigest"), SelCatalogDigest(cat))) outp.add("catalog_digest_mismatch");
        L ids = new();
        foreach (object? g in list(sg.get("grants"))) ids.add(G.get(g, "gid"));
        foreach (object? p in list(sg.get("prohibits"))) ids.add(G.get(p, "pid"));
        foreach (object? b in list(sg.get("bounds"))) ids.add(G.get(b, "bid"));
        bool idsOk = true;
        foreach (object? i in ids) if (!(i is string) || !SEL_ID_RE.IsMatch((string)i)) idsOk = false;
        if (!idsOk) outp.add("bad_id");
        bool catOk = true;
        foreach (object? v in list(cat.get("verbs"))) if (declOf(ont, G.get(v, "verb")) == null) catOk = false;
        if (!catOk) outp.add("catalog_mismatch");
        bool g1 = true, p1 = true, b1 = true;
        foreach (object? g in list(sg.get("grants"))) if (!grantSelOk(cat, mm(g))) g1 = false;
        if (!g1) outp.add("bad_grant_selector");
        foreach (object? p in list(sg.get("prohibits"))) if (!prohSelOk(cat, mm(p))) p1 = false;
        if (!p1) outp.add("bad_prohibit_selector");
        foreach (object? b in list(sg.get("bounds"))) if (!boundSelOk(cat, list(sg.get("grants")), mm(b))) b1 = false;
        if (!b1) outp.add("bad_bound_selector");
        List<EG> es = expandGrants(ont, cat, list(sg.get("grants")), null);
        bool rb = true;
        foreach (object? b in list(sg.get("bounds"))) if (boundValue(ont, cat, boundRoleVerbs(ont, cat, es, mm(mm(b).get("sel"))), mm(mm(b).get("value"))) == null) rb = false;
        if (!rb) outp.add("unresolved_role_bound");
        return outp;
    }

    /**
     * CompileX: selector reasons first (fail closed), then expansion and the core compiler. {@code compileGoal} is the injected proved
     * compiler (goal, ontology) -&gt; {ok: true, policy} | {ok: false, reasons}; it is not carried natively. Returns {ok, policy, goal, report} or {ok: false, reasons}.
     */
    public static D CompileSelGoal(D sg, D ont, D cat, Func<D, D, D> compileGoal) {
        L rs = SelReasons(sg, ont, cat);
        if (!rs.isEmpty()) return G.map("ok", false, "reasons", rs);
        D ex = ExpandSelGoal(sg, ont, cat);
        D goal = mm(ex.get("goal"));
        D c = compileGoal(goal, ont);
        return c.get("ok") is true ? G.map("ok", true, "policy", c.get("policy"), "goal", goal, "report", ex.get("report")) : G.map("ok", false, "reasons", c.get("reasons"));
    }

    // ---------------- acts ----------------

    /**
     * Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
     * supplies, {@code @<role>} is that parameter's value. Any {@code @} key the caller sent is removed first.
     */
    public static D WithRoleParams(D act, D cat) {
        D prm = new();
        foreach (KeyValuePair<string, object?> e in mm(act.get("params"))) if (!e.Key.startsWith("@")) prm.put(e.Key, e.Value);
        D info = infoOf(cat, act.get("verb"));
        if (info != null) {
            foreach (KeyValuePair<string, object?> e in mm(info.get("roles"))) {
                L paths = list(e.Value);
                if (paths.size() == 1 && prm.containsKey(G.jsStr(paths.get(0)))) prm.put("@" + e.Key, prm.get(G.jsStr(paths.get(0))));
            }
        }
        D r = new(act);
        r.put("params", prm);
        return r;
    }

    // ---------------- the policy card ----------------

    private static string phrase(Dictionary<string, D> reg, object? id) {
        D? t = id is string s && reg.TryGetValue(s, out var tv) ? tv : null;
        return t != null && t.get("card_phrase") is string cp ? cp : G.jsStr(id);
    }

    private static string selectorText(L all, L none, Dictionary<string, D> reg) {
        List<string> ap = new();
        foreach (object? x in all) ap.add(phrase(reg, x));
        string a = !all.isEmpty() ? "every action that " + string.Join(" and ", ap) : "every action";
        if (none.isEmpty()) return a;
        List<string> np = new();
        foreach (object? x in none) np.add(phrase(reg, x));
        return a + ", except those that " + string.Join(" or ", np);
    }

    private static string qs(object? s) { return G.q(G.jsStr(s)); }

    private static string qlist(L xs) { List<string> o = new(); foreach (object? x in xs) o.add(qs(x)); return string.Join(", ", o); }

    /** The card of a selector goal: one line per selector clause in the words of the trait phrases, then the card of the expansion. {@code reg} null: the core registry. {lines, warnings}. */
    public static D RenderSelCard(D sg, D ont, D cat, Dictionary<string, D> reg) {
        Dictionary<string, D> rg = reg != null ? reg : Actions.CoreRegistry;
        D ex = ExpandSelGoal(sg, ont, cat);
        D report = mm(ex.get("report"));
        L lines = new(), warnings = new();
        L grants = list(sg.get("grants"));
        for (int i = 0; i < grants.size(); i++) {
            D g = mm(grants.get(i));
            D r = mm(list(report.get("grants")).get(i));
            D sel = mm(g.get("sel"));
            L verbs = list(r.get("verbs"));
            if ("class".equals(G.kind(sel))) lines.add("ALLOW " + qs(g.get("gid")) + ": " + selectorText(list(sel.get("all_of")), new(), rg) + " [" + verbs.size() + " verb(s) in the pinned catalog: " + qlist(verbs) + "]");
            foreach (object? d in list(r.get("dropped"))) warnings.add("grant " + qs(g.get("gid")) + " does not cover " + qs(G.get(d, "verb")) + ": it has no unique parameter for a role the condition names");
        }
        L prohibits = list(sg.get("prohibits"));
        for (int i = 0; i < prohibits.size(); i++) {
            D p = mm(prohibits.get(i));
            D r = mm(list(report.get("prohibits")).get(i));
            D t = mm(p.get("target"));
            L verbs = list(r.get("verbs"));
            if ("trait".equals(G.kind(t))) lines.add("NEVER " + qs(p.get("pid")) + ": " + selectorText(list(t.get("all_of")), list(t.get("none_of")), rg) + ", today " + verbs.size() + " verb(s) [" + qlist(verbs) + "]; it also covers every verb added to the catalog later");
            foreach (object? v in list(r.get("unconditional"))) warnings.add("prohibition " + qs(p.get("pid")) + " applies to " + qs(v) + " without its condition: the verb has no unique parameter for a role the condition names");
        }
        L bounds = list(sg.get("bounds"));
        L breports = list(report.get("bounds"));
        for (int i = 0; i < bounds.size(); i++) {
            D b = mm(bounds.get(i));
            D r = i < breports.size() ? mm(breports.get(i)) : null;
            D sel = mm(b.get("sel"));
            if ("trait".equals(G.kind(sel)) && r != null) lines.add("LIMIT " + qs(b.get("bid")) + ": over " + selectorText(list(sel.get("all_of")), list(sel.get("none_of")), rg) + " (" + list(r.get("gids")).size() + " grant(s))");
            if (r != null && r.get("dropped") is true) warnings.add("limit " + qs(b.get("bid")) + " selects no grant and bounds nothing");
            if (r != null && "role_key".equals(r.get("value"))) warnings.add("limit " + qs(b.get("bid")) + " sums a role the verbs carry on different parameters: the action must supply the role key");
        }
        D core = GoalCard.RenderCard(mm(ex.get("goal")));
        L l2 = new(lines); l2.addAll(list(core.get("lines")));
        L w2 = new(warnings); w2.addAll(list(core.get("warnings")));
        return G.map("lines", l2, "warnings", w2);
    }

    /** The closure of a trait id list under the registry (a selector written with a parent trait covers the children by {@code implies}). {@code reg} null: core. */
    public static List<string> TraitClosure(L ids, Dictionary<string, D> reg) { return Actions.Closure(reg != null ? reg : Actions.CoreRegistry, ids); }

    // ---------------- the carrier form (the differential with the extracted model) ----------------

    private const string ROLE_MARK = "\u0001role:";

    private static D carryTerm(D t) {
        switch (G.kind(t)) {
            case "role": return G.map("k", "param", "path", ROLE_MARK + G.jsStr(t.get("role")), "ty", G.map("k", "s"));
            case "param": return G.map("k", "param", "path", t.get("path"), "ty", t.get("ty"));
            case "lit": return G.map("k", "lit", "v", t.get("v"));
            default: return G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u"));
        }
    }

    private static D carryCond(D c) {
        string k = G.kind(c);
        switch (k) {
            case "true": return G.map("k", "true");
            case "cmp": return G.map("k", "cmp", "op", c.get("op"), "l", carryTerm(mm(c.get("l"))), "r", carryTerm(mm(c.get("r"))));
            case "and": case "or": return G.map("k", k, "a", carryCond(mm(c.get("a"))), "b", carryCond(mm(c.get("b"))));
            case "not": return G.map("k", "not", "c", carryCond(mm(c.get("c"))));
            default: throw new IrError("unknown condition");
        }
    }

    private static string join(L xs, string sep) { List<string> o = new(); foreach (object? x in xs) o.add(x == null ? "" : G.jsStr(x)); return string.Join(sep, o); }

    private static string sel2(L all, L none) { return join(all, "\u0002") + "\u0001" + join(none, "\u0002"); }

    /** An ordinary Goal carrying a selector goal (selectors ride in strings and role-marked prm), so the extracted model decodes it with its existing Goal decoder. */
    public static D SelCarrier(D sg) {
        L grants = new();
        foreach (object? go in list(sg.get("grants"))) {
            D g = mm(go);
            D s = mm(g.get("sel"));
            string verb = "verb".equals(G.kind(s)) ? "V\u0001" + G.jsStr(s.get("verb")) : "C\u0001" + sel2(list(s.get("all_of")), list(s.get("none_of")));
            grants.add(G.map("gid", g.get("gid"), "verb", verb, "res", g.get("res"), "cond", carryCond(mm(g.get("cond")))));
        }
        L prohibits = new();
        foreach (object? po in list(sg.get("prohibits"))) {
            D p = mm(po);
            D t = mm(p.get("target"));
            string k = G.kind(t);
            string verb = k.equals("verb") ? "V\u0001" + G.jsStr(t.get("verb")) : k.equals("effect") ? "E\u0001" + G.jsStr(t.get("cls")) : "T\u0001" + sel2(list(t.get("all_of")), list(t.get("none_of")));
            prohibits.add(G.map("pid", p.get("pid"), "res", p.get("res"), "cond", carryCond(mm(p.get("cond"))), "target", G.map("k", "verb", "verb", verb)));
        }
        L bounds = new();
        foreach (object? bo in list(sg.get("bounds"))) {
            D b = mm(bo);
            D s = mm(b.get("sel"));
            string k = G.kind(s);
            D sel = k.equals("gids") ? G.map("k", "gids", "gids", s.get("gids")) : k.equals("effect") ? G.map("k", "effect", "cls", s.get("cls"))
                : G.map("k", "effect", "cls", "T\u0001" + sel2(list(s.get("all_of")), list(s.get("none_of"))));
            bounds.add(G.map("bid", b.get("bid"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed"), "agg", b.get("agg"),
                "value", carryTerm(mm(b.get("value"))), "sel", sel));
        }
        return G.map("v", G.num(1), "principal", sg.get("principal"), "ontDigest", sg.get("ontDigest"), "nlDigest", sg.get("nlDigest"), "sources", sg.get("sources"),
            "grants", grants, "prohibits", prohibits, "bounds", bounds, "validity", sg.get("validity"), "deleg", sg.get("deleg"), "escalateOn", sg.get("escalateOn"), "wildcardAck", sg.get("wildcardAck"), "holes", sg.get("holes"));
    }

    private static L tok(string t, object? v) { L x = new(2); x.add(t); x.add(v); return x; }

    private static void strs(L outp, L xs) {
        outp.add(tok("i", G.num(xs.size())));
        foreach (object? x in xs) outp.add(tok("s", x));
    }

    /** The catalog tape {@code DecCatalog} reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*. */
    public static L EncodeSelCatalog(D c) {
        L outp = new();
        strs(outp, list(c.get("known")));
        L verbs = list(c.get("verbs"));
        outp.add(tok("i", G.num(verbs.size())));
        foreach (object? vo in verbs) {
            D v = mm(vo);
            outp.add(tok("s", v.get("verb")));
            strs(outp, list(v.get("traits")));
            D roles = mm(v.get("roles"));
            outp.add(tok("i", G.num(roles.size())));
            foreach (KeyValuePair<string, object?> e in roles) { outp.add(tok("s", e.Key)); strs(outp, list(e.Value)); }
        }
        return outp;
    }
}
