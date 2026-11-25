using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * An independent reading of the goal semantics D_G for the grammar the tests generate (conditions, grants, prohibitions, count /
 * sum / max / distinct bounds, validity, delegation). Three-valued: 0 false/deny, 1 unknown/escalate, 2 true/allow. Numbers are
 * JavaScript doubles, as in the reference.
 */
public static class GoalRefsem {

    private static int and_(int a, int b) { return Math.Min(a, b); }
    private static int or_(int a, int b) { return Math.Max(a, b); }
    private static int not_(int a) { return 2 - a; }
    private static int b2t(bool b) { return b ? 2 : 0; }
    private static bool sameUnit(object? a, object? b) { return G.stringify(a).equals(G.stringify(b)); }

    private static double n(object? o) { return G.toNum(o); }

    /** JavaScript {@code ===} on two parsed JSON scalars. */
    private static bool seq(object? a, object? b) {
        double? x = G.strictNum(a), y = G.strictNum(b);
        if (x != null || y != null) return x != null && y != null && x.Value == y.Value;
        return object.Equals(a, b);
    }

    private static D val(D t, D a, D h) {
        string k = G.kind(t);
        if (k.equals("param")) {
            D ps = G.m(a.get("params"));
            if (a.get("params") == null) throw new IrError("params expected");
            return ps != null && ps.containsKey(t.get("path")) ? G.m(ps.get(t.get("path"))) : null;
        }
        if (k.equals("lit")) return G.m(t.get("v"));
        D aggs = G.m(h.get("aggs"));
        return aggs != null && aggs.containsKey(t.get("bid")) ? G.map("k", "q", "q", aggs.get(t.get("bid"))) : null;
    }

    // v.q.n / v.q.u: a number, string or array has no such member (undefined); null or undefined is a TypeError
    private static object? qm(D v, string k) {
        var q = v.get("q");
        if (q == null) throw new IrError("cannot read properties of null (reading '" + k + "')");
        return q is D d ? d.get(k) : null;
    }
    private static object? qn(D v) { return qm(v, "n"); }
    private static object? qu(D v) { return qm(v, "u"); }

    private static int eq(D x, D y) {
        string kx = G.kind(x), ky = G.kind(y);
        if (kx.equals("q") && ky.equals("q")) return sameUnit(qu(x), qu(y)) ? b2t(seq(qn(x), qn(y))) : 1;
        if (kx.equals("s") && ky.equals("s")) return b2t(seq(x.get("s"), y.get("s")));
        return 1;
    }

    private static int lt(D x, D y) {
        return G.kind(x).equals("q") && G.kind(y).equals("q") && sameUnit(qu(x), qu(y)) ? b2t(n(qn(x)) < n(qn(y))) : 1;
    }

    private static int inSet(D x, D y) {
        if (!G.kind(y).equals("set")) return 1;
        int acc = 0;
        foreach (object? it in G.arr(y.get("items"), "items")) acc = or_(acc, eq(x, G.m(it)));
        return acc;
    }

    private static int cmp(string op, D x, D y) {
        if (x == null || y == null) return 1;
        switch (op) {
            case "eq": return eq(x, y);
            case "ne": return not_(eq(x, y));
            case "lt": return lt(x, y);
            case "gte": return not_(lt(x, y));
            case "gt": return lt(y, x);
            case "lte": return not_(lt(y, x));
            case "in": return inSet(x, y);
            default: return not_(inSet(x, y));
        }
    }

    private static int evalC(D c, D a, D h) {
        switch (G.kind(c)) {
            case "true": return 2;
            case "cmp": return cmp(G.jsStr(c.get("op")), val(G.m(c.get("l")), a, h), val(G.m(c.get("r")), a, h));
            case "and": return and_(evalC(G.m(c.get("a")), a, h), evalC(G.m(c.get("b")), a, h));
            case "or": return or_(evalC(G.m(c.get("a")), a, h), evalC(G.m(c.get("b")), a, h));
            case "not": return not_(evalC(G.m(c.get("c")), a, h));
            default: throw new IrError("unknown condition");
        }
    }

    private static bool includes(object? list, object? x) {
        L l = G.l(list);
        if (l == null) return false;
        foreach (object? o in l) if (o != null && o.equals(x)) return true;
        return false;
    }

    private static bool resOk(D s, D ont, object? r) {
        switch (G.kind(s)) {
            case "any": return true;
            case "exact": return seq(r, s.get("id"));
            case "oneof": return includes(s.get("ids"), r);
            case "related":
                foreach (object? x in G.arr(ont.get("rels"), "rels")) {
                    if (s.get("rel") != null && s.get("rel").equals(G.get(x, "rel")) && s.get("anchor") != null && s.get("anchor").equals(G.get(x, "anchor"))) return includes(G.get(x, "members"), r);
                }
                return false;
            case "all_of":
                foreach (object? p in G.arr(s.get("parts"), "parts")) if (!resOk(G.m(p), ont, r)) return false;
                return true;
            default: throw new IrError("unknown selector");
        }
    }

    private static L verbsOf(D ont, object? cls) {
        L outp = new();
        foreach (object? v in G.arr(ont.get("verbs"), "verbs")) if (cls != null && cls.equals(G.get(v, "cls"))) outp.add(G.get(v, "verb"));
        return outp;
    }

    private static bool inScope(D sc, D a, D x) {
        switch (G.kind(sc)) {
            case "session": return object.Equals(a.get("sess"), x.get("sess"));
            case "principal": return object.Equals(a.get("prin"), x.get("prin"));
            case "org": return object.Equals(a.get("org"), x.get("org"));
            case "fleet": return includes(sc.get("agents"), a.get("agent")) && includes(sc.get("agents"), x.get("agent"));
            default: return false;
        }
    }

    private static bool inWin(D w, D a, D x) {
        switch (G.kind(w)) {
            case "task": case "lifetime": return true;
            case "sliding": return n(x.get("t")) > n(a.get("t")) - n(w.get("ms")) && n(x.get("t")) <= n(a.get("t"));
            case "period": {
                double ms = n(w.get("ms"));
                return ms > 0 && Math.Floor((n(a.get("t")) - n(w.get("t0"))) / ms) == Math.Floor((n(x.get("t")) - n(w.get("t0"))) / ms);
            }
            default: return false;
        }
    }

    /** The decision (0 deny, 1 escalate, 2 allow); see {@link #refExplain}. */
    public static int RefDecide(D g, D ont, D a, D h) {
        return int.Parse(((Num)RefExplain(g, ont, a, h).get("d")!).Raw);
    }

    /** {d, witness, prohibit}: witness is the first grant whose own decision is allow (only when d = 2); prohibit is the meet over the prohibitions. */
    public static D RefExplain(D g, D ont, D a, D h) {
        int d = 2, prohibit = 2;
        string witness = null;
        D validity = G.m(g.get("validity")), deleg = G.m(g.get("deleg"));
        double t = n(a.get("t")), depth = n(a.get("depth"));
        if (t < n(validity.get("notBefore")) || t > n(validity.get("notAfter"))) d = Math.Min(d, 0);
        else if (n(validity.get("maxIdle")) > 0 && n(h.get("last")) >= 0 && t - n(h.get("last")) > n(validity.get("maxIdle"))) d = Math.Min(d, 0);
        else if (depth < 0 || depth > n(deleg.get("maxDepth"))) d = Math.Min(d, 0);
        foreach (object? po in G.arr(g.get("prohibits"), "prohibits")) {
            D p = G.m(po), tg = G.m(p.get("target"));
            L verbs;
            if (G.kind(tg).equals("verb")) { verbs = new(); verbs.add(tg.get("verb")); } else verbs = verbsOf(ont, tg.get("cls"));
            int m = and_(b2t(includes(verbs, a.get("verb"))), and_(b2t(resOk(G.m(p.get("res")), ont, a.get("res"))), evalC(G.m(p.get("cond")), a, h)));
            int pd = m == 2 ? 0 : m == 1 ? 1 : 2;
            d = Math.Min(d, pd);
            prohibit = Math.Min(prohibit, pd);
        }
        foreach (object? c in G.arr(g.get("escalateOn"), "escalateOn")) d = Math.Min(d, evalC(G.m(c), a, h) == 0 ? 2 : 1);
        int best = 0;
        foreach (object? gro in G.arr(g.get("grants"), "grants")) {
            D gr = G.m(gro);
            int m = and_(b2t(object.Equals(a.get("verb"), gr.get("verb")) && (seq(a.get("depth"), G.num(0)) || includes(deleg.get("mayTouch"), gr.get("gid")))),
                and_(b2t(resOk(G.m(gr.get("res")), ont, a.get("res"))), evalC(G.m(gr.get("cond")), a, h)));
            int gd = m;
            foreach (object? bo in G.arr(g.get("bounds"), "bounds")) {
                D b = G.m(bo), sel = G.m(b.get("sel"));
                L gids = G.kind(sel).equals("gids") ? G.arr(sel.get("gids"), "gids") : new();
                L verbs = G.kind(sel).equals("effect") ? verbsOf(ont, sel.get("cls")) : new();
                if (!(includes(gids, gr.get("gid")) || includes(verbs, a.get("verb")))) continue;
                List<D> items = new();
                foreach (object? ao in G.arr(h.get("adms"), "adms")) {
                    D x = G.m(G.m(ao).get("act"));
                    if ((includes(gids, G.m(ao).get("gid")) || includes(verbs, x.get("verb"))) && inScope(G.m(b.get("scope")), a, x) && inWin(G.m(b.get("window")), a, x)) items.add(x);
                }
                items.add(a);
                D cap = G.m(b.get("cap"));
                string agg = G.jsStr(b.get("agg"));
                int ex;
                if (agg.equals("count")) ex = b2t(items.size() > n(cap.get("n")));
                else if (agg.equals("sum") || agg.equals("max")) {
                    List<double?> xs = new();
                    bool ok = true;
                    foreach (D it in items) {
                        D v = val(G.m(b.get("value")), it, h);
                        if (v == null || !G.kind(v).equals("q") || !sameUnit(qu(v), cap.get("u"))) { ok = false; break; }
                        xs.add(n(qn(v)));
                    }
                    if (!ok) ex = 1;
                    else if (agg.equals("sum")) { double s = 0; foreach (double x in xs) s += x; ex = b2t(s > n(cap.get("n"))); }
                    else if (xs.isEmpty()) ex = 1;
                    else { double mx = double.NegativeInfinity; foreach (double x in xs) { if (double.IsNaN(x)) { mx = double.NaN; break; } mx = Math.Max(mx, x); } ex = b2t(mx > n(cap.get("n"))); }
                } else {
                    HashSet<string> ks = new();
                    bool ok = true;
                    foreach (D it in items) {
                        D ps = G.m(it.get("params"));
                        if (ps == null || !ps.containsKey(b.get("key"))) { ok = false; break; }
                        ks.add(G.stringify(ps.get(b.get("key"))));
                    }
                    ex = ok ? b2t(ks.size() > n(cap.get("n"))) : 1;
                }
                gd = Math.Min(gd, ex == 2 ? ("deny".equals(b.get("onExceed")) ? 0 : 1) : ex == 1 ? 1 : 2);
            }
            if (gd == 2 && witness == null) witness = (string) gr.get("gid");
            best = Math.Max(best, gd);
        }
        d = Math.Min(d, best);
        return G.map("d", G.num(d), "witness", d == 2 ? witness : null, "prohibit", G.num(prohibit));
    }
}
