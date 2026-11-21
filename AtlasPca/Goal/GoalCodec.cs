using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * The token-tape form of the Goal IR. A tape is a list of tokens; a token is a two-element list {@code ["k", n]} (keyword),
 * {@code ["i", n]} (integer) or {@code ["s", text]}. Encoding is strict: anything that is not exactly an IR value throws
 * {@link IrError}. Goals, ontologies, acts and histories are parsed-JSON maps shaped like the TypeScript IR.
 */
public static class GoalCodec {

    public static readonly List<string> OPS = new() { "eq", "ne", "lt", "lte", "gt", "gte", "in", "nin" };
    public static readonly List<string> AGGS = new() { "count", "sum", "max", "distinct" };

    private static L tok(string t, object? v) { L x = new(2); x.add(t); x.add(v); return x; }
    private static L K(long n) { return tok("k", G.num(n)); }

    private static L I(object? v) {
        long? n = G.safeInt(v);
        if (n == null) throw new IrError(v + " is not a safe integer");
        return tok("i", G.num(n.Value));
    }

    private static L I(long n) { return tok("i", G.num(n)); }

    private static L S(object? s) {
        if (!(s is string)) throw new IrError("string expected");
        return tok("s", s);
    }

    private static IrError bad(string what, object? v) {
        string s;
        try { s = G.stringify(v); } catch (Exception e) { s = G.jsStr(v); }
        return new IrError("unknown " + what + ": " + s);
    }

    private delegate void Enc(L outp, object? x);

    private static void list(L outp, object? xs, Enc f) {
        L a = G.l(xs);
        if (a == null) throw new IrError("array expected");
        outp.add(I(a.size()));
        foreach (object? x in a) f(outp, x);
    }

    private static void strs(L outp, object? xs) { list(outp, xs, (o, s) => o.add(S(s))); }

    private static void unit(L outp, object? u) {
        switch (G.kind(u)) {
            case "money": outp.add(K(300)); outp.add(S(G.get(u, "ccy"))); break;
            case "count": outp.add(K(301)); break;
            case "duration": outp.add(K(302)); break;
            case "instant": outp.add(K(303)); break;
            case "bytes": outp.add(K(304)); break;
            case "ratio": outp.add(K(305)); break;
            default: throw bad("unit", u);
        }
    }

    private static void quantity(L outp, object? q) { unit(outp, G.get(q, "u")); outp.add(I(G.get(q, "n"))); }

    private static void ty(L outp, object? t) {
        string k = G.kind(t);
        if (k.equals("q")) { outp.add(K(310)); unit(outp, G.get(t, "u")); }
        else if (k.equals("s")) outp.add(K(311));
        else throw bad("type", t);
    }

    private static void atom(L outp, object? a) {
        string k = G.kind(a);
        if (k.equals("q")) { outp.add(K(320)); quantity(outp, G.get(a, "q")); }
        else if (k.equals("s")) { outp.add(K(321)); outp.add(S(G.get(a, "s"))); }
        else throw bad("set member (sets hold quantities and strings only)", a);
    }

    private static void value(L outp, object? v) {
        switch (G.kind(v)) {
            case "q": outp.add(K(330)); quantity(outp, G.get(v, "q")); break;
            case "s": outp.add(K(331)); outp.add(S(G.get(v, "s"))); break;
            case "set": outp.add(K(332)); list(outp, G.get(v, "items"), GoalCodec.atom); break;
            default: throw bad("value", v);
        }
    }

    private static void term(L outp, object? t) {
        switch (G.kind(t)) {
            case "param": outp.add(K(340)); outp.add(S(G.get(t, "path"))); ty(outp, G.get(t, "ty")); break;
            case "lit": outp.add(K(341)); value(outp, G.get(t, "v")); break;
            case "hist": outp.add(K(342)); outp.add(S(G.get(t, "bid"))); unit(outp, G.get(t, "u")); break;
            default: throw bad("term", t);
        }
    }

    private static void op(L outp, object? o) {
        int i = o is string ? OPS.indexOf((string)o) : -1;
        if (i < 0) throw bad("operator", o);
        outp.add(K(350 + i));
    }

    private static void cond(L outp, object? c) {
        switch (G.kind(c)) {
            case "true": outp.add(K(360)); break;
            case "cmp": outp.add(K(361)); op(outp, G.get(c, "op")); term(outp, G.get(c, "l")); term(outp, G.get(c, "r")); break;
            case "and": outp.add(K(362)); cond(outp, G.get(c, "a")); cond(outp, G.get(c, "b")); break;
            case "or": outp.add(K(363)); cond(outp, G.get(c, "a")); cond(outp, G.get(c, "b")); break;
            case "not": outp.add(K(364)); cond(outp, G.get(c, "c")); break;
            default: throw bad("condition", c);
        }
    }

    private static void part(L outp, object? s) {
        switch (G.kind(s)) {
            case "exact": outp.add(K(375)); outp.add(S(G.get(s, "id"))); break;
            case "oneof": outp.add(K(376)); strs(outp, G.get(s, "ids")); break;
            case "related": outp.add(K(377)); outp.add(S(G.get(s, "rel"))); outp.add(S(G.get(s, "anchor"))); break;
            default: throw bad("resource part", s);
        }
    }

    private static void res(L outp, object? s) {
        switch (G.kind(s)) {
            case "exact": outp.add(K(370)); outp.add(S(G.get(s, "id"))); break;
            case "oneof": outp.add(K(371)); strs(outp, G.get(s, "ids")); break;
            case "related": outp.add(K(372)); outp.add(S(G.get(s, "rel"))); outp.add(S(G.get(s, "anchor"))); break;
            case "any": outp.add(K(373)); outp.add(S(G.get(s, "reason"))); break;
            case "all_of": outp.add(K(374)); list(outp, G.get(s, "parts"), GoalCodec.part); break;
            default: throw bad("resource selector", s);
        }
    }

    private static void grant(L outp, object? g) {
        outp.add(K(380)); outp.add(S(G.get(g, "gid"))); outp.add(S(G.get(g, "verb"))); res(outp, G.get(g, "res")); cond(outp, G.get(g, "cond"));
    }

    private static void target(L outp, object? t) {
        string k = G.kind(t);
        if (k.equals("verb")) { outp.add(K(390)); outp.add(S(G.get(t, "verb"))); }
        else if (k.equals("effect")) { outp.add(K(391)); outp.add(S(G.get(t, "cls"))); }
        else throw bad("prohibit target", t);
    }

    private static void prohibit(L outp, object? p) {
        outp.add(K(392)); outp.add(S(G.get(p, "pid"))); target(outp, G.get(p, "target")); res(outp, G.get(p, "res")); cond(outp, G.get(p, "cond"));
    }

    private static void sel(L outp, object? s) {
        string k = G.kind(s);
        if (k.equals("gids")) { outp.add(K(410)); strs(outp, G.get(s, "gids")); }
        else if (k.equals("effect")) { outp.add(K(411)); outp.add(S(G.get(s, "cls"))); }
        else throw bad("selection", s);
    }

    private static void window(L outp, object? w) {
        switch (G.kind(w)) {
            case "task": outp.add(K(420)); break;
            case "sliding": outp.add(K(421)); outp.add(I(G.get(w, "ms"))); break;
            case "period": outp.add(K(422)); outp.add(I(G.get(w, "ms"))); outp.add(I(G.get(w, "t0"))); break;
            case "lifetime": outp.add(K(423)); break;
            default: throw bad("window", w);
        }
    }

    private static void scope(L outp, object? s) {
        switch (G.kind(s)) {
            case "session": outp.add(K(430)); break;
            case "principal": outp.add(K(431)); break;
            case "org": outp.add(K(432)); break;
            case "fleet": outp.add(K(433)); strs(outp, G.get(s, "agents")); break;
            default: throw bad("scope", s);
        }
    }

    private static void onExceed(L outp, object? o) {
        if ("deny".equals(o)) outp.add(K(440));
        else if ("escalate".equals(o)) outp.add(K(441));
        else throw bad("on_exceed", o);
    }

    private static void bcore(L outp, object? b) {
        object? agg = G.get(b, "agg");
        int a = agg is string ? AGGS.indexOf((string)agg) : -1;
        if (a < 0) throw bad("aggregate", agg);
        outp.add(K(450)); outp.add(K(400 + a)); term(outp, G.get(b, "value")); outp.add(S(G.get(b, "key")));
        window(outp, G.get(b, "window")); scope(outp, G.get(b, "scope")); quantity(outp, G.get(b, "cap")); onExceed(outp, G.get(b, "onExceed"));
    }

    private static void bound(L outp, object? b) { outp.add(K(451)); outp.add(S(G.get(b, "bid"))); sel(outp, G.get(b, "sel")); bcore(outp, b); }

    private static void validity(L outp, object? v) {
        outp.add(K(460)); outp.add(I(G.get(v, "notBefore"))); outp.add(I(G.get(v, "notAfter"))); outp.add(I(G.get(v, "maxIdle")));
    }

    private static void deleg(L outp, object? d) {
        outp.add(K(461)); outp.add(I(G.get(d, "maxDepth"))); outp.add(I(G.truthy(G.get(d, "narrowOnly")) ? 1 : 0)); strs(outp, G.get(d, "mayTouch"));
    }

    private static void hole(L outp, object? h) {
        outp.add(K(470)); outp.add(S(G.get(h, "hid"))); outp.add(S(G.get(h, "q"))); strs(outp, G.get(h, "domain")); strs(outp, G.get(h, "affects"));
        outp.add(I(G.truthy(G.get(h, "global")) ? 1 : 0));
    }

    /** The goal as a token tape. */
    public static L EncodeGoal(D g) {
        L outp = new();
        outp.add(K(480)); outp.add(I(G.get(g, "v"))); outp.add(S(G.get(g, "principal"))); outp.add(S(G.get(g, "ontDigest"))); outp.add(S(G.get(g, "nlDigest")));
        strs(outp, G.get(g, "sources"));
        list(outp, G.get(g, "grants"), GoalCodec.grant);
        list(outp, G.get(g, "prohibits"), GoalCodec.prohibit);
        list(outp, G.get(g, "bounds"), GoalCodec.bound);
        validity(outp, G.get(g, "validity"));
        deleg(outp, G.get(g, "deleg"));
        list(outp, G.get(g, "escalateOn"), GoalCodec.cond);
        strs(outp, G.get(g, "wildcardAck"));
        list(outp, G.get(g, "holes"), GoalCodec.hole);
        return outp;
    }

    public static L EncodeOntology(D o) {
        L outp = new();
        outp.add(K(510));
        list(outp, G.get(o, "verbs"), (t, v) => {
            t.add(K(501)); t.add(S(G.get(v, "verb"))); t.add(S(G.get(v, "cls")));
            list(t, G.get(v, "params"), (u, p) => { u.add(K(500)); u.add(S(G.get(p, "path"))); ty(u, G.get(p, "ty")); });
        });
        list(outp, G.get(o, "rels"), (t, r) => { t.add(K(502)); t.add(S(G.get(r, "rel"))); t.add(S(G.get(r, "anchor"))); strs(t, G.get(r, "members")); });
        return outp;
    }

    /** {@code object?.keys(o).sort()}: null throws (TypeError), arrays and strings expose their indices, other scalars have none. */
    private static List<string> sortedKeys(object? o) {
        if (o == null) throw new IrError("object expected");
        List<string> ks = new();
        if (o is D) foreach (object? k in ((D)o).keySet()) ks.add((string) k);
        else if (o is L) for (int i = 0; i < ((L)o).size(); i++) ks.add(G.itoa(i));
        ks.sort(string.CompareOrdinal);
        return ks;
    }

    private static object? member(object? o, string k) {
        if (o is L) return ((L)o).get(int.Parse(k));
        return G.get(o, k);
    }

    private static void act(L outp, object? a) {
        object? prm = G.get(a, "params");
        List<string> keys = sortedKeys(prm);
        outp.add(K(530)); outp.add(S(G.get(a, "verb"))); outp.add(S(G.get(a, "res")));
        outp.add(I(keys.size()));
        foreach (string k in keys) { outp.add(K(520)); outp.add(S(k)); value(outp, member(prm, k)); }
        outp.add(I(G.get(a, "t"))); outp.add(S(G.get(a, "sess"))); outp.add(S(G.get(a, "prin"))); outp.add(S(G.get(a, "org"))); outp.add(S(G.get(a, "agent")));
        outp.add(I(G.get(a, "depth")));
    }

    public static L EncodeAct(D a) { L outp = new(); act(outp, a); return outp; }

    public static L EncodeHist(D h) {
        L outp = new();
        object? aggs = G.get(h, "aggs");
        List<string> keys = sortedKeys(aggs);
        outp.add(K(541));
        list(outp, G.get(h, "adms"), (t, a) => { t.add(K(531)); t.add(S(G.get(a, "gid"))); act(t, G.get(a, "act")); });
        outp.add(I(G.get(h, "last")));
        outp.add(I(keys.size()));
        foreach (string k in keys) { outp.add(K(540)); outp.add(S(k)); quantity(outp, member(aggs, k)); }
        return outp;
    }

    // ---- decoding ----
    /** A cursor over a tape. */
    public sealed class Rd {
        private L t;
        private int i;

        public Rd(L t) { this.t = t; }

        private L next() {
            if (i >= t.size()) throw new IrError("truncated tape");
            L x = G.l(t.get(i++));
            if (x == null || x.size() != 2) throw new IrError("malformed token");
            return x;
        }

        public long k() {
            L x = next();
            if (!"k".equals(x.get(0))) throw new IrError("keyword expected");
            return tokInt(x.get(1));
        }

        public long integer() {
            L x = next();
            if (!"i".equals(x.get(0))) throw new IrError("integer expected");
            return tokInt(x.get(1));
        }

        public string str() {
            L x = next();
            if (!"s".equals(x.get(0)) || !(x.get(1) is string)) throw new IrError("string expected");
            return (string) x.get(1);
        }

        public bool done() { return i >= t.size(); }

        private static long tokInt(object? v) {
            long? n = G.safeInt(v);
            if (n == null) throw new IrError("integer expected");
            return n.Value;
        }

        public L list(Func<object?> f) {
            long n = integer();
            if (n < 0) throw new IrError("negative length");
            L outp = new();
            for (long j = 0; j < n; j++) outp.add(f());
            return outp;
        }

        public L strs() { return list(this.str); }
    }

    private static D dUnit(Rd r) {
        long k = r.k();
        if (k == 300) return G.map("k", "money", "ccy", r.str());
        string u = k == 301 ? "count" : k == 302 ? "duration" : k == 303 ? "instant" : k == 304 ? "bytes" : k == 305 ? "ratio" : null;
        if (u == null) throw new IrError("bad unit tag " + k);
        return G.map("k", u);
    }

    private static D dQ(Rd r) { D u = dUnit(r); return G.map("u", u, "n", G.num(r.integer())); }

    private static D dTy(Rd r) {
        long k = r.k();
        if (k == 310) return G.map("k", "q", "u", dUnit(r));
        if (k == 311) return G.map("k", "s");
        throw new IrError("bad type tag " + k);
    }

    private static D dAtom(Rd r) {
        long k = r.k();
        if (k == 320) return G.map("k", "q", "q", dQ(r));
        if (k == 321) return G.map("k", "s", "s", r.str());
        throw new IrError("bad atom tag " + k);
    }

    private static D dV(Rd r) {
        long k = r.k();
        if (k == 330) return G.map("k", "q", "q", dQ(r));
        if (k == 331) return G.map("k", "s", "s", r.str());
        if (k == 332) return G.map("k", "set", "items", r.list(() => dAtom(r)));
        throw new IrError("bad value tag " + k);
    }

    private static D dTerm(Rd r) {
        long k = r.k();
        if (k == 340) { string p = r.str(); return G.map("k", "param", "path", p, "ty", dTy(r)); }
        if (k == 341) return G.map("k", "lit", "v", dV(r));
        if (k == 342) { string b = r.str(); return G.map("k", "hist", "bid", b, "u", dUnit(r)); }
        throw new IrError("bad term tag " + k);
    }

    private static string dOp(Rd r) {
        long k = r.k() - 350;
        if (k < 0 || k >= OPS.size()) throw new IrError("bad operator");
        return OPS.get((int) k);
    }

    private static D dN(Rd r) {
        long k = r.k();
        if (k == 600) return G.map("k", "true");
        if (k == 601) return G.map("k", "false");
        if (k == 602) { string op = dOp(r); D l = dTerm(r); return G.map("k", "atom", "op", op, "l", l, "r", dTerm(r)); }
        if (k == 603) { D a = dN(r); return G.map("k", "and", "a", a, "b", dN(r)); }
        if (k == 604) { D a = dN(r); return G.map("k", "or", "a", a, "b", dN(r)); }
        throw new IrError("bad condition tag " + k);
    }

    private static D dResPat(Rd r) {
        long k = r.k();
        if (k == 630) return G.map("k", "star");
        if (k == 631) return G.map("k", "set", "ids", r.strs());
        throw new IrError("bad resource pattern tag " + k);
    }

    private static D dWindow(Rd r) {
        long k = r.k();
        if (k == 420) return G.map("k", "task");
        if (k == 421) return G.map("k", "sliding", "ms", G.num(r.integer()));
        if (k == 422) { long ms = r.integer(); return G.map("k", "period", "ms", G.num(ms), "t0", G.num(r.integer())); }
        if (k == 423) return G.map("k", "lifetime");
        throw new IrError("bad window tag " + k);
    }

    private static D dScope(Rd r) {
        long k = r.k();
        if (k == 430) return G.map("k", "session");
        if (k == 431) return G.map("k", "principal");
        if (k == 432) return G.map("k", "org");
        if (k == 433) return G.map("k", "fleet", "agents", r.strs());
        throw new IrError("bad scope tag " + k);
    }

    /** Remaining fields of a bound core after the 450 tag: agg, value, key, window, scope, cap, onExceed. */
    private static void dBoundCore(Rd r, D into) {
        long ak = r.k() - 400;
        if (ak < 0 || ak >= AGGS.size()) throw new IrError("bad aggregate");
        into.put("agg", AGGS.get((int) ak));
        into.put("value", dTerm(r));
        into.put("key", r.str());
        into.put("window", dWindow(r));
        into.put("scope", dScope(r));
        into.put("cap", dQ(r));
        long oe = r.k();
        if (oe != 440 && oe != 441) throw new IrError("bad on_exceed");
        into.put("onExceed", oe == 440 ? "deny" : "escalate");
    }

    private static D dCeil(Rd r) {
        if (r.k() != 610) throw new IrError("ceiling expected");
        D m = new();
        m.put("bid", r.str());
        m.put("selGids", r.strs());
        m.put("selVerbs", r.strs());
        if (r.k() != 450) throw new IrError("bound core expected");
        dBoundCore(r, m);
        return m;
    }

    /** Decode the compiler's policy tape (the leading status token already consumed). */
    public static D DecodePolicy(L t) {
        Rd r = new Rd(t);
        if (r.k() != 650) throw new IrError("policy expected");
        L preds = r.list(() => {
            if (r.k() != 620) throw new IrError("pred");
            string gid = r.str(); string verb = r.str(); D rp = dResPat(r);
            return G.map("gid", gid, "verb", verb, "res", rp, "cond", dN(r));
        });
        L prohs = r.list(() => {
            if (r.k() != 640) throw new IrError("prohibition");
            string pid = r.str(); L vs = r.strs(); D rp = dResPat(r);
            return G.map("pid", pid, "verbs", vs, "res", rp, "cond", dN(r));
        });
        L ceils = r.list(() => dCeil(r));
        L escs = r.list(() => dN(r));
        if (r.k() != 460) throw new IrError("validity");
        long nb = r.integer(), na = r.integer(), mi = r.integer();
        D validity = G.map("notBefore", G.num(nb), "notAfter", G.num(na), "maxIdle", G.num(mi));
        if (r.k() != 461) throw new IrError("delegation");
        long md = r.integer(); bool no = r.integer() == 1; L mt = r.strs();
        D deleg = G.map("maxDepth", G.num(md), "narrowOnly", no, "mayTouch", mt);
        if (!r.done()) throw new IrError("trailing tokens after policy");
        return G.map("preds", preds, "prohs", prohs, "ceils", ceils, "escs", escs, "validity", validity, "deleg", deleg);
    }

    private static D dCond(Rd r) {
        long k = r.k();
        if (k == 360) return G.map("k", "true");
        if (k == 361) { string op = dOp(r); D l = dTerm(r); return G.map("k", "cmp", "op", op, "l", l, "r", dTerm(r)); }
        if (k == 362) { D a = dCond(r); return G.map("k", "and", "a", a, "b", dCond(r)); }
        if (k == 363) { D a = dCond(r); return G.map("k", "or", "a", a, "b", dCond(r)); }
        if (k == 364) return G.map("k", "not", "c", dCond(r));
        throw new IrError("bad condition tag " + k);
    }

    private static D dPart(Rd r) {
        long k = r.k();
        if (k == 375) return G.map("k", "exact", "id", r.str());
        if (k == 376) return G.map("k", "oneof", "ids", r.strs());
        if (k == 377) { string rel = r.str(); return G.map("k", "related", "rel", rel, "anchor", r.str()); }
        throw new IrError("bad resource part tag " + k);
    }

    private static D dRes(Rd r) {
        long k = r.k();
        if (k == 370) return G.map("k", "exact", "id", r.str());
        if (k == 371) return G.map("k", "oneof", "ids", r.strs());
        if (k == 372) { string rel = r.str(); return G.map("k", "related", "rel", rel, "anchor", r.str()); }
        if (k == 373) return G.map("k", "any", "reason", r.str());
        if (k == 374) return G.map("k", "all_of", "parts", r.list(() => dPart(r)));
        throw new IrError("bad resource selector tag " + k);
    }

    private static void expect(Rd r, long k, string what) { if (r.k() != k) throw new IrError(what + " expected"); }

    /** Parse a goal tape; throws IrError unless the whole tape is exactly one goal. */
    public static D DecodeGoal(L t) {
        Rd r = new Rd(t);
        expect(r, 480, "goal");
        long v = r.integer();
        string principal = r.str(), ontDigest = r.str(), nlDigest = r.str();
        L sources = r.strs();
        L grants = r.list(() => {
            expect(r, 380, "grant");
            string gid = r.str(), verb = r.str(); D rs = dRes(r);
            return G.map("gid", gid, "verb", verb, "res", rs, "cond", dCond(r));
        });
        L prohibits = r.list(() => {
            expect(r, 392, "prohibit");
            string pid = r.str();
            long tk = r.k();
            D target;
            if (tk == 390) target = G.map("k", "verb", "verb", r.str());
            else if (tk == 391) target = G.map("k", "effect", "cls", r.str());
            else throw new IrError("bad prohibit target");
            D rs = dRes(r);
            return G.map("pid", pid, "target", target, "res", rs, "cond", dCond(r));
        });
        L bounds = r.list(() => {
            expect(r, 451, "bound");
            D m = new();
            m.put("bid", r.str());
            long sk = r.k();
            if (sk == 410) m.put("sel", G.map("k", "gids", "gids", r.strs()));
            else if (sk == 411) m.put("sel", G.map("k", "effect", "cls", r.str()));
            else throw new IrError("bad selection");
            expect(r, 450, "bound core");
            dBoundCore(r, m);
            return m;
        });
        expect(r, 460, "validity");
        long nb = r.integer(), na = r.integer(), mi = r.integer();
        D validity = G.map("notBefore", G.num(nb), "notAfter", G.num(na), "maxIdle", G.num(mi));
        expect(r, 461, "delegation");
        long md = r.integer(); bool no = r.integer() == 1; L mt = r.strs();
        D deleg = G.map("maxDepth", G.num(md), "narrowOnly", no, "mayTouch", mt);
        L escalateOn = r.list(() => dCond(r));
        L wildcardAck = r.strs();
        L holes = r.list(() => {
            expect(r, 470, "hole");
            string hid = r.str(), q = r.str(); L dom = r.strs(); L aff = r.strs(); bool gl = r.integer() == 1;
            return G.map("hid", hid, "q", q, "domain", dom, "affects", aff, "global", gl);
        });
        if (!r.done()) throw new IrError("trailing tokens after goal");
        D g = new();
        g.put("v", G.num(v)); g.put("principal", principal); g.put("ontDigest", ontDigest); g.put("nlDigest", nlDigest); g.put("sources", sources);
        g.put("grants", grants); g.put("prohibits", prohibits); g.put("bounds", bounds); g.put("validity", validity); g.put("deleg", deleg);
        g.put("escalateOn", escalateOn); g.put("wildcardAck", wildcardAck); g.put("holes", holes);
        return g;
    }
}
