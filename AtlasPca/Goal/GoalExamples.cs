using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * Boundary examples and signed goal tests over the IR and its reference semantics. An action is classified per coordinate
 * (verb, resource, relation bits, each parameter) against the literals of the policies; {@link #cells} enumerates one
 * representative per decision cell. Goals, acts and histories are parsed-JSON maps.
 */
public static class GoalExamples {

    /** The classification space of one or more goals. */
    public sealed class Space {
        public List<string> verbs = new();
        public List<string> resources = new();
        /** {rel, anchor} pairs. */
        public List<string[]> rels = new();
        /** param => (unit key => sorted distinct values), insertion ordered. */
        public Dictionary<string, Dictionary<string, List<long>>> q = new();
        /** param => sorted distinct discrete keys ("s:" + text). */
        public Dictionary<string, List<string>> d = new();

        public D toJson() {
            L rs = new();
            foreach (string[] r in rels) rs.add(G.map("rel", r[0], "anchor", r[1]));
            D qj = new();
            foreach (KeyValuePair<string, Dictionary<string, List<long>>> e in q) {
                D inner = new();
                foreach (KeyValuePair<string, List<long>> g in e.Value) { L ns = new(); foreach (long v in g.Value) ns.add(G.num(v)); inner.put(g.Key, ns); }
                qj.put(e.Key, inner);
            }
            D dj = new();
            foreach (KeyValuePair<string, List<string>> e in d) dj.put(e.Key, new L(e.Value));
            return G.map("verbs", new L(verbs), "resources", new L(resources), "rels", rs, "q", qj, "d", dj);
        }
    }

    private static D emptyHist() { return G.map("adms", new L(), "last", G.num(-1), "aggs", new D()); }

    public static string DecisionOf(int d) { return d == 2 ? "allow" : d == 1 ? "escalate" : "deny"; }

    public static int RankOf(string d) { return "allow".equals(d) ? 0 : "escalate".equals(d) ? 1 : 2; }

    /** An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0). */
    public static D MkAct(string verb, string res, D prm) {
        return G.map("verb", verb, "res", res, "params", prm, "t", G.num(0), "sess", "s", "prin", "p", "org", "o", "agent", "a", "depth", G.num(0));
    }

    private static D mm(object? o) { return G.m(o); }

    /** The reference decision of a goal for an action, its history and its relation facts: {decision, witness, prohibited}. */
    public static D DecideCase(D g, D ont, D c) {
        object? rels = c.get("rels");
        D o = ont;
        if (rels != null) { o = new(ont); o.put("rels", rels); }
        object? hist = c.get("hist");
        D x = GoalRefsem.RefExplain(g, o, mm(c.get("act")), hist == null ? emptyHist() : mm(hist));
        int d = int.Parse(((Num)x.get("d")!).Raw);
        int p = int.Parse(((Num)x.get("prohibit")!).Raw);
        return G.map("decision", DecisionOf(d), "witness", x.get("witness"), "prohibited", p < 2);
    }

    /** The history of the admitted prefix of {@code acts}: an action the goal refuses is not recorded. */
    public static D Replay(D g, D ont, L acts, L rels) {
        D h = emptyHist();
        L adms = G.l(h.get("adms"));
        foreach (object? a in acts) {
            D c = G.map("act", a, "hist", h, "rels", rels);
            D v = DecideCase(g, ont, c);
            if ("allow".equals(v.get("decision")) && v.get("witness") != null) {
                adms.add(G.map("gid", v.get("witness"), "act", a));
                h.put("last", G.get(a, "t"));
            }
        }
        return h;
    }

    // ---- space ----
    private static long qval(D q) {
        long? n = G.safeInt(q.get("n"));
        if (n == null) throw new IrError("quantity is not a safe integer");
        return n.Value;
    }

    private static string qkey(D q) {
        D u = mm(q.get("u"));
        return G.kind(u).equals("money") ? "money:" + u.get("ccy") : G.kind(u);
    }

    private static D unitOfKey(string key) {
        return key.startsWith("money:") ? G.map("k", "money", "ccy", key.substring(6)) : G.map("k", key);
    }

    private static string dkey(D v) { return G.kind(v).equals("s") ? "s:" + v.get("s") : null; }

    private delegate void LitFn(string p, D v);

    private static void walkCond(D c, LitFn f) {
        string k = G.kind(c);
        if (k.equals("cmp")) {
            D l = mm(c.get("l")), r = mm(c.get("r"));
            string p = G.kind(l).equals("param") ? (string) l.get("path") : G.kind(r).equals("param") ? (string) r.get("path") : null;
            D other = G.kind(l).equals("param") ? r : l;
            if (p == null || !G.kind(other).equals("lit")) return;
            D v = mm(other.get("v"));
            if (G.kind(v).equals("set")) { foreach (object? i in G.arr(v.get("items"), "items")) f(p, mm(i)); } else f(p, v);
        } else if (k.equals("and") || k.equals("or")) { walkCond(mm(c.get("a")), f); walkCond(mm(c.get("b")), f); }
        else if (k.equals("not")) walkCond(mm(c.get("c")), f);
    }

    private static List<D> parts(D s) {
        List<D> outp = new();
        string k = G.kind(s);
        if (k.equals("all_of")) { foreach (object? p in G.arr(s.get("parts"), "parts")) outp.add(mm(p)); }
        else if (!k.equals("any")) outp.add(s);
        return outp;
    }

    /** The space of the goals plus extra verbs. */
    public static Space BuildSpace(List<D> goals, List<string> extraVerbs) {
        HashSet<string> verbs = new(extraVerbs), resources = new();
        Dictionary<string, string[]> rels = new();
        Dictionary<string, Dictionary<string, HashSet<long>>> q = new();
        Dictionary<string, HashSet<string>> d = new();
        LitFn lit = (p, v) => {
            if (G.kind(v).equals("q")) {
                D qq = mm(v.get("q"));
                Dictionary<string, HashSet<long>> m = q.computeIfAbsent(p, x => new());
                m.computeIfAbsent(qkey(qq), x => new()).add(qval(qq));
            } else {
                string k = dkey(v);
                if (k == null) return;
                d.computeIfAbsent(p, x => new()).add(k);
            }
        };
        Action<D> res = s => {
            foreach (D x in parts(s)) {
                string k = G.kind(x);
                if (k.equals("exact")) resources.add((string) x.get("id"));
                else if (k.equals("oneof")) { foreach (object? i in G.arr(x.get("ids"), "ids")) resources.add((string) i); }
                else rels.put(x.get("rel") + "\0" + x.get("anchor"), new string[] {(string) x.get("rel"), (string) x.get("anchor")});
            }
        };
        foreach (D g in goals) {
            foreach (object? gro in G.arr(g.get("grants"), "grants")) { D gr = mm(gro); verbs.add((string) gr.get("verb")); res(mm(gr.get("res"))); walkCond(mm(gr.get("cond")), lit); }
            foreach (object? po in G.arr(g.get("prohibits"), "prohibits")) {
                D p = mm(po), t = mm(p.get("target"));
                if (G.kind(t).equals("verb")) verbs.add((string) t.get("verb"));
                res(mm(p.get("res")));
                walkCond(mm(p.get("cond")), lit);
            }
            foreach (object? c in G.arr(g.get("escalateOn"), "escalateOn")) walkCond(mm(c), lit);
            foreach (object? bo in G.arr(g.get("bounds"), "bounds")) {
                D b = mm(bo), val = mm(b.get("value"));
                if ("sum".equals(b.get("agg")) && G.kind(val).equals("param")) lit((string) val.get("path"), G.map("k", "q", "q", b.get("cap")));
            }
        }
        Space sp = new Space();
        sp.verbs = sorted(verbs);
        sp.resources = sorted(resources);
        sp.rels = new(rels.Values);
        sp.rels.sort((a, b) => (a[0] + a[1]).compareTo(b[0] + b[1]) < 0 ? -1 : 1);
        foreach (KeyValuePair<string, Dictionary<string, HashSet<long>>> e in q) {
            Dictionary<string, List<long>> inner = new();
            foreach (KeyValuePair<string, HashSet<long>> g in e.Value) { List<long> ns = new(g.Value); ns.Sort(); inner.put(g.Key, ns); }
            sp.q.put(e.Key, inner);
        }
        foreach (KeyValuePair<string, HashSet<string>> e in d) sp.d.put(e.Key, sorted(e.Value));
        return sp;
    }

    private static List<string> sorted(HashSet<string> s) { List<string> l = new(s); l.sort(string.CompareOrdinal); return l; }

    private static string classifyLit(Space sp, string p, D l) {
        if (l == null || G.kind(l).equals("set")) return "missing";
        Dictionary<string, List<long>> groups = sp.q.get(p);
        List<string> ds = sp.d.get(p);
        if (G.kind(l).equals("q")) {
            D qq = mm(l.get("q"));
            List<long> g = groups == null ? null : groups.get(qkey(qq));
            if (g == null) return groups != null || ds != null ? "unit" : "any";
            long v = qval(qq);
            int i = g.indexOf(v);
            if (i >= 0) return qkey(qq) + "=" + i;
            int pos = 0;
            while (pos < g.size() && g.get(pos) < v) pos++;
            return qkey(qq) + "@" + pos;
        }
        string k = dkey(l);
        if (ds == null) return groups != null ? "unit" : "any";
        return k != null && ds.contains(k) ? k : "other";
    }

    private static int relBit(D c, string rel, string anchor) {
        foreach (object? xo in G.arr(c.get("rels"), "rels")) {
            D x = mm(xo);
            if (rel.equals(x.get("rel")) && anchor.equals(x.get("anchor"))) return G.arr(x.get("members"), "members").contains(mm(c.get("act")).get("res")) ? 1 : 0;
        }
        return 0;
    }

    /** The decision cell of a case under a space (canonical string; the unit of precedents). */
    public static string CellKey(Space sp, D c) {
        HashSet<string> prm = new(sp.q.keySet());
        prm.addAll(sp.d.keySet());
        D act = mm(c.get("act"));
        L l = new();
        foreach (string[] r in sp.rels) l.add(G.num(relBit(c, r[0], r[1])));
        D pm = new();
        D actParams = mm(act.get("params"));
        foreach (string p in sorted(prm)) pm.put(p, classifyLit(sp, p, actParams == null ? null : mm(actParams.get(p))));
        return G.stable(G.map("v", sp.verbs.contains(act.get("verb")) ? act.get("verb") : "*", "r", sp.resources.contains(act.get("res")) ? act.get("res") : "*", "l", l, "p", pm));
    }

    private const string OTHER = "\u0000other";
    public const int MAX_CELLS = 40000;

    private static List<D> paramOptions(Space sp, string p) {
        List<D> outp = new();
        outp.add(null); // the parameter absent
        HashSet<string> seen = new();
        Action<D> add = v => { if (seen.add(G.stable(v))) outp.add(v); };
        Dictionary<string, List<long>> groups = sp.q.get(p);
        if (groups != null) {
            foreach (KeyValuePair<string, List<long>> e in groups) {
                string key = e.Key;
                bool isInstant = key.equals("instant");
                foreach (long v in e.Value) foreach (long x in new long[] {v - 1, v, v + 1}) if (x >= 0 || isInstant) add(G.map("k", "q", "q", G.map("u", unitOfKey(key), "n", G.num(x))));
                if (key.startsWith("money:")) add(G.map("k", "q", "q", G.map("u", G.map("k", "money", "ccy", "ZZZ"), "n", G.num(0))));
            }
        }
        List<string> ds = sp.d.get(p);
        if (ds != null) foreach (string k in ds) add(G.map("k", "s", "s", k.substring(2)));
        if (sp.d.containsKey(p)) add(G.map("k", "s", "s", OTHER));
        return outp;
    }

    private static D build(Space sp, List<string> prm, string verb, string resource, int bits, List<D> choice) {
        D pr = new();
        for (int i = 0; i < prm.size(); i++) if (choice.get(i) != null) pr.put(prm.get(i), choice.get(i));
        L rels = new();
        for (int i = 0; i < sp.rels.size(); i++) {
            L members = new();
            if ((bits & (1 << i)) != 0) members.add(resource);
            rels.add(G.map("rel", sp.rels.get(i)[0], "anchor", sp.rels.get(i)[1], "members", members));
        }
        return G.map("act", MkAct(verb, resource, pr), "rels", rels);
    }

    /** One representative per decision cell: {cases, complete} (complete false when the grid exceeded MAX_CELLS: then a subset). */
    public static D Cells(Space sp, List<string> verbsOpt) {
        List<string> verbs = verbsOpt != null ? verbsOpt : new(sp.verbs);
        if (verbsOpt == null) verbs.add("\u0000other-verb");
        List<string> resources = new(sp.resources);
        resources.add("\u0000other-resource");
        HashSet<string> ps = new(sp.q.keySet());
        ps.addAll(sp.d.keySet());
        List<string> prm = sorted(ps);
        List<List<D>> pOpts = new();
        foreach (string p in prm) pOpts.add(paramOptions(sp, p));
        int relBits = sp.rels.size();
        double total = (double) verbs.size() * resources.size() * Math.Pow(2, relBits);
        foreach (List<D> o in pOpts) total *= o.size();
        bool complete = total <= MAX_CELLS;
        L outp = new();
        HashSet<string> seen = new();
        Action<D> push = c => { if (seen.add(CellKey(sp, c))) outp.add(c); };
        int nbits = 1 << relBits;
        if (complete) {
            int[] idx = new int[prm.size()];
            foreach (string verb in verbs) foreach (string res in resources) for (int bits = 0; bits < nbits; bits++) {
                Array.Fill(idx, 0);
                for (;;) {
                    List<D> choice = new();
                    for (int i = 0; i < idx.Length; i++) choice.add(pOpts.get(i).get(idx[i]));
                    push(build(sp, prm, verb, res, bits, choice));
                    int k = 0;
                    while (k < idx.Length && ++idx[k] == pOpts.get(k).size()) { idx[k] = 0; k++; }
                    if (k == idx.Length) break;
                }
            }
        } else {
            foreach (string verb in verbs) {
                List<D> baseCh = new();
                foreach (List<D> o in pOpts) baseCh.add(o.get(Math.Min(2, o.size() - 1)));
                push(build(sp, prm, verb, resources.get(0), 0, baseCh));
                foreach (string res in resources) for (int bits = 0; bits < nbits; bits++) push(build(sp, prm, verb, res, bits, baseCh));
                for (int i = 0; i < pOpts.size(); i++) foreach (D l in pOpts.get(i)) {
                    List<D> ch = new(baseCh);
                    ch[i] = l;
                    push(build(sp, prm, verb, resources.get(0), 0, ch));
                }
            }
        }
        return G.map("cases", outp, "complete", complete);
    }

    private static long magnitude(D a) {
        long s = 0;
        D ps = mm(a.get("params"));
        if (ps != null) foreach (object? v in ps.Values) if (G.kind(v).equals("q")) s += Math.Abs(qval(mm(G.get(v, "q"))));
        return s;
    }

    /** The smallest-magnitude case the grant admits (a minimal Allow witness), or null if its Allow set is empty. */
    public static D AllowWitness(D g, D gr, D ont) {
        Space sp = BuildSpace(new List<D> { g }, new());
        D best = null;
        D cs = Cells(sp, new List<string> { (string)gr.get("verb")! });
        foreach (object? co in G.arr(cs.get("cases"), "cases")) {
            D c = mm(co);
            D v = DecideCase(g, ont, c);
            if ("allow".equals(v.get("decision")) && v.get("witness") != null && v.get("witness").equals(gr.get("gid")) && (best == null || magnitude(mm(c.get("act"))) < magnitude(mm(best.get("act"))))) best = c;
        }
        return best;
    }

    private static D example(string kind, string why, D cs, D hist, D g, D ont) {
        D body = G.map("act", cs.get("act"), "hist", hist, "rels", cs.get("rels"));
        string id = kind + ":" + Pca.HashCanonical(body).substring(0, 12);
        D dc = DecideCase(g, ont, G.map("act", cs.get("act"), "hist", hist, "rels", cs.get("rels")));
        return G.map("id", id, "kind", kind, "why", why, "act", cs.get("act"), "hist", hist, "rels", cs.get("rels"), "decision", dc.get("decision"));
    }

    /** The full example set (cell representatives, cap sequences, unmentioned-dimension probes): {examples, complete}. */
    public static D BoundaryExamples(D g, D ont, List<D> extra, List<string> verbsOpt) {
        List<D> goals = new();
        goals.add(g);
        if (extra != null) goals.addAll(extra);
        Space sp = BuildSpace(goals, verbsOpt == null ? new() : verbsOpt);
        D c = Cells(sp, null);
        L outp = new();
        foreach (object? cso in G.arr(c.get("cases"), "cases")) {
            D cs = mm(cso);
            D v = DecideCase(g, ont, cs);
            bool prohibited = v.get("prohibited") is true;
            outp.add(example(prohibited && "deny".equals(v.get("decision")) ? "prohibit_trigger" : "allow".equals(v.get("decision")) ? "member" : "boundary", "cell " + v.get("decision"), cs, emptyHist(), g, ont));
        }
        foreach (object? gro in G.arr(g.get("grants"), "grants")) {
            D w = AllowWitness(g, mm(gro), ont);
            if (w != null) outp.add(example("allow_witness", "minimal Allow witness of grant " + G.get(gro, "gid"), w, emptyHist(), g, ont));
        }
        foreach (object? bo in G.arr(g.get("bounds"), "bounds")) {
            D b = mm(bo), sel = mm(b.get("sel"));
            L gids = G.kind(sel).equals("gids") ? G.arr(sel.get("gids"), "gids") : new();
            D gr = null;
            foreach (object? x in G.arr(g.get("grants"), "grants")) if (gids.contains(G.get(x, "gid"))) { gr = mm(x); break; }
            D w = gr != null ? AllowWitness(g, gr, ont) : null;
            if (w == null) continue;
            double per;
            if ("count".equals(b.get("agg"))) per = 1;
            else {
                D val = mm(b.get("value"));
                D pv = G.kind(val).equals("param") ? mm(mm(mm(w.get("act")).get("params")).get(val.get("path"))) : null;
                per = pv != null && G.kind(pv).equals("q") ? qval(mm(pv.get("q"))) : 0;
            }
            if ("sum".equals(b.get("agg")) && per <= 0) continue;
            double n = Math.Floor(qval(mm(b.get("cap"))) / per);
            if (n > 60) continue;
            L acts = new();
            for (int i = 0; i < (int) n; i++) acts.add(w.get("act"));
            outp.add(example("cap_sequence", "reach the " + b.get("bid") + " cap with " + (long) n + " action(s), then one more", w, Replay(g, ont, acts, G.arr(w.get("rels"), "rels")), g, ont));
        }
        foreach (object? gro in G.arr(g.get("grants"), "grants")) {
            D w = AllowWitness(g, mm(gro), ont);
            if (w == null) continue;
            D wact = mm(w.get("act"));
            foreach (KeyValuePair<string, object?> e in mm(wact.get("params"))) {
                D l = mm(e.Value);
                if (G.kind(l).equals("q") && G.kind(mm(mm(l.get("q")).get("u"))).equals("money")) {
                    D q2 = new(mm(l.get("q")));
                    q2.put("n", G.num(1000000000L));
                    D ps2 = new(mm(wact.get("params")));
                    ps2.put(e.Key, G.map("k", "q", "q", q2));
                    D act2 = new(wact);
                    act2.put("params", ps2);
                    outp.add(example("probe", "extreme " + e.Key, G.map("act", act2, "rels", w.get("rels")), emptyHist(), g, ont));
                }
            }
            L nothing = new();
            foreach (object? ro in G.arr(w.get("rels"), "rels")) { D r2 = new(mm(ro)); r2.put("members", new L()); nothing.add(r2); }
            D act3 = new(wact);
            act3.put("res", "\u0000other-resource");
            outp.add(example("probe", "other resource", G.map("act", act3, "rels", nothing), emptyHist(), g, ont));
            outp.add(example("probe", "other customer/anchor", G.map("act", w.get("act"), "rels", nothing), emptyHist(), g, ont));
        }
        HashSet<string> seen = new();
        L uniq = new();
        foreach (object? e in outp) if (seen.add((string) G.get(e, "id"))) uniq.add(e);
        return G.map("examples", uniq, "complete", c.get("complete"));
    }

    /** Review subset: at most {@code cap} examples, riskiest-looking first (probe, cap_sequence, allow_witness, prohibit_trigger, member, boundary), stable. */
    public static L ReviewSet(L examples, int cap) {
        Dictionary<string, int> w = new() { ["probe"] = 0, ["cap_sequence"] = 1, ["allow_witness"] = 2, ["prohibit_trigger"] = 3, ["member"] = 4, ["boundary"] = 5 };
        L s = new(examples);
        s.sort((a, b) => {
            int r = RankOf((string) G.get(a, "decision")) - RankOf((string) G.get(b, "decision"));
            if (r != 0) return r;
            int k = w.get((string) G.get(a, "kind")) - w.get((string) G.get(b, "kind"));
            if (k != 0) return k;
            return ((string) G.get(a, "id")).compareTo((string) G.get(b, "id")) < 0 ? -1 : 1;
        });
        return new L(s.GetRange(0, Math.Max(0, Math.Min(cap, s.size()))));
    }

    // ---- GoalTest and the pin ----
    public static string ExpectedDecision(string answer) { return "allow".equals(answer) ? "allow" : "deny".equals(answer) ? "deny" : "escalate"; }

    /** Order-independent digest of a test list. */
    public static string TestsDigest(L tests) {
        L s = new(tests);
        s.sort((a, b) => ((string) G.get(a, "id")).compareTo((string) G.get(b, "id")));
        return Pca.HashCanonical(G.map("d", "atlas-pca/goal-tests/v1", "tests", s));
    }

    /** confirmed: list of {example, answer}. */
    public static D MakeGoalTests(D g, L confirmed) {
        L tests = new();
        foreach (object? co in confirmed) {
            D ex = mm(G.get(co, "example"));
            tests.add(G.map("id", ex.get("id"), "act", ex.get("act"), "hist", ex.get("hist"), "rels", ex.get("rels"), "answer", G.get(co, "answer")));
        }
        return G.map("goal_digest", GoalDigests.GoalDigest(g), "ontology_digest", g.get("ontDigest"), "tests", tests, "tests_digest", TestsDigest(tests));
    }

    public static D SignGoalTests(D s, byte[] seed) { return GoalSign.SignPayload("goal-tests", s, seed); }

    /** Recompile check: every confirmed test must be reproduced by {@code decideFn} (test => decision). {ok, reason?, failures}. */
    public static D CheckGoalTests(D s, IEnumerable<object?> pins, Func<D, string> decideFn) {
        if (!GoalSign.VerifyPayload(s, "goal-tests", pins)) return G.map("ok", false, "reason", "signature", "failures", new L());
        D payload = mm(s.get("payload"));
        L tests = G.arr(payload.get("tests"), "tests");
        if (!TestsDigest(tests).equals(payload.get("tests_digest"))) return G.map("ok", false, "reason", "tests_digest", "failures", new L());
        L failures = new();
        foreach (object? to in tests) {
            D t = mm(to);
            string got = decideFn(t);
            string want = ExpectedDecision((string) t.get("answer"));
            if (!want.equals(got)) failures.add(G.map("id", t.get("id"), "expected", want, "got", got));
        }
        return failures.isEmpty() ? G.map("ok", true, "failures", failures) : G.map("ok", false, "reason", "test_regression", "failures", failures);
    }

    public static D SignPin(D p, byte[] seed) { return GoalSign.SignPayload("policy-pin", p, seed); }

    /** cur: {goal, policy_digest, tests}. {ok, reason?}. */
    public static D CheckPin(D pin, IEnumerable<object?> pins, D cur) {
        if (!GoalSign.VerifyPayload(pin, "policy-pin", pins)) return G.map("ok", false, "reason", "signature");
        D p = mm(pin.get("payload")), goal = mm(cur.get("goal")), tests = mm(cur.get("tests"));
        if (!object.Equals(p.get("goal_digest"), GoalDigests.GoalDigest(goal))) return G.map("ok", false, "reason", "goal changed under the pin");
        if (!object.Equals(p.get("policy_digest"), cur.get("policy_digest"))) return G.map("ok", false, "reason", "policy changed under the pin");
        if (!object.Equals(p.get("tests_digest"), tests.get("tests_digest")) || !object.Equals(p.get("tests_digest"), TestsDigest(G.arr(tests.get("tests"), "tests")))) return G.map("ok", false, "reason", "tests changed under the pin");
        if (!object.Equals(p.get("ontology_digest"), goal.get("ontDigest"))) return G.map("ok", false, "reason", "ontology changed under the pin");
        return G.map("ok", true);
    }
}
