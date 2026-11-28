using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * N-version interpretation: the enforced policy is the semantic meet of the readings. Allow(meet gs) a implies Allow(g) a for
 * every g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named {@code x&y&z}),
 * resources intersect through {@code all_of}, conditions conjoin; a bound counts the admitted actions of the merged grants
 * derived from the grants it selected, so the merged goal never admits more than any reading.
 */
public static class GoalNVersion {

    private static D mm(object? o) { return G.m(o); }

    private static List<D> partsOf(D s) {
        List<D> outp = new();
        string k = G.kind(s);
        if (k.equals("all_of")) { foreach (object? p in G.arr(s.get("parts"), "parts")) outp.add(mm(p)); }
        else if (!k.equals("any")) outp.add(s);
        return outp;
    }

    private static D intersect(D a, D b) {
        if (G.kind(a).equals("any")) return b;
        if (G.kind(b).equals("any")) return a;
        Dictionary<string, D> uniq = new();
        foreach (D p in partsOf(a)) uniq.put(G.stable(p), p);
        foreach (D p in partsOf(b)) uniq.put(G.stable(p), p);
        if (uniq.size() == 1) return uniq.Values.First();
        return G.map("k", "all_of", "parts", new L(uniq.Values));
    }

    private static D conj(D a, D b) {
        if (G.kind(a).equals("true")) return b;
        if (G.kind(b).equals("true")) return a;
        return G.map("k", "and", "a", a, "b", b);
    }

    /** A merged grant and, per reading, the gid of the grant it was derived from. */
    private sealed class Tracked {
        public D g;
        public List<string> frm;
        public Tracked(D g, List<string> frm) { this.g = g; this.frm = frm; }
    }

    private static List<Tracked> cross(List<Tracked> a, List<Tracked> b) {
        List<Tracked> outp = new();
        foreach (Tracked x in a) foreach (Tracked y in b) {
            if (!object.Equals(x.g.get("verb"), y.g.get("verb"))) continue;
            D g = G.map("gid", x.g.get("gid") + "&" + y.g.get("gid"), "verb", x.g.get("verb"),
                "res", intersect(mm(x.g.get("res")), mm(y.g.get("res"))), "cond", conj(mm(x.g.get("cond")), mm(y.g.get("cond"))));
            List<string> frm = new(x.frm);
            frm.addAll(y.frm);
            outp.add(new Tracked(g, frm));
        }
        return outp;
    }

    private static List<Tracked> track(L grants) {
        List<Tracked> outp = new();
        foreach (object? g in grants) outp.add(new Tracked(mm(g), new(G.lst((string) G.get(g, "gid")))));
        return outp;
    }

    /** Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions. */
    public static L MeetGrants(L a, L b) {
        L outp = new();
        foreach (Tracked t in cross(track(a), track(b))) outp.add(t.g);
        return outp;
    }

    private static L derived(List<Tracked> tracked, int i, L gids) {
        L outp = new();
        foreach (Tracked t in tracked) if (gids.contains(t.frm.get(i))) outp.add(t.g.get("gid"));
        return outp;
    }

    private static L sortedStrings(L xs) {
        L s = new(xs);
        s.sort((a, b) => ((string) a).compareTo((string) b));
        return s;
    }

    private static double num(object? o) { return G.toNum(o); }

    private static object? numOut(double d) {
        if (d == Math.Round(d) && Math.Abs(d) <= G.MAX_SAFE) return G.num((long) d);
        throw new IrError("non-integer result");
    }

    public static D Meet(List<D> goals) {
        if (goals.isEmpty()) throw new IrError("meet: no goals");
        D first = goals.get(0);
        foreach (D g in goals) {
            if (!object.Equals(g.get("principal"), first.get("principal")) || !object.Equals(g.get("ontDigest"), first.get("ontDigest"))
                || !object.Equals(g.get("nlDigest"), first.get("nlDigest"))) throw new IrError("meet: readings must share principal, ontology and text");
        }
        if (goals.size() == 1) return first;
        List<Tracked> tracked = track(G.arr(first.get("grants"), "grants"));
        foreach (D g in goals.Skip(1)) tracked = cross(tracked, track(G.arr(g.get("grants"), "grants")));
        L grants = new();
        foreach (Tracked t in tracked) grants.add(t.g);

        L prohibits = new();
        D pseen = new();
        for (int i = 0; i < goals.size(); i++) {
            foreach (object? po in G.arr(goals.get(i).get("prohibits"), "prohibits")) {
                D p = mm(po);
                D bodyMap = new(p);
                bodyMap.put("pid", "");
                string body = G.stable(bodyMap);
                if (pseen.containsKey(body)) continue;
                bool taken = pseen.Values.contains(p.get("pid"));
                pseen.put(body, p.get("pid"));
                if (taken) { D np = new(p); np.put("pid", p.get("pid") + "#" + i); prohibits.add(np); } else prohibits.add(p);
            }
        }

        L bounds = new();
        Dictionary<string, D> bseen = new();
        for (int i = 0; i < goals.size(); i++) {
            foreach (object? bo in G.arr(goals.get(i).get("bounds"), "bounds")) {
                D b = mm(bo), bsel = mm(b.get("sel"));
                D sel = bsel;
                if (G.kind(bsel).equals("gids")) sel = G.map("k", "gids", "gids", sortedStrings(derived(tracked, i, G.arr(bsel.get("gids"), "gids"))));
                if (G.kind(sel).equals("gids") && G.arr(sel.get("gids"), "gids").isEmpty()) continue;
                string key = G.stable(G.map("sel", sel, "agg", b.get("agg"), "value", b.get("value"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "unit", mm(b.get("cap")).get("u")));
                D prev = bseen.get(key);
                if (prev != null) {
                    if (num(mm(b.get("cap")).get("n")) < num(mm(prev.get("cap")).get("n"))) prev.put("cap", b.get("cap"));
                    if ("deny".equals(b.get("onExceed"))) prev.put("onExceed", "deny");
                    continue;
                }
                D nb = new(b);
                nb.put("sel", sel);
                bool dup = false;
                foreach (object? x in bounds) if (object.Equals(G.get(x, "bid"), b.get("bid"))) dup = true;
                nb.put("bid", dup ? b.get("bid") + "#" + i : b.get("bid"));
                bounds.add(nb);
                bseen.put(key, nb);
            }
        }

        D escSeen = new();
        foreach (D g in goals) foreach (object? c in G.arr(g.get("escalateOn"), "escalateOn")) escSeen.put(G.stable(c), c);

        List<double> idle = new();
        foreach (D g in goals) { double x = num(mm(g.get("validity")).get("maxIdle")); if (x > 0) idle.add(x); }
        L touch = new();
        foreach (Tracked t in tracked) {
            bool all = true;
            for (int i = 0; i < goals.size(); i++) if (!G.arr(mm(goals.get(i).get("deleg")).get("mayTouch"), "mayTouch").contains(t.frm.get(i))) { all = false; break; }
            if (all) touch.add(t.g.get("gid"));
        }
        L ack = new();
        foreach (Tracked t in tracked) {
            if (!G.kind(t.g.get("res")).equals("any")) continue;
            bool all = true;
            for (int i = 0; i < goals.size(); i++) {
                D? src = null;
                foreach (object? x in G.arr(goals.get(i).get("grants"), "grants")) if (t.frm.get(i).equals(G.get(x, "gid"))) { src = mm(x); break; }
                bool notAny = src == null || !G.kind(src.get("res")).equals("any");
                if (!(notAny || G.arr(goals.get(i).get("wildcardAck"), "wildcardAck").contains(t.frm.get(i)))) { all = false; break; }
            }
            if (all) ack.add(t.g.get("gid"));
        }
        Dictionary<string, D> holes = new();
        for (int i = 0; i < goals.size(); i++) {
            foreach (object? ho in G.arr(goals.get(i).get("holes"), "holes")) {
                D h = mm(ho);
                D prev = holes.get(h.get("hid"));
                HashSet<string> aff = new();
                if (prev != null) foreach (object? a in G.arr(prev.get("affects"), "affects")) aff.add((string) a);
                foreach (object? a in derived(tracked, i, G.arr(h.get("affects"), "affects"))) aff.add((string) a);
                L affects = sortedStrings(new L(aff));
                D nh = new(h);
                nh.put("affects", affects);
                nh.put("global", G.truthy(h.get("global")) ? h.get("global") : prev != null && prev.get("global") != null ? prev.get("global") : (object?) false);
                holes.put((string) h.get("hid"), nh);
            }
        }
        HashSet<string> sources = new();
        foreach (D g in goals) foreach (object? s in G.arr(g.get("sources"), "sources")) sources.add((string) s);
        double nbf = double.NegativeInfinity, naf = double.PositiveInfinity, md = double.PositiveInfinity;
        foreach (D g in goals) {
            D v = mm(g.get("validity"));
            nbf = Math.Max(nbf, num(v.get("notBefore")));
            naf = Math.Min(naf, num(v.get("notAfter")));
            md = Math.Min(md, num(mm(g.get("deleg")).get("maxDepth")));
        }
        double mi = 0;
        if (!idle.isEmpty()) { mi = double.PositiveInfinity; foreach (double x in idle) mi = Math.Min(mi, x); }
        D outp = new(first);
        outp.put("grants", grants);
        outp.put("prohibits", prohibits);
        outp.put("bounds", bounds);
        outp.put("escalateOn", new L(escSeen.Values));
        outp.put("sources", new L(sources));
        outp.put("validity", G.map("notBefore", numOut(nbf), "notAfter", numOut(naf), "maxIdle", numOut(mi)));
        outp.put("deleg", G.map("maxDepth", numOut(md), "narrowOnly", true, "mayTouch", touch));
        outp.put("holes", new L(holes.Values));
        outp.put("wildcardAck", ack);
        return GoalNormalize.CanonicalizeGoal(outp);
    }

    /** Panel requirements: at least 3 interpreters, one deterministic non-LLM interpreter, two distinct model families. Issues {code, msg}. */
    public static L CheckPanel(List<D> readings) {
        L outp = new();
        if (readings.size() < 3) outp.add(G.map("code", "too_few", "msg", "need at least 3 interpreters"));
        bool det = false;
        HashSet<object?> fams = new();
        foreach (D r in readings) { if (G.truthy(r.get("deterministic"))) det = true; else fams.add(r.get("family") == null ? "\u0000undefined" : r.get("family")); }
        if (!det) outp.add(G.map("code", "no_deterministic", "msg", "need at least one deterministic template interpreter"));
        if (fams.size() < 2) outp.add(G.map("code", "no_family_diversity", "msg", "need at least two distinct model families"));
        return outp;
    }

    /** {merged, panelIssues, disagreementHoles, mass, signable}. */
    public static D NVersion(List<D> readings, GoalDisambiguate.Opts opts, double? massThreshold) {
        List<D> goals = new();
        foreach (D r in readings) goals.add(mm(r.get("goal")));
        D merged = Meet(goals);
        L panelIssues = CheckPanel(readings);
        List<HashSet<string>> verbSets = new();
        SortedSet<string> allVerbs = new(StringComparer.Ordinal);
        foreach (D g in goals) {
            HashSet<string> s = new();
            foreach (object? gr in G.arr(g.get("grants"), "grants")) s.add((string) G.get(gr, "verb"));
            verbSets.add(s);
            allVerbs.UnionWith(s);
        }
        L holes = new();
        foreach (string v in allVerbs) {
            bool some = false;
            foreach (HashSet<string> s in verbSets) if (!s.contains(v)) some = true;
            if (some) holes.add(G.map("hid", "nv:verb:" + v, "q", "Only some readings allow \"" + v + "\". Should it be allowed at all?", "domain", new L(), "affects", new L(), "global", false));
        }
        double mass = GoalDisambiguate.DisagreementMass(readings, opts.ont);
        if (mass > (massThreshold ?? 0)) {
            List<D> qs = GoalDisambiguate.Questions(readings, opts);
            holes.add(G.map("hid", "nv:split", "q", qs.isEmpty() ? "The readings disagree." : qs.get(0).get("text"), "domain", new L(), "affects", new L(), "global", true));
        }
        L all = new(G.arr(merged.get("holes"), "holes"));
        all.addAll(holes);
        D byHid = new();
        foreach (object? h in all) byHid.put((string) G.get(h, "hid"), h);
        D m2 = new(merged);
        m2.put("holes", new L(byHid.Values));
        return G.map("merged", GoalNormalize.CanonicalizeGoal(m2), "panelIssues", panelIssues, "disagreementHoles", holes, "mass", mass, "signable", panelIssues.isEmpty() && all.isEmpty());
    }
}
