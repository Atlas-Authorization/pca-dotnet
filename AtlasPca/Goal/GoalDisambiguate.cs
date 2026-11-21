using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using AtlasPca.IntentPkg;

namespace AtlasPca.GoalPkg;


/**
 * Active disambiguation by version-space halving over a finite class of readings. A reading is a map
 * {id, family, deterministic, goal, notes}; a distinguishing case is {act, prior, rels}.
 */
public static class GoalDisambiguate {

    public static readonly Dictionary<string, int> DEFAULT_RISK = new() { ["read"] = 1, ["reversible"] = 2, ["external_send"] = 8, ["irreversible"] = 10 };

    /** Question options: the IR ontology the readings are decided against and optional risk / mass of an action (default risk by effect class, mass 1). */
    public sealed class Opts {
        public D ont;
        public Func<D, double?>? riskOf;
        public Func<D, double?>? massOf;
        public int? Budget;

        public Opts(D ont) { this.ont = ont; }
    }

    private static D mm(object? o) { return G.m(o); }

    private static double h2(double p) {
        return p <= 0 || p >= 1 ? 0 : -(p * IntentMath.Log2(p) + (1 - p) * IntentMath.Log2(1 - p));
    }

    public static bool AllowsWitness(D g, D ont, D w) {
        D hist = GoalExamples.Replay(g, ont, G.arr(w.get("prior"), "prior"), G.arr(w.get("rels"), "rels"));
        return "allow".equals(GoalExamples.DecideCase(g, ont, G.map("act", w.get("act"), "hist", hist, "rels", w.get("rels"))).get("decision"));
    }

    private static bool allowSet(D r, D w, D ont) { return AllowsWitness(mm(r.get("goal")), ont, w); }

    private static List<D> goalsOf(List<D> readings) {
        List<D> goals = new();
        foreach (D r in readings) goals.add(mm(r.get("goal")));
        return goals;
    }

    /** Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences. */
    static List<D> witnesses(List<D> readings, D ont) {
        List<D> goals = goalsOf(readings);
        List<D> outp = new();
        foreach (object? co in G.arr(GoalExamples.Cells(GoalExamples.BuildSpace(goals, new()), null).get("cases"), "cases")) {
            outp.add(G.map("act", G.get(co, "act"), "prior", new L(), "rels", G.get(co, "rels")));
        }
        foreach (D r in readings) {
            foreach (object? eo in G.arr(GoalExamples.BoundaryExamples(mm(r.get("goal")), ont, goals, null).get("examples"), "examples")) {
                if (!"cap_sequence".equals(G.get(eo, "kind"))) continue;
                L prior = new();
                foreach (object? a in G.arr(G.get(G.get(eo, "hist"), "adms"), "adms")) prior.add(G.get(a, "act"));
                outp.add(G.map("act", G.get(eo, "act"), "prior", prior, "rels", G.get(eo, "rels")));
            }
        }
        return outp;
    }

    /** Questions over the symmetric difference of the readings, ranked by H2(vote) x risk x mass (best first). */
    public static List<D> Questions(List<D> readings, Opts opts) {
        D ont = opts.ont;
        int k = readings.size();
        D cls = new();
        foreach (object? v in G.arr(ont.get("verbs"), "verbs")) cls.put((string) G.get(v, "verb"), G.get(v, "cls"));
        List<D> outp = new();
        HashSet<string> seen = new();
        foreach (D w in witnesses(readings, ont)) {
            L yes = new();
            foreach (D r in readings) if (allowSet(r, w, ont)) yes.add(r.get("id"));
            if (yes.isEmpty() || yes.size() == k) continue;
            string id = G.stringify(G.list(w.get("act"), G.num(G.arr(w.get("prior"), "prior").size())));
            if (!seen.add(id)) continue;
            D act = mm(w.get("act"));
            double risk;
            if (opts.riskOf != null) risk = opts.riskOf(act)!.Value;
            else {
                object? c = cls.get(act.get("verb"));
                risk = c is string cs && DEFAULT_RISK.TryGetValue(cs, out var rk) ? rk : 10;
            }
            double mass = opts.massOf != null ? opts.massOf(act)!.Value : 1;
            int np = G.arr(w.get("prior"), "prior").size();
            L notAllow = new();
            foreach (D rr in readings) if (!yes.contains(rr.get("id"))) notAllow.add(rr.get("id"));
            D q = new();
            q.put("id", id);
            foreach (KeyValuePair<string, object?> e in w) q[e.Key] = e.Value;
            q.put("allow", yes);
            q.put("notAllow", notAllow);
            q.put("text", "Should this be allowed: " + GoalFmt.FmtAct(act) + (np > 0 ? " (after " + np + " earlier identical action(s))" : "") + "?");
            q.put("score", h2((double) yes.size() / k) * risk * mass);
            outp.add(q);
        }
        outp.sort((a, b) => {
            double d = (double) b.get("score")! - (double) a.get("score")!;
            if (d != 0) return d > 0 ? 1 : -1;
            return ((string) a.get("id")).compareTo((string) b.get("id")) < 0 ? -1 : 1;
        });
        return outp;
    }

    /** Fraction of witness cells on which the readings do not all agree on Allow. */
    public static double DisagreementMass(List<D> readings, D ont) {
        List<D> w = witnesses(readings, ont);
        if (w.isEmpty()) return 0;
        int split = 0;
        foreach (D x in w) {
            int n = 0;
            foreach (D r in readings) if (allowSet(r, x, ont)) n++;
            if (n > 0 && n < readings.size()) split++;
        }
        return (double) split / w.size();
    }

    /** Active disambiguation: {status, goal, asked, residualMass, remaining}. {@code ask} maps a question to "allow" or "deny". */
    public static D Disambiguate(List<D> readings, Func<D, string> ask, Opts opts) {
        D ont = opts.ont;
        int budget = opts.Budget ?? readings.size();
        List<D> active = new(readings);
        L asked = new();
        while (active.size() > 1 && asked.size() < budget) {
            List<D> qs = Questions(active, opts);
            if (qs.isEmpty()) break;
            D q = qs.get(0);
            asked.add(q);
            bool allow = "allow".equals(ask(q));
            List<D> next = new();
            foreach (D r in active) if (allowSet(r, q, ont) == allow) next.add(r);
            active = next;
        }
        double mass = DisagreementMass(active, ont);
        D g = GoalNVersion.Meet(goalsOf(active));
        L remaining = new();
        foreach (D r in active) remaining.add(r.get("id"));
        if (mass > 0) {
            L hs = new(G.arr(g.get("holes"), "holes"));
            hs.add(G.map("hid", "budget", "q", "Question budget exhausted with disagreement left.", "domain", new L(), "affects", new L(), "global", true));
            hs.sort((a, b) => ((string) G.get(a, "hid")).compareTo((string) G.get(b, "hid")));
            D g2 = new(g);
            g2.put("holes", hs);
            return G.map("status", "budget_exhausted", "goal", g2, "asked", asked, "residualMass", mass, "remaining", remaining);
        }
        return G.map("status", "resolved", "goal", g, "asked", asked, "residualMass", 0, "remaining", remaining);
    }
}
