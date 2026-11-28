using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * Round-trip checks. (a) The card's lossless token tape decodes back to the goal. (b) An explainer sees only the compiled card
 * lines and a comparator judges the explanation against the principal's text: a detector, tighten-only (it can only escalate),
 * measured by semantic mutations that WIDEN the policy.
 */
public static class GoalRoundTrip {

    public static readonly List<string> MUTATION_KINDS = G.lst("widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant");

    private static D mm(object? o) { return G.m(o); }

    /** decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape. */
    public static bool CardRoundTrips(D g) {
        return G.stable(GoalCodec.DecodeGoal(GoalCodec.EncodeGoal(g))).equals(G.stable(g));
    }

    private static object? copy(object? o) {
        if (o is D) { D r = new(); foreach (KeyValuePair<string, object?> e in ((D) o)) r.put(e.Key, copy(e.Value)); return r; }
        if (o is L) { L r = new(); foreach (object? x in (L) o) r.add(copy(x)); return r; }
        return o;
    }

    private static object? numOut(double d) {
        if (d == Math.Round(d) && Math.Abs(d) <= G.MAX_SAFE) return G.num((long) d);
        throw new IrError("non-integer result");
    }

    private static D scale(D x, double f) {
        string uk = G.kind(mm(x.get("u")));
        if (!uk.equals("money") && !uk.equals("count")) return x;
        D r = new(x);
        r.put("n", numOut(G.toNum(x.get("n")) * f));
        return r;
    }

    private static D mapLitsInCond(D c) {
        string k = G.kind(c);
        if (k.equals("cmp")) {
            D r = mm(c.get("r"));
            D outp = new(c);
            bool lit = G.kind(r).equals("lit") && G.kind(mm(r.get("v"))).equals("q") && ("lte".equals(c.get("op")) || "lt".equals(c.get("op")));
            if (lit) outp.put("r", G.map("k", "lit", "v", G.map("k", "q", "q", scale(mm(mm(r.get("v")).get("q")), 10))));
            return outp;
        }
        if (k.equals("and") || k.equals("or")) {
            D outp = new(c);
            outp.put("a", mapLitsInCond(mm(c.get("a"))));
            outp.put("b", mapLitsInCond(mm(c.get("b"))));
            return outp;
        }
        return c;
    }

    /** A semantic mutation that WIDENS the policy (or leaves it equal); null when the goal has nothing to mutate. */
    public static D MutateGoal(D g, string kind, D ontology) {
        D x = mm(copy(g));
        switch (kind) {
            case "widen_cap": {
                L bounds = G.arr(x.get("bounds"), "bounds");
                if (bounds.isEmpty()) return null;
                mm(bounds.get(0)).put("cap", scale(mm(mm(bounds.get(0)).get("cap")), 10));
                return x;
            }
            case "widen_where": {
                foreach (object? yo in G.arr(x.get("grants"), "grants")) {
                    D y = mm(yo);
                    D mapped = mapLitsInCond(mm(y.get("cond")));
                    if (!G.stringify(mapped).equals(G.stringify(y.get("cond")))) { y.put("cond", mapped); return x; }
                }
                return null;
            }
            case "drop_prohibit": {
                L ps = G.arr(x.get("prohibits"), "prohibits");
                if (ps.isEmpty()) return null;
                ps.RemoveAt(ps.Count - 1);
                return x;
            }
            case "drop_bound": {
                L bs = G.arr(x.get("bounds"), "bounds");
                if (bs.isEmpty()) return null;
                bs.RemoveAt(bs.Count - 1);
                return x;
            }
            case "swap_resource": {
                foreach (object? yo in G.arr(x.get("grants"), "grants")) {
                    D y = mm(yo);
                    if (G.kind(y.get("res")).equals("exact")) { y.put("res", G.map("k", "exact", "id", mm(y.get("res")).get("id") + "9")); return x; }
                }
                return null;
            }
            case "add_grant": {
                HashSet<object?> have = new();
                foreach (object? y in G.arr(x.get("grants"), "grants")) have.add(G.get(y, "verb"));
                D v = null;
                foreach (object? yo in G.arr(ontology.get("verbs"), "verbs")) {
                    D y = mm(yo);
                    if ("read".equals(y.get("effect")) || have.contains(y.get("id"))) continue;
                    bool prohibited = false;
                    foreach (object? p in G.arr(x.get("prohibits"), "prohibits")) if (G.kind(G.get(p, "target")).equals("verb") && object.Equals(mm(G.get(p, "target")).get("verb"), y.get("id"))) prohibited = true;
                    if (!prohibited) { v = y; break; }
                }
                if (v == null) return null;
                G.arr(x.get("grants"), "grants").add(G.map("gid", "injected", "verb", v.get("id"), "res", G.map("k", "any", "reason", "injected"), "cond", G.map("k", "true")));
                G.arr(x.get("wildcardAck"), "wildcardAck").add("injected");
                return GoalNormalize.CanonicalizeGoal(x);
            }
            default: return null;
        }
    }

    /** The reference explainer: the card lines themselves. */
    public static string DeterministicExplain(List<string> proseLines) { return string.Join("\n", proseLines); }

    /**
     * Round trip (b): the explainer sees ONLY the compiled card lines. {@code comparator(goalText, explanation)} returns a map with
     * {@code equivalent}. Any failure escalates. Result: "ok" or "escalate".
     */
    public static string RoundTrip(D goal, string goalText, Func<List<string>, string> explainer, Func<string, string, D> comparator) {
        try {
            List<string> lines = new();
            foreach (object? l in G.arr(GoalCard.RenderCard(goal).get("lines"), "lines")) lines.add((string) l);
            string e = explainer(lines);
            return G.truthy(comparator(goalText, e).get("equivalent")) ? "ok" : "escalate";
        } catch (Exception ex) {
            return "escalate";
        }
    }

    /** Fraction of semantic widenings the pair flags, per mutation kind: [{kind, applied, detected, rate}]. {@code cases} = [{goal, text}]. */
    public static L MeasureDetection(L cases, D ontology, Func<List<string>, string> explainer, Func<string, string, D> comparator) {
        L outp = new();
        foreach (string kind in MUTATION_KINDS) {
            int applied = 0, detected = 0;
            foreach (object? co in cases) {
                D m = MutateGoal(mm(G.get(co, "goal")), kind, ontology);
                if (m == null) continue;
                applied++;
                if (RoundTrip(m, (string) G.get(co, "text"), explainer, comparator) == "escalate") detected++;
            }
            outp.add(G.map("kind", kind, "applied", G.num(applied), "detected", G.num(detected), "rate", applied > 0 ? (object?) ((double) detected / applied) : G.num(0)));
        }
        return outp;
    }
}
