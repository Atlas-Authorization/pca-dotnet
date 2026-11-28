using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;

/// <summary>A review refusal with a stable code: card_too_large, unrenderable, holes, wildcard_unacknowledged, diff_too_large, too_many_widenings.</summary>
public sealed class ReviewError : Exception
{
    public string Code { get; }

    public ReviewError(string code, string detail) : base("goal review: " + code + ": " + detail) { Code = code; }
}

/**
 * Principal review and signing for a Goal IR. The PolicyCard is a deterministic, template-only (no model) rendering of the WHOLE goal:
 * every grant, prohibition, bound, validity window, delegation limit, escalation trigger, hole, wildcard and confirmed boundary example,
 * with exact numbers. Lossless-or-refuse: a card is never truncated; reviewer-fatigue limits REFUSE a goal or diff that is too large to
 * read. The semantic diff counts anything not PROVEN narrower as a widening. A GoalApproval is a pinned reviewer's signature over
 * {goal, policy, card, ontology, tests, instruction, model-set digests}; LoadApprovedGoal trusts nothing the submission claims
 * about itself: it recomputes every digest, recompiles, re-renders, re-runs the confirmed examples, then checks the signature.
 *
 * The compiler is injected (ReviewKernel): the proved extracted compiler is not carried natively. A submission is
 * {goal, ontology, instruction, model_set, tests?}.
 */
public static class GoalReview {

    /** The compiler and decision entry points the review flow needs. */
    public interface ReviewKernel {
        /** Goal, IR ontology -> {ok: true, policy} | {ok: false, reasons}. Pure and total. */
        D Compile(D goal, D ont);

        /** Content digest of the compiled policy. */
        string PolicyDigest(D policy);

        /** Error-level analyzer findings over the compiled policy; any finding refuses. The default has no analyzer. */
        List<string> Analyze(D policy) { return new(); }

        /** Whether Decide is available (needed to re-run the confirmed examples). */
        bool CanDecide() { return false; }

        /** The decision ("allow" | "deny" | "escalate") for an action. */
        string Decide(D goal, D ont, D act, D hist) { throw new NotSupportedException("no decide"); }

        /** Whether NewlyAllowed is available. */
        bool CanListNewlyAllowed() { return false; }

        /** Actions allowed by next and not by prev: {witnesses, complete}. */
        D NewlyAllowed(D prev, D next, D ont, long limit) { throw new NotSupportedException("no newlyAllowed"); }
    }

    // ---- limits (reviewer fatigue) ----

    /** The hard caps on what a human is asked to read, as a fresh map. */
    public static Dictionary<string, long> ReviewLimits() {
        return new Dictionary<string, long> {
            ["max_grants"] = 32, ["max_prohibits"] = 64, ["max_bounds"] = 32, ["max_escalate_on"] = 32, ["max_examples"] = 40,
            ["max_card_lines"] = 200, ["max_card_bytes"] = 24576, ["max_diff_changes"] = 60, ["max_diff_widenings"] = 12, ["max_witnesses"] = 20,
        };
    }

    /** Caller overrides may only TIGHTEN a limit (a larger number is ignored). o may be null. */
    public static Dictionary<string, long> EffectiveLimits(D? o) {
        Dictionary<string, long> outp = ReviewLimits();
        if (o != null) foreach (string k in new List<string>(outp.Keys)) {
            object? v = o.get(k);
            long? x = v == null ? null : G.safeInt(v);
            if (x != null && x >= 0 && x < outp[k]) outp[k] = x.Value;
        }
        return outp;
    }

    private const string D_CARD = "atlas-pca/policy-card/v1";
    private const string D_CLAUSE = "atlas-pca/goal-clause/v1";
    public const string GOAL_APPROVAL_KIND = "goal-approval";
    /** An approval may not be valid for longer than this. */
    public const long MAX_GOAL_APPROVAL_TTL_MS = 24L * 3_600_000L;
    private const long DEFAULT_TTL_MS = 3_600_000L;

    /** The fields covered by the signature. */
    public static readonly List<string> GOAL_APPROVAL_SIGNED_FIELDS = G.lst("v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest", "model_set_digest", "reviewer", "approved_at", "expires_at");

    private static D mm(object? o) { return G.m(o)!; }

    private static L list(object? o) { return G.arr(o, ""); }

    private static bool isObj(object? o) { return o is D; }

    private static string jsonOf(object? v) {
        try { return Pca.Canonicalize(v); } catch (Exception) { throw new ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)"); }
    }

    private static D line(string id, string kind, string text, object? clause, string severity) {
        return G.map("id", id, "kind", kind, "severity", severity, "text", text, "clause_digest", Pca.HashCanonical(G.map("d", D_CLAUSE, "kind", kind, "clause", clause)));
    }

    /** Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped. */
    private static string safeText(Func<string> f, object? clause) {
        try {
            string t = f();
            if (t.contains("undefined")) throw new InvalidOperationException("unknown clause shape");
            return t;
        } catch (ReviewError) {
            throw;
        } catch (Exception) {
            return jsonOf(clause);
        }
    }

    private static void big(string what, long n, long max) {
        if (n > max) throw new ReviewError("card_too_large", n.ToString(System.Globalization.CultureInfo.InvariantCulture) + " " + what + " exceed the cap of " + max.ToString(System.Globalization.CultureInfo.InvariantCulture) + ": split the goal into smaller goals");
    }

    private static string goalDigestOf(D goal) {
        try { return GoalDigests.GoalDigest(goal); } catch (Exception) { throw new ReviewError("unrenderable", "the Goal has no canonical form (float, undefined or cycle)"); }
    }

    private static string sev(bool red) { return red ? "red" : "info"; }

    /**
     * Render the card: {v, goal_digest, ontology_digest, nl_digest, principal, lines}. Deterministic, no model, no locale. Throws
     * ReviewError holes (unless allowHoles), wildcard_unacknowledged, card_too_large, unrenderable. tests and limits may be null.
     */
    public static D RenderPolicyCard(D? goalArg, L? tests, D? limits, bool allowHoles) {
        Dictionary<string, long> lim = EffectiveLimits(limits);
        L ts = tests ?? new();
        if (goalArg == null || goalArg.get("grants") is not L || goalArg.get("prohibits") is not L || goalArg.get("bounds") is not L || goalArg.get("escalateOn") is not L
            || goalArg.get("holes") is not L || !isObj(goalArg.get("validity")) || !isObj(goalArg.get("deleg"))) throw new ReviewError("unrenderable", "not a Goal IR");
        D goal = goalArg;
        L grants = list(goal.get("grants")), prohibits = list(goal.get("prohibits")), bounds = list(goal.get("bounds")), escalateOn = list(goal.get("escalateOn")), holes = list(goal.get("holes"));
        big("grants", grants.size(), lim["max_grants"]);
        big("prohibitions", prohibits.size(), lim["max_prohibits"]);
        big("bounds", bounds.size(), lim["max_bounds"]);
        big("escalation triggers", escalateOn.size(), lim["max_escalate_on"]);
        big("boundary examples", ts.size(), lim["max_examples"]);
        big("card lines", 3L + grants.size() + prohibits.size() + bounds.size() + escalateOn.size() + holes.size() + ts.size(), lim["max_card_lines"]);
        if (!holes.isEmpty() && !allowHoles) throw new ReviewError("holes", holes.size().ToString(System.Globalization.CultureInfo.InvariantCulture) + " unresolved question(s): a goal with holes is a draft and cannot be signed");
        L ack = new();
        if (goal.get("wildcardAck") is L wa) ack.addAll(wa);
        L lines = new();
        lines.add(line("principal", "meta", "Acting for principal " + jsonOf(goal.get("principal")) + ". Nothing outside this card is allowed (default deny).", goal.get("principal"), "info"));
        foreach (object? go in grants) {
            D g = mm(go);
            bool wild = "any".equals(G.kind(G.get(g, "res")));
            if (wild && !ack.contains(g.get("gid"))) throw new ReviewError("wildcard_unacknowledged", "grant " + jsonOf(g.get("gid")) + " allows ANY resource without a wildcard acknowledgement");
            lines.add(line(G.jsStr(g.get("gid")), "grant", safeText(() => GoalCard.GrantLine(g) + "." + (wild ? " WILDCARD acknowledged by the principal." : ""), g), g, sev(wild)));
        }
        foreach (object? po in prohibits) {
            D p = mm(po);
            lines.add(line(G.jsStr(p.get("pid")), "prohibit", safeText(() => GoalCard.ProhibitLine(p) + ".", p), p, sev("any".equals(G.kind(G.get(p, "res"))))));
        }
        foreach (object? bo in bounds) {
            D b = mm(bo);
            lines.add(line(G.jsStr(b.get("bid")), "bound", safeText(() => GoalCard.BoundLine(b) + ".", b), b, "info"));
        }
        D validity = mm(goal.get("validity")), deleg = mm(goal.get("deleg"));
        lines.add(line("validity", "validity", safeText(() => GoalCard.ValidityLine(validity) + ".", validity), validity, "info"));
        lines.add(line("delegation", "delegation", safeText(() => GoalCard.DelegationLine(deleg) + ".", deleg), deleg, sev(!G.truthy(deleg.get("narrowOnly")))));
        for (int i = 0; i < escalateOn.size(); i++) {
            D c = mm(escalateOn[i]);
            lines.add(line("escalate_on[" + G.itoa(i) + "]", "escalate", safeText(() => GoalCard.EscalateLine(c) + ".", c), c, "info"));
        }
        for (int i = 0; i < holes.size(); i++) {
            D h = mm(holes[i]);
            lines.add(line("hole[" + G.itoa(i) + "]", "hole", safeText(() => GoalCard.HoleLine(h) + ". Everything depending on it is dropped.", h), h, "red"));
        }
        foreach (object? to in ts) {
            D t = mm(to);
            D act = mm(t.get("act"));
            int adms = list(mm(t.get("hist")).get("adms")).size();
            string ans = "ask".equals(t.get("answer")) ? "ASKED about" : "allow".equals(t.get("answer")) ? "ALLOWED" : "DENIED";
            lines.add(line("example:" + G.jsStr(t.get("id")), "example", "EXAMPLE you confirmed: " + jsonOf(act.get("verb")) + " on " + jsonOf(act.get("res")) + " with " + jsonOf(act.get("params"))
                + (adms > 0 ? " after " + G.itoa(adms) + " earlier admitted action(s)" : "") + " must be " + ans + ".", t, "info"));
        }
        big("card lines", lines.size(), lim["max_card_lines"]);
        D card = G.map("v", G.num(1), "goal_digest", goalDigestOf(goal), "ontology_digest", goal.get("ontDigest"), "nl_digest", goal.get("nlDigest"), "principal", goal.get("principal"), "lines", lines);
        big("bytes of card", Encoding.UTF8.GetByteCount(Pca.Canonicalize(card)), lim["max_card_bytes"]);
        return card;
    }

    public static string CardDigest(D card) { return Pca.HashCanonical(G.map("d", D_CARD, "card", card)); }

    /** Plain-text form of a card for any console or terminal. Red lines are prefixed "!!". */
    public static string CardToText(D card) {
        List<string> outp = new();
        foreach (object? lo in list(card.get("lines"))) outp.add(("red".equals(G.get(lo, "severity")) ? "!! " : "   ") + G.jsStr(G.get(lo, "text")));
        return string.Join("\n", outp);
    }

    // ---- semantic diff ----

    private static bool same(object? a, object? b) { return jsonOf(a).equals(jsonOf(b)); }

    private static L conjuncts(D c) {
        L outp = new();
        string k = G.kind(c);
        if (k.equals("and")) { outp.addAll(conjuncts(mm(c.get("a")))); outp.addAll(conjuncts(mm(c.get("b")))); }
        else if (!k.equals("true")) outp.add(c);
        return outp;
    }

    /** new.cond is old.cond AND more (or equal): provably no wider. */
    private static bool whereNoWider(D oldW, D newW) {
        HashSet<string> have = new();
        foreach (object? c in conjuncts(newW)) have.add(jsonOf(c));
        foreach (object? c in conjuncts(oldW)) if (!have.Contains(jsonOf(c))) return false;
        return true;
    }

    private static string grantDir(D o, D n) {
        if (same(o, n)) return "neutral";
        return object.Equals(o.get("verb"), n.get("verb")) && same(o.get("res"), n.get("res")) && whereNoWider(mm(o.get("cond")), mm(n.get("cond"))) ? "narrow" : "unknown";
    }

    private static string prohibitDir(D o, D n) {
        if (same(o, n)) return "neutral";
        return same(o.get("target"), n.get("target")) && same(o.get("res"), n.get("res")) && whereNoWider(mm(n.get("cond")), mm(o.get("cond"))) ? "narrow" : "unknown";
    }

    private static string boundDir(D o, D n) {
        if (same(o, n)) return "neutral";
        D ro = new(o), rn = new(n);
        ro["cap"] = null; rn["cap"] = null;
        if (!same(ro, rn) || !same(G.get(o.get("cap"), "u"), G.get(n.get("cap"), "u"))) return "unknown";
        double a = G.toNum(G.get(n.get("cap"), "n")), b = G.toNum(G.get(o.get("cap"), "n"));
        return a < b ? "narrow" : a > b ? "widen" : "neutral";
    }

    private static double idle(object? x) { double d = G.toNum(x); return d == 0 ? double.PositiveInfinity : d; }

    private static string validityDir(D o, D n) {
        if (same(o, n)) return "neutral";
        double nb = G.toNum(n.get("notBefore")), ob = G.toNum(o.get("notBefore")), na = G.toNum(n.get("notAfter")), oa = G.toNum(o.get("notAfter"));
        bool nar = nb >= ob && na <= oa && idle(n.get("maxIdle")) <= idle(o.get("maxIdle"));
        bool wid = nb <= ob && na >= oa && idle(n.get("maxIdle")) >= idle(o.get("maxIdle"));
        return nar ? "narrow" : wid ? "widen" : "unknown";
    }

    private static bool containsAll(L a, L b) {
        foreach (object? x in b) if (!a.contains(x)) return false;
        return true;
    }

    private static string delegationDir(D o, D n) {
        if (same(o, n)) return "neutral";
        L touchO = list(o.get("mayTouch")), touchN = list(n.get("mayTouch"));
        bool sub = containsAll(touchO, touchN), sup = containsAll(touchN, touchO);
        double nd = G.toNum(n.get("maxDepth")), od = G.toNum(o.get("maxDepth"));
        bool nar = nd <= od && sub && (G.truthy(n.get("narrowOnly")) || !G.truthy(o.get("narrowOnly")));
        bool wid = nd >= od && sup && (G.truthy(o.get("narrowOnly")) || !G.truthy(n.get("narrowOnly")));
        return nar ? "narrow" : wid ? "widen" : "unknown";
    }

    private static List<object?[]> keyed(L xs, string field) {
        List<object?[]> r = new();
        foreach (object? x in xs) r.add(new object?[] { G.jsStr(G.get(x, field)), x });
        return r;
    }

    private static void pairs(L outp, List<object?[]> prev, List<object?[]> next, string kind, string added, string removed, Func<D, D, string> changed, Func<string, D, string> text) {
        D pm = new(), nm = new();
        foreach (object?[] e in prev) pm[(string) e[0]!] = e[1];
        foreach (object?[] e in next) nm[(string) e[0]!] = e[1];
        foreach (object?[] e in next) {
            string id = (string) e[0]!;
            D v = mm(e[1]);
            object? o = pm.get(id);
            if (!pm.ContainsKey(id)) outp.add(G.map("change", "added", "kind", kind, "id", id, "direction", added, "text", "ADDED " + text(id, v)));
            else if (!same(o, v)) outp.add(G.map("change", "changed", "kind", kind, "id", id, "direction", changed(mm(o), v), "text", "CHANGED " + text(id, v) + " (was: " + text(id, mm(o)) + ")"));
        }
        foreach (object?[] e in prev) if (!nm.ContainsKey((string) e[0]!)) outp.add(G.map("change", "removed", "kind", kind, "id", e[0], "direction", removed, "text", "REMOVED " + text((string) e[0]!, mm(e[1]))));
    }

    private static bool isWide(object? c) { object? d = G.get(c, "direction"); return "widen".equals(d) || "unknown".equals(d); }

    /**
     * Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Throws ReviewError
     * diff_too_large / too_many_widenings past the fatigue caps. kernel (NewlyAllowed), limits and ontology may be null.
     */
    public static D DiffGoals(D prev, D next, ReviewKernel? kernel, D? limits, D? ontology) {
        Dictionary<string, long> lim = EffectiveLimits(limits);
        Func<string, D, string> gl = (id, g) => "grant " + jsonOf(id) + ": " + jsonOf(g.get("verb")) + " on " + GoalCard.Res(mm(g.get("res"))) + " when " + GoalCard.Cond(mm(g.get("cond")));
        Func<string, D, string> pl = (id, p) => {
            D t = mm(p.get("target"));
            return "prohibition " + jsonOf(id) + ": " + ("verb".equals(G.kind(t)) ? jsonOf(t.get("verb")) : "effect class " + jsonOf(t.get("cls"))) + " on " + GoalCard.Res(mm(p.get("res"))) + " when " + GoalCard.Cond(mm(p.get("cond")));
        };
        Func<string, D, string> bl = (id, b) => "bound " + jsonOf(id) + ": " + GoalCard.BoundLine(b) + " (" + GoalCard.Quantity(mm(b.get("cap"))) + ")";
        L changes = new();
        pairs(changes, keyed(list(prev.get("grants")), "gid"), keyed(list(next.get("grants")), "gid"), "grant", "widen", "narrow", grantDir, gl);
        pairs(changes, keyed(list(prev.get("prohibits")), "pid"), keyed(list(next.get("prohibits")), "pid"), "prohibit", "narrow", "widen", prohibitDir, pl);
        pairs(changes, keyed(list(prev.get("bounds")), "bid"), keyed(list(next.get("bounds")), "bid"), "bound", "narrow", "widen", boundDir, bl);
        List<object?[]> ep = new(), en = new();
        foreach (object? ce in list(prev.get("escalateOn"))) ep.add(new object?[] { jsonOf(ce), ce });
        foreach (object? ce in list(next.get("escalateOn"))) en.add(new object?[] { jsonOf(ce), ce });
        pairs(changes, ep, en, "escalate", "narrow", "widen", (o, n) => "unknown", (id, c) => "escalation when " + GoalCard.Cond(c));
        if (!same(prev.get("validity"), next.get("validity"))) changes.add(G.map("change", "changed", "kind", "validity", "id", "validity", "direction", validityDir(mm(prev.get("validity")), mm(next.get("validity"))),
            "text", "CHANGED validity: " + jsonOf(next.get("validity")) + " (was: " + jsonOf(prev.get("validity")) + ")"));
        if (!same(prev.get("deleg"), next.get("deleg"))) changes.add(G.map("change", "changed", "kind", "delegation", "id", "delegation", "direction", delegationDir(mm(prev.get("deleg")), mm(next.get("deleg"))),
            "text", "CHANGED delegation: " + jsonOf(next.get("deleg")) + " (was: " + jsonOf(prev.get("deleg")) + ")"));
        // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
        if (!object.Equals(prev.get("principal"), next.get("principal"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "principal", "direction", "unknown",
            "text", "CHANGED principal: " + jsonOf(next.get("principal")) + " (was: " + jsonOf(prev.get("principal")) + ")"));
        if (!object.Equals(prev.get("ontDigest"), next.get("ontDigest"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "ontology", "direction", "unknown",
            "text", "CHANGED ontology: every term now means what the new vocabulary says (was " + jsonOf(prev.get("ontDigest")) + ", now " + jsonOf(next.get("ontDigest")) + ")"));
        if (!same(prev.get("wildcardAck"), next.get("wildcardAck"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "wildcard_ack", "direction", "unknown",
            "text", "CHANGED wildcard acknowledgements: " + jsonOf(next.get("wildcardAck")) + " (was: " + jsonOf(prev.get("wildcardAck")) + ")"));
        if (!object.Equals(prev.get("nlDigest"), next.get("nlDigest"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "instruction", "direction", "neutral", "text", "CHANGED the instruction text the goal was interpreted from"));
        int widenings = 0;
        foreach (object? c in changes) if (isWide(c)) widenings++;
        if (changes.size() > lim["max_diff_changes"]) throw new ReviewError("diff_too_large", G.itoa(changes.size()) + " changes exceed the cap of " + lim["max_diff_changes"].ToString(System.Globalization.CultureInfo.InvariantCulture) + ": review the new goal as a whole instead");
        if (widenings > lim["max_diff_widenings"]) throw new ReviewError("too_many_widenings", G.itoa(widenings) + " widenings exceed the cap of " + lim["max_diff_widenings"].ToString(System.Globalization.CultureInfo.InvariantCulture) + " per review");
        D? na = ontology != null && kernel != null && kernel.CanListNewlyAllowed() ? kernel.NewlyAllowed(prev, next, ontology, lim["max_witnesses"]) : null;
        L witnesses = new();
        bool complete = false;
        if (na != null) {
            L w = list(na.get("witnesses"));
            for (int i = 0; i < w.size() && i < lim["max_witnesses"]; i++) witnesses.add(w[i]);
            complete = na.get("complete") is true && w.size() <= lim["max_witnesses"];
        }
        L ordered = new();
        foreach (object? c in changes) if (isWide(c)) ordered.add(c);
        foreach (object? c in changes) if (!isWide(c)) ordered.add(c);
        return G.map("v", G.num(1), "from_goal_digest", goalDigestOf(prev), "to_goal_digest", goalDigestOf(next), "newly_allowed", witnesses, "newly_allowed_complete", complete, "changes", ordered, "widenings", G.num(widenings));
    }

    public static string DiffToText(D d) {
        List<string> outp = new();
        foreach (object? w in list(d.get("newly_allowed"))) outp.add("!! NEWLY ALLOWED: " + jsonOf(G.get(w, "verb")) + " on " + jsonOf(G.get(w, "res")) + " with " + jsonOf(G.get(w, "params")));
        if (d.get("newly_allowed_complete") is not true) outp.add("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.");
        foreach (object? c in list(d.get("changes"))) outp.add((isWide(c) ? "!! " : "   ") + G.jsStr(G.get(c, "text")));
        return string.Join("\n", outp);
    }

    // ---- GoalApproval ----

    /** Options of ApproveGoal; every field may be null. */
    public sealed class ApproveOptions {
        public ReviewKernel? Kernel;
        public long? Now;
        public long? TtlMs;
        public D? Limits;
        /** The previously approved goal: when given, the diff must be reviewable (fatigue caps) or signing is refused. */
        public D? Base;
    }

    /** Options of LoadApprovedGoal. Reviewers: pinned b64u keys or {pk, ...} maps. */
    public sealed class LoadOptions {
        public ReviewKernel? Kernel;
        public List<object?>? Reviewers;
        public string? OntologyDigest;
        public long? Now;
        public D? Limits;
    }

    private static D bad(string reason) { return G.map("ok", false, "reason", reason); }

    private static readonly string[][] FIELD_REASON = {
        new[] { "goal_digest", "goal_digest_mismatch" }, new[] { "policy_digest", "policy_digest_mismatch" }, new[] { "ontology_digest", "ontology_mismatch" },
        new[] { "tests_digest", "tests_digest_mismatch" }, new[] { "nl_digest", "nl_digest_mismatch" }, new[] { "model_set_digest", "model_set_digest_mismatch" },
        new[] { "card_digest", "card_digest_mismatch" } };

    /** {ok: true, digests, policy} | {ok: false, reason}. */
    private static D derive(object? subO, ReviewKernel kernel, D? limits) {
        if (!isObj(subO)) return bad("malformed_submission");
        D sub = mm(subO);
        if (!isObj(sub.get("goal")) || !isObj(sub.get("ontology")) || sub.get("instruction") is not string || sub.get("model_set") is not L || (sub.containsKey("tests") && sub.get("tests") is not L)) return bad("malformed_submission");
        foreach (object? m0 in list(sub.get("model_set"))) if (m0 is not string) return bad("malformed_submission");
        D goal = mm(sub.get("goal")), ontology = mm(sub.get("ontology"));
        L tests = sub.containsKey("tests") ? list(sub.get("tests")) : new();
        D card;
        try {
            card = RenderPolicyCard(goal, tests, limits, false);
        } catch (ReviewError e) { return bad(e.Code); } catch (Exception) { return bad("malformed_goal"); }
        string gd, nl, ts, ms;
        try {
            gd = GoalDigests.GoalDigest(goal);
            nl = GoalDigests.NlDigest((string) sub.get("instruction")!);
            ts = GoalExamples.TestsDigest(tests);
            List<string> models = new();
            foreach (object? m in list(sub.get("model_set"))) models.add((string) m!);
            ms = GoalDigests.ModelSetDigest(models);
        } catch (Exception) { return bad("malformed_goal"); }
        if (goal.get("nlDigest") is not string || !nl.equals(goal.get("nlDigest"))) return bad("instruction_mismatch");
        D? compiled;
        try { compiled = kernel.Compile(goal, ontology); } catch (Exception) { return bad("compile_error"); }
        if (compiled == null || compiled.get("ok") is not true) return bad("compile_error");
        D policy = mm(compiled.get("policy"));
        string pd;
        try {
            List<string>? findings = kernel.Analyze(policy);
            if (findings != null && !findings.isEmpty()) return bad("analyzer_error");
            pd = kernel.PolicyDigest(policy);
        } catch (Exception) { return bad("analyzer_error"); }
        if (!tests.isEmpty()) {
            if (!kernel.CanDecide()) return bad("tests_unverifiable");
            // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
            foreach (object? to in tests) {
                D t = mm(to);
                string got;
                try {
                    D ont = ontology;
                    if (G.truthy(t.get("rels"))) { ont = new(ontology); ont.put("rels", t.get("rels")); }
                    got = kernel.Decide(goal, ont, mm(t.get("act")), mm(t.get("hist")));
                } catch (Exception) { return bad("tests_unverifiable"); }
                if (!object.Equals(got, GoalExamples.ExpectedDecision((string) t.get("answer")!))) return bad("tests_contradicted");
            }
        }
        D digests = G.map("goal_digest", gd, "policy_digest", pd, "card_digest", CardDigest(card), "ontology_digest", goal.get("ontDigest"), "tests_digest", ts, "nl_digest", nl, "model_set_digest", ms);
        return G.map("ok", true, "digests", digests, "policy", policy);
    }

    private static D approveWith(D? sub, string reviewerId, Func<D, D> signer, ApproveOptions? opts) {
        ApproveOptions o = opts ?? new ApproveOptions();
        long now = o.Now ?? AtlasPca.ReplayClock.NowMs();
        long ttl = o.TtlMs ?? DEFAULT_TTL_MS;
        if (ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS || Math.Abs(now) > G.MAX_SAFE) throw new ArgumentException("approveGoal: invalid time or ttl");
        if (o.Kernel == null) throw new ArgumentException("approveGoal: a compiler kernel is required");
        D d = derive(sub, o.Kernel, o.Limits);
        if (d.get("ok") is not true) throw new ArgumentException("approveGoal: " + G.jsStr(d.get("reason")));
        if (o.Base != null) DiffGoals(o.Base, mm(sub!.get("goal")), null, o.Limits, null);
        D body = new(mm(d.get("digests")));
        body["v"] = G.num(1); body["reviewer"] = reviewerId; body["approved_at"] = G.num(now); body["expires_at"] = G.num(now + ttl);
        return signer(body);
    }

    /**
     * The human step: sign the exact goal with an Ed25519 seed. Re-derives everything the loader will; throws when the goal is not signable
     * (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a contradicted test, an instruction that
     * does not match nlDigest). A kernel is required.
     */
    public static D ApproveGoal(D? sub, byte[] reviewerSeed, ApproveOptions? opts) {
        return approveWith(sub, GoalSign.SignerId(reviewerSeed), body => GoalSign.SignGoalArtifact(GOAL_APPROVAL_KIND, body, reviewerSeed), opts);
    }

    /** ApproveGoal with a suite-agile (hybrid or post-quantum) signer. */
    public static D ApproveGoal(D? sub, SuiteKey reviewer, ApproveOptions? opts) {
        return approveWith(sub, reviewer.Id!, body => GoalSign.SignGoalArtifact(GOAL_APPROVAL_KIND, body, reviewer), opts);
    }

    /**
     * The only door from a submitted goal to an enforceable one: recomputes every digest, recompiles, re-renders the card, re-runs the
     * confirmed examples, then checks the signature. Never throws: {ok: true, approved} | {ok: false, reason}.
     */
    public static D LoadApprovedGoal(D? sub, D? approval, LoadOptions opts) {
        try {
            long now = opts.Now ?? AtlasPca.ReplayClock.NowMs();
            if (opts.Reviewers == null || opts.Reviewers.isEmpty()) return bad("no_reviewers_pinned");
            D? a = approval;
            if (a == null || G.safeInt(a.get("v")) != 1 || a.get("sig") is not string || a.get("reviewer") is not string || G.safeInt(a.get("approved_at")) == null || G.safeInt(a.get("expires_at")) == null) return bad("malformed_approval");
            foreach (string[] f in FIELD_REASON) if (a.get(f[0]) is not string) return bad("malformed_approval");
            if (opts.Kernel == null) throw new ArgumentException("a compiler kernel is required");
            D d = derive(sub, opts.Kernel, opts.Limits);
            if (d.get("ok") is not true) return d;
            D goal = mm(sub!.get("goal"));
            if (opts.OntologyDigest != null && !opts.OntologyDigest.equals(goal.get("ontDigest"))) return bad("ontology_mismatch");
            D digests = mm(d.get("digests"));
            foreach (string[] f in FIELD_REASON) if (!object.Equals(a.get(f[0]), digests.get(f[0]))) return bad(f[1]);
            bool pinned = false;
            foreach (object? p in opts.Reviewers) if (object.Equals(p is string ? p : G.get(p, "pk"), a.get("reviewer"))) pinned = true;
            if (!pinned) return bad("reviewer_not_pinned");
            long approvedAt = G.safeInt(a.get("approved_at"))!.Value, expiresAt = G.safeInt(a.get("expires_at"))!.Value;
            if (expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_GOAL_APPROVAL_TTL_MS) return bad("ttl_too_long");
            if (approvedAt > now) return bad("not_yet_valid");
            if (now >= expiresAt) return bad("expired");
            if (!GoalSign.VerifyGoalArtifact(GOAL_APPROVAL_KIND, a, "reviewer", opts.Reviewers)) return bad("bad_signature");
            D rf = G.map("goal_digest", digests.get("goal_digest"), "policy_digest", digests.get("policy_digest"));
            D approved = G.map("goal", goal, "ontology", sub.get("ontology"), "policy", d.get("policy"), "ref", rf,
                "goal_string", Pca.IntentGoalV3(new ApprovedGoalRef((string) rf.get("goal_digest")!, (string) rf.get("policy_digest")!)),
                "intent_policy", G.map("approved_goal", rf), "instruction", sub.get("instruction"), "reviewer", a.get("reviewer"), "expires_at", a.get("expires_at"));
            return G.map("ok", true, "approved", approved);
        } catch (Exception) {
            return bad("malformed_approval");
        }
    }
}
