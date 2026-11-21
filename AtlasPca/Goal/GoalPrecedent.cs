using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * Progressive authorization. Widening is only by an escalation request answered by a principal-signed answer; a verified answer
 * becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered action's exact quantities
 * as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation; a deny is never turned into
 * an allow (precedents act only on escalate). Entries, answers and answered cases are parsed-JSON maps.
 */
public static class GoalPrecedent {

    private static D mm(object? o) { return G.m(o); }

    private static string unitKey(D q) {
        D u = mm(q.get("u"));
        return G.kind(u).equals("money") ? "money:" + u.get("ccy") : G.kind(u);
    }

    /** Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action. */
    public static D CeilingsOf(D prm) {
        D outp = new();
        foreach (KeyValuePair<string, object?> e in prm) {
            D v = mm(e.Value);
            if (G.kind(v).equals("q")) { D q = mm(v.get("q")); outp.put(e.Key + "|" + unitKey(q), q.get("n")); }
        }
        return outp;
    }

    private static D caseOf(D a) {
        D act = mm(mm(a.get("pcactn")).get("action"));
        return G.map("act", GoalExamples.MkAct((string) act.get("verb"), (string) act.get("resource"), mm(a.get("params"))), "rels", a.get("rels"));
    }

    public static D SignRevocation(D p, byte[] seed) { return GoalSign.SignPayload("precedent-revocation", p, seed); }

    /** The answer body for a request: bound to the request's exact (policy, action, history head). Sign it with the escalation signer. */
    public static D AnswerBodyFor(D req, string principal, string decision, object? iat, object? expiresAt, string nonce) {
        return G.map("v", G.num(1), "kind", "pca-escalation-answer", "principal", principal, "policy_digest", req.get("policy_digest"), "action_digest", req.get("action_digest"),
            "history_head", req.get("history_head"), "decision", decision, "iat", iat, "expires_at", expiresAt, "nonce", nonce);
    }

    private static readonly string GENESIS = new string('0', 64);

    private static object? orNull(object? o) { return o; }

    private static string entryDigest(D e) {
        object? answered = e.get("answered");
        object? answeredOut = null;
        if (G.truthy(answered)) {
            D a = new(mm(answered));
            if (a.get("lastCounter") == null) a.put("lastCounter", null);
            answeredOut = a;
        }
        return Pca.HashCanonical(G.map("d", "atlas-pca/goal-precedent-entry/v1", "seq", e.get("seq"), "prev", e.get("prev"), "kind", e.get("kind"),
            "answer", orNull(e.get("answer")), "answered", answeredOut, "cell", e.get("cell"), "ceilings", e.get("ceilings"), "revocation", e.get("revocation")));
    }

    private static D ok(object? entry) { return G.map("ok", true, "entry", entry); }
    private static D no(string reason) { return G.map("ok", false, "reason", reason); }

    /** The append-only precedent log of one verifier, which pins the principals allowed to answer and revoke. */
    public sealed class Log {
        private List<D> entriesL = new();
        private readonly IEnumerable<object?> principals;

        public Log(IEnumerable<object?> principals) { this.principals = principals; }

        public List<D> entries() { return entriesL; }

        public string head() { return entriesL.isEmpty() ? GENESIS : (string) entriesL.get(entriesL.size() - 1).get("digest"); }

        private static List<PinnedSigner> Pins(IEnumerable<object?> ps)
        {
            var r = new List<PinnedSigner>();
            foreach (var p in ps)
            {
                if (p is string s) r.Add(new PinnedSigner(s));
                else if (p is D d && d.get("pk") is string pk) r.Add(new PinnedSigner(pk, d.get("pq_pk") as string));
            }
            return r;
        }

        private object? pinFor(string pk) {
            foreach (object? p in principals) if (pk.equals(p is string ? p : G.get(p, "pk"))) return p;
            return null;
        }

        /** Everything about an answer that does not depend on the clock. Null = sound. */
        private string answerFault(D answer, D answered) {
            if (Escalation.AnswerShapeError(answer) != null) return "malformed answer";
            object? pin = pinFor((string) answer.get("principal"));
            if (pin == null || !GoalSign.VerifyArtifactSig(Escalation.AnswerDomain, answer, pin)) return "bad signature";
            D pcactn = mm(answered.get("pcactn"));
            if (!object.Equals(answer.get("action_digest"), Escalation.ActionDigest(pcactn))) return "answer is bound to another action";
            long? lc = G.safeInt(answered.get("lastCounter"));
            if (!object.Equals(answer.get("history_head"), Escalation.HistoryHead(lc))) return "answer is bound to another history state";
            if (!Pca.ParamsDigest(answered.get("params")).equals(mm(pcactn.get("action")).get("params_digest"))) return "params do not match the signed action";
            return null;
        }

        /** Recompute the whole chain, every signature and binding, and every derived cell and ceiling under {@code space}. */
        public bool verifyChain(GoalExamples.Space space) {
            try {
                string prev = GENESIS;
                for (int i = 0; i < entriesL.size(); i++) {
                    D e = entriesL.get(i);
                    long? seq = G.safeInt(e.get("seq"));
                    if (seq == null || seq != i || !prev.equals(e.get("prev")) || !entryDigest(e).equals(e.get("digest"))) return false;
                    if ("answer".equals(e.get("kind"))) {
                        D answer = mm(e.get("answer")), answered = mm(e.get("answered"));
                        if (answer == null || answered == null || answerFault(answer, answered) != null) return false;
                        if (!object.Equals(e.get("cell"), GoalExamples.CellKey(space, caseOf(answered)))
                            || !G.stringify(e.get("ceilings")).equals(G.stringify(CeilingsOf(mm(answered.get("params")))))) return false;
                    } else if (!(G.truthy(e.get("revocation")) && GoalSign.VerifyPayload(mm(e.get("revocation")), "precedent-revocation", principals))) return false;
                    prev = (string) e.get("digest");
                }
                return true;
            } catch (Exception ex) {
                return false;
            }
        }

        private D live(object? policy, object? cell, double now) {
            HashSet<object?> revoked = new();
            foreach (D e in entriesL) if ("revocation".equals(e.get("kind"))) revoked.add(mm(mm(e.get("revocation")).get("payload")).get("target_entry"));
            for (int i = entriesL.size() - 1; i >= 0; i--) {
                D e = entriesL.get(i);
                if (!"answer".equals(e.get("kind"))) continue;
                D a = mm(e.get("answer"));
                if (object.Equals(a.get("policy_digest"), policy) && object.Equals(e.get("cell"), cell) && G.toNum(a.get("expires_at")) > now && !revoked.contains(e.get("digest"))) return e;
            }
            return null;
        }

        /** Verify the answer (pinned signer, bound to this grant's policy digest, this exact action and history, unexpired) and record it: {ok, entry | reason}. */
        public D append(D answer, D answered, D grant, GoalExamples.Space space, long now) {
            EscalationBinding bind = new EscalationBinding(Escalation.PolicyDigest(grant), Escalation.ActionDigest(mm(answered.get("pcactn"))), Escalation.HistoryHead(G.safeInt(answered.get("lastCounter"))));
            var v = Escalation.Verify(answer, Pins(principals), bind, now);
            if (!v.Ok) return no(v.Reason ?? "refused");
            string fault = answerFault(answer, answered);
            if (fault != null) return no(fault);
            string cell = GoalExamples.CellKey(space, caseOf(answered));
            D existing = live(answer.get("policy_digest"), cell, now);
            if (existing != null && !object.Equals(mm(existing.get("answer")).get("decision"), answer.get("decision"))) return no("conflicts with a recorded decision; revoke it first");
            D fields = new();
            fields.put("kind", "answer");
            fields.put("answer", answer);
            fields.put("answered", answered);
            fields.put("cell", cell);
            fields.put("ceilings", CeilingsOf(mm(answered.get("params"))));
            return ok(push(fields));
        }

        public D revoke(D rev) {
            if (!GoalSign.VerifyPayload(rev, "precedent-revocation", principals)) return no("bad signature");
            D p = mm(rev.get("payload"));
            bool found = false;
            foreach (D e in entriesL) {
                if ("answer".equals(e.get("kind")) && object.Equals(e.get("digest"), p.get("target_entry"))
                    && object.Equals(mm(e.get("answer")).get("policy_digest"), p.get("policy_digest")) && object.Equals(e.get("cell"), p.get("cell"))) found = true;
            }
            if (!found) return no("no such precedent");
            D fields = new();
            fields.put("kind", "revocation");
            fields.put("revocation", rev);
            return ok(push(fields));
        }

        private D push(D fields) {
            D bse = new();
            bse.put("seq", G.num(entriesL.size()));
            bse.put("prev", head());
            foreach (KeyValuePair<string, object?> f in fields) if (f.Value != null) bse.put(f.Key, f.Value);
            D entry = new(bse);
            entry.put("digest", entryDigest(bse));
            entriesL.add(entry);
            return entry;
        }

        /** The recorded decision covering this case under this policy, or null: {decision, entry}. */
        public D lookup(string policyDigest, GoalExamples.Space space, D c, double now) {
            D e = live(policyDigest, GoalExamples.CellKey(space, c), now);
            if (e == null) return null;
            D ceil = mm(e.get("ceilings"));
            D now2 = CeilingsOf(mm(mm(c.get("act")).get("params")));
            foreach (KeyValuePair<string, object?> kv in now2) {
                object? cap = ceil.get(kv.Key);
                double limit = cap == null ? double.NegativeInfinity : G.toNum(cap);
                if (G.toNum(kv.Value) > limit) return null;
            }
            foreach (string k in ceil.keySet()) if (!now2.containsKey(k)) return null;
            return G.map("decision", mm(e.get("answer")).get("decision"), "entry", e);
        }
    }

    /** Policy decision refined by precedents: {decision, via, precedent?}. Precedents act only on escalate; a recorded deny also tightens. */
    public static D AuthorizeWithPrecedents(D goal, D ont, string policyDigest, Log log, D c, double now) {
        string baseD = (string) GoalExamples.DecideCase(goal, ont, c).get("decision");
        if (!baseD.equals("escalate")) return G.map("decision", baseD, "via", "policy");
        GoalExamples.Space space = GoalExamples.BuildSpace(new List<D> { goal }, new());
        if (!log.verifyChain(space)) return G.map("decision", "escalate", "via", "policy");
        D hit = log.lookup(policyDigest, space, c, now);
        if (hit == null) return G.map("decision", "escalate", "via", "policy");
        return G.map("decision", "allow".equals(hit.get("decision")) ? "allow" : "deny", "via", "precedent", "precedent", hit.get("entry"));
    }
}
