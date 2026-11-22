using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/** The decision-to-effect binding and the claimed-fidelity gate of goal-to-decision. */
public static class GoalBinding {

    /** Digest of exactly the action that was decided: verb, resource and every parameter. */
    public static string ActionDigest(D act) { return Pca.HashCanonical(G.map("d", "atlas-pca/goal-action/v1", "act", act)); }

    /** Bind a decision to the action it was made for: {decision, action_digest}. */
    public static D BindDecision(D act, string decision) {
        return G.map("decision", decision, "action_digest", ActionDigest(act));
    }

    private static bool ctEq(string x, string y) {
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(x), Encoding.UTF8.GetBytes(y));
    }

    /** Run guard: true only for an {@code allow} bound to exactly this action. Total. */
    public static bool GuardExecute(D bound, D executed) {
        try {
            if (!"allow".equals(bound.get("decision"))) return false;
            object? d = bound.get("action_digest");
            return d is string && ctEq((string) d, ActionDigest(executed));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, and only downward.
     * {@code replayedPpm} null = not replayed; a NaN replay is unconfirmed and tightens.
     */
    public static string ClaimGate(string baseDecision, double minPpm, double? replayedPpm) {
        return replayedPpm != null && !(replayedPpm >= minPpm) ? PcaDecision.Tighten(baseDecision, "escalate") : baseDecision;
    }

    /** Hiding goal commitment (goal binding v3). */
    public static string GoalCommit(string goalDigest, string policyDigest, string salt) {
        return Pca.B64u(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("pca-goal:v3:commit:" + goalDigest + ":" + policyDigest + ":" + salt)));
    }

    /** Constant-time check that {@code commit} opens to (goal, policy, salt). */
    public static bool OpenCommit(string commit, string goalDigest, string policyDigest, string salt) {
        return ctEq(commit, GoalCommit(goalDigest, policyDigest, salt));
    }
}
