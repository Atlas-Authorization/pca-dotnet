namespace AtlasPca.Mpc;

/// <summary>
/// Composition semantics (the "meet" of stakeholder authorities) and the cleartext reference: allow = AND, t = MAX, rQuant = MAX. Composition
/// can only tighten, never loosen.
/// </summary>
public static class Compose
{
    public sealed record ComposedDecision(int Allow, int T, int RQuant);

    /// <summary>Rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer rQuant in [0,Q]).</summary>
    public static void AssertDecisionVectors(IReadOnlyList<Party.DecisionVector?>? vectors, int Q)
    {
        if (vectors == null) throw new ArgumentException("decision vectors must be an array");
        for (int i = 0; i < vectors.Count; i++)
        {
            var v = vectors[i];
            if (v == null) throw new ArgumentException("party " + i + ": decision vector must be an object");
            if (v.Allow != 0 && v.Allow != 1) throw new ArgumentException("party " + i + ": allow must be 0 or 1");
            if (v.T < 1 || v.T > 3) throw new ArgumentException("party " + i + ": t must be 1, 2 or 3");
            if (v.RQuant < 0 || v.RQuant > Q) throw new ArgumentException("party " + i + ": rQuant must be an integer in [0, " + Q + "]");
        }
    }

    public static ComposedDecision ComposeClear(IReadOnlyList<Party.DecisionVector?> vectors, int Q = Party.DEFAULT_Q)
    {
        if (vectors.Count == 0) throw new ArgumentException("composeClear: no parties (fail closed)");
        AssertDecisionVectors(vectors, Q);
        int allow = 1, t = 1, r = 0;
        foreach (var v in vectors)
        {
            if (v!.Allow == 0) allow = 0;
            if (v.T > t) t = v.T;
            if (v.RQuant > r) r = v.RQuant;
        }
        return new ComposedDecision(allow, t, r);
    }
}
