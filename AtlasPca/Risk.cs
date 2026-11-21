using System.Globalization;

namespace AtlasPca;

/// <summary>The risk policy of a grant envelope as numbers (see <see cref="Risk.PolicyOf"/>).</summary>
public sealed record RiskPolicy(double Alpha, double Beta, double Gamma, double Delta, double Epsilon, double Zeta, double Theta1, double Theta2, double Kappa, double Lambda, double Rho, double BMax);

/// <summary>The six risk inputs, each normalised to [0,1]. Missing or non-finite is the WORST case (see <see cref="Risk.Worst"/>).</summary>
public sealed record RiskInputs(double SemanticDistance, double Reversibility, double BlastRadius, double Taint, double Confidence, double Age);

/// <summary>The trust budget: <c>B</c> in [0, bMax], <c>Tau</c> the last human-touch time (ms) and <c>AsOf</c> the time it was last brought up to date (null: <c>Tau</c>).</summary>
public sealed record TrustBudget(double B, double Tau, double? AsOf = null);

/// <summary>The threshold an action needs: <c>T</c> 1, 2 or 3, the proof strength and whether optimistic acceptance may be offered.</summary>
public sealed record RequiredThreshold(int T, string Proof, bool OptimisticAllowed);

/// <summary>The budget admission of one action.</summary>
public sealed record Admission(bool Admit, bool NeedStepUp, int T, bool Metered);

/// <summary>The machine-only decision of the policy VM (<see cref="Risk.DecideCore"/>).</summary>
public sealed record CoreDecision(bool Release, bool Admit, bool NeedStepUp, RequiredThreshold Threshold, bool Debit);

/// <summary>The result of a sub-budget or consolidated debit: <c>Ok</c>, the budgets, or the <c>Reason</c>.</summary>
public sealed record BudgetResult(bool Ok, IReadOnlyList<TrustBudget>? Nodes = null, string? Reason = null);

/// <summary>Risk functional, threshold map and decaying trust budget (spec section 10, L3): a port of the reference <c>risk.ts</c> and of the numeric
/// kernels of its policy VM (<c>ReqThr</c>, <c>Escalate</c>, <c>AdmitOf</c>, <c>DecideCore</c>). Pure and deterministic. Time is epoch milliseconds;
/// <c>Lambda</c> is budget drained PER SECOND. A non-finite input fails closed (it counts as its worst case).</summary>
public static class Risk
{
    public static string[] InputKeys => new[] { "semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age" };

    /// <summary>The worst case of each input: a missing or non-finite value counts as this.</summary>
    public static RiskInputs Worst => new(1, 0, 1, 1, 0, 1);

    static bool Fin(double x) => double.IsFinite(x);
    static double Clamp01(double x) => x < 0 ? 0 : x > 1 ? 1 : x;
    static double Unit(double x, int worst) => Fin(x) ? Clamp01(x) : worst;
    static double Wt(double x) => Fin(x) && x > 0 ? x : 0;
    static double Nz(double x) => Fin(x) && x > 0 ? x : 0;

    /// <summary>The policy of a (validated) risk_policy JSON object, or null when it is not one.</summary>
    public static RiskPolicy? PolicyOf(object? p)
    {
        if (Pca.ValidateRiskPolicy(p) != null) return null;
        var m = (Dictionary<string, object?>)p!;
        var w = (Dictionary<string, object?>)m["weights"]!;
        double F(Dictionary<string, object?> d, string k) => IntentJs.NumOf(d[k]) ?? double.NaN;
        return new RiskPolicy(F(w, "alpha"), F(w, "beta"), F(w, "gamma"), F(w, "delta"), F(w, "epsilon"), F(w, "zeta"),
            F(m, "theta1"), F(m, "theta2"), F(m, "kappa"), F(m, "lambda"), F(m, "rho"), F(m, "bMax"));
    }

    /// <summary>r = clamp(a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1). Weights are clamped to &gt;= 0, which makes r monotone for any policy.</summary>
    public static double Score(RiskInputs i, RiskPolicy w)
    {
        var r = Wt(w.Alpha) * Unit(i.SemanticDistance, 1) + Wt(w.Beta) * (1 - Unit(i.Reversibility, 0)) + Wt(w.Gamma) * Unit(i.BlastRadius, 1)
              + Wt(w.Delta) * Unit(i.Taint, 1) + Wt(w.Epsilon) * (1 - Unit(i.Confidence, 0)) + Wt(w.Zeta) * Unit(i.Age, 1);
        return Clamp01(r);
    }

    /// <summary>The piecewise map: r &lt;= theta1 is t=1 (claim; optimistic ok unless <paramref name="irreversible"/>), r &lt;= theta2 is t=2, else t=3. NaN r is the worst.</summary>
    public static RequiredThreshold Required(double r, double theta1, double theta2, bool irreversible = false)
    {
        var x = Fin(r) ? r : 1;
        if (x <= theta1) return new(1, "claim", !irreversible);
        if (x <= theta2) return new(2, "standard", false);
        return new(3, "strong", false);
    }

    static int ProofRank(string p) => p switch { "claim" => 0, "standard" => 1, _ => 2 };
    static string ProofFor(int t) => t switch { 1 => "claim", 2 => "standard", _ => "strong" };

    /// <summary>Raises a threshold to at least <paramref name="minT"/> and keeps it coherent (t=2 needs proof &gt;= standard, t=3 strong, optimistic only at t=1). Never lowers.</summary>
    public static RequiredThreshold Escalate(RequiredThreshold rt, int minT)
    {
        var t = minT > rt.T ? minT : rt.T;
        var floor = ProofFor(t);
        var proof = ProofRank(rt.Proof) >= ProofRank(floor) ? rt.Proof : floor;
        return new(t, proof, t > 1 ? false : rt.OptimisticAllowed);
    }

    // ---- trust budget

    /// <summary>c(A) = kappa * r(A); a non-finite r costs as r = 1.</summary>
    public static double Cost(double r, double kappa) => Nz(kappa) * Clamp01(Fin(r) ? r : 1);

    /// <summary>Passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same <paramref name="now"/>.</summary>
    public static TrustBudget Leak(TrustBudget b, double now, double lambda)
    {
        var from = b.AsOf ?? b.Tau;
        var dt = Fin(now) && Fin(from) ? Math.Max(0, now - from) : 0;
        var bb = Math.Max(0, b.B - Nz(lambda) * (dt / 1000.0));
        return new(bb, b.Tau, Fin(now) ? Math.Max(now, from) : from);
    }

    /// <summary>B = max(0, B - cost). The caller checks B &gt;= cost first.</summary>
    public static TrustBudget Debit(TrustBudget b, double c) => b with { B = Math.Max(0, b.B - Nz(c)) };

    /// <summary>A human co-sign recharge: B = min(bMax, B + rho), tau = now. The only way the budget rises.</summary>
    public static TrustBudget Recharge(TrustBudget b, double rho, double bMax, double now) => new(Math.Min(Nz(bMax), b.B + Nz(rho)), now, now);

    /// <summary>A full goal re-confirmation: B = bMax, tau = now.</summary>
    public static TrustBudget RechargeFull(double bMax, double now) => new(Nz(bMax), now, now);

    /// <summary>Normalised age since the last human touch: clamp((now - tau) / horizon, 0, 1).</summary>
    public static double AgeSinceTouch(TrustBudget b, double now, double horizonMs = 3_600_000)
    {
        if (!Fin(now) || !Fin(b.Tau) || !(Fin(horizonMs) && horizonMs > 0)) return 1;
        return Clamp01((now - b.Tau) / horizonMs);
    }

    /// <summary>The machine-only band is t=1 AND t=2 (both metered): an action at t &lt; 3 proceeds only if the budget covers it; otherwise it escalates to t=3.</summary>
    public static Admission AdmitOf(int t, bool budgetCovers)
    {
        if (t < 3 && !budgetCovers) return new(false, true, 3, false);
        if (t == 1) return new(true, false, 1, true);
        if (t == 2) return new(false, true, 2, true);
        return new(false, true, 3, false);
    }

    public static Admission Admit(double r, TrustBudget b, RiskPolicy p) => AdmitOf(Required(r, p.Theta1, p.Theta2).T, b.B >= Cost(r, p.Kappa));

    /// <summary>The policy VM's release decision: release needs the envelope predicates, the caveats, the delegated caveats and the chain; admitted / step-up
    /// follow the budget admission; the threshold is escalated to the admission's t; the action is debited only when released AND metered.</summary>
    public static CoreDecision DecideCore(bool predicatesOk, bool caveatsOk, bool delegatedOk, bool chainOk, RequiredThreshold rt, Admission adm)
    {
        var release = predicatesOk && caveatsOk && delegatedOk && chainOk;
        return new(release, release && adm.Admit, release ? adm.NeedStepUp : true, Escalate(rt, adm.T), release && adm.Metered);
    }

    /// <summary>Between two consecutive human recharges the total risk of machine-only actions is at most bMax / kappa.</summary>
    public static double SafetyBound(double bMax, double kappa) => kappa > 0 ? Math.Max(0, bMax) / kappa : 0;

    // ---- multi-agent budget algebra

    /// <summary>A sub-agent budget B_sub = alloc, guarded by 0 &lt;= alloc &lt;= parent.B.</summary>
    public static BudgetResult SubBudget(TrustBudget parent, double alloc)
    {
        if (!Fin(alloc) || alloc < 0) return new(false, null, "allocation must be finite and >= 0");
        if (alloc > parent.B) return new(false, null, "allocation exceeds parent remaining budget");
        return new(true, new[] { new TrustBudget(alloc, parent.Tau, parent.AsOf ?? parent.Tau) });
    }

    /// <summary>A sub-agent's debit ALSO debits the parent; fails (no state change) if either cannot cover <paramref name="c"/>. Nodes: parent, sub.</summary>
    public static BudgetResult DebitConsolidated(TrustBudget parent, TrustBudget sub, double c)
    {
        var x = Nz(c);
        if (sub.B < x) return new(false, null, "sub-agent budget insufficient");
        if (parent.B < x) return new(false, null, "parent budget insufficient");
        return new(true, new[] { Debit(parent, x), Debit(sub, x) });
    }

    /// <summary>A consolidated debit along a root-to-leaf budget path: every node must cover <paramref name="c"/>, else nothing is debited and the first offender is named.</summary>
    public static BudgetResult DebitConsolidatedPath(IReadOnlyList<TrustBudget> path, double c)
    {
        var x = Nz(c);
        for (int i = 0; i < path.Count; i++)
            if (!(path[i].B >= x)) return new(false, null, $"budget node at depth {i} insufficient (need {JsCanon.NumberString(x)}, have {JsCanon.NumberString(path[i].B)})");
        return new(true, path.Select(b => Debit(b, x)).ToList());
    }

    /// <summary>JavaScript <c>r.toFixed(3)</c> for r in [0, 1].</summary>
    public static string ToFixed3(double r)
    {
        // exact: r = m * 2^e, n = floor(r * 1000 + 1/2) with the tie going up, as JavaScript does (.NET rounds an exact tie to even)
        if (!double.IsFinite(r) || r < 0) return r.ToString("F3", CultureInfo.InvariantCulture);
        long bits = BitConverter.DoubleToInt64Bits(r);
        int exp = (int)((bits >> 52) & 0x7FF);
        var m = new System.Numerics.BigInteger(exp == 0 ? bits & 0xFFFFFFFFFFFFFL : (bits & 0xFFFFFFFFFFFFFL) | (1L << 52));
        int e = (exp == 0 ? 1 : exp) - 1075;
        System.Numerics.BigInteger n = e >= 0 ? (m << e) * 1000 : ((m * 2000) + (System.Numerics.BigInteger.One << -e)) >> (1 - e);
        return $"{n / 1000}.{(int)(n % 1000):D3}";
    }

    // ---- plan geodesic

    static string[] PreKeys => new[] { "after", "depends_on", "requires", "nodes" };
    static string[] PostKeys => new[] { "before", "enables", "then", "next" };

    static List<string> RefsOf(object? x, string[] keys)
    {
        var o = new List<string>();
        void Add(object? v)
        {
            if (v is string s) o.Add(s);
            else if (v is List<object?> l) foreach (var e in l) if (e is string t) o.Add(t);
        }
        Add(x);
        if (x is Dictionary<string, object?> d) foreach (var k in keys) Add(d.GetValueOrDefault(k));
        return o;
    }

    /// <summary>The normalised geodesic distance in the committed plan DAG, in [0,1] (an approximation, as the reference): edges come from node references
    /// (<c>pre</c> ids are predecessors, <c>post</c> ids successors); BFS hop count over the undirected graph divided by (n - 1); unreachable or an unknown
    /// node id is 1; no edges at all is the index distance |i - j| / (n - 1). The same node is 0.</summary>
    public static double PlanGeodesic(object? plan, string? fromId, string? toId)
    {
        if (plan is not List<object?> nodes || fromId == null || toId == null) return 1;
        var idx = new Dictionary<string, int>();
        for (int i = 0; i < nodes.Count; i++) if (nodes[i] is Dictionary<string, object?> nd && nd.GetValueOrDefault("id") is string id) idx[id] = i;
        if (!idx.TryGetValue(fromId, out var a) || !idx.TryGetValue(toId, out var b)) return 1;
        if (a == b) return 0;
        int n = nodes.Count;
        var adj = Enumerable.Range(0, n).Select(_ => new SortedSet<int>()).ToArray();
        int edges = 0;
        void Link(int i, int j)
        {
            if (i == j) return;
            if (!adj[i].Contains(j)) edges++;
            adj[i].Add(j); adj[j].Add(i);
        }
        var preKeys = PreKeys;
        var postKeys = PostKeys;
        for (int i = 0; i < n; i++)
        {
            if (nodes[i] is not Dictionary<string, object?> node) continue;
            foreach (var id in RefsOf(node.GetValueOrDefault("pre"), preKeys)) if (idx.TryGetValue(id, out var j)) Link(j, i);
            foreach (var id in RefsOf(node.GetValueOrDefault("post"), postKeys)) if (idx.TryGetValue(id, out var j)) Link(i, j);
        }
        if (edges == 0) return Clamp01(Math.Abs(a - b) / (double)(n - 1));
        var dist = Enumerable.Repeat(-1, n).ToArray();
        dist[a] = 0;
        var q = new List<int> { a };
        for (int h = 0; h < q.Count; h++)
        {
            var u = q[h];
            foreach (var v in adj[u]) if (dist[v] == -1) { dist[v] = dist[u] + 1; q.Add(v); }
        }
        return dist[b] < 0 ? 1 : Clamp01(dist[b] / (double)(n - 1));
    }
}
