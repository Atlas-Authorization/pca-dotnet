using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Invariants;

/// <summary>One point at which to probe a chain's effective authority: an action context and a caveat-evaluation context.</summary>
public sealed record EvalPoint(D Action, D CavCtx);

/// <summary>The six risk weights (each finite and &gt;= 0).</summary>
public sealed record RiskWeights(double Alpha, double Beta, double Gamma, double Delta, double Epsilon, double Zeta);

/// <summary>Generators of WELL-FORMED random inputs for the PCA core: Ed25519 seeds and key pairs, multi-hop chain models whose every hop legally
/// attenuates (turned into signed chains by <see cref="PcaInvariants.BuildChain"/>), predicates, action and caveat contexts, risk policies / inputs /
/// budgets / deltas. Each draws from an <see cref="InvariantsRng"/> stream, so a run is reproducible from (seed, property index). Values are the verifier's
/// JSON model (dictionaries, lists, strings, long, bool, Num); everything is pure data handed to the real core.</summary>
public static class InvariantArbitraries
{
    public static readonly IReadOnlyList<string> Verbs = new[] { "read", "write", "delete", "transfer", "list", "admin" };
    public static readonly IReadOnlyList<string> Resources = new[] { "/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/" };
    static readonly IReadOnlyList<string> LeafOps = new[] { "eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists" };
    static readonly IReadOnlyList<string> LeafFields = new[] { "subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount" };
    static readonly IReadOnlyList<string> Reversibility = new[] { "reversible", "rate_limited", "irreversible", "teleport" };
    static readonly IReadOnlyList<string> SpecReversibility = new[] { "reversible", "rate_limited", "irreversible" };
    public const long MaxTime = 10_000_000;

    /// <summary>A fractional JSON number (the canonical form is the shortest JavaScript rendering).</summary>
    static Num Fx(double d) => new(JsJson.NumberToString(d));

    // ---- keys -------------------------------------------------------------------------

    /// <summary>32 random bytes: a reproducible Ed25519 secret seed (any 32 bytes is valid).</summary>
    public static byte[] ArbSeed32(InvariantsRng g) => g.Bytes(32);

    public static GenKeyPair ArbKeyPair(InvariantsRng g) => PcaInvariants.KeyPairFromSeed(ArbSeed32(g));

    // ---- predicates -------------------------------------------------------------------

    public static string ArbVerb(InvariantsRng g) => g.Pick(Verbs);

    public static string ArbResource(InvariantsRng g) => g.Bool() ? g.Pick(Resources) : g.String(0, 10);

    static L Strings(InvariantsRng g, int min, int max)
    {
        var l = new L();
        for (var n = g.Int(min, max); n > 0; n--) l.Add(g.String(0, 10));
        return l;
    }

    /// <summary>A decidable, well-formed leaf comparison.</summary>
    public static D ArbLeafCondition(InvariantsRng g)
    {
        var field = g.Pick(LeafFields);
        var op = g.Pick(LeafOps);
        object? value = g.Int(0, 3) switch
        {
            0 => g.String(0, 10),
            1 => g.IntB(-10, 10),
            2 => g.Bool(),
            _ => Strings(g, 0, 3),
        };
        return new D { ["field"] = field, ["op"] = op, ["value"] = value };
    }

    public static D ArbCondition(InvariantsRng g) => ArbLeafCondition(g);

    public static D ArbPredicate(InvariantsRng g)
    {
        object verb = g.Int(0, 2) switch
        {
            0 => ArbVerb(g),
            1 => ArbVerbList(g),
            _ => "*",
        };
        string? resource = g.Int(0, 3) switch
        {
            0 => null,
            1 => "*",
            2 => g.Pick(new[] { "/acct/*", "/docs/*" }),
            _ => ArbResource(g),
        };
        L? where = null;
        if (g.Bool())
        {
            where = new L();
            for (var n = g.Int(0, 2); n > 0; n--) where.Add(ArbCondition(g));
        }
        var p = new D { ["verb"] = verb };
        if (resource != null) p["resource"] = resource;
        if (where != null) p["where"] = where;
        return p;
    }

    static L ArbVerbList(InvariantsRng g)
    {
        var l = new L();
        for (var n = g.Int(1, 3); n > 0; n--) l.Add(ArbVerb(g));
        return l;
    }

    /// <summary>1..4 predicates.</summary>
    public static L ArbPredicateList(InvariantsRng g)
    {
        var l = new L();
        for (var n = g.Int(1, 4); n > 0; n--) l.Add(ArbPredicate(g));
        return l;
    }

    // ---- action + caveat contexts -----------------------------------------------------

    /// <summary>An action context <c>{action: {verb, resource, params?}, subject?, env?}</c>.</summary>
    public static D ArbActionContext(InvariantsRng g)
    {
        var action = new D { ["verb"] = ArbVerb(g), ["resource"] = ArbResource(g) };
        if (g.Bool())
        {
            var ps = new D();
            foreach (var k in new[] { "amount", "target", "reason" })
                if (g.Bool())
                    ps[k] = g.Int(0, 2) switch { 0 => g.String(0, 10), 1 => g.IntB(-5, 100), _ => (object)g.Bool() };
            action["params"] = ps;
        }
        var role = g.Pick(new[] { "admin", "user", "guest" });
        var tier = g.IntB(0, 5);
        var ip = g.String(0, 10);
        var withSubject = g.Bool();
        var withEnv = g.Bool();
        var ctx = new D { ["action"] = action };
        if (withSubject) ctx["subject"] = new D { ["role"] = role, ["tier"] = tier };
        if (withEnv) ctx["env"] = new D { ["ip"] = ip };
        return ctx;
    }

    /// <summary>A caveat-evaluation context (every optional member present or absent), in the native snake_case member names.</summary>
    public static D ArbCaveatContext(InvariantsRng g)
    {
        var ctx = new D { ["now"] = g.IntB(0, MaxTime) };
        if (g.Bool()) ctx["blast_radius"] = g.Dbl(0.0, 1.0);
        if (g.Bool()) ctx["reversibility_class"] = g.Pick(Reversibility);
        if (g.Bool()) ctx["delegation_depth"] = g.IntB(0, 20);
        if (g.Bool())
        {
            var times = new L();
            for (var n = g.Int(0, 6); n > 0; n--) times.Add(g.IntB(0, MaxTime));
            ctx["recent_action_times"] = times;
        }
        return ctx;
    }

    public static EvalPoint ArbEvalPoint(InvariantsRng g) => new(ArbActionContext(g), ArbCaveatContext(g));

    // ---- attenuating delegation chains ------------------------------------------------

    /// <summary>A built-in, evaluator-decidable caveat spec (<c>budget_frac</c> is materialised monotone by <see cref="PcaInvariants.BuildChain"/>).</summary>
    public static D ArbCaveatSpec(InvariantsRng g) => g.Int(0, 6) switch
    {
        0 => new D { ["k"] = "expires", ["at"] = g.IntB(0, MaxTime) },
        1 => new D { ["k"] = "not_before", ["at"] = g.IntB(0, MaxTime) },
        2 => new D { ["k"] = "rate", ["max"] = g.IntB(1, 10), ["per_secs"] = g.IntB(1, 3600) },
        // quantized to 3 decimals so the limit is canonical-wire-safe
        3 => new D { ["k"] = "max_blast_radius", ["max"] = Fx(g.IntB(0, 1000) / 1000.0) },
        4 => new D { ["k"] = "reversibility_max", ["cls"] = g.Pick(SpecReversibility) },
        5 => new D { ["k"] = "delegation_depth", ["max"] = g.IntB(0, 20) },
        _ => new D { ["k"] = "budget_frac", ["frac"] = Fx(g.Dbl(0.0, 1.0)) },
    };

    static List<D> Specs(InvariantsRng g, int min, int max)
    {
        var l = new List<D>();
        for (var n = g.Int(min, max); n > 0; n--) l.Add(ArbCaveatSpec(g));
        return l;
    }

    /// <summary>The model of a legal chain, the input of <see cref="PcaInvariants.BuildChain"/>.</summary>
    public static ChainModel ArbChainModel(InvariantsRng g)
    {
        var principal = ArbSeed32(g);
        var holder0 = ArbSeed32(g);
        var rootSpecs = Specs(g, 1, 4);
        var hops = new List<HopModel>();
        for (var n = g.Int(0, 5); n > 0; n--) hops.Add(new HopModel(ArbSeed32(g), Specs(g, 0, 3)));
        return new ChainModel(principal, holder0, rootSpecs, hops, ArbPredicateList(g));
    }

    /// <summary>A generated, signed, legally-attenuating chain.</summary>
    public static GeneratedChain ArbChain(InvariantsRng g) => PcaInvariants.BuildChain(ArbChainModel(g));

    // ---- risk policy / inputs / budget ------------------------------------------------

    public static RiskWeights ArbRiskWeights(InvariantsRng g) =>
        new(g.Dbl(0, 2), g.Dbl(0, 2), g.Dbl(0, 2), g.Dbl(0, 2), g.Dbl(0, 2), g.Dbl(0, 2));

    /// <summary>A well-formed policy: kappa &gt; 0, 0 &lt;= theta1 &lt;= theta2, the rest finite and &gt;= 0.</summary>
    public static RiskPolicy ArbRiskPolicy(InvariantsRng g)
    {
        var w = ArbRiskWeights(g);
        var theta1 = g.Dbl(0, 1);
        var gap = g.Dbl(0, 1);
        return new RiskPolicy(w.Alpha, w.Beta, w.Gamma, w.Delta, w.Epsilon, w.Zeta, theta1, theta1 + gap, g.Dbl(0.001, 5), g.Dbl(0, 0.01), g.Dbl(0, 2), g.Dbl(0, 10));
    }

    public static RiskInputs ArbRiskInputs(InvariantsRng g) =>
        new(g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1));

    public static TrustBudget ArbTrustBudget(InvariantsRng g)
    {
        var b = g.Dbl(0, 10);
        var tau = g.IntB(0, MaxTime);
        return g.Bool() ? new TrustBudget(b, tau, g.IntB(0, MaxTime)) : new TrustBudget(b, tau);
    }

    /// <summary>Non-negative deltas that build a pointwise-WORSE risk input.</summary>
    public static RiskDeltas ArbRiskDeltas(InvariantsRng g) => new(g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1), g.Dbl(0, 1));
}
