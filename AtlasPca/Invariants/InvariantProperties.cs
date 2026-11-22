using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Invariants;

/// <summary>A named safety property: <see cref="Generate"/> draws one case's arguments from the property's stream, <see cref="Check"/> returns true for a passing
/// case (any violation, or a throw, is a failure).</summary>
public sealed record InvariantProperty(string Name, Func<InvariantsRng, object[]> Generate, Func<object[], bool> Check);

/// <summary>The outcome of one invariant (<see cref="InvariantProperties.CheckInvariants"/>); a failure carries the first counterexample.</summary>
public sealed record InvariantResult(string Name, bool Ok, int NumRuns, long Seed, string? Error = null);

/// <summary>Options of <see cref="InvariantProperties.CheckInvariants"/>: iterations per invariant (default 1000), the PRNG seed (default 20260108) and stop-at-first-failure.</summary>
public sealed record CheckInvariantsOptions(int NumRuns = PcaInvariants.DefaultNumRuns, long Seed = PcaInvariants.DefaultSeed, bool Bail = false);

/// <summary>The PCA core safety invariants as runnable property checks plus the <see cref="CheckInvariants"/> runner, over the REAL native core (nothing is
/// re-implemented): attenuation monotonicity, budget soundness, fail-closed behaviour and determinism. Cases come from one <see cref="InvariantsRng"/> stream per
/// property (seeded from the seed and the property's index), <c>NumRuns</c> cases each; a failure is reported without shrinking.</summary>
public static class InvariantProperties
{
    const double Eps = 1e-9;
    static readonly HashSet<string> KnownCaveatTypes = new() { "expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth", "budget_alloc", "max_spend", "intent_session" };
    static readonly string[] Mutations = { "tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch", "break-id", "append-forged-hop" };

    // ---- helpers ----------------------------------------------------------------------

    static L AsList(IEnumerable<D> caps) => new(caps);

    static bool Verifies(IEnumerable<D> caps, string? issuer) => Pca.VerifyChain(AsList(caps), issuer, issuer != null).Ok;

    /// <summary>Effective authority of a hop at a probe point: the envelope predicates AND every caveat satisfied.</summary>
    static bool AuthAllowed(object? caveats, object? predicates, EvalPoint pt) =>
        Predicates.EvaluatePredicates(predicates, pt.Action) && Caveats.EvaluateCaveats(caveats, pt.CavCtx).Ok;

    /// <summary>Caveats of <paramref name="child"/> must begin with the full caveat array of <paramref name="parent"/> (append-only, order-preserving).</summary>
    static bool PrefixExtension(D parent, D child)
    {
        if (parent.GetValueOrDefault("caveats") is not L pc || child.GetValueOrDefault("caveats") is not L cc || cc.Count < pc.Count) return false;
        for (var j = 0; j < pc.Count; j++)
            if (Pca.HashCanonical(cc[j]) != Pca.HashCanonical(pc[j])) return false;
        return true;
    }

    static List<double> AllocLimits(L caveats)
    {
        var o = new List<double>();
        foreach (var cv in caveats)
            if (cv is D d && d.GetValueOrDefault("type") as string == "budget_alloc" && d.GetValueOrDefault("limit") is Num or long or int or double)
                o.Add(JsJson.ToJsNumber(d["limit"]));
        return o;
    }

    static D Ctx(string verb, string resource, D? subject = null, D? env = null)
    {
        var c = new D { ["action"] = new D { ["verb"] = verb, ["resource"] = resource } };
        if (subject != null) c["subject"] = subject;
        if (env != null) c["env"] = env;
        return c;
    }

    static D PolicyTree(RiskPolicy p)
    {
        static Num F(double d) => new(JsJson.NumberToString(d));
        return new D
        {
            ["weights"] = new D { ["alpha"] = F(p.Alpha), ["beta"] = F(p.Beta), ["gamma"] = F(p.Gamma), ["delta"] = F(p.Delta), ["epsilon"] = F(p.Epsilon), ["zeta"] = F(p.Zeta) },
            ["theta1"] = F(p.Theta1), ["theta2"] = F(p.Theta2), ["kappa"] = F(p.Kappa), ["lambda"] = F(p.Lambda), ["rho"] = F(p.Rho), ["bMax"] = F(p.BMax),
        };
    }

    static RiskInputs Worse(RiskInputs i, RiskDeltas d)
    {
        var w = PcaInvariants.Worsen(new RiskAxes(i.SemanticDistance, i.BlastRadius, i.Taint, i.Age, i.Reversibility, i.Confidence), d);
        return new RiskInputs(w.SemanticDistance, w.Reversibility, w.BlastRadius, w.Taint, w.Confidence, w.Age);
    }

    static D CloneD(D d)
    {
        var o = new D();
        foreach (var kv in d) o[kv.Key] = CloneV(kv.Value);
        return o;
    }

    static object? CloneV(object? v) => v switch
    {
        D d => CloneD(d),
        L l => new L(l.Select(CloneV)),
        _ => v,
    };

    static List<D> CloneCaps(IEnumerable<D> caps) => caps.Select(CloneD).ToList();

    static L CavsOf(D cap) => (L)cap["caveats"]!;

    // ---- 1. attenuation monotonicity --------------------------------------------------

    /// <summary>For any legal chain: it verifies, each hop's caveats extend its parent's, <c>budget_alloc</c> limits never grow, and per-hop authority never widens root to leaf.</summary>
    public static InvariantProperty AttenuationMonotonicityProperty() => new("attenuation-monotonicity",
        g =>
        {
            var model = InvariantArbitraries.ArbChainModel(g);
            var points = new List<EvalPoint>();
            for (var n = g.Int(1, 5); n > 0; n--) points.Add(InvariantArbitraries.ArbEvalPoint(g));
            return new object[] { model, points };
        },
        a =>
        {
            var chain = PcaInvariants.BuildChain((ChainModel)a[0]);
            var points = (List<EvalPoint>)a[1];
            var caps = chain.Caps;
            if (!Verifies(caps, chain.RootIssuer)) return false;
            for (var i = 1; i < caps.Count; i++)
                if (!PrefixExtension(caps[i - 1], caps[i])) return false;
            var leaf = caps[^1];
            if (Pca.AllocationsMonotone(leaf["caveats"]) != null) return false;
            var limits = AllocLimits(CavsOf(leaf));
            for (var i = 1; i < limits.Count; i++)
                if (limits[i] > limits[i - 1]) return false;
            foreach (var pt in points)
            {
                var ancestorAllowed = true;
                foreach (var cap in caps)
                {
                    var allowed = AuthAllowed(cap["caveats"], chain.Predicates, pt);
                    if (allowed && !ancestorAllowed) return false; // a true after a false would be a widening
                    ancestorAllowed = allowed;
                }
            }
            return true;
        });

    // ---- 2. budget soundness ----------------------------------------------------------

    /// <summary>The risk functional is clamped to [0, 1] and monotone: a pointwise-worse input never yields a lower r.</summary>
    public static InvariantProperty RiskMonotoneProperty() => new("risk-wellformed-and-monotone",
        g => new object[] { InvariantArbitraries.ArbRiskPolicy(g), InvariantArbitraries.ArbRiskInputs(g), InvariantArbitraries.ArbRiskDeltas(g) },
        a =>
        {
            var (policy, inputs, deltas) = ((RiskPolicy)a[0], (RiskInputs)a[1], (RiskDeltas)a[2]);
            var r = Risk.Score(inputs, policy);
            if (!(r >= 0 && r <= 1)) return false;
            var rWorse = Risk.Score(Worse(inputs, deltas), policy);
            if (!(rWorse >= 0 && rWorse <= 1)) return false;
            return rWorse + Eps >= r;
        });

    /// <summary>Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget; and the safety bound is exactly bMax / kappa.</summary>
    public static InvariantProperty AdmissionSoundnessProperty() => new("admission-soundness",
        g => new object[] { InvariantArbitraries.ArbRiskPolicy(g), InvariantArbitraries.ArbRiskInputs(g), InvariantArbitraries.ArbTrustBudget(g) },
        a =>
        {
            var (policy, inputs, budget) = ((RiskPolicy)a[0], (RiskInputs)a[1], (TrustBudget)a[2]);
            if (Pca.ValidateRiskPolicy(PolicyTree(policy)) != null) return false; // the generated policy must be well formed (self-check of the generator)
            var r = Risk.Score(inputs, policy);
            var c = Risk.Cost(r, policy.Kappa);
            var adm = Risk.Admit(r, budget, policy);
            if (adm.Metered && (adm.T >= 3 || !(budget.B + Eps >= c))) return false;
            if (adm.Admit && (adm.T != 1 || !adm.Metered || !(budget.B + Eps >= c))) return false;
            var expected = policy.Kappa > 0 ? Math.Max(0, policy.BMax) / policy.Kappa : 0;
            return Math.Abs(Risk.SafetyBound(policy.BMax, policy.Kappa) - expected) <= Eps;
        });

    /// <summary>From a full budget, any sequence of machine-only actions debiting kappa*r never overdraws and keeps Sum(r) &lt;= bMax / kappa.</summary>
    public static InvariantProperty CumulativeBudgetBoundProperty() => new("cumulative-budget-bound",
        g =>
        {
            var policy = InvariantArbitraries.ArbRiskPolicy(g);
            var seq = new List<RiskInputs>();
            for (var n = g.Int(1, 40); n > 0; n--) seq.Add(InvariantArbitraries.ArbRiskInputs(g));
            return new object[] { policy, seq };
        },
        a =>
        {
            var (policy, seq) = ((RiskPolicy)a[0], (List<RiskInputs>)a[1]);
            var bound = Risk.SafetyBound(policy.BMax, policy.Kappa);
            var b = Math.Max(0, policy.BMax); // fresh recharge: B0 = bMax
            var sumR = 0.0;
            foreach (var inputs in seq)
            {
                var r = Risk.Score(inputs, policy);
                var adm = Risk.Admit(r, new TrustBudget(b, 0, 0), policy);
                if (!adm.Metered || adm.T >= 3) continue;
                var c = Risk.Cost(r, policy.Kappa);
                if (!(b + Eps >= c)) return false; // admit only returns metered once B >= c
                b = Math.Max(0, b - c);
                sumR += r;
                if (b < -Eps) return false;
                if (!(policy.Kappa * sumR <= policy.BMax + 1e-6) || !(sumR <= bound + 1e-6)) return false;
            }
            return true;
        });

    // ---- 3. fail closed ---------------------------------------------------------------

    /// <summary>Every structurally undecidable leaf evaluates to unknown (never true), so a predicate carrying it never grants.</summary>
    public static InvariantProperty UndecidableLeafFailsClosedProperty() => new("fail-closed:undecidable-leaf",
        g => new object[] { (int)g.Int(0, 4), g.Pick(new[] { "read", "write", "delete" }) },
        a =>
        {
            var (pick, verb) = ((int)a[0], (string)a[1]);
            const string f = "subject.role";
            var leaf = pick switch
            {
                0 => new D { ["field"] = f + ".definitely_absent", ["op"] = "eq", ["value"] = "x" }, // missing field
                1 => new D { ["field"] = f, ["op"] = "lt", ["value"] = 5L }, // string field against a number: incomparable
                2 => new D { ["field"] = f, ["op"] = "in", ["value"] = "not-an-array" }, // non-array operand
                3 => new D { ["field"] = f, ["op"] = "eq" }, // no value and no ref
                _ => new D { ["field"] = f, ["op"] = "member_of", ["value"] = "g", ["collection"] = "env.no_such_collection" }, // missing collection
            };
            var ctx = Ctx(verb, "/x", new D { ["role"] = "admin" });
            if (Predicates.EvaluateConditionTri(leaf, ctx) == Predicates.Tri.True) return false;
            if (Predicates.EvaluateCondition(leaf, ctx)) return false;
            var pred = new D { ["verb"] = verb, ["resource"] = "/x", ["where"] = new L { leaf } };
            return !Predicates.EvaluatePredicates(new L { pred }, ctx);
        });

    /// <summary>not / all_of / any_of over undecidable or empty children fail closed (never true).</summary>
    public static InvariantProperty UndecidableGroupsFailClosedProperty() => new("fail-closed:undecidable-groups",
        _ => new object[] { 0 },
        _ =>
        {
            var ctx = Ctx("read", "/x", new D { ["role"] = "admin" });
            var bad = new D { ["field"] = "subject.role", ["op"] = "lt", ["value"] = 5L }; // a string compared with lt to a number
            foreach (var c in new D[] { new() { ["not"] = bad }, new() { ["all_of"] = new L() }, new() { ["any_of"] = new L() }, new() { ["all_of"] = new L { bad } }, new() { ["any_of"] = new L { bad } } })
                if (Predicates.EvaluateConditionTri(c, ctx) == Predicates.Tri.True) return false;
            return true;
        });

    /// <summary>member_of over a cyclic adjacency terminates with a correct verdict; an unreachable target fails closed.</summary>
    public static InvariantProperty MemberOfCycleSafeProperty() => new("fail-closed:member-of-cycle-safe",
        g => new object[] { g.Pick(new[] { "a", "b", "c", "z" }) },
        a =>
        {
            var target = (string)a[0];
            // a -> b -> a is a cycle; c hangs off b; z is absent
            var rel = new D { ["a"] = new L { "b" }, ["b"] = new L { "a", "c" } };
            var ctx = Ctx("read", "/x", new D { ["g"] = "a" }, new D { ["rel"] = rel });
            var tri = Predicates.EvaluateConditionTri(new D { ["field"] = "subject.g", ["op"] = "member_of", ["value"] = target, ["collection"] = "env.rel" }, ctx);
            return tri == (target is "a" or "b" or "c" ? Predicates.Tri.True : Predicates.Tri.False);
        });

    /// <summary>An unknown caveat type is never satisfied, so a caveat set containing it is never ok.</summary>
    public static InvariantProperty UnknownCaveatTypeDeniesProperty() => new("fail-closed:unknown-caveat-type",
        g =>
        {
            string type;
            do type = g.String(1, 12); while (KnownCaveatTypes.Contains(type));
            return new object[] { type, g.IntB(0, InvariantArbitraries.MaxTime) };
        },
        a =>
        {
            var cav = new D { ["type"] = (string)a[0] };
            var ctx = new D { ["now"] = (long)a[1] };
            return !Caveats.Satisfied(cav, ctx) && !Caveats.EvaluateCaveats(new L { cav }, ctx).Ok;
        });

    /// <summary>A legal chain mutated by one of nine attacks never verifies.</summary>
    public static InvariantProperty ForgedChainRejectedProperty() => new("fail-closed:forged-chain-rejected",
        g => new object[] { InvariantArbitraries.ArbChainModel(g), g.Pick(Mutations), (int)g.IntB(0, 1_000_000), InvariantArbitraries.ArbSeed32(g) },
        a =>
        {
            var chain = PcaInvariants.BuildChain((ChainModel)a[0]);
            var (mutation, pick, auxSeed) = ((string)a[1], (int)a[2], (byte[])a[3]);
            var caps = chain.Caps;
            if (!Verifies(caps, chain.RootIssuer)) return false; // the pristine chain must verify
            var n = caps.Count;
            var idx = pick % n;
            var aux = PcaInvariants.KeyPairFromSeed(auxSeed);
            bool Rejected(IEnumerable<D> m, string issuer) => !Verifies(m, issuer);
            switch (mutation)
            {
                case "tamper-caveat":
                {
                    var m = CloneCaps(caps);
                    var cv = new L(CavsOf(m[idx])) { new D { ["type"] = "expires", ["at"] = 999L } };
                    m[idx]["caveats"] = cv;
                    return Rejected(m, chain.RootIssuer);
                }
                case "drop-leaf-caveat":
                {
                    var m = CloneCaps(caps);
                    var cv = CavsOf(m[n - 1]);
                    if (cv.Count == 0) return true; // inapplicable: trivially pass
                    m[n - 1]["caveats"] = cv.GetRange(0, cv.Count - 1);
                    return Rejected(m, chain.RootIssuer);
                }
                case "swap-holder":
                {
                    var m = CloneCaps(caps);
                    m[idx]["holder"] = aux.Pub;
                    return Rejected(m, chain.RootIssuer);
                }
                case "break-parent":
                {
                    if (n < 2) return true; // no non-root hop to detach
                    var m = CloneCaps(caps);
                    m[Math.Max(1, idx)]["parent"] = Pca.HashCanonical(new D { ["bogus"] = (long)auxSeed.Length, ["tag"] = "not-a-real-parent" });
                    return Rejected(m, chain.RootIssuer);
                }
                case "bad-sig":
                {
                    var m = CloneCaps(caps);
                    using var k = EdKey.FromSeed(auxSeed);
                    m[idx]["sig"] = Pca.B64u(k.Sign(new byte[] { 1, 2, 3, 4 })); // well formed, but over other bytes by another key
                    return Rejected(m, chain.RootIssuer);
                }
                case "wrong-root-issuer":
                    return aux.Pub == chain.RootIssuer || Rejected(caps, aux.Pub);
                case "suite-mismatch":
                {
                    var m = CloneCaps(caps);
                    m[idx]["alg"] = "ml-dsa-65"; // the suite is bound into body_digest
                    return Rejected(m, chain.RootIssuer);
                }
                case "break-id":
                {
                    var m = CloneCaps(caps);
                    m[idx]["id"] = Pca.HashCanonical(new D { ["not"] = "the-body-digest", ["n"] = (long)idx });
                    return Rejected(m, chain.RootIssuer);
                }
                case "append-forged-hop":
                {
                    // issued as if from the leaf, but signed by a key that is NOT the leaf's holder
                    using var k = EdKey.FromSeed(auxSeed);
                    using var signer = SuiteKey.Ed25519(k);
                    var forged = Issue.Delegate(caps[n - 1], aux.Pub, new L(), signer);
                    return Rejected(caps.Append(forged), chain.RootIssuer);
                }
            }
            return false; // an unknown mutation name (cannot happen: fail closed)
        });

    /// <summary>Well-typed but never-signed chains (including the empty chain) never verify.</summary>
    public static InvariantProperty GarbageChainRejectedProperty() => new("fail-closed:garbage-chain-rejected",
        g =>
        {
            var caps = new List<D>();
            for (var n = g.Int(0, 4); n > 0; n--)
            {
                var cv = new L();
                for (var m = g.Int(0, 3); m > 0; m--) cv.Add(new D { ["type"] = g.String(0, 10) });
                caps.Add(new D { ["id"] = g.String(0, 10), ["issuer"] = g.String(0, 10), ["holder"] = g.String(0, 10), ["caveats"] = cv, ["body_digest"] = g.String(0, 10), ["sig"] = g.String(0, 10) });
            }
            return new object[] { caps };
        },
        a => !Verifies((List<D>)a[0], null));

    // ---- 4. determinism ---------------------------------------------------------------

    /// <summary>verifyChain, predicates, caveats, risk score, threshold and admission are all deterministic.</summary>
    public static InvariantProperty DeterminismProperty() => new("determinism",
        g => new object[] { InvariantArbitraries.ArbChainModel(g), InvariantArbitraries.ArbEvalPoint(g), InvariantArbitraries.ArbPredicateList(g),
            InvariantArbitraries.ArbRiskPolicy(g), InvariantArbitraries.ArbRiskInputs(g), InvariantArbitraries.ArbTrustBudget(g) },
        a =>
        {
            var chain = PcaInvariants.BuildChain((ChainModel)a[0]);
            var (pt, preds, policy, inputs, budget) = ((EvalPoint)a[1], (L)a[2], (RiskPolicy)a[3], (RiskInputs)a[4], (TrustBudget)a[5]);
            var v1 = Pca.VerifyChain(AsList(chain.Caps), chain.RootIssuer, true);
            var v2 = Pca.VerifyChain(AsList(chain.Caps), chain.RootIssuer, true);
            if (v1.Ok != v2.Ok || v1.Why != v2.Why) return false;
            if (Predicates.EvaluatePredicates(preds, pt.Action) != Predicates.EvaluatePredicates(preds, pt.Action)) return false;
            var leaf = chain.Caps[^1];
            var c1 = Caveats.EvaluateCaveats(leaf["caveats"], pt.CavCtx);
            var c2 = Caveats.EvaluateCaveats(leaf["caveats"], pt.CavCtx);
            if (c1.Ok != c2.Ok || string.Join("|", c1.Failed) != string.Join("|", c2.Failed)) return false;
            var r1 = Risk.Score(inputs, policy);
            var r2 = Risk.Score(inputs, policy);
            if (!r1.Equals(r2)) return false;
            if (Risk.Required(r1, policy.Theta1, policy.Theta2) != Risk.Required(r1, policy.Theta1, policy.Theta2)) return false;
            return Risk.Admit(r1, budget, policy) == Risk.Admit(r1, budget, policy);
        });

    /// <summary>Forbid-wins is monotone and order-independent: adding a forbid never moves a decision up, a matching forbid always denies, clause order is irrelevant.</summary>
    public static InvariantProperty ForbidMonotoneProperty() => new("forbid-monotone",
        g => new object[] { InvariantArbitraries.ArbPredicateList(g), InvariantArbitraries.ArbPredicateList(g), InvariantArbitraries.ArbPredicateList(g), InvariantArbitraries.ArbEvalPoint(g), (int)g.Int(0, 5) },
        a =>
        {
            var (permits, forbids, extra, pt, rot) = ((L)a[0], (L)a[1], (L)a[2], (EvalPoint)a[3], (int)a[4]);
            static int Rank(string d) => d switch { "deny" => 0, "escalate" => 1, _ => 2 };
            static IEnumerable<object?> Mk(string kind, L ps, string tag) => ps.Select((when, i) => (object?)new D { ["id"] = tag + i, ["kind"] = kind, ["when"] = when });
            var bas = Mk("permit", permits, "p").Concat(Mk("escalate", extra, "e")).ToList();
            var withForbid = bas.Concat(Mk("forbid", forbids, "f")).ToList();
            var before = Forbid.Decide(new L(bas), pt.Action).Decision;
            var after = Forbid.Decide(new L(withForbid), pt.Action).Decision;
            if (Rank(after) > Rank(before)) return false; // adding a forbid must never grow the admit set
            if (forbids.Any(w => Prohibitions.WhenMatches(w, pt.Action)) && after != "deny") return false; // a matching forbid beats every permit
            var k = rot % withForbid.Count;
            var rotated = withForbid.Skip(k).Concat(withForbid.Take(k)).ToList();
            return Forbid.Decide(new L(rotated), pt.Action).Decision == after; // order independent
        });

    // ---- registry and runner ----------------------------------------------------------

    /// <summary>Every invariant, in the reference's order.</summary>
    public static IReadOnlyList<InvariantProperty> All() => new[]
    {
        AttenuationMonotonicityProperty(), RiskMonotoneProperty(), AdmissionSoundnessProperty(), CumulativeBudgetBoundProperty(),
        UndecidableLeafFailsClosedProperty(), UndecidableGroupsFailClosedProperty(), MemberOfCycleSafeProperty(), UnknownCaveatTypeDeniesProperty(),
        ForgedChainRejectedProperty(), GarbageChainRejectedProperty(), ForbidMonotoneProperty(), DeterminismProperty(),
    };

    /// <summary>The first failing case of <paramref name="p"/> over <paramref name="numRuns"/> cases of stream <paramref name="index"/>, as a message; null when every case passes. A check that throws is a failure.</summary>
    public static string? Run(InvariantProperty p, int index, int numRuns, long seed)
    {
        var g = InvariantsRng.ForProperty(seed, index);
        for (var i = 0; i < numRuns; i++)
        {
            var args = p.Generate(g);
            string? error = null;
            bool ok;
            try { ok = p.Check(args); }
            catch (Exception e) { ok = false; error = e.GetType().Name + ": " + e.Message; }
            if (!ok) return $"invariant {p.Name} failed at case {i} (seed {seed})" + (error == null ? "" : ": " + error);
        }
        return null;
    }

    /// <summary>Machine-checks every PCA safety invariant. A zero (or negative) <c>NumRuns</c> would pass vacuously and is refused.</summary>
    public static IReadOnlyList<InvariantResult> CheckInvariants(CheckInvariantsOptions? opts = null)
    {
        opts ??= new CheckInvariantsOptions();
        if (opts.NumRuns < 1) throw new ArgumentOutOfRangeException(nameof(opts), "checkInvariants: numRuns must be a positive integer");
        var results = new List<InvariantResult>();
        var all = All();
        for (var index = 0; index < all.Count; index++)
        {
            var err = Run(all[index], index, opts.NumRuns, opts.Seed);
            results.Add(new InvariantResult(all[index].Name, err == null, opts.NumRuns, opts.Seed, err));
            if (err != null && opts.Bail) break;
        }
        return results;
    }
}
