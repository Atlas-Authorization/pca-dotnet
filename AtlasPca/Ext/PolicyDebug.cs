// The replayable policy debugger: explains an admission decision by RE-RUNNING the pure decision core (PolicyVmDecide.Decide) and decomposing its arithmetic, and replays the
// core under single hypothetical changes ("if the blast radius were X", "if the human just co-signed", "if the budget were B"), reporting which change flips allow / deny or
// moves the required threshold. Deterministic and verifier-recomputable: nothing here is a logged guess. This is the Policy VM's explainer; it takes a decision input and is
// not the explanation of a verified PCActn of the explain package.
//
// A decision input is the parsed-JSON object PolicyVmDecide.Decide reads; a non-finite number in a tree is a double (NaN, Infinity), and the results spell one {"$num": "NaN"}.
using AtlasPca.Analyzer;
using AtlasPca.Authzen;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The verifier's per-check table of a PCActn and the decomposition of the admission decision for the same action.</summary>
public sealed record PolicyAudit(PcaCore.Result Verify, D Explanation);

public static class PolicyDebug
{
    static readonly string[] TermNames = { "semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age" };
    static readonly double[] Worst = { 1, 0, 1, 1, 0, 1 };
    static readonly string[] WeightNames = { "alpha", "beta", "gamma", "delta", "epsilon", "zeta" };
    static readonly bool[] Inverted = { false, true, false, false, true, false };

    static double Clamp01(double x) => x < 0 ? 0 : x > 1 ? 1 : x;
    static double Wt(object? x) => Jx.Fin(x) is double d && d > 0 ? d : 0;
    static double Nz(double x) => double.IsFinite(x) && x > 0 ? x : 0;
    static object NumOut(double d) => Jx.NumOut(d);
    static double Dv(object? x) => IntentJs.NumOf(x) ?? double.NaN;

    // one term of r = alpha*d + beta*(1-rev) + gamma*bl + delta*taint + epsilon*(1-conf) + zeta*age
    static (D Term, double Contribution) Term(int i, object? weightRaw, object? raw)
    {
        // a non-finite input is the worst case for its term (as decide fills it), never NaN and never the safe end of an inverted term
        var input = Jx.Fin(raw) is double f ? Clamp01(f) : Worst[i];
        var effective = Inverted[i] ? 1 - input : input;
        var weight = Wt(weightRaw);
        return (new D
        {
            ["term"] = TermNames[i], ["weight"] = NumOut(weight), ["input"] = NumOut(input), ["effective"] = NumOut(effective),
            ["contribution"] = NumOut(weight * effective), ["inverted"] = Inverted[i],
        }, weight * effective);
    }

    /// <summary>Decompose the risk score into its six additive terms (in the fixed order of the risk functional): <c>{inputs, weights, terms, rawSum, rScore, rFloor, r}</c> with
    /// <c>rawSum</c> the sum before the clamp to [0, 1], <c>rScore = clamp(rawSum)</c> and <c>r = max(rScore, rFloor)</c>. A non-finite <paramref name="rFloorIn"/> (or one that is not a
    /// number) is 0. <paramref name="inputs"/> and <paramref name="weights"/> are returned as given; throws on a null one.</summary>
    public static D ExplainRisk(object? inputs, object? weights, object? rFloorIn = null) => ExplainRiskCore(inputs, weights, Jx.Fin(rFloorIn) ?? 0);

    static D ExplainRiskCore(object? inputs, object? weights, double rFloor)
    {
        var terms = new L();
        double rawSum = 0;
        for (int i = 0; i < 6; i++)
        {
            var t = Term(i, Jx.Prop(weights, WeightNames[i]), Jx.Prop(inputs, TermNames[i]));
            terms.Add(t.Term);
            rawSum += t.Contribution;
        }
        var rScore = Clamp01(rawSum);
        return new D
        {
            ["inputs"] = inputs, ["weights"] = weights, ["terms"] = terms, ["rawSum"] = NumOut(rawSum), ["rScore"] = NumOut(rScore),
            ["rFloor"] = NumOut(Clamp01(rFloor)), ["r"] = NumOut(Math.Max(rScore, Clamp01(rFloor))),
        };
    }

    // ---- budget arithmetic over the tree (the members may be anything the input carries: numbers are read as JavaScript reads them) ----

    static object? Coalesce(object? a, object? b) => a == null || Jx.IsUndef(a) ? b : a;

    // leak(b, now, lambda): the budget after the passive leak up to now (idempotent at the same instant)
    static D Leak(object? budget, object? nowO, double lambda)
    {
        var tau = Jx.Prop(budget, "tau");
        var fromO = Coalesce(Jx.Prop(budget, "asOf"), tau);
        var nowFin = Jx.Fin(nowO) != null;
        var now = Jx.ToNumber(nowO);
        var from = Jx.ToNumber(fromO);
        var dt = nowFin && Jx.Fin(fromO) != null ? Math.Max(0, now - from) : 0;
        var b = Math.Max(0, Jx.ToNumber(Jx.Prop(budget, "B")) - Nz(lambda) * (dt / 1000));
        var o = new D { ["B"] = NumOut(b) };
        Jx.Set(o, "tau", tau);
        Jx.Set(o, "asOf", nowFin ? NumOut(Math.Max(now, from)) : fromO);
        return o;
    }

    static double AgeSinceTouch(object? tau, object? now, object? horizon)
    {
        var h = Jx.IsUndef(horizon) ? 3_600_000.0 : Jx.Fin(horizon) ?? double.NaN;
        if (Jx.Fin(now) is not double n || Jx.Fin(tau) is not double t || !(h > 0)) return 1;
        return Clamp01((n - t) / h);
    }

    static RiskPolicy PolicyOfEnvelope(D? env) => Risk.PolicyOf(env == null ? Issue.DefaultRiskPolicy() : env["risk_policy"])!;

    // the risk inputs exactly as decide resolves them (fail-closed fill, plan geodesic for a missing semantic distance, age from the budget)
    static (D Inputs, double RFloor, D Leaked) ResolveRiskInputs(object? input, D env, RiskPolicy pol)
    {
        var leaked = Leak(Jx.Prop(input, "budget"), Jx.Prop(input, "now"), pol.Lambda);
        var risk = Jx.Opt(input, "risk");
        var v = (double[])Worst.Clone();
        if (risk is D rm)
            for (int i = 0; i < 6; i++)
                if (rm.TryGetValue(TermNames[i], out var x) && Jx.Fin(x) is double d) v[i] = d;

        var nodeId = Jx.Prop(input, "nodeId");
        var plan = Jx.Prop(input, "plan");
        if (Jx.Truthy(plan) && Jx.IsUndef(Jx.Opt(risk, "semanticDistance")))
        {
            var goal = Jx.Prop(input, "goalNodeId");
            if (goal == null || Jx.IsUndef(goal)) goal = plan is L pl && pl.Count > 0 ? Jx.Opt(pl[^1], "id") : Jx.Undef;
            v[0] = !Jx.IsUndef(nodeId) && !Jx.IsUndef(goal) ? Risk.PlanGeodesic(plan, nodeId as string, goal as string) : 1;
        }
        if (Jx.IsUndef(Jx.Opt(risk, "age"))) v[5] = AgeSinceTouch(leaked.GetValueOrDefault("tau"), Jx.Prop(input, "now"), Jx.Prop(input, "ageHorizonMs"));

        var rFloor = Jx.Fin(Jx.Prop(input, "rFloor")) is double rf ? Math.Min(1, Math.Max(0, rf)) : 0;
        var inputs = new D();
        for (int i = 0; i < 6; i++) inputs[TermNames[i]] = NumOut(v[i]);
        return (inputs, rFloor, leaked);
    }

    /// <summary>Explain one decision: run <see cref="PolicyVmDecide.Decide"/> and decompose it. Result: <c>{decision, risk, requiredThreshold, t, autoAllow, needStepUp,
    /// releaseGuardianShare, budget: {before, leaked, after, cost, safetyBound}, reasons, envelopeValid}</c>; <c>risk</c> is <see cref="ExplainRisk"/> of the inputs
    /// the decision resolved. A grant without a valid envelope was denied by the decision (risk 1): the explanation keeps that shape, with no terms. Throws only when the
    /// input is null.</summary>
    public static D ExplainDecision(object? input)
    {
        var decision = PolicyVmDecide.Decide(input);
        var env = Pca.ReadEnvelope(Jx.Prop(input, "grant"));
        var pol = PolicyOfEnvelope(env);
        var dr = (D)decision["requiredThreshold"]!;
        var r = Dv(decision["r"]);

        D risk;
        object? leaked;
        if (env != null)
        {
            var res = ResolveRiskInputs(input, env, pol);
            leaked = res.Leaked;
            risk = ExplainRiskCore(res.Inputs, ((D)env["risk_policy"]!)["weights"], res.RFloor);
        }
        else
        {
            // fail-closed denial: decide returned r = 1; keep the shape coherent
            var worst = new D();
            for (int i = 0; i < 6; i++) worst[TermNames[i]] = NumOut(Worst[i]);
            var zero = new D();
            foreach (var w in WeightNames) zero[w] = NumOut(0);
            leaked = Jx.Prop(input, "budget");
            risk = new D { ["inputs"] = worst, ["weights"] = zero, ["terms"] = new L(), ["rawSum"] = decision["r"], ["rScore"] = decision["r"], ["rFloor"] = NumOut(0), ["r"] = decision["r"] };
        }

        var budget = new D();
        Jx.Set(budget, "before", Jx.Prop(input, "budget"));
        Jx.Set(budget, "leaked", leaked);
        Jx.Set(budget, "after", decision["budget"]);
        budget["cost"] = NumOut(Risk.Cost(r, pol.Kappa));
        budget["safetyBound"] = NumOut(Risk.SafetyBound(pol.BMax, pol.Kappa));

        return new D
        {
            ["decision"] = decision, ["risk"] = risk, ["requiredThreshold"] = dr, ["t"] = dr["t"], ["autoAllow"] = decision["admit"], ["needStepUp"] = decision["needStepUp"],
            ["releaseGuardianShare"] = decision["releaseGuardianShare"], ["budget"] = budget, ["reasons"] = decision["reasons"], ["envelopeValid"] = env != null,
        };
    }

    // ---- counterfactuals ----

    static bool HumanCosignFull(object? hc) => hc is D m && m.TryGetValue("full", out var f) && f is true;

    /// <summary>The hypothetical decision input a delta denotes (the input is not mutated). A delta overlays <c>risk</c>, <c>budget</c> and <c>caveatContext</c> members,
    /// replaces <c>rFloor</c> and <c>now</c>, and with <c>humanCosign</c> (true, or <c>{full}</c>) first recharges the budget as a human co-sign does (+rho, or the whole of bMax when
    /// <c>full</c>), which also resets the human-touch time.</summary>
    public static D ApplyDelta(object? input, object? delta)
    {
        var d = delta;
        var now = Coalesce(Jx.Prop(d, "now"), Jx.Prop(input, "now"));
        var budget = JsX.Spread(Jx.Prop(input, "budget"));
        Overlay(budget, Jx.Prop(d, "budget"));
        var hc = Jx.Prop(d, "humanCosign");
        if (Jx.Truthy(hc))
        {
            var pol = PolicyOfEnvelope(Pca.ReadEnvelope(Jx.Prop(input, "grant")));
            var b = HumanCosignFull(hc) ? Nz(pol.BMax) : Math.Min(Nz(pol.BMax), Jx.ToNumber(budget.GetValueOrDefault("B", Jx.Undef)) + Nz(pol.Rho));
            budget = new D { ["B"] = NumOut(b) };
            Jx.Set(budget, "tau", now);
            Jx.Set(budget, "asOf", now);
        }
        var next = JsX.Spread(input);
        Jx.Set(next, "now", now);
        next["budget"] = budget;
        var risk = JsX.Spread(Jx.Prop(input, "risk"));
        Overlay(risk, Jx.Prop(d, "risk"));
        next["risk"] = risk;
        var cc = JsX.Spread(Jx.Prop(input, "caveatContext"));
        Overlay(cc, Jx.Prop(d, "caveatContext"));
        next["caveatContext"] = cc;
        var rf = Jx.Prop(d, "rFloor");
        if (!Jx.IsUndef(rf)) next["rFloor"] = rf;
        return next;
    }

    // `...(x ?? {})`: the members of x laid over the target
    static void Overlay(D target, object? x)
    {
        if (x == null || Jx.IsUndef(x)) return;
        foreach (var (k, v) in JsX.Spread(x)) target[k] = v;
    }

    static string Describe(object? d)
    {
        var label = Jx.Prop(d, "label");
        if (Jx.Truthy(label)) return JsX.Str(label);
        var parts = new List<string>();
        var hc = Jx.Prop(d, "humanCosign");
        if (Jx.Truthy(hc)) parts.Add(HumanCosignFull(hc) ? "human re-confirms goal (B←Bmax)" : "human co-signs (B+ρ)");
        var risk = Jx.Prop(d, "risk");
        if (Jx.Truthy(risk)) foreach (var k in JsX.Keys(risk)) parts.Add($"{k}={JsX.Str(Jx.Prop(risk, k))}");
        var bud = Jx.Prop(d, "budget");
        if (Jx.Truthy(bud)) foreach (var k in JsX.Keys(bud)) parts.Add($"budget.{k}={JsX.Str(Jx.Prop(bud, k))}");
        var rf = Jx.Prop(d, "rFloor");
        if (!Jx.IsUndef(rf)) parts.Add($"caution={JsX.Str(rf)}");
        var nw = Jx.Prop(d, "now");
        if (!Jx.IsUndef(nw)) parts.Add($"now={JsX.Str(nw)}");
        var cc = Jx.Prop(d, "caveatContext");
        if (Jx.Truthy(cc)) foreach (var k in JsX.Keys(cc)) parts.Add($"ctx.{k}={JsJson.Stringify(Jx.Prop(cc, k))}");
        return parts.Count > 0 ? string.Join(", ", parts) : "no-op";
    }

    /// <summary>Replay the decision under each hypothetical single change of <paramref name="deltas"/>: <c>{baseline, outcomes, flipping, thresholdChanging}</c>. An outcome is
    /// <c>{label, delta, explanation, flipsAllow, allow, thresholdDirection (raised|lowered|same), changesThreshold, t, rDelta}</c>; <c>flipping</c> and <c>thresholdChanging</c> name the
    /// changes that flip the autonomous allow or move the threshold. A pure re-run of the decision core, not a guess.</summary>
    public static D Counterfactual(object? input, object? deltas)
    {
        var baseline = ExplainDecision(input);
        if (deltas is not L list) throw JsX.TypeError("deltas.map is not a function");
        var bt = Dv(baseline["t"]);
        var br = Dv(((D)baseline["risk"]!)["r"]);
        var outcomes = new L();
        var flipping = new L();
        var changing = new L();
        foreach (var d in list)
        {
            var exp = ExplainDecision(ApplyDelta(input, d));
            var t = Dv(exp["t"]);
            var dir = t > bt ? "raised" : t < bt ? "lowered" : "same";
            var label = Describe(d);
            var flips = !Equals(exp["autoAllow"], baseline["autoAllow"]);
            outcomes.Add(new D
            {
                ["label"] = label, ["delta"] = d, ["explanation"] = exp, ["flipsAllow"] = flips, ["allow"] = exp["autoAllow"], ["thresholdDirection"] = dir,
                ["changesThreshold"] = dir != "same", ["t"] = exp["t"], ["rDelta"] = NumOut(Dv(((D)exp["risk"]!)["r"]) - br),
            });
            if (flips) flipping.Add(label);
            if (dir != "same") changing.Add(label);
        }
        return new D { ["baseline"] = baseline, ["outcomes"] = outcomes, ["flipping"] = flipping, ["thresholdChanging"] = changing };
    }

    /// <summary>The full audit of a PCActn: the verifier's per-check table (<see cref="PcaCore.Verify"/>) and the decomposition of the admission decision for the same action
    /// (<paramref name="input"/> should be derived from the same PCActn by <see cref="PolicyVmDecide.DeriveDecideInput"/>, so the audit reflects what the admission path saw).</summary>
    public static PolicyAudit AuditPCActn(object? pcactn, object? input, PcaCore.Options options) => new(PcaCore.Verify(pcactn, options), ExplainDecision(input));
}
