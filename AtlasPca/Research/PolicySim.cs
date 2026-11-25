// Policy simulation and linting. Before a principal enables a grant, replay a batch of historical or hypothetical actions against the compiled policy (which auto-admit,
// which force a human step-up, which are denied) and run static lints for the classic mistakes. Pure, offline, mutating and signing nothing: it composes the compiled
// policy's predicates and caveats with the trust-budget algebra. A planning tool: the resource server's verifier remains the authority at run time.
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Research;

public static class PolicySim
{
    static Num N(double d) => new(JsX.JsNumString(d));
    static Num N(long l) => IntentJs.OfLong(l);
    static double Clamp01(double x) => Math.Max(0.0, Math.Min(1.0, x));
    static double Num_(object? o) => IntentJs.NumOf(o) ?? double.NaN;
    static readonly string[] ReversibilityOrder = { "reversible", "rate_limited", "irreversible" };
    static int Sev(string cls) => Array.IndexOf(ReversibilityOrder, cls);

    // the risk of one action: amount / kappa in the dollars model, else the catalog's blast radius (0.8 for a verb it does not know)
    static double RiskOf(CompiledPolicy policy, Catalog catalog, string? verb, D? prms)
    {
        var spec = verb == null ? null : catalog.Get(verb);
        var kappa = Num_(policy.RiskPolicy.GetValueOrDefault("kappa"));
        if (policy.BudgetModel == "dollars" && spec?.AmountField is { Length: > 0 } f)
        {
            var amt = Actions.JsNumber(prms?.GetValueOrDefault(f), prms != null && prms.ContainsKey(f));
            if (double.IsFinite(amt) && kappa > 0) return Clamp01(amt / kappa);
        }
        return Clamp01(spec?.BlastRadius ?? 0.8);
    }

    static D Result(object? action, string outcome, int? t, double r, string? reason, double budgetAfter)
    {
        var m = new D { ["action"] = action, ["outcome"] = outcome };
        if (t != null) m["t"] = N((long)t.Value);
        m["r"] = N(r);
        if (reason != null) m["reason"] = reason;
        m["budgetAfter"] = N(budgetAfter);
        return m;
    }

    /// <summary>Replay <paramref name="actions"/> (each <c>{verb, resource, params?, at?}</c>) in time order against the policy, threading the trust budget as the server
    /// would (leak between actions; debit kappa * r on every metered admit; step-up when the budget cannot cover a machine-band action). An action with no finite time is
    /// reported as denied, not skipped or guessed; an action without one is timed <c>start + index</c>. <paramref name="catalog"/> null is the built-in one.
    /// Returns <c>{results, auto, stepUp, deny, endBudget, peakRisk, autonomousRisk}</c>.</summary>
    public static D Simulate(CompiledPolicy policy, L actions, Catalog? catalog = null, double start = 0)
    {
        var cat = catalog ?? Catalog.Default;
        var timed = new List<(D A, double At)>();
        for (int i = 0; i < actions.Count; i++)
        {
            var a = (D)actions[i]!;
            var at = a.GetValueOrDefault("at");
            timed.Add((a, at != null ? (IntentJs.IsFinite(at) ? Num_(at) : double.NaN) : start + i));
        }
        var rp = Risk.PolicyOf(policy.RiskPolicy)!;
        var budget = new TrustBudget(Num_(policy.RiskPolicy["bMax"]), start, start);
        var results = new L();
        foreach (var (a, at) in timed) if (!double.IsFinite(at)) results.Add(Result(a, "deny", null, 1.0, "action has no finite time", budget.B));
        var ordered = timed.Where(x => double.IsFinite(x.At)).OrderBy(x => x, Comparer<(D A, double At)>.Create((x, y) => Math.Sign(x.At - y.At))).ToList();

        var recent = new List<double>();
        double peakRisk = 0, autonomousRisk = 0;
        foreach (var (a, at) in ordered)
        {
            var verb = a.GetValueOrDefault("verb") as string;
            var spec = verb == null ? null : cat.Get(verb);
            var prms = a.GetValueOrDefault("params") as D;
            var rev = spec?.Reversibility ?? "irreversible";
            var ctx = new D { ["action"] = new D { ["verb"] = a.GetValueOrDefault("verb"), ["resource"] = a.GetValueOrDefault("resource"), ["params"] = prms ?? new D(), ["reversibility_class"] = rev } };
            var r = RiskOf(policy, cat, verb, prms);
            peakRisk = Math.Max(peakRisk, r);

            var denial = Pca.EnvelopePredicates(policy.Predicates, ctx);
            Caveats.Result? cav = null;
            if (denial == null)
                cav = Caveats.EvaluateCaveats(policy.Caveats, new D
                {
                    ["now"] = Facade.JsNumber(at), ["blast_radius"] = Facade.JsNumber(spec?.BlastRadius ?? 1.0), ["reversibility_class"] = rev,
                    ["recent_action_times"] = new L(recent.Select(t => Facade.JsNumber(t))),
                });
            budget = Risk.Leak(budget, at, Num_(policy.RiskPolicy["lambda"]));

            if (denial != null) { results.Add(Result(a, "deny", null, r, denial, budget.B)); continue; }
            if (!cav!.Ok) { results.Add(Result(a, "deny", null, r, "caveat(s) failed: " + string.Join(", ", cav.Failed), budget.B)); continue; }
            var adm = Risk.Admit(r, budget, rp);
            if (adm.T == 1 && adm.Admit)
            {
                budget = budget with { B = budget.B - Risk.Cost(r, rp.Kappa) };
                autonomousRisk += r;
                recent.Add(at);
                results.Add(Result(a, "auto", 1, r, null, budget.B));
            }
            else
            {
                // t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view
                results.Add(Result(a, "step_up", adm.T, r, adm.NeedStepUp ? $"requires tier {adm.T}" : null, budget.B));
            }
        }
        long auto = 0, stepUp = 0, deny = 0;
        foreach (D m in results)
            switch (m["outcome"]) { case "auto": auto++; break; case "step_up": stepUp++; break; default: deny++; break; }
        return new D
        {
            ["results"] = results, ["auto"] = N(auto), ["stepUp"] = N(stepUp), ["deny"] = N(deny),
            ["endBudget"] = N(budget.B), ["peakRisk"] = N(peakRisk), ["autonomousRisk"] = N(autonomousRisk),
        };
    }

    static D Lint(string level, string code, string message) => new() { ["level"] = level, ["code"] = code, ["message"] = message };

    /// <summary>Static lints over a compiled policy as <c>[{level, code, message}]</c>: <c>error</c> = almost certainly a mistake (a limit that matches no granted action),
    /// <c>warn</c> = a real risk worth a second look, <c>info</c> = a notable but intentional property.</summary>
    public static L LintPolicy(CompiledPolicy policy, Catalog? catalog = null)
    {
        var cat = catalog ?? Catalog.Default;
        var lints = new L();
        var granted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in policy.Actions) { granted.Add(s.Verb); granted.Add(s.Action); foreach (var al in s.Aliases) granted.Add(al); }
        foreach (var key in IntentJs.JsKeys(policy.InputLimits.Keys))
            if (!granted.Contains(key)) lints.Add(Lint("error", "limit-unmatched", $"limit for '{key}' matches no granted action"));

        foreach (var spec in policy.Actions)
        {
            var pred = policy.Predicates.OfType<D>().FirstOrDefault(p => p.GetValueOrDefault("verb") is string v && v == spec.Verb);
            var broad = pred == null || pred.GetValueOrDefault("resource") is not string { Length: > 0 } res || res == "*";
            if (spec.AmountField is { Length: > 0 } && !policy.Limits.Any(l => l.Key == spec.Verb))
                lints.Add(Lint("warn", "money-unbounded", $"money action '{spec.Verb}' has no per-call limit — spend is bounded only by the trust budget"));
            if (broad && Sev(spec.Reversibility) >= Sev("rate_limited"))
                lints.Add(Lint("warn", "broad-resource", $"'{spec.Verb}' ({spec.Reversibility}) matches ANY resource — consider a resource prefix"));
            if (cat.Get(spec.Verb) == null)
                lints.Add(Lint("info", "uncatalogued", $"'{spec.Verb}' is not in the catalog — treated conservatively (irreversible, high blast radius)"));
        }

        // the budget never forces a human: every within-cap action auto-admits (t=1) - intentional for a capped autonomous agent, but worth stating
        var theta2 = Num_(policy.RiskPolicy.GetValueOrDefault("theta2"));
        var bMax = Num_(policy.RiskPolicy.GetValueOrDefault("bMax"));
        var kappa = Num_(policy.RiskPolicy.GetValueOrDefault("kappa"));
        if (theta2 >= 1)
        {
            var hasIrrev = policy.Actions.Any(s => Sev(s.Reversibility) >= Sev("irreversible"));
            lints.Add(Lint(hasIrrev ? "warn" : "info", "no-step-up-band",
                "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted" + (hasIrrev ? " — including irreversible actions" : "")));
        }
        if (kappa > 0 && bMax / kappa > 100)
            lints.Add(Lint("warn", "large-autonomy", $"autonomous bound is {JsX.JsNumString(Math.Floor(bMax / kappa + 0.5))}× a max-risk action between human co-signs"));
        return lints;
    }
}
