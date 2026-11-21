// Budget planning of the reference (budget-forecast.ts): the policy parameters that give a target number of autonomous actions between two human co-signs,
// and the bound a policy states. Values are the JSON tree; a reference throw (a RangeError) is an exception.
using System.Globalization;
using AtlasPca.Js;
using AtlasPca.Research;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class BudgetForecast
{
    static object? PropOpt(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;

    static bool IsNumber(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d);

    static object NumOut(double d) => double.IsFinite(d) ? Facade.JsNumber(d) : d;

    /// <summary>JavaScript's <c>toFixed</c>: exact decimal digits (ties to the larger value); a magnitude of 1e21 or more is printed as <c>Number</c> does.</summary>
    static string Fixed(double d, int digits) => double.IsFinite(d) && Math.Abs(d) < 1e21 ? d.ToString("F" + digits, CultureInfo.InvariantCulture) : JsJson.NumberToString(d);

    /// <summary>The risk parameters for <paramref name="targetActions"/> autonomous actions of risk <paramref name="perActionRisk"/> (clamped to [1e-6, 1]) between two co-signs:
    /// <c>{kappa, bMax, autonomousBound, rationale}</c> with <c>bMax = n * r * kappa</c>. <paramref name="opts"/> may carry <c>kappa</c> (default 1). Throws
    /// <see cref="ArgumentOutOfRangeException"/> for a kappa that is not a positive finite number or a target or risk that is not finite.</summary>
    public static D RecommendPolicy(object? targetActions, object? perActionRisk, object? opts = null)
    {
        var kv = PropOpt(opts, "kappa");
        var kappaO = kv ?? Facade.JsNumber(1);
        if (!IsNumber(kappaO) || IntentJs.NumOf(kappaO) <= 0) throw new ArgumentOutOfRangeException(nameof(opts), "recommendPolicy: kappa must be a positive finite number");
        if (!IsNumber(targetActions) || !IsNumber(perActionRisk)) throw new ArgumentOutOfRangeException(nameof(targetActions), "recommendPolicy: targetActions and perActionRisk must be finite numbers");
        double kappa = IntentJs.NumOf(kappaO)!.Value;
        double r = Math.Max(1e-6, Math.Min(1, IntentJs.NumOf(perActionRisk)!.Value));
        double n = Math.Max(0, IntentJs.NumOf(targetActions)!.Value);
        double bMax = n * r * kappa;
        return new D
        {
            ["kappa"] = NumOut(kappa), ["bMax"] = NumOut(bMax), ["autonomousBound"] = NumOut(bMax / kappa),
            ["rationale"] = $"Σr ≤ bMax/κ = {Fixed(bMax / kappa, 3)} ≥ {JsJson.NumberToString(n)}×{Fixed(r, 3)} actions before a human co-sign",
        };
    }

    /// <summary>Forecast how the trust budget drains over a planned sequence of actions (each <c>{verb, resource, params?, at?}</c>; the replay of <see cref="PolicySim.Simulate"/>):
    /// <c>{steps: [{verb, resource, outcome, r, budgetAfter}], firstStepUpAt?, autonomousRisk, forcesCosign, cosignsNeeded, endBudget}</c>. <c>firstStepUpAt</c> is the index of the first
    /// step forced to a step-up (absent when none is); <c>cosignsNeeded</c> counts every step-up. <paramref name="catalog"/> null is the built-in one; a verb it does not know fails closed.</summary>
    public static D Forecast(CompiledPolicy policy, L plan, Catalog? catalog = null, double start = 0)
    {
        var rep = PolicySim.Simulate(policy, plan, catalog, start);
        var steps = new L();
        int first = -1;
        foreach (D r in (L)rep["results"]!)
        {
            var a = (D)r["action"]!;
            var s = new D();
            if (a.TryGetValue("verb", out var verb)) s["verb"] = verb;
            if (a.TryGetValue("resource", out var res)) s["resource"] = res;
            s["outcome"] = r["outcome"]; s["r"] = r["r"]; s["budgetAfter"] = r["budgetAfter"];
            if (first < 0 && r["outcome"] is "step_up") first = steps.Count;
            steps.Add(s);
        }
        var o = new D { ["steps"] = steps };
        if (first >= 0) o["firstStepUpAt"] = IntentJs.OfLong(first);
        o["autonomousRisk"] = rep["autonomousRisk"];
        o["forcesCosign"] = IntentJs.NumOf(rep["stepUp"]) > 0;
        o["cosignsNeeded"] = rep["stepUp"];
        o["endBudget"] = rep["endBudget"];
        return o;
    }

    /// <summary>The bound a policy states on the total risk of autonomous actions between two co-signs: <c>bMax / kappa</c>, 0 when kappa is not positive.</summary>
    public static double AutonomyBoundOf(object? policy) => SafetyCertificate.Bound(policy);
}
