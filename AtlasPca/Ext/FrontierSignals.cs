// Tighten-or-escalate typing of the intent-frontier results (the semantic judge threshold, objective risk, proof of progress).
//
// What those modules compute are PROXIES for "does this action serve the principal's goal": a judge ensemble's score, an embedding distance, a potential function. None of them
// is a judgement that may grant anything. This is the one place that turns each result into a signal (ok | escalate | deny), the value a tighten rule or a verifier gate may act
// on. A signal can only LOWER a decision; ok is the neutral element, never a grant. Every function is total: a missing, malformed or unrecognised result is deny, never ok.
// Results are parsed-JSON trees (Dictionary<string, object?>, bool, string, Num).
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public static class FrontierSignals
{
    public const string Ok = "ok", Escalate = "escalate", Deny = "deny";

    // a result counts only when it is a non-array object whose `ok` is a real boolean
    static bool Verdict(object? result, out bool ok)
    {
        ok = false;
        if (result is not D m || m.GetValueOrDefault("ok") is not bool b) return false;
        ok = b;
        return true;
    }

    /// <summary><c>ok</c> iff the ensemble met its quorum and the calibrated gate; a clean "not faithful" is <c>escalate</c> (ask a human); anything that is not a result is <c>deny</c>.</summary>
    public static string SemanticSignal(object? result) => !Verdict(result, out var ok) ? Deny : ok ? Ok : Escalate;

    /// <summary><c>ok</c> iff the step verified; an ok:false whose reason is exactly <c>exploration-exhausted</c> or <c>budget-exceeded</c> (not enough progress, a human may decide)
    /// escalates; every other denial (forgery, gap, mismatch, malformed) and anything that is not a result denies.</summary>
    public static string ProgressSignal(object? result)
    {
        if (!Verdict(result, out var ok)) return Deny;
        if (ok) return Ok;
        return ((D)result!).GetValueOrDefault("reason") is "exploration-exhausted" or "budget-exceeded" ? Escalate : Deny;
    }

    /// <summary>Objective risk: nothing committed (<c>none</c>) and a reproduced objective (<c>objective</c>) are <c>ok</c>; a mismatch is <c>ok</c> only when the grant's <c>onMismatch</c> is
    /// exactly <c>heuristic</c> (the server-held class baseline), else <c>deny</c>; anything else denies. A reproduced result adds no signal of its own: it enters the decision through
    /// <see cref="TightenRiskInputs"/>.</summary>
    public static string ObjectiveSignal(object? res)
    {
        if (res is not D m) return Deny;
        return m.GetValueOrDefault("mode") switch
        {
            "none" or "objective" => Ok,
            "mismatch" => m.GetValueOrDefault("onMismatch") is "heuristic" ? Ok : Deny,
            _ => Deny,
        };
    }

    // a tree number, keeping the sign of a zero
    static object NumberOf(double d) => double.IsNegative(d) && d == 0 ? new Num("-0") : Jx.N(d)!;

    /// <summary>Combine the server-held baseline risk inputs with the objective ones so the objective path can only RAISE risk: <c>reversibility</c> is the lower of the two and
    /// <c>blastRadius</c> the higher; when any of those four values (on either side) is not a finite number both become the worst case (0 and 1) together. <c>semanticDistance</c> is the
    /// objective's when a finite number, else 1 (for the caller to fold with the plan geodesic). No clamping. Throws on a null baseline or objective.</summary>
    public static D TightenRiskInputs(object? baseline, object? objective)
    {
        var br = Jx.Fin(Jx.Prop(baseline, "reversibility"));
        var orv = Jx.Fin(Jx.Prop(objective, "reversibility"));
        var bb = Jx.Fin(Jx.Prop(baseline, "blastRadius"));
        var ob = Jx.Fin(Jx.Prop(objective, "blastRadius"));
        var ok = br != null && orv != null && bb != null && ob != null;
        return new D
        {
            ["reversibility"] = ok ? NumberOf(Math.Min(br!.Value, orv!.Value)) : IntentJs.OfLong(0),
            ["blastRadius"] = ok ? NumberOf(Math.Max(bb!.Value, ob!.Value)) : IntentJs.OfLong(1),
            ["semanticDistance"] = Jx.Fin(Jx.Prop(objective, "semanticDistance")) is double sd ? NumberOf(sd) : IntentJs.OfLong(1),
        };
    }
}
