// Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor, and
// the regret of a choice the grant admits (the utility is the principal's, supplied by the caller).
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.IntentPkg;

public static class IntentProvenance
{
    static readonly string[] FrictionOrder = { "tap", "hold", "typed", "device" };

    /// <summary>The fixed banner for a tainted value (web / agent / tool); null for trusted and first-party values.</summary>
    public static string? ProvenanceBanner(string level, string? what = null)
    {
        var w = what ?? "value";
        return level switch
        {
            "web" => $"This {w} was suggested by content on the page, not by you.",
            "agent" => $"This {w} came from your agent, not from you or the site.",
            "tool" => $"This {w} came from another service, not from you or this site.",
            _ => null,
        };
    }

    /// <summary>True for the tainted levels (tool, web, agent).</summary>
    public static bool IsTainted(string level) => level is "tool" or "web" or "agent";

    /// <summary>The friction a value needs: the maximum of <paramref name="baseTier"/> and the provenance floor (tainted critical: typed; tainted material: hold; else tap).</summary>
    public static string ProvenanceFriction(string baseTier, string sensitivity, string level)
    {
        var floor = !IsTainted(level) ? "tap" : sensitivity == "critical" ? "typed" : "hold";
        return FrictionOrder[Math.Max(Array.IndexOf(FrictionOrder, baseTier), Array.IndexOf(FrictionOrder, floor))];
    }

    /// <summary>One choice: the options feasible at the time, the chosen one, membership in the effective grant and the principal's utility.</summary>
    public sealed record RegretCase(IReadOnlyList<Outcome> Feasible, Outcome Chosen, Func<Outcome, bool> Admits, Func<Outcome, double> Utility);

    static (double Regret, Outcome? Best, bool Admitted) Evaluate(RegretCase c)
    {
        bool admitted = c.Admits(c.Chosen);
        Outcome? best = null;
        double bestU = double.NegativeInfinity;
        foreach (var o in c.Feasible)
        {
            if (!c.Admits(o)) continue;
            double u = c.Utility(o);
            if (u > bestU) { bestU = u; best = o; }
        }
        return (!admitted || best == null ? 0.0 : Math.Max(0, bestU - c.Utility(c.Chosen)), best, admitted);
    }

    /// <summary>Within-grant regret of one choice: {regret, best, admitted}. Only options inside the grant compete.</summary>
    public static D WithinGrantRegret(RegretCase c)
    {
        var (regret, best, admitted) = Evaluate(c);
        return new D { ["regret"] = N(regret), ["best"] = best == null ? null : OutcomeToJson(best), ["admitted"] = admitted };
    }

    /// <summary>Aggregate regret: {cases, admitted, positive, mean, max, regret_est_ppm} (ppm of the utility scale <paramref name="scale"/>).</summary>
    public static D RegretReport(IReadOnlyList<RegretCase> cases, double scale = 1)
    {
        int admitted = 0, positive = 0;
        double sum = 0, max = 0;
        foreach (var c in cases)
        {
            var (reg, _, adm) = Evaluate(c);
            if (!adm) continue;
            admitted++;
            sum += reg;
            if (reg > 0) positive++;
            if (reg > max) max = reg;
        }
        double mean = admitted > 0 ? sum / admitted : 0;
        return new D
        {
            ["cases"] = N(cases.Count), ["admitted"] = N(admitted), ["positive"] = N(positive), ["mean"] = N(mean), ["max"] = N(max),
            ["regret_est_ppm"] = N(IntentMath.JsRound((mean / (scale > 0 ? scale : 1)) * 1_000_000)),
        };
    }
}
