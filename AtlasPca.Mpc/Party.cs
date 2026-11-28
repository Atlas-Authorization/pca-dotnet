using System.Globalization;
using AtlasPca.Authzen;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc;

/// <summary>Per-stakeholder local evaluation: each party distills its own Policy VM result to a small decision vector.</summary>
public static class Party
{
    public const int DEFAULT_Q = 100;

    /// <summary>The decision a party contributes to the MPC: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}.</summary>
    public sealed record DecisionVector(int Allow, int T, int RQuant);

    /// <summary>Quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q).</summary>
    public static int QuantizeR(double r, int Q = DEFAULT_Q)
    {
        if (double.IsNaN(r) || double.IsInfinity(r)) return Q;
        // floor(x + 0.5) matches JS Math.round for the non-negative values reached here
        long q = (long)Math.Floor(Math.Max(0, Math.Min(1, r)) * Q + 0.5);
        return (int)Math.Max(0, Math.Min(Q, q));
    }

    static double Dbl(object? v) => v switch
    {
        Num n => double.Parse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture),
        int i => i,
        long l => l,
        double d => d,
        _ => double.NaN,
    };

    /// <summary>Evaluates a party's own decide input through the Policy VM to its decision vector.</summary>
    public static DecisionVector EvaluateParty(D decideInput, int Q = DEFAULT_Q)
    {
        var d = PolicyVmDecide.Decide(decideInput);
        var thr = (D)d["requiredThreshold"]!;
        return new DecisionVector(
            d["releaseGuardianShare"] is true ? 1 : 0,
            (int)Dbl(thr["t"]),
            QuantizeR(Dbl(d.GetValueOrDefault("r")), Q));
    }
}
