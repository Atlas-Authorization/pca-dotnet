// Thin adapters binding the two mechanisms to the PCA bookkeeping they replace (packages/pca-ratchet adapters.ts): the ratchet leaf index is the
// PCActn spend-once counter, and the accumulator's integer units are the quantized control-theoretic risk budget (RiskPolicy.bMax / kappa).
using System.Globalization;
using System.Numerics;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Ratchet;

public static class RatchetAdapters
{
    /// <summary>Fixed-point scale quantizing a core risk score (r in [0, 1]) into accumulator units: 1000 = millirisk resolution.</summary>
    public const int RiskScale = 1000;

    static void CheckDepth(object? depth)
    {
        if (IntentJs.NumOf(depth) is not double d || !double.IsFinite(d) || Math.Floor(d) != d || d < 1 || d > Ggm.MaxRatchetDepth)
            throw new RatchetError("invalid_depth", $"depth must be an integer in [1, {Ggm.MaxRatchetDepth}]");
    }

    /// <summary>Map a PCActn's spend-once counter to a ratchet leaf index: spending counter c signs (and punctures) leaf c, so a counter can never
    /// be re-used. The depth is checked first, then the counter (a non-negative safe integer, not -0, below 2^depth).</summary>
    public static long CounterToLeafIndex(object? counter, object? depth)
    {
        CheckDepth(depth);
        if (!IntentJs.IsNonNeg(counter)) throw new RatchetError("leaf_out_of_range", "counter must be a non-negative safe integer");
        long c = IntentJs.Lng(counter);
        int dp = (int)IntentJs.NumOf(depth)!.Value;
        if (c >= 1L << dp) throw new RatchetError("leaf_out_of_range", $"counter {c} exceeds the ratchet capacity 2^{dp}");
        return c;
    }

    /// <summary>Inverse of <see cref="CounterToLeafIndex"/>: a leaf index is the spend-once counter it realizes.</summary>
    public static long LeafIndexToCounter(object? leafIndex)
    {
        if (!IntentJs.IsNonNeg(leafIndex)) throw new RatchetError("leaf_out_of_range", "leafIndex must be a non-negative safe integer");
        return IntentJs.Lng(leafIndex);
    }

    /// <summary>The ratchet leaf index of a PCActn, read off its <c>counter</c> member (a null action throws, like reading a member of null).</summary>
    public static long LeafIndexForAction(object? actn, object? depth)
    {
        if (actn == null) throw new InvalidOperationException("Cannot read properties of null (reading 'counter')");
        return CounterToLeafIndex(IntentJs.Get(actn, "counter"), depth);
    }

    /// <summary>JavaScript Math.round: ties go towards +infinity.</summary>
    static double JsRound(double x)
    {
        var f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    /// <summary>Quantize a core risk score (any finite r >= 0) to non-negative integer units, ROUNDING UP (a nonzero risk is never 0 units; a sum of
    /// quantized risks never under-counts the true sum). A value within float noise of an exact unit keeps that unit.</summary>
    public static BigInteger RiskToUnits(object? r)
    {
        if (IntentJs.NumOf(r) is not double x || !double.IsFinite(x) || x < 0) throw new AccumulatorError("invalid_value", "risk must be a finite number >= 0");
        var v = x * RiskScale;
        var nearest = JsRound(v);
        if (Math.Abs(v - nearest) <= 1e-9 * Math.Max(1, v)) return new BigInteger(nearest);
        return new BigInteger(Math.Ceiling(v)); // an infinite product (r near 1.8e305) overflows, like BigInt(Infinity) throws
    }

    /// <summary>Carry-forward quantizer: emits per-action integer units whose running total is ALWAYS ceil(sum of true risk * scale), never below the
    /// true cumulative sum and over by less than one unit in total. Stateful: one instance per budget stream.</summary>
    public sealed class RiskQuantizer
    {
        static readonly BigInteger Nano = 1_000_000;
        BigInteger _nano = BigInteger.Zero;
        BigInteger _emitted = BigInteger.Zero;

        public BigInteger Next(object? r)
        {
            if (IntentJs.NumOf(r) is not double x || !double.IsFinite(x) || x < 0) throw new AccumulatorError("invalid_value", "risk must be a finite number >= 0");
            // r * scale in millionths of a unit, rounded UP so the total can only over-approximate
            double a = x * RiskScale;
            double b = a * 1e6;
            double c = b - 1e-3;
            _nano += new BigInteger(Math.Ceiling(c));
            var total = (_nano + Nano - 1) / Nano;
            var o = total - _emitted;
            _emitted = total;
            return o;
        }

        public BigInteger TotalUnits => _emitted;
    }

    /// <summary>JavaScript ToNumber over the parsed JSON tree (an absent member is NaN; arrays and objects are treated as NaN).</summary>
    static double ToNumber(object? v, bool present)
    {
        if (!present) return double.NaN;
        switch (v)
        {
            case null: return 0;
            case bool b: return b ? 1 : 0;
            case string s:
                {
                    var t = s.Trim();
                    if (t.Length == 0) return 0;
                    return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;
                }
        }
        return IntentJs.NumOf(v) ?? double.NaN;
    }

    /// <summary>The accumulator's budget ceiling in integer units, from a RiskPolicy: the core safety bound sum(risk) &lt;= bMax / kappa, quantized, so
    /// the zero-knowledge budget proof proves the SAME inequality the control plane enforces. A null policy throws.</summary>
    public static BigInteger BudgetCeilingUnits(object? policy)
    {
        if (policy == null) throw new InvalidOperationException("Cannot read properties of null (reading 'kappa')");
        var m = policy as JD;
        bool hasK = m != null && m.ContainsKey("kappa"), hasB = m != null && m.ContainsKey("bMax");
        double kappa = ToNumber(hasK ? m!["kappa"] : null, hasK);
        double bMax = ToNumber(hasB ? m!["bMax"] : null, hasB);
        double bound = kappa > 0 ? Math.Max(0, bMax) / kappa : 0;
        if (!double.IsFinite(bound) || bound < 0) throw new AccumulatorError("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0");
        return new BigInteger(Math.Floor(bound * RiskScale));
    }
}
