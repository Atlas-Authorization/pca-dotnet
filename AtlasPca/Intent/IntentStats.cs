// Exact Clopper-Pearson upper bounds (integer arithmetic on the 2^-52 grid), the floating-point binomial CDF used for starting
// guesses, Hoeffding half-widths and Wilson intervals. Logarithms and exponentials come from the fdlibm ports of IntentMath
// (the reference engine's), square roots are exact, so every double matches the reference bit for bit.
using System.Numerics;

namespace AtlasPca.IntentPkg;

public static class IntentStats
{
    public const int CpGridBits = 52;
    public static readonly double CpTolerance = Math.ScaleB(1.0, -44);

    static readonly BigInteger A = BigInteger.One << CpGridBits;
    static readonly BigInteger TolUnits = BigInteger.One << (CpGridBits - 44);

    /// <summary>The exact binary fraction <c>Num / 2^Exp</c> of a double in (0, 1).</summary>
    public sealed record Dyadic(BigInteger Num, int Exp);

    /// <summary>A bound on the 2^-52 grid with its certified bracket.</summary>
    public sealed record CpCertificate(double Upper, BigInteger UpperUnits, BigInteger LowerUnits);

    public sealed record Bracket(BigInteger Hi, BigInteger Lo);

    public sealed record Wilson(double P, double Lo, double Hi);

    public static double[] LogFactorials(int n)
    {
        var lf = new double[n + 1];
        for (int i = 1; i <= n; i++) lf[i] = lf[i - 1] + IntentMath.Log(i);
        return lf;
    }

    /// <summary>P(X &lt;= k), X ~ Binomial(n, p), in floating point (guesses and diagnostics only).</summary>
    public static double BinomialCdf(double k, double n, double p, double[]? lf = null)
    {
        if (k >= n) return 1;
        if (k < 0) return 0;
        if (p <= 0) return 1;
        if (p >= 1) return 0;
        int ni = (int)n;
        lf ??= LogFactorials(ni);
        double lp = IntentMath.Log(p);
        double lq = IntentMath.Log1p(-p);
        double s = 0;
        for (int i = 0; i <= k; i++) s += IntentMath.Exp(lf[ni] - lf[i] - lf[ni - i] + i * lp + (ni - i) * lq);
        return Math.Min(1, s);
    }

    public static Dyadic DoubleToDyadic(double x)
    {
        if (!(double.IsFinite(x) && x > 0 && x < 1)) throw new ArgumentException("doubleToDyadic: need 0 < x < 1");
        int e = 0;
        double y = x;
        while (y != Math.Floor(y))
        {
            y *= 2;
            e++;
            if (e > 1100) throw new ArgumentException("doubleToDyadic: not reached");
        }
        return new Dyadic(new BigInteger(y), e);
    }

    /// <summary>N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the definition.</summary>
    public static BigInteger CdfRecNumerator(int n, int k, BigInteger a)
    {
        if (a.Sign < 0 || a > A) throw new ArgumentException("cdfRecNumerator: a must be in [0, 2^52]");
        var b = A - a;
        int kk = Math.Min(k, n);
        if (kk < 0) throw new ArgumentException("cdfRecNumerator: bad k");
        var row = new BigInteger[kk + 1];
        Array.Fill(row, BigInteger.One);
        var pow = BigInteger.One;
        for (int m = 0; m < n; m++)
        {
            var next = new BigInteger[kk + 1];
            var powNext = pow * A;
            for (int j = 0; j <= kk; j++)
            {
                if (j >= m + 1) next[j] = powNext;
                else
                {
                    var left = j == 0 ? BigInteger.Zero : row[j - 1];
                    next[j] = a * left + b * row[j];
                }
            }
            row = next;
            pow = powNext;
        }
        return row[kk];
    }

    /// <summary>Exactly decides alpha &lt; cdfRec(a / 2^52, n, k).</summary>
    public static bool CdfExceeds(int n, int k, BigInteger a, Dyadic alpha)
    {
        var num = CdfRecNumerator(n, k, a);
        return num * (BigInteger.One << alpha.Exp) > alpha.Num * BigInteger.Pow(A, n);
    }

    static double FloatGuess(int k, int n, double alpha)
    {
        var lf = LogFactorials(n);
        double lo = (double)k / n;
        double hi = 1;
        for (int it = 0; it < 200 && hi - lo > 1e-13; it++)
        {
            double mid = (lo + hi) / 2;
            if (BinomialCdf(k, n, mid, lf) > alpha) lo = mid;
            else hi = mid;
        }
        return hi;
    }

    static BigInteger Clamp(BigInteger a) => a.Sign < 0 ? BigInteger.Zero : a > A ? A : a;

    static bool IsInt(double d) => double.IsFinite(d) && d == Math.Floor(d);

    /// <summary>The exact one-sided Clopper-Pearson upper bound with its certificate: upper - 2^-44 &lt;= the exact bound &lt;= upper.</summary>
    public static CpCertificate ClopperPearsonCertified(double kD, double nD, double alpha)
    {
        if (!(IsInt(kD) && IsInt(nD) && kD >= 0 && nD >= 0 && kD <= nD)) throw new ArgumentException("clopperPearsonUpper: need integers 0 <= k <= n");
        if (!(alpha > 0 && alpha < 1)) throw new ArgumentException("clopperPearsonUpper: alpha must be in (0, 1)");
        int k = (int)kD, n = (int)nD;
        if (n == 0 || k == n) return new CpCertificate(1, A, A);
        var al = DoubleToDyadic(alpha);
        var start = Clamp(new BigInteger(Math.Ceiling(FloatGuess(k, n, alpha) * Math.ScaleB(1.0, CpGridBits))) + TolUnits);
        var br = CertifyBracket(start, a => CdfExceeds(n, k, a, al));
        return new CpCertificate((double)br.Hi / Math.ScaleB(1.0, CpGridBits), br.Hi, br.Lo);
    }

    /// <summary>Certifies a bracket of at most 2^8 units around the flip point of the antitone <paramref name="exceeds"/>.</summary>
    public static Bracket CertifyBracket(BigInteger start, Func<BigInteger, bool> exceeds)
    {
        var hi = start;
        var step = TolUnits;
        while (exceeds(hi))
        {
            hi = Clamp(hi + step);
            step <<= 1;
        }
        var lo = Clamp(hi - TolUnits);
        step = TolUnits;
        while (lo.Sign > 0 && !exceeds(lo))
        {
            hi = lo;
            lo = Clamp(lo - step);
            step <<= 1;
        }
        if (lo.IsZero && !exceeds(BigInteger.Zero)) throw new InvalidOperationException("clopperPearsonUpper: unreachable (cdfRec(0) = 1)");
        while (hi - lo > TolUnits)
        {
            var mid = (lo + hi) >> 1;
            if (exceeds(mid)) lo = mid;
            else hi = mid;
        }
        return new Bracket(hi, lo);
    }

    public static double ClopperPearsonUpper(double k, double n, double alpha) => ClopperPearsonCertified(k, n, alpha).Upper;

    public static double HoeffdingHalfWidth(double range, double samples, double deltaPrime = 0.05) =>
        range * Math.Sqrt(IntentMath.Log(2 / deltaPrime) / (2 * samples));

    public static Wilson WilsonInterval(double k, double n, double z = 1.959963984540054)
    {
        if (!(n > 0)) return new Wilson(double.NaN, 0, 1);
        double p = k / n;
        double z2 = z * z;
        double den = 1 + z2 / n;
        double centre = (p + z2 / (2 * n)) / den;
        double half = (z * Math.Sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / den;
        return new Wilson(p, Math.Max(0, centre - half), Math.Min(1, centre + half));
    }
}
