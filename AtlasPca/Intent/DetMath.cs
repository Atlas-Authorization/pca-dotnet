// DETERMINISTIC MATH (the rule every language follows; reference: packages/pca-intent/src/detmath.ts). libm's log, exp, log2 and pow are not correctly rounded and differ in
// the last digit between implementations, which moves a decision that sits on a boundary (the drift threshold, the next question, a map weight, an integer cut point). The
// functions here use only integer arithmetic: fixed point with 96 fractional bits (a value is an integer scaled by 2^96), TRUNCATING division (toward zero), and one final
// conversion of the integer to a double with round-to-nearest-even followed by an exact power-of-two scaling.
using System.Numerics;

namespace AtlasPca.IntentPkg;

public static class DetMath
{
    const int Frac = 96;
    static readonly BigInteger One = BigInteger.One << Frac;
    static readonly double OneD = Math.ScaleB(1.0, Frac);

    // 2 * atanh(num / den) in fixed point: z + z^3/3 + z^5/5 + ... until a term is 0
    static BigInteger Atanh2(BigInteger num, BigInteger den)
    {
        var z = (num << Frac) / den;
        var z2 = (z * z) >> Frac;
        var term = z;
        var sum = BigInteger.Zero;
        for (BigInteger i = 1; !term.IsZero; i += 2)
        {
            sum += term / i;
            term = (term * z2) >> Frac;
        }
        return 2 * sum;
    }

    static readonly BigInteger Ln2 = Atanh2(1, 3); // ln 2 = 2 atanh(1/3)

    /// <summary>The integer converted to the nearest double (ties to even), as JavaScript's Number(bigint) does; a magnitude beyond the double range is an infinity.</summary>
    internal static double ToDouble(BigInteger v)
    {
        if (v.IsZero) return 0.0;
        var neg = v.Sign < 0;
        var a = BigInteger.Abs(v);
        var bits = (int)a.GetBitLength();
        double r;
        if (bits <= 53) r = (double)(ulong)a;
        else
        {
            int shift = bits - 53;
            var top = a >> shift;
            var rest = a - (top << shift);
            var half = BigInteger.One << (shift - 1);
            int c = rest.CompareTo(half);
            if (c > 0 || (c == 0 && !top.IsEven)) top += 1; // a carry into the 54th bit is a power of two, exact
            r = Math.ScaleB((double)(ulong)top, shift);
        }
        return neg ? -r : r;
    }

    // x = m * 2^E with m = M / 2^52 in [1, 2): (E, M); subnormals are scaled by 2^64 first (exact)
    static (long E, BigInteger M) Split(double x)
    {
        long scale = 0;
        double y = x;
        if (y < Math.ScaleB(1.0, -1022)) { y *= Math.ScaleB(1.0, 64); scale = 64; }
        long bits = BitConverter.DoubleToInt64Bits(y);
        long e = ((bits >> 52) & 0x7ff) - 1023 - scale;
        var m = new BigInteger((bits & ((1L << 52) - 1)) | (1L << 52));
        return (e, m);
    }

    static BigInteger LnFixed(double x)
    {
        var (e, m) = Split(x);
        var p52 = BigInteger.One << 52;
        return e * Ln2 + Atanh2(m - p52, m + p52);
    }

    /// <summary>ln x (x = 0 of either sign gives -Infinity, x &lt; 0 or NaN gives NaN, +Infinity gives +Infinity, x = 1 gives exactly 0).</summary>
    public static double DetLn(double x)
    {
        if (x == 0) return double.NegativeInfinity; // as Math.Log: a probability of 0 is a weight of 0 after DetExp, never NaN (either zero)
        if (!(x > 0)) return double.NaN;
        if (double.IsPositiveInfinity(x)) return x;
        if (x == 1) return 0;
        return ToDouble(LnFixed(x)) / OneD;
    }

    /// <summary>log2 x: the fixed-point ln divided by ln 2 in fixed point (an exact power of two gives its integer exponent exactly).</summary>
    public static double DetLog2(double x)
    {
        if (x == 0) return double.NegativeInfinity;
        if (!(x > 0)) return double.NaN;
        if (double.IsPositiveInfinity(x)) return x;
        if (x == 1) return 0;
        var l = LnFixed(x);
        return ToDouble((l << Frac) / Ln2) / OneD;
    }

    static BigInteger FloorDiv(BigInteger a, BigInteger b)
    {
        var q = BigInteger.DivRem(a, b, out var rem);
        return !rem.IsZero && (a.Sign < 0) != (b.Sign < 0) ? q - 1 : q;
    }

    /// <summary>e^x (x &gt; 709.782712893384 gives +Infinity, x &lt; -745.2 gives 0, NaN gives NaN).</summary>
    public static double DetExp(double x)
    {
        if (double.IsNaN(x)) return x;
        if (x > 709.782712893384) return double.PositiveInfinity;
        if (x < -745.2) return 0;
        if (x == 0) return 1;
        long bits = BitConverter.DoubleToInt64Bits(Math.Abs(x));
        int be = (int)((bits >> 52) & 0x7ff);
        long frac = bits & ((1L << 52) - 1);
        var m = new BigInteger(be == 0 ? frac : frac | (1L << 52));
        int sh = (be == 0 ? 1 : be) - 1075 + 96; // |x| * 2^96 = m * 2^sh
        var X = sh >= 0 ? m << sh : m >> -sh;
        if (x < 0) X = -X;
        var k = FloorDiv(X + Ln2 / 2, Ln2);
        var r = X - k * Ln2;
        var term = One;
        var sum = One;
        for (BigInteger n = 1; !term.IsZero; n += 1)
        {
            term = (term * r) / One / n;
            sum += term;
        }
        int e = (int)k - Frac;
        int half = (int)Math.Truncate(e / 2.0);
        return ToDouble(sum) * Math.ScaleB(1.0, half) * Math.ScaleB(1.0, e - half);
    }

    /// <summary>b^n for an integer n &gt;= 0: 1 multiplied by b, n times, in sequence (IEEE multiplication is exactly rounded).</summary>
    public static double DetPowInt(double b, long n)
    {
        double r = 1;
        for (long i = 0; i < n; i++) r = r * b;
        return r;
    }
}
