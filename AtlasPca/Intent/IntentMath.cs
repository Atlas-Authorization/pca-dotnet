// Correctly-specified elementary functions for the intent numerics: the reference runtime computes Math.log / Math.exp with the
// fdlibm algorithms, and the platform libm may differ from them in the last bit, so the two functions the outcome space and the
// numerics use are ported from fdlibm (e_log.c, e_exp.c) and give the reference's exact doubles.
namespace AtlasPca.IntentPkg;

internal static class IntentMath
{
    /// <summary>Math.round: the nearest integer, ties toward positive infinity (exact: no x + 0.5 rounding).</summary>
    internal static double JsRound(double x)
    {
        double f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    static int Hi(double x) => unchecked((int)(BitConverter.DoubleToInt64Bits(x) >> 32));
    static uint Lo(double x) => unchecked((uint)BitConverter.DoubleToInt64Bits(x));
    static double SetHi(double x, int hi) => BitConverter.Int64BitsToDouble(((long)hi << 32) | (long)Lo(x));

    const double Ln2Hi = 6.93147180369123816490e-01, Ln2Lo = 1.90821492927058770002e-10, Two54 = 1.80143985094819840000e+16;
    const double Lg1 = 6.666666666666735130e-01, Lg2 = 3.999999999940941908e-01, Lg3 = 2.857142874366239149e-01,
        Lg4 = 2.222219843214978396e-01, Lg5 = 1.818357216161805012e-01, Lg6 = 1.531383769920937332e-01, Lg7 = 1.479819860511658591e-01;

    /// <summary>Math.log (fdlibm __ieee754_log).</summary>
    internal static double Log(double x)
    {
        unchecked
        {
            int hx = Hi(x);
            uint lx = Lo(x);
            int k = 0;
            if (hx < 0x00100000)
            {
                if (((hx & 0x7fffffff) | (int)lx) == 0) return double.NegativeInfinity;
                if (hx < 0) return double.NaN;
                k -= 54;
                x *= Two54;
                hx = Hi(x);
            }
            if (hx >= 0x7ff00000) return x + x;
            k += (hx >> 20) - 1023;
            hx &= 0x000fffff;
            int i = (hx + 0x95f64) & 0x100000;
            x = SetHi(x, hx | (i ^ 0x3ff00000));
            k += i >> 20;
            double f = x - 1.0;
            double dk, R;
            if ((0x000fffff & (2 + hx)) < 3)
            {
                if (f == 0.0)
                {
                    if (k == 0) return 0.0;
                    dk = k;
                    return dk * Ln2Hi + dk * Ln2Lo;
                }
                R = f * f * (0.5 - 0.33333333333333333 * f);
                if (k == 0) return f - R;
                dk = k;
                return dk * Ln2Hi - ((R - dk * Ln2Lo) - f);
            }
            double s = f / (2.0 + f);
            dk = k;
            double z = s * s;
            i = hx - 0x6147a;
            double w = z * z;
            int j = 0x6b851 - hx;
            double t1 = w * (Lg2 + w * (Lg4 + w * Lg6));
            double t2 = z * (Lg1 + w * (Lg3 + w * (Lg5 + w * Lg7)));
            i |= j;
            R = t2 + t1;
            if (i > 0)
            {
                double hfsq = 0.5 * f * f;
                if (k == 0) return f - (hfsq - s * (hfsq + R));
                return dk * Ln2Hi - ((hfsq - (s * (hfsq + R) + dk * Ln2Lo)) - f);
            }
            if (k == 0) return f - s * (f - R);
            return dk * Ln2Hi - ((s * (f - R) - dk * Ln2Lo) - f);
        }
    }

    const double Lp1 = 6.666666666666735130e-01, Lp2 = 3.999999999940941908e-01, Lp3 = 2.857142874366239149e-01,
        Lp4 = 2.222219843214978396e-01, Lp5 = 1.818357216161805012e-01, Lp6 = 1.531383769920937332e-01, Lp7 = 1.479819860511658591e-01;

    /// <summary>Math.log1p (fdlibm s_log1p.c).</summary>
    internal static double Log1p(double x)
    {
        unchecked
        {
            int hx = Hi(x);
            int ax = hx & 0x7fffffff;
            int k = 1, hu = 0;
            double f = 0, c = 0, u;
            if (hx < 0x3FDA827A)
            {
                if (ax >= 0x3ff00000) return x == -1.0 ? double.NegativeInfinity : double.NaN;
                if (ax < 0x3e200000)
                {
                    if (Two54 + x > 0.0 && ax < 0x3c900000) return x;
                    return x - x * x * 0.5;
                }
                if (hx > 0 || hx <= (int)0xbfd2bec3) { k = 0; f = x; hu = 1; }
            }
            if (hx >= 0x7ff00000) return x + x;
            if (k != 0)
            {
                if (hx < 0x43400000)
                {
                    u = 1.0 + x;
                    hu = Hi(u);
                    k = (hu >> 20) - 1023;
                    c = k > 0 ? 1.0 - (u - x) : x - (u - 1.0);
                    c /= u;
                }
                else
                {
                    u = x;
                    hu = Hi(u);
                    k = (hu >> 20) - 1023;
                    c = 0;
                }
                hu &= 0x000fffff;
                if (hu < 0x6a09e) u = SetHi(u, hu | 0x3ff00000);
                else
                {
                    k += 1;
                    u = SetHi(u, hu | 0x3fe00000);
                    hu = (0x00100000 - hu) >> 2;
                }
                f = u - 1.0;
            }
            double hfsq = 0.5 * f * f;
            double dk = k;
            if (hu == 0)
            {
                if (f == 0.0)
                {
                    if (k == 0) return 0.0;
                    c += dk * Ln2Lo;
                    return dk * Ln2Hi + c;
                }
                double r0 = hfsq * (1.0 - 0.66666666666666666 * f);
                if (k == 0) return f - r0;
                return dk * Ln2Hi - ((r0 - (dk * Ln2Lo + c)) - f);
            }
            double s = f / (2.0 + f);
            double z = s * s;
            double R = z * (Lp1 + z * (Lp2 + z * (Lp3 + z * (Lp4 + z * (Lp5 + z * (Lp6 + z * Lp7))))));
            if (k == 0) return f - (hfsq - s * (hfsq + R));
            return dk * Ln2Hi - ((hfsq - (s * (hfsq + R) + (dk * Ln2Lo + c))) - f);
        }
    }

    const double OThreshold = 7.09782712893383973096e+02, UThreshold = -7.45133219101941108420e+02, InvLn2 = 1.44269504088896338700e+00,
        Twom1000 = 9.33263618503218878990e-302, Huge = 1.0e+300,
        P1 = 1.66666666666666019037e-01, P2 = -2.77777777770155933842e-03, P3 = 6.61375632143793436117e-05,
        P4 = -1.65339022054652515390e-06, P5 = 4.13813679705723846039e-08;

    /// <summary>Math.exp (fdlibm __ieee754_exp).</summary>
    internal static double Exp(double x)
    {
        unchecked
        {
            double hi = 0.0, lo = 0.0;
            int k = 0;
            int hx = Hi(x);
            int xsb = (hx >> 31) & 1;
            hx &= 0x7fffffff;
            if (hx >= 0x40862E42)
            {
                if (hx >= 0x7ff00000)
                {
                    if (((hx & 0xfffff) | (int)Lo(x)) != 0) return x + x;
                    return xsb == 0 ? x : 0.0;
                }
                if (x > OThreshold) return Huge * Huge;
                if (x < UThreshold) return Twom1000 * Twom1000;
            }
            if (hx > 0x3fd62e42)
            {
                if (hx < 0x3FF0A2B2)
                {
                    hi = x - (xsb == 0 ? Ln2Hi : -Ln2Hi);
                    lo = xsb == 0 ? Ln2Lo : -Ln2Lo;
                    k = 1 - xsb - xsb;
                }
                else
                {
                    k = (int)(InvLn2 * x + (xsb == 0 ? 0.5 : -0.5));
                    double t0 = k;
                    hi = x - t0 * Ln2Hi;
                    lo = t0 * Ln2Lo;
                }
                x = hi - lo;
            }
            else if (hx < 0x3e300000)
            {
                if (Huge + x > 1.0) return 1.0 + x;
            }
            else k = 0;
            double t = x * x;
            double c = x - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
            if (k == 0) return 1.0 - ((x * c) / (c - 2.0) - x);
            double y = 1.0 - ((lo - (x * c) / (2.0 - c)) - hi);
            if (k >= -1021) return SetHi(y, Hi(y) + (k << 20));
            y = SetHi(y, Hi(y) + ((k + 1000) << 20));
            return y * Twom1000;
        }
    }

    static double KLog1p(double f)
    {
        double s = f / (2.0 + f);
        double z = s * s;
        double w = z * z;
        double t1 = w * (Lg2 + w * (Lg4 + w * Lg6));
        double t2 = z * (Lg1 + w * (Lg3 + w * (Lg5 + w * Lg7)));
        double r = t2 + t1;
        double hfsq = 0.5 * f * f;
        return s * (hfsq + r);
    }

    /// <summary>Math.log2 (fdlibm e_log2.c), the reference's exact bits.</summary>
    internal static double Log2(double x)
    {
        unchecked
        {
            const double ivln2hi = 1.44269504072144627571e+00, ivln2lo = 1.67517131648865118353e-10;
            int hx = Hi(x);
            uint lx = Lo(x);
            int k = 0;
            if (hx < 0x00100000)
            {
                if (((hx & 0x7fffffff) | (int)lx) == 0) return double.NegativeInfinity;
                if (hx < 0) return double.NaN;
                k -= 54;
                x *= Two54;
                hx = Hi(x);
            }
            if (hx >= 0x7ff00000) return x + x;
            if (hx == 0x3ff00000 && lx == 0) return 0.0;
            k += (hx >> 20) - 1023;
            hx &= 0x000fffff;
            int i = (hx + 0x95f64) & 0x100000;
            x = SetHi(x, hx | (i ^ 0x3ff00000));
            k += i >> 20;
            double y = k;
            double f = x - 1.0;
            double hfsq = 0.5 * f * f;
            double r = KLog1p(f);
            double hi = BitConverter.Int64BitsToDouble(BitConverter.DoubleToInt64Bits(f - hfsq) & unchecked((long)0xffffffff00000000UL));
            double lo = (f - hi) - hfsq + r;
            double valHi = hi * ivln2hi;
            double valLo = (lo + hi) * ivln2lo + lo * ivln2hi;
            double w = y + valHi;
            valLo += (y - w) + valHi;
            valHi = w;
            return valLo + valHi;
        }
    }
}
