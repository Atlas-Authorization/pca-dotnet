// Math.pow as the reference computes it: fdlibm's __ieee754_pow (e_pow.c), statement for statement with the same constants, plus the reference language's rule
// that (+-1) ** +-Infinity is NaN. Method: log2(x) to extra precision as t1 + t2, y * log2(x) = n + y' with |y'| <= 0.5, x**y = 2**n * exp(y' * ln2). No fused
// multiply-add is used. The platform's Math.Pow may round differently in the last place, which moves a health-test cutoff; this routine does not.
namespace AtlasPca;

internal static class FdLibm
{
    static double D(ulong bits) => BitConverter.UInt64BitsToDouble(bits);
    static int Hi(double x) => (int)(BitConverter.DoubleToUInt64Bits(x) >> 32);
    static int Lo(double x) => (int)BitConverter.DoubleToUInt64Bits(x);
    static double SetHi(double x, int h) => D(((ulong)(uint)h << 32) | (BitConverter.DoubleToUInt64Bits(x) & 0xffff_ffffUL));
    static double Lo0(double x) => D(BitConverter.DoubleToUInt64Bits(x) & 0xffff_ffff_0000_0000UL);

    internal static double Pow(double x, double y)
    {
        unchecked
        {
            const int signifBits = 0x7fffffff;
            double z, r, t, u, v, w;
            int i, j, k, n;

            if (y == 0.0) return 1.0; // x**0 = 1
            if (double.IsNaN(x) || double.IsNaN(y)) return x + y;

            double yAbs = Math.Abs(y), xAbs = Math.Abs(x);
            // special values of y
            if (y == 2.0) return x * x;
            if (y == 0.5)
            {
                if (x >= -double.MaxValue) return Math.Sqrt(x + 0.0); // x == -infinity is handled later; + 0.0 for x == -0.0
            }
            else if (yAbs == 1.0) return y == 1.0 ? x : 1.0 / x;
            else if (yAbs == double.PositiveInfinity)
            {
                if (xAbs == 1.0) return y - y; // (+-1)**+-inf is NaN
                if (xAbs > 1.0) return y >= 0 ? y : 0.0; // (|x| > 1)**+-inf = inf, 0
                return y < 0 ? -y : 0.0; // (|x| < 1)**-+inf = inf, 0
            }

            int hx = Hi(x);
            int ix = hx & signifBits;

            // yIsInt = 0: y is not an integer, 1: y is an odd integer, 2: y is an even integer (only needed for x < 0)
            int yIsInt = 0;
            if (hx < 0)
            {
                if (yAbs >= D(0x4340000000000000UL)) yIsInt = 2; // 2^53: even, ulp(2^53) = 2
                else if (yAbs >= 1.0)
                {
                    long yAbsAsLong = (long)yAbs;
                    if ((double)yAbsAsLong == yAbs) yIsInt = 2 - (int)(yAbsAsLong & 1);
                }
            }

            // special values of x
            if (xAbs == 0.0 || xAbs == double.PositiveInfinity || xAbs == 1.0)
            {
                z = xAbs; // x is +-0, +-inf, +-1
                if (y < 0.0) z = 1.0 / z;
                if (hx < 0)
                {
                    if (((ix - 0x3ff00000) | yIsInt) == 0) z = (z - z) / (z - z); // (-1)**non-int is NaN
                    else if (yIsInt == 1) z = -1.0 * z; // (x < 0)**odd = -(|x|**odd)
                }
                return z;
            }

            n = (hx >> 31) + 1;
            if ((n | yIsInt) == 0) return (x - x) / (x - x); // (x < 0)**(non-int) is NaN

            double s = 1.0; // sign of the result: -1 for (negative)**(odd integer)
            if ((n | (yIsInt - 1)) == 0) s = -1.0;

            double pH, pL, t1, t2;
            if (yAbs > D(0x41E00000FFFFFFFFUL)) // |y| > ~2**31
            {
                double invLn2 = D(0x3FF71547652B82FEUL);  // 1/ln2
                double invLn2H = D(0x3FF7154700000000UL); // 21 bits of 1/ln2
                double invLn2L = D(0x3E994AE0BF85DDF4UL); // 1/ln2 tail
                // over/underflow if x is not close to one
                if (xAbs < D(0x3FEFFFFF00000000UL)) return y < 0.0 ? s * double.PositiveInfinity : s * 0.0;
                if (xAbs > D(0x3FF00000FFFFFFFFUL)) return y > 0.0 ? s * double.PositiveInfinity : s * 0.0;
                // now |1 - x| is tiny <= 2**-20: log(x) by x - x^2/2 + x^3/3 - x^4/4
                t = xAbs - 1.0; // t has 20 trailing zeros
                w = (t * t) * (0.5 - t * (0.3333333333333333333333 - t * 0.25));
                u = invLn2H * t; // invLn2H has 21 significant bits
                v = t * invLn2L - w * invLn2;
                t1 = u + v;
                t1 = Lo0(t1);
                t2 = v - (t1 - u);
            }
            else
            {
                double cp = D(0x3FEEC709DC3A03FDUL);  // 2/(3 ln2)
                double cpH = D(0x3FEEC709E0000000UL); // (float)cp
                double cpL = D(0xBE3E2FE0145B01F5UL); // tail of cpH
                double zH, zL, ss, s2, sH, sL, tH, tL;
                n = 0;
                if (ix < 0x00100000) // subnormal x
                {
                    xAbs *= D(0x4340000000000000UL);
                    n -= 53;
                    ix = Hi(xAbs);
                }
                n += (ix >> 20) - 0x3ff;
                j = ix & 0x000fffff;
                // determine the interval
                ix = j | 0x3ff00000; // normalize ix
                if (j <= 0x3988E) k = 0; // |x| < sqrt(3/2)
                else if (j < 0xBB67A) k = 1; // |x| < sqrt(3)
                else
                {
                    k = 0;
                    n += 1;
                    ix -= 0x00100000;
                }
                xAbs = SetHi(xAbs, ix);

                // ss = sH + sL = (x - 1)/(x + 1) or (x - 1.5)/(x + 1.5)
                double dpH = D(0x3FE2B80340000000UL);
                double dpL = D(0x3E4CFDEB43CFD006UL);
                // polynomial coefficients for (3/2)*(log(x) - 2s - 2/3*s**3)
                double l1 = D(0x3FE3333333333303UL);
                double l2 = D(0x3FDB6DB6DB6FABFFUL);
                double l3 = D(0x3FD55555518F264DUL);
                double l4 = D(0x3FD17460A91D4101UL);
                double l5 = D(0x3FCD864A93C9DB65UL);
                double l6 = D(0x3FCA7E284A454EEFUL);
                double kD = k;
                double bpK = 1.0 + 0.5 * kD; // BP[0] = 1.0, BP[1] = 1.5
                u = xAbs - bpK;
                v = 1.0 / (xAbs + bpK);
                ss = u * v;
                sH = ss;
                sH = Lo0(sH);
                // tH = xAbs + BP[k], high part
                tH = 0.0;
                tH = SetHi(tH, ((ix >> 1) | 0x20000000) + 0x00080000 + (k << 18));
                tL = xAbs - (tH - bpK);
                sL = v * ((u - sH * tH) - sH * tL);
                // log(xAbs)
                s2 = ss * ss;
                r = s2 * s2 * (l1 + s2 * (l2 + s2 * (l3 + s2 * (l4 + s2 * (l5 + s2 * l6)))));
                r += sL * (sH + ss);
                s2 = sH * sH;
                tH = 3.0 + s2 + r;
                tH = Lo0(tH);
                tL = r - ((tH - 3.0) - s2);
                // u + v = ss * (1 + ...)
                u = sH * tH;
                v = sL * tH + tL * ss;
                // 2/(3 log2) * (ss + ...)
                pH = u + v;
                pH = Lo0(pH);
                pL = v - (pH - u);
                zH = cpH * pH; // cpH + cpL = 2/(3 log2)
                zL = cpL * pH + pL * cp + dpL * kD;
                // log2(xAbs) = (ss + ...) * 2/(3 log2) = n + dpH + zH + zL
                t = n;
                t1 = (((zH + zL) + dpH * kD) + t);
                t1 = Lo0(t1);
                t2 = zL - (((t1 - t) - dpH * kD) - zH);
            }

            // split y into y1 + y2 and compute (y1 + y2) * (t1 + t2)
            double y1 = y;
            y1 = Lo0(y1);
            pL = (y - y1) * t1 + y * t2;
            pH = y1 * t1;
            z = pL + pH;
            j = Hi(z);
            i = Lo(z);
            if (j >= 0x40900000) // z >= 1024
            {
                if (((j - 0x40900000) | i) != 0) return s * double.PositiveInfinity; // z > 1024: overflow
                const double ovt = 8.0085662595372944372e-0017; // -(1024 - log2(ovfl + .5ulp))
                if (pL + ovt > z - pH) return s * double.PositiveInfinity; // overflow
            }
            else if ((j & signifBits) >= 0x4090cc00) // z <= -1075
            {
                if (((j - (int)0xc090cc00) | i) != 0) return s * 0.0; // z < -1075: underflow
                if (pL <= z - pH) return s * 0.0; // underflow
            }

            // 2**(pH + pL)
            double p1 = D(0x3FC555555555553EUL);
            double p2 = D(0xBF66C16C16BEBD93UL);
            double p3 = D(0x3F11566AAF25DE2CUL);
            double p4 = D(0xBEBBBD41C5D26BF1UL);
            double p5 = D(0x3E66376972BEA4D0UL);
            double lg2 = D(0x3FE62E42FEFA39EFUL);
            double lg2H = D(0x3FE62E4300000000UL);
            double lg2L = D(0xBE205C610CA86C39UL);
            i = j & signifBits;
            k = (i >> 20) - 0x3ff;
            n = 0;
            if (i > 0x3fe00000) // |z| > 0.5: n = [z + 0.5]
            {
                n = j + (0x00100000 >> (k + 1));
                k = ((n & signifBits) >> 20) - 0x3ff; // new k for n
                t = 0.0;
                t = SetHi(t, n & ~(0x000fffff >> k));
                n = ((n & 0x000fffff) | 0x00100000) >> (20 - k);
                if (j < 0) n = -n;
                pH -= t;
            }
            t = pL + pH;
            t = Lo0(t);
            u = t * lg2H;
            v = (pL - (t - pH)) * lg2 + t * lg2L;
            z = u + v;
            w = v - (z - u);
            t = z * z;
            t1 = z - t * (p1 + t * (p2 + t * (p3 + t * (p4 + t * p5))));
            r = (z * t1) / (t1 - 2.0) - (w + z * w);
            z = 1.0 - (r - z);
            j = Hi(z);
            j += n << 20;
            if ((j >> 20) <= 0) z = Math.ScaleB(z, n); // subnormal output
            else z = SetHi(z, Hi(z) + (n << 20));
            return s * z;
        }
    }
}
