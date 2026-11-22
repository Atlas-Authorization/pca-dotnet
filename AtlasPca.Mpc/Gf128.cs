using System.Numerics;

namespace AtlasPca.Mpc;

/// <summary>
/// GF(2^128) arithmetic with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check. Elements are 128-bit
/// non-negative BigIntegers (bit i = coefficient of x^i); addition is XOR. Not constant-time.
/// </summary>
public static class Gf128
{
    static readonly BigInteger Mask = (BigInteger.One << 128) - 1;
    static readonly BigInteger Red = new(0x87);

    static bool Bit(BigInteger v, int i) => !((v >> i) & BigInteger.One).IsZero;

    public static BigInteger Add(BigInteger a, BigInteger b) => (a ^ b) & Mask;

    public static BigInteger MulX(BigInteger v)
    {
        var carry = Bit(v, 127);
        var r = (v << 1) & Mask;
        return carry ? r ^ Red : r;
    }

    public static BigInteger MulByXi(BigInteger v, int i)
    {
        var r = v & Mask;
        for (int k = 0; k < i; k++) r = MulX(r);
        return r;
    }

    public static BigInteger Mul(BigInteger a, BigInteger b)
    {
        var res = BigInteger.Zero;
        var v = a & Mask;
        for (int i = 0; i < 128; i++)
        {
            if (Bit(b, i)) res ^= v;
            v = MulX(v);
        }
        return res & Mask;
    }
}
