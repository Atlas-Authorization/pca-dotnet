using System.Numerics;
using static AtlasPca.Mpc.Field;

namespace AtlasPca.Mpc;

/// <summary>
/// Additive secret sharing over F_p for N parties: shares sum to the secret; reconstruction is all-or-nothing and fails closed on an absent
/// share. A shared value is a <c>BigInteger[]</c> with <c>x[i]</c> held by party i.
/// </summary>
public static class Sharing
{
    /// <summary>Largest party count accepted (bounds allocation).</summary>
    public const int MAX_PARTIES = 1024;

    public static BigInteger[] Share(BigInteger secret, int n, IFieldSource rng)
    {
        if (n < 1 || n > MAX_PARTIES) throw new ArgumentException("share: n must be an integer in [1, " + MAX_PARTIES + "]");
        var o = new BigInteger[n];
        var acc = BigInteger.Zero;
        for (int i = 0; i < n - 1; i++)
        {
            var s = rng.Next();
            o[i] = s;
            acc = Fadd(acc, s);
        }
        o[n - 1] = Fadd(Mod(secret), Fneg(acc));
        return o;
    }

    public static BigInteger Reconstruct(BigInteger[] shares) => Reconstruct(shares.Select(s => (BigInteger?)s).ToArray());

    public static BigInteger Reconstruct(BigInteger?[] shares)
    {
        if (shares.Length == 0) throw new ArgumentException("reconstruct: no shares (fail closed)");
        var acc = BigInteger.Zero;
        foreach (var s in shares)
        {
            if (s is null) throw new ArgumentException("reconstruct: missing share (fail closed)");
            acc = Fadd(acc, s.Value);
        }
        return acc;
    }

    public static BigInteger[] ShareConstant(BigInteger c, int n)
    {
        if (n < 1 || n > MAX_PARTIES) throw new ArgumentException("shareConstant: n must be an integer in [1, " + MAX_PARTIES + "]");
        var o = new BigInteger[n];
        o[0] = Mod(c);
        return o;
    }

    public static BigInteger[] AddSV(BigInteger[] x, BigInteger[] y)
    {
        Same(x, y);
        var o = new BigInteger[x.Length];
        for (int i = 0; i < x.Length; i++) o[i] = Fadd(x[i], y[i]);
        return o;
    }

    public static BigInteger[] SubSV(BigInteger[] x, BigInteger[] y)
    {
        Same(x, y);
        var o = new BigInteger[x.Length];
        for (int i = 0; i < x.Length; i++) o[i] = Fadd(x[i], Fneg(y[i]));
        return o;
    }

    public static BigInteger[] NegSV(BigInteger[] x)
    {
        var o = new BigInteger[x.Length];
        for (int i = 0; i < x.Length; i++) o[i] = Fneg(x[i]);
        return o;
    }

    public static BigInteger[] ScaleSV(BigInteger[] x, BigInteger c)
    {
        var o = new BigInteger[x.Length];
        for (int i = 0; i < x.Length; i++) o[i] = Fmul(x[i], c);
        return o;
    }

    public static BigInteger[] AddPublicSV(BigInteger[] x, BigInteger c)
    {
        var o = (BigInteger[])x.Clone();
        o[0] = Fadd(o[0], Mod(c));
        return o;
    }

    public static BigInteger[] NotBitSV(BigInteger[] b) => AddPublicSV(NegSV(b), BigInteger.One);

    static void Same(BigInteger[] x, BigInteger[] y)
    {
        if (x.Length != y.Length) throw new ArgumentException("shared values must have the same party count");
    }
}
