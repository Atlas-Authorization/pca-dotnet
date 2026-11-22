// Fixed-width, branch-free arithmetic modulo the edwards25519 group order L on 32-byte little-endian scalars: a 1:1 port of the reference
// constant-time scalar module. Secret-dependent steps run the same operations on 16-bit limbs held in int[]: bit loops have fixed bounds,
// "if" is a mask select, and a secret never indexes an array or drives a branch. No BigInteger on the secret path.
// Honest limit: this removes variable-time big-integer multiply/divide from the secret path; the JIT and the CPU are still outside our control.
namespace AtlasPca;

public static class CtScalar
{
    const int Limbs = 16;
    const int Mask = 0xffff;
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian 16-bit limbs.
    static readonly int[] LLimbs = BuildL();

    static int[] BuildL()
    {
        var v = Ratchet.EdwardsPoint.Order;
        var o = new int[Limbs];
        for (var i = 0; i < Limbs; i++) { o[i] = (int)(v & 0xffff); v >>= 16; }
        return o;
    }

    static int[] FromBytes(byte[] b)
    {
        var o = new int[Limbs];
        for (var i = 0; i < Limbs; i++) o[i] = b[2 * i] | (b[2 * i + 1] << 8);
        return o;
    }

    static byte[] ToBytes(int[] x)
    {
        var o = new byte[32];
        for (var i = 0; i < Limbs; i++) { o[2 * i] = (byte)(x[i] & 0xff); o[2 * i + 1] = (byte)(x[i] >> 8); }
        return o;
    }

    /// <summary>x - L when x >= L, else x, chosen with a mask (x &lt; 2L).</summary>
    static int[] CondSubL(int[] x)
    {
        var t = new int[Limbs];
        var borrow = 0;
        for (var i = 0; i < Limbs; i++)
        {
            var d = x[i] - LLimbs[i] - borrow;
            borrow = (d >> 31) & 1;
            t[i] = d & Mask;
        }
        var keepT = borrow - 1;
        var o = new int[Limbs];
        for (var i = 0; i < Limbs; i++) o[i] = (t[i] & keepT) | (x[i] & ~keepT);
        return o;
    }

    static int[] AddMod(int[] a, int[] b)
    {
        var s = new int[Limbs];
        var carry = 0;
        for (var i = 0; i < Limbs; i++)
        {
            var v = a[i] + b[i] + carry;
            s[i] = v & Mask;
            carry = v >> 16;
        }
        return CondSubL(s);
    }

    static int[] SubMod(int[] a, int[] b)
    {
        var d = new int[Limbs];
        var borrow = 0;
        for (var i = 0; i < Limbs; i++)
        {
            var v = a[i] - b[i] - borrow;
            borrow = (v >> 31) & 1;
            d[i] = v & Mask;
        }
        var addL = -borrow;
        var carry = 0;
        var o = new int[Limbs];
        for (var i = 0; i < Limbs; i++)
        {
            var v = d[i] + (LLimbs[i] & addL) + carry;
            o[i] = v & Mask;
            carry = v >> 16;
        }
        return o;
    }

    /// <summary>Horner over the bits of <paramref name="bitsLe"/> (MSB first): acc = 2*acc + bit*addend, all mod L; a null addend means the plain value.</summary>
    static int[] HornerMod(byte[] bitsLe, int[]? addend)
    {
        var acc = new int[Limbs];
        for (var i = bitsLe.Length * 8 - 1; i >= 0; i--)
        {
            var bit = (bitsLe[i >> 3] >> (i & 7)) & 1;
            acc = AddMod(acc, acc);
            var t = new int[Limbs];
            if (addend == null) t[0] = bit;
            else
            {
                var m = -bit;
                for (var k = 0; k < Limbs; k++) t[k] = addend[k] & m;
            }
            acc = AddMod(acc, t);
        }
        return acc;
    }

    static byte[] Check(byte[]? x, string what)
    {
        if (x == null || x.Length != 32) throw new ArgumentException($"ct-scalar: {what} must be 32 bytes");
        return x;
    }

    /// <summary>Reduce 1..64 little-endian bytes modulo L.</summary>
    public static byte[] Reduce(byte[] bytesLe)
    {
        if (bytesLe == null || bytesLe.Length < 1 || bytesLe.Length > 64) throw new ArgumentException("ct-scalar: reduce takes 1..64 bytes");
        return ToBytes(HornerMod(bytesLe, null));
    }

    public static byte[] Add(byte[] a, byte[] b) => ToBytes(AddMod(FromBytes(Reduce(Check(a, "a"))), FromBytes(Reduce(Check(b, "b")))));

    public static byte[] Sub(byte[] a, byte[] b) => ToBytes(SubMod(FromBytes(Reduce(Check(a, "a"))), FromBytes(Reduce(Check(b, "b")))));

    /// <summary>a * b mod L; Horner over b's raw bits is exact for any 256-bit b.</summary>
    public static byte[] Mul(byte[] a, byte[] b) => ToBytes(HornerMod(Check(b, "b"), FromBytes(Reduce(Check(a, "a")))));

    public static bool IsZero(byte[] a)
    {
        var r = Reduce(Check(a, "a"));
        var acc = 0;
        for (var i = 0; i < 32; i++) acc |= r[i];
        return acc == 0;
    }
}
