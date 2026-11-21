using System.Numerics;
using System.Security.Cryptography;
using static supranational.blst;

namespace AtlasPca.Pairing;

/// <summary>
/// Thin helpers over blst (via its C# binding) shared by the pairing-based packages: scalar-field arithmetic mod r on BigInteger,
/// point multiplication by a scalar through blst's own scalar type, RFC 9380 expand_message_xmd (SHA-256), and the canonical decoders.
/// No pairing, field or curve arithmetic is implemented here.
/// shortcut: scalar-field arithmetic (add/mul/inverse) is BigInteger, which is not constant-time. Point multiplication (the expensive,
/// key-dependent part) is blst's constant-time implementation. Upgrade to blst's Scalar arithmetic if a deployment needs the scalar steps constant-time too.
/// </summary>
public static class Bls12
{
    /// <summary>The prime order r of the BLS12-381 groups.</summary>
    public static readonly BigInteger R = BigInteger.Parse("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", System.Globalization.NumberStyles.HexNumber);

    public static BigInteger Mod(BigInteger x) { var m = x % R; return m.Sign < 0 ? m + R : m; }
    public static BigInteger Add(BigInteger a, BigInteger b) => Mod(a + b);
    public static BigInteger Sub(BigInteger a, BigInteger b) => Mod(a - b);
    public static BigInteger Mul(BigInteger a, BigInteger b) => Mod(a * b);

    /// <summary>Fermat inverse x^(r-2) mod r (fixed public exponent). Throws on zero.</summary>
    public static BigInteger Inv(BigInteger x)
    {
        var v = Mod(x);
        if (v.IsZero) throw new ArithmeticException("inverse of zero");
        return BigInteger.ModPow(v, R - 2, R);
    }

    /// <summary>I2OSP: non-negative integer to fixed-length big-endian octets; throws when it does not fit.</summary>
    public static byte[] I2osp(BigInteger n, int len)
    {
        if (n.Sign < 0 || n.GetBitLength() > 8L * len) throw new ArgumentException("integer does not fit " + len + " octets");
        var be = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        var o = new byte[len];
        Array.Copy(be, 0, o, len - be.Length, be.Length);
        return o;
    }

    /// <summary>OS2IP: big-endian octets to a non-negative integer.</summary>
    public static BigInteger Os2ip(byte[] b) => new(b, isUnsigned: true, isBigEndian: true);

    /// <summary>A blst scalar from a value in [0, r): the 32-byte big-endian form.</summary>
    public static Scalar ScalarOf(BigInteger s) => new Scalar(I2osp(Mod(s), 32));

    /// <summary>s * P as a new point (P is not modified); the identity when s is zero mod r.</summary>
    public static P1 Mul(P1 p, BigInteger s) { var v = Mod(s); return v.IsZero ? Id1() : p.dup().mult(ScalarOf(v)); }
    public static P2 Mul(P2 p, BigInteger s) { var v = Mod(s); return v.IsZero ? Id2() : p.dup().mult(ScalarOf(v)); }

    // a default struct has no point storage, so the identity is built by decoding the compressed infinity
    public static P1 Id1() { var b = new byte[48]; b[0] = 0xC0; return new P1(b); }
    public static P2 Id2() { var b = new byte[96]; b[0] = 0xC0; return new P2(b); }

    public static P1 Add(P1 a, P1 b) => a.dup().add(b);
    public static P2 Add(P2 a, P2 b) => a.dup().add(b);
    public static P1 Sub(P1 a, P1 b) => a.dup().add(b.dup().neg());

    /// <summary>Strict compressed-G1 decoding: compression flag set, canonical, on curve, in the prime-order subgroup. Identity is allowed (check it separately).</summary>
    public static P1 DecodeG1(byte[]? b)
    {
        if (b == null || b.Length != 48 || (b[0] & 0x80) == 0) throw new ArgumentException("not a 48-byte compressed G1 point");
        try
        {
            var a = new P1_Affine(b);
            if (!a.compress().AsSpan().SequenceEqual(b) || !a.on_curve() || !a.in_group()) throw new ArgumentException("non-canonical or invalid G1 encoding");
            return a.to_jacobian();
        }
        catch (ArgumentException) { throw; }
        catch (System.Exception t) when (!Fatal(t)) { throw new ArgumentException("invalid G1 encoding", t); }
    }

    public static P2 DecodeG2(byte[]? b)
    {
        if (b == null || b.Length != 96 || (b[0] & 0x80) == 0) throw new ArgumentException("not a 96-byte compressed G2 point");
        try
        {
            var a = new P2_Affine(b);
            if (!a.compress().AsSpan().SequenceEqual(b) || !a.on_curve() || !a.in_group()) throw new ArgumentException("non-canonical or invalid G2 encoding");
            return a.to_jacobian();
        }
        catch (ArgumentException) { throw; }
        catch (System.Exception t) when (!Fatal(t)) { throw new ArgumentException("invalid G2 encoding", t); }
    }

    /// <summary>e(a, x) == e(b, y), by blst's pairing.</summary>
    public static bool PairingEq(P1 a, P2 x, P1 b, P2 y)
    {
        var l = new PT(x.to_affine(), a.to_affine());
        var r = new PT(y.to_affine(), b.to_affine());
        return PT.finalverify(l, r);
    }

    /// <summary>True for a native-library failure: it must surface, never be read as "bad input".</summary>
    public static bool Fatal(System.Exception t) => t is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or OutOfMemoryException;

    /// <summary>expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets.</summary>
    public static byte[] ExpandMessageXmd(byte[] msg, byte[] dst, int len)
    {
        int ell = (len + 31) / 32;
        if (ell > 255 || len > 65535 || dst.Length > 255 || len < 0) throw new ArgumentException("expand_message_xmd: invalid length or DST");
        var dstPrime = new byte[dst.Length + 1];
        dst.CopyTo(dstPrime, 0);
        dstPrime[dst.Length] = (byte)dst.Length;
        static byte[] H(params byte[][] parts) => SHA256.HashData(parts.SelectMany(p => p).ToArray());
        var b0 = H(new byte[64], msg, new[] { (byte)(len >> 8), (byte)len, (byte)0 }, dstPrime);
        var bi = H(b0, new byte[] { 1 }, dstPrime);
        var o = new byte[len];
        Array.Copy(bi, 0, o, 0, Math.Min(32, len));
        for (int i = 2; i <= ell; i++)
        {
            var x = new byte[32];
            for (int k = 0; k < 32; k++) x[k] = (byte)(b0[k] ^ bi[k]);
            bi = H(x, new[] { (byte)i }, dstPrime);
            int off = (i - 1) * 32;
            Array.Copy(bi, 0, o, off, Math.Min(32, len - off));
        }
        return o;
    }
}
