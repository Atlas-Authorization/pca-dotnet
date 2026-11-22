// The OPRF suite's view of ristretto255 (RFC 9496): a thin adapter over the one native implementation, AtlasPca.Ratchet.RistrettoPoint
// (checked against the reference's and the RFC's known-answer vectors), plus expand_message_xmd(SHA-512) (RFC 9380). Keeps this suite's
// scalar-range refusals. Group arithmetic is libsodium's (constant time).
using System.Numerics;
using System.Security.Cryptography;
using AtlasPca.Ratchet;

namespace AtlasPca.Oprf;

internal sealed class RPoint
{
    /// <summary>The prime-subgroup order L = 2^252 + 27742317777372353535851937790883648493.</summary>
    internal static readonly BigInteger Order = RistrettoPoint.Order;

    readonly RistrettoPoint _p;
    RPoint(RistrettoPoint p) { _p = p; }

    internal static readonly RPoint Zero = new(RistrettoPoint.Zero);
    internal static readonly RPoint Base = new(RistrettoPoint.Base);

    /// <summary>Decode a 32-byte canonical encoding; null when it is not a valid ristretto255 element.</summary>
    internal static RPoint? Decode(byte[] b) => b == null ? null : RistrettoPoint.TryDecode(b) is { } p ? new RPoint(p) : null;

    internal byte[] Encode() => _p.Encode();

    /// <summary>RFC 9496 element derivation from 64 uniform bytes.</summary>
    internal static RPoint FromUniformBytes(byte[] uniform64)
    {
        if (uniform64.Length != 64) throw new ArgumentException("ristretto255 element derivation needs 64 bytes");
        return new(RistrettoPoint.FromUniformBytes(uniform64));
    }

    internal RPoint Add(RPoint o) => new(_p.Add(o._p));
    internal RPoint Neg() => new(_p.Negate());
    internal bool Eq(RPoint o) => _p.Equals(o._p);
    internal bool IsIdentity => Eq(Zero);

    /// <summary>Scalar multiply (k in [0, L)), zero allowed (the identity).</summary>
    internal RPoint MulUnsafe(BigInteger k)
    {
        if (k.Sign < 0 || k >= Order) throw new ArgumentOutOfRangeException(nameof(k), "invalid scalar: expected 0 <= k < group order");
        return k.IsZero ? Zero : new(_p.Multiply(k));
    }

    /// <summary>Scalar multiply (k in [1, L)); a zero scalar is refused like the reference's constant-time multiply.</summary>
    internal RPoint Mul(BigInteger k)
    {
        if (k.Sign <= 0 || k >= Order) throw new ArgumentOutOfRangeException(nameof(k), "invalid scalar: expected 1 <= k < group order");
        return new(_p.Multiply(k));
    }

    /// <summary>expand_message_xmd with SHA-512 (RFC 9380 section 5.3.1).</summary>
    internal static byte[] ExpandMessageXmd(byte[] msg, byte[] dst, int lenInBytes)
    {
        const int bIn = 64, rIn = 128;
        int ell = (lenInBytes + bIn - 1) / bIn;
        if (ell > 255 || lenInBytes > 65535 || dst.Length > 255) throw new ArgumentOutOfRangeException(nameof(lenInBytes), "expand_message_xmd: invalid length or DST");
        var dstPrime = Pca.Cat(dst, new[] { (byte)dst.Length });
        var msgPrime = Pca.Cat(new byte[rIn], msg, new[] { (byte)(lenInBytes >> 8), (byte)lenInBytes }, new byte[] { 0 }, dstPrime);
        var b0 = SHA512.HashData(msgPrime);
        var bi = SHA512.HashData(Pca.Cat(b0, new byte[] { 1 }, dstPrime));
        var o = new List<byte>(bi);
        for (int i = 2; i <= ell; i++)
        {
            var x = new byte[bIn];
            for (int j = 0; j < bIn; j++) x[j] = (byte)(b0[j] ^ bi[j]);
            bi = SHA512.HashData(Pca.Cat(x, new[] { (byte)i }, dstPrime));
            o.AddRange(bi);
        }
        return o.Take(lenInBytes).ToArray();
    }
}
