using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Native;

namespace AtlasPca.Mpc;

/// <summary>
/// A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19), used in its prime-order
/// subgroup (order L). The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's constant-time Ed25519 core
/// on the compressed encoding; BigInteger is only the public coordinate codec (affine normalisation, RFC 8032 x-recovery) and the
/// on-curve predicate, which touch no secret. Every point received across the OT trust boundary is validated (on curve, non-identity, [L]P = O).
/// </summary>
public static class Ec
{
    public static readonly BigInteger Q = (BigInteger.One << 255) - 19;
    public static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    static readonly BigInteger Two = new(2);
    static readonly BigInteger D = ModFq(new BigInteger(-121665) * InvFq(new BigInteger(121666)));
    static readonly BigInteger SqrtM1 = PowFq(Two, (Q - 1) >> 2);

    /// <summary>A curve point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z.</summary>
    public sealed record Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    public static readonly Point IDENTITY = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
    public static readonly Point BASE = FromAffine(
        BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

    /// <summary>Non-negative remainder (Java BigInteger.mod).</summary>
    internal static BigInteger Mod(BigInteger a, BigInteger m)
    {
        var r = BigInteger.Remainder(a, m);
        return r.Sign < 0 ? r + m : r;
    }

    public static BigInteger ModFq(BigInteger x) => Mod(x, Q);

    static BigInteger InvFq(BigInteger a) => PowFq(ModFq(a), Q - Two);

    static BigInteger PowFq(BigInteger b, BigInteger e) => BigInteger.ModPow(ModFq(b), e, Q);

    public static Point FromAffine(BigInteger x, BigInteger y)
    {
        BigInteger X = ModFq(x), Y = ModFq(y);
        return new Point(X, Y, BigInteger.One, ModFq(X * Y));
    }

    static BigInteger Mm(BigInteger a, BigInteger b) => Mod(a * b, Q);

    /// <summary>Little-endian bytes of a non-negative integer below 256^len (the low len bytes otherwise).</summary>
    internal static byte[] LeBytes(BigInteger v, int len)
    {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        var o = new byte[len];
        Array.Copy(raw, o, Math.Min(len, raw.Length));
        return o;
    }

    /// <summary>Little-endian 32 bytes of a non-negative integer below 2^256.</summary>
    internal static byte[] Le32(BigInteger n)
    {
        if (n.Sign < 0 || n.GetBitLength() > 256) throw new ArgumentException("scalar out of range");
        return LeBytes(n, 32);
    }

    internal static BigInteger FromLe(byte[] b) => new(b, isUnsigned: true, isBigEndian: false);

    static Point Binary(bool sub, Point p1, Point p2)
    {
        byte[] a = CompressPoint(p1), b = CompressPoint(p2);
        var r = sub ? Sodium.Ed25519Sub(a, b) : Sodium.Ed25519Add(a, b);
        if (r == null) throw new PointValidationError("point is not on the curve");
        return DecompressPoint(r);
    }

    static Point Add(Point p1, Point p2) => Binary(false, p1, p2);

    /// <summary>Public group addition P + Q (complete on the subgroup).</summary>
    public static Point AddPoints(Point p1, Point p2) => Add(p1, p2);

    public static Point Dbl(Point p) => Add(p, p);

    /// <summary>[k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion).</summary>
    public static Point Mul(BigInteger k, Point p)
    {
        var s = Mod(k, L);
        if (s.IsZero || IsIdentity(p)) return IDENTITY;
        var r = Sodium.Ed25519Mul(Le32(s), CompressPoint(p));
        if (r == null) throw new PointValidationError("scalar multiplication refused: point not in the prime-order subgroup");
        return DecompressPoint(r);
    }

    public static Point MulBase(BigInteger k)
    {
        var s = Mod(k, L);
        if (s.IsZero) return IDENTITY;
        var r = Sodium.Ed25519MulBase(Le32(s));
        if (r == null) throw new InvalidOperationException("ed25519 base multiplication failed");
        return DecompressPoint(r);
    }

    public static Point Neg(Point p) => Sub(IDENTITY, p);

    public static Point Sub(Point p1, Point p2) => Binary(true, p1, p2);

    /// <summary>Affine {x, y} of a point (identity is (0, 1)).</summary>
    public static BigInteger[] ToAffine(Point p)
    {
        var zinv = InvFq(p.Z);
        return new[] { ModFq(p.X * zinv), ModFq(p.Y * zinv) };
    }

    public static bool Equal(Point a, Point b) =>
        ModFq(a.X * b.Z) == ModFq(b.X * a.Z) && ModFq(a.Y * b.Z) == ModFq(b.Y * a.Z);

    static byte[] FeBytes(BigInteger a) => LeBytes(ModFq(a), 32);

    /// <summary>Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input.</summary>
    public static byte[] EncodePoint(Point p)
    {
        var xy = ToAffine(p);
        var o = new byte[64];
        Array.Copy(FeBytes(xy[0]), 0, o, 0, 32);
        Array.Copy(FeBytes(xy[1]), 0, o, 32, 32);
        return o;
    }

    /// <summary>Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255).</summary>
    public static byte[] CompressPoint(Point p)
    {
        var xy = ToAffine(p);
        var o = FeBytes(xy[1]);
        o[31] = (byte)(o[31] | ((xy[0].IsEven ? 0 : 1) << 7));
        return o;
    }

    /// <summary>Raised when a received point fails on-curve / subgroup / identity validation.</summary>
    public sealed class PointValidationError : Exception
    {
        public PointValidationError(string message) : base(message) { }
    }

    /// <summary>Decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery).</summary>
    public static Point DecompressPoint(byte[] bytes)
    {
        if (bytes.Length != 32) throw new PointValidationError("decompressPoint: expected 32 bytes");
        int sign = (bytes[31] >> 7) & 1;
        var y = FromLe(bytes) & ((BigInteger.One << 255) - 1);
        if (y >= Q) throw new PointValidationError("decompressPoint: non-canonical y (>= q)");
        var y2 = Mm(y, y);
        var u = ModFq(y2 - 1);
        var v = ModFq(D * y2 + 1);
        var v3 = Mm(Mm(v, v), v);
        var v7 = Mm(Mm(v3, v3), v);
        var x = Mm(Mm(u, v3), PowFq(Mm(u, v7), (Q - 5) >> 3));
        var vx2 = Mm(v, Mm(x, x));
        if (vx2 == ModFq(u))
        {
            // x is correct as-is
        }
        else if (vx2 == ModFq(-u))
        {
            x = Mm(x, SqrtM1);
        }
        else
        {
            throw new PointValidationError("decompressPoint: not on curve");
        }
        if (x.IsZero && sign == 1) throw new PointValidationError("decompressPoint: non-canonical sign");
        if ((x.IsEven ? 0 : 1) != sign) x = ModFq(Q - x);
        return FromAffine(x, y);
    }

    /// <summary>Whether the extended coordinates lie on the curve (projectively, no inversion).</summary>
    public static bool IsOnCurve(Point p)
    {
        if (ModFq(p.Z).IsZero) return false;
        if (ModFq(p.T * p.Z) != ModFq(p.X * p.Y)) return false;
        BigInteger x2 = Mm(p.X, p.X), y2 = Mm(p.Y, p.Y), z2 = Mm(p.Z, p.Z);
        var lhs = ModFq((y2 - x2) * z2);
        var z4 = Mm(z2, z2);
        var dxy = Mm(Mm(D, x2), y2);
        return lhs == ModFq(z4 + dxy);
    }

    public static bool IsIdentity(Point p) => Equal(p, IDENTITY);

    /// <summary>The cofactor check [L]P = O (true for the identity too).</summary>
    public static bool HasPrimeOrder(Point p)
    {
        if (!IsOnCurve(p)) return false;
        // the group law decides (IsTorsionFree multiplies by L with the plain add): libsodium 1.0.20 and older accept a mixed-order point through its validity query
        return IsIdentity(p) || AtlasPca.Ratchet.EdwardsPoint.FromBytes(CompressPoint(p)).IsTorsionFree();
    }

    /// <summary>A valid non-identity point of the prime-order subgroup.</summary>
    public static bool IsInSubgroup(Point p) => IsOnCurve(p) && !IsIdentity(p) && HasPrimeOrder(p);

    public static void AssertInSubgroup(Point p, string label)
    {
        if (!IsOnCurve(p)) throw new PointValidationError(label + ": not on curve");
        if (IsIdentity(p)) throw new PointValidationError(label + ": identity element (forbidden here)");
        if (!HasPrimeOrder(p)) throw new PointValidationError(label + ": not in the prime-order subgroup (small-order/cofactor)");
    }

    public static void AssertInSubgroup(Point p) => AssertInSubgroup(p, "point");

    /// <summary>Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y.</summary>
    public sealed record SchnorrProof(Point U, BigInteger Z);

    static readonly byte[] TagSchnorr = Encoding.UTF8.GetBytes("atlas-pca-mpc/schnorr-dlog");

    static BigInteger SchnorrChallenge(Point S, Point U, byte[] ctx)
    {
        using var ms = new MemoryStream();
        void W(byte[] b) => ms.Write(b, 0, b.Length);
        W(TagSchnorr);
        W(new[] { (byte)(ctx.Length >>> 24), (byte)(ctx.Length >>> 16), (byte)(ctx.Length >>> 8), (byte)ctx.Length });
        W(ctx);
        W(EncodePoint(BASE));
        W(EncodePoint(S));
        W(EncodePoint(U));
        return Mod(new BigInteger(SHA512.HashData(ms.ToArray()), isUnsigned: true, isBigEndian: true), L);
    }

    public static SchnorrProof SchnorrProve(BigInteger y, Point S, Func<BigInteger> rnd, byte[]? ctx)
    {
        if (ctx == null || ctx.Length == 0) throw new ArgumentException("schnorrProve: a non-empty session binding is required");
        var r = Mod(rnd(), L);
        if (r.IsZero) throw new InvalidOperationException("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof");
        var U = MulBase(r);
        var e = SchnorrChallenge(S, U, ctx);
        var z = Mod(r + e * Mod(y, L), L);
        return new SchnorrProof(U, z);
    }

    public static bool SchnorrVerify(Point S, SchnorrProof proof, byte[]? ctx)
    {
        if (ctx == null || ctx.Length == 0) return false;
        if (proof.Z.Sign < 0 || proof.Z >= L) return false;
        if (!IsInSubgroup(proof.U)) return false;
        var e = SchnorrChallenge(S, proof.U, ctx);
        try
        {
            return Equal(MulBase(proof.Z), Add(proof.U, Mul(e, S)));
        }
        catch (PointValidationError)
        {
            return false;
        }
    }
}
