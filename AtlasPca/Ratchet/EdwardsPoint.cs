// Public handle on an Edwards25519 point (the Ed25519 group, RFC 8032 encoding), held as its canonical 32-byte encoding. All group
// arithmetic is libsodium's (AtlasPca.Native.Sodium): point multiplication by a secret scalar is constant time. Immutable.
using System.Numerics;
using AtlasPca.Native;

namespace AtlasPca.Ratchet;

public sealed class EdwardsPoint
{
    public static readonly BigInteger Order = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);
    static readonly byte[] IdBytes = Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000000");
    public static readonly EdwardsPoint Zero = new(IdBytes);
    /// <summary>The Ed25519 base point (y = 4/5, even x).</summary>
    public static readonly EdwardsPoint Base = new(Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666"));

    readonly byte[] _b;
    EdwardsPoint(byte[] canonical) { _b = canonical; }

    /// <summary>Decode a canonical 32-byte Ed25519 point (RFC 8032 section 5.1.3): throws on a wrong length, a non-canonical encoding or a point off the curve. Torsion is not checked here.</summary>
    public static EdwardsPoint FromBytes(byte[] b)
    {
        if (b == null || b.Length != 32) throw new ArgumentException("ed25519: point must be 32 bytes");
        // libsodium's add validates the curve equation; a non-canonical y or x = 0 with the sign bit set re-encodes differently.
        var r = Sodium.Ed25519Add(b, IdBytes);
        if (r == null) throw new ArgumentException("ed25519: point is not on the curve");
        if (!r.AsSpan().SequenceEqual(b)) throw new ArgumentException("ed25519: non-canonical point encoding");
        return new EdwardsPoint(r);
    }

    public EdwardsPoint Add(EdwardsPoint o) =>
        new(Sodium.Ed25519Add(_b, o._b) ?? throw new InvalidOperationException("ed25519: add failed"));

    /// <summary>k times this point for 0 &lt;= k &lt; 2^256 (zero gives the identity). The point must be the identity or in the prime-order subgroup (libsodium refuses anything else; throws InvalidOperationException).</summary>
    public EdwardsPoint Multiply(BigInteger k)
    {
        if (k.Sign < 0 || k.GetBitLength() > 256) throw new ArgumentOutOfRangeException(nameof(k));
        var raw = k.ToByteArray(isUnsigned: true, isBigEndian: false);
        var n = Sodium.ScalarReduce(raw); // libsodium's noclamp multiply masks the top bit, so reduce mod L first
        if (IsIdentity() || n.All(x => x == 0)) return Zero;
        var q = (ReferenceEquals(this, Base) ? Sodium.Ed25519MulBase(n) : Sodium.Ed25519Mul(n, _b))
            ?? throw new InvalidOperationException("ed25519: point is not in the prime-order subgroup");
        return new EdwardsPoint(q);
    }

    /// <summary>True point equality (canonical encodings are unique).</summary>
    public bool SameAs(EdwardsPoint o) => _b.AsSpan().SequenceEqual(o._b);

    public bool IsIdentity() => SameAs(Zero);

    /// <summary>8 * P is the identity.</summary>
    public bool IsSmallOrder()
    {
        var t = this;
        for (var i = 0; i < 3; i++) t = t.Add(t);
        return t.IsIdentity();
    }

    /// <summary>L * P is the identity (no torsion component): the identity itself or a valid prime-subgroup point.</summary>
    public bool IsTorsionFree() => IsIdentity() || (Sodium.Ed25519IsValidPoint(_b) && TimesOrderIsIdentity());

    /// <summary>L * P by double-and-add over the group law alone (no subgroup precondition, a public point): the definition of "no torsion component",
    /// independent of how a given libsodium build answers its validity query for a mixed-order point.</summary>
    bool TimesOrderIsIdentity()
    {
        EdwardsPoint? acc = null;
        for (int i = (int)Order.GetBitLength() - 1; i >= 0; i--)
        {
            if (acc != null) acc = acc.Add(acc);
            if (!((Order >> i) & 1).IsZero) acc = acc == null ? this : acc.Add(this);
        }
        return acc != null && acc.IsIdentity();
    }

    /// <summary>The canonical 32-byte Ed25519 encoding.</summary>
    public byte[] ToBytes() => (byte[])_b.Clone();
}
