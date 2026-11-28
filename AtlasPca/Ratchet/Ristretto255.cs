// ristretto255 (RFC 9496) over libsodium (AtlasPca.Native.Sodium): the prime-order group of the Pedersen risk accumulator and the OPRF suite
// (packages/pca-ratchet group.ts). No group or field arithmetic lives here; multiplication by a secret scalar is libsodium's constant-time one.
// Elements and scalars cross the API as BigInteger/objects but are held as canonical 32-byte encodings.
using System.Numerics;
using AtlasPca.Native;

namespace AtlasPca.Ratchet;

/// <summary>A ristretto255 group element (immutable; held as its canonical 32-byte encoding).</summary>
public sealed class RistrettoPoint
{
    /// <summary>Prime order of the group (= the ed25519 subgroup order).</summary>
    public static readonly BigInteger Order = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);

    readonly byte[] _e;
    RistrettoPoint(byte[] canonical) { _e = canonical; }

    /// <summary>The identity element.</summary>
    public static readonly RistrettoPoint Zero = new(new byte[32]);

    /// <summary>The standard generator: the encoding RFC 9496 gives for it (the ed25519 base point's class).</summary>
    public static readonly RistrettoPoint Base = Decode(Convert.FromHexString("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"));

    /// <summary>Decode a 32-byte encoding; null for a non-canonical, negative, off-group or otherwise invalid encoding.</summary>
    public static RistrettoPoint? TryDecode(ReadOnlySpan<byte> enc)
    {
        if (enc.Length != 32) return null;
        var b = enc.ToArray();
        return Sodium.RistrettoIsValidPoint(b) ? new RistrettoPoint(b) : null;
    }

    /// <summary>Decode a 32-byte encoding; throws <see cref="FormatException"/> when it is not a valid ristretto255 element.</summary>
    public static RistrettoPoint Decode(ReadOnlySpan<byte> enc) =>
        TryDecode(enc) ?? throw new FormatException("ristretto255: invalid encoding");

    /// <summary>The canonical 32-byte encoding.</summary>
    public byte[] Encode() => (byte[])_e.Clone();

    /// <summary>The one-way map from 64 uniform bytes (RFC 9496 hash-to-group).</summary>
    public static RistrettoPoint FromUniformBytes(ReadOnlySpan<byte> bytes64)
    {
        if (bytes64.Length != 64) throw new ArgumentException("ristretto255: 64 uniform bytes required");
        return new(Sodium.RistrettoFromHash(bytes64.ToArray()));
    }

    /// <summary>The sum of two elements.</summary>
    public RistrettoPoint Add(RistrettoPoint o) => new(Sodium.RistrettoAdd(_e, o._e));

    /// <summary>This element minus another.</summary>
    public RistrettoPoint Subtract(RistrettoPoint o) => new(Sodium.RistrettoSub(_e, o._e));

    /// <summary>The additive inverse.</summary>
    public RistrettoPoint Negate() => Zero.Subtract(this);

    /// <summary>k times this element for 1 &lt;= k &lt; Order (libsodium, constant time in k).</summary>
    public RistrettoPoint Multiply(BigInteger k)
    {
        if (k.Sign <= 0 || k >= Order) throw new ArgumentOutOfRangeException(nameof(k), "scalar must be in [1, order)");
        var n = RistrettoScalar.ToLe(k, 32);
        // libsodium refuses an identity result: only the identity element times a non-zero scalar gives one here.
        var q = ReferenceEquals(this, Base) ? Sodium.RistrettoMulBase(n) : Sodium.RistrettoMul(n, _e);
        if (q != null) return new(q);
        if (_e.All(x => x == 0)) return Zero;
        throw new InvalidOperationException("ristretto255: scalar multiplication failed");
    }

    /// <summary>Group equality: the same ristretto255 element (encodings are canonical, so byte equality).</summary>
    public bool Equals(RistrettoPoint o) => _e.AsSpan().SequenceEqual(o._e);

    public override bool Equals(object? obj) => obj is RistrettoPoint p && Equals(p);
    public override int GetHashCode() => BitConverter.ToInt32(_e, 0);
}

/// <summary>Scalar arithmetic modulo the group order (RFC 9496: the ed25519 subgroup order L), on libsodium's constant-time scalar routines.</summary>
public static class RistrettoScalar
{
    public static BigInteger Order => RistrettoPoint.Order;

    /// <summary>Reduce an integer into [0, L).</summary>
    public static BigInteger Mod(BigInteger x) => FromLe(Red(x));

    static byte[] Red(BigInteger x)
    {
        var neg = x.Sign < 0;
        var raw = (neg ? -x : x).ToByteArray(isUnsigned: true, isBigEndian: false);
        // shortcut: an input wider than 512 bits (never a product of two reduced scalars) takes the BigInteger path; callers pass public data there.
        if (raw.Length > 64) { var r = x % Order; return ToLe(r.Sign < 0 ? r + Order : r, 32); }
        var red = Sodium.ScalarReduce(raw);
        return neg ? Sodium.ScalarNegate(red) : red;
    }

    public static BigInteger Add(BigInteger a, BigInteger b) => FromLe(Sodium.ScalarAdd(Red(a), Red(b)));
    public static BigInteger Sub(BigInteger a, BigInteger b) => FromLe(Sodium.ScalarSub(Red(a), Red(b)));
    public static BigInteger Mul(BigInteger a, BigInteger b) => FromLe(Sodium.ScalarMul(Red(a), Red(b)));

    /// <summary>Multiplicative inverse mod L; throws for a scalar that is 0 mod L.</summary>
    public static BigInteger Invert(BigInteger a) =>
        Sodium.ScalarInvert(Red(a)) is { } r ? FromLe(r) : throw new DivideByZeroException("scalar inverse of zero");

    /// <summary>Little-endian bytes (any length) to an unsigned integer.</summary>
    public static BigInteger FromLe(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    /// <summary>Reduce 64 uniform bytes (little-endian) mod L.</summary>
    public static BigInteger Reduce64(ReadOnlySpan<byte> b64)
    {
        if (b64.Length != 64) throw new ArgumentException("64 bytes required");
        return FromLe(Sodium.ScalarReduce(b64.ToArray()));
    }

    /// <summary>A non-negative integer as little-endian bytes of exactly <paramref name="len"/>; throws when it does not fit.</summary>
    public static byte[] ToLe(BigInteger n, int len)
    {
        if (n.Sign < 0) throw new ArgumentOutOfRangeException(nameof(n), "negative");
        var b = n.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (b.Length > len && b.Skip(len).Any(x => x != 0)) throw new ArgumentOutOfRangeException(nameof(n), "overflow");
        var o = new byte[len];
        Array.Copy(b, o, Math.Min(len, b.Length));
        return o;
    }
}
