// Prime-order group layer of the homomorphic risk accumulator (packages/pca-ratchet group.ts): the ristretto255 generators G and H,
// scalar helpers mod L, the wire encodings (canonical base64url) and the Fiat-Shamir transcript hash.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace AtlasPca.Ratchet;

public static class RatchetGroup
{
    /// <summary>Prime order of ristretto255 (= the ed25519 subgroup order).</summary>
    public static BigInteger L => RistrettoPoint.Order;

    /// <summary>The standard generator G.</summary>
    public static RistrettoPoint G => RistrettoPoint.Base;

    /// <summary>The identity element.</summary>
    public static RistrettoPoint Zero => RistrettoPoint.Zero;

    const string HLabel = "atlas-pca-ratchet/pedersen-generator-H/v1";

    /// <summary>The second Pedersen generator H: hash-to-group of a constant label, so nobody knows dlog_G(H).</summary>
    public static readonly RistrettoPoint H = RistrettoPoint.FromUniformBytes(SHA512.HashData(Encoding.UTF8.GetBytes(HLabel)));

    public static BigInteger Mod(BigInteger x) => RistrettoScalar.Mod(x);
    public static BigInteger ScalarAdd(BigInteger a, BigInteger b) => RistrettoScalar.Add(a, b);
    public static BigInteger ScalarSub(BigInteger a, BigInteger b) => RistrettoScalar.Sub(a, b);
    public static BigInteger ScalarMul(BigInteger a, BigInteger b) => RistrettoScalar.Mul(a, b);

    /// <summary>k times P, tolerating k = 0 (mod L) by returning the identity. The multiplication is ALWAYS performed (by 1 when
    /// k = 0) and the identity chosen afterwards, so the call does not reveal by its cost whether a secret scalar is zero.</summary>
    public static RistrettoPoint Mul(RistrettoPoint p, BigInteger k)
    {
        var s = Mod(k);
        var r = p.Multiply(s.IsZero ? BigInteger.One : s);
        return s.IsZero ? RistrettoPoint.Zero : r;
    }

    public static RistrettoPoint Add(RistrettoPoint a, RistrettoPoint b) => a.Add(b);
    public static RistrettoPoint Sub(RistrettoPoint a, RistrettoPoint b) => a.Subtract(b);

    /// <summary>A uniformly random non-zero scalar in [1, L).</summary>
    public static BigInteger RandScalar()
    {
        for (; ; )
        {
            var s = Mod(BytesToNumberLe(RandomNumberGenerator.GetBytes(64)));
            if (!s.IsZero) return s;
        }
    }

    public static byte[] NumberToBytesLe(BigInteger n, int len) => RistrettoScalar.ToLe(n, len);
    public static BigInteger BytesToNumberLe(byte[] b) => RistrettoScalar.FromLe(b);

    public static string EncodePoint(RistrettoPoint p) => Pca.B64u(p.Encode());

    /// <summary>Decode a wire point; throws on a non-canonical base64url string, a length other than 32 bytes, or an invalid ristretto encoding.</summary>
    public static RistrettoPoint DecodePoint(object? s)
    {
        var bytes = Pca.B64uDecode(s, 32) ?? throw new FormatException("decodePoint: not a canonical 32-byte base64url string");
        return RistrettoPoint.Decode(bytes);
    }

    public static string EncodeScalar(BigInteger k) => Pca.B64u(NumberToBytesLe(Mod(k), 32));

    /// <summary>Decode a wire scalar. Strict: canonical base64url, exactly 32 bytes, value below L (reducing instead would make every proof malleable).</summary>
    public static BigInteger DecodeScalar(object? s)
    {
        var bytes = Pca.B64uDecode(s, 32) ?? throw new FormatException("decodeScalar: not a canonical 32-byte base64url string");
        var v = BytesToNumberLe(bytes);
        if (v >= L) throw new FormatException("decodeScalar: non-canonical scalar (>= L)");
        return v;
    }

    /// <summary>Length-prefixed concatenation (4-byte big-endian length per part), hashed with SHA-512 and reduced mod L.</summary>
    public static BigInteger HashToScalar(IReadOnlyList<byte[]> parts)
    {
        using var ms = new MemoryStream();
        foreach (var p in parts)
        {
            ms.WriteByte((byte)(p.Length >>> 24));
            ms.WriteByte((byte)(p.Length >>> 16));
            ms.WriteByte((byte)(p.Length >>> 8));
            ms.WriteByte((byte)p.Length);
            ms.Write(p, 0, p.Length);
        }
        return Mod(BytesToNumberLe(SHA512.HashData(ms.ToArray())));
    }

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}
