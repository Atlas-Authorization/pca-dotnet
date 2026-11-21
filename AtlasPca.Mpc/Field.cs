using System.Numerics;
using System.Security.Cryptography;

namespace AtlasPca.Mpc;

/// <summary>
/// Arithmetic in the prime field F_p (p = 2^61 - 1) used for additive secret sharing, plus the field randomness sources: a deterministic
/// SplitMix64 <see cref="FieldRng"/> (reproducible tests behind an explicit seed) and the CSPRNG <see cref="SecureFieldRng"/> (the default for
/// protocol randomness). All arithmetic is exact BigInteger.
/// </summary>
public static class Field
{
    public static readonly BigInteger PRIME = (BigInteger.One << 61) - 1;
    internal const ulong PRIME_LONG = (1UL << 61) - 1;
    // Largest multiple of p that fits in 64 bits is 2^64 - 8; anything at or above it is rejected so `% p` is uniform.
    internal const ulong LIMIT = ulong.MaxValue - 7;

    /// <summary>Canonical representative in [0, p).</summary>
    public static BigInteger Mod(BigInteger x) { var r = x % PRIME; return r.Sign < 0 ? r + PRIME : r; }
    public static BigInteger Fadd(BigInteger a, BigInteger b) => Mod(a + b);
    public static BigInteger Fsub(BigInteger a, BigInteger b) => Mod(a - b);
    public static BigInteger Fmul(BigInteger a, BigInteger b) => Mod(a * b);
    public static BigInteger Fneg(BigInteger a) => Mod(-a);

    /// <summary>Lower-case hex of a non-negative integer without a leading zero (Java BigInteger.toString(16)).</summary>
    public static string Hex(BigInteger v)
    {
        if (v.Sign < 0) return "-" + Hex(-v);
        var s = v.ToString("x").TrimStart('0');
        return s.Length == 0 ? "0" : s;
    }

    /// <summary>Non-negative integer from lower/upper-case hex digits (the caller has validated the text).</summary>
    public static BigInteger ParseHex(string s) =>
        BigInteger.Parse("0" + s, System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>A source of uniform field elements.</summary>
    public interface IFieldSource { BigInteger Next(); }

    /// <summary>Deterministic SplitMix64 drawing unbiased field elements by rejection sampling.</summary>
    public class FieldRng : IFieldSource
    {
        ulong _s;

        public FieldRng() : this(ParseHex("243f6a8885a308d3")) { }

        // the low 64 bits of the seed (Java BigInteger.longValue)
        public FieldRng(BigInteger seed) { _s = (ulong)(seed & ulong.MaxValue); }

        internal ulong NextU64()
        {
            unchecked
            {
                _s += 0x9e3779b97f4a7c15UL;
                var z = _s;
                z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9UL;
                z = (z ^ (z >> 27)) * 0x94d049bb133111ebUL;
                return z ^ (z >> 31);
            }
        }

        public virtual BigInteger Next()
        {
            for (;;)
            {
                var u = NextU64();
                if (u < LIMIT) return new BigInteger(u % PRIME_LONG);
            }
        }
    }

    /// <summary>CSPRNG-backed field source: fresh random bytes, rejection sampled.</summary>
    public sealed class SecureFieldRng : FieldRng
    {
        public SecureFieldRng() : base(BigInteger.Zero) { }

        public override BigInteger Next()
        {
            for (;;)
            {
                var u = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
                if (u < LIMIT) return new BigInteger(u % PRIME_LONG);
            }
        }
    }

    /// <summary>CSPRNG by default, a reproducible seeded <see cref="FieldRng"/> only when <paramref name="testSeed"/> is non-null.</summary>
    public static IFieldSource FieldRandom(BigInteger? testSeed) => testSeed is null ? new SecureFieldRng() : new FieldRng(testSeed.Value);
}
