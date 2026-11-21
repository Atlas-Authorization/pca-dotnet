using System.Numerics;
using static AtlasPca.Mpc.Field;

namespace AtlasPca.Mpc;

/// <summary>
/// Privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform bits b and takes
/// x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding.
/// </summary>
public static class Enc
{
    public const int FIELD_BITS = 61;
    public const int STAT_SEC = 64;
    public const int MIN_STAT_SEC = 40;

    static bool Bit(BigInteger v, int i) => !((v >> i) & BigInteger.One).IsZero;

    public static int EncBits(int s) => FIELD_BITS + 3 * s;

    /// <summary>A receiver operand: its field value together with the choice bits that encode it.</summary>
    public sealed record EncShare(BigInteger Value, int[] Bits);

    public static BigInteger[] MakeGadget(int s, IFieldSource next, bool unsafeOk)
    {
        if (s < 0 || s > 64) throw new ArgumentException("statSec must be an integer in [0, 64]");
        if (s < MIN_STAT_SEC && !unsafeOk)
            throw new ArgumentException("statSec " + s + " is below " + MIN_STAT_SEC + ": refused (tests may pass the explicit unsafe flag)");
        int m = EncBits(s);
        var g = new BigInteger[m];
        for (int k = 0; k < m; k++) g[k] = s == 0 ? Mod(BigInteger.One << k) : next.Next();
        return g;
    }

    public static BigInteger EncValue(BigInteger[] g, int[] bits)
    {
        if (g.Length != bits.Length) throw new ArgumentException("encValue: gadget / bits length mismatch");
        var v = BigInteger.Zero;
        for (int k = 0; k < g.Length; k++) if (bits[k] == 1) v += g[k];
        return Mod(v);
    }

    public static EncShare PlainShare(BigInteger x)
    {
        var v = Mod(x);
        var bits = new int[FIELD_BITS];
        for (int k = 0; k < FIELD_BITS; k++) bits[k] = Bit(v, k) ? 1 : 0;
        return new EncShare(v, bits);
    }

    public static BigInteger[] PlainGadget()
    {
        var g = new BigInteger[FIELD_BITS];
        for (int k = 0; k < FIELD_BITS; k++) g[k] = Mod(BigInteger.One << k);
        return g;
    }

    /// <summary>m uniform bits from a field source (the 60 low bits of each draw are uniform).</summary>
    public static int[] RandomBits(int m, IFieldSource rng)
    {
        var o = new int[m];
        int k = 0;
        while (k < m)
        {
            var w = rng.Next();
            for (int i = 0; i < 60 && k < m; i++, k++) o[k] = Bit(w, i) ? 1 : 0;
        }
        return o;
    }

    public static EncShare SampleEnc(BigInteger[] g, IFieldSource rng)
    {
        var bits = RandomBits(g.Length, rng);
        return new EncShare(EncValue(g, bits), bits);
    }
}
