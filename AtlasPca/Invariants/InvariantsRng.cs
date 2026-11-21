namespace AtlasPca.Invariants;

/// <summary>The seeded PRNG behind the invariant property generators: mulberry32, a 32-bit generator whose stream for a seed is the same in every
/// implementation. One stream per property, seeded from (seed, property index) by <see cref="ForProperty"/>; a property draws <c>numRuns</c> cases from
/// its stream, so the same (seed, index) always gives the same cases and another seed gives another stream.</summary>
public sealed class InvariantsRng
{
    uint _a;

    public InvariantsRng(long seed) { _a = unchecked((uint)(seed & 0xFFFFFFFFL)); }

    /// <summary>The stream of property number <paramref name="index"/> for <paramref name="seed"/> (the seed's high half is folded in, so any 64-bit seed is distinct).</summary>
    public static InvariantsRng ForProperty(long seed, int index) => new(unchecked((seed ^ (seed >> 32)) + index * 0x9E3779B1L));

    /// <summary>The next float in [0, 1).</summary>
    public double Next()
    {
        unchecked
        {
            _a += 0x6D2B79F5u;
            uint t = _a;
            t = (t ^ (t >> 15)) * (t | 1u);
            t ^= t + (t ^ (t >> 7)) * (t | 61u);
            return (t ^ (t >> 14)) / 4294967296.0;
        }
    }

    /// <summary>A uniform integer in [lo, hi].</summary>
    public long Int(long lo, long hi) => Math.Min(hi, lo + (long)Math.Floor(Next() * (hi - lo + 1)));

    /// <summary>An integer in [lo, hi] that hits each bound about 6% of the time (edge cases are where properties break).</summary>
    public long IntB(long lo, long hi)
    {
        var r = Next();
        return r < 0.06 ? lo : r < 0.12 ? hi : Int(lo, hi);
    }

    /// <summary>A float in [lo, hi] (never NaN) that hits each bound about 6% of the time.</summary>
    public double Dbl(double lo, double hi)
    {
        var r = Next();
        return r < 0.06 ? lo : r < 0.12 ? hi : lo + Next() * (hi - lo);
    }

    public bool Bool() => Next() < 0.5;

    public T Pick<T>(IReadOnlyList<T> xs) => xs[(int)Int(0, xs.Count - 1)];

    /// <summary><paramref name="n"/> random bytes.</summary>
    public byte[] Bytes(int n)
    {
        var b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)Int(0, 255);
        return b;
    }

    /// <summary>A printable-ASCII (0x20 to 0x7e) string of length min..max.</summary>
    public string String(int min, int max)
    {
        var n = (int)Int(min, max);
        var c = new char[n];
        for (int i = 0; i < n; i++) c[i] = (char)Int(0x20, 0x7E);
        return new string(c);
    }
}
