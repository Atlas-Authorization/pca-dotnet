using System.Numerics;

namespace AtlasPca.Mpc;

/// <summary>Thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR.</summary>
public static class Thermometer
{
    /// <summary>Encodes v in {0..M}; v is clamped into range (fail-safe). v is a JS number (non-finite clamps like Math.trunc).</summary>
    public static int[] ThermometerEncode(double v, int M)
    {
        if (M < 0) throw new ArgumentException("thermometerEncode: M must be a non-negative integer");
        double tr = double.IsNaN(v) ? double.NaN : (v < 0 ? Math.Ceiling(v) : Math.Floor(v));
        double clamped = double.IsNaN(tr) ? double.NaN : Math.Max(0, Math.Min(M, tr));
        var bits = new int[M];
        for (int k = 1; k <= M; k++) bits[k - 1] = clamped >= k ? 1 : 0; // NaN compares false: all zero
        return bits;
    }

    /// <summary>Number of 1s (robust to non-monotone input).</summary>
    public static int ThermometerDecode(int[] bits)
    {
        int c = 0;
        foreach (var b in bits) if (b == 1) c++;
        return c;
    }

    public static int ThermometerDecode(BigInteger[] bits)
    {
        int c = 0;
        foreach (var b in bits) if (b.IsOne) c++;
        return c;
    }
}
