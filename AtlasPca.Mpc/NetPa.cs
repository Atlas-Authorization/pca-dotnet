using System.Numerics;
using static AtlasPca.Mpc.Field;

namespace AtlasPca.Mpc;

/// <summary>
/// Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per verifier and
/// one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local.
/// </summary>
public static class NetPa
{
    /// <summary>x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share).</summary>
    public sealed record PA(BigInteger X, BigInteger[] Tag, BigInteger[] Key);

    /// <summary>An authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated.</summary>
    public sealed record AW(PA V, PA[] M);

    public sealed record PaEnv(int Id, int N, BigInteger Delta, bool Tagged);

    static BigInteger[] Zip(BigInteger[] a, BigInteger[] b, Func<BigInteger, BigInteger, BigInteger> f)
    {
        var o = new BigInteger[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = f(a[i], b[i]);
        return o;
    }

    static BigInteger[] Map(BigInteger[] a, Func<BigInteger, BigInteger> f)
    {
        var o = new BigInteger[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = f(a[i]);
        return o;
    }

    public static PA PaAdd(PA a, PA b) => new(Fadd(a.X, b.X), Zip(a.Tag, b.Tag, Fadd), Zip(a.Key, b.Key, Fadd));
    public static PA PaSub(PA a, PA b) => new(Fsub(a.X, b.X), Zip(a.Tag, b.Tag, Fsub), Zip(a.Key, b.Key, Fsub));
    public static PA PaNeg(PA a) => new(Fneg(a.X), Map(a.Tag, Fneg), Map(a.Key, Fneg));
    public static PA PaScale(PA a, BigInteger c) => new(Fmul(a.X, c), Map(a.Tag, t => Fmul(t, c)), Map(a.Key, k => Fmul(k, c)));

    /// <summary>Adds a PUBLIC constant to party 0's share (every party applies the same call).</summary>
    public static PA PaAddPublic0(PaEnv env, PA a, BigInteger c)
    {
        if (env.Id == 0) return new PA(Fadd(a.X, c), a.Tag, a.Key);
        if (!env.Tagged) return a;
        var key = (BigInteger[])a.Key.Clone();
        key[0] = Fsub(key[0], Fmul(env.Delta, c));
        return new PA(a.X, a.Tag, key);
    }

    static PA[] Each(PA[] a, Func<PA, PA> f)
    {
        var o = new PA[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = f(a[i]);
        return o;
    }

    public static AW WAdd(AW a, AW b)
    {
        var m = new PA[a.M.Length];
        for (int l = 0; l < m.Length; l++) m[l] = PaAdd(a.M[l], b.M[l]);
        return new AW(PaAdd(a.V, b.V), m);
    }

    public static AW WSub(AW a, AW b)
    {
        var m = new PA[a.M.Length];
        for (int l = 0; l < m.Length; l++) m[l] = PaSub(a.M[l], b.M[l]);
        return new AW(PaSub(a.V, b.V), m);
    }

    public static AW WNeg(AW a) => new(PaNeg(a.V), Each(a.M, PaNeg));

    public static AW WScale(AW a, BigInteger c) => new(PaScale(a.V, c), Each(a.M, p => PaScale(p, c)));

    /// <summary>x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c.</summary>
    public static AW WAddPublic(PaEnv env, AW a, BigInteger c, PA[] alpha)
    {
        var m = new PA[a.M.Length];
        for (int l = 0; l < m.Length; l++) m[l] = PaAdd(a.M[l], PaScale(alpha[l], c));
        return new AW(PaAddPublic0(env, a.V, c), m);
    }

    /// <summary>Verifies peer <paramref name="from"/>'s opened share x with tag against my key for that peer.</summary>
    public static bool PaVerify(PaEnv env, PA a, int from, BigInteger x, BigInteger tag) => Fadd(a.Key[from], Fmul(env.Delta, x)) == tag;

    // ---- wire codec ----

    public static int PaWidth(int n, bool tagged) => tagged ? 1 + 2 * (n - 1) : 1;

    public static List<BigInteger> PaFlat(PA a, int id, int n, bool tagged)
    {
        var o = new List<BigInteger> { a.X };
        if (tagged)
        {
            for (int j = 0; j < n; j++) if (j != id) o.Add(a.Tag[j]);
            for (int j = 0; j < n; j++) if (j != id) o.Add(a.Key[j]);
        }
        return o;
    }

    public static PA PaParse(IReadOnlyList<BigInteger> nums, int off, int id, int n, bool tagged)
    {
        var x = nums[off];
        if (!tagged) return new PA(x, Array.Empty<BigInteger>(), Array.Empty<BigInteger>());
        var tag = new BigInteger[n];
        var key = new BigInteger[n];
        int o = off + 1;
        for (int j = 0; j < n; j++) if (j != id) tag[j] = nums[o++];
        for (int j = 0; j < n; j++) if (j != id) key[j] = nums[o++];
        return new PA(x, tag, key);
    }

    public static int AwWidth(int n, int keys, bool tagged) => (1 + keys) * PaWidth(n, tagged);

    public static List<BigInteger> AwFlat(AW a, int id, int n, bool tagged)
    {
        var o = new List<BigInteger>(PaFlat(a.V, id, n, tagged));
        foreach (var p in a.M) o.AddRange(PaFlat(p, id, n, tagged));
        return o;
    }

    public static AW AwParse(IReadOnlyList<BigInteger> nums, int off, int id, int n, int keys, bool tagged)
    {
        int w = PaWidth(n, tagged);
        var v = PaParse(nums, off, id, n, tagged);
        var m = new PA[keys];
        for (int l = 0; l < keys; l++) m[l] = PaParse(nums, off + (1 + l) * w, id, n, tagged);
        return new AW(v, m);
    }
}
