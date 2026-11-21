using System.Globalization;
using System.Numerics;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mpc.Tests;

/// <summary>Argument decoding and result encoding shared by the MPC differential tests (bigints travel as decimal strings).</summary>
static class MpcSupport
{
    public static BigInteger B(object? o)
    {
        if (o is not string s) throw new ArgumentException("bigint arg");
        return BigInteger.Parse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
    }

    public static double Dbl(object? o) => o is Num n ? double.Parse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture) : throw new ArgumentException("not a number");

    /// <summary>A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure).</summary>
    public static int I(object? o)
    {
        var d = Dbl(o);
        if (double.IsNaN(d) || double.IsInfinity(d) || d != Math.Round(d)) throw new ArgumentException("not an integer");
        if (Math.Abs(d) > 1e9) return d > 0 ? int.MaxValue : int.MinValue;
        return (int)d;
    }

    public static Field.FieldRng Rng(object? seed) => new(B(seed));

    // a null element is the reference's undefined share: the Java port NPEs, the native refuses the same way
    public static BigInteger[] BA(object? o) => ((L)o!).Select(x => x == null ? throw new ArgumentException("missing value") : B(x)).ToArray();

    public static BigInteger[][] BAA(object? o) => ((L)o!).Select(BA).ToArray();

    public static int[] IA(object? o) => ((L)o!).Select(I).ToArray();

    public static string S(BigInteger b) => b.ToString(CultureInfo.InvariantCulture);

    public static L Ls(BigInteger[] a) => a.Select(x => (object?)S(x)).ToList();

    public static L LL(BigInteger[][] a) => a.Select(x => (object?)Ls(x)).ToList();

    public static L Li(int[] a) => a.Select(x => (object?)x).ToList();

    public static D M(params object?[] kv)
    {
        var m = new D();
        for (int i = 0; i < kv.Length; i += 2) m[(string)kv[i]!] = kv[i + 1];
        return m;
    }

    public static D Map(object? o) => o as D ?? throw new ArgumentException("not an object");

    public static List<Party.DecisionVector?> Vectors(object? o)
    {
        if (o is not L l) throw new ArgumentException("decision vectors must be an array");
        var o2 = new List<Party.DecisionVector?>();
        foreach (var e in l)
        {
            if (e is not D m) throw new ArgumentException("decision vector must be an object");
            o2.Add(new Party.DecisionVector(I(m.GetValueOrDefault("allow")), I(m.GetValueOrDefault("t")), I(m.GetValueOrDefault("rQuant"))));
        }
        return o2;
    }

    public static D AuthSv(Spdz.AuthSV x) => M("value", Ls(x.Value), "mac", Ls(x.Mac), "extraMac", LL(x.ExtraMac));

    public static D Triple(Spdz.AuthTriple t) => M("a", AuthSv(t.A), "b", AuthSv(t.B), "c", AuthSv(t.C));

    public static D Key(Spdz.MacKey k) => M("alphaShares", Ls(k.AlphaShares), "alpha", S(k.Alpha));

    public static D Ctx(Spdz.MacContext c) =>
        M("n", c.N, "alphaShares", Ls(c.AlphaShares), "alpha", S(c.Alpha), "extraKeys", c.ExtraKeys.Select(k => (object?)Key(k)).ToList());

    public static List<Spdz.Deviation> Devs(object? o)
    {
        var o2 = new List<Spdz.Deviation>();
        foreach (var e in (L)o!)
        {
            var d = (L)e!;
            o2.Add(new Spdz.Deviation(I(d[0]), I(d[1]), d[2] == null ? null : B(d[2]), d[3] == null ? null : B(d[3]), d[4] == null ? null : I(d[4])));
        }
        return o2;
    }

    public static Spdz.DealerFault? Fault(object? o)
    {
        if (o == null) return null;
        var m = Map(o);
        List<BigInteger?>? p = null;
        if (m.GetValueOrDefault("partnerCDelta") != null)
            p = ((L)m["partnerCDelta"]!).Select(x => x == null ? (BigInteger?)null : B(x)).ToList();
        return new Spdz.DealerFault(m.GetValueOrDefault("keepCDelta") == null ? null : B(m["keepCDelta"]), p);
    }
}
