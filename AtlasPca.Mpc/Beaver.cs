using System.Numerics;
using static AtlasPca.Mpc.Field;

namespace AtlasPca.Mpc;

/// <summary>Secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples).</summary>
public static class Beaver
{
    /// <summary>A Beaver triple (a, b, c = a*b), each component additively shared.</summary>
    public sealed record Triple(BigInteger[] A, BigInteger[] B, BigInteger[] C);

    /// <summary>One opened (public) protocol message; <c>Label</c> is "d" or "e".</summary>
    public sealed record OpenedMsg(string Label, BigInteger Value, BigInteger[] Shares);

    public static List<Triple> GenTriples(int count, int n, IFieldSource rng)
    {
        var o = new List<Triple>();
        for (int i = 0; i < count; i++) o.Add(GenTriple(n, rng));
        return o;
    }

    public static Triple GenTriple(int n, IFieldSource rng)
    {
        var a = rng.Next();
        var b = rng.Next();
        var c = Fmul(a, b);
        return new Triple(Sharing.Share(a, n, rng), Sharing.Share(b, n, rng), Sharing.Share(c, n, rng));
    }

    /// <summary>x*y consuming <paramref name="triple"/>; every opened value is appended to <paramref name="transcript"/> when non-null.</summary>
    public static BigInteger[] BeaverMul(BigInteger[] x, BigInteger[] y, Triple triple, List<OpenedMsg>? transcript)
    {
        if (x.Length != y.Length) throw new ArgumentException("beaverMul: operand party counts differ");
        foreach (var part in new[] { triple.A, triple.B, triple.C })
            if (part == null || part.Length != x.Length) throw new ArgumentException("beaverMul: triple party count differs from the operands");
        var dShares = Sharing.SubSV(x, triple.A);
        var eShares = Sharing.SubSV(y, triple.B);
        var d = Sharing.Reconstruct(dShares);
        var e = Sharing.Reconstruct(eShares);
        if (transcript != null)
        {
            transcript.Add(new OpenedMsg("d", d, dShares));
            transcript.Add(new OpenedMsg("e", e, eShares));
        }
        var de = Fmul(d, e);
        var z = new BigInteger[x.Length];
        for (int i = 0; i < z.Length; i++)
        {
            var zi = Fadd(triple.C[i], Fadd(Fmul(d, triple.B[i]), Fmul(e, triple.A[i])));
            z[i] = i == 0 ? Fadd(zi, de) : zi;
        }
        return z;
    }
}
