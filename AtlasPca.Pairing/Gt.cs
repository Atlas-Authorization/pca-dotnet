using System.Numerics;
using System.Runtime.InteropServices;
using static supranational.blst;

namespace AtlasPca.Pairing;

/// <summary>
/// The pairing target group GT of BLS12-381 through a small shim over blst's public API (Native/pca_gt.c, compiled into the same
/// native library as blst): canonical 576-byte parsing, multiplication, constant-time exponentiation (a Montgomery ladder over blst's Fp12
/// multiply and square) and multi-pairing with one final exponentiation. The binding has neither parsing nor exponentiation of GT.
/// An element is its 576-byte encoding (the 12 Fp coordinates in tower order, 48 bytes big-endian each), the same bytes as the TypeScript reference.
/// A missing native library is a DllNotFoundException, never a "bad input" result.
/// </summary>
public static class Gt
{
    public const int Bytes = 576;

    [DllImport("blst.dll")] private static extern int pca_gt_mul(byte[] o, byte[] a, byte[] b);
    [DllImport("blst.dll")] private static extern int pca_gt_pow(byte[] o, byte[] a, byte[] k);
    [DllImport("blst.dll")] private static extern int pca_gt_is_element(byte[] a);
    [DllImport("blst.dll")] private static extern int pca_gt_pairing(byte[] o, byte[] g1s, byte[] g2s, UIntPtr n);

    /// <summary>a * b; throws on a non-canonical operand.</summary>
    public static byte[] Mul(byte[] a, byte[] b)
    {
        if (a.Length != Bytes || b.Length != Bytes) throw new ArgumentException("not a canonical GT encoding");
        var o = new byte[Bytes];
        if (pca_gt_mul(o, a, b) != 1) throw new ArgumentException("not a canonical GT encoding");
        return o;
    }

    /// <summary>a^(k mod r); throws on a non-canonical operand.</summary>
    public static byte[] Pow(byte[] a, BigInteger k)
    {
        if (a.Length != Bytes) throw new ArgumentException("not a canonical GT encoding");
        var o = new byte[Bytes];
        if (pca_gt_pow(o, a, Bls12.I2osp(Bls12.Mod(k), 32)) != 1) throw new ArgumentException("not a canonical GT encoding");
        return o;
    }

    /// <summary>True iff the bytes canonically encode an element of the order-r subgroup other than the identity.</summary>
    public static bool IsElement(byte[]? a) => a != null && a.Length == Bytes && pca_gt_is_element(a) == 1;

    /// <summary>e(p, q). Throws on an identity point.</summary>
    public static byte[] Pairing(P1 p, P2 q) => PairingProduct(new[] { p }, new[] { q });

    /// <summary>prod e(g1[i], g2[i]) with one shared final exponentiation. Throws on an identity point.</summary>
    public static byte[] PairingProduct(IReadOnlyList<P1> g1, IReadOnlyList<P2> g2)
    {
        int n = g1.Count;
        if (n == 0 || n != g2.Count || n > 4096) throw new ArgumentException("pairing product needs equal, non-empty point lists");
        var a = new byte[48 * n];
        var b = new byte[96 * n];
        for (int i = 0; i < n; i++)
        {
            if (g1[i].is_inf() || g2[i].is_inf()) throw new ArgumentException("pairing is not defined for the identity");
            g1[i].compress().CopyTo(a, 48 * i);
            g2[i].compress().CopyTo(b, 96 * i);
        }
        var o = new byte[Bytes];
        if (pca_gt_pairing(o, a, b, (UIntPtr)n) != 1) throw new ArgumentException("invalid pairing input");
        return o;
    }
}
