using System.Collections;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc;

/// <summary>
/// Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers: strict base64,
/// minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the gadget seed exchange.
/// </summary>
public static class NetCodec
{
    public static string B64(byte[] u) => Convert.ToBase64String(u);

    // \A..\z, never ^..$: $ would also accept a trailing newline
    static readonly Regex B64Re = new(@"\A[A-Za-z0-9+/]*={0,2}\z", RegexOptions.CultureInvariant);
    static readonly Regex Hex255 = new(@"\A(0|[1-9a-f][0-9a-f]{0,63})\z", RegexOptions.CultureInvariant);

    /// <summary>Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); <paramref name="len"/> &lt; 0 means any length.</summary>
    public static byte[] Unb64(object? s, int len)
    {
        if (s is not string t || !B64Re.IsMatch(t)) throw new ArgumentException("bad base64");
        byte[] b;
        try { b = Convert.FromBase64String(t); }
        catch (FormatException) { throw new ArgumentException("bad base64"); }
        if (Convert.ToBase64String(b) != t) throw new ArgumentException("non-canonical base64");
        if (len >= 0 && b.Length != len) throw new ArgumentException("bad length");
        return b;
    }

    public static D PtJ(Ec.Point p)
    {
        var xy = Ec.ToAffine(p);
        return new D { ["x"] = NetWire.Hx(xy[0]), ["y"] = NetWire.Hx(xy[1]) };
    }

    /// <summary>Canonical lowercase hex without leading zeros of an element below the curve field prime.</summary>
    public static BigInteger HexBig(object? s)
    {
        if (s is not string t || !Hex255.IsMatch(t)) throw new ArgumentException("bad field element");
        var v = Field.ParseHex(t);
        if (v >= Ec.Q) throw new ArgumentException("non-canonical field element");
        return v;
    }

    /// <summary>A point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point.</summary>
    public static Ec.Point JPt(object? v)
    {
        if (v is not IDictionary m) throw new ArgumentException("bad point");
        var x = HexBig(m.Contains("x") ? m["x"] : null);
        var y = HexBig(m.Contains("y") ? m["y"] : null);
        var p = new Ec.Point(x, y, BigInteger.One, Ec.ModFq(x * y));
        Ec.AssertInSubgroup(p, "received point");
        return p;
    }

    public static int SharingsPerTriple(int partners) => 3 + 2 * partners;

    /// <summary>Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex.</summary>
    public static string GadgetCommit(string sessionId, int party, byte[] seed)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(Encoding.UTF8.GetBytes("atlas-pca-mpc/gadget-commit"));
        h.AppendData(Encoding.UTF8.GetBytes(sessionId));
        h.AppendData(Encoding.UTF8.GetBytes(party.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        h.AppendData(seed);
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o").</summary>
    public static byte[] GadgetStatement(string sessionId, string round, int signer, string value) =>
        Encoding.UTF8.GetBytes(NetWire.Stringify(new List<object?> { "atlas-pca-mpc/gadget-sig/v1", sessionId, round, signer, value }));
}
