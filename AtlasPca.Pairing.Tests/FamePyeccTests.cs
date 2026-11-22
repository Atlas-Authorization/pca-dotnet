using System.Numerics;
using AtlasPca.Abe;
using AtlasPca.Pairing;
using static supranational.blst;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte.</summary>
public class FamePyeccTests
{
    static BigInteger Unhex(object? s) => Bls12.Os2ip(Convert.FromHexString((string)s!));
    static BigInteger[] Scalars(object? l) => ((L)l!).Select(Unhex).ToArray();
    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    static string Hex1(P1[] p) => string.Join(",", p.Select(x => Hex(x.compress())));
    static string Hex2(P2[] p) => string.Join(",", p.Select(x => Hex(x.compress())));
    static string Strs(object? l) => string.Join(",", ((L)l!).Select(x => (string)x!));

    static void Same(string want, string have, string msg) => Assert.True(want == have, $"{msg}: want {want} have {have}");

    [Fact]
    public void MatchesPyEcc()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "test-data", "fame-pyecc", "fame-pyecc.json");
        var doc = (D)FixtureJson.Parse(File.ReadAllText(path))!;
        foreach (var co in (L)doc["cases"]!)
        {
            var c = (D)co!;
            var name = (string)c["name"]!;
            var n = AbePolicy.Normalize(c["policy"]);
            Assert.True(n.Tree != null, name);
            var attrs = ((L)c["attrs"]!).Select(x => (string)x!).ToList();
            var s = (D)c["scalars"]!;
            var ms = Fame.Setup(Scalars(s["a"]), Scalars(s["b"]), Scalars(s["d"]));
            var key = Fame.Keygen(ms.Msk, attrs, Scalars(s["r"]), Scalars(s["sigma"]).ToList(), Unhex(s["sigmaPrime"]));
            var e = Fame.Encrypt(ms.Mpk, n.Tree!, Scalars(s["s"]));
            Same(Strs(c["h"]), Hex(ms.Mpk.H1.compress()) + "," + Hex(ms.Mpk.H2.compress()), name + " h");
            Same(Strs(c["mskg"]), Hex1(ms.Msk.G), name + " mskg");
            Same(Strs(c["k0"]), Hex2(key.K0), name + " k0");
            Same(Strs(c["kp"]), Hex1(key.Kp), name + " kp");
            foreach (var en in (D)c["key"]!) Same(Strs(en.Value), Hex1(key.Attrs[en.Key]), name + " key " + en.Key);
            Same(Strs(c["ct0"]), Hex2(e.Ct.Ct0), name + " ct0");
            var want = ((L)c["rows"]!).Select(Strs).ToList();
            var have = e.Ct.Rows.Select(Hex1).ToList();
            Assert.True(want.SequenceEqual(have), name + " rows");
            // the reference decrypted these with the attribute set it was issued; so must the native
            var dec = Fame.Decrypt(key, n.Tree!, e.Ct);
            if (AbePolicy.Satisfies(n.Tree!, new HashSet<string>(attrs))) Assert.True(dec != null && e.K.AsSpan().SequenceEqual(dec), name + " decrypt");
        }
    }
}
