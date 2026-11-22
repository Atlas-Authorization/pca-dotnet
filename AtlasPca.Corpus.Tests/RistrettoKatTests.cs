using System.Numerics;
using System.Text.Json;
using AtlasPca.Ratchet;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>ristretto255 known answers: the RFC 9496 generator multiples, bad encodings and hash-to-group vectors, plus random scalar
/// multiplications, sums and reductions dumped from the reference library.</summary>
public class RistrettoKatTests
{
    static JsonElement Kat()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "ristretto255-kat.json");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "ristretto255-kat.json");
            if (File.Exists(f)) return JsonDocument.Parse(File.ReadAllText(f)).RootElement.Clone();
        }
        throw new FileNotFoundException("test-data/ristretto255-kat.json");
    }

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    static byte[] Unhex(string s) => Convert.FromHexString(s);
    static RistrettoPoint Pt(string h) => RistrettoPoint.Decode(Unhex(h));

    [Fact]
    public void GeneratorMultiplesMatchRfc9496()
    {
        var k = Kat().GetProperty("mult");
        // the first vectors are the RFC 9496 appendix A.1 list, typed independently of the dump
        Assert.Equal("0000000000000000000000000000000000000000000000000000000000000000", k[0].GetProperty("enc").GetString());
        Assert.Equal("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76", k[1].GetProperty("enc").GetString());
        Assert.Equal("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919", k[2].GetProperty("enc").GetString());
        var acc = RistrettoPoint.Zero;
        foreach (var e in k.EnumerateArray())
        {
            Assert.Equal(e.GetProperty("enc").GetString(), Hex(acc.Encode()));
            if (e.GetProperty("k").GetInt32() > 0) Assert.True(RistrettoPoint.Decode(Unhex(e.GetProperty("enc").GetString()!)).Equals(acc));
            acc = acc.Add(RistrettoPoint.Base);
        }
        Assert.Equal(16, k.GetArrayLength());
    }

    [Fact]
    public void MultiplyByGeneratorMultiples()
    {
        var k = Kat().GetProperty("mult");
        for (int i = 1; i < 16; i++)
            Assert.Equal(k[i].GetProperty("enc").GetString(), Hex(RistrettoPoint.Base.Multiply(i).Encode()));
    }

    [Fact]
    public void BadEncodingsAreRejected()
    {
        foreach (var e in Kat().GetProperty("bad").EnumerateArray())
            Assert.Equal(e.GetProperty("ok").GetBoolean(), RistrettoPoint.TryDecode(Unhex(e.GetProperty("enc").GetString()!)) != null);
        Assert.Null(RistrettoPoint.TryDecode(new byte[31]));
        Assert.Null(RistrettoPoint.TryDecode(new byte[33]));
    }

    [Fact]
    public void FromUniformBytesMatches()
    {
        foreach (var e in Kat().GetProperty("uniform").EnumerateArray())
            Assert.Equal(e.GetProperty("enc").GetString(), Hex(RistrettoPoint.FromUniformBytes(Unhex(e.GetProperty("in").GetString()!)).Encode()));
    }

    [Fact]
    public void PedersenGeneratorHMatches()
    {
        var h = RistrettoPoint.FromUniformBytes(System.Security.Cryptography.SHA512.HashData(System.Text.Encoding.UTF8.GetBytes("atlas-pca-ratchet/pedersen-generator-H/v1")));
        Assert.Equal(Kat().GetProperty("H").GetString(), Hex(h.Encode()));
    }

    [Fact]
    public void ScalarMultiplicationMatches()
    {
        foreach (var e in Kat().GetProperty("scalarMul").EnumerateArray())
        {
            var k = RistrettoScalar.FromLe(Unhex(e.GetProperty("k").GetString()!));
            Assert.Equal(e.GetProperty("kp").GetString(), Hex(Pt(e.GetProperty("p").GetString()!).Multiply(k).Encode()));
        }
    }

    [Fact]
    public void AddSubNegateEqualsMatch()
    {
        foreach (var e in Kat().GetProperty("addSub").EnumerateArray())
        {
            var p = Pt(e.GetProperty("p").GetString()!); var q = Pt(e.GetProperty("q").GetString()!);
            Assert.Equal(e.GetProperty("sum").GetString(), Hex(p.Add(q).Encode()));
            Assert.Equal(e.GetProperty("diff").GetString(), Hex(p.Subtract(q).Encode()));
            Assert.Equal(e.GetProperty("neg").GetString(), Hex(p.Negate().Encode()));
            Assert.Equal(e.GetProperty("eq").GetBoolean(), p.Equals(q));
            Assert.True(p.Equals(p));
            Assert.True(p.Add(p.Negate()).Equals(RistrettoPoint.Zero));
        }
    }

    [Fact]
    public void ScalarReduceAndInvert()
    {
        foreach (var e in Kat().GetProperty("reduce").EnumerateArray())
        {
            var r = RistrettoScalar.Reduce64(Unhex(e.GetProperty("in").GetString()!));
            Assert.Equal(e.GetProperty("out").GetString(), Hex(RistrettoScalar.ToLe(r, 32)));
            if (!r.IsZero) Assert.Equal(BigInteger.One, RistrettoScalar.Mul(r, RistrettoScalar.Invert(r)));
        }
    }
}
