using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.Corpus.Tests.IntentV2KillTests;

namespace AtlasPca.Corpus.Tests;

/// <summary>Round-3 CI mutation kills (Stryker.NET survivors after the shared-oracle ports): exact-value tests of the primitives the
/// oracles do not pin.</summary>
public class R3KillTests
{
    // ---------------------------------------------------------------- Pca.cs

    [Fact]
    public void PqVerifyRefusesGarbageAndWrongLengthsForEveryPrimitive()
    {
        var msg = new byte[] { 1, 2, 3 };
        foreach (var p in new[] { Pq.Prim.MlDsa65, Pq.Prim.MlDsa87, Pq.Prim.Slh128f, Pq.Prim.Slh256s })
        {
            var (pkLen, sigLen) = Pq.Lens(p);
            foreach (var fill in new byte[] { 0, 0xff, 0x5a })
            {
                var pk = Enumerable.Repeat(fill, pkLen).ToArray();
                var sig = Enumerable.Repeat(fill, sigLen).ToArray();
                Assert.False(Pq.Verify(p, pk, msg, sig));
            }
            Assert.False(Pq.Verify(p, new byte[pkLen - 1], msg, new byte[sigLen]));
            Assert.False(Pq.Verify(p, new byte[pkLen + 1], msg, new byte[sigLen]));
            Assert.False(Pq.Verify(p, new byte[pkLen], msg, new byte[sigLen - 1]));
            Assert.False(Pq.Verify(p, new byte[pkLen], msg, new byte[sigLen + 1]));
            Assert.False(Pq.Verify(p, new byte[pkLen], msg, Array.Empty<byte>()));
            Assert.False(Pq.Verify(p, Array.Empty<byte>(), msg, new byte[sigLen]));
        }
        Assert.False(Pq.Verify(Pq.Prim.None, Array.Empty<byte>(), msg, Array.Empty<byte>()));
        Assert.False(Pq.Verify(Pq.Prim.None, new byte[1], msg, new byte[1]));
        Assert.False(Pq.Verify(Pq.Prim.None, new byte[32], msg, new byte[64]));
    }

    [Fact]
    public void StrictEd25519AcceptsEveryValidKeyAndRefusesTamperedOnes()
    {
        // about half of all points need the sqrt(-1) correction in the decoder (public key and R alike), so many seeds exercise both branches
        for (int i = 0; i < 80; i++)
        {
            var seed = SHA256.HashData(Encoding.UTF8.GetBytes("r3/ed/" + i));
            var pk = new byte[32]; Ed25519.GeneratePublicKey(seed, 0, pk, 0);
            var msg = Encoding.UTF8.GetBytes("message " + i);
            var sig = new byte[64]; Ed25519.Sign(seed, 0, msg, 0, msg.Length, sig, 0);
            Assert.True(IntentJs.VerifyEd(Pca.B64u(pk), msg, Pca.B64u(sig)), "valid #" + i);
            var bad = (byte[])sig.Clone(); bad[40] ^= 1;
            Assert.False(IntentJs.VerifyEd(Pca.B64u(pk), msg, Pca.B64u(bad)));
            Assert.False(IntentJs.VerifyEd(Pca.B64u(pk), Encoding.UTF8.GetBytes("other"), Pca.B64u(sig)));
        }
    }

    [Fact]
    public void StrictEd25519RefusesTorsionAndNonCanonicalEncodings()
    {
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes("r3/ed/torsion"));
        var h = SHA512.HashData(seed);
        var a = (byte[])h[..32].Clone(); a[0] &= 248; a[31] &= 127; a[31] |= 64;
        var s = new BigInteger(a, isUnsigned: true, isBigEndian: false) % Ed25519L;
        var big = new byte[32]; Ed25519.GeneratePublicKey(seed, 0, big, 0);   // R = [s]B
        var sig = new byte[64]; Array.Copy(big, sig, 32);
        var sb = s.ToByteArray(isUnsigned: true, isBigEndian: false); Array.Copy(sb, 0, sig, 32, sb.Length);
        var msg = new byte[] { 9 };
        // A = identity (y = 1, canonical): [S]B = R + h*A holds for ANY message, so only the small-order check refuses it
        var identity = new byte[32]; identity[0] = 1;
        Assert.False(IntentJs.VerifyEd(Pca.B64u(identity), msg, Pca.B64u(sig)));
        // the same point with the non-canonical y = p + 1
        var alias = Enumerable.Repeat((byte)0xff, 32).ToArray(); alias[0] = 0xee; alias[31] = 0x7f;
        Assert.False(IntentJs.VerifyEd(Pca.B64u(alias), msg, Pca.B64u(sig)));
        // the order-2 point (0, -1)
        var minusOne = Enumerable.Repeat((byte)0xff, 32).ToArray(); minusOne[0] = 0xec; minusOne[31] = 0x7f;
        Assert.False(IntentJs.VerifyEd(Pca.B64u(minusOne), msg, Pca.B64u(sig)));
        // S = L (non-canonical scalar) and S = L + s
        var withL = new byte[64]; Array.Copy(big, withL, 32);
        var lb = Ed25519L.ToByteArray(isUnsigned: true, isBigEndian: false); Array.Copy(lb, 0, withL, 32, lb.Length);
        Assert.False(IntentJs.VerifyEd(Pca.B64u(big), msg, Pca.B64u(withL)));
        var sPlusL = new byte[64]; Array.Copy(big, sPlusL, 32);
        var spl = (s + Ed25519L).ToByteArray(isUnsigned: true, isBigEndian: false); Array.Copy(spl, 0, sPlusL, 32, Math.Min(32, spl.Length));
        Assert.False(IntentJs.VerifyEd(Pca.B64u(big), msg, Pca.B64u(sPlusL)));
        // wrong lengths
        Assert.False(IntentJs.VerifyEd(Pca.B64u(new byte[31]), msg, Pca.B64u(sig)));
        Assert.False(IntentJs.VerifyEd(Pca.B64u(big), msg, Pca.B64u(new byte[63])));
    }

    static readonly BigInteger Ed25519L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    [Fact]
    public void PcaHeaderDecodingIsStrictUtf8()
    {
        string H(params byte[] b) => Pca.B64u(b);
        Assert.Equal("ab", Pca.DecodePcaHeader(H((byte)'a', (byte)'b')));
        Assert.Null(Pca.DecodePcaHeader(H(0xff)));
        Assert.Null(Pca.DecodePcaHeader(H(0xc0, 0xaf)));            // overlong
        Assert.Null(Pca.DecodePcaHeader(H(0xed, 0xa0, 0x80)));      // encoded surrogate
        Assert.Null(Pca.DecodePcaHeader(H(0xe2, 0x82)));            // truncated
        Assert.Equal("€", Pca.DecodePcaHeader(H(0xe2, 0x82, 0xac)));
        Assert.Null(Pca.DecodePcaHeader(""));
        Assert.Null(Pca.DecodePcaHeader(null));
    }

    // ---------------------------------------------------------------- IntentJs

    [Fact]
    public void ShortestSpellingOfNonIntegralAndHugeNumbers()
    {
        string N(string raw) => ((Num)IntentJs.Normalize(new Num(raw))!).Raw;
        Assert.Equal("-0.00000015", N("-1.5e-7"));
        Assert.Equal("0.00000015", N("1.5e-7"));
        Assert.Equal("-10000000000000000000000", N("-1e22"));
        Assert.Equal("10000000000000000000000", N("1e22"));
        Assert.Equal("-1234567890123456.5", N("-1234567890123456.5"));
        Assert.Equal("1234567890123456.5", N("1234567890123456.5"));
        Assert.Equal("123456789012345683968", N("123456789012345680000"));
        Assert.Equal("1000000000000000000000", N("1e21"));
        Assert.Equal("999999999999999868928", N("999999999999999900000"));
        Assert.Equal("-0", N("-0"));
        Assert.Equal("0.000001", N("0.000001"));
        Assert.Equal("1e999", N("1e999"));
    }

    [Fact]
    public void PinnedSuiteVerificationFailsClosed()
    {
        var msg = new byte[] { 1 };
        Assert.False(IntentJs.VerifyPinnedSuite("fn-dsa-512", true, Pub("r3/id"), null, msg, "AA", null, null));
        Assert.False(IntentJs.VerifyPinnedSuite(5L, true, Pub("r3/id"), null, msg, "AA", null, null));
        Assert.False(IntentJs.VerifyPinnedSuite("ml-dsa-65", true, Pub("r3/id"), "pk", null!, "AA", "BB", new Dictionary<string, string> { [Pub("r3/id")] = "pk" }));
        Assert.True(IntentJs.VerifyPinnedSuite(null, false, Pub("r3/id"), null, msg, Sign("r3/id", msg), null, null));
        Assert.False(IntentJs.VerifyPinnedSuite(null, false, Pub("r3/id"), null, null!, Sign("r3/id", msg), null, null));
    }

    // ---------------------------------------------------------------- IntentRevocation text helpers

    [Fact]
    public void JsTextAndTruthinessFollowJavaScript()
    {
        Assert.Equal("undefined", IntentRevocation.JsText(5L, false));
        Assert.Equal("null", IntentRevocation.JsText(null, true));
        Assert.Equal("0", IntentRevocation.JsText(new Num("-0"), true));
        Assert.Equal("5", IntentRevocation.JsText(new Num("5"), true));
        Assert.Equal("1.5", IntentRevocation.JsText(new Num("1.5"), true));
        Assert.Equal("true", IntentRevocation.JsText(true, true));
        Assert.Equal("false", IntentRevocation.JsText(false, true));
        Assert.Equal("x", IntentRevocation.JsText("x", true));
        Assert.Equal("1,,a,true,[object Object],2,3", IntentRevocation.JsText(new L { new Num("1"), null, "a", true, new D(), new L { new Num("2"), new Num("3") } }, true));
        Assert.Equal("[object Object]", IntentRevocation.JsText(new D { ["a"] = 1L }, true));
        Assert.Equal("7", IntentRevocation.JsText(7L, true));
        Assert.Equal("", IntentRevocation.JsText(new L(), true));

        Assert.False(IntentRevocation.Truthy(null));
        Assert.True(IntentRevocation.Truthy(true)); Assert.False(IntentRevocation.Truthy(false));
        Assert.True(IntentRevocation.Truthy("a")); Assert.False(IntentRevocation.Truthy(""));
        Assert.True(IntentRevocation.Truthy(new Num("5"))); Assert.True(IntentRevocation.Truthy(new Num("-5"))); Assert.True(IntentRevocation.Truthy(new Num("0.5")));
        Assert.False(IntentRevocation.Truthy(new Num("0"))); Assert.False(IntentRevocation.Truthy(new Num("-0"))); Assert.False(IntentRevocation.Truthy(new Num("0.0")));
        Assert.False(IntentRevocation.Truthy(new Num("NaN")));
        Assert.True(IntentRevocation.Truthy(new L())); Assert.True(IntentRevocation.Truthy(new D()));
    }

    // ---------------------------------------------------------------- IntentMap

    [Fact]
    public void MapHashingPrimitives()
    {
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, IntentMap.U64be(0x0102030405060708L));
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }, IntentMap.U64be(1));
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 1, 0 }, IntentMap.U64be(256));
        Assert.Equal(new byte[] { 0x80, 0, 0, 0, 0, 0, 0, 0 }, IntentMap.U64be(long.MinValue));
        Assert.Equal(Enumerable.Repeat((byte)0xff, 8).ToArray(), IntentMap.U64be(-1));
        var salt = new byte[32];
        var e = Assert.Throws<ArgumentException>(() => IntentMap.LeafHash("bogus", salt, new D()));
        Assert.Equal("unknown leaf kind", e.Message);
        foreach (var bad in new byte[]?[] { null, new byte[31], new byte[33], Array.Empty<byte>() })
            Assert.Equal("mapLeafHash: the salt is 32 bytes", Assert.Throws<ArgumentException>(() => IntentMap.LeafHash("header", bad, new D())).Message);
        Assert.NotEqual(IntentMap.LeafHash("header", salt, new D()), IntentMap.LeafHash("cell", salt, new D()));
        Assert.NotEqual(IntentMap.LeafHash("metrics", salt, new D()), IntentMap.LeafHash("learner", salt, new D()));
        Assert.Equal("mapTree: empty", Assert.Throws<ArgumentException>(() => IntentMap.CommitLeaves(new L())).Message);
    }

    [Fact]
    public void InclusionPathFolding()
    {
        var lh = SHA256.HashData(new byte[] { 7 });
        var p1 = SHA256.HashData(new byte[] { 8 });
        var p2 = SHA256.HashData(new byte[] { 9 });
        Assert.Equal(lh, IntentMap.RootFromPath(0, 1, lh, new List<byte[]>()));
        Assert.Null(IntentMap.RootFromPath(1, 1, lh, new List<byte[]>()));
        Assert.Null(IntentMap.RootFromPath(2, 1, lh, new List<byte[]>()));
        Assert.Null(IntentMap.RootFromPath(-1, 1, lh, new List<byte[]>()));
        Assert.Null(IntentMap.RootFromPath(0, 0, lh, new List<byte[]>()));
        Assert.Null(IntentMap.RootFromPath(5, 3, lh, new List<byte[]> { p1 }));
        Assert.Null(IntentMap.RootFromPath(0, 1, lh, new List<byte[]> { p1 }));                 // a path longer than the tree
        Assert.Null(IntentMap.RootFromPath(0, 2, lh, new List<byte[]> { p1, p2 }));
        Assert.Null(IntentMap.RootFromPath(0, 3, lh, new List<byte[]> { p1 }));                 // a path shorter than the tree
        Assert.NotNull(IntentMap.RootFromPath(0, 2, lh, new List<byte[]> { p1 }));
        Assert.NotNull(IntentMap.RootFromPath(1, 2, lh, new List<byte[]> { p1 }));
        Assert.NotNull(IntentMap.RootFromPath(0, 3, lh, new List<byte[]> { p1, p2 }));
        Assert.NotNull(IntentMap.RootFromPath(2, 3, lh, new List<byte[]> { p1 }));
        Assert.NotEqual(IntentMap.RootFromPath(0, 2, lh, new List<byte[]> { p1 }), IntentMap.RootFromPath(1, 2, lh, new List<byte[]> { p1 }));
    }

    [Fact]
    public void MetricsLeafReportsTheFirstBadFieldInDeclaredOrder()
    {
        var m = new D();
        foreach (var f in IntentMap.MetricFields) m[f] = new Num("1");
        Assert.Null(IntentMap.MetricsError(m));
        m["log2_vs_mbits"] = new Num("-1");
        Assert.Equal("metrics.log2_vs_mbits must be a non-negative safe integer", IntentMap.MetricsError(m));
        m[IntentMap.MetricFields[0]] = new Num("-1");
        Assert.Equal($"metrics.{IntentMap.MetricFields[0]} must be a non-negative safe integer", IntentMap.MetricsError(m));
    }

    [Fact]
    public void MapPrimitiveEntryReasons()
    {
        Assert.Equal("map error (fail closed): NullReferenceException", IntentMap.DecidePrimitive(null).Reason);
        Assert.Equal("map error (fail closed): InvalidCastException", IntentMap.DecidePrimitive("x").Reason);
        Assert.False(IntentMap.DecidePrimitive(null).Ok);
        var input = new D { ["max_residual_risk_ppm"] = "x" };
        Assert.Equal("max_residual_risk_ppm must be a number", IntentMap.DecidePrimitive(input).Reason);
        Assert.Equal("max_residual_risk_ppm must be a number", IntentMap.DecidePrimitive(new D { ["max_residual_risk_ppm"] = null }).Reason);
    }
}
