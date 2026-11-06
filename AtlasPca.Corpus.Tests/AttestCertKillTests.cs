using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;
using BcBig = Org.BouncyCastle.Math.BigInteger;

namespace AtlasPca.Corpus.Tests;

/// <summary>The certificate reader against the reference: packages/pca/src/x509-strict.ts where it reads the same thing, and Node's
/// X509Certificate (OpenSSL) elsewhere. Small hand-built elements, both sides of every condition, the boundary of every comparison.</summary>
public class AttestCertKillTests
{
    const string WrongTag = "error:068000A8:asn1 encoding routines::wrong tag";
    const string Nested = "error:0688010A:asn1 encoding routines::nested asn1 error";
    const string NoData = "error:0680007B:asn1 encoding routines::header too long";
    const string ZeroContent = "error:068000DE:asn1 encoding routines::illegal zero content";
    const string Padding = "error:068000DD:asn1 encoding routines::illegal padding";
    const string Unsupported = "error:1E08010C:DECODER routines::unsupported";
    const string NoStartLine = "error:0480006C:PEM routines::no start line";

    const string EcSha256 = "1.2.840.10045.4.3.2", RsaSha256 = "1.2.840.113549.1.1.11", RsaPss = "1.2.840.113549.1.1.10", Mgf1 = "1.2.840.113549.1.1.8";
    const string Ed = "1.3.101.112", EcKeyOid = "1.2.840.10045.2.1", RsaKeyOid = "1.2.840.113549.1.1.1";
    const string Sha1Oid = "1.3.14.3.2.26", Sha256Oid = "2.16.840.1.101.3.4.2.1", Sha384Oid = "2.16.840.1.101.3.4.2.2";
    const string Aia = "1.3.6.1.5.5.7.1.1", Ocsp = "1.3.6.1.5.5.7.48.1", CaIssuers = "1.3.6.1.5.5.7.48.2";
    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;

    static string Why(Action a)
    {
        try { a(); }
        catch (Exception e) { return e.Message; }
        return "";
    }

    static byte[] B(params byte[] b) => b;
    static byte[] A(string s) => Encoding.Latin1.GetBytes(s);

    static byte[] T(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        return (body.Length < 0x80 ? new[] { tag, (byte)body.Length } : new[] { tag, (byte)0x82, (byte)(body.Length >> 8), (byte)body.Length }).Concat(body).ToArray();
    }

    static byte[] Oid(string dotted)
    {
        var a = dotted.Split('.').Select(x => ulong.Parse(x)).ToArray();
        var o = new List<byte>();
        foreach (var arc in new[] { a[0] * 40 + a[1] }.Concat(a.Skip(2)))
        {
            var chunk = new List<byte> { (byte)(arc & 0x7f) };
            for (var v = arc >> 7; v > 0; v >>= 7) chunk.Insert(0, (byte)((v & 0x7f) | 0x80));
            o.AddRange(chunk);
        }
        return T(0x06, o.ToArray());
    }

    // ---- a small certificate, part by part

    static readonly byte[] CnOid = Oid("2.5.4.3");
    static readonly byte[] Name = T(0x30, T(0x31, T(0x30, CnOid, T(0x0c, A("x")))));
    static readonly byte[] SigAlg = T(0x30, Oid(EcSha256));
    static readonly byte[] Ut = T(0x17, A("200101000000Z"));
    static readonly byte[] Gt = T(0x18, A("20300101000000Z"));
    static readonly byte[] KeyAlg = T(0x30, Oid(Ed));
    static readonly byte[] V3 = T(0xa0, T(0x02, B(2)));

    static byte[] Tbs(byte[]? version = null, byte[]? serial = null, byte[]? alg = null, byte[]? issuer = null, byte[]? validity = null, byte[]? subject = null, byte[]? spki = null, byte[]? tail = null) =>
        T(0x30, version ?? B(), serial ?? T(0x02, B(9)), alg ?? SigAlg, issuer ?? Name, validity ?? T(0x30, Ut, Ut), subject ?? Name, spki ?? T(0x30, KeyAlg, T(0x03, B(0, 1))), tail ?? B());

    static byte[] Cert(byte[]? tbs = null, byte[]? alg = null, byte[]? sig = null, byte[]? extra = null) =>
        T(0x30, tbs ?? Tbs(), alg ?? SigAlg, sig ?? T(0x03, B(0, 1)), extra ?? B());

    static byte[] Exts(params byte[][] exts) => T(0xa3, T(0x30, exts));

    static string Refusal(byte[] der) => Why(() => AttestCerts.ParseDer(der));

    // ---- defaults

    [Fact]
    public void TheDefaultsAreTheEmptyAndUnknownOnes()
    {
        Assert.Equal("", new AttCert().SigOid);
        Assert.Equal("unknown", new CertKey().Type);
        Assert.Equal("", new CertKey().GoCurve);
    }

    // ---- EcPointOn (x509-strict.ts:298-300)

    [Fact]
    public void OnlyAnEcKeyWithAPointHasAnEcPoint()
    {
        Assert.Equal("public key is not EC (got unknown)", Why(() => new CertKey().EcPointOn("P-256")));
        Assert.Equal("public key is not EC (got rsa)", Why(() => new CertKey { Type = "rsa", EcPoint = B(4) }.EcPointOn("P-256")));
        Assert.Equal("public key is not EC (got ec)", Why(() => new CertKey { Type = "ec" }.EcPointOn("P-256")));
        Assert.Equal("public key is not on P-384 (got P-256)", Why(() => new CertKey { Type = "ec", EcPoint = B(4), GoCurve = "P-256" }.EcPointOn("P-384")));
        Assert.Equal(B(4), new CertKey { Type = "ec", EcPoint = B(4), GoCurve = "P-256" }.EcPointOn("P-256"));
    }

    // ---- OcspServers, HasOcspSigningEku

    static AttCert WithExt(string oid, byte[] value) => new AttCert { Exts = { new LenientExt(oid, false, value) } };
    static byte[] Ad(string method, byte tag, string url) => T(0x30, Oid(method), T(tag, A(url)));

    [Fact]
    public void OnlyATwoPartOcspUriAccessDescriptionIsAResponder()
    {
        var good = Ad(Ocsp, 0x86, "http://o");
        var skipped = new[]
        {
            T(0x30, Oid(Ocsp), T(0x86, A("http://three")), T(0x05)),
            T(0x30),
            T(0x30, Oid(Ocsp)),
            T(0x30, T(0x04, A("x")), T(0x86, A("http://notoid"))),
            T(0x30, T(0x06), T(0x86, A("http://badoid"))),
            T(0x04, B(1)),
            Ad(CaIssuers, 0x86, "http://issuer"),
            Ad(Ocsp, 0x82, "http://dns"),
        };
        foreach (var d in skipped)
            Assert.Equal(new List<string> { "http://o" }, WithExt(Aia, T(0x30, d, good)).OcspServers());
    }

    [Fact]
    public void AnUnreadableAccessInformationNamesNoResponder()
    {
        Assert.Empty(new AttCert().OcspServers());
        Assert.Empty(WithExt(Aia, B(0x04, 0x00)).OcspServers());
        Assert.Empty(WithExt(Aia, T(0x30, Ad(Ocsp, 0x86, "http://o"), B(0x30, 0x05))).OcspServers());
    }

    [Fact]
    public void OnlyTheOcspSigningPurposeIsTheOcspSigningEku()
    {
        Assert.True(WithExt("2.5.29.37", T(0x30, Oid("1.3.6.1.5.5.7.3.1"), Oid("1.3.6.1.5.5.7.3.9"))).HasOcspSigningEku());
        Assert.False(WithExt("2.5.29.37", T(0x30, Oid("1.3.6.1.5.5.7.3.1"))).HasOcspSigningEku());
        Assert.False(WithExt("2.5.29.37", B(0x04, 0x00)).HasOcspSigningEku());
        Assert.False(new AttCert().HasOcspSigningEku());
    }

    // ---- ReadElem and the lenient length forms

    [Fact]
    public void AnElementPastTheLimitIsHeaderTooLong()
    {
        Assert.Equal(NoData, Why(() => AttestCerts.ReadElem(B(0x30, 0x00), 2, 2, 0)));
        Assert.Equal(NoData, Why(() => AttestCerts.ReadElem(B(0x30, 0x00), 0, 0, 0)));
        Assert.Equal(new CertElem(0x30, 0, 2, 2), AttestCerts.ReadElem(B(0x30, 0x00), 0, 2, 0));
    }

    [Fact]
    public void ABadLengthIsTheNestedError()
    {
        foreach (var b in new[]
        {
            B(0x30),                                   // one octet
            B(0x30, 0x02, 0x00),                       // overruns
            B(0x30, 0x80, 0x00),                       // indefinite
            B(0x30, 0x85, 0, 0, 0, 0, 0),              // five length octets, all present
            B(0x30, 0x82, 0x00),                       // length octets past the end
            B(0x30, 0x84, 0, 0, 0),
        })
            Assert.Equal(Nested, Why(() => AttestCerts.ReadElem(b, 0, b.Length, 0)));
    }

    [Fact]
    public void FourLengthOctetsEndingAtTheLimitAreRead()
    {
        Assert.Equal(new CertElem(0x30, 0, 6, 6), AttestCerts.ReadElem(B(0x30, 0x84, 0, 0, 0, 0), 0, 6, 0));
        Assert.Equal(new CertElem(0x30, 0, 3, 4), AttestCerts.ReadElem(B(0x30, 0x81, 1, 9), 0, 4, 0x30));
        Assert.Equal(WrongTag, Why(() => AttestCerts.ReadElem(B(0x30, 0x00), 0, 2, 0x31)));
    }

    // ---- DottedOid (x509-strict.ts:133-152)

    static string Arcs(params byte[] c) => AttestCerts.DottedOid(c, new DerTlv(0x06, 0, c.Length));

    [Fact]
    public void TheFirstOctetSplitsAtFortyAndEighty()
    {
        Assert.Equal("0.0", Arcs(0));
        Assert.Equal("0.9", Arcs(9));
        Assert.Equal("0.39", Arcs(39));
        Assert.Equal("1.0", Arcs(40));
        Assert.Equal("1.39", Arcs(79));
        Assert.Equal("2.0", Arcs(80));
        Assert.Equal("1.2.3", Arcs(0x2a, 3));
        Assert.Equal("2.16305", Arcs(0x81, 0x80, 0x01));
    }

    [Fact]
    public void AnOidThatIsNotOneIsMalformed()
    {
        const string m = "extension OID is malformed";
        Assert.Equal(m, Why(() => AttestCerts.DottedOid(B(0x2a), new DerTlv(0x04, 0, 1))));
        Assert.Equal(m, Why(() => AttestCerts.DottedOid(B(0x2a), new DerTlv(0x06, 0, 0))));
        Assert.Equal("extension OID has a non-minimal arc", Why(() => Arcs(0x80, 0x01)));
        Assert.Equal("extension OID has a non-minimal arc", Why(() => Arcs(0x2a, 0x80, 0x01)));
        Assert.Equal("extension OID is truncated", Why(() => Arcs(0x2a, 0x81)));
        Assert.Equal("1.2", AttestCerts.Dotted(B(0x2a), new CertElem(0x06, 0, 0, 1)));
    }

    // ---- AlgId and the object-identifier check

    static string AlgRefusal(params byte[][] kids)
    {
        var b = T(0x30, kids);
        return Why(() => AttestCerts.AlgId(b, AttestCerts.ReadElem(b, 0, b.Length, 0x30)));
    }

    [Fact]
    public void AnAlgorithmIdentifierIsAnOidAndAtMostOneParameter()
    {
        Assert.Equal(Nested, AlgRefusal());
        Assert.Equal(Nested, AlgRefusal(Oid("1.2.3"), T(0x05), T(0x05)));
        var one = T(0x30, Oid("1.2.3"));
        var two = T(0x30, Oid("1.2.3"), T(0x05));
        var (oid1, prm1) = AttestCerts.AlgId(one, AttestCerts.ReadElem(one, 0, one.Length, 0x30));
        Assert.Equal("1.2.3", oid1);
        Assert.Null(prm1);
        var (oid2, prm2) = AttestCerts.AlgId(two, AttestCerts.ReadElem(two, 0, two.Length, 0x30));
        Assert.Equal("1.2.3", oid2);
        Assert.Equal(B(0x05, 0x00), prm2);
    }

    [Fact]
    public void AnIllFormedOidIsTheNestedErrorNotAnObjectError()
    {
        // a check that let these through would answer with the object-encoding error of the dotted reader instead
        Assert.Equal(Nested, AlgRefusal(T(0x04, B(0x2a))));
        Assert.Equal(Nested, AlgRefusal(T(0x06)));
        Assert.Equal(Nested, AlgRefusal(T(0x06, B(0x2a, 0x81))));
        Assert.Equal(Nested, AlgRefusal(T(0x06, B(0x80, 0x01))));
        Assert.Equal(Nested, AlgRefusal(T(0x06, B(0x2a, 0x80, 0x01))));
    }

    [Fact]
    public void A0x80InsideAnArcIsNotARefusal()
    {
        var b = T(0x30, T(0x06, B(0x81, 0x80, 0x01)));
        Assert.Equal("2.16305", AttestCerts.AlgId(b, AttestCerts.ReadElem(b, 0, b.Length, 0x30)).Oid);
    }

    [Fact]
    public void TheOidCheckStopsAtTheEndOfTheOid()
    {
        var b = T(0x30, T(0x06, B(0x2a)), T(0x80));
        var (oid, prm) = AttestCerts.AlgId(b, AttestCerts.ReadElem(b, 0, b.Length, 0x30));
        Assert.Equal("1.2", oid);
        Assert.Equal(B(0x80, 0x00), prm);
    }

    [Fact]
    public void A0x80FirstOctetIsRefusedWhateverPrecedesTheOid()
    {
        // the octet before the content is the length octet, and here it has its high bit set
        var content = new byte[0x80];
        Array.Fill(content, (byte)1);
        content[0] = 0x80;
        var b = T(0x30, B(0x06, 0x81, 0x80), content);
        Assert.Equal(Nested, Why(() => AttestCerts.AlgId(b, AttestCerts.ReadElem(b, 0, b.Length, 0x30))));
    }

    // ---- ParseDer

    [Fact]
    public void ACertificateIsReadWithAndWithoutAVersion()
    {
        var v1 = AttestCerts.ParseDer(Cert());
        Assert.Equal(B(9), v1.Serial);
        Assert.Equal(EcSha256, v1.SigOid);
        Assert.Equal(Name, v1.RawIssuer);
        Assert.Equal(Name, v1.RawSubject);
        Assert.True(v1.AlgsAgree);
        Assert.Equal(B(1), v1.Signature);
        Assert.Equal(B(9), AttestCerts.ParseDer(Cert(Tbs(version: V3))).Serial);
    }

    [Fact]
    public void AnEmptyTbsHasNoSerial()
    {
        Assert.Equal(NoData, Refusal(Cert(T(0x30))));
    }

    [Fact]
    public void TheSignatureIsTheLastElementAndABitString()
    {
        Assert.Equal(Nested, Refusal(Cert(extra: T(0x05))));
        Assert.Equal(WrongTag, Refusal(Cert(sig: T(0x03))));
        Assert.Throws<AttestError>(() => AttestCerts.ParseDer(Cert(sig: T(0x03, B(8, 1)))));
        Assert.Equal(B(0x80), AttestCerts.ParseDer(Cert(sig: T(0x03, B(7, 0x80)))).Signature);
        Assert.Empty(AttestCerts.ParseDer(Cert(sig: T(0x03, B(0)))).Signature);
    }

    [Fact]
    public void TheVersionHoldsExactlyOneInteger()
    {
        Assert.Equal(Nested, Refusal(Cert(Tbs(version: T(0xa0, T(0x02, B(2)), T(0x05))))));
    }

    // Node (OpenSSL c2i_ASN1_INTEGER, reached through new X509Certificate, e.g. hardware-sevsnp.ts:438, attest-azure-maa.ts:368) refuses these;
    // x509-strict.ts readCertRoleInfo walks past the serial without looking at it (:72-75).
    [Fact]
    public void ASerialOrVersionWithRedundantPaddingOrNoContentIsRefused()
    {
        foreach (var (content, why) in new[]
        {
            (B(), ZeroContent),
            (B(0x00, 0x00), Padding),
            (B(0x00, 0x01), Padding),
            (B(0x00, 0x7f), Padding),
            (B(0xff, 0x80), Padding),
            (B(0xff, 0xff), Padding),
        })
        {
            Assert.Equal(why, Refusal(Cert(Tbs(serial: T(0x02, content)))));
            Assert.Equal(why, Refusal(Cert(Tbs(version: T(0xa0, T(0x02, content))))));
        }
    }

    [Fact]
    public void AMinimalSerialIsReadAsIs()
    {
        foreach (var content in new[] { B(0x00), B(0xff), B(0x7f), B(0x80), B(0x00, 0x80), B(0x00, 0xff, 0x01), B(0xff, 0x7f), B(0xff, 0x00), B(0x01, 0x00), B(0xfe, 0xff) })
        {
            Assert.Equal(content, AttestCerts.ParseDer(Cert(Tbs(serial: T(0x02, content)))).Serial);
            Assert.Equal("", Refusal(Cert(Tbs(version: T(0xa0, T(0x02, content))))));
        }
    }

    [Fact]
    public void TheInnerAlgorithmAndBothNamesAreChecked()
    {
        var badName = T(0x30, T(0x30));
        Assert.Equal(Nested, Refusal(Cert(Tbs(alg: T(0x30)))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(issuer: badName))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(subject: badName))));
    }

    [Fact]
    public void ValidityIsExactlyTwoTimes()
    {
        var other = T(0x02, B(1));
        foreach (var v in new[] { T(0x30, Ut, Ut, Ut), T(0x30, Ut), T(0x30), T(0x30, other, Ut), T(0x30, Ut, other), T(0x30, other, other) })
            Assert.Equal(Nested, Refusal(Cert(Tbs(validity: v))));
        foreach (var v in new[] { T(0x30, Ut, Ut), T(0x30, Ut, Gt), T(0x30, Gt, Ut), T(0x30, Gt, Gt) })
            Assert.Equal("", Refusal(Cert(Tbs(validity: v))));
    }

    [Fact]
    public void TheKeyIsAnAlgorithmAndABitString()
    {
        foreach (var s in new[]
        {
            T(0x30, KeyAlg, T(0x03, B(0, 1)), T(0x05)),
            T(0x30, KeyAlg),
            T(0x30, T(0x31), T(0x03, B(0, 1))),
            T(0x30, T(0x30), T(0x03, B(0, 1))),
        })
            Assert.Equal(Nested, Refusal(Cert(Tbs(spki: s))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(spki: T(0x30, KeyAlg, T(0x04, B(0)))))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(spki: T(0x30, KeyAlg, T(0x03))))));
        Assert.Throws<AttestError>(() => AttestCerts.ParseDer(Cert(Tbs(spki: T(0x30, KeyAlg, T(0x03, B(8, 1)))))));
        Assert.Equal("", Refusal(Cert(Tbs(spki: T(0x30, KeyAlg, T(0x03, B(0)))))));
        Assert.Equal("", Refusal(Cert(Tbs(spki: T(0x30, KeyAlg, T(0x03, B(7, 0x80)))))));
    }

    [Fact]
    public void UniqueIdentifiersAreSkippedInOrder()
    {
        var iu = T(0x81, B(0, 1));
        var su = T(0x82, B(0, 1));
        foreach (var tail in new[] { iu, su, iu.Concat(su).ToArray(), iu.Concat(su).Concat(Exts()).ToArray() })
            Assert.Equal("", Refusal(Cert(Tbs(tail: tail))));
        Assert.Equal(Nested, Refusal(Cert(Tbs(tail: su.Concat(iu).ToArray()))));
    }

    [Fact]
    public void AnythingElseAfterTheKeyIsTheNestedError()
    {
        Assert.Equal(Nested, Refusal(Cert(Tbs(tail: T(0x05)))));
        Assert.Equal(Nested, Refusal(Cert(Tbs(tail: Exts().Concat(T(0x05)).ToArray()))));
    }

    [Fact]
    public void TheExtensionsBlockHoldsOneSequenceOfSequences()
    {
        Assert.Equal(Nested, Refusal(Cert(Tbs(tail: T(0xa3, T(0x30), T(0x05))))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(tail: Exts(T(0x31))))));
    }

    [Fact]
    public void AnExtensionHasTwoOrThreeParts()
    {
        var id = Oid("2.5.29.19");
        foreach (var e in new[]
        {
            T(0x30, id),
            T(0x30, id, T(0x01, B(0xff)), T(0x04), T(0x05)),
            T(0x30, T(0x06, B(0x80, 0x01)), T(0x04)),
            T(0x30, T(0x04, B(0x2a)), T(0x04)),
        })
            Assert.Equal(Nested, Refusal(Cert(Tbs(tail: Exts(e)))));
    }

    [Fact]
    public void TheCriticalFlagIsAOneOctetBoolean()
    {
        var id = Oid("2.5.29.19");
        foreach (var flag in new[] { T(0x02, B(0xff)), T(0x01, B(0xff, 0xff)), T(0x01) })
            Assert.Equal(Nested, Refusal(Cert(Tbs(tail: Exts(T(0x30, id, flag, T(0x04)))))));

        LenientExt Read(params byte[][] parts) => Assert.Single(AttestCerts.ParseDer(Cert(Tbs(tail: Exts(T(0x30, parts))))).Exts);
        var plain = Read(id, T(0x04, B(7, 8)));
        Assert.Equal("2.5.29.19", plain.Oid);
        Assert.False(plain.Critical);
        Assert.Equal(B(7, 8), plain.Value);
        Assert.True(Read(id, T(0x01, B(0xff)), T(0x04)).Critical);
        Assert.True(Read(id, T(0x01, B(0x01)), T(0x04)).Critical);
        var off = Read(id, T(0x01, B(0x00)), T(0x04, B(9)));
        Assert.False(off.Critical);
        Assert.Equal(B(9), off.Value);
    }

    [Fact]
    public void TheExtensionValueIsAnOctetString()
    {
        var id = Oid("2.5.29.19");
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(tail: Exts(T(0x30, id, T(0x05)))))));
        Assert.Equal(WrongTag, Refusal(Cert(Tbs(tail: Exts(T(0x30, id, T(0x01, B(0xff)), T(0x05)))))));
    }

    // ---- CheckName

    static string NameRefusal(byte[] n) => Why(() => AttestCerts.CheckName(n, AttestCerts.ReadElem(n, 0, n.Length, 0x30)));

    [Fact]
    public void ANameIsASequenceOfSetsOfTwoPartSequences()
    {
        var str = T(0x0c, A("x"));
        Assert.Equal("", NameRefusal(Name));
        Assert.Equal("", NameRefusal(T(0x30)));
        Assert.Equal("", NameRefusal(T(0x30, T(0x31))));
        Assert.Equal(WrongTag, NameRefusal(T(0x30, T(0x30))));
        Assert.Equal(WrongTag, NameRefusal(T(0x30, T(0x31, T(0x31)))));
        Assert.Equal(Nested, NameRefusal(T(0x30, T(0x31, T(0x30, CnOid)))));
        Assert.Equal(Nested, NameRefusal(T(0x30, T(0x31, T(0x30, CnOid, str, str)))));
        Assert.Equal(Nested, NameRefusal(T(0x30, T(0x31, T(0x30, T(0x06, B(0x80, 0x01)), str)))));
        Assert.Equal(Nested, NameRefusal(T(0x30, T(0x31, T(0x30, CnOid, T(0x04, A("x")))))));
    }

    // ---- LengthHeader

    static byte[] Header(int n) => (byte[])typeof(AttestCerts).GetMethod("LengthHeader", NP)!.Invoke(null, new object[] { (byte)0x30, n })!;

    [Fact]
    public void TheOuterLengthIsWrittenInItsMinimalForm()
    {
        Assert.Equal(B(0x30, 0x00), Header(0));
        Assert.Equal(B(0x30, 0x05), Header(5));
        Assert.Equal(B(0x30, 0x7f), Header(0x7f));
        Assert.Equal(B(0x30, 0x81, 0x80), Header(0x80));
        Assert.Equal(B(0x30, 0x81, 0xff), Header(0xff));
        Assert.Equal(B(0x30, 0x82, 0x01, 0x00), Header(0x100));
        Assert.Equal(B(0x30, 0x82, 0x12, 0x34), Header(0x1234));
        Assert.Equal(B(0x30, 0x82, 0xff, 0xff), Header(0xffff));
        Assert.Equal(B(0x30, 0x83, 0x01, 0x00, 0x00), Header(0x10000));
        Assert.Equal(B(0x30, 0x83, 0x01, 0x02, 0x03), Header(0x010203));
        Assert.Equal(B(0x30, 0x83, 0xff, 0xff, 0xff), Header(0xffffff));
        Assert.Equal(B(0x30, 0x84, 0x01, 0x00, 0x00, 0x00), Header(0x1000000));
        Assert.Equal(B(0x30, 0x84, 0x01, 0x02, 0x03, 0x04), Header(0x01020304));
    }

    // ---- FromPem

    [Fact]
    public void AnythingWithoutACertificateBlockHasNoStartLine()
    {
        Assert.Equal(NoStartLine, Why(() => AttestCerts.FromPem("not a certificate")));
    }

    [Fact]
    public void ThePemBodyMayCarrySpacesTabsAndLineBreaks()
    {
        var b64 = Convert.ToBase64String(Cert());
        var pem = "-----BEGIN CERTIFICATE-----\r\n " + b64[..8] + "\t" + b64[8..16] + " " + b64[16..] + "\n-----END CERTIFICATE-----\n";
        Assert.Equal(B(9), AttestCerts.FromPem(pem).Serial);
    }

    // ---- KeyOfSpki

    static readonly RSA Rsa = RSA.Create(2048);
    static readonly ECDsa EcKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    static readonly Ed25519PrivateKeyParameters EdKey = new(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), 0);
    static readonly byte[] EdPub = EdKey.GeneratePublicKey().GetEncoded();

    static byte[] Spki(byte[] alg, byte[] bits) => T(0x30, alg, T(0x03, B(0), bits));
    static string KeyRefusal(byte[] spki) => Why(() => AttestCerts.KeyOfSpki(spki));

    [Fact]
    public void AnRsaKeyIsNamedByItsAlgorithmAndIsPublic()
    {
        var rsa = AttestCerts.KeyOfSpki(Spki(T(0x30, Oid(RsaKeyOid), T(0x05)), Rsa.ExportRSAPublicKey()));
        Assert.Equal("rsa", rsa.Type);
        Assert.NotNull(rsa.Rsa);
        Assert.False(rsa.RsaBc!.IsPrivate);
        Assert.Equal("rsa-pss", AttestCerts.KeyOfSpki(Spki(T(0x30, Oid(RsaPss)), Rsa.ExportRSAPublicKey())).Type);
    }

    [Fact]
    public void BytesAfterTheRsaPublicKeyAreUnsupported()
    {
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(RsaKeyOid), T(0x05)), Rsa.ExportRSAPublicKey().Concat(B(0)).ToArray())));
    }

    [Fact]
    public void AnEcKeyOnACurveOutsideTheTableIsUnsupported()
    {
        // secp256k1 is known to the platform and not in the table; a lone 04 is its only length-consistent point
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid), Oid("1.3.132.0.10")), B(4))));
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid), Oid("1.3.132.0.10")), new byte[] { 4 }.Concat(new byte[64]).ToArray())));
        // a table curve with the wrong point length: longer, shorter
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid), Oid("1.2.840.10045.3.1.7")), new byte[] { 4 }.Concat(new byte[65]).ToArray())));
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid), Oid("1.2.840.10045.3.1.7")), new byte[] { 4 }.Concat(new byte[63]).ToArray())));
    }

    [Fact]
    public void AnEcKeyNeedsANamedCurve()
    {
        var k = AttestCerts.KeyOfSpki(EcKey.ExportSubjectPublicKeyInfo());
        Assert.Equal("ec", k.Type);
        Assert.Equal("P-256", k.GoCurve);
        var point = B(4);
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid), T(0x05)), point)));
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(EcKeyOid)), point)));
    }

    [Fact]
    public void AnEd25519KeyIsThirtyTwoOctetsWithoutParameters()
    {
        var k = AttestCerts.KeyOfSpki(Spki(KeyAlg, EdPub));
        Assert.Equal("ed25519", k.Type);
        Assert.Equal(EdPub, k.Ed25519);
        Assert.Equal(Unsupported, KeyRefusal(Spki(KeyAlg, EdPub[..31])));
        Assert.Equal(Unsupported, KeyRefusal(Spki(KeyAlg, EdPub.Concat(B(0)).ToArray())));
        Assert.Equal(Unsupported, KeyRefusal(Spki(T(0x30, Oid(Ed), T(0x05)), EdPub)));
    }

    [Fact]
    public void AKeyInfoHasExactlyTwoParts()
    {
        Assert.Equal(Nested, KeyRefusal(T(0x30, KeyAlg, T(0x03, B(0), EdPub), T(0x05))));
        Assert.Equal(Nested, KeyRefusal(T(0x30, KeyAlg)));
    }

    // ---- SigOk

    static readonly byte[] Msg = T(0x30, A("the signed part"));

    static AttCert Child(string oid, byte[] sig, byte[]? prm = null) =>
        new AttCert { AlgsAgree = true, SigOid = oid, RawTbs = Msg, Signature = sig, SigParams = prm };

    [Fact]
    public void AnEd25519SignatureNeedsAnEd25519Key()
    {
        var s = new Ed25519Signer();
        s.Init(true, EdKey);
        s.BlockUpdate(Msg, 0, Msg.Length);
        var sig = s.GenerateSignature();
        Assert.True(AttestCerts.SigOk(Child(Ed, sig), new CertKey { Type = "ed25519", Ed25519 = EdPub }));
        Assert.False(AttestCerts.SigOk(Child(Ed, new byte[64]), new CertKey { Type = "ed25519", Ed25519 = EdPub }));
        Assert.False(AttestCerts.SigOk(Child(Ed, sig), new CertKey { Type = "rsa", Ed25519 = EdPub }));
        Assert.False(AttestCerts.SigOk(Child(Ed, sig), new CertKey { Type = "ed25519" }));
        Assert.False(AttestCerts.SigOk(Child(Ed, sig), new CertKey()));
    }

    [Fact]
    public void AnEcdsaSignatureNeedsAnEcdsaAlgorithm()
    {
        var sig = EcKey.SignData(Msg, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(AttestCerts.SigOk(Child(EcSha256, sig), new CertKey { Ec = EcKey }));
        Assert.False(AttestCerts.SigOk(Child(RsaSha256, sig), new CertKey { Ec = EcKey }));
    }

    [Fact]
    public void APkcs1SignatureNeedsAnRsaAlgorithm()
    {
        var sig = Rsa.SignData(Msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(AttestCerts.SigOk(Child(RsaSha256, sig), new CertKey { Rsa = Rsa }));
        // Node: PKCS#1 under an rsa-pss key verifies false
        Assert.False(AttestCerts.SigOk(Child(RsaSha256, sig), new CertKey { Type = "rsa-pss", Rsa = Rsa }));
        Assert.True(AttestIntelCollateral.CrlSigOk(Msg, sig, new CertKey { Type = "rsa", Rsa = Rsa }));
        Assert.False(AttestIntelCollateral.CrlSigOk(Msg, sig, new CertKey { Type = "rsa-pss", Rsa = Rsa }));
        Assert.False(AttestCerts.SigOk(Child(EcSha256, sig), new CertKey { Rsa = Rsa }));
    }

    [Fact]
    public void AnUnknownAlgorithmOrNoKeyDoesNotVerify()
    {
        var sig = Rsa.SignData(Msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.False(AttestCerts.SigOk(Child("1.2.3", sig), new CertKey { Rsa = Rsa }));
        Assert.False(AttestCerts.SigOk(Child(RsaSha256, sig), new CertKey()));
    }

    [Fact]
    public void AKeyThatCannotBeReadSignsNothing()
    {
        var sig = Rsa.SignData(Msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.False(AttestCerts.SigOkBy(Child(RsaSha256, sig), new AttCert()));
        Assert.True(AttestCerts.SigOkBy(Child(RsaSha256, sig), new AttCert { RawSpki = Spki(T(0x30, Oid(RsaKeyOid), T(0x05)), Rsa.ExportRSAPublicKey()) }));
    }

    // ---- RSASSA-PSS. The modulus is one bit past a byte boundary: an engine initialised for signing would pad the recovered block past the
    // verifier's buffer, so only one initialised for verifying accepts these signatures.

    static readonly AsymmetricCipherKeyPair PssPair = NewPssPair();
    static readonly RsaKeyParameters PssPub = (RsaKeyParameters)PssPair.Public;

    static AsymmetricCipherKeyPair NewPssPair()
    {
        var g = new RsaKeyPairGenerator();
        g.Init(new RsaKeyGenerationParameters(BcBig.ValueOf(65537), new SecureRandom(), 1025, 25));
        return g.GenerateKeyPair();
    }

    static IDigest Dig(string h) => h switch { "SHA1" => new Sha1Digest(), "SHA256" => new Sha256Digest(), _ => new Sha384Digest() };

    static byte[] PssSign(string hash, int salt)
    {
        var s = new PssSigner(new RsaEngine(), Dig(hash), Dig(hash), salt);
        s.Init(true, PssPair.Private);
        s.BlockUpdate(Msg, 0, Msg.Length);
        return s.GenerateSignature();
    }

    static byte[] PssPrm(string hashOid, string mgfHashOid, byte salt) => T(0x30,
        T(0xa0, T(0x30, Oid(hashOid))),
        T(0xa1, T(0x30, Oid(Mgf1), T(0x30, Oid(mgfHashOid)))),
        T(0xa2, T(0x02, B(salt))));

    static bool PssOk(byte[] sig, byte[]? prm) => AttestCerts.SigOk(Child(RsaPss, sig, prm), new CertKey { RsaBc = PssPub });

    [Fact]
    public void AbsentPssParametersMeanSha1AndSalt20()
    {
        var sig = PssSign("SHA1", 20);
        Assert.True(PssOk(sig, null));
        Assert.True(PssOk(sig, Array.Empty<byte>()));
        Assert.True(PssOk(sig, T(0x30)));
        Assert.False(PssOk(PssSign("SHA256", 32), null));
    }

    [Fact]
    public void ThePssHashesAreTheNamedOnes()
    {
        Assert.True(PssOk(PssSign("SHA1", 20), PssPrm(Sha1Oid, Sha1Oid, 20)));
        Assert.True(PssOk(PssSign("SHA256", 32), PssPrm(Sha256Oid, Sha256Oid, 32)));
        Assert.True(PssOk(PssSign("SHA384", 48), PssPrm(Sha384Oid, Sha384Oid, 48)));
    }

    [Fact]
    public void AnUncheckedPssProfileOrNoKeyDoesNotVerify()
    {
        Assert.False(PssOk(PssSign("SHA256", 32), PssPrm(Sha256Oid, Sha384Oid, 32)));
        Assert.False(AttestCerts.SigOk(Child(RsaPss, PssSign("SHA1", 20)), new CertKey()));
    }

    static (string? Hash, int Salt, bool Ok) PssParams(byte[]? raw) =>
        ((string?, int, bool))typeof(AttestCerts).GetMethod("PssParams", NP)!.Invoke(null, new object?[] { raw })!;

    static readonly (string?, int, bool) Refused = default;

    static byte[] Salt(params byte[] content) => T(0x30, T(0xa2, T(0x02, content)));
    static byte[] Trailer(params byte[] content) => T(0x30, T(0xa3, T(0x02, content)));

    [Fact]
    public void TheDefaultProfileComesBackForNoParameters()
    {
        Assert.Equal(("SHA1", 20, true), PssParams(null));
        Assert.Equal(("SHA1", 20, true), PssParams(Array.Empty<byte>()));
        Assert.Equal(("SHA1", 20, true), PssParams(T(0x30)));
    }

    [Fact]
    public void Mgf1IsTheOnlyMaskAndNeedsItsHash()
    {
        Assert.Equal(Refused, PssParams(T(0x30, T(0xa1, T(0x30, Oid("1.2.3"), T(0x30, Oid(Sha1Oid)))))));
        Assert.Equal(Refused, PssParams(T(0x30, T(0xa1, T(0x30, Oid(Mgf1))))));
        Assert.Equal(("SHA1", 20, true), PssParams(T(0x30, T(0xa1, T(0x30, Oid(Mgf1), T(0x30, Oid(Sha1Oid)))))));
    }

    [Fact]
    public void TheSaltLengthIsABigEndianNonNegativeBoundedInteger()
    {
        Assert.Equal(("SHA1", 0, true), PssParams(Salt(0)));
        Assert.Equal(("SHA1", 127, true), PssParams(Salt(0x7f)));
        Assert.Equal(("SHA1", 128, true), PssParams(Salt(0x00, 0x80)));
        Assert.Equal(("SHA1", 256, true), PssParams(Salt(0x01, 0x00)));
        Assert.Equal(("SHA1", 1 << 20, true), PssParams(Salt(0x10, 0x00, 0x00)));
        Assert.Equal(Refused, PssParams(Salt(0x10, 0x00, 0x01)));
    }

    // Node's X509Certificate.verify (OpenSSL ossl_rsa_pss_get_param, c2i_ASN1_INTEGER) refuses these; there is no TypeScript of its own on this path.
    [Fact]
    public void ANegativeOrIllEncodedPssIntegerIsRefused()
    {
        foreach (var content in new[] { B(0xff), B(0x80), B(0xff, 0x00), B(), B(0x00, 0x20), B(0xff, 0x80) })
        {
            Assert.Equal(Refused, PssParams(Salt(content)));
            Assert.Equal(Refused, PssParams(Trailer(content)));
        }
        Assert.Equal(("SHA1", 20, true), PssParams(Trailer(1)));
        Assert.Equal(Refused, PssParams(Trailer(2)));
    }

    // ---- NameText

    static string Dn(byte tag, byte[] content, string oid = "2.5.4.3") => AttestCerts.NameText(T(0x30, T(0x31, T(0x30, Oid(oid), T(tag, content)))));

    [Fact]
    public void EachAttributeHasItsOpenSslShortName()
    {
        foreach (var (oid, label) in new[]
        {
            ("2.5.4.3", "CN"), ("2.5.4.6", "C"), ("2.5.4.7", "L"), ("2.5.4.8", "ST"), ("2.5.4.10", "O"), ("2.5.4.11", "OU"),
            ("2.5.4.5", "serialNumber"), ("2.5.4.9", "street"), ("2.5.4.17", "postalCode"), ("2.5.4.4", "SN"), ("2.5.4.42", "GN"),
            ("2.5.4.12", "title"), ("2.5.4.46", "dnQualifier"), ("1.2.840.113549.1.9.1", "emailAddress"),
            ("0.9.2342.19200300.100.1.25", "DC"), ("0.9.2342.19200300.100.1.1", "UID"), ("1.2.3.4", "1.2.3.4"),
        })
            Assert.Equal(label + "=x", Dn(0x0c, A("x"), oid));
    }

    [Fact]
    public void ReservedCharactersAreEscaped()
    {
        foreach (var ch in ",+\"\\<>;")
            Assert.Equal("CN=a\\" + ch + "b", Dn(0x0c, A("a" + ch + "b")));
    }

    [Fact]
    public void ALeadingSpaceOrHashAndATrailingSpaceAreEscaped()
    {
        Assert.Equal("CN=\\ a", Dn(0x0c, A(" a")));
        Assert.Equal("CN=\\#a", Dn(0x0c, A("#a")));
        Assert.Equal("CN=a\\ ", Dn(0x0c, A("a ")));
        Assert.Equal("CN=a#", Dn(0x0c, A("a#")));
        Assert.Equal("CN=a b#c", Dn(0x0c, A("a b#c")));
    }

    [Fact]
    public void ControlCharactersAreTwoHexDigits()
    {
        Assert.Equal("CN=a\\01b", Dn(0x0c, B(0x61, 0x01, 0x62)));
        Assert.Equal("CN=a\\1Fb", Dn(0x0c, B(0x61, 0x1f, 0x62)));
        Assert.Equal("CN=a\\7Fb", Dn(0x0c, B(0x61, 0x7f, 0x62)));
        Assert.Equal("CN=a~b", Dn(0x0c, A("a~b")));
    }

    [Fact]
    public void InvalidUtf8IsNoText()
    {
        Assert.Equal("", Dn(0x0c, B(0xff)));
    }

    [Fact]
    public void APrintableStringHoldsItsAlphabetOnly()
    {
        Assert.Equal("CN=azAZ09 '()\\+\\,-./:=?", Dn(0x13, A("azAZ09 '()+,-./:=?")));
        foreach (var ch in "_*@[`{!")
            Assert.Equal("", Dn(0x13, A("a" + ch)));
    }

    [Fact]
    public void AnIa5StringStopsAt127()
    {
        Assert.Equal("CN=a\\7F", Dn(0x16, B(0x61, 0x7f)));
        Assert.Equal("", Dn(0x16, B(0x61, 0x80)));
    }

    [Fact]
    public void ANumericStringHoldsDigitsAndSpaces()
    {
        Assert.Equal("CN=0 19", Dn(0x12, A("0 19")));
        foreach (var bad in new[] { "/", ":", "a", "0a" })
            Assert.Equal("", Dn(0x12, A(bad)));
    }

    [Fact]
    public void ABmpStringIsPairsOfOctets()
    {
        Assert.Equal("CN=A", Dn(0x1e, B(0x00, 0x41)));
        Assert.Equal("", Dn(0x1e, B(0x00, 0x41, 0x00)));
    }

    [Fact]
    public void ANameThatCannotBeDecodedIsEmpty()
    {
        Assert.Equal("", Dn(0x03, B(0)));
        Assert.Equal("", AttestCerts.NameText(Name.Concat(B(0)).ToArray()));
        Assert.Equal("", AttestCerts.NameText(B(0x30, 0x05, 0x31)));
    }

    [Fact]
    public void AttributesJoinWithAPlusAndSetsWithANewline()
    {
        byte[] Atv(string oid, string v) => T(0x30, Oid(oid), T(0x0c, A(v)));
        Assert.Equal("CN=a + O=b", AttestCerts.NameText(T(0x30, T(0x31, Atv("2.5.4.3", "a"), Atv("2.5.4.10", "b")))));
        Assert.Equal("CN=a\nO=b", AttestCerts.NameText(T(0x30, T(0x31, Atv("2.5.4.3", "a")), T(0x31, Atv("2.5.4.10", "b")))));
    }
}
