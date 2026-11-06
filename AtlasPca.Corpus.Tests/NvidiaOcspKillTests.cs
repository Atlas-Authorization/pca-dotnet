using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>NVIDIA OCSP against the reference (packages/pca/src/attest-nvidia-ocsp.ts) on a SYNTHETIC P-384 PKI (labelled: not NVIDIA): a small DER
/// builder drives VerifyResponse and CheckChain end to end, every reason, both sides of every condition, the boundary of every comparison.
/// Reasons the reference leaves to the pkijs schema ("OCSP response rejected: " + the library's text) keep that wrapper with this SDK's own text.</summary>
public class NvidiaOcspKillTests
{
    const string Wrapped = "OCSP response rejected: ";
    const string NoMatch = "no SingleResponse matches the certificate (serial / issuer hashes differ)";
    const string IssuerSig = "OCSP response signature does not verify under the issuer key";
    const string NoResponder = "no embedded responder certificate verifies the response";
    const string NotMatching = "embedded certificates do not match the responderID";
    const string NoEku = "delegated responder certificate lacks the id-kp-OCSPSigning EKU";
    const string OutOfWindow = "delegated responder certificate is outside its validity window";
    const string NotSigned = "delegated responder certificate is not signed by the supplied NVIDIA chain";
    const string DelegatedSig = "OCSP response signature does not verify under the delegated responder key";
    const string BadTime = "response carries a malformed (out-of-range) ASN.1 time";

    const string OidBasic = "1.3.6.1.5.5.7.48.1.1";
    const string OidOcspSigning = "1.3.6.1.5.5.7.3.9";
    const string EcSha256 = "1.2.840.10045.4.3.2", EcSha384 = "1.2.840.10045.4.3.3", EcSha512 = "1.2.840.10045.4.3.4";
    const string RsaSha256 = "1.2.840.113549.1.1.11", RsaSha384 = "1.2.840.113549.1.1.12", RsaSha512 = "1.2.840.113549.1.1.13";
    const string HashSha1 = "1.3.14.3.2.26", HashSha256 = "2.16.840.1.101.3.4.2.1", HashSha384 = "2.16.840.1.101.3.4.2.2", HashSha512 = "2.16.840.1.101.3.4.2.3";

    const long Minute = 60_000, Hour = 3_600_000, Day = 86_400_000;
    static readonly long Now = new DateTimeOffset(2026, 10, 8, 23, 8, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
    static int nextSerial = 100;

    static readonly RSA Rsa = RSA.Create(2048);
    static readonly byte[] E = Array.Empty<byte>();
    static readonly byte[] Good = { 0x80, 0 };

    sealed record Id(string Cn, ECDsa Key, byte[] Der, AttCert Cert);

    static readonly Id Root = Mk("root", ca: true);
    static readonly Id Ica = Mk("ica", Root, ca: true);
    static readonly Id Leaf = Mk("leaf", Ica);
    static readonly Id Stranger = Mk("stranger", ca: true);
    static readonly Id ARoot = Mk("aroot", ca: true, aia: true);
    static readonly Id AIca = Mk("aica", ARoot, ca: true, aia: true);
    static readonly Id ALeaf = Mk("aleaf", AIca, aia: true);

    // ---- certificates

    static byte[] Serial()
    {
        int n = nextSerial++;
        return new[] { (byte)(1 + (n >> 8)), (byte)n };
    }

    static DateTimeOffset At(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms);

    static void AddExts(CertificateRequest req, bool ca, bool eku, bool aia)
    {
        if (ca) req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        if (eku) req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(OidOcspSigning) }, false));
        if (aia) req.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(new[] { "http://ocsp.example.test/" }, null));
    }

    static byte[] Issue(CertificateRequest req, string issuerCn, ECDsa signer, long? nb, long? na) =>
        req.Create(new X500DistinguishedName("CN=" + issuerCn), X509SignatureGenerator.CreateForECDsa(signer),
            At(nb ?? Now - 30 * Day), At(na ?? Now + 365 * Day), Serial()).RawData;

    static Id Mk(string cn, Id? signer = null, bool ca = false, bool eku = false, bool aia = false, long? nb = null, long? na = null, string? issuerCn = null, ECDsa? signKey = null)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA384);
        AddExts(req, ca, eku, aia);
        var der = Issue(req, issuerCn ?? signer?.Cn ?? cn, signKey ?? signer?.Key ?? key, nb, na);
        return new Id(cn, key, der, AttestCerts.ParseDer(der));
    }

    static Id Responder(Id signer, string cn = "resp", long? nb = null, long? na = null, bool eku = true) => Mk(cn, signer, eku: eku, nb: nb, na: na);

    /// <summary>A delegated responder whose validity bounds are the given elements (the signature is not valid: only the checks before it can pass).</summary>
    static Id RawValidity(byte[] nb, byte[] na)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var alg = T(0x30, Oid(EcSha384));
        var subject = T(0x30, T(0x31, T(0x30, Oid("2.5.4.3"), T(0x0c, A("rawcert")))));
        var eku = T(0xa3, T(0x30, T(0x30, Oid("2.5.29.37"), T(0x04, T(0x30, Oid(OidOcspSigning))))));
        var tbs = T(0x30, T(0xa0, T(0x02, new byte[] { 2 })), T(0x02, new byte[] { 9 }), alg, Ica.Cert.RawSubject, T(0x30, nb, na), subject, key.ExportSubjectPublicKeyInfo(), eku);
        var der = T(0x30, tbs, alg, T(0x03, new byte[] { 0 }, T(0x30)));
        return new Id("rawcert", key, der, AttestCerts.ParseDer(der));
    }

    /// <summary>A properly issued responder whose public point is compressed: this SDK cannot read the key, the chain signature still verifies.</summary>
    static Id CompressedKeyResponder()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = key.ExportParameters(false).Q;
        var point = new[] { (byte)(2 + (q.Y![^1] & 1)) }.Concat(q.X!).ToArray();
        var pub = new PublicKey(new Oid("1.2.840.10045.2.1"), new AsnEncodedData(Oid("1.2.840.10045.3.1.7")), new AsnEncodedData(point));
        var req = new CertificateRequest(new X500DistinguishedName("CN=compressed"), pub, HashAlgorithmName.SHA384);
        AddExts(req, false, true, false);
        var der = Issue(req, "ica", Ica.Key, null, null);
        return new Id("compressed", key, der, AttestCerts.ParseDer(der));
    }

    // ---- DER

    static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    static byte[] T(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        var hdr = new List<byte> { tag };
        if (body.Length < 0x80) hdr.Add((byte)body.Length);
        else
        {
            var len = new List<byte>();
            for (int n = body.Length; n > 0; n >>= 8) len.Insert(0, (byte)n);
            hdr.Add((byte)(0x80 | len.Count));
            hdr.AddRange(len);
        }
        return hdr.Concat(body).ToArray();
    }

    static byte[] Oid(string dotted)
    {
        var arcs = dotted.Split('.').Select(s => ulong.Parse(s, CultureInfo.InvariantCulture)).ToArray();
        var o = new List<byte>();
        void Arc(ulong v)
        {
            var buf = new List<byte> { (byte)(v & 0x7f) };
            while ((v >>= 7) != 0) buf.Insert(0, (byte)(0x80 | (v & 0x7f)));
            o.AddRange(buf);
        }
        Arc(arcs[0] * 40 + arcs[1]);
        foreach (var a in arcs.Skip(2)) Arc(a);
        return T(0x06, o.ToArray());
    }

    static byte[] GtS(string s) => T(0x18, A(s));
    static byte[] Ut(string s) => T(0x17, A(s));

    static byte[] Gt(long ms)
    {
        var s = At(ms).UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        if (ms % 1000 != 0) s += "." + (ms % 1000).ToString("000", CultureInfo.InvariantCulture).TrimEnd('0');
        return GtS(s + "Z");
    }

    static NvidiaOcsp.Node Top(byte[] b) => NvidiaOcsp.ReadNode(b, 0, b.Length);

    /// <summary>Depth nested SEQUENCEs, written back to front in one buffer (repeated concatenation would be quadratic).</summary>
    static byte[] Nested(int depth)
    {
        var buf = new byte[depth * 5];
        int p = buf.Length;
        for (int i = 0; i < depth; i++)
        {
            int len = buf.Length - p;
            buf[--p] = (byte)len;
            buf[--p] = (byte)(len >> 8);
            buf[--p] = (byte)(len >> 16);
            buf[--p] = 0x83;
            buf[--p] = 0x30;
        }
        return buf;
    }

    // ---- OCSP responses

    static byte[] H(string h, byte[] d) => h switch
    {
        "SHA1" => SHA1.HashData(d), "SHA256" => SHA256.HashData(d), "SHA384" => SHA384.HashData(d), _ => SHA512.HashData(d),
    };

    static byte[] Bits(Id i)
    {
        var q = i.Key.ExportParameters(false).Q;
        return new byte[] { 4 }.Concat(q.X!).Concat(q.Y!).ToArray();
    }

    static byte[] AlgId(string oid) => T(0x30, Oid(oid), new byte[] { 5, 0 });

    static byte[] CertId(Id cert, Id issuer, string oid = HashSha384, string h = "SHA384") =>
        T(0x30, AlgId(oid), T(0x04, H(h, issuer.Cert.RawSubject)), T(0x04, H(h, Bits(issuer))), T(0x02, cert.Cert.Serial));

    static byte[] Sr(byte[]? id = null, byte[]? st = null, byte[]? tu = null, byte[]? nx = null, bool noNext = false, byte[]? extra = null) =>
        T(0x30, id ?? CertId(Leaf, Ica), st ?? Good, tu ?? Gt(Now - Minute), noNext ? E : nx ?? T(0xa0, Gt(Now - Minute + Day)), extra ?? E);

    static byte[] RidName(Id i) => T(0xa1, i.Cert.RawSubject);
    static byte[] RidKey(Id i) => T(0xa2, T(0x04, SHA1.HashData(Bits(i))));

    static byte[] Rd(byte[]? rid = null, byte[]? produced = null, byte[][]? singles = null, byte[]? ver = null, byte[]? ext = null) =>
        T(0x30, ver ?? E, rid ?? RidName(Ica), produced ?? Gt(Now - Minute), T(0x30, singles ?? new[] { Sr() }), ext ?? E);

    static byte[] BitStr(byte[] sig) => T(0x03, new byte[] { 0 }, sig);

    static HashAlgorithmName HashName(string alg) => alg switch
    {
        EcSha256 or RsaSha256 => HashAlgorithmName.SHA256,
        EcSha384 or RsaSha384 => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    static byte[] Basic(byte[] tbs, string alg, byte[] sig, byte[]? certs = null) => T(0x30, tbs, AlgId(alg), BitStr(sig), certs ?? E);
    static byte[] SignEc(ECDsa k, byte[] tbs, string alg = EcSha384) => k.SignData(tbs, HashName(alg), DSASignatureFormat.Rfc3279DerSequence);
    static byte[] SignRsa(byte[] tbs, string alg) => Rsa.SignData(tbs, HashName(alg), RSASignaturePadding.Pkcs1);
    static byte[] Certs(params Id[] ids) => T(0xa0, T(0x30, ids.Select(i => i.Der).ToArray()));

    static byte[] RespBytes(params byte[][] inner) => T(0x30, T(0x0a, new byte[] { 0 }), T(0xa0, T(0x30, inner)));
    static byte[] Outer(byte[] basic) => RespBytes(Oid(OidBasic), T(0x04, basic));

    static byte[] Resp(byte[]? tbs = null, ECDsa? key = null, byte[]? certs = null, string alg = EcSha384)
    {
        var t = tbs ?? Rd();
        return Outer(Basic(t, alg, SignEc(key ?? Ica.Key, t, alg), certs));
    }

    static byte[] ByResponder(Id r, byte[]? rid = null, ECDsa? key = null) => Resp(Rd(rid ?? RidName(r)), key ?? r.Key, Certs(r));

    static List<AttCert> C(params Id[] ids) => ids.Select(i => i.Cert).ToList();

    static string Run(byte[] der, Id? cert = null, Id? issuer = null, List<AttCert>? chain = null, long? now = null)
    {
        var r = NvidiaOcsp.VerifyResponse(der, (cert ?? Leaf).Cert, (issuer ?? Ica).Cert, chain ?? C(Leaf, Ica, Root), now ?? Now);
        return r.Ok ? "ok:" + r.Status : r.Reason;
    }

    static void Rej(string want, params byte[][] ders)
    {
        foreach (var d in ders) Assert.Equal(want, Run(d));
    }

    static string Fresh(long now, long tu, long? next = null, long? produced = null) =>
        Run(Resp(Rd(produced: Gt(produced ?? tu), singles: new[] { Sr(tu: Gt(tu), nx: next is long n ? T(0xa0, Gt(n)) : null, noNext: next == null) })), now: now);

    // ---- times (timeTextInRange, attest-nvidia-ocsp.ts:94-106)

    static long Ms(int y, int mo, int d, int h = 0, int mi = 0, int s = 0) => new DateTimeOffset(y, mo, d, h, mi, s, TimeSpan.Zero).ToUnixTimeMilliseconds();

    [Fact]
    public void GeneralizedTimeInRangeIsItsInstant()
    {
        foreach (var (s, want) in new (string, long)[]
        {
            ("20240101000000Z", Ms(2024, 1, 1)), ("20241231235959Z", Ms(2024, 12, 31, 23, 59, 59)), ("20241201000000Z", Ms(2024, 12, 1)),
            ("20240229120000Z", Ms(2024, 2, 29, 12)), ("20000229000000Z", Ms(2000, 2, 29)), ("20230228000000Z", Ms(2023, 2, 28)),
            ("20240131000000Z", Ms(2024, 1, 31)), ("20240331000000Z", Ms(2024, 3, 31)), ("20240531000000Z", Ms(2024, 5, 31)), ("20240731000000Z", Ms(2024, 7, 31)),
            ("20240831000000Z", Ms(2024, 8, 31)), ("20241031000000Z", Ms(2024, 10, 31)),
            ("20240430000000Z", Ms(2024, 4, 30)), ("20240630000000Z", Ms(2024, 6, 30)), ("20240930000000Z", Ms(2024, 9, 30)), ("20241130000000Z", Ms(2024, 11, 30)),
            ("20240101230000Z", Ms(2024, 1, 1, 23)), ("20240101005900Z", Ms(2024, 1, 1, 0, 59)), ("20240101000059Z", Ms(2024, 1, 1, 0, 0, 59)),
        })
            Assert.Equal(want, NvidiaOcsp.TimeMs(s, false));
    }

    [Fact]
    public void AFractionAddsItsMillisecondsAndTruncates()
    {
        foreach (var (s, plus) in new (string, long)[] { ("20240615120000.5Z", 500), ("20240615120000.123Z", 123), ("20240615120000.1239Z", 123), ("20240615120000.05Z", 50), ("20240615120000.001Z", 1) })
            Assert.Equal(Ms(2024, 6, 15, 12) + plus, NvidiaOcsp.TimeMs(s, false));
    }

    [Fact]
    public void AnOutOfRangeGeneralizedTimeIsRefusedNeverRolledOver()
    {
        foreach (var s in new[]
        {
            "20240001000000Z", "20241301000000Z", "20240100000000Z", "20240132000000Z", "20240230000000Z", "20230229000000Z", "19000229000000Z",
            "20240431000000Z", "20240631000000Z", "20240931000000Z", "20241131000000Z", "20240101240000Z", "20240101006000Z", "20240101000060Z",
            "20240615120000.0Z", "20240615120000.50Z", "20240615120000.Z", "20240615120000", "x20240615120000Z", "20240615120000Zx", "20240615120000Z\n", "2024061512000Z", "20240615120000+0100",
        })
            Assert.Null(NvidiaOcsp.TimeMs(s, false));
    }

    [Fact]
    public void TwoDigitYearsPivotAtFifty()
    {
        foreach (var (s, want) in new (string, long)[]
        {
            ("000229000000Z", Ms(2000, 2, 29)), ("240101000000Z", Ms(2024, 1, 1)), ("480229000000Z", Ms(2048, 2, 29)), ("490101000000Z", Ms(2049, 1, 1)),
            ("500101000000Z", Ms(1950, 1, 1)), ("960229000000Z", Ms(1996, 2, 29)), ("990101000000Z", Ms(1999, 1, 1)), ("491231235959Z", Ms(2049, 12, 31, 23, 59, 59)),
        })
            Assert.Equal(want, NvidiaOcsp.TimeMs(s, true));
        foreach (var s in new[]
        {
            "490229000000Z", "500229000000Z", "000230000000Z", "491301000000Z", "490001000000Z", "490100000000Z", "490132000000Z", "490101240000Z", "490101006000Z", "490101000060Z",
            "490101000000.5Z", "x490101000000Z", "490101000000Zx", "4901010000Z", "20240101000000Z",
        })
            Assert.Null(NvidiaOcsp.TimeMs(s, true));
    }

    [Fact]
    public void TheTimeWalkDescendsEveryConstructedElement()
    {
        var goodGt = GtS("20240101000000Z");
        var badGt = GtS("20241301000000Z");
        var goodUt = Ut("240101000000Z");
        var badUt = Ut("241301000000Z");
        foreach (var b in new[] { goodGt, goodUt, T(0x04, A("20241301000000Z")), T(0x80, A("241301000000Z")), T(0x30), T(0x30, goodGt, goodUt), T(0xa0, T(0x30, T(0x31, goodGt))) })
            Assert.True(NvidiaOcsp.TimesWellFormed(b, Top(b)));
        foreach (var b in new[]
        {
            badGt, badUt, GtS("240101000000Z"), Ut("20240101000000Z"),
            T(0x30, badGt), T(0x30, badUt), T(0x30, badGt, goodGt), T(0x30, goodGt, badGt), T(0xa0, T(0x30, T(0x31, badGt))), T(0x30, T(0x30, goodGt), T(0x30, badUt)),
        })
            Assert.False(NvidiaOcsp.TimesWellFormed(b, Top(b)));
    }

    [Fact]
    public void TheTimeWalkThrowsOnAnElementThatIsNotValidDer()
    {
        var b = T(0x30, new byte[] { 0x30, 0x05, 0x01 });
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(b, Top(b))).Message);
    }

    [Fact]
    public void InvalidDerAnywhereOutranksAMalformedTime()
    {
        var b = T(0x30, GtS("20241301000000Z"), T(0x30, new byte[] { 0x30, 0x05, 0x01 }));
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(b, Top(b))).Message);
    }

    // ---- the reference parser's limits (asn1js 3.0.10 DEFAULT_MAX_DEPTH, DEFAULT_MAX_NODES, DEFAULT_MAX_CONTENT_LENGTH)

    [Fact]
    public void NestingIsBoundedAtTheReferenceDepth()
    {
        var deepest = Nested(101); // the root is depth 0
        Assert.True(NvidiaOcsp.TimesWellFormed(deepest, Top(deepest)));
        foreach (int levels in new[] { 102, 1_000_000 })
        {
            var deep = Nested(levels);
            Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(deep, Top(deep))).Message);
            Assert.Equal("response is not valid DER", Run(deep));
            Assert.Equal("BasicOCSPResponse is not valid DER", Run(Outer(deep)));
        }
        Assert.Equal(Wrapped + "malformed OCSPResponse", Run(deepest));
        Assert.Equal(Wrapped + "malformed BasicOCSPResponse", Run(Outer(deepest)));
    }

    [Fact]
    public void TheNodeCountIsBoundedAtTheReferenceLimit()
    {
        byte[] Nulls(int n) => T(0x30, Enumerable.Repeat(T(0x05), n).ToArray());
        var most = Nulls(9_999); // with the root: 10000
        Assert.True(NvidiaOcsp.TimesWellFormed(most, Top(most)));
        var over = Nulls(10_000);
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(over, Top(over))).Message);
        Assert.Equal("response is not valid DER", Run(over));
        Assert.Equal("BasicOCSPResponse is not valid DER", Run(Outer(over)));
        // counted over the whole walk, not per level
        var spread = T(0x30, Nulls(5_000), Nulls(5_000));
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(spread, Top(spread))).Message);
    }

    [Fact]
    public void ContentLengthIsBoundedAtTheReferenceLimit()
    {
        const int limit = 16 * 1024 * 1024;
        byte[] Octets(int n)
        {
            var b = new byte[5 + n];
            b[0] = 0x04; b[1] = 0x83; b[2] = (byte)(n >> 16); b[3] = (byte)(n >> 8); b[4] = (byte)n;
            return b;
        }
        var most = Octets(limit - 1);
        Assert.True(NvidiaOcsp.TimesWellFormed(most, Top(most)));
        var exact = new byte[] { 0x04, 0x84, 0x01, 0x00, 0x00, 0x00 }.Concat(new byte[limit]).ToArray();
        Assert.True(NvidiaOcsp.TimesWellFormed(exact, Top(exact)));
        var over = new byte[] { 0x04, 0x84, 0x01, 0x00, 0x00, 0x01 }.Concat(new byte[limit + 1]).ToArray();
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.TimesWellFormed(over, Top(over))).Message);
        Assert.Equal("response is not valid DER", Run(over));
    }

    // ---- DER readers

    [Fact]
    public void ConstructedIsBitSix()
    {
        foreach (byte tag in new byte[] { 0x30, 0x31, 0xa0, 0xa1 }) Assert.True(new NvidiaOcsp.Node(tag, 0, 2, 2).Constructed);
        foreach (byte tag in new byte[] { 0x04, 0x18, 0x80, 0x82 }) Assert.False(new NvidiaOcsp.Node(tag, 0, 2, 2).Constructed);
    }

    [Fact]
    public void ReadNodeStaysInsideItsLimit()
    {
        var b = T(0x30, T(0x04, new byte[] { 1, 2 }));
        Assert.Equal(new NvidiaOcsp.Node(0x30, 0, 2, 6), NvidiaOcsp.ReadNode(b, 0, b.Length));
        Assert.Equal(new NvidiaOcsp.Node(0x04, 2, 4, 6), NvidiaOcsp.ReadNode(b, 2, b.Length));
        Assert.Equal(new NvidiaOcsp.Node(0x04, 2, 4, 6), NvidiaOcsp.ReadNode(b, 2, 6));
        foreach (int limit in new[] { 5, 4, 3, 2 })
            Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.ReadNode(b, 2, limit)).Message);
        var padded = b.Concat(new byte[] { 9, 9 }).ToArray();
        Assert.Equal(new NvidiaOcsp.Node(0x04, 2, 4, 6), NvidiaOcsp.ReadNode(padded, 2, 6));
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.ReadNode(padded, 2, 5)).Message);
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.ReadNode(new byte[] { 0x04, 5, 1 }, 0, 3)).Message);
        Assert.Equal("not valid DER", Assert.Throws<AttestError>(() => NvidiaOcsp.ReadNode(new byte[] { 0x04 }, 0, 1)).Message);
    }

    [Fact]
    public void MultiByteTagsAreRefused()
    {
        foreach (byte tag in new byte[] { 0x1f, 0x3f, 0x5f, 0x9f, 0xbf })
            Assert.Equal("multi-byte tags are not supported", Assert.Throws<AttestError>(() => NvidiaOcsp.ReadNode(new[] { tag, (byte)0 }, 0, 2)).Message);
        Assert.Equal(0x1e, NvidiaOcsp.ReadNode(new byte[] { 0x1e, 0 }, 0, 2).Tag);
    }

    [Fact]
    public void OidOfReadsOnlyAnObjectIdentifier()
    {
        var o = Oid(OidBasic);
        Assert.Equal(OidBasic, NvidiaOcsp.OidOf(o, Top(o)));
        var b = T(0x04, new byte[] { 1 });
        Assert.Equal("expected an OBJECT IDENTIFIER", Assert.Throws<AttestError>(() => NvidiaOcsp.OidOf(b, Top(b))).Message);
    }

    [Fact]
    public void LeadingZerosAreStrippedButTheLastOctetIsKept()
    {
        foreach (var (input, want) in new (byte[], byte[])[]
        {
            (E, E), (new byte[] { 0 }, new byte[] { 0 }), (new byte[] { 0, 0 }, new byte[] { 0 }), (new byte[] { 0, 5 }, new byte[] { 5 }),
            (new byte[] { 0, 0, 5 }, new byte[] { 5 }), (new byte[] { 5, 0 }, new byte[] { 5, 0 }), (new byte[] { 5 }, new byte[] { 5 }), (new byte[] { 0, 5, 0 }, new byte[] { 5, 0 }),
        })
            Assert.Equal(want, NvidiaOcsp.StripLeading0(input));
    }

    [Fact]
    public void SpkiKeyBitsIsTheBitStringContentOfATwoPartSpki()
    {
        Assert.Equal(Bits(Ica), NvidiaOcsp.SpkiKeyBits(Ica.Cert));
        var alg = T(0x30, Oid("1.2.840.10045.2.1"));
        var bits = T(0x03, new byte[] { 0, 7, 8 });
        Assert.Equal(new byte[] { 7, 8 }, NvidiaOcsp.SpkiKeyBits(new AttCert { RawSpki = T(0x30, alg, bits) }));
        foreach (var spki in new[] { T(0x30, alg), T(0x30, alg, bits, bits), T(0x30) })
            Assert.Equal("malformed SubjectPublicKeyInfo", Assert.Throws<AttestError>(() => NvidiaOcsp.SpkiKeyBits(new AttCert { RawSpki = spki })).Message);
    }

    // ---- signatures (verifySig, attest-nvidia-ocsp.ts:191-202)

    [Fact]
    public void EverySignatureAlgorithmVerifiesUnderItsFamilyOnly()
    {
        var tbs = new byte[] { 1, 2, 3 };
        var ec = AttestCerts.KeyOf(Ica.Cert);
        var rsa = new CertKey { Type = "rsa", Rsa = Rsa };
        foreach (var alg in new[] { EcSha256, EcSha384, EcSha512 })
        {
            var sig = SignEc(Ica.Key, tbs, alg);
            Assert.True(NvidiaOcsp.SigOk(alg, tbs, sig, ec));
            Assert.False(NvidiaOcsp.SigOk(alg, new byte[] { 9 }, sig, ec));
            Assert.False(NvidiaOcsp.SigOk(alg, tbs, new byte[] { 0x30, 0 }, ec));
            Assert.False(NvidiaOcsp.SigOk(alg, tbs, sig, rsa));
        }
        foreach (var alg in new[] { RsaSha256, RsaSha384, RsaSha512 })
        {
            var sig = SignRsa(tbs, alg);
            Assert.True(NvidiaOcsp.SigOk(alg, tbs, sig, rsa));
            Assert.False(NvidiaOcsp.SigOk(alg, new byte[] { 9 }, sig, rsa));
            Assert.False(NvidiaOcsp.SigOk(alg, tbs, new byte[256], rsa));
            Assert.False(NvidiaOcsp.SigOk(alg, tbs, sig, ec));
        }
        Assert.False(NvidiaOcsp.SigOk(EcSha256, tbs, SignEc(Ica.Key, tbs, EcSha384), ec));
        Assert.False(NvidiaOcsp.SigOk(RsaSha256, tbs, SignRsa(tbs, RsaSha384), rsa));
        // an algorithm outside the table and a key of neither family never verify, even with an otherwise valid signature
        Assert.False(NvidiaOcsp.SigOk("1.2.3", tbs, SignEc(Ica.Key, tbs), ec));
        Assert.False(NvidiaOcsp.SigOk("1.2.3", tbs, SignRsa(tbs, RsaSha256), rsa));
        Assert.False(NvidiaOcsp.SigOk(EcSha384, tbs, SignEc(Ica.Key, tbs), new CertKey { Type = "ed25519" }));
        Assert.False(NvidiaOcsp.SigOk(RsaSha256, tbs, SignRsa(tbs, RsaSha256), new CertKey { Type = "ed25519" }));
    }

    [Fact]
    public void EcdsaAndRsaResponsesVerifyEndToEnd()
    {
        foreach (var alg in new[] { EcSha256, EcSha384, EcSha512 })
            Assert.Equal("ok:good", Run(Resp(alg: alg)));
        var t = Rd();
        Assert.Equal(IssuerSig, Run(Outer(Basic(t, EcSha256, SignEc(Ica.Key, t, EcSha384)))));
        Assert.Equal(IssuerSig, Run(Outer(Basic(t, RsaSha256, SignEc(Ica.Key, t, EcSha256)))));

        var req = new CertificateRequest("CN=rsa-resp", Rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        AddExts(req, false, true, false);
        var der = Issue(req, "ica", Ica.Key, null, null);
        var cert = AttestCerts.ParseDer(der);
        var tbs = Rd(T(0xa1, cert.RawSubject));
        var certs = T(0xa0, T(0x30, der));
        foreach (var alg in new[] { RsaSha256, RsaSha384, RsaSha512 })
            Assert.Equal("ok:good", Run(Outer(Basic(tbs, alg, SignRsa(tbs, alg), certs))));
        Assert.Equal(DelegatedSig, Run(Outer(Basic(tbs, EcSha384, SignRsa(tbs, RsaSha384), certs))));
    }

    // ---- OCSPResponse and responseBytes

    [Fact]
    public void TheOuterStructureIsRefusedWithExactReasons()
    {
        Rej("response is not valid DER", E, new byte[] { 0x30 }, new byte[] { 0x30, 0x05, 0x01 }, T(0x30, new byte[] { 0xa0, 0x05, 0x01 }));
        Rej("trailing bytes after OCSPResponse", Resp().Concat(new byte[] { 0 }).ToArray());
        Rej(Wrapped + "OCSPResponse is not a SEQUENCE", T(0x31, T(0x0a, new byte[] { 0 })), T(0x04, new byte[] { 1 }));
        Rej(Wrapped + "malformed OCSPResponse",
            T(0x30), T(0x30, T(0x02, new byte[] { 0 })), T(0x30, T(0x0a)), T(0x30, T(0x0a, new byte[] { 0, 0 })),
            T(0x30, T(0x0a, new byte[] { 0 }), T(0x04)), T(0x30, T(0x0a, new byte[] { 1 }), T(0x04)));
        Rej("successful response carries no responseBytes", T(0x30, T(0x0a, new byte[] { 0 })));
    }

    [Fact]
    public void ResponseStatusIsReportedAsTheSignedEnumeratedValue()
    {
        foreach (var (raw, shown) in new (byte, string)[] { (1, "1"), (2, "2"), (6, "6"), (0x7f, "127"), (0x80, "-128"), (0xff, "-1") })
            Assert.Equal($"OCSP responseStatus is {shown} (not successful)", Run(T(0x30, T(0x0a, new[] { raw }))));
    }

    [Fact]
    public void ResponseBytesAreRefusedWithExactReasons()
    {
        var oid = Oid(OidBasic);
        var body = T(0x04, Basic(Rd(), EcSha384, SignEc(Ica.Key, Rd())));
        var status = T(0x0a, new byte[] { 0 });
        Rej(Wrapped + "malformed responseBytes",
            T(0x30, status, T(0xa0)), T(0x30, status, T(0xa0, T(0x30, oid, body), T(0x30, oid, body))), T(0x30, status, T(0xa0, T(0x31, oid, body))),
            RespBytes(oid), RespBytes(oid, body, body), RespBytes(oid, T(0x03, new byte[] { 0 })));
        Rej(Wrapped + "expected an OBJECT IDENTIFIER", RespBytes(T(0x04), body));
        Rej("responseType is not id-pkix-ocsp-basic", RespBytes(Oid("1.3.6.1.5.5.7.48.1.2"), body));
    }

    // ---- BasicOCSPResponse

    static readonly byte[] AnySig = BitStr(new byte[] { 0x30, 0 });

    [Fact]
    public void TheBasicResponseIsRefusedWithExactReasons()
    {
        var alg = AlgId(EcSha384);
        Rej("BasicOCSPResponse is not valid DER", Outer(E), Outer(new byte[] { 0x30, 0x05 }), Outer(T(0x30, new byte[] { 0x04, 0x05, 0x01 })));
        Rej(Wrapped + "BasicOCSPResponse is not a SEQUENCE", Outer(T(0x31)), Outer(T(0x04, new byte[] { 1 })));
        Rej(Wrapped + "malformed BasicOCSPResponse",
            Outer(T(0x30)), Outer(T(0x30, Rd(), alg)),
            Outer(T(0x30, T(0x31), alg, AnySig)), Outer(T(0x30, Rd(), T(0x31), AnySig)), Outer(T(0x30, Rd(), alg, T(0x04, new byte[] { 0 }))),
            Outer(T(0x30, Rd(), alg, AnySig, T(0x04))), Outer(T(0x30, Rd(), alg, AnySig, T(0x80))));
        Rej(Wrapped + "malformed signatureAlgorithm", Outer(T(0x30, Rd(), T(0x30), AnySig)));
        Rej(Wrapped + "expected an OBJECT IDENTIFIER", Outer(T(0x30, Rd(), T(0x30, T(0x05)), AnySig)));
        Rej("unsupported OCSP signature algorithm 1.2.3", Outer(T(0x30, Rd(), T(0x30, Oid("1.2.3")), AnySig)));
        Rej(Wrapped + "malformed signature", Outer(T(0x30, Rd(), alg, T(0x03))));
        Rej(IssuerSig, Outer(T(0x30, Rd(), alg, T(0x03, new byte[] { 0 }))));
    }

    [Fact]
    public void AnyMalformedTimeInTheBasicResponseRefusesIt()
    {
        Rej(BadTime,
            Resp(Rd(produced: GtS("20241301000000Z"))),
            Resp(Rd(singles: new[] { Sr(tu: GtS("20240230000000Z")) })),
            Resp(Rd(singles: new[] { Sr(nx: T(0xa0, GtS("20240132000000Z"))) })),
            Resp(Rd(ext: T(0xa1, T(0x30, Ut("241301000000Z"))))),
            Outer(T(0x30, Rd(produced: GtS("20241301000000Z")), T(0x30, Oid("1.2.3")), AnySig))); // before the algorithm, as the reference
    }

    [Fact]
    public void ResponseDataIsRefusedWithExactReasons()
    {
        var ver = T(0xa0, T(0x02, new byte[] { 0 }));
        var rid = RidName(Ica);
        var prod = Gt(Now - Minute);
        var list = T(0x30, Sr());
        byte[] M(params byte[][] parts)
        {
            var tbs = T(0x30, parts);
            return Outer(Basic(tbs, EcSha384, SignEc(Ica.Key, tbs)));
        }
        Rej(Wrapped + "malformed ResponseData",
            M(), M(rid), M(rid, prod), M(ver), M(ver, rid, prod),
            M(T(0x04), prod, list), M(T(0xa3), prod, list), M(T(0x30), prod, list),
            M(rid, T(0x17, A("260101000000Z")), list), M(rid, prod, T(0x31, Sr())),
            M(rid, prod, list, T(0x04)), M(rid, prod, list, T(0xa0)), M(ver, rid, prod, list, T(0x04)),
            M(T(0xa0), rid, prod, list), M(T(0xa0, T(0x04)), rid, prod, list));
        Assert.Equal("ok:good", Run(Resp(Rd(ver: ver))));
        Assert.Equal("ok:good", Run(Resp(Rd(ext: T(0xa1, T(0x30))))));
        Assert.Equal("ok:good", Run(Resp(Rd(ver: ver, ext: T(0xa1, T(0x30))))));
    }

    [Fact]
    public void ASingleResponseIsRefusedWithExactReasons()
    {
        var id = CertId(Leaf, Ica);
        var tu = Gt(Now - Minute);
        var next = T(0xa0, Gt(Now + Day));
        var ext = T(0xa1, T(0x30));
        var other = CertId(Stranger, Stranger);
        byte[] One(byte[] single) => Resp(Rd(singles: new[] { single }));
        foreach (var bad in new[]
        {
            T(0x31, id, Good, tu), T(0x30, id, Good), T(0x30, T(0x31), Good, tu), T(0x30, id, Good, Ut("260101000000Z")),
            T(0x30, id, Good, tu, T(0x04)), T(0x30, id, Good, tu, T(0x80, A("20300101000000Z"))), T(0x30, id, Good, tu, next, T(0x04)), T(0x30, id, Good, tu, next, next),
            T(0x30, other, Good, tu, T(0x04)), // refused in every SingleResponse, not only the one that matches
        })
            Assert.Equal(Wrapped + "malformed SingleResponse", Run(One(bad)));
        foreach (var bad in new[] { T(0xa0), T(0xa0, Ut("300101000000Z")), T(0xa0, Gt(Now + Day), Gt(Now + Day)) })
        {
            Assert.Equal(Wrapped + "malformed nextUpdate", Run(One(T(0x30, id, Good, tu, bad))));
            Assert.Equal(Wrapped + "malformed nextUpdate", Run(One(T(0x30, other, Good, tu, bad))));
        }
        Assert.Equal("ok:good", Run(One(T(0x30, id, Good, tu))));
        Assert.Equal("ok:good", Run(One(T(0x30, id, Good, tu, next))));
        Assert.Equal("ok:good", Run(One(T(0x30, id, Good, tu, ext))));
        Assert.Equal("ok:good", Run(One(T(0x30, id, Good, tu, next, ext))));
    }

    [Fact]
    public void ACertIdIsRefusedWithExactReasons()
    {
        var alg = AlgId(HashSha384);
        var name = T(0x04, H("SHA384", Ica.Cert.RawSubject));
        var key = T(0x04, H("SHA384", Bits(Ica)));
        var serial = T(0x02, Leaf.Cert.Serial);
        byte[] One(params byte[][] parts) => Resp(Rd(singles: new[] { Sr(id: T(0x30, parts)) }));
        Rej(Wrapped + "malformed CertID",
            One(), One(alg, name, key), One(alg, name, key, serial, serial),
            One(T(0x31, Oid(HashSha384)), name, key, serial), One(alg, T(0x03, new byte[] { 0 }), key, serial), One(alg, name, T(0x03, new byte[] { 0 }), serial), One(alg, name, key, T(0x04)));
        Rej(Wrapped + "malformed CertID hash algorithm", One(T(0x30), name, key, serial));
        Rej(Wrapped + "expected an OBJECT IDENTIFIER", One(T(0x30, T(0x05)), name, key, serial));
        Assert.Equal("ok:good", Run(One(alg, name, key, serial)));
    }

    [Fact]
    public void EveryCertIdHashMatchesAndAnUnknownOneNever()
    {
        foreach (var (oid, h) in new[] { (HashSha1, "SHA1"), (HashSha256, "SHA256"), (HashSha384, "SHA384"), (HashSha512, "SHA512") })
            Assert.Equal("ok:good", Run(Resp(Rd(singles: new[] { Sr(id: CertId(Leaf, Ica, oid, h)) }))));
        // SHA-512 values: an unknown OID must not fall through to the hash that is HashOf's default arm
        foreach (var h in new[] { "SHA1", "SHA256", "SHA384", "SHA512" })
            Assert.Equal(NoMatch, Run(Resp(Rd(singles: new[] { Sr(id: CertId(Leaf, Ica, "1.2.3.4", h)) }))));
    }

    [Fact]
    public void SerialNameHashAndKeyHashMustEachMatch()
    {
        var alg = AlgId(HashSha384);
        var name = T(0x04, H("SHA384", Ica.Cert.RawSubject));
        var key = T(0x04, H("SHA384", Bits(Ica)));
        var serial = T(0x02, Leaf.Cert.Serial);
        byte[] One(params byte[][] parts) => Resp(Rd(singles: new[] { Sr(id: T(0x30, parts)) }));
        Rej(NoMatch,
            One(alg, name, key, T(0x02, new byte[] { 99 })),
            One(alg, T(0x04, H("SHA384", Root.Cert.RawSubject)), key, serial),
            One(alg, name, T(0x04, H("SHA384", Bits(Root))), serial),
            Resp(Rd(singles: Array.Empty<byte[]>())));
    }

    [Fact]
    public void SerialsCompareWithoutLeadingZeros()
    {
        var padded = T(0x30, AlgId(HashSha384), T(0x04, H("SHA384", Ica.Cert.RawSubject)), T(0x04, H("SHA384", Bits(Ica))), T(0x02, new byte[] { 0, 0 }.Concat(Leaf.Cert.Serial).ToArray()));
        Assert.Equal("ok:good", Run(Resp(Rd(singles: new[] { Sr(id: padded) }))));

        byte[] WithSerial(params byte[] s) => Resp(Rd(singles: new[] { Sr(id: T(0x30, AlgId(HashSha384), T(0x04, H("SHA384", Ica.Cert.RawSubject)), T(0x04, H("SHA384", Bits(Ica))), T(0x02, s))) }));
        string For(byte[] der, params byte[] certSerial)
        {
            var c = AttestCerts.ParseDer(Leaf.Der);
            c.Serial = certSerial;
            var r = NvidiaOcsp.VerifyResponse(der, c, Ica.Cert, C(Leaf, Ica, Root), Now);
            return r.Ok ? "ok" : r.Reason;
        }
        Assert.Equal("ok", For(WithSerial(0, 0), 0)); // a zero serial
        Assert.Equal("ok", For(WithSerial(5), 0, 5));
        Assert.Equal(NoMatch, For(WithSerial(5, 0), 0, 5));
        Assert.Equal(NoMatch, For(WithSerial(0, 5), 5, 0));
    }

    [Fact]
    public void ExactlyOneSingleResponseMustSpeakForTheCertificate()
    {
        Assert.Equal("ambiguous: multiple SingleResponses match the certificate", Run(Resp(Rd(singles: new[] { Sr(), Sr() }))));
        var other = Sr(id: CertId(Stranger, Stranger));
        Assert.Equal("ok:good", Run(Resp(Rd(singles: new[] { other, Sr() }))));
        Assert.Equal("ok:good", Run(Resp(Rd(singles: new[] { Sr(), other }))));
        Assert.Equal(NoMatch, Run(Resp(Rd(singles: new[] { other, other }))));
    }

    // ---- responder authentication

    [Fact]
    public void TheIssuerAnswersByNameOrByKeyHash()
    {
        Assert.Equal("ok:good", Run(Resp(Rd(RidName(Ica)))));
        Assert.Equal("ok:good", Run(Resp(Rd(RidKey(Ica)))));
        Rej(IssuerSig, Resp(Rd(RidName(Ica)), Stranger.Key), Resp(Rd(RidKey(Ica)), Stranger.Key));
    }

    [Fact]
    public void AResponderIdThatIsNotTheIssuersGetsNoIssuerTrust()
    {
        var wrongHash = T(0xa2, T(0x04, SHA1.HashData(Bits(Stranger))));
        var rightHashWrongTag = T(0xa2, T(0x05, SHA1.HashData(Bits(Ica))));
        var nameInOctetString = T(0xa1, T(0x04, Ica.Cert.RawSubject));
        Rej(NoResponder,
            Resp(Rd(RidName(Stranger))), Resp(Rd(wrongHash)), Resp(Rd(rightHashWrongTag)), Resp(Rd(nameInOctetString)),
            Resp(Rd(T(0xa2, T(0x04, Bits(Ica))))));
        Rej(Wrapped + "malformed responderID", Resp(Rd(T(0xa1))), Resp(Rd(T(0xa2))), Resp(Rd(T(0xa1, Ica.Cert.RawSubject, Ica.Cert.RawSubject))));
    }

    [Fact]
    public void ADelegatedResponderSignedAtOrAboveTheIssuerIsAccepted()
    {
        var byIssuer = Responder(Ica);
        var byRoot = Responder(Root);
        Assert.Equal("ok:good", Run(ByResponder(byIssuer)));
        Assert.Equal("ok:good", Run(ByResponder(byIssuer, RidKey(byIssuer))));
        Assert.Equal("ok:good", Run(ByResponder(byRoot)));
        // a certificate list without a usable one, and an empty list, change nothing about the issuer path
        Assert.Equal("ok:good", Run(Resp(certs: T(0xa0, T(0x30)))));
        Assert.Equal("ok:good", Run(Resp(certs: Certs(byIssuer))));
        // an unusable candidate before a usable one
        Assert.Equal("ok:good", Run(Resp(Rd(RidName(byIssuer)), byIssuer.Key, Certs(Stranger, byIssuer))));
    }

    [Fact]
    public void TheSignersAreTheChainFromTheFirstOccurrenceOfTheIssuer()
    {
        var below = Mk("resp", Leaf, eku: true);
        Assert.Equal(NotSigned, Run(ByResponder(below)));
        var byRoot = Responder(Root);
        // the issuer twice: the first occurrence admits the root (findIndex, attest-nvidia-ocsp.ts:295)
        Assert.Equal("ok:good", Run(ByResponder(byRoot), chain: C(Leaf, Ica, Root, Ica)));
        // the issuer at index 0 admits the whole chain
        Assert.Equal("ok:good", Run(ByResponder(Responder(Root)), chain: C(Ica, Root)));
        // the issuer not in the chain: only the issuer itself may sign the responder
        Assert.Equal("ok:good", Run(ByResponder(Responder(Ica)), chain: C(Leaf, Root)));
        Assert.Equal("ok:good", Run(ByResponder(Responder(Ica)), chain: new List<AttCert>()));
        Assert.Equal(NotSigned, Run(ByResponder(byRoot), chain: C(Leaf, Root)));
    }

    [Fact]
    public void EachDelegatedRefusalIsItsOwnReasonAndStopsThatCandidate()
    {
        // every candidate is valid in all the other respects: without the "continue" the response would be accepted
        var r = Responder(Ica);
        Assert.Equal(NoResponder, Run(Resp(Rd(RidName(Stranger)), Stranger.Key)));
        Assert.Equal(NotMatching, Run(Resp(Rd(RidName(Stranger)), r.Key, Certs(r))));
        Assert.Equal(NotMatching, Run(Resp(Rd(RidKey(Stranger)), r.Key, Certs(r))));
        var noEku = Responder(Ica, eku: false);
        Assert.Equal(NoEku, Run(ByResponder(noEku)));
        var early = Responder(Ica, nb: Now + 1000);
        Assert.Equal(OutOfWindow, Run(ByResponder(early)));
        var late = Responder(Ica, na: Now - 1000);
        Assert.Equal(OutOfWindow, Run(ByResponder(late)));
        var strangerSigned = Mk("resp", issuerCn: "ica", signKey: Stranger.Key, eku: true);
        Assert.Equal(NotSigned, Run(ByResponder(strangerSigned)));
        var wrongIssuerName = Mk("resp", issuerCn: "other", signKey: Ica.Key, eku: true);
        Assert.Equal(NotSigned, Run(ByResponder(wrongIssuerName)));
        Assert.Equal(DelegatedSig, Run(ByResponder(r, key: Stranger.Key)));
        var compressed = CompressedKeyResponder();
        Assert.Equal(DelegatedSig, Run(ByResponder(compressed)));
        // the last candidate's reason is the one reported
        Assert.Equal(NoEku, Run(Resp(Rd(RidName(noEku)), noEku.Key, Certs(Stranger, noEku))));
    }

    [Fact]
    public void AnIssuerResponderIdReportsTheIssuerKeyWhateverTheCandidates()
    {
        var sameName = Mk("ica", Ica, eku: true);
        Assert.Equal("ok:good", Run(Resp(Rd(RidName(Ica)), sameName.Key, Certs(sameName))));
        Assert.Equal(IssuerSig, Run(Resp(Rd(RidName(Ica)), Stranger.Key, Certs(sameName))));
        Assert.Equal(IssuerSig, Run(Resp(Rd(RidName(Ica)), Stranger.Key, Certs(Stranger))));
    }

    /// <summary>The candidate loop ends at the first responder that verifies (attest-nvidia-ocsp.ts:305-306). Only a hand-edited chain entry can make a
    /// later candidate throw: a certificate that went through ParseDer never does, so the signer here is edited after parsing.</summary>
    [Fact]
    public void TheFirstVerifyingResponderEndsTheCandidateLoop()
    {
        var poison = Mk("poison", ca: true);
        var broken = AttestCerts.ParseDer(poison.Der);
        broken.RawSpki = T(0x30, T(0x30, Oid("1.2.840.10045.2.1")), T(0x03)); // an empty BIT STRING: reading the key throws, and not an AttestError
        var chain = C(Leaf, Ica);
        chain.Add(broken);
        var good = Responder(Ica);
        var later = Mk("resp", poison, eku: true); // matches, has the EKU, is in its window, and is checked against the broken signer
        var tbs = Rd(RidName(good));
        Assert.Equal("ok:good", Run(Resp(tbs, good.Key, Certs(good, later)), chain: chain));
        // the control: reached first, the same candidate does refuse the response
        Assert.StartsWith(Wrapped, Run(Resp(tbs, good.Key, Certs(later, good)), chain: chain));
    }

    [Fact]
    public void AnEmbeddedCertificateWithAThreePartKeyIsRefusedWhenParsedNotInTheLoop()
    {
        const string nested = "error:0688010A:asn1 encoding routines::nested asn1 error";
        var good = Responder(Ica);
        var alg = T(0x30, Oid(EcSha384));
        var spki = T(0x30, T(0x30, Oid("1.2.840.10045.2.1")), BitStr(Bits(good)), T(0x05));
        var eku = T(0xa3, T(0x30, T(0x30, Oid("2.5.29.37"), T(0x04, T(0x30, Oid(OidOcspSigning))))));
        var tbs = T(0x30, T(0x02, new byte[] { 9 }), alg, Ica.Cert.RawSubject, T(0x30, Ut("200101000000Z"), Ut("300101000000Z")), good.Cert.RawSubject, spki, eku);
        var bad = T(0x30, tbs, alg, T(0x03, new byte[] { 0 }, T(0x30)));
        Assert.Equal(nested, Assert.Throws<AttestError>(() => AttestCerts.ParseDer(bad)).Message);
        var rd = Rd(RidKey(good));
        Assert.Equal(Wrapped + nested, Run(Resp(rd, good.Key, T(0xa0, T(0x30, good.Der, bad)))));
    }

    [Fact]
    public void TheResponderValidityWindowIncludesBothBounds()
    {
        Assert.Equal("ok:good", Run(ByResponder(Responder(Ica, nb: Now))));
        Assert.Equal("ok:good", Run(ByResponder(Responder(Ica, na: Now))));
        Assert.Equal(OutOfWindow, Run(ByResponder(Responder(Ica, nb: Now + 1000))));
        Assert.Equal(OutOfWindow, Run(ByResponder(Responder(Ica, na: Now - 1000))));
    }

    [Fact]
    public void AnUnparseableResponderBoundIsOutsideTheWindow()
    {
        // well-formed for the time walk, but a certificate validity carries no fraction: the bound is not ok and reads as instant 0
        var fractional = GtS("20200101000000.5Z");
        var badFrom = RawValidity(fractional, Ut("300101000000Z"));
        Assert.Equal(OutOfWindow, Run(ByResponder(badFrom)));
        var badTo = RawValidity(Ut("690101000000Z"), fractional);
        // at instant 0 the window itself would hold: only the bound's own check refuses
        Assert.Equal(OutOfWindow, Run(ByResponder(badTo), now: 0));
        var bothGood = RawValidity(Ut("690101000000Z"), Ut("300101000000Z"));
        Assert.Equal(NotSigned, Run(ByResponder(bothGood)));
    }

    [Fact]
    public void MalformedCertificatesAreRefusedWhoeverSigned()
    {
        // the reference's schema parses them before anything else
        Assert.Equal(Wrapped + "error:068000A8:asn1 encoding routines::wrong tag", Run(Resp(certs: T(0xa0, T(0x30, T(0x30, T(0x02, new byte[] { 1 })))))));
        foreach (var certs in new[] { T(0xa0), T(0xa0, T(0x31)), T(0xa0, T(0x30), T(0x30)) })
            Assert.Equal(Wrapped + "malformed certs", Run(Resp(certs: certs)));
    }

    // ---- freshness (attest-nvidia-ocsp.ts:328-334)

    [Fact]
    public void ThisUpdateAndProducedAtMayNotBeInTheFuture()
    {
        Assert.Equal("ok:good", Fresh(Now, Now));
        Assert.Equal("response thisUpdate is in the future", Fresh(Now, Now + 1, produced: Now - 1000));
        Assert.Equal("response thisUpdate is in the future", Fresh(Now, Now + 1000, produced: Now - 1000));
        Assert.Equal("ok:good", Fresh(Now, Now - 1000, produced: Now));
        Assert.Equal("response producedAt is in the future", Fresh(Now, Now - 1000, produced: Now + 1));
        Assert.Equal("response producedAt is in the future", Fresh(Now, Now - 1000, produced: Now + 1000));
    }

    [Fact]
    public void NextUpdateBoundsTheResponseWhenPresent()
    {
        Assert.Equal("response nextUpdate is invalid", Fresh(Now, Now - 1000, next: Now - 1001));
        Assert.Equal("ok:good", Fresh(Now - 1000, Now - 1000, next: Now - 1000));
        Assert.Equal("response is stale (past nextUpdate)", Fresh(Now, Now - 2000, next: Now - 1));
        Assert.Equal("ok:good", Fresh(Now, Now - 2000, next: Now));
        Assert.Equal("ok:good", Fresh(Now, Now - 2000));
    }

    [Fact]
    public void TheMaximumAgeIsSevenDaysWithOrWithoutNextUpdate()
    {
        const string old = "response is older than the maximum accepted age";
        Assert.Equal("ok:good", Fresh(Now, Now - 7 * Day));
        Assert.Equal(old, Fresh(Now, Now - 7 * Day - 1));
        Assert.Equal("ok:good", Fresh(Now, Now - 7 * Day, next: Now + Day));
        Assert.Equal(old, Fresh(Now, Now - 7 * Day - 1, next: Now + Day));
    }

    // ---- certStatus (attest-nvidia-ocsp.ts:337-355 and the pkijs SingleResponse schema)

    [Fact]
    public void GoodUnknownAndRevokedAreTheAcceptedChoices()
    {
        string Status(byte[] st) => Run(Resp(Rd(singles: new[] { Sr(st: st) })));
        var at = Gt(Now - Hour);
        Assert.Equal("ok:good", Status(T(0x80)));
        Assert.Equal("ok:unknown", Status(T(0x82)));
        Assert.Equal("ok:unknown", Status(T(0x82, new byte[] { 0 })));
        Assert.Equal("ok:revoked", Status(T(0xa1, at)));
        Assert.Equal("ok:revoked", Status(T(0xa1, at, T(0xa0, T(0x0a, new byte[] { 4 })))));
    }

    /// <summary>FAIL-OPEN regression: a constructed [0] read as GOOD; the reference's schema admits only a primitive [0].</summary>
    [Fact]
    public void AConstructedGoodOrUnknownIsNeverAStatus()
    {
        string Status(byte[] st) => Run(Resp(Rd(singles: new[] { Sr(st: st) })));
        var at = Gt(Now - Hour);
        foreach (var st in new[] { T(0xa0), T(0xa0, at), T(0xa2), T(0xa2, at), T(0xa3), T(0x81), T(0x81, at), T(0x05), T(0x40), T(0xc0), T(0x04, new byte[] { 0 }) })
            Assert.Equal("malformed certStatus", Status(st));
        foreach (var st in new[] { T(0x83), T(0x84), T(0x9e) })
            Assert.Equal("unrecognised certStatus", Status(st));
        foreach (var st in new[]
        {
            T(0xa1), T(0xa1, T(0x04, A("20260101000000Z"))), T(0xa1, GtS("20260101000000.5Z")), T(0xa1, T(0x30, at)),
        })
            Assert.Equal("malformed revoked certStatus", Status(st));
    }

    // ---- failure wrapper

    [Fact]
    public void AnyExceptionBecomesAWrappedRefusal()
    {
        var c = AttestCerts.ParseDer(Leaf.Der);
        c.Serial = null!; // not an AttestError: the last line of defence
        var r = NvidiaOcsp.VerifyResponse(Resp(), c, Ica.Cert, C(Leaf, Ica, Root), Now);
        Assert.False(r.Ok);
        Assert.StartsWith(Wrapped, r.Reason);
        Assert.NotEqual(Wrapped, r.Reason);
    }

    // ---- CheckChain (attest-nvidia-ocsp.ts:410-461)

    static byte[] For(Id cert, Id issuer, byte[]? st = null) => Resp(Rd(RidName(issuer), singles: new[] { Sr(id: CertId(cert, issuer), st: st) }), issuer.Key);
    static string Chk(List<AttCert> chain, params byte[][] responses) => NvidiaOcsp.CheckChain(chain, responses.ToList(), Now);

    [Fact]
    public void TheChainGuards()
    {
        Assert.Equal("chain too short for OCSP", Chk(C(), For(Leaf, Ica)));
        Assert.Equal("chain too short for OCSP", Chk(C(Leaf), For(Leaf, Ica)));
        Assert.Equal("no OCSP responses supplied", Chk(C(Leaf, Ica)));
        Assert.Equal("", Chk(C(Leaf, Ica), For(Leaf, Ica)));
        Assert.Equal("", Chk(C(Leaf, Ica, Root), For(Leaf, Ica)));
    }

    [Fact]
    public void ACertificateThatAdvertisesOcspMustHaveAGoodResponse()
    {
        var chain = C(ALeaf, AIca, ARoot);
        var unknown = T(0x82);
        Assert.Equal("", Chk(chain, For(ALeaf, AIca), For(AIca, ARoot)));
        Assert.Equal("no GOOD OCSP response for required certificate 'CN=aica' (status: absent)", Chk(chain, For(ALeaf, AIca)));
        Assert.Equal("no GOOD OCSP response for required certificate 'CN=aleaf' (status: absent)", Chk(chain, For(AIca, ARoot)));
        Assert.Equal("no GOOD OCSP response for required certificate 'CN=aleaf' (status: unknown)", Chk(chain, For(ALeaf, AIca, unknown), For(AIca, ARoot)));
        // without an advertised responder an unknown or absent status is tolerated
        Assert.Equal("", Chk(C(Leaf, Ica, Root), For(Leaf, Ica, unknown)));
        Assert.Equal("", Chk(C(Leaf, Ica, Root), For(Ica, Root)));
        Assert.Equal("", Chk(C(Leaf, Ica, Root), For(Leaf, Ica), For(Ica, Root)));
    }

    [Fact]
    public void ARevokedDuplicateOrUnmatchedResponseFailsTheChain()
    {
        var chain = C(Leaf, Ica, Root);
        var at = Gt(Now - Hour);
        Assert.Equal("chain certificate 'CN=leaf' is revoked (OCSP)", Chk(chain, For(Leaf, Ica, T(0xa1, at))));
        Assert.Equal("chain certificate 'CN=ica' is revoked (OCSP)", Chk(chain, For(Leaf, Ica), For(Ica, Root, T(0xa1, at))));
        Assert.Equal("duplicate OCSP responses for chain certificate #0", Chk(chain, For(Leaf, Ica), For(Leaf, Ica)));
        Assert.Equal("duplicate OCSP responses for chain certificate #1", Chk(chain, For(Ica, Root), For(Ica, Root)));
        var nobody = For(Stranger, Stranger);
        Assert.Equal("OCSP response #0 rejected: " + NoMatch, Chk(chain, nobody));
        Assert.Equal("OCSP response #1 rejected: " + NoMatch, Chk(chain, For(Leaf, Ica), nobody));
    }

    [Fact]
    public void ADefectiveResponseFailsClosedNamingTheCertificate()
    {
        var chain = C(Leaf, Ica, Root);
        var forged = Resp(Rd(RidName(Ica)), Stranger.Key);
        Assert.Equal("OCSP response #0 for 'CN=leaf' rejected: " + IssuerSig, Chk(chain, forged));
        Assert.Equal("OCSP response #1 for 'CN=leaf' rejected: " + IssuerSig, Chk(chain, For(Ica, Root), forged));
        Assert.Equal("OCSP response #0 for 'CN=leaf' rejected: trailing bytes after OCSPResponse", Chk(chain, For(Leaf, Ica).Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void OneResponseMayNotVouchForTwoCertificates()
    {
        var shared = Responder(Root, "shared");
        var both = Resp(Rd(RidKey(shared), singles: new[] { Sr(id: CertId(Leaf, Ica)), Sr(id: CertId(Ica, Root)) }), shared.Key, Certs(shared));
        Assert.Equal("OCSP response #0 matches more than one chain certificate", Chk(C(Leaf, Ica, Root), both));
    }

    [Fact]
    public void ANextUpdateTimeThatDoesNotParseIsMalformed()
    {
        // VerifyResponse refuses this earlier (the well-formed-times walk), so the fail-closed throw is driven directly
        var w = T(0xa0, GtS("20301301000000Z"));
        Assert.Equal("malformed nextUpdate", Assert.Throws<AttestError>(() => NvidiaOcsp.NextUpdateOf(w, Top(w))).Message);
    }
}
