using System.Diagnostics;
using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>0.5 hardening (track A): the RSA public-key rule, the OID size caps, the lenient JSON size cap and the RSA-PSS key parameter restrictions.</summary>
public class K05HATests
{
    // ---------------------------------------------------------------- H1: RSA public-key rule

    static byte[] Be(int bits, bool odd = true)
    {
        var b = new byte[(bits + 7) / 8];
        Array.Fill(b, (byte)0x5a);
        int top = bits % 8 == 0 ? 8 : bits % 8;
        b[0] = (byte)(1 << (top - 1)); // exactly `bits` bits long
        if (b.Length > 1) b[1] = 0xa5;
        b[^1] = (byte)(odd ? (b[^1] | 1) : (b[^1] & 0xfe));
        return b;
    }

    static byte[] BeInt(ulong v)
    {
        var l = new List<byte>();
        while (v != 0) { l.Insert(0, (byte)v); v >>= 8; }
        return l.Count == 0 ? new byte[] { 0 } : l.ToArray();
    }

    static byte[] RsaPublicKey(byte[] n, byte[] e)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteIntegerUnsigned(n);
            w.WriteIntegerUnsigned(e);
        }
        return w.Encode();
    }

    static byte[] Spki(byte[] rsaPublicKey, string oid = "1.2.840.113549.1.1.1", byte[]? prm = null)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(oid);
                if (prm == null) w.WriteNull(); else if (prm.Length > 0) w.WriteEncodedValue(prm); // empty: the parameters are absent
            }
            w.WriteBitString(rsaPublicKey);
        }
        return w.Encode();
    }

    // the rule itself, on arbitrary moduli (a platform RSA stack refuses some synthetic moduli before the rule is asked, so the boundaries are asserted on the rule)
    static bool Usable(int nBits, ulong e, bool oddN = true) => AttestCerts.RsaKeyOk(Be(nBits, oddN), BeInt(e));

    [Fact]
    public void ARealKeyIsUsableAndTheSameModulusWithABadExponentIsNot()
    {
        using var real = RSA.Create(2048);
        var pr = real.ExportParameters(false);
        Assert.NotNull(AttestCerts.KeyOfSpki(Spki(RsaPublicKey(pr.Modulus!, pr.Exponent!))).Rsa);
        foreach (var bad in new ulong[] { 1, 2, 4, 65536, (1UL << 33) + 1 })
            Assert.Null(AttestCerts.KeyOfSpki(Spki(RsaPublicKey(pr.Modulus!, BeInt(bad)))).Rsa);
        Assert.Null(AttestCerts.KeyOfSpki(Spki(RsaPublicKey(Be(511), BeInt(65537)))).Rsa);
        Assert.Null(AttestCerts.KeyOfSpki(Spki(RsaPublicKey(Be(16385), BeInt(65537)))).Rsa);
    }

    [Fact]
    public void TheModulusMustHave512To16384Bits()
    {
        Assert.False(Usable(511, 65537));
        Assert.True(Usable(512, 65537)); // 512 bits is the floor of the rule (the platform may still refuse the key outright)
        Assert.True(Usable(2048, 65537));
        Assert.True(Usable(16384, 65537));
        Assert.False(Usable(16385, 65537));
        Assert.False(Usable(256, 65537));
    }

    [Fact]
    public void TheExponentMustBeOddAtLeastThreeAndAtMost32Bits()
    {
        Assert.False(Usable(2048, 1));
        Assert.False(Usable(2048, 2));
        Assert.True(Usable(2048, 3));
        Assert.False(Usable(2048, 4));
        Assert.True(Usable(2048, 5));
        Assert.False(Usable(2048, 65536));
        Assert.True(Usable(2048, 65537));
        Assert.True(Usable(2048, 2147483647));
        Assert.True(Usable(2048, 2147483649));        // 32 bits, odd
        Assert.False(Usable(2048, 2147483648));       // 32 bits, even
        Assert.False(Usable(2048, 4294967297));       // 33 bits
        Assert.False(Usable(2048, (1UL << 33) + 1));
        Assert.False(Usable(2048, 0));
    }

    [Fact]
    public void AHugeModulusIsRefusedWithoutAnyModularArithmetic()
    {
        var sw = Stopwatch.StartNew();
        var k = AttestCerts.KeyOfSpki(Spki(RsaPublicKey(Be(17000), BeInt(65537))));
        Assert.Null(k.Rsa);
        Assert.Null(k.RsaBc);
        Assert.Equal("rsa", k.Type);
        Assert.True(sw.ElapsedMilliseconds < 1000, $"{sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void AnUnusableKeyNeverVerifiesAndAUsableOneIsUnchanged()
    {
        using var real = RSA.Create(2048);
        var good = AttestCerts.KeyOfSpki(real.ExportSubjectPublicKeyInfo());
        Assert.NotNull(good.Rsa);
        Assert.NotNull(good.RsaBc);
        Assert.Equal("rsa", good.Type);
        // an e = 1 key: an RSA signature equals its encoded message, so any "signature" verifies under raw arithmetic: the key must not exist
        var pss = AttestCerts.KeyOfSpki(Spki(RsaPublicKey(Be(2048), BeInt(1)), "1.2.840.113549.1.1.10", new byte[] { 0x30, 0x00 }));
        Assert.Null(pss.Rsa);
        Assert.Null(pss.RsaBc);
        Assert.Equal("rsa-pss", pss.Type);
    }

    [Fact]
    public void AJwkOutsideTheRuleIsUnsupported()
    {
        const string unsupported = "error:1E08010C:DECODER routines::unsupported";
        static string B64(byte[] b) => Pca.B64u(b);
        using var real = RSA.Create(2048);
        var pr = real.ExportParameters(false);
        Assert.NotNull(AttestJws.JwkRsaKey(B64(pr.Modulus!), B64(pr.Exponent!)).Rsa);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(pr.Modulus!), B64(BeInt(4)))).Message);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(pr.Modulus!), B64(BeInt((1UL << 33) + 1)))).Message);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(Be(256)), B64(BeInt(65537)))).Message);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(Be(17000)), B64(BeInt(65537)))).Message);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(Be(2048)), B64(BeInt(1)))).Message);
        Assert.Equal(unsupported, Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(B64(Be(511)), B64(BeInt(65537)))).Message);
    }

    // ---------------------------------------------------------------- H2: OID content and arc caps

    static string Dotted(byte[] content)
    {
        var m = typeof(AttestDer).GetMethod("OidToDotted", BindingFlags.NonPublic | BindingFlags.Static)!;
        try { return (string)m.Invoke(null, new object[] { content, new DerTlv(0x06, 0, content.Length) })!; }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }

    static string DottedCert(byte[] content) => AttestCerts.DottedOid(content, new DerTlv(0x06, 0, content.Length));

    static byte[] Arc(int groups, byte last = 0x01)
    {
        var a = new byte[groups];
        Array.Fill(a, (byte)0x81);
        a[^1] = last;
        return a;
    }

    static byte[] Cat(params byte[][] p) => p.SelectMany(x => x).ToArray();

    [Fact]
    public void AnOrdinaryOidDecodes()
    {
        var oid = new byte[] { 0x55, 0x1d, 0x13 };
        Assert.Equal("2.5.29.19", Dotted(oid));
        Assert.Equal("2.5.29.19", DottedCert(oid));
        // 2.25.<UUID>: the arc after 2.25 is a 128-bit number, 19 base-128 groups
        var uuid = Cat(new byte[] { 0x69 }, Arc(19, 0x7f));
        Assert.StartsWith("2.25.", Dotted(uuid));
        Assert.Equal(Dotted(uuid), DottedCert(uuid));
    }

    [Fact]
    public void TheContentIsCappedAt256Bytes()
    {
        // 256 bytes: four arcs of 64 groups each (the arc cap), decodes
        var ok = Cat(Arc(64), Arc(64), Arc(64), Arc(64));
        Assert.Equal(256, ok.Length);
        Assert.NotEmpty(Dotted(ok));
        Assert.NotEmpty(DottedCert(ok));
        var big = Cat(ok, new byte[] { 0x01 });
        Assert.Equal("extension OID is too long", Assert.Throws<AttestError>(() => Dotted(big)).Message);
        Assert.Equal("extension OID is too long", Assert.Throws<AttestError>(() => DottedCert(big)).Message);
    }

    [Fact]
    public void AnArcIsCappedAt64Groups()
    {
        Assert.NotEmpty(Dotted(Arc(64)));
        Assert.NotEmpty(DottedCert(Arc(64)));
        Assert.Equal("extension OID has an oversized arc", Assert.Throws<AttestError>(() => Dotted(Arc(65))).Message);
        Assert.Equal("extension OID has an oversized arc", Assert.Throws<AttestError>(() => DottedCert(Arc(65))).Message);
        // the count restarts at every arc
        Assert.NotEmpty(Dotted(Cat(Arc(64), Arc(64))));
    }

    [Fact]
    public void AHundredKilobyteOidIsRefusedImmediately()
    {
        var huge = new byte[100_000];
        Array.Fill(huge, (byte)0x81);
        huge[^1] = 0x01;
        var sw = Stopwatch.StartNew();
        Assert.Equal("extension OID is too long", Assert.Throws<AttestError>(() => Dotted(huge)).Message);
        Assert.Equal("extension OID is too long", Assert.Throws<AttestError>(() => DottedCert(huge)).Message);
        Assert.True(sw.ElapsedMilliseconds < 500, $"{sw.ElapsedMilliseconds} ms");
    }

    // ---------------------------------------------------------------- H7: the 16 MiB lenient JSON cap

    static string Seg(string json) => Pca.B64u(Encoding.UTF8.GetBytes(json));

    static string Token(byte[] header, byte[] payload) => Pca.B64u(header) + "." + Pca.B64u(payload) + ".c2ln";

    [Fact]
    public void AJwsSegmentOverSixteenMiBIsRefusedBeforeParsing()
    {
        Assert.Equal(16 * 1024 * 1024, AttestJws.MaxAttestJsonBytes);
        // 17 MiB of spaces then {}: valid JSON that would parse, refused by size alone
        var big = new byte[16 * 1024 * 1024 + 1];
        Array.Fill(big, (byte)' ');
        big[^1] = (byte)'}';
        big[0] = (byte)'{';
        var small = Encoding.UTF8.GetBytes("{\"alg\":\"RS256\"}");
        var e = Assert.Throws<AttestError>(() => AttestJws.ParseJwt(Token(small, big), "parseMaaJwt"));
        Assert.Equal("parseMaaJwt: malformed JSON segment: input too large", e.Message);
        var e2 = Assert.Throws<AttestError>(() => AttestJws.ParseJwt(Token(big, small), "parseGcpJwt"));
        Assert.Equal("parseGcpJwt: malformed JSON segment: input too large", e2.Message);
        // both sizes are checked before either segment is parsed: an invalid header does not hide it
        var bad = Encoding.UTF8.GetBytes("not json");
        var e3 = Assert.Throws<AttestError>(() => AttestJws.ParseJwt(Token(bad, big), "parseMaaJwt"));
        Assert.Equal("parseMaaJwt: malformed JSON segment: input too large", e3.Message);
    }

    [Fact]
    public void AJwsSegmentOfExactlySixteenMiBIsStillParsed()
    {
        var exact = new byte[16 * 1024 * 1024];
        Array.Fill(exact, (byte)' ');
        exact[0] = (byte)'{';
        exact[^1] = (byte)'}';
        var hdr = Encoding.UTF8.GetBytes("{\"alg\":\"RS256\"}");
        var p = AttestJws.ParseJwt(Token(hdr, exact), "parseMaaJwt");
        Assert.Equal("RS256", p.Alg);
    }

    // ---------------------------------------------------------------- H8: RSA-PSS issuer key parameter restrictions

    static byte[] HashAlg(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence()) { w.WriteObjectIdentifier(oid); w.WriteNull(); }
        return w.Encode();
    }

    const string Sha256Oid = "2.16.840.1.101.3.4.2.1", Sha384Oid = "2.16.840.1.101.3.4.2.2";

    /// <summary>RSASSA-PSS-params { hashAlgorithm, maskGenAlgorithm MGF1(mgfHash), saltLength }.</summary>
    static byte[] PssParamsDer(string hashOid, string mgfOid, int salt)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true))) w.WriteEncodedValue(HashAlg(hashOid));
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.840.113549.1.1.8");
                w.WriteEncodedValue(HashAlg(mgfOid));
            }
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true))) w.WriteInteger(salt);
        }
        return w.Encode();
    }

    /// <summary>A certificate signed by the key with RSASSA-PSS over <paramref name="hash"/> (salt = digest length).</summary>
    static AttCert PssSigned(RSA issuer, HashAlgorithmName hash)
    {
        using var subject = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=child", subject, hash);
        var der = req.Create(new System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=issuer"),
            System.Security.Cryptography.X509Certificates.X509SignatureGenerator.CreateForRSA(issuer, RSASignaturePadding.Pss),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new byte[] { 0x42 }).RawData;
        return AttestCerts.ParseDer(der);
    }

    static CertKey PssKey(RSA rsa, byte[]? prm) =>
        AttestCerts.KeyOfSpki(Spki(rsa.ExportRSAPublicKey(), "1.2.840.113549.1.1.10", prm));

    [Fact]
    public void ARestrictedPssKeyOnlyVerifiesWhatItsParametersAllow()
    {
        using var rsa = RSA.Create(2048);
        var sha384 = PssSigned(rsa, HashAlgorithmName.SHA384); // salt 48
        var sha256 = PssSigned(rsa, HashAlgorithmName.SHA256); // salt 32
        // restricted to SHA-384 / MGF1-SHA-384 / salt 48 (the AMD ARK and ASK keys)
        var k384 = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 48));
        Assert.NotNull(k384.Rsa);
        Assert.True(AttestCerts.SigOk(sha384, k384));
        Assert.False(AttestCerts.SigOk(sha256, k384));                       // other hash
        // a larger minimum salt than the signature used
        var kSalt64 = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 64));
        Assert.False(AttestCerts.SigOk(sha384, kSalt64));
        // a smaller minimum salt is satisfied (the signature's salt is at least the key's)
        var kSalt20 = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 20));
        Assert.True(AttestCerts.SigOk(sha384, kSalt20));
        var kSalt48 = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 48));
        Assert.True(AttestCerts.SigOk(sha384, kSalt48));
        var kSalt49 = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 49));
        Assert.False(AttestCerts.SigOk(sha384, kSalt49));
        // restricted to SHA-256 / salt 32
        var k256 = PssKey(rsa, PssParamsDer(Sha256Oid, Sha256Oid, 32));
        Assert.True(AttestCerts.SigOk(sha256, k256));
        Assert.False(AttestCerts.SigOk(sha384, k256));
        // a different MGF1 hash than the key's
        var kMgf = PssKey(rsa, PssParamsDer(Sha384Oid, Sha256Oid, 48));
        Assert.False(AttestCerts.SigOk(sha384, kMgf));
    }

    [Fact]
    public void AnUnrestrictedKeyVerifiesAnyProfileThisVerifierChecks()
    {
        using var rsa = RSA.Create(2048);
        var sha384 = PssSigned(rsa, HashAlgorithmName.SHA384);
        var sha256 = PssSigned(rsa, HashAlgorithmName.SHA256);
        // id-RSASSA-PSS with the parameters ABSENT, and a plain rsaEncryption key: no restriction
        var absent = PssKey(rsa, Array.Empty<byte>());
        var plain = AttestCerts.KeyOfSpki(rsa.ExportSubjectPublicKeyInfo());
        foreach (var k in new[] { absent, plain })
        {
            Assert.Null(k.Pss);
            Assert.NotNull(k.Rsa);
            Assert.True(AttestCerts.SigOk(sha384, k));
            Assert.True(AttestCerts.SigOk(sha256, k));
        }
        // present parameters are recorded as written
        var set = PssKey(rsa, PssParamsDer(Sha384Oid, Sha384Oid, 48));
        Assert.Equal(("SHA384", "SHA384", 48), set.Pss);
        // an empty SEQUENCE is all defaults: SHA-1 / MGF1-SHA-1 / salt 20 (a restriction nothing modern satisfies)
        var defaults = PssKey(rsa, new byte[] { 0x30, 0x00 });
        Assert.Equal(("SHA1", "SHA1", 20), defaults.Pss);
        Assert.False(AttestCerts.SigOk(sha256, defaults));
    }

    [Fact]
    public void PssParametersTheVerifierCannotReadMakeTheKeyUnusable()
    {
        using var rsa = RSA.Create(2048);
        var garbage = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 };
        var k = PssKey(rsa, garbage);
        Assert.Null(k.Rsa);
        Assert.Null(k.RsaBc);
        Assert.Equal("rsa-pss", k.Type);
    }
}
