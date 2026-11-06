using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The NVIDIA SPDM parser, device chain and verifier against the reference (packages/pca/src/attest-nvidia-spdm.ts): exact reasons,
/// the boundary of every length check, and the order pinned measurements are checked in.</summary>
public class NvidiaKillTests
{
    const string P = "parseNvidiaSpdmEvidence: ";
    const string NotSelfSigned = "device chain root is not a self-signed CA";

    static readonly long Now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    static readonly ECDsa LeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384), MidKey = ECDsa.Create(ECCurve.NamedCurves.nistP384),
        RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384), Stranger = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    static readonly AttestationBinding Bound = new("holder", "grant", 1, "nonce");

    static byte[] Cert(string cn, ECDsa key, string issuerCn, ECDsa signer, bool? ca = null, X509KeyUsageFlags? ku = null)
    {
        var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA384);
        if (ca is bool b) req.CertificateExtensions.Add(new X509BasicConstraintsExtension(b, false, 0, true));
        if (ku is X509KeyUsageFlags f) req.CertificateExtensions.Add(new X509KeyUsageExtension(f, true));
        return req.Create(new X500DistinguishedName("CN=" + issuerCn), X509SignatureGenerator.CreateForECDsa(signer),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new byte[] { 1 }).RawData;
    }

    static byte[] Leaf() => Cert("leaf", LeafKey, "mid", MidKey, ca: false);
    static byte[] Mid() => Cert("mid", MidKey, "root", RootKey, ca: true, ku: X509KeyUsageFlags.KeyCertSign);
    static byte[] Root() => Cert("root", RootKey, "root", RootKey, ca: true, ku: X509KeyUsageFlags.KeyCertSign);

    static string Pem(params byte[][] ders) => string.Concat(ders.Select(d =>
        "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(d, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n"));
    static string Spki(byte[] der) => AttestCerts.KeyOf(AttestCerts.ParseDer(der)).SpkiSha256();

    /// <summary>A P-384 certificate whose public point is not uncompressed, so its key cannot be read.</summary>
    static byte[] UnreadableKeyCert()
    {
        var der = Cert("leaf", LeafKey, "leaf", LeafKey, ca: false);
        var q = LeafKey.ExportParameters(false).Q;
        var point = new byte[] { 4 }.Concat(q.X!).Concat(q.Y!).ToArray();
        int at = der.AsSpan().IndexOf(point);
        Assert.True(at > 0);
        der[at] = 2;
        return der;
    }

    /// <summary>A transcript with a zero signature: record, responder nonce, opaque data (recLen may lie about the record).</summary>
    static byte[] Spdm(byte[]? record = null, int blocks = 0, byte[]? opaque = null, byte[]? nonce = null, int? recLen = null)
    {
        record ??= Array.Empty<byte>();
        opaque ??= Array.Empty<byte>();
        int n = recLen ?? record.Length;
        var b = new List<byte> { 0x11, 0xe0, 0, 0 };
        b.AddRange(nonce ?? new byte[32]);
        b.Add(0);
        b.AddRange(new byte[] { 0x11, 0x60, 0, 0, (byte)blocks, (byte)n, (byte)(n >> 8), (byte)(n >> 16) });
        b.AddRange(record);
        b.AddRange(new byte[32]);
        b.Add((byte)opaque.Length);
        b.Add((byte)(opaque.Length >> 8));
        b.AddRange(opaque);
        b.AddRange(new byte[96]);
        return b.ToArray();
    }

    /// <summary>One measurement block; size and vsize may lie about the digest.</summary>
    static byte[] Blk(int index, byte[] digest, int? size = null, int? vsize = null)
    {
        int s = size ?? 3 + digest.Length, v = vsize ?? digest.Length;
        return new byte[] { (byte)index, 0, (byte)s, (byte)(s >> 8), 0, (byte)v, (byte)(v >> 8) }.Concat(digest).ToArray();
    }

    static string ParseErr(byte[] b) => Assert.Throws<AttestError>(() => NvidiaVerifier.ParseEvidence(b)).Message;

    static byte[] Sign(byte[] transcript)
    {
        LeafKey.SignHash(AttestUtil.Sha384(transcript[..^96]), DSASignatureFormat.IeeeP1363FixedFieldConcatenation).CopyTo(transcript, transcript.Length - 96);
        return transcript;
    }

    static JD Evidence(byte[]? record = null, int blocks = 0) => new()
    {
        ["evidence"] = Convert.ToBase64String(Sign(Spdm(record, blocks, nonce: AttestUtil.Sha256(AttestUtil.BindingBytes(Bound))))),
        ["certChainPem"] = Pem(Leaf(), Mid(), Root()),
    };

    static NvidiaVerifier Verifier(JD measurements, object? leafSubject = null)
    {
        var policy = new JD { ["measurements"] = measurements };
        if (leafSubject != null) policy["leafSubjectIncludes"] = leafSubject;
        return NvidiaVerifier.Create(new JD { ["rootSpkiSha256"] = new JL { Spki(Root()) }, ["policy"] = policy });
    }

    // ---- ParseEvidence

    [Fact]
    public void TranscriptFloorIs175Bytes()
    {
        Assert.Equal(P + "transcript too short (174)", ParseErr(new byte[174]));
        Assert.Equal(P + "request code 0x0 is not GET_MEASUREMENTS", ParseErr(new byte[175]));
    }

    [Fact]
    public void RecordLengthHasAThirdByte()
    {
        Assert.Equal(P + "measurement record length overruns transcript", ParseErr(Spdm(recLen: 0x10000)));
        var rep = NvidiaVerifier.ParseEvidence(Spdm(Blk(1, new byte[65529]), blocks: 1));
        Assert.Equal(65529, Assert.Single(rep.Measurements).Digest.Length);
    }

    [Fact]
    public void RecordOneByteTooLongIsRefusedUpFront() =>
        Assert.Equal(P + "measurement record length overruns transcript", ParseErr(Spdm(recLen: 1)));

    [Fact]
    public void BlockHeaderMustFitTheRecord() =>
        Assert.Equal(P + "truncated measurement block header", ParseErr(Spdm(new byte[3])));

    [Fact]
    public void BlockNeedsThreeBytes()
    {
        Assert.Equal(P + "measurement block overruns record", ParseErr(Spdm(new byte[] { 1, 0, 2, 0, 0, 0 }, blocks: 1)));
        var rep = NvidiaVerifier.ParseEvidence(Spdm(Blk(1, Array.Empty<byte>()), blocks: 1));
        var (index, digest) = Assert.Single(rep.Measurements);
        Assert.Equal(1, index);
        Assert.Empty(digest);
    }

    [Fact]
    public void DmtfValueMustFitItsBlock()
    {
        Assert.Equal(P + "DMTF value overruns measurement block", ParseErr(Spdm(Blk(1, Array.Empty<byte>(), size: 3, vsize: 1), blocks: 1)));
        Assert.Equal(new byte[] { 7 }, Assert.Single(NvidiaVerifier.ParseEvidence(Spdm(Blk(1, new byte[] { 7 }), blocks: 1)).Measurements).Digest);
        // slack after the value is not an overrun
        Assert.Equal(new byte[] { 7 }, Assert.Single(NvidiaVerifier.ParseEvidence(Spdm(Blk(1, new byte[] { 7, 8 }, size: 5, vsize: 1), blocks: 1)).Measurements).Digest);
    }

    [Fact]
    public void OpaqueTlvBoundaries()
    {
        Assert.Empty(NvidiaVerifier.ParseEvidence(Spdm(opaque: new byte[] { 3, 0, 0, 0 })).Opaque[3]);
        Assert.Equal(new byte[] { 0xaa }, NvidiaVerifier.ParseEvidence(Spdm(opaque: new byte[] { 1, 0, 1, 0, 0xaa })).Opaque[1]);
        Assert.Equal(P + "truncated opaque TLV header", ParseErr(Spdm(opaque: new byte[] { 3, 0, 0 })));
        Assert.Equal(P + "opaque TLV overruns opaque data", ParseErr(Spdm(opaque: new byte[] { 1, 0, 1, 0 })));
    }

    // ---- FormatVbiosVersion (values worked from formatVbiosVersion in the reference)

    [Theory]
    [InlineData("", "")]
    [InlineData("ab", "b")]
    [InlineData("0102", "01.02")]
    [InlineData("010203", "20.13.0")]
    public void VbiosVersionOfShortInputs(string rawHex, string want) =>
        Assert.Equal(want, NvidiaVerifier.FormatVbiosVersion(Convert.FromHexString(rawHex)));

    // ---- CertIsCa

    [Fact]
    public void CertIsCaFollowsBasicConstraintsAndKeyUsage()
    {
        bool Is(bool? ca, X509KeyUsageFlags? ku) => NvidiaVerifier.CertIsCa(AttestCerts.ParseDer(Cert("x", RootKey, "x", RootKey, ca, ku)));
        Assert.True(Is(true, null));
        Assert.True(Is(true, X509KeyUsageFlags.KeyCertSign));
        Assert.False(Is(true, X509KeyUsageFlags.DigitalSignature));
        Assert.False(Is(false, null));
        Assert.False(Is(null, X509KeyUsageFlags.KeyCertSign));
    }

    [Fact]
    public void CertIsCaIsFalseOnUnreadableDer() =>
        Assert.False(NvidiaVerifier.CertIsCa(new AttCert { Raw = new byte[] { 0x30 } }));

    // ---- CheckIssued: every row was observed on the reference's X509Certificate.checkIssued (attest-nvidia-ocsp.ts), except those marked strict

    static readonly byte[] KeyId = Enumerable.Repeat((byte)1, 20).ToArray();

    static byte[] Der(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(p => p).ToArray();
        Assert.True(body.Length < 0x80);
        return new[] { tag, (byte)body.Length }.Concat(body).ToArray();
    }

    static LenientExt Akid(params byte[][] parts) => new("2.5.29.35", false, Der(0x30, parts));
    static LenientExt Skid(byte[] value) => new("2.5.29.14", false, value);
    static LenientExt GoodSkid() => Skid(Der(0x04, KeyId));

    /// <summary>The CA "mid", issued by "root", serial 01, keyCertSign, with these extensions.</summary>
    static AttCert Ca(params LenientExt[] exts)
    {
        var ca = AttestCerts.ParseDer(Mid());
        ca.Exts = exts.ToList();
        return ca;
    }

    static bool Issued(AttCert ca, params LenientExt[] exts) =>
        NvidiaVerifier.CheckIssued(new AttCert { RawIssuer = ca.RawSubject, Exts = exts.ToList() }, ca);

    static byte[] Names(params byte[][] generalNames) => Der(0xa1, generalNames);
    static byte[] Dn(byte[] name) => Der(0xa4, name);

    [Fact]
    public void AnEmptyAkidComparesNothing()
    {
        Assert.True(Issued(Ca(GoodSkid()), Akid()));
        Assert.True(Issued(Ca(), Akid()));
    }

    [Fact]
    public void BytesAfterTheKeyIdentifierAreIgnored()
    {
        Assert.True(Issued(Ca(GoodSkid()), new LenientExt("2.5.29.35", false, Der(0x30).Concat(new byte[] { 5, 0 }).ToArray())));
        Assert.True(Issued(Ca(Skid(Der(0x04, KeyId).Concat(new byte[] { 5, 0 }).ToArray())), Akid(Der(0x80, KeyId))));
    }

    [Fact]
    public void AnAkidWithoutAKeyIdDoesNotCompareItsFirstChildToTheSkid()
    {
        var ca = Ca(GoodSkid());
        Assert.True(Issued(ca, Akid(Der(0x82, ca.Serial))));
        Assert.True(Issued(ca, Akid(Names(Dn(ca.RawIssuer)))));
        Assert.True(Issued(ca, Akid(Names())));
        Assert.True(Issued(ca, Akid(Names(Der(0x82, new byte[] { 0x78 })))));
    }

    [Fact]
    public void KeyIdIsComparedOnlyAgainstAnIssuerSkid()
    {
        var other = Enumerable.Repeat((byte)2, 20).ToArray();
        Assert.True(Issued(Ca(GoodSkid()), Akid(Der(0x80, KeyId))));
        Assert.False(Issued(Ca(GoodSkid()), Akid(Der(0x80, other))));
        Assert.False(Issued(Ca(GoodSkid()), Akid(Der(0x80))));
        Assert.True(Issued(Ca(), Akid(Der(0x80, other))));
    }

    [Fact]
    public void SerialMustBeTheIssuers()
    {
        var bad = Der(0x82, new byte[] { 2 });
        Assert.False(Issued(Ca(GoodSkid()), Akid(bad)));
        Assert.False(Issued(Ca(), Akid(bad)));
        Assert.False(Issued(Ca(GoodSkid()), Akid(Der(0x80, KeyId), bad)));
        Assert.False(Issued(Ca(GoodSkid()), Akid(Der(0x82))));
    }

    [Fact]
    public void DirectoryNameMustBeTheIssuersIssuer()
    {
        var ca = Ca(GoodSkid());
        var subject = Names(Dn(ca.RawSubject));
        Assert.False(Issued(ca, Akid(subject)));
        Assert.False(Issued(Ca(), Akid(subject)));
        Assert.False(Issued(ca, Akid(Der(0x80, KeyId), subject)));
        Assert.False(Issued(ca, Akid(subject, Der(0x82, ca.Serial))));
        Assert.True(Issued(ca, Akid(Der(0x80, KeyId), Names(Dn(ca.RawIssuer)), Der(0x82, ca.Serial))));
    }

    [Fact]
    public void OnlyTheFirstDirectoryNameCounts()
    {
        var ca = Ca(GoodSkid());
        var dns = Der(0x82, new byte[] { 0x78 });
        Assert.True(Issued(ca, Akid(Names(Dn(ca.RawIssuer), Dn(ca.RawSubject)))));
        Assert.False(Issued(ca, Akid(Names(Dn(ca.RawSubject), Dn(ca.RawIssuer)))));
        Assert.True(Issued(ca, Akid(Names(dns, Dn(ca.RawIssuer)))));
        Assert.False(Issued(ca, Akid(Names(dns, Dn(ca.RawSubject)))));
    }

    [Theory]
    [InlineData(0x81)]
    [InlineData(0x82)]
    [InlineData(0x86)]
    [InlineData(0x87)]
    public void StringGeneralNamesAreSkipped(int tag) =>
        Assert.True(Issued(Ca(GoodSkid()), Akid(Names(Der((byte)tag, new byte[] { 0x78 })))));

    [Theory]
    [InlineData(0x04)] // not a GeneralName
    [InlineData(0x89)] // not a GeneralName
    [InlineData(0x84)] // a directoryName must be constructed
    public void OtherGeneralNamesAreRefused(int tag) =>
        Assert.False(Issued(Ca(GoodSkid()), Akid(Names(Der((byte)tag, new byte[] { 0x2a })))));

    [Fact]
    public void ARegisteredIdAndAnOtherNameAreRead()
    {
        Assert.True(Issued(Ca(GoodSkid()), Akid(Names(Der(0x88, new byte[] { 0x2a })))));
        Assert.True(Issued(Ca(GoodSkid()), Akid(Names(Der(0xa0, Der(0x06, new byte[] { 0x2a }), Der(0xa0, Der(0x0c)))))));
        Assert.False(Issued(Ca(GoodSkid()), Akid(Names(Der(0xa0, Der(0x06, new byte[] { 0x2a }))))));
    }

    [Fact]
    public void AMalformedDirectoryNameIsRefusedEvenWhenItIsNotTheFirst()
    {
        var ca = Ca(GoodSkid());
        var first = Dn(ca.RawIssuer);
        Assert.False(Issued(ca, Akid(Names(first, Dn(Der(0x04, new byte[] { 1 }))))));
        Assert.False(Issued(ca, Akid(Names(first, Der(0xa4)))));
        Assert.False(Issued(ca, Akid(Names(first, Der(0xa4, ca.RawIssuer, Der(0x05))))));
        Assert.False(Issued(ca, Akid(Names(first, Dn(Der(0x30, Der(0x04, new byte[] { 1 })))))));
        Assert.False(Issued(ca, Akid(Names(Dn(Der(0x30))))));
    }

    [Fact]
    public void AkidChildrenAreKnownOnceAndInOrder()
    {
        var ca = Ca(GoodSkid());
        byte[] id = Der(0x80, KeyId), names = Names(Dn(ca.RawIssuer)), serial = Der(0x82, ca.Serial);
        Assert.False(Issued(ca, Akid(serial, id)));
        Assert.False(Issued(ca, Akid(names, id)));
        Assert.False(Issued(ca, Akid(serial, names)));
        Assert.False(Issued(ca, Akid(id, id)));
        Assert.False(Issued(ca, Akid(names, names)));
        Assert.False(Issued(ca, Akid(serial, serial)));
        Assert.False(Issued(ca, Akid(Der(0x83, new byte[] { 1 }))));
        Assert.False(Issued(ca, Akid(id, Der(0x83, new byte[] { 1 }))));
        Assert.False(Issued(ca, Akid(serial, Der(0x05))));
        Assert.False(Issued(ca, Akid(Der(0x04, KeyId))));
        Assert.False(Issued(ca, Akid(Der(0x81, new byte[] { 1 }))));
        Assert.False(Issued(ca, Akid(Der(0xa2, Der(0x02, ca.Serial)))));
        // strict: the reference reads a constructed key id
        Assert.False(Issued(ca, Akid(Der(0xa0, id))));
    }

    [Fact]
    public void AMalformedKeyIdentifierOnEitherCertificateRefusesEvenWithNothingToCompare()
    {
        var badSkid = Skid(Der(0x30));
        var badAkid = Akid(Der(0x83, new byte[] { 1 }));
        Assert.False(Issued(Ca(badSkid)));
        Assert.False(Issued(Ca(GoodSkid()), badSkid));
        Assert.False(Issued(Ca(GoodSkid(), badAkid)));
        Assert.False(Issued(Ca(GoodSkid(), new LenientExt("2.5.29.35", false, Der(0x04, new byte[] { 0 })))));
        // a certificate's own well-formed subject key identifier is not compared with anything
        Assert.True(Issued(Ca(GoodSkid()), Skid(Der(0x04, new byte[] { 2 }))));
    }

    [Fact]
    public void ARepeatedKeyIdentifierRefuses()
    {
        var id = Akid(Der(0x80, KeyId));
        Assert.False(Issued(Ca(GoodSkid()), id, id));
        Assert.False(Issued(Ca(GoodSkid(), GoodSkid())));
        Assert.False(Issued(Ca(GoodSkid(), id, id)));
        Assert.False(Issued(Ca(GoodSkid()), GoodSkid(), GoodSkid()));
    }

    // ---- VerifyDeviceChain

    const string Garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    static string ChainWhy(string pem, params string[] pins)
    {
        var (chain, why) = NvidiaVerifier.VerifyDeviceChain(pem, pins, Now);
        Assert.Null(chain);
        return why;
    }

    [Fact]
    public void ChainLengthAndParseFailures()
    {
        string Repeat(int n) => string.Concat(Enumerable.Repeat(Garbage, n));
        var parse = "device chain unparseable: " + Assert.Throws<AttestError>(() => AttestCerts.FromPem(Garbage)).Message;
        Assert.Equal(parse, ChainWhy(Garbage));
        Assert.Equal(parse, ChainWhy(Repeat(5)));
        Assert.Equal("device chain unparseable: parsePemChain: chain longer than 5", ChainWhy(Repeat(6)));
    }

    [Fact]
    public void AnUnreadableKeyIsNotP384()
    {
        var der = UnreadableKeyCert();
        Assert.Equal("device chain cert #0 is not an ECDSA P-384 key", ChainWhy(Pem(der), Spki(Root())));
    }

    [Fact]
    public void RootMustBeBothACaAndSelfSigned()
    {
        // a CA issued by someone else, its own SPKI pinned
        var crossSigned = Cert("mid", MidKey, "stranger", Stranger, ca: true, ku: X509KeyUsageFlags.KeyCertSign);
        Assert.Equal(NotSelfSigned, ChainWhy(Pem(Leaf(), crossSigned), Spki(crossSigned)));
        // self-signed, its own SPKI pinned, but not a CA
        var notCa = Cert("leaf", LeafKey, "leaf", LeafKey, ca: false);
        Assert.Equal(NotSelfSigned, ChainWhy(Pem(notCa), Spki(notCa)));
    }

    [Fact]
    public void AnyPinMatchesAndNoPinsRefuse()
    {
        var pem = Pem(Leaf(), Mid(), Root());
        var pin = Spki(Root());
        foreach (var pins in new[] { new[] { "aa", pin }, new[] { pin, "aa" }, new[] { pin.ToUpperInvariant() } })
        {
            var (chain, why) = NvidiaVerifier.VerifyDeviceChain(pem, pins, Now);
            Assert.Equal("", why);
            Assert.Equal(3, chain!.Count);
        }
        Assert.Equal("chain root is not a pinned NVIDIA root", ChainWhy(pem));
        Assert.Equal("chain root is not a pinned NVIDIA root", ChainWhy(pem, "aa"));
    }

    // ---- Create: measurement keys

    static string? KeyProblem(string key)
    {
        try { NvidiaVerifier.Create(new JD { ["rootSpkiSha256"] = new JL { "aa" }, ["policy"] = new JD { ["measurements"] = new JD { [key] = "aa" } } }); return null; }
        catch (ArgumentException e) { return e.Message; }
    }

    [Theory]
    [InlineData("0")]
    [InlineData("255")]
    [InlineData("0x10")]
    [InlineData("-0")]
    [InlineData("")]
    public void MeasurementKeysAccepted(string key) => Assert.Null(KeyProblem(key));

    [Theory]
    [InlineData("abc")]
    [InlineData("1.5")]
    [InlineData("-1")]
    [InlineData("256")]
    public void MeasurementKeysRefused(string key) => Assert.Equal("createNvidiaSpdmVerifier: measurement index out of range", KeyProblem(key));

    /// <summary>Object.entries order decides which reason comes first: array-index keys ascending, then the other keys in insertion order.</summary>
    [Theory]
    [InlineData(9, "10", "9")]
    [InlineData(0, "5", "0")]
    [InlineData(5, "0x01", "5")]
    [InlineData(255, "0x01", "255")]
    [InlineData(2, "0x02", "0x01")]
    [InlineData(1, "0x01", "0x02")]
    public void MeasurementsAreCheckedInObjectEntriesOrder(int first, string keyA, string keyB)
    {
        var r = Verifier(new JD { [keyA] = "aa", [keyB] = "aa" }).Verify(Evidence(), Bound, Now);
        Assert.Equal($"measurement block {first} missing from report", r.Reason);
    }

    // ---- Verify

    [Fact]
    public void EvidenceAndChainAreBothRequired()
    {
        var v = Verifier(new JD { ["1"] = "aa" });
        const string none = "no NVIDIA GPU evidence for this action";
        Assert.Equal(none, v.Verify(null, Bound, Now).Reason);
        Assert.Equal(none, v.Verify(new JD { ["certChainPem"] = "x" }, Bound, Now).Reason);
        Assert.Equal(none, v.Verify(new JD { ["evidence"] = "AAAA" }, Bound, Now).Reason);
    }

    [Fact]
    public void LeafSubjectPolicy()
    {
        var digest = new byte[48];
        var meas = new JD { ["1"] = AttestUtil.Hex(digest) };
        var ev = Evidence(Blk(1, digest), 1);
        Assert.True(Verifier(meas).Verify(ev, Bound, Now).Ok);
        Assert.True(Verifier(meas, "").Verify(ev, Bound, Now).Ok);
        Assert.True(Verifier(meas, "leaf").Verify(ev, Bound, Now).Ok);
        Assert.Equal("device leaf subject does not contain 'GH100'", Verifier(meas, "GH100").Verify(ev, Bound, Now).Reason);
        // the reference coerces a non-string through String.prototype.includes: it never switches the check off
        Assert.Equal("device leaf subject does not contain '5'", Verifier(meas, 5d).Verify(ev, Bound, Now).Reason);
    }

    [Fact]
    public void ABindingIsRequiredAfterTheSignature() =>
        Assert.Equal("no expected attestation binding supplied", Verifier(new JD { ["1"] = "aa" }).Verify(Evidence(), null, Now).Reason);

    [Fact]
    public void LeafSignatureFailsClosedWithoutAnEcKey()
    {
        var signed = new byte[] { 1, 2, 3 };
        var sig = LeafKey.SignHash(AttestUtil.Sha384(signed), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var rep = new SpdmReport { SignedBytes = signed, Signature = sig };
        Assert.True(NvidiaVerifier.LeafSigOk(AttestCerts.ParseDer(Leaf()), rep));
        Assert.False(NvidiaVerifier.LeafSigOk(AttestCerts.ParseDer(Mid()), rep));
        Assert.False(NvidiaVerifier.LeafSigOk(AttestCerts.ParseDer(UnreadableKeyCert()), rep));
        // an Ed25519 SubjectPublicKeyInfo: the key reads, but it is not EC
        var ed = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }.Concat(new byte[32]).ToArray();
        Assert.False(NvidiaVerifier.LeafSigOk(new AttCert { RawSpki = ed }, rep));
    }
}
