using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact outcomes of the AMD SEV-SNP, Intel DCAP, Google Confidential Space and Azure MAA verifiers over synthetic chains, reports,
/// quotes and tokens. Every limit and message is the reference's: hardware-sevsnp.ts, attest-amd-snp.ts, attest-intel-tdx.ts, attest-intel-dcap.ts,
/// attest-gcp-confidential-space.ts, attest-azure-maa.ts.</summary>
public class AttestVendorsKillTests
{
    // ---- a clock and keys (field order matters: these are used by the initializers below)

    static readonly DateTimeOffset From = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), To = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly long Now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
    static readonly long NowSec = Now / 1000, ToMs = To.ToUnixTimeMilliseconds();
    static AttestationBinding Bind => new("h", "g", 1, "n");
    static byte[] BindBytes => AttestUtil.BindingBytes(Bind);

    static ECDsa P384() => ECDsa.Create(ECCurve.NamedCurves.nistP384);
    static ECDsa P256() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    static readonly ECDsa ArkKey = P384(), AskKey = P384(), VcekKey = P384(), RootKey = P384(), OtherKey = P384(), LeafKey = P256(), PckKey = P256(), AkKey = P256();

    static byte[] Sign(CertificateRequest r, string issuer, ECDsa issuerKey) =>
        r.Create(new X500DistinguishedName(issuer), X509SignatureGenerator.CreateForECDsa(issuerKey), From, To, new byte[] { 1 }).RawData;

    static byte[] Ca(string cn, string issuer, ECDsa key, ECDsa issuerKey)
    {
        var r = new CertificateRequest(cn, key, HashAlgorithmName.SHA384);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return Sign(r, issuer, issuerKey);
    }

    static byte[] EndEntity(string cn, ECDsa key, string issuer, ECDsa issuerKey, params X509Extension[] exts)
    {
        var r = new CertificateRequest(cn, key, HashAlgorithmName.SHA384);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        foreach (var e in exts) r.CertificateExtensions.Add(e);
        return Sign(r, issuer, issuerKey);
    }

    static string Pem(byte[] der) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    static string SpkiOf(byte[] der) => AttestCerts.KeyOf(AttestCerts.ParseDer(der)).SpkiSha256();
    static string Spki(ECDsa k) => AttestUtil.Hex(SHA256.HashData(k.ExportSubjectPublicKeyInfo()));
    static byte[] Cat(params byte[][] p) => p.SelectMany(x => x).ToArray();
    static JL X5c(params byte[][] ders) => ders.Select(d => (object?)Convert.ToBase64String(d)).ToList();
    static List<string> Strs(params byte[][] ders) => ders.Select(Convert.ToBase64String).ToList();

    static readonly byte[] RootDer = Ca("CN=root", "CN=root", RootKey, RootKey), OtherDer = Ca("CN=other", "CN=other", OtherKey, OtherKey);
    static readonly byte[] LeafDer = EndEntity("CN=leaf", LeafKey, "CN=root", RootKey);

    /// <summary>An ECDSA key whose verification answers as told (null: throws), to reach the guards around the primitive.</summary>
    sealed class StubEc : ECDsa
    {
        readonly bool? answer;
        public StubEc(bool? answer) { this.answer = answer; }
        public override byte[] SignHash(byte[] hash) => throw new NotSupportedException();
        public override bool VerifyHash(byte[] hash, byte[] signature) => answer ?? throw new InvalidOperationException("stub");
    }

    // ---- AMD: fixtures

    static readonly byte[] Chip = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
    const ulong Tcb = 1UL | (2UL << 8) | (3UL << 48) | (4UL << 56);
    const string OHw = "1.3.6.1.4.1.3704.1.4", OBl = "1.3.6.1.4.1.3704.1.3.1", OTee = "1.3.6.1.4.1.3704.1.3.2", OSnp = "1.3.6.1.4.1.3704.1.3.3", OUc = "1.3.6.1.4.1.3704.1.3.8";

    static byte[] Spl(int v) => new byte[] { 0x02, 0x01, (byte)v };
    static (string Oid, bool Crit, byte[] Val)[] GoodExts() => new[] { (OHw, false, Chip), (OBl, false, Spl(1)), (OTee, false, Spl(2)), (OSnp, false, Spl(3)), (OUc, false, Spl(4)) };

    static readonly byte[] ArkDer = Ca("CN=ark", "CN=ark", ArkKey, ArkKey), AskDer = Ca("CN=ask", "CN=ark", AskKey, ArkKey);
    static readonly string AskArk = Pem(AskDer) + Pem(ArkDer);
    static string ArkPin => AttestCerts.KeyOf(AttestCerts.ParseDer(ArkDer)).SpkiSha384();

    static byte[] Vcek(CertificateRequest r)
    {
        foreach (var (oid, crit, val) in GoodExts()) r.CertificateExtensions.Add(new X509Extension(new Oid(oid), val, crit));
        return Sign(r, "CN=ask", AskKey);
    }

    static readonly byte[] VcekDer = Vcek(new CertificateRequest("CN=vcek", VcekKey, HashAlgorithmName.SHA384));

    static byte[] SnpReportBytes()
    {
        var b = new byte[AttestAmd.ReportLen];
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(AttestAmd.OffSigAlgo), AttestAmd.SigAlgoEcdsaP384);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(AttestAmd.OffReportedTcb), Tcb);
        Array.Fill(b, (byte)0xaa, AttestAmd.OffMeasurement, 48);
        BindBytes.CopyTo(b, AttestAmd.OffReportData);
        Chip.CopyTo(b, AttestAmd.OffChipId);
        var sig = VcekKey.SignHash(SHA384.HashData(b[..AttestAmd.OffSignedEnd]), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var r = sig[..48]; var s = sig[48..];
        Array.Reverse(r); Array.Reverse(s);
        r.CopyTo(b, AttestAmd.OffSigR); s.CopyTo(b, AttestAmd.OffSigS);
        return b;
    }

    static JD AmdCfg() => new()
    {
        ["family"] = "milan", ["binding"] = "report-data",
        ["policy"] = new JD { ["measurements"] = new JL { string.Concat(Enumerable.Repeat("aa", 48)) } },
    };

    static AmdVerifier AmdV()
    {
        AttestAmd.HarnessArkPin.Value = ArkPin;
        try { return AmdVerifier.Create(AmdCfg()); }
        finally { AttestAmd.HarnessArkPin.Value = null; }
    }

    /// <summary>The DER with its validity text replaced in place and the body signed again.</summary>
    static byte[] PatchTime(byte[] der, ECDsa issuerKey, string from, string to)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        var tbs = outer.ReadEncodedValue().ToArray();
        var alg = outer.ReadEncodedValue().ToArray();
        var at = tbs.AsSpan().IndexOf(Encoding.ASCII.GetBytes(from));
        Assert.True(at > 0);
        Encoding.ASCII.GetBytes(to).CopyTo(tbs, at);
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteEncodedValue(tbs);
            w.WriteEncodedValue(alg);
            w.WriteBitString(issuerKey.SignData(tbs, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence));
        }
        return w.Encode();
    }

    /// <summary>A tbsCertificate holding only an extensions block.</summary>
    static byte[] Tbs(params (string Oid, bool Crit, byte[] Val)[] exts)
    {
        var seq = new AsnWriter(AsnEncodingRules.DER);
        using (seq.PushSequence())
            foreach (var (oid, crit, val) in exts)
                using (seq.PushSequence())
                {
                    seq.WriteObjectIdentifier(oid);
                    if (crit) seq.WriteBoolean(true);
                    seq.WriteOctetString(val);
                }
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3)))
            w.WriteEncodedValue(seq.Encode());
        return w.Encode();
    }

    // ---- AMD: the policy

    [Fact]
    public void SnpPolicyFloorsVmplAndAllowlistGate()
    {
        var at5 = new SnpReport { CommittedTcb = 5 };
        var floor = new SnpPolicy { MinCommittedTcb = (BigInteger)5 };
        Assert.Null(floor.Check(at5));
        Assert.Equal("committed_tcb below minimum (rollback?)", floor.Check(new SnpReport { CommittedTcb = 4 }));

        Assert.Equal("vmpl 0 is not the required 2", new SnpPolicy { RequireVmpl = "2" }.Check(new SnpReport()));
        Assert.Null(new SnpPolicy { RequireVmpl = "any" }.Check(new SnpReport { Vmpl = 3 }));
        // String(requireVmpl) of a value that is no number
        Assert.Equal("vmpl 0 is not the required true", new SnpPolicy { RequireVmpl = true }.Check(new SnpReport()));
        Assert.Equal("vmpl 0 is not the required 1,2", new SnpPolicy { RequireVmpl = new JL { new Num("1"), new Num("2") } }.Check(new SnpReport()));
        Assert.Equal("vmpl 0 is not the required [object Object]", new SnpPolicy { RequireVmpl = new JD() }.Check(new SnpReport()));

        // an empty measurement list is no gate at this level; a set one is
        Assert.Null(new SnpPolicy().Check(new SnpReport()));
        Assert.Equal("measurement not in policy allowlist", new SnpPolicy { Measurements = new List<string> { "aa" } }.Check(new SnpReport()));
    }

    [Fact]
    public void AmdVerifierWithoutABindingIsRefused()
    {
        var ev = new JD { ["report"] = "AA", ["vcekDer"] = "AA", ["askArkPem"] = "x" };
        Assert.Equal("no expected attestation binding supplied", AmdV().Verify(ev, null, Now).Reason);
    }

    [Fact]
    public void AGenuineReportVerifiesEndToEnd()
    {
        var v = AmdV();
        var raw = SnpReportBytes();
        var (why, rep) = v.VerifyReport(raw, VcekDer, AskArk, Now, Bind);
        Assert.Equal("", why);
        Assert.NotNull(rep);
        var ev = new JD { ["report"] = Convert.ToBase64String(raw), ["vcekDer"] = Convert.ToBase64String(VcekDer), ["askArkPem"] = AskArk };
        var r = v.Verify(ev, Bind, Now);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("milan", r.HostAsserted!["family"]);
    }

    [Fact]
    public void EachPartOfTheChainAnswerIsChecked()
    {
        var k = new CertKey();
        var t = new byte[1];
        Assert.False(AmdVerifier.ChainRefused("", k, t));
        Assert.True(AmdVerifier.ChainRefused("x", k, t));
        Assert.True(AmdVerifier.ChainRefused("", null, t));
        Assert.True(AmdVerifier.ChainRefused("", k, null));
    }

    // ---- AMD: the report signature

    static readonly BigInteger P384Order = BigInteger.Parse("0ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    static byte[] Le(BigInteger v)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Resize(ref b, 72);
        return b;
    }

    static SnpReport Sig(BigInteger r, BigInteger s) => new() { SigR = Le(r), SigS = Le(s) };

    [Fact]
    public void TheSignatureScalarsAreRangeCheckedBeforeThePrimitive()
    {
        var yes = new CertKey { Ec = new StubEc(true) };
        BigInteger one = BigInteger.One, n = P384Order;
        Assert.True(AttestAmd.VerifyReportSignature(Sig(one, one), yes));
        Assert.True(AttestAmd.VerifyReportSignature(Sig(n - 1, n - 1), yes));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(BigInteger.Zero, one), yes));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(n, one), yes));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(one, BigInteger.Zero), yes));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(one, n), yes));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(one, one), new CertKey()));
    }

    [Fact]
    public void TheScalarsAreUnsignedAndAThrowingPrimitiveIsARefusal()
    {
        // a 48-byte field with its top bit set is a large positive scalar, not a negative one
        var high = Le(P384Order - 1)[..48];
        Assert.True(AttestAmd.VerifyReportSignature(new SnpReport { SigR = high, SigS = high }, new CertKey { Ec = new StubEc(true) }));
        Assert.False(AttestAmd.VerifyReportSignature(Sig(BigInteger.One, BigInteger.One), new CertKey { Ec = new StubEc(null) }));
    }

    // ---- AMD: VCEK <-> report

    static SnpReport BoundReport => new() { ChipId = Chip, ReportedTcb = Tcb };

    [Fact]
    public void TheVcekBindingReasons()
    {
        string Run(params (string, bool, byte[])[] e) => AttestAmd.CheckVcekReportBinding(Tbs(e), BoundReport);
        (string, bool, byte[])[] Set(int i, (string, bool, byte[]) x) { var g = GoodExts().Select(v => ((string, bool, byte[]))v).ToArray(); g[i] = x; return g; }

        Assert.Equal("", Run(GoodExts().Select(v => ((string, bool, byte[]))v).ToArray()));
        Assert.Equal("VCEK extensions malformed: DER: truncated header", AttestAmd.CheckVcekReportBinding(new byte[] { 0x30 }, BoundReport));
        Assert.Equal("VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)", Run(Set(0, (OHw, true, Chip))));
        Assert.Equal("VCEK certificate has no bootloader SPL extension", Run(GoodExts().Where(e => e.Oid != OBl).Select(v => ((string, bool, byte[]))v).ToArray()));
        Assert.Equal("VCEK tee SPL extension is marked critical (the AMD profile is non-critical)", Run(Set(2, (OTee, true, Spl(2)))));
        Assert.Equal("VCEK snp SPL extension is not a DER INTEGER", Run(Set(3, (OSnp, false, new byte[] { 0x04, 0x01, 3 }))));
        Assert.Equal("VCEK microcode SPL 9 does not match report reported_tcb (4) — TCB downgrade?", Run(Set(4, (OUc, false, Spl(9)))));
    }

    // ---- AMD: the chain

    [Fact]
    public void TheChainVerifiesWithAZeroSkewAndRefusesANegativeOne()
    {
        var ok = AttestAmd.VerifyChain(VcekDer, AskArk, ArkPin, Now, new Num("0"));
        Assert.Equal("", ok.Reason);
        Assert.NotNull(ok.Key);
        Assert.NotNull(ok.Tbs);
        Assert.Equal("clockSkewMs must be a non-negative number", AttestAmd.VerifyChain(VcekDer, AskArk, ArkPin, Now, new Num("-1")).Reason);
    }

    [Fact]
    public void AValidityBoundThatDoesNotParseIsRefusedAlone()
    {
        var badTo = PatchTime(VcekDer, AskKey, "350101000000Z", "351301000000Z");
        var badFrom = PatchTime(VcekDer, AskKey, "250101000000Z", "251301000000Z");
        Assert.Equal("VCEK certificate validity is unparseable", AttestAmd.VerifyChain(badTo, AskArk, ArkPin, Now, null).Reason);
        Assert.Equal("VCEK certificate validity is unparseable", AttestAmd.VerifyChain(badFrom, AskArk, ArkPin, Now, null).Reason);
    }

    [Fact]
    public void ExpiryAppliesTheSkewBackwards()
    {
        Assert.Equal("", AttestAmd.VerifyChain(VcekDer, AskArk, ArkPin, ToMs + 5000, new Num("10000")).Reason);
        Assert.Equal("VCEK certificate has expired", AttestAmd.VerifyChain(VcekDer, AskArk, ArkPin, ToMs + 5000, null).Reason);
    }

    [Fact]
    public void TheVcekMustBeP384()
    {
        using var p256 = P256();
        using var rsa = RSA.Create(2048);
        var ec = EndEntity("CN=vcek", p256, "CN=ask", AskKey);
        var rsaReq = new CertificateRequest("CN=vcek", rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var rs = Sign(rsaReq, "CN=ask", AskKey);
        Assert.Equal("AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)", AttestAmd.VerifyChain(ec, AskArk, ArkPin, Now, null).Reason);
        Assert.Equal("AMD chain verification error: VCEK is not EC secp384r1 (got rsa/undefined)", AttestAmd.VerifyChain(rs, AskArk, ArkPin, Now, null).Reason);
    }

    // ---- AMD: BigInt(v) of the wire floors

    [Fact]
    public void BigIntOfAValue()
    {
        foreach (var (v, want) in new (object, long)[]
        {
            (true, 1), (false, 0), ("", 0), ("  ", 0), ("0", 0), ("5", 5), ("12", 12), (" 12 ", 12), ("+5", 5), ("-5", -5),
            ("0x0", 0), ("0x9", 9), ("0xa", 10), ("0xf", 15), ("0xA", 10), ("0xF", 15), ("0x1f", 31), ("0XaF", 175),
            ("0o17", 15), ("0O7", 7), ("0b11", 3), ("0B1", 1), (new Num("5"), 5), (new Num("1e2"), 100),
        })
            Assert.True(new BigInteger(want) == AttestAmd.ParseJsBigInt(v), v.ToString());
    }

    [Fact]
    public void BigIntRefusals()
    {
        static string Err(object? v) => Assert.Throws<ArgumentException>(() => AttestAmd.ParseJsBigInt(v)).Message;
        Assert.Equal("Cannot convert null to a BigInt", Err(null));
        foreach (var s in new[] { "0x", "0o", "0b", "0x-1", "0x+1", "0xg", "0xG", "0x@", "0x:", "0x/", "0x`", "0o8", "0b2", "1x0", "+", "-", "1-2", "abc", "-0x10", "12\0" })
            Assert.Equal($"Cannot convert {s} to a BigInt", Err(s));
        Assert.Equal("The number 1.5 cannot be converted to a BigInt because it is not an integer", Err(new Num("1.5")));
        // stricter than BigInt(), which reads a list through its string form (BigInt([]) is 0): a floor is never a list
        Assert.Equal("Cannot convert value to a BigInt", Err(new JL()));
    }

    // ---- Intel: defaults, configuration

    [Fact]
    public void IntelResultDefaultsAreEmpty()
    {
        Assert.Equal("", new DcapQuote().PckChainPem);
        Assert.Equal("", new PckChainResult().Reason);
        Assert.Equal("", new TdxResult().Reason);
        Assert.Equal("", new TdxResult().Fmspc);
    }

    static readonly string Mrtd = string.Concat(Enumerable.Repeat("11", 48));

    [Theory]
    [InlineData("mrSeams")]
    [InlineData("mrSignerSeams")]
    public void EveryMrSeamEntryMustBe96HexChars(string name)
    {
        JD Cfg(string entry) => new() { ["binding"] = "report-data", ["policy"] = new JD { ["mrtds"] = new JL { Mrtd }, [name] = new JL { entry } } };
        var want = $"createIntelDcapVerifier: every {name} entry must be 96 hex chars (48 bytes)";
        Assert.Equal(want, Assert.Throws<ArgumentException>(() => IntelVerifier.Create(Cfg(new string('a', 95)))).Message);
        Assert.Equal(want, Assert.Throws<ArgumentException>(() => IntelVerifier.Create(Cfg(new string('g', 96)))).Message);
        Assert.NotNull(IntelVerifier.Create(Cfg(new string('a', 96))));
    }

    [Fact]
    public void ACollateralAnswerIsRecordedAndARefusalIsWorded()
    {
        var host = new Dictionary<string, string>();
        Assert.Null(IntelVerifier.ApplyCollateral(new CollateralResult { Ok = true }, host));
        Assert.Empty(host); // no status, no key
        Assert.Null(IntelVerifier.ApplyCollateral(new CollateralResult { Ok = true, Status = "UpToDate", AdvisoryIds = new List<string> { "a", "b" } }, host));
        Assert.Equal("UpToDate", host["tcb_status"]);
        Assert.Equal("a,b", host["advisory_ids"]);
        Assert.Equal("Intel collateral: rejected", IntelVerifier.ApplyCollateral(new CollateralResult(), host));
        Assert.Equal("Intel collateral: why", IntelVerifier.ApplyCollateral(new CollateralResult { Reason = "why" }, host));
    }

    // ---- Intel: the quote parser

    static byte[] U16(int v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)v); return b; }
    static byte[] U32(int v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v); return b; }

    static byte[] QuoteHeader()
    {
        var h = new byte[48];
        h[0] = 4; h[2] = 2; h[4] = 0x81;
        return h;
    }

    static string ParseErr(byte[] q) => Assert.Throws<AttestError>(() => AttestIntel.ParseQuote(q)).Message;

    [Fact]
    public void TheQuoteLengthFloorIsExact()
    {
        byte[] Of(int n) { var q = new byte[n]; QuoteHeader().CopyTo(q, 0); return q; }
        Assert.Equal("parseDcapQuote: too short for header + TD report + sig length", ParseErr(Of(635)));
        Assert.Equal("parseDcapQuote: truncated reading quote signature", ParseErr(Of(636)));
    }

    [Fact]
    public void EachTruncatedSectionIsNamed()
    {
        byte[] Q(params byte[][] after)
        {
            var sig = Cat(new byte[64], new byte[64], U16(6), U32(0), Cat(after));
            return Cat(QuoteHeader(), new byte[584], U32(sig.Length), sig);
        }
        byte[] qe = new byte[384], qs = new byte[64];
        Assert.Equal("parseDcapQuote: truncated reading QE report", ParseErr(Q()));
        Assert.Equal("parseDcapQuote: truncated reading QE report signature", ParseErr(Q(qe)));
        Assert.Equal("parseDcapQuote: truncated reading QE auth-data size", ParseErr(Q(qe, qs)));
        Assert.Equal("parseDcapQuote: truncated reading inner cert-data header", ParseErr(Q(qe, qs, U16(0))));
    }

    // ---- Intel: the lenient TLV reader (attest-intel-tdx.ts:316)

    [Fact]
    public void TheLenientTlvReaderBounds()
    {
        static bool R(byte[] b, int off) => AttestIntel.ReadTlvLenient(b, off, out _);

        // the header
        Assert.False(R(new byte[] { 0x04, 0x00 }, -1));
        Assert.True(R(new byte[] { 0x04, 0x00 }, 0));
        Assert.False(R(new byte[] { 0, 0, 0, 0 }, 3));
        Assert.True(AttestIntel.ReadTlvLenient(new byte[] { 0x04, 0x01, 0xaa }, 0, out var t));
        Assert.Equal(new DerTlv(0x04, 2, 3), t);

        // the length form
        Assert.False(R(new byte[] { 0x30, 0x80 }, 0));
        Assert.False(R(new byte[] { 0x30, 0x85, 0, 0, 0, 0, 0 }, 0));
        Assert.True(R(new byte[] { 0x30, 0x84, 0, 0, 0, 0 }, 0));
        Assert.False(R(new byte[] { 0x30, 0x82, 0 }, 0));
        Assert.True(R(new byte[] { 0x30, 0x81, 0x00 }, 0));

        // the value
        Assert.False(R(new byte[] { 0x04, 0x05, 0 }, 0));
    }

    // ---- Intel: the SGX extension

    static readonly byte[] OidF = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04 };
    static readonly byte[] OidT = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02 };
    static readonly byte[] Fm6 = { 1, 2, 3, 4, 5, 6 };

    static byte[] Tlv(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        byte[] hdr = body.Length < 0x80 ? new[] { tag, (byte)body.Length }
            : body.Length < 0x100 ? new byte[] { tag, 0x81, (byte)body.Length }
            : new byte[] { tag, 0x82, (byte)(body.Length >> 8), (byte)body.Length };
        return hdr.Concat(body).ToArray();
    }

    static byte[] F() => Cat(OidF, Tlv(0x04, Fm6));
    static byte[] T(params byte[][] comps) => Cat(OidT, Tlv(0x30, comps));
    static byte[] Comp(byte arc, params byte[] v) => Tlv(0x30, new byte[] { 0x06, 0x01, arc }, Tlv(0x02, v));

    static string ExtractErr(byte[] leaf) => Assert.Throws<AttestError>(() => AttestIntel.ExtractPckFmspcAndTcb(leaf)).Message;

    [Fact]
    public void TheExtensionIsReadWhereverItSits()
    {
        var a = AttestIntel.ExtractPckFmspcAndTcb(Cat(F(), T(Comp(1, 7), Comp(16, 9), Comp(17, 1, 2))));
        Assert.Equal(Fm6, a.Fmspc);
        Assert.Equal(7, a.Sgx[0]);
        Assert.Equal(9, a.Sgx[15]);
        Assert.Equal(258, a.Pcesvn);

        // the TCB OID at the very start, and a PCESVN of zero
        var b = AttestIntel.ExtractPckFmspcAndTcb(Cat(T(Comp(17, 0)), F()));
        Assert.Equal(0, b.Pcesvn);

        // what follows the TCB sequence is not part of it
        Assert.Equal(1, AttestIntel.ExtractPckFmspcAndTcb(Cat(F(), T(Comp(17, 1)), new byte[] { 0x05, 0x00 })).Pcesvn);
    }

    [Fact]
    public void TheExtensionMalformations()
    {
        Assert.Equal("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING", ExtractErr(Cat(OidF, Tlv(0x05, Fm6), T(Comp(17, 1)))));
        Assert.Equal("extractPckFmspcAndTcb: malformed TCB SEQUENCE", ExtractErr(Cat(F(), OidT, Tlv(0x31, Comp(17, 1)))));
        Assert.Equal("extractPckFmspcAndTcb: malformed TCB component", ExtractErr(Cat(F(), T(Tlv(0x31, new byte[] { 0x06, 0x01, 17 }, new byte[] { 0x02, 0x01, 0x01 })))));
        Assert.Equal("extractPckFmspcAndTcb: TCB component missing OID", ExtractErr(Cat(F(), T(Tlv(0x30, new byte[] { 0x05, 0x00 }, new byte[] { 0x02, 0x01, 0x01 })))));
        Assert.Equal("extractPckFmspcAndTcb: TCB component missing value", ExtractErr(Cat(F(), T(Tlv(0x30, new byte[] { 0x06, 0x01, 17 })))));
    }

    [Fact]
    public void TheComponentWalkStopsAfter65Entries()
    {
        byte[] Walk(int fillers) => Cat(F(), T(Enumerable.Repeat(Comp(1, 1), fillers).Append(Comp(17, 5)).ToArray()));
        Assert.Equal(5, AttestIntel.ExtractPckFmspcAndTcb(Walk(64)).Pcesvn);
        Assert.Equal("extractPckFmspcAndTcb: PCESVN not found in TCB extension", ExtractErr(Walk(65)));
    }

    // ---- Intel: the PCK chain

    static readonly byte[] PckDer = EndEntity("CN=pck", PckKey, "CN=root", RootKey, new X509Extension(new Oid("1.2.840.113741.1.13.1"), Cat(F(), T(Comp(17, 1))), false));
    static readonly string PckChain = Pem(PckDer) + Pem(RootDer);
    static string RootPin => SpkiOf(RootDer);

    [Fact]
    public void APckLeafOnAnotherCurveThanP256IsRefusedByTheChain()
    {
        // the chain is otherwise valid (P-384 leaf signed by the root under the pin): only the curve check refuses it, before any quote signature is looked at
        var leaf384 = EndEntity("CN=pck", OtherKey, "CN=root", RootKey, new X509Extension(new Oid("1.2.840.113741.1.13.1"), Cat(F(), T(Comp(17, 1))), false));
        var r = AttestIntel.VerifyPckChain(Pem(leaf384) + Pem(RootDer), RootPin, Now);
        Assert.False(r.Ok);
        Assert.Equal("PCK chain X.509 verification error (fail closed): public key is not on P-256 (got P-384)", r.Reason);
    }

    [Fact]
    public void AnExpiredChainIsAValidityFailure()
    {
        Assert.True(AttestIntel.VerifyPckChain(PckChain, RootPin, Now).Ok);
        var r = AttestIntel.VerifyPckChain(PckChain, RootPin, ToMs + 1000);
        Assert.False(r.Ok);
        Assert.True(r.Validity);
        Assert.Equal("PCK chain certificate outside its validity period", r.Reason);
    }

    [Fact]
    public void TheLeafIsTheFirstCertificateIssuingNothing()
    {
        // two candidates: the first has an unknown issuer, the second would make a shorter valid path
        using var k = P256();
        var orphan = EndEntity("CN=a", k, "CN=gone", k);
        var other = EndEntity("CN=b", k, "CN=root", RootKey);
        Assert.Equal("PCK chain does not terminate in a self-signed root", AttestIntel.VerifyPckChain(Pem(orphan) + Pem(other) + Pem(RootDer), RootPin, Now).Reason);
    }

    [Fact]
    public void AnIssuerCycleEnds()
    {
        using var k = P256();
        var a = EndEntity("CN=a", k, "CN=b", k);
        var b = EndEntity("CN=b", k, "CN=a", k);
        Assert.Equal("PCK chain does not terminate in a self-signed root", AttestIntel.VerifyPckChain(Pem(a) + Pem(b), RootPin, Now).Reason);
    }

    [Fact]
    public void EachPartOfThePckChainAnswerIsChecked()
    {
        var leaf = new AttCert();
        var key = new CertKey { Ec = new StubEc(true) };
        Assert.False(AttestIntel.ChainRefused(new PckChainResult { Ok = true, Leaf = leaf, LeafKey = key }));
        Assert.True(AttestIntel.ChainRefused(new PckChainResult { Leaf = leaf, LeafKey = key }));
        Assert.True(AttestIntel.ChainRefused(new PckChainResult { Ok = true, Leaf = leaf }));
        Assert.True(AttestIntel.ChainRefused(new PckChainResult { Ok = true, Leaf = leaf, LeafKey = new CertKey() }));
        Assert.True(AttestIntel.ChainRefused(new PckChainResult { Ok = true, LeafKey = key }));
    }

    [Fact]
    public void TheCompactP256CheckRefusesAWrongLengthAndAThrowingPrimitive()
    {
        var msg = new byte[] { 1 };
        Assert.True(AttestIntel.VerifyP256Compact(msg, new byte[64], new StubEc(true)));
        Assert.False(AttestIntel.VerifyP256Compact(msg, new byte[63], new StubEc(true)));
        Assert.False(AttestIntel.VerifyP256Compact(msg, new byte[64], new StubEc(null)));
    }

    // ---- Intel: the genuine quote

    static byte[] P256Sig(ECDsa k, byte[] m) => k.SignHash(SHA256.HashData(m), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    static byte[] Quote(byte[]? akRaw = null)
    {
        var hdr = QuoteHeader();
        var td = new byte[584];
        Array.Fill(td, (byte)0x11, 136, 48);
        BindBytes.CopyTo(td, 520);
        var q = AkKey.ExportParameters(false).Q;
        var ak = akRaw ?? Cat(q.X!, q.Y!);
        var qe = new byte[384];
        SHA256.HashData(ak).CopyTo(qe, 0x140);
        var pem = Encoding.ASCII.GetBytes(PckChain);
        var outer = Cat(qe, P256Sig(PckKey, qe), U16(0), U16(5), U32(pem.Length), pem);
        var sig = Cat(P256Sig(AkKey, Cat(hdr, td)), ak, U16(6), U32(outer.Length), outer);
        return Cat(hdr, td, U32(sig.Length), sig);
    }

    static IntelVerifier IntelV() => IntelVerifier.Create(new JD
    {
        ["binding"] = "report-data", ["allowMissingCollateral"] = true, ["trustAnchorRootCaSpkiSha256"] = RootPin.ToUpperInvariant(),
        ["policy"] = new JD { ["mrtds"] = new JL { Mrtd } },
    });

    [Fact]
    public void AGenuineQuoteVerifiesUnderACaseInsensitivePin()
    {
        var ev = new JD { ["quote"] = Convert.ToBase64String(Quote()) };
        var r = IntelV().Verify(ev, Bind, Now);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("unevaluated", r.HostAsserted!["tcb_status"]);
        Assert.Equal(AttestUtil.Hex(Fm6), r.HostAsserted!["fmspc"]);
        Assert.Equal("no expected attestation binding supplied", IntelV().Verify(ev, null, Now).Reason);
    }

    [Fact]
    public void AnEmptyMrtdListIsNoGateAtTheQuoteLevel()
    {
        var r = AttestIntel.VerifyGenuineTdxQuote(Quote(), RootPin, Now, new TdxQuotePolicy(), false);
        Assert.True(r.Ok, r.Reason);
    }

    [Fact]
    public void AnOffCurveAttestationKeyIsNamed()
    {
        var off = Enumerable.Repeat((byte)1, 64).ToArray();
        Assert.Equal("attestation public key is not a valid P-256 point", AttestIntel.VerifyGenuineTdxQuote(Quote(off), RootPin, Now, null, false).Reason);
    }

    // ---- tokens

    static string Seg(JD j) => Pca.B64u(JsonSerializer.SerializeToUtf8Bytes(j));

    static string Jwt(JD header, JD payload, ECDsa key)
    {
        var input = Seg(header) + "." + Seg(payload);
        return input + "." + Pca.B64u(key.SignData(Encoding.UTF8.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    static JD EcJwk(ECDsa k, string kid = "k", string crv = "P-256")
    {
        var p = k.ExportParameters(false);
        return new JD { ["kid"] = kid, ["kty"] = "EC", ["crv"] = crv, ["x"] = Pca.B64u(p.Q.X!), ["y"] = Pca.B64u(p.Q.Y!) };
    }

    static JD Jwks(params JD[] keys) => new() { ["keys"] = keys.Cast<object?>().ToList() };

    // ---- GCP: configuration

    static JD Pins(params string[] pins) => new() { ["trustedKeySpki"] = new JL(pins) };
    static JD Roots(params string[] pems) => new() { ["rootCertsPem"] = new JL(pems) };

    static GcpVerifier GcpV(JD anchors, JD? pol = null, object? skew = null, string issuer2 = "https://i2")
    {
        var p = pol ?? new JD();
        p["imageDigests"] = new JL { "sha256:aa" };
        var c = new JD { ["trustedIssuers"] = new JL { "https://i", issuer2 }, ["trustAnchors"] = anchors, ["policy"] = p };
        if (skew != null) c["clockSkewMs"] = skew;
        return GcpVerifier.Create(c);
    }

    [Fact]
    public void GcpConfiguration()
    {
        const string want = "createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string";
        JD Iss(object? i) => new() { ["trustedIssuers"] = new JL { i }, ["trustAnchors"] = Pins("aa"), ["policy"] = new JD { ["imageDigests"] = new JL { "x" } } };
        Assert.Equal(want, Assert.Throws<ArgumentException>(() => GcpVerifier.Create(Iss(""))).Message);
        Assert.Equal(want, Assert.Throws<ArgumentException>(() => GcpVerifier.Create(Iss(new Num("1")))).Message);

        // the anchors add up: no two kinds cancel out
        Assert.NotNull(GcpV(new JD { ["trustedKeySpki"] = new JL { "aa" }, ["rootCertsPem"] = new JL { "x" } }));
        Assert.NotNull(GcpV(new JD { ["trustedJwks"] = Jwks(new JD()), ["trustedKeySpki"] = new JL { "aa" } }));
    }

    // ---- GCP: resolving the signing key

    const string NoAnchor = "x5c chain does not anchor in a configured GCP trust root";
    const string NotAnchored = "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)";

    [Fact]
    public void AHeaderChainIsVerifiedNeverTrustedOutright()
    {
        var tok = new JwtParsed { X5c = Strs(LeafDer, RootDer), HasX5c = true };
        Assert.Equal("signing key not trusted: " + NoAnchor, GcpV(Pins("aa")).SigningKey(tok, null, Now).Why);
        // a root configured, the header chain anchored there
        var (k, why) = GcpV(Roots(Pem(RootDer))).SigningKey(tok, null, Now);
        Assert.Equal("", why);
        Assert.Equal(SpkiOf(LeafDer), k!.SpkiSha256());
        // an empty header list is no chain
        Assert.Equal("no kid on the token and no unambiguous single signing key available", GcpV(Pins("aa")).SigningKey(new JwtParsed { HasX5c = true }, null, Now).Why);
    }

    [Fact]
    public void AKeyInTheEvidenceWinsOverTheHeaderChain()
    {
        var tok = new JwtParsed { X5c = Strs(OtherDer), HasX5c = true };
        var (k, why) = GcpV(Pins(Spki(LeafKey))).SigningKey(tok, Jwks(EcJwk(LeafKey)), Now);
        Assert.Equal("", why);
        Assert.Equal(Spki(LeafKey), k!.SpkiSha256());
    }

    [Fact]
    public void AnEmptyKidIsNoKid()
    {
        var tok = new JwtParsed { HasKid = true, Kid = "" };
        Assert.Equal("", GcpV(Pins(Spki(LeafKey))).SigningKey(tok, Jwks(EcJwk(LeafKey)), Now).Why);
        Assert.Equal("no kid on the token and no unambiguous single signing key available", GcpV(Pins("aa")).SigningKey(tok, null, Now).Why);
    }

    [Fact]
    public void AnEvidenceKeyMustMatchATrustedKeyByMaterial()
    {
        var anchors = new JD { ["trustedJwks"] = Jwks(EcJwk(AkKey, "a")) };
        var tok = new JwtParsed { HasKid = true, Kid = "k" };
        var withChain = EcJwk(LeafKey);
        withChain["x5c"] = X5c(LeafDer, RootDer);
        // no root and no pin configured: a chain cannot anchor anything
        Assert.Equal(NotAnchored, GcpV(anchors).SigningKey(tok, Jwks(withChain), Now).Why);
        Assert.Equal("", GcpV(anchors).SigningKey(tok, Jwks(EcJwk(AkKey)), Now).Why);
        // a malformed trusted entry is skipped
        Assert.Equal(NotAnchored, GcpV(new JD { ["trustedJwks"] = Jwks(new JD { ["kid"] = "z" }) }).SigningKey(tok, Jwks(EcJwk(LeafKey)), Now).Why);
    }

    [Fact]
    public void AnEmptyJwkChainAnchorsNothing()
    {
        var jwk = EcJwk(LeafKey);
        jwk["x5c"] = new JL();
        Assert.Equal(NotAnchored, GcpV(Pins("aa")).SigningKey(new JwtParsed(), Jwks(jwk), Now).Why);
    }

    [Fact]
    public void APinAloneLetsAChainAnchorAndItsLeafSign()
    {
        var (k, why) = GcpV(Pins(SpkiOf(RootDer))).SigningKey(new JwtParsed(), Jwks(new JD { ["x5c"] = X5c(LeafDer, RootDer) }), Now);
        Assert.Equal("", why);
        Assert.Equal(SpkiOf(LeafDer), k!.SpkiSha256());
    }

    [Fact]
    public void AJwkWithNoUsableKey()
    {
        var v = GcpV(Pins("aa"));
        Assert.Equal("JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate", v.SigningKey(new JwtParsed(), Jwks(new JD { ["x5c"] = new JL() }), Now).Why);
        Assert.StartsWith("JWKS key is not a usable public key: ", v.SigningKey(new JwtParsed(), Jwks(new JD { ["x5c"] = new JL { "AAAA" } }), Now).Why);
    }

    // ---- GCP: the x5c chain

    [Fact]
    public void GcpChainReasons()
    {
        var v = GcpV(Pins("aa"));
        Assert.Equal("empty x5c certificate chain", v.VerifyJwkX5cChain(new JL(), Now));
        Assert.Equal("empty x5c entry at index 0", v.VerifyJwkX5cChain(new JL { "" }, Now));
        Assert.Equal("empty x5c entry at index 1", v.VerifyJwkX5cChain(new JL { Convert.ToBase64String(LeafDer), new Num("1") }, Now));
        Assert.StartsWith("malformed x5c certificate at index 0: ", v.VerifyJwkX5cChain(new JL { "AAAA" }, Now));
        Assert.Equal("x5c certificate at index 0 is outside its validity window", v.VerifyJwkX5cChain(X5c(LeafDer), ToMs + 1000));
        Assert.Equal("x5c link 0 is not signed by the certificate above it", v.VerifyJwkX5cChain(X5c(LeafDer, OtherDer), Now));
        Assert.Equal(NoAnchor, v.VerifyJwkX5cChain(X5c(LeafDer, RootDer), Now));
    }

    [Fact]
    public void GcpChainAnchors()
    {
        // a pin on any certificate of the chain
        Assert.Equal("", GcpV(Pins(SpkiOf(RootDer))).VerifyJwkX5cChain(X5c(LeafDer, RootDer), Now));
        Assert.Equal("", GcpV(Pins(SpkiOf(LeafDer))).VerifyJwkX5cChain(X5c(LeafDer, RootDer), Now));
        // a root: the top certificate must be signed by it
        Assert.Equal("", GcpV(Roots(Pem(RootDer))).VerifyJwkX5cChain(X5c(LeafDer), Now));
        Assert.Equal(NoAnchor, GcpV(Roots(Pem(OtherDer))).VerifyJwkX5cChain(X5c(LeafDer), Now));
        // a bare public key as the root
        var bare = "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(RootKey.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks) + "\n-----END PUBLIC KEY-----\n";
        Assert.Equal("", GcpV(Roots(bare)).VerifyJwkX5cChain(X5c(LeafDer), Now));
    }

    // ---- GCP: the whole token

    static JD GcpClaims() => new()
    {
        ["iss"] = "https://i", ["exp"] = NowSec + 100, ["swname"] = "CONFIDENTIAL_SPACE", ["hwmodel"] = "GCP_INTEL_TDX", ["dbgstat"] = "disabled-since-boot",
        ["eat_nonce"] = AttestUtil.Hex(BindBytes),
        ["submods"] = new JD { ["confidential_space"] = new JD(), ["container"] = new JD { ["image_digest"] = "sha256:aa" } },
    };

    static GcpVerifier GcpPinned(JD? pol = null, object? skew = null, string issuer2 = "https://i2") => GcpV(Pins(Spki(LeafKey)), pol, skew, issuer2);

    static HardwareResult GcpRun(JD claims, GcpVerifier? v = null, bool bound = true)
    {
        var ev = new JD { ["token"] = Jwt(new JD { ["alg"] = "ES256", ["kid"] = "k" }, claims, LeafKey), ["jwks"] = Jwks(EcJwk(LeafKey)) };
        return (v ?? GcpPinned()).Verify(ev, bound ? Bind : null, Now);
    }

    static JD With(JD c, string k, object? val) { c[k] = val; return c; }

    [Fact]
    public void AGoodGcpTokenVerifies()
    {
        var r = GcpRun(GcpClaims());
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("tdx", r.HostAsserted!["attestation_type"]);
        Assert.Equal("no expected attestation binding supplied", GcpRun(GcpClaims(), bound: false).Reason);
    }

    [Theory]
    [InlineData("GCP_AMD_SEV", "sev-snp")]
    [InlineData("GCP_AMD_SEV_SNP", "sev-snp")]
    [InlineData("GCP_AMD_SEV_ES", "sev-snp")]
    [InlineData("GCP_AMD_SEV_FUTURE", "sev-snp")]
    [InlineData("GCP_INTEL_TDX", "tdx")]
    public void GcpHardwareModels(string model, string want) => Assert.Equal(want, GcpRun(With(GcpClaims(), "hwmodel", model)).HostAsserted!["attestation_type"]);

    [Fact]
    public void AMissingIssuerNeverMatchesAConfiguredOne()
    {
        var c = GcpClaims();
        c.Remove("iss");
        // whatever a default for the missing claim were, it must not reach the issuer set
        Assert.Equal("token iss 'undefined' is not a configured trusted Google attestation issuer", GcpRun(c, GcpPinned(issuer2: "Stryker was here!")).Reason);
    }

    [Fact]
    public void GcpTimeWindowWithSkew()
    {
        var one = GcpPinned(skew: new Num("1000"));
        Assert.True(GcpRun(With(GcpClaims(), "exp", NowSec - 1), one).Ok);
        Assert.Equal("Confidential Space token expired", GcpRun(With(GcpClaims(), "exp", NowSec - 2), one).Reason);
        // a partial second of skew counts whole
        Assert.True(GcpRun(With(GcpClaims(), "exp", NowSec - 2), GcpPinned(skew: new Num("1500"))).Ok);

        var two = GcpPinned(skew: new Num("2000"));
        Assert.True(GcpRun(With(GcpClaims(), "nbf", NowSec + 2), two).Ok);
        Assert.Equal("Confidential Space token not yet valid (nbf)", GcpRun(With(GcpClaims(), "nbf", NowSec + 3), two).Reason);
        Assert.True(GcpRun(With(GcpClaims(), "iat", NowSec + 2), two).Ok);
        Assert.Equal("Confidential Space token issued in the future (iat)", GcpRun(With(GcpClaims(), "iat", NowSec + 3), two).Reason);
    }

    [Fact]
    public void GcpSoftwareClaims()
    {
        var c = GcpClaims();
        c.Remove("swname");
        Assert.Equal("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')", GcpRun(c).Reason);

        const string notAllowed = "swversion not in policy allowlist";
        JD Allow(params string[] a) => new() { ["allowedSwVersions"] = new JL(a) };
        // any intersection accepts
        Assert.True(GcpRun(With(GcpClaims(), "swversion", new List<string> { "1", "2" }), GcpPinned(Allow("1"))).Ok);
        Assert.True(GcpRun(With(GcpClaims(), "swversion", "1"), GcpPinned(Allow("1"))).Ok);
        // no claim, and an empty single value, are no version
        Assert.Equal(notAllowed, GcpRun(GcpClaims(), GcpPinned(Allow("1"))).Reason);
        Assert.Equal(notAllowed, GcpRun(With(GcpClaims(), "swversion", ""), GcpPinned(Allow(""))).Reason);
    }

    [Fact]
    public void EmptyNonceCandidatesAreNoNonce() =>
        Assert.Equal("token carries no eat_nonce claim to bind the PCA challenge", GcpRun(With(GcpClaims(), "eat_nonce", new List<string> { "" })).Reason);

    [Fact]
    public void Es256NeedsAP256Key()
    {
        using var p384 = P384();
        var ev = new JD { ["token"] = Jwt(new JD { ["alg"] = "ES256", ["kid"] = "k" }, GcpClaims(), LeafKey), ["jwks"] = Jwks(EcJwk(p384, "k", "P-384")) };
        Assert.Equal("ES256 token but signing key is EC/P-384 (not EC P-256)", GcpV(Pins(Spki(p384))).Verify(ev, Bind, Now).Reason);
    }

    [Fact]
    public void GcpSignatureRefusesAnyOtherAlg() =>
        Assert.Equal("unsupported JWS alg 'none' (Confidential Space uses RS256)", GcpVerifier.JwsSignature(new JwtParsed { Alg = "none" }, new CertKey()));

    // ---- MAA: configuration

    static JD Spkis(params string[] s) => new() { ["rootSpkiSha256"] = new JL(s) };

    static MaaVerifier MaaV(JD anchors, JD? pol = null, object? skew = null, string issuer2 = "https://i2")
    {
        var c = new JD
        {
            ["trustedIssuers"] = new JL { "https://i", issuer2 }, ["trustAnchors"] = anchors,
            ["policy"] = pol ?? new JD { ["tdxMrtds"] = new JL { Mrtd } },
        };
        if (skew != null) c["clockSkewMs"] = skew;
        return MaaVerifier.Create(c);
    }

    [Fact]
    public void MaaConfiguration()
    {
        // the anchors add up
        Assert.NotNull(MaaV(new JD { ["rootCertsPem"] = new JL { "x" }, ["rootSpkiSha256"] = new JL { "aa" } }));

        JD Tcb(object? v) => new() { ["tdxMrtds"] = new JL { Mrtd }, ["sevSnpMinTcb"] = v };
        string Err(object? v) => Assert.Throws<ArgumentException>(() => MaaV(Spkis("aa"), Tcb(v))).Message;
        Assert.Equal("createAzureMaaVerifier: policy.sevSnpMinTcb must be an object", Err(new Num("1")));
        // the first bad field in document order (attest-azure-maa.ts:659 walks Object.entries)
        Assert.Equal("createAzureMaaVerifier: policy.sevSnpMinTcb.zeta is not a known field (bootloader | snp | microcode | tee)", Err(new JD { ["zeta"] = new Num("1"), ["alpha"] = new Num("1") }));
    }

    // ---- MAA: the x5c chain

    [Fact]
    public void MaaChainReasons()
    {
        Assert.Equal("empty x5c certificate chain", MaaV(Spkis("aa")).VerifyX5cChain(new JL(), Now).Why);
        // an empty fingerprint is no anchor
        Assert.Equal("no MAA trust anchor configured (fail closed)", MaaV(Spkis("")).VerifyX5cChain(X5c(LeafDer), Now).Why);
        Assert.StartsWith("x5c chain verification error (fail closed): ", MaaV(Roots("garbage")).VerifyX5cChain(X5c(LeafDer), Now).Why);
        // no certificate is an anchor: the whole chain must link
        Assert.Equal("x5c link 0 is not signed by the certificate above it", MaaV(Roots(Pem(RootDer))).VerifyX5cChain(X5c(LeafDer, OtherDer), Now).Why);
    }

    [Fact]
    public void AConfiguredRootInTheChainIsItsAnchor()
    {
        // what lies above the anchor is not verified
        var (leaf, why) = MaaV(Roots(Pem(RootDer))).VerifyX5cChain(X5c(LeafDer, RootDer, OtherDer), Now);
        Assert.Equal("", why);
        Assert.NotNull(leaf);
    }

    [Fact]
    public void TheFirstAnchorInTheChainCounts()
    {
        var (leaf, why) = MaaV(Spkis(SpkiOf(LeafDer), SpkiOf(OtherDer))).VerifyX5cChain(X5c(LeafDer, OtherDer), Now);
        Assert.Equal("", why);
        Assert.NotNull(leaf);
    }

    [Fact]
    public void AChainToAnExternalRootHasNoReason()
    {
        var (leaf, why) = MaaV(Roots(Pem(RootDer))).VerifyX5cChain(X5c(LeafDer), Now);
        Assert.Equal("", why);
        Assert.NotNull(leaf);
    }

    // ---- MAA: resolving the chain

    [Fact]
    public void ResolvingTheSigningChain()
    {
        JD K(string? kid, params string[] x5c)
        {
            var j = new JD();
            if (kid != null) j["kid"] = kid;
            if (x5c.Length > 0) j["x5c"] = new JL(x5c);
            return j;
        }
        var empty = new JwtParsed { HasKid = true, Kid = "" };
        Assert.Equal("token has no kid and the JWKS publishes multiple keys (ambiguous)", MaaVerifier.ResolveSigningX5c(empty, Jwks(K("a"), K("b"))).Why);

        var none = MaaVerifier.ResolveSigningX5c(new JwtParsed(), Jwks(K(null)));
        Assert.Null(none.Chain);
        Assert.Equal("JWKS key carries no x5c chain", none.Why);

        var sole = MaaVerifier.ResolveSigningX5c(new JwtParsed(), Jwks(K(null, "c")));
        Assert.Equal("", sole.Why);
        Assert.Equal(new JL { "c" }, sole.Chain);

        var byKid = MaaVerifier.ResolveSigningX5c(new JwtParsed { HasKid = true, Kid = "b" }, Jwks(K("a", "x"), K("b", "c")));
        Assert.Equal("", byKid.Why);
        Assert.Equal(new JL { "c" }, byKid.Chain);

        var emptyHeader = MaaVerifier.ResolveSigningX5c(new JwtParsed { HasX5c = true }, null);
        Assert.Null(emptyHeader.Chain);
        Assert.Equal("no signing x5c available (no JWKS and no header x5c)", emptyHeader.Why);

        var header = MaaVerifier.ResolveSigningX5c(new JwtParsed { HasX5c = true, X5c = new List<string> { "c" } }, null);
        Assert.Equal("", header.Why);
        Assert.Equal(new JL { "c" }, header.Chain);
    }

    [Fact]
    public void MaaSignatureReasons()
    {
        using var p384 = P384();
        var leaf384 = AttestCerts.ParseDer(EndEntity("CN=l", p384, "CN=root", RootKey));
        Assert.Equal("ES256 token but signing key is EC/P-384 (not EC P-256)", MaaVerifier.JwsSignature(new JwtParsed { Alg = "ES256" }, leaf384));
        Assert.Equal("unsupported JWS alg 'none' (MAA uses ES256 / RS256)", MaaVerifier.JwsSignature(new JwtParsed { Alg = "none" }, leaf384));
        Assert.StartsWith("x5c chain verification error (fail closed): ", MaaVerifier.JwsSignature(new JwtParsed { Alg = "ES256" }, new AttCert { RawSpki = new byte[] { 1 } }));
    }

    // ---- MAA: the whole token

    static JD MaaClaims() => new()
    {
        ["iss"] = "https://i", ["exp"] = NowSec + 100, ["x-ms-attestation-type"] = "tdxvm", ["tdx_mrtd"] = Mrtd,
        ["tdx_report_data"] = AttestUtil.Hex(BindBytes), ["tdx_rtmr0"] = "aB",
    };

    static MaaVerifier MaaPinned(object? skew = null, string issuer2 = "https://i2") =>
        MaaV(Spkis(SpkiOf(LeafDer)), new JD { ["tdxMrtds"] = new JL { Mrtd }, ["tdxRtmrs"] = new JL { "AB" } }, skew, issuer2);

    static HardwareResult MaaRun(JD claims, MaaVerifier? v = null, bool bound = true)
    {
        var ev = new JD { ["token"] = Jwt(new JD { ["alg"] = "ES256", ["x5c"] = X5c(LeafDer) }, claims, LeafKey) };
        return (v ?? MaaPinned()).Verify(ev, bound ? Bind : null, Now);
    }

    [Fact]
    public void AGoodMaaTokenVerifiesAndLowercasesTheRtmr()
    {
        var r = MaaRun(MaaClaims());
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("ab", r.HostAsserted!["rtmr0"]);
        Assert.Equal("no expected attestation binding supplied", MaaRun(MaaClaims(), bound: false).Reason);
    }

    [Fact]
    public void AMissingMaaIssuerNeverMatchesAConfiguredOne()
    {
        var c = MaaClaims();
        c.Remove("iss");
        Assert.Equal("token iss 'undefined' is not a configured trusted MAA instance", MaaRun(c, MaaPinned(issuer2: "Stryker was here!")).Reason);
    }

    [Fact]
    public void MaaTimeWindowWithSkew()
    {
        var one = MaaPinned(new Num("1000"));
        Assert.True(MaaRun(With(MaaClaims(), "exp", NowSec - 1), one).Ok);
        Assert.Equal("MAA token expired", MaaRun(With(MaaClaims(), "exp", NowSec - 2), one).Reason);
        var two = MaaPinned(new Num("2000"));
        Assert.True(MaaRun(With(MaaClaims(), "iat", NowSec + 2), two).Ok);
        Assert.Equal("MAA token issued in the future (iat)", MaaRun(With(MaaClaims(), "iat", NowSec + 3), two).Reason);
    }
}
