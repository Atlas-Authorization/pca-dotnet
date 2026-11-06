using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Attestation parity with the reference: the Intel signed body (attest-intel-collateral.ts:242), the AMD pin (attest-amd-snp.ts:83), malformed
/// allowlists never read as no list, the evaluation floor (attest-intel-collateral.ts:458) and the OCSP refusals (attest-nvidia-ocsp.ts:195, :269, :297).</summary>
public class AttestParityTests
{
    static JD J(string json) => (JD)Pca.ParseJson(json)!;

    // ---- the signed body

    static (string Hex, CertKey Key) SignRaw(string raw)
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sig = ec.SignHash(SHA256.HashData(Encoding.UTF8.GetBytes(raw)), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return (Convert.ToHexString(sig), new CertKey { Ec = ec });
    }

    [Theory]
    [InlineData("tcbInfo")]
    [InlineData("enclaveIdentity")]
    public void TheBodyIsTheSignedBytesNeverALaterDuplicate(string name)
    {
        const string raw = "{\"status\":\"Revoked\"}";
        var (hex, key) = SignRaw(raw);
        var honest = AttestIntelCollateral.VerifySignedJson($"{{\"{name}\":{raw},\"signature\":\"{hex}\"}}", name, key);
        Assert.Equal("", honest.Why);
        Assert.Equal("Revoked", honest.Body!["status"]);

        var forged = AttestIntelCollateral.VerifySignedJson($"{{\"{name}\":{raw},\"{name}\":{{\"status\":\"UpToDate\"}},\"signature\":\"{hex}\"}}", name, key);
        Assert.Equal("", forged.Why);
        Assert.Equal("Revoked", forged.Body!["status"]);
    }

    [Fact]
    public void ATamperedBodyAndAnInvalidDocumentAreStillRefused()
    {
        const string raw = "{\"status\":\"Revoked\"}";
        var (hex, key) = SignRaw(raw);
        Assert.Equal("tcbInfo signature does not verify under the TCB Signing certificate",
            AttestIntelCollateral.VerifySignedJson($"{{\"tcbInfo\":{{\"status\":\"UpToDate\"}},\"signature\":\"{hex}\"}}", "tcbInfo", key).Why);
        Assert.Equal("tcbInfo document is not valid JSON", AttestIntelCollateral.VerifySignedJson($"{{\"tcbInfo\":{raw},,}}", "tcbInfo", key).Why);
    }

    // ---- the AMD pin

    static readonly string Hex96 = new('a', 96);
    static readonly string Amd = """{"family":"milan","binding":"report-data","policy":{"measurements":["@H"]}}""".Replace("@H", Hex96);

    [Fact]
    public void TheConfigurationCannotReplaceTheArkPin()
    {
        var cfg = J(Amd);
        cfg["trustAnchorArkSpkiSha384"] = new string('b', 96);
        Assert.Equal(AmdVerifier.ArkSpkiSha384["milan"], AmdVerifier.Create(cfg).Pin);
    }

    [Fact]
    public void TheHarnessSeamIsScopedToTheVectorVerifier()
    {
        var cfg = J(Amd);
        cfg["trustAnchorArkSpkiSha384"] = new string('b', 96);
        Assert.NotNull(Conf.VectorVerifier("amd-sev-snp", cfg));
        Assert.Null(AttestAmd.HarnessArkPin.Value);
        AttestAmd.HarnessArkPin.Value = new string('b', 96);
        try { Assert.Equal(new string('b', 96), AmdVerifier.Create(J(Amd)).Pin); }
        finally { AttestAmd.HarnessArkPin.Value = null; }
    }

    // ---- malformed allowlists

    static readonly string Intel = """{"binding":"report-data","policy":{"mrtds":["@H"]}}""".Replace("@H", Hex96);
    static readonly string Maa = """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["@H"]}}""".Replace("@H", Hex96);
    static readonly string Maa2 = """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["@H"]}}""".Replace("@H", Hex96);
    const string Gcp = """{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:aa"]}}""";

    static string Refusal(string vendor, string baseCfg, string key, object? value)
    {
        var cfg = J(baseCfg);
        ((JD)cfg["policy"]!)[key] = value;
        return Assert.Throws<ArgumentException>(() => AttestationVerifiers.FromConfig(vendor, cfg)).Message;
    }

    static JL Mixed() => new() { "aa", new Num("1") };

    [Theory]
    [InlineData("amd-sev-snp", "hostData", "createAmdSnpVerifier: policy")]
    [InlineData("amd-sev-snp", "chipIds", "createAmdSnpVerifier: policy")]
    [InlineData("intel-tdx-dcap", "fmspcs", "createIntelDcapVerifier: policy")]
    [InlineData("intel-tdx-dcap", "rtmrs", "createIntelDcapVerifier: policy")]
    [InlineData("azure-maa", "sevSnpHostData", "createAzureMaaVerifier: policy")]
    [InlineData("azure-maa", "tdxRtmrs", "createAzureMaaVerifier: policy")]
    [InlineData("azure-maa", "tdxAllowedTcbStatuses", "createAzureMaaVerifier: policy")]
    public void AMixedOrNonListAllowlistRefusesTheConfiguration(string vendor, string key, string where)
    {
        var b = vendor switch { "amd-sev-snp" => Amd, "intel-tdx-dcap" => Intel, _ => Maa };
        Assert.Equal($"{where}: {key} must be a list of strings", Refusal(vendor, b, key, Mixed()));
        Assert.Equal($"{where}: {key} must be a list of strings", Refusal(vendor, b, key, "aa"));
        // absent, null and an empty list are no refusal
        var cfg = J(b);
        ((JD)cfg["policy"]!)[key] = null;
        Assert.NotNull(AttestationVerifiers.FromConfig(vendor, cfg));
        ((JD)cfg["policy"]!)[key] = new JL();
        Assert.NotNull(AttestationVerifiers.FromConfig(vendor, cfg));
        ((JD)cfg["policy"]!)[key] = new JL { "aa" };
        Assert.NotNull(AttestationVerifiers.FromConfig(vendor, cfg));
    }

    [Fact]
    public void AMixedMaaMeasurementListRefusesTheConfiguration()
    {
        Assert.Equal("createAzureMaaVerifier: policy: sevSnpMeasurements must be a list of strings", Refusal("azure-maa", Maa2, "sevSnpMeasurements", Mixed()));
        Assert.Equal("createAzureMaaVerifier: policy: tdxMrtds must be a list of strings", Refusal("azure-maa", Maa, "tdxMrtds", Mixed()));
    }

    [Theory]
    [InlineData("allowedTeeTypes")]
    [InlineData("allowedSwVersions")]
    public void ANonListGcpListRefusesTheConfiguration(string key)
    {
        Assert.Equal($"createGcpConfidentialSpaceVerifier: policy.{key} must be a list", Refusal("gcp-confidential-space", Gcp, key, "x"));
        var cfg = J(Gcp);
        ((JD)cfg["policy"]!)[key] = null;
        Assert.NotNull(AttestationVerifiers.FromConfig("gcp-confidential-space", cfg));
    }

    [Theory]
    [InlineData("denyDriverVersions")]
    [InlineData("denyVbiosVersions")]
    public void AMixedFirmwareDenyListRefuses(string key)
    {
        Assert.Equal($"nvidiaCollateralHook: firmware: {key} must be a list of strings",
            Assert.Throws<ArgumentException>(() => FirmwarePolicy.Compile(new JD { [key] = Mixed() })).Message);
        Assert.Empty(FirmwarePolicy.Compile(new JD { [key] = null }).DenyD);
    }

    [Fact]
    public void FirmwareDenyEntriesStillApply()
    {
        var p = FirmwarePolicy.Compile(new JD { ["denyDriverVersions"] = new JL { "1.2" }, ["denyVbiosVersions"] = new JL { "96.00" } });
        Assert.Single(p.DenyD);
        Assert.Single(p.DenyV);
    }

    [Fact]
    public void AMixedRequireCrlIssuersListRefuses()
    {
        var col = new JD { ["rimRootSpkiSha256"] = new JL { "aa" }, ["requireCrlIssuers"] = Mixed() };
        Assert.Equal("nvidiaCollateralHook: requireCrlIssuers must be a list of strings", Assert.Throws<ArgumentException>(() => NvidiaHook.Create(col)).Message);
    }

    // ---- collateral policy

    [Fact]
    public void AMixedAcceptStatusesListRefusesAndAValidOneIsKept()
    {
        Assert.Equal("createIntelDcapVerifier: policy.collateral: acceptStatuses must be a list of strings",
            Assert.Throws<ArgumentException>(() => IntelVerifier.CollateralPolicyOf(new JD { ["acceptStatuses"] = new JL { "SWHardeningNeeded", new Num("1") } })).Message);
        var c = IntelVerifier.CollateralPolicyOf(new JD { ["acceptStatuses"] = new JL { "SWHardeningNeeded" } });
        Assert.True(c.HasAccept);
        Assert.Equal(new[] { "SWHardeningNeeded" }, c.AcceptStatuses);
        Assert.False(IntelVerifier.CollateralPolicyOf(new JD { ["acceptStatuses"] = null }).HasAccept);
    }

    [Fact]
    public void TheEvaluationFloorIsCoercedAndNeverDropped()
    {
        foreach (var (raw, want) in new (object, double)[] { (new Num("5"), 5), ("5", 5), (" 7 ", 7), (true, 1) })
        {
            var c = IntelVerifier.CollateralPolicyOf(new JD { ["minTcbEvaluationDataNumber"] = raw });
            Assert.True(c.HasMinEval);
            Assert.Equal(want, c.MinEval);
        }
        Assert.False(IntelVerifier.CollateralPolicyOf(new JD()).HasMinEval);
        Assert.False(IntelVerifier.CollateralPolicyOf(new JD { ["minTcbEvaluationDataNumber"] = null }).HasMinEval);
        Assert.Equal("createIntelDcapVerifier: policy.collateral: minTcbEvaluationDataNumber must be a number",
            Assert.Throws<ArgumentException>(() => IntelVerifier.CollateralPolicyOf(new JD { ["minTcbEvaluationDataNumber"] = "abc" })).Message);
    }

    // ---- OCSP

    static byte[] Tlv(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        Assert.True(body.Length < 128);
        return new[] { tag, (byte)body.Length }.Concat(body).ToArray();
    }
    static NvidiaOcsp.Node Top(byte[] b) => NvidiaOcsp.ReadNode(b, 0, b.Length);
    static byte[] Gt(string s) => Tlv(0x18, Encoding.ASCII.GetBytes(s));

    [Fact]
    public void AValidNextUpdateIsRead()
    {
        var b = Tlv(0xa0, Gt("20300101000000Z"));
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z").ToUnixTimeMilliseconds(), NvidiaOcsp.NextUpdateOf(b, Top(b)));
    }

    [Fact]
    public void AMalformedNextUpdateRejectsTheResponse()
    {
        foreach (var b in new[]
        {
            Tlv(0xa0, Tlv(0x17, Encoding.ASCII.GetBytes("300101000000Z"))), // UTCTime
            Tlv(0xa0, Gt("not a time")),
            Tlv(0xa0, Gt("20300101000000Z"), Gt("20300101000000Z")),
            Tlv(0xa0),
        })
            Assert.Throws<AttestError>(() => NvidiaOcsp.NextUpdateOf(b, Top(b)));
    }

    static byte[] GoodCert()
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest("CN=x", k, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)).RawData;
    }

    [Fact]
    public void AMalformedEmbeddedCertificateRejectsTheResponse()
    {
        var garbage = Tlv(0x30, Tlv(0x02, new byte[] { 1 }));
        var seq = Tlv(0x30, garbage);
        var one = Tlv(0xa0, seq);
        Assert.Throws<AttestError>(() => NvidiaOcsp.EmbeddedCerts(one, Top(one)));
        var two = Tlv(0xa0, Tlv(0x30), Tlv(0x30));
        Assert.Throws<AttestError>(() => NvidiaOcsp.EmbeddedCerts(two, Top(two)));
        var none = Tlv(0xa0);
        Assert.Throws<AttestError>(() => NvidiaOcsp.EmbeddedCerts(none, Top(none)));
    }

    [Fact]
    public void AnEmptyCertificateListIsNoCertificate()
    {
        var b = Tlv(0xa0, Tlv(0x30));
        Assert.Empty(NvidiaOcsp.EmbeddedCerts(b, Top(b)));
    }

    [Fact]
    public void AValidEmbeddedCertificateIsRead()
    {
        var c = GoodCert();
        // long form lengths: a real certificate is over 127 bytes
        byte[] Long(byte tag, byte[] body) => (body.Length < 256 ? new byte[] { tag, 0x81, (byte)body.Length } : new byte[] { tag, 0x82, (byte)(body.Length >> 8), (byte)body.Length }).Concat(body).ToArray();
        var b = Long(0xa0, Long(0x30, c));
        var got = NvidiaOcsp.EmbeddedCerts(b, Top(b));
        Assert.Equal(c, Assert.Single(got).Raw);
    }

    const string Sha256Rsa = "1.2.840.113549.1.1.11";

    [Fact]
    public void APkcs1SignatureUnderAnRsaPssKeyIsRefused()
    {
        using var rsa = RSA.Create(2048);
        var tbs = new byte[] { 1, 2, 3 };
        var sig = rsa.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(NvidiaOcsp.SigOk(Sha256Rsa, tbs, sig, new CertKey { Type = "rsa", Rsa = rsa }));
        Assert.False(NvidiaOcsp.SigOk(Sha256Rsa, tbs, sig, new CertKey { Type = "rsa-pss", Rsa = rsa }));
    }

    // ---- outer and inner signature algorithm (X509_verify)

    static byte[] Rewrap(byte[] tbs, ECDsa key)
    {
        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteEncodedValue(tbs);
            w.WriteEncodedValue(Convert.FromHexString("300A06082A8648CE3D040302")); // ecdsa-with-SHA256
            w.WriteBitString(key.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
        return w.Encode();
    }

    [Fact]
    public void AnOuterAlgorithmThatDiffersFromTheTbsAlgorithmIsRefused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var self = AttestCerts.ParseDer(new CertificateRequest("CN=x", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)).RawData);
        var ck = AttestCerts.KeyOf(self);
        var tbs = self.RawTbs;
        Assert.True(AttestCerts.SigOk(AttestCerts.ParseDer(Rewrap(tbs, key)), ck));

        var at = tbs.AsSpan().IndexOf(Convert.FromHexString("06082A8648CE3D040302"));
        Assert.True(at > 0);
        var changed = (byte[])tbs.Clone();
        changed[at + 9] = 3; // ecdsa-with-SHA384 inside the signed bytes; the outer one stays SHA-256
        var c = AttestCerts.ParseDer(Rewrap(changed, key));
        Assert.False(c.AlgsAgree);
        Assert.False(AttestCerts.SigOk(c, ck));
    }

    // ---- the delegated responder's issuer check

    static (AttCert Issuer, ECDsa Key) Issuer(string cn, byte[]? ski, X509KeyUsageFlags? ku)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        if (ski != null) req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(ski, false));
        if (ku is X509KeyUsageFlags f) req.CertificateExtensions.Add(new X509KeyUsageExtension(f, true));
        return (AttestCerts.ParseDer(req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)).RawData), key);
    }

    static AttCert Responder(string issuerCn, ECDsa issuerKey, byte[]? aki)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=responder", key, HashAlgorithmName.SHA256);
        if (aki != null) req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(aki));
        return AttestCerts.ParseDer(req.Create(new X500DistinguishedName(issuerCn), X509SignatureGenerator.CreateForECDsa(issuerKey),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new byte[] { 3 }).RawData);
    }

    static readonly byte[] Id1 = Enumerable.Repeat((byte)1, 20).ToArray(), Id2 = Enumerable.Repeat((byte)2, 20).ToArray();

    [Fact]
    public void CheckIssuedComparesNameKeyIdAndKeyUsage()
    {
        var (i, k) = Issuer("CN=ca", Id1, X509KeyUsageFlags.KeyCertSign);
        Assert.True(NvidiaVerifier.CheckIssued(Responder("CN=ca", k, Id1), i));
        Assert.False(NvidiaVerifier.CheckIssued(Responder("CN=other", k, Id1), i));
        Assert.False(NvidiaVerifier.CheckIssued(Responder("CN=ca", k, Id2), i));
        Assert.True(NvidiaVerifier.CheckIssued(Responder("CN=ca", k, null), i));

        var (noSki, k2) = Issuer("CN=ca", null, X509KeyUsageFlags.KeyCertSign);
        Assert.True(NvidiaVerifier.CheckIssued(Responder("CN=ca", k2, Id2), noSki));

        var (noCertSign, k3) = Issuer("CN=ca", Id1, X509KeyUsageFlags.DigitalSignature);
        Assert.False(NvidiaVerifier.CheckIssued(Responder("CN=ca", k3, Id1), noCertSign));

        var (noKu, k4) = Issuer("CN=ca", Id1, null);
        Assert.True(NvidiaVerifier.CheckIssued(Responder("CN=ca", k4, Id1), noKu));
    }

    [Fact]
    public void AMalformedKeyIdentifierIsNotIssued()
    {
        var (i, k) = Issuer("CN=ca", Id1, X509KeyUsageFlags.KeyCertSign);
        var r = Responder("CN=ca", k, Id1);
        r.Exts = new List<LenientExt> { new("2.5.29.35", false, new byte[] { 0x04, 0x01, 0x00 }) };
        Assert.False(NvidiaVerifier.CheckIssued(r, i));
    }
}
