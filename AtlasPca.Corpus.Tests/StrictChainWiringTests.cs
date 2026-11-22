using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The strict chain profile (packages/pca/src/x509-strict.ts strictChainError) at each chain site: MAA x5c (attest-azure-maa.ts:395, :411),
/// GCP x5c (attest-gcp-confidential-space.ts:384) and the NVIDIA device and RIM signer chains (attest-nvidia-spdm.ts:224).</summary>
public class StrictChainWiringTests
{
    sealed record Spec(bool? Ca = null, int? PathLen = null, X509KeyUsageFlags? Ku = null, string? Crit = null, bool CritEku = false);

    static readonly Spec Leaf = new(Ca: false, CritEku: true);
    static readonly Spec Ca = new(Ca: true, Ku: X509KeyUsageFlags.KeyCertSign);
    static readonly long Now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>A leaf-first DER chain, every link signed by the next (the last self-signed), all P-384.</summary>
    static List<byte[]> Build(params Spec[] specs)
    {
        var keys = specs.Select(_ => ECDsa.Create(ECCurve.NamedCurves.nistP384)).ToArray();
        var outp = new List<byte[]>();
        for (int i = 0; i < specs.Length; i++)
        {
            var s = specs[i];
            var req = new CertificateRequest("CN=c" + i, keys[i], HashAlgorithmName.SHA384);
            if (s.Ca is bool ca) req.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, s.PathLen.HasValue, s.PathLen ?? 0, true));
            if (s.Ku is X509KeyUsageFlags ku) req.CertificateExtensions.Add(new X509KeyUsageExtension(ku, true));
            if (s.CritEku) req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            if (s.Crit is string oid) req.CertificateExtensions.Add(new X509Extension(new Oid(oid), new byte[] { 5, 0 }, true));
            int up = i + 1 < specs.Length ? i + 1 : i;
            var cert = req.Create(new X500DistinguishedName("CN=c" + up), X509SignatureGenerator.CreateForECDsa(keys[up]),
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new[] { (byte)(i + 1) });
            outp.Add(cert.RawData);
        }
        return outp;
    }

    static string Pem(byte[] der) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    static string Spki(byte[] der) => AttestCerts.KeyOf(AttestCerts.ParseDer(der)).SpkiSha256();
    static JL X5c(IEnumerable<byte[]> chain) => chain.Select(d => (object?)Convert.ToBase64String(d)).ToList();

    static string Maa(List<byte[]> chain, string? spki = null, byte[]? rootCert = null)
    {
        var anchors = new JD();
        if (spki != null) anchors["rootSpkiSha256"] = new JL { spki };
        if (rootCert != null) anchors["rootCertsPem"] = new JL { Pem(rootCert) };
        var v = MaaVerifier.Create(new JD { ["trustedIssuers"] = new JL { "https://maa.example" }, ["trustAnchors"] = anchors, ["policy"] = new JD { ["sevSnpMeasurements"] = new JL { new string('a', 96) } } });
        return v.VerifyX5cChain(X5c(chain), Now).Why;
    }

    static GcpVerifier GcpV(string? spki = null, byte[]? rootCert = null)
    {
        var anchors = new JD();
        if (spki != null) anchors["trustedKeySpki"] = new JL { spki };
        if (rootCert != null) anchors["rootCertsPem"] = new JL { Pem(rootCert) };
        return GcpVerifier.Create(new JD { ["trustedIssuers"] = new JL { "https://confidentialcomputing.googleapis.com" }, ["trustAnchors"] = anchors, ["policy"] = new JD { ["imageDigests"] = new JL { "sha256:" + new string('a', 64) } } });
    }

    static string Gcp(List<byte[]> chain, string? spki = null, byte[]? rootCert = null) => GcpV(spki, rootCert).VerifyJwkX5cChain(X5c(chain), Now);

    static string Nvidia(List<byte[]> chain) => NvidiaVerifier.VerifyDeviceChain(string.Concat(chain.Select(Pem)), new[] { Spki(chain[^1]) }, Now).Why;

    const string LeafCa = "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)";

    /// <summary>The refusals over a three-certificate chain: the specs and the profile reason.</summary>
    static IEnumerable<(Spec[] Specs, string Why, bool RoleOfIssuer)> Bad()
    {
        yield return (new[] { new Spec(Ca: true), Ca, Ca }, LeafCa, false);
        yield return (new[] { Leaf, new Spec(Ca: false), Ca }, "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)", true);
        yield return (new[] { Leaf, new Spec(), Ca }, "issuer certificate at depth 1 has no BasicConstraints (not a CA)", true);
        yield return (new[] { Leaf, new Spec(Ca: true, Ku: X509KeyUsageFlags.DigitalSignature), Ca }, "issuer certificate at depth 1 keyUsage lacks keyCertSign", true);
        yield return (new[] { Leaf, Ca, new Spec(Ca: true, PathLen: 0, Ku: X509KeyUsageFlags.KeyCertSign) }, "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)", false);
        yield return (new[] { new Spec(Ca: false, Crit: "1.2.3.4"), Ca, Ca }, "certificate at depth 0 has an unrecognised critical extension 1.2.3.4", false);
        yield return (new[] { Leaf, new Spec(Ca: true, Ku: X509KeyUsageFlags.KeyCertSign, Crit: "1.2.3.4"), Ca }, "certificate at depth 1 has an unrecognised critical extension 1.2.3.4", false);
        yield return (new[] { Leaf, Ca, new Spec(Ca: true, Ku: X509KeyUsageFlags.KeyCertSign, Crit: "1.2.3.4") }, "certificate at depth 2 has an unrecognised critical extension 1.2.3.4", false);
    }

    [Fact]
    public void TheHelperReportsEachReasonAndAcceptsCriticalEku()
    {
        foreach (var (specs, why, _) in Bad()) Assert.Equal(why, AttestDer.StrictChainError(Build(specs)));
        Assert.Null(AttestDer.StrictChainError(Build(Leaf, Ca, Ca)));
        Assert.Equal("certificate extension parse failed: DER: truncated header", AttestDer.StrictChainError(new[] { new byte[] { 0x30 } }));
    }

    [Fact]
    public void MaaAnchoredInTheChain()
    {
        foreach (var (specs, why, _) in Bad())
        {
            var c = Build(specs);
            Assert.Equal("x5c chain profile: " + why, Maa(c, spki: Spki(c[^1])));
        }
        var ok = Build(Leaf, Ca, Ca);
        Assert.Equal("", Maa(ok, spki: Spki(ok[^1])));
    }

    [Fact]
    public void MaaProfileCoversOnlyTheCertificatesUpToTheAnchor()
    {
        // an anchor at index 1: the junk above it is not part of the verified chain
        var above = Build(Leaf, Ca, new Spec(Ca: false, Crit: "1.2.3.4"));
        Assert.Equal("", Maa(above, spki: Spki(above[1])));
        // the anchor itself is in the slice
        var nonCa = Build(Leaf, new Spec(Ca: false), Ca);
        Assert.Equal("x5c chain profile: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)", Maa(nonCa, spki: Spki(nonCa[1])));
        // a bare anchor has no leaf/issuer relationship, but its critical extensions are still read
        var bare = Build(new Spec(Ca: true));
        Assert.Equal("", Maa(bare, spki: Spki(bare[0])));
        var bareCrit = Build(new Spec(Ca: true, Crit: "1.2.3.4"));
        Assert.Equal("x5c chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4", Maa(bareCrit, spki: Spki(bareCrit[0])));
    }

    [Fact]
    public void MaaAnchoredByAnExternalRoot()
    {
        foreach (var (specs, why, _) in Bad())
        {
            var c = Build(specs);
            if (why.Contains("depth 2")) continue; // the root is not in the presented chain here
            Assert.Equal("x5c chain profile: " + why, Maa(c.Take(2).ToList(), rootCert: c[2]));
        }
        var ok = Build(Leaf, Ca, Ca);
        Assert.Equal("", Maa(ok.Take(2).ToList(), rootCert: ok[2]));
        var stranger = Build(Ca);
        Assert.Equal("x5c chain does not anchor in a configured MAA trust root", Maa(ok.Take(2).ToList(), rootCert: stranger[0]));
    }

    [Fact]
    public void GcpPinnedAndRooted()
    {
        foreach (var (specs, why, _) in Bad())
        {
            var c = Build(specs);
            Assert.Equal("x5c chain profile: " + why, Gcp(c, spki: Spki(c[^1])));
            Assert.Equal("x5c chain profile: " + why, Gcp(c, rootCert: c[^1]));
        }
        var ok = Build(Leaf, Ca, Ca);
        Assert.Equal("", Gcp(ok, spki: Spki(ok[^1])));
        Assert.Equal("", Gcp(ok, rootCert: ok[^1]));
    }

    [Fact]
    public void NvidiaDeviceChain()
    {
        foreach (var (specs, why, roleOfIssuer) in Bad())
        {
            // an issuer that is no CA is refused by the earlier link check with its own reason
            var want = roleOfIssuer ? "device chain cert #1 issues a certificate but is not a CA" : "device chain profile: " + why;
            Assert.Equal(want, Nvidia(Build(specs)));
        }
        Assert.Equal("", Nvidia(Build(Leaf, Ca, Ca)));
    }

    // ---- the GCP key is bound to its x5c leaf (attest-gcp-confidential-space.ts resolveTrustedSigningKey, TS 365d0e8ec)

    const string NotLeaf = "signing key not trusted: the JWK key is not the key of its x5c leaf";

    /// <summary>A root and a leaf (leaf first) for a leaf request.</summary>
    static List<byte[]> LeafChain(CertificateRequest leaf)
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ca = new CertificateRequest("CN=ca", caKey, HashAlgorithmName.SHA384);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var from = DateTimeOffset.UtcNow.AddDays(-1); var to = DateTimeOffset.UtcNow.AddDays(1);
        var root = ca.CreateSelfSigned(from, to);
        leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return new List<byte[]> { leaf.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), from, to, new byte[] { 2 }).RawData, root.RawData };
    }

    static JD RsaJwk(RSA k) { var p = k.ExportParameters(false); return new JD { ["kid"] = "k", ["kty"] = "RSA", ["n"] = Pca.B64u(p.Modulus!), ["e"] = Pca.B64u(p.Exponent!) }; }
    static JD EcJwk(ECDsa k) { var p = k.ExportParameters(false); return new JD { ["kid"] = "k", ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Pca.B64u(p.Q.X!), ["y"] = Pca.B64u(p.Q.Y!) }; }

    /// <summary>The reason SigningKey gives for a JWK carrying a chain, under each anchor kind (the same reason under both), and the key's SPKI.</summary>
    static (string Why, string? Spki) Resolve(JD jwk, List<byte[]> chain)
    {
        var withChain = new JD(jwk) { ["x5c"] = X5c(chain) };
        var tok = new JwtParsed { Kid = "k", HasKid = true };
        var jwks = new JD { ["keys"] = new JL { withChain } };
        var (kr, wr) = GcpV(rootCert: chain[^1]).SigningKey(tok, jwks, Now);
        var (kp, wp) = GcpV(spki: Spki(chain[^1])).SigningKey(tok, jwks, Now);
        Assert.Equal(wr, wp);
        Assert.Equal(kr?.SpkiSha256(), kp?.SpkiSha256());
        return (wr, kr?.SpkiSha256());
    }

    [Fact]
    public void GcpRefusesAnAttackerKeyBesideAGenuineChain()
    {
        using var honestRsa = RSA.Create(2048);
        using var attackerRsa = RSA.Create(2048);
        using var honestEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rsaChain = LeafChain(new CertificateRequest("CN=l", honestRsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
        var ecChain = LeafChain(new CertificateRequest("CN=l", honestEc, HashAlgorithmName.SHA384));

        Assert.Equal((NotLeaf, (string?)null), Resolve(RsaJwk(attackerRsa), rsaChain));
        Assert.Equal((NotLeaf, (string?)null), Resolve(EcJwk(attackerEc), ecChain));
        Assert.Equal((NotLeaf, (string?)null), Resolve(RsaJwk(attackerRsa), ecChain)); // another key type
    }

    [Fact]
    public void GcpAcceptsTheLeafKeyBesideItsOwnChainAndABareChain()
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rsaChain = LeafChain(new CertificateRequest("CN=l", rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
        var ecChain = LeafChain(new CertificateRequest("CN=l", ec, HashAlgorithmName.SHA384));

        Assert.Equal(("", Spki(rsaChain[0])), Resolve(RsaJwk(rsa), rsaChain));
        Assert.Equal(("", Spki(ecChain[0])), Resolve(EcJwk(ec), ecChain));
        Assert.Equal(("", Spki(ecChain[0])), Resolve(new JD { ["kid"] = "k" }, ecChain));
    }

    [Fact]
    public void GcpReportsABrokenChainBeforeTheLeafBinding()
    {
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bad = Build(new Spec(Ca: true), Ca);
        var (why, spki) = Resolve(EcJwk(attacker), bad);
        Assert.Null(spki);
        Assert.Equal("signing key not trusted: x5c chain profile: " + LeafCa, why);
    }

    // ---- same batch

    [Fact]
    public void AnEmptyFirmwarePolicyIsAPolicy()
    {
        var p = FirmwarePolicy.Compile(new JD());
        Assert.Equal("driver version 'x' in the GPU report is not parseable", p.Check(new NvidiaRimIds { DriverVersion = "x", VbiosVersion = "1" }));
        Assert.Equal("VBIOS version 'z' in the GPU report is not parseable", p.Check(new NvidiaRimIds { DriverVersion = "1", VbiosVersion = "z" }));
        Assert.Equal("", p.Check(new NvidiaRimIds { DriverVersion = "1", VbiosVersion = "1" }));
    }

    [Theory]
    [InlineData("2026-01-01T00:00:00+24:00")]
    [InlineData("2026-01-01T00:00:00-24:00")]
    [InlineData("2026-01-01T00:00:00+00:60")]
    [InlineData("2026-01-01T00:00:00.000+99:00")]
    public void DateParseRefusesAnOutOfRangeZoneOffset(string s) => Assert.Null(AttestIntelCollateral.JsDateParse(s));

    [Fact]
    public void DateParseAppliesAnInRangeZoneOffset()
    {
        var utc = AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00Z");
        Assert.NotNull(utc);
        Assert.Equal(utc - 3_600_000, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00+01:00"));
    }
}
