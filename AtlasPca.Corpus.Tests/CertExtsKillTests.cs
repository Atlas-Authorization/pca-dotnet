// SPDX-License-Identifier: Apache-2.0
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The extensions X509Certificate.checkIssued decodes (OpenSSL x509v3_cache_extensions), on really signed certificates.
/// Rows marked strict are refused here where the reference decodes them.</summary>
public class CertExtsKillTests
{
    const string Bc = "2.5.29.19", Ku = "2.5.29.15", Ns = "2.16.840.1.113730.1.1", Eku = "2.5.29.37", San = "2.5.29.17", Nc = "2.5.29.30", Crl = "2.5.29.31";

    static byte[] B(params int[] x) => x.Select(i => (byte)i).ToArray();

    static byte[] E(int tag, params byte[][] parts)
    {
        var body = parts.SelectMany(p => p).ToArray();
        Assert.True(body.Length < 0x80);
        return new[] { (byte)tag, (byte)body.Length }.Concat(body).ToArray();
    }

    static readonly byte[] Oid = E(0x06, B(0x2a));
    static readonly byte[] Dns = E(0x82, B(0x78));
    static readonly byte[] Name = E(0x30, E(0x31, E(0x30, E(0x06, B(0x55, 4, 3)), E(0x0c, B(0x78)))));

    static bool Decodes(string oid, byte[] value)
    {
        try
        {
            CertExts.Check(new AttCert { Exts = new List<LenientExt> { new(oid, false, value) } });
            return true;
        }
        catch (AttestError) { return false; }
    }

    static void Good(string oid, params byte[][] values)
    {
        foreach (var v in values) Assert.True(Decodes(oid, v), Convert.ToHexString(v));
    }

    static void Bad(string oid, params byte[][] values)
    {
        foreach (var v in values) Assert.False(Decodes(oid, v), Convert.ToHexString(v));
    }

    [Fact]
    public void BasicConstraintsAsOpenSslDecodesThem()
    {
        byte[] yes = E(1, B(0xff)), three = E(2, B(3));
        Good(Bc, E(0x30), E(0x30, yes), E(0x30, E(1, B(0))), E(0x30, three), E(0x30, yes, three), E(0x30, E(2, B(0, 0x80))), E(0x30).Concat(B(5, 0)).ToArray());
        Bad(Bc, E(0x31), E(0x30, E(1)), E(0x30, E(1, B(0xff, 0xff))), E(0x30, E(2)), E(0x30, E(2, B(0xff))), E(0x30, E(2, B(0x80))),
            E(0x30, E(2, B(0, 1))), E(0x30, E(2, B(0xff, 0x7f))), E(0x30, E(2, B(0xff, 0x80))),
            E(0x30, three, yes), E(0x30, yes, yes), E(0x30, three, three), E(0x30, yes, three, E(5)), E(0x30, E(5)), B(0x30));
    }

    [Theory]
    [InlineData(Ku)]
    [InlineData(Ns)]
    public void ABitStringExtension(string oid)
    {
        Good(oid, E(3, B(0, 4)), E(3, B(0)), E(3, B(7)));
        Bad(oid, E(3), E(3, B(8)), E(4, B(0)), E(0x23, B(0)));
    }

    [Fact]
    public void ExtendedKeyUsageIsASequenceOfOids()
    {
        Good(Eku, E(0x30), E(0x30, Oid, Oid));
        Bad(Eku, E(0x31), E(0x30, E(5)), E(0x30, E(6)), E(0x30, Oid, E(6, B(0x81))));
    }

    [Fact]
    public void SubjectAltNameIsASequenceOfGeneralNames()
    {
        Good(San, E(0x30), E(0x30, E(0x81, B(0x78))), E(0x30, Dns), E(0x30, E(0x86, B(0x78))), E(0x30, E(0x87, B(1, 2, 3, 4))),
            E(0x30, E(0x88, B(0x2a))), E(0x30, E(0xa0, Oid, E(0xa0, E(0x0c)))), E(0x30, E(0xa4, Name)), E(0x30, Dns, E(0xa4, Name)));
        Bad(San, E(0x31), E(0x30, E(0x88)), E(0x30, E(0x88, B(0x81))),
            E(0x30, E(0xa0)), E(0x30, E(0xa0, Oid)), E(0x30, E(0xa0, E(4), E(0xa0, E(0x0c)))), E(0x30, E(0xa0, Oid, E(0x30, E(0x0c)))),
            E(0x30, E(0xa0, Oid, E(0xa0))), E(0x30, E(0xa0, Oid, E(0xa0, E(0x0c), E(0x0c)))), E(0x30, E(0xa0, Oid, E(0xa0, E(0x0c)), E(5))),
            E(0x30, E(0xa4)), E(0x30, E(0xa4, E(4))), E(0x30, E(0xa4, Name, E(5))), E(0x30, E(0xa4, E(0x30, E(4)))),
            E(0x30, E(0x80)), E(0x30, E(0x83)), E(0x30, E(0x84)), E(0x30, E(0x85)), E(0x30, E(0x89)), E(0x30, E(4)), E(0x30, Dns, E(4)),
            E(0x30, E(0xa3)), E(0x30, E(0xa5))); // the last two are strict
    }

    static byte[] Tree(params byte[][] limits) => E(0x30, new[] { Dns }.Concat(limits).ToArray());

    [Fact]
    public void NameConstraintsDecodeEverySubtree()
    {
        byte[] Lists(params byte[][] l) => E(0x30, l);
        Good(Nc, Lists(), Lists(E(0xa0)), Lists(E(0xa1)), Lists(E(0xa0, Tree()), E(0xa1, Tree(), Tree())),
            Lists(E(0xa0, Tree(E(0x80, B(0))))), Lists(E(0xa0, Tree(E(0x81, B(5))))), Lists(E(0xa0, Tree(E(0x80, B(0)), E(0x81, B(5))))),
            Lists(E(0xa0, Tree(E(0x80, B(0xff))))), Lists(E(0xa0, Tree(E(0x80, B(0, 0x80))))), Lists(E(0xa0, Tree(E(0x80, B(0xff, 0x7f))))));
        Bad(Nc, E(0x31), Lists(E(0xa1), E(0xa0)), Lists(E(0xa0), E(0xa0)), Lists(E(0xa1), E(0xa1)), Lists(E(0x82)),
            Lists(E(0xa0, E(4))), Lists(E(0xa0, E(0x30))), Lists(E(0xa0, E(0x30, E(4)))), Lists(E(0xa1, E(0x30, E(4)))), Lists(E(0xa0, Tree(), E(4))),
            Lists(E(0xa0, Tree(E(0x81, B(5)), E(0x80, B(0))))), Lists(E(0xa0, Tree(E(0x80, B(0)), E(0x80, B(0))))), Lists(E(0xa0, Tree(E(0x81, B(0)), E(0x81, B(0))))),
            Lists(E(0xa0, Tree(E(0x82, B(0))))), Lists(E(0xa0, Tree(E(0x80)))), Lists(E(0xa0, Tree(E(0x81)))),
            Lists(E(0xa0, Tree(E(0x80, B(0, 1))))), Lists(E(0xa0, Tree(E(0x80, B(0xff, 0x80))))));
    }

    [Fact]
    public void CrlDistributionPointsDecodeEveryField()
    {
        byte[] Dp(params byte[][] f) => E(0x30, E(0x30, f));
        byte[] name = E(0xa0, E(0xa0, Dns)), why = E(0x81, B(0, 0x80)), who = E(0xa2, Dns);
        Good(Crl, E(0x30), Dp(), Dp(name), Dp(why), Dp(who), Dp(name, why, who), E(0x30, E(0x30, name), E(0x30, who)), Dp(E(0xa0, E(0xa0))));
        Bad(Crl, E(0x31), E(0x30, E(4)), E(0x30, E(0x30), E(4)), Dp(E(0xa1)), Dp(why, name), Dp(who, why), Dp(name, name), Dp(why, why), Dp(who, who),
            Dp(E(0x81)), Dp(E(0x81, B(8))), Dp(E(0xa2, E(4))), Dp(name, E(0xa2, E(4))), Dp(E(0xa0)), Dp(E(0xa0, E(0xa0), E(0xa0))), Dp(E(0xa0, E(0xa0, E(4)))),
            Dp(E(0xa0, E(0xa1)))); // the last is strict
    }

    [Fact]
    public void ProxyCertInfoIsRefused() => // strict
        Bad("1.3.6.1.5.5.7.1.14", E(0x30), B(1));

    [Fact]
    public void TheRefusalNamesAMalformedExtension() =>
        Assert.Equal("certificate extension is malformed", Assert.Throws<AttestError>(() =>
            CertExts.Check(new AttCert { Exts = new List<LenientExt> { new("1.3.6.1.5.5.7.1.14", false, E(0x30)) } })).Message);

    [Theory]
    [InlineData(Bc)]
    [InlineData(Ku)]
    [InlineData(Ns)]
    [InlineData(Eku)]
    [InlineData(San)]
    [InlineData(Nc)]
    [InlineData(Crl)]
    public void ARepeatedOneIsRefusedEvenWhenEachDecodes(string oid)
    {
        var good = oid is Ku or Ns ? E(3, B(0, 4)) : E(0x30);
        var one = new LenientExt(oid, false, good);
        CertExts.Check(new AttCert { Exts = new List<LenientExt> { one } });
        Assert.Throws<AttestError>(() => CertExts.Check(new AttCert { Exts = new List<LenientExt> { one, one } }));
    }

    [Fact]
    public void OtherExtensionsAreNotDecoded() => Good("1.2.3", B(0xff));

    // ---- X509_check_issued, either certificate

    static readonly ECDsa UpKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), LowKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    static AttCert Signed(string cn, ECDsa key, string issuer, ECDsa signer, byte[][] extra, string? oid)
    {
        var r = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256);
        if (oid != null) foreach (var v in extra) r.CertificateExtensions.Add(new X509Extension(oid, v, false));
        var now = DateTimeOffset.UtcNow;
        return AttestCerts.ParseDer(r.Create(new X500DistinguishedName("CN=" + issuer), X509SignatureGenerator.CreateForECDsa(signer), now.AddDays(-1), now.AddDays(1), B(1)).RawData);
    }

    [Theory]
    [InlineData(Bc)]
    [InlineData(Ku)]
    [InlineData(Eku)]
    [InlineData(San)]
    [InlineData(Nc)]
    [InlineData(Crl)]
    public void AMalformedExtensionOnEitherCertificateMeansNotIssued(string oid)
    {
        var junk = new[] { E(5) };
        var none = Array.Empty<byte[]>();
        Assert.True(NvidiaVerifier.CheckIssued(Signed("low", LowKey, "up", UpKey, none, null), Signed("up", UpKey, "up", UpKey, none, null)));
        Assert.False(NvidiaVerifier.CheckIssued(Signed("low", LowKey, "up", UpKey, junk, oid), Signed("up", UpKey, "up", UpKey, none, null)));
        Assert.False(NvidiaVerifier.CheckIssued(Signed("low", LowKey, "up", UpKey, none, null), Signed("up", UpKey, "up", UpKey, junk, oid)));
    }

    [Fact]
    public void AWellFormedSetOfExtensionsStaysIssued()
    {
        var up = Signed("up", UpKey, "up", UpKey, new[] { E(0x30, E(1, B(0xff))) }, Bc);
        Assert.True(NvidiaVerifier.CheckIssued(Signed("low", LowKey, "up", UpKey, new[] { E(0x30, Dns, E(0xa0, Oid, E(0xa0, E(0x0c)))) }, San), up));
        Assert.True(NvidiaVerifier.CheckIssued(Signed("low", LowKey, "up", UpKey, new[] { E(0x30, E(0x30, E(0xa0, E(0xa0, E(0x86, B(0x78)))))) }, Crl), up));
    }
}
