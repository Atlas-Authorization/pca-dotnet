using System.Text;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The public names of the core helpers and of the vendor attestation modules, pinned to the reference values.</summary>
public class PcaReferenceNamesTests
{
    [Fact]
    public void WireConstants()
    {
        Assert.Equal(256, PcaConstants.MaxAudLen);
        Assert.Equal(128, PcaConstants.MaxNonceLen);
        Assert.Equal(2, PcaConstants.PcactnVersion);
        Assert.Equal(3_600_000L, PcaConstants.PcactnMaxLifetimeMs);
        Assert.Equal(60_000L, PcaConstants.PcactnMaxSkewMs);
        Assert.Equal(new[] { "trusted", "first_party", "tool", "web", "agent" }, PcaConstants.ProvLevels);
        Assert.Equal(ParamProvenance.TaintLevels, PcaConstants.ProvLevels);
    }

    [Fact]
    public void HashHelpers()
    {
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Convert.ToHexString(PcaHelpers.Sha256(Array.Empty<byte>())).ToLowerInvariant());
        Assert.StartsWith("38b060a751ac9638", Convert.ToHexString(PcaHelpers.Sha384(Array.Empty<byte>())).ToLowerInvariant());
        Assert.Equal("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", PcaHelpers.Sha256B64u(Encoding.ASCII.GetBytes("abc")));
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        Assert.Equal(key, PcaHelpers.DecodeKey(PcaHelpers.EncodeKey(key)));
        Assert.Throws<FormatException>(() => PcaHelpers.Unb64u("AB=="));
        Assert.Equal(new byte[] { 0x61, 0x62 }, PcaHelpers.Utf8("ab"));
    }

    [Fact]
    public void DecodePcactnChecksTheSizeFirstAndTheShapeNext()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PcaHelpers.DecodePcactn(new string(' ', 524289)));
        Assert.Throws<ArgumentException>(() => PcaHelpers.DecodePcactn("[1]"));
        Assert.Throws<ArgumentException>(() => PcaHelpers.DecodePcactn("3"));
        Assert.Equal("x", PcaHelpers.DecodePcactn("{\"a\":\"x\"}")["a"]);
    }

    [Fact]
    public void DerTimeAndPem()
    {
        Assert.Equal(1704164645000d, PcaHelpers.ParseDerTime(0x18, "20240102030405Z"));
        Assert.Equal(1704164645000d, PcaHelpers.ParseDerTime(0x17, "240102030405Z"));
        Assert.True(double.IsNaN(PcaHelpers.ParseDerTime(0x18, "20240230030405Z"))); // Feb 30
        Assert.True(double.IsNaN(PcaHelpers.ParseDerTime(0x18, "20240102030405")));
        Assert.Equal(new byte[] { 1, 2, 3 }, PcaHelpers.PemToDer("junk\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"));
        Assert.Throws<ArgumentOutOfRangeException>(() => PcaHelpers.PemToDer("no certificate"));
    }

    [Fact]
    public async Task SettleAnswersOnlyABooleanInTime()
    {
        Assert.True(await PcaHelpers.Settle(() => Task.FromResult<object?>(true), 1000));
        Assert.False(await PcaHelpers.Settle(() => Task.FromResult<object?>(false), 1000));
        Assert.Null(await PcaHelpers.Settle(() => Task.FromResult<object?>("yes"), 1000));
        Assert.Null(await PcaHelpers.Settle(() => throw new InvalidOperationException("x"), 1000));
        Assert.Null(await PcaHelpers.Settle(async () => { await Task.Delay(5000); return true; }, 50));
    }

    [Fact]
    public void VendorSuiteConstants()
    {
        Assert.Equal("amd-sev-snp-ecdsa-p384", AttestVendors.AmdSnp.Suite);
        Assert.Equal("intel-tdx-dcap-ecdsa-p256", AttestVendors.IntelDcap.Suite);
        Assert.Equal("azure-maa-jwt", AttestVendors.AzureMaa.Suite);
        Assert.Equal(new[] { "ES256", "RS256" }, AttestVendors.AzureMaa.Suites);
        Assert.Equal("gcp-confidential-space-jwt", AttestVendors.GcpConfidentialSpace.Suite);
        Assert.Equal(new[] { "RS256", "ES256" }, AttestVendors.GcpConfidentialSpace.Suites);
        Assert.Equal("https://confidentialcomputing.googleapis.com", AttestVendors.GcpConfidentialSpace.DefaultIssuer);
        Assert.Equal("a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e", AttestVendors.IntelTdx.SgxRootCaSpkiSha256);
        Assert.Equal(new[] { "UpToDate", "SWHardeningNeeded" }, AttestVendors.IntelPcsCollateral.DefaultAcceptedStatuses);
        Assert.Equal(AmdVerifierPins(), AttestVendors.AmdSnp.ArkSpkiSha384.Keys.OrderBy(k => k).ToList());
    }

    static List<string> AmdVerifierPins() => new() { "genoa", "milan", "turin" };

    [Fact]
    public void TeeTypeOfHwModel()
    {
        Assert.Equal("sev-snp", AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel("GCP_AMD_SEV"));
        Assert.Equal("sev-snp", AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel("GCP_AMD_SEV_ES"));
        Assert.Equal("sev-snp", AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel("gcp_amd_sev_future"));
        Assert.Equal("tdx", AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel("GCP_INTEL_TDX"));
        Assert.Null(AttestVendors.GcpConfidentialSpace.TeeTypeOfHwModel("OTHER"));
    }

    [Fact]
    public void IssuerChainHeaderAndCrlSerials()
    {
        Assert.Equal("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
            AttestVendors.IntelPcsCollateral.DecodeIssuerChainHeader("-----BEGIN%20CERTIFICATE-----%0AAA%3D%3D%0A-----END%20CERTIFICATE-----%0A"));
        var revoked = new HashSet<string> { "abc" };
        Assert.True(AttestVendors.IntelPcsCollateral.SerialIsRevoked(revoked, "00ABC"));
        Assert.False(AttestVendors.IntelPcsCollateral.SerialIsRevoked(revoked, "abd"));
    }

    [Fact]
    public void P256PointDecompression()
    {
        // the generator of P-256: compressed (03 || x) to uncompressed (04 || x || y)
        var x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        var y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        var full = AttestVendors.IntelTdx.EcdsaP256PublicKey(Convert.FromHexString("03" + x));
        Assert.Equal("04" + x + y, Convert.ToHexString(full).ToLowerInvariant());
        Assert.Throws<ArgumentException>(() => AttestVendors.IntelTdx.EcdsaP256PublicKey(new byte[10]));
    }

    [Fact]
    public void TdReportFields()
    {
        var body = new byte[584];
        for (int i = 0; i < body.Length; i++) body[i] = (byte)(i % 251);
        var r = AttestVendors.IntelTdx.ParseDcapTdReport(body);
        Assert.Equal(body[136..184], (byte[])r["mrTd"]!);
        Assert.Equal(body[520..584], (byte[])r["reportData"]!);
        Assert.Equal(body, (byte[])r["raw"]!);
        Assert.Throws<ArgumentException>(() => AttestVendors.IntelTdx.ParseDcapTdReport(new byte[583]));
    }

    [Fact]
    public void FetchersNeedATransportAndReadTheJwks()
    {
        Assert.Throws<InvalidOperationException>(() => AttestVendors.AzureMaa.FetchMaaJwks("https://m.example", null));
        var seen = new List<string>();
        var jwks = AttestVendors.AzureMaa.FetchMaaJwks("https://m.example/", u =>
        {
            seen.Add(u);
            return new KdsResponse(true, 200, Encoding.UTF8.GetBytes("{\"keys\":[{\"kid\":\"k1\",\"kty\":\"RSA\",\"x5c\":[\"AA==\"],\"extra\":\"x\"},3]}"));
        });
        Assert.Equal(new[] { "https://m.example/certs" }, seen);
        var k = (D)((List<object?>)jwks["keys"]!)[0]!;
        Assert.Equal("k1", k["kid"]);
        Assert.False(k.ContainsKey("extra"));
        Assert.Single((List<object?>)jwks["keys"]!);
        Assert.Throws<InvalidOperationException>(() => AttestVendors.AzureMaa.FetchMaaJwks("https://m.example", _ => new KdsResponse(false, 503, Array.Empty<byte>())));
    }

    [Fact]
    public void ConfidentialSpaceFetcherFollowsTheOpenIdConfiguration()
    {
        var seen = new List<string>();
        var jwks = AttestVendors.GcpConfidentialSpace.FetchGcpConfidentialSpaceJwks("https://g.example/", u =>
        {
            seen.Add(u);
            return u.EndsWith("openid-configuration")
                ? new KdsResponse(true, 200, Encoding.UTF8.GetBytes("{\"jwks_uri\":\"https://g.example/keys\"}"))
                : new KdsResponse(true, 200, Encoding.UTF8.GetBytes("{\"keys\":[{\"kid\":\"a\",\"alg\":\"RS256\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}"));
        });
        Assert.Equal(new[] { "https://g.example/.well-known/openid-configuration", "https://g.example/keys" }, seen);
        Assert.Equal("a", (string)((D)((List<object?>)jwks["keys"]!)[0]!)["kid"]!);
    }

    [Fact]
    public void OprfModesAndRecorderClock()
    {
        Assert.Equal(0, AtlasPca.Oprf.Oprf.Mode["oprf"]);
        Assert.Equal(1, AtlasPca.Oprf.Oprf.Mode["voprf"]);
        Assert.Equal(2, AtlasPca.Oprf.Oprf.Mode["poprf"]);
        var a = AtlasPca.StoreConformancePkg.HistoryRecorder.Clock();
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Assert.InRange(a, now - 5000, now + 5000);
    }
}
