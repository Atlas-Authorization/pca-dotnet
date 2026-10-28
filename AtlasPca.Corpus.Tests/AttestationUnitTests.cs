using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact-outcome units for the attestation building blocks and the fail-closed table of every vendor verifier: a verifier built from a
// minimal valid configuration refuses missing evidence and a missing binding with the reference's reason, and a configuration without an
// allowlist / trust anchor is refused at construction (there is no accept-all).
public class AttestationUnitTests
{
    static D J(string json) => (D)Pca.ParseJson(json)!;

    static string Why(Action a)
    {
        try { a(); }
        catch (Exception e) { return e.Message; }
        return "";
    }

    // ---- strict DER

    [Fact]
    public void ReadTlvStrictRefusesEveryNonMinimalOrMalformedLength()
    {
        Assert.Equal(new DerTlv(0x30, 2, 5), AttestDer.ReadTlvStrict(new byte[] { 0x30, 3, 1, 2, 3 }, 0, 5));
        Assert.Equal("DER: truncated header", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30 }, 0, 1)));
        Assert.Equal("DER: multi-byte tags are not supported", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x1f, 0 }, 0, 2)));
        Assert.Equal("DER: unsupported length form", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 0x80 }, 0, 2)));
        Assert.Equal("DER: unsupported length form", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 0x84, 0, 0, 0, 1, 0 }, 0, 7)));
        Assert.Equal("DER: non-minimal length (leading zero)", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 0x82, 0, 0x80 }, 0, 4)));
        Assert.Equal("DER: non-minimal length (long form below 128)", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 0x81, 0x7f, 0 }, 0, 4)));
        Assert.Equal("DER: truncated length", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 0x82, 1 }, 0, 3)));
        Assert.Equal("DER: element overruns its parent", Why(() => AttestDer.ReadTlvStrict(new byte[] { 0x30, 5, 1 }, 0, 3)));
    }

    [Fact]
    public void DerTimeIsStrictRfc5280()
    {
        Assert.Equal(new DerInstant(0, true), AttestDer.ParseDerTime(0x17, "700101000000Z"));
        Assert.Equal(new DerInstant(946684800000, true), AttestDer.ParseDerTime(0x17, "000101000000Z"));
        Assert.Equal(new DerInstant(-631152000000, true), AttestDer.ParseDerTime(0x17, "500101000000Z"));
        Assert.Equal(new DerInstant(1709164800000, true), AttestDer.ParseDerTime(0x18, "20240229000000Z"));
        foreach (var (tag, text) in new[] { (0x17, "700101000000"), (0x17, "701301000000Z"), (0x17, "700001000000Z"), (0x17, "700132000000Z"), (0x17, "700101240000Z"),
            (0x17, "700101006000Z"), (0x17, "700101000060Z"), (0x18, "20230229000000Z"), (0x18, "20240230000000Z"), (0x18, "2024022900000Z"), (0x17, "70010100000aZ"),
            (0x16, "700101000000Z"), (0x17, "7001010000000Z") })
            Assert.False(AttestDer.ParseDerTime(tag, text).Ok, $"{tag} {text}");
    }

    [Fact]
    public void EpochMsRollsFieldsOverLikeDateUtc()
    {
        Assert.Equal(0, AttestDer.EpochMs(1970, 1, 1, 0, 0, 0));
        Assert.Equal(AttestDer.EpochMs(1971, 1, 1, 0, 0, 0), AttestDer.EpochMs(1970, 13, 1, 0, 0, 0));
        Assert.Equal(AttestDer.EpochMs(1970, 3, 1, 0, 0, 0), AttestDer.EpochMs(1970, 2, 29, 0, 0, 0));
        Assert.Equal(86_400_000, AttestDer.EpochMs(1970, 1, 2, 0, 0, 0));
        Assert.Equal(AttestDer.EpochMs(1969, 12, 1, 0, 0, 0), AttestDer.EpochMs(1970, 0, 1, 0, 0, 0));
    }

    [Fact]
    public void ChainRolesRefuseAParseFailureWithTheReferenceText()
    {
        Assert.Equal("certificate extension parse failed: DER: truncated header", AttestDer.CheckChainRoles(new[] { new byte[] { 0x30 } }));
    }

    // ---- the OpenSSL-style JSON.parse wording, the JWS gate

    [Theory]
    [InlineData("{", "Expected property name or '}' in JSON at position 1 (line 1 column 2)")]
    [InlineData("[1,", "Unexpected end of JSON input")]
    [InlineData("", "Unexpected end of JSON input")]
    [InlineData("{\"a\":}", "Unexpected token '}', \"{\"a\":}\" is not valid JSON")]
    [InlineData("{\"a\" 1}", "Expected ':' after property name in JSON at position 5 (line 1 column 6)")]
    [InlineData("{\"a\":1 \"b\"", "Expected ',' or '}' after property value in JSON at position 7 (line 1 column 8)")]
    [InlineData("\"abc", "Unterminated string in JSON at position 4 (line 1 column 5)")]
    [InlineData("-", "No number after minus sign in JSON at position 1 (line 1 column 2)")]
    [InlineData("01", "Unexpected number in JSON at position 1 (line 1 column 2)")]
    [InlineData("1.", "Unterminated fractional number in JSON at position 2 (line 1 column 3)")]
    [InlineData("1e", "Exponent part is missing a number in JSON at position 2 (line 1 column 3)")]
    [InlineData("{} x", "Unexpected non-whitespace character after JSON at position 3 (line 1 column 4)")]
    [InlineData("undefined", "\"undefined\" is not valid JSON")]
    [InlineData("{\"a\":1}", "")]
    public void V8JsonMessages(string text, string want) => Assert.Equal(want, V8Json.Error(text));

    [Fact]
    public void CanonicalBase64urlGateNamesTheFailure()
    {
        Assert.Equal(new byte[] { 1, 2, 3 }, AttestJws.DecodeCanonicalBase64url("AQID"));
        Assert.Equal("non-canonical compact JWS: bad-character", Why(() => AttestJws.DecodeCanonicalBase64url("AQ==")));
        Assert.Equal("non-canonical compact JWS: non-canonical-base64url (impossible length)", Why(() => AttestJws.DecodeCanonicalBase64url("A")));
        Assert.Equal("non-canonical compact JWS: non-canonical-base64url", Why(() => AttestJws.DecodeCanonicalBase64url("AR")));
    }

    [Fact]
    public void JwtParseRefusesEveryMalformedShape()
    {
        string B(string s) => Pca.B64u(Encoding.UTF8.GetBytes(s));
        Assert.Equal("p: empty token", Why(() => AttestJws.ParseJwt("", "p")));
        Assert.Equal("p: a compact JWS has exactly three dot-separated parts", Why(() => AttestJws.ParseJwt("a.b", "p")));
        Assert.Equal("p: empty JWS segment", Why(() => AttestJws.ParseJwt("a..c", "p")));
        Assert.Equal("p: header is not a JSON object", Why(() => AttestJws.ParseJwt($"{B("[]")}.{B("{}")}.AQ", "p")));
        Assert.Equal("p: payload is not a JSON object", Why(() => AttestJws.ParseJwt($"{B("{}")}.{B("1")}.AQ", "p")));
        Assert.Equal("p: header has no alg", Why(() => AttestJws.ParseJwt($"{B("{}")}.{B("{}")}.AQ", "p")));
        Assert.StartsWith("p: malformed JSON segment: Expected property name or '}'", Why(() => AttestJws.ParseJwt($"{B("{")}.{B("{}")}.AQ", "p")));
        Assert.StartsWith("p: malformed signature segment: non-canonical compact JWS", Why(() => AttestJws.ParseJwt($"{B("{\"alg\":\"ES256\"}")}.{B("{}")}.A", "p")));
        var t = AttestJws.ParseJwt($"{B("{\"alg\":\"ES256\",\"kid\":\"k\",\"x5c\":[\"AA\"]}")}.{B("{\"iss\":\"i\"}")}.AQID", "p");
        Assert.Equal(("ES256", "k", true), (t.Alg, t.Kid, t.HasKid));
        Assert.Equal(new[] { "AA" }, t.X5c);
        Assert.Equal(new byte[] { 1, 2, 3 }, t.Signature);
    }

    // ---- small readers

    [Fact]
    public void VbiosVersionIsByteReversedAndRePaired()
    {
        Assert.Equal("96.00.9f.00.04", NvidiaVerifier.FormatVbiosVersion(new byte[] { 0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa }));
    }

    [Fact]
    public void AzureRuntimeDataBindingChecksEveryStep()
    {
        var b = new AttestationBinding("h", "g", 1, "n");
        var bind = AttestUtil.BindingBytes(b);
        var runtime = Encoding.UTF8.GetBytes("{\"user-data\":\"" + AttestUtil.Hex(bind) + "\"}");
        var rd = AttestUtil.Sha256(runtime).Concat(new byte[32]).ToArray();
        Assert.Null(AttestUtil.CheckAzureRuntimeDataBinding(rd, runtime, b));
        Assert.Equal("report_data is not 64 bytes", AttestUtil.CheckAzureRuntimeDataBinding(new byte[63], runtime, b));
        Assert.Equal("report_data[32:64] is not zero (not an Azure runtime-data hash)", AttestUtil.CheckAzureRuntimeDataBinding(AttestUtil.Sha256(runtime).Concat(new byte[31]).Append((byte)1).ToArray(), runtime, b));
        Assert.Equal("sha256(runtime data) does not equal the quote report_data", AttestUtil.CheckAzureRuntimeDataBinding(new byte[64], runtime, b));
        var junk = Encoding.UTF8.GetBytes("nope");
        Assert.Equal("runtime data is not valid JSON", AttestUtil.CheckAzureRuntimeDataBinding(AttestUtil.Sha256(junk).Concat(new byte[32]).ToArray(), junk, b));
        var other = Encoding.UTF8.GetBytes("{\"user-data\":\"" + AttestUtil.Hex(new byte[64]) + "\"}");
        Assert.Equal("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)", AttestUtil.CheckAzureRuntimeDataBinding(AttestUtil.Sha256(other).Concat(new byte[32]).ToArray(), other, b));
    }

    [Fact]
    public void BindingBytesAreConstructedOnlyFromAWellFormedBinding()
    {
        Assert.Equal(64, AttestUtil.BindingBytes(new AttestationBinding("h", "g", 0, "n")).Length);
        Assert.Equal("binding: holderPub required", Why(() => AttestUtil.BindingBytes(new AttestationBinding("", "g", 0, "n"))));
        Assert.Equal("binding: grantRef required", Why(() => AttestUtil.BindingBytes(new AttestationBinding("h", "", 0, "n"))));
        Assert.Equal("binding: nonce required", Why(() => AttestUtil.BindingBytes(new AttestationBinding("h", "g", 0, ""))));
        Assert.Equal("binding: epoch must be a non-negative safe integer", Why(() => AttestUtil.BindingBytes(new AttestationBinding("h", "g", 1.5, "n"))));
        Assert.Equal("binding: epoch must be a non-negative safe integer", Why(() => AttestUtil.BindingBytes(new AttestationBinding("h", "g", -1, "n"))));
        Assert.NotEqual(AttestUtil.BindingBytes(new AttestationBinding("h", "g", 1, "n")), AttestUtil.BindingBytes(new AttestationBinding("h", "g", 2, "n")));
    }

    [Fact]
    public void SplDecodingIsMinimalDerInteger()
    {
        var m = typeof(AttestAmd).GetMethod("DecodeSpl", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        (int, string?) Run(params byte[] v) => ((int, string?))m.Invoke(null, new object[] { v })!;
        Assert.Equal((7, null), Run(0x02, 1, 7));
        Assert.Equal((200, null), Run(0x02, 2, 0, 200));
        Assert.Equal("is not a DER INTEGER", Run(0x04, 1, 7).Item2);
        Assert.Equal("is negative", Run(0x02, 1, 0x80).Item2);
        Assert.Equal("is a non-minimal INTEGER", Run(0x02, 2, 0, 7).Item2);
        Assert.Equal("is out of range (> 255)", Run(0x02, 2, 1, 0).Item2);
        Assert.Equal("has a wrong-length INTEGER", Run(0x02, 3, 0, 0, 1).Item2);
    }

    // ---- the fail-closed table: constructor refusals and absent evidence / binding


    static readonly Dictionary<string, D> MinimalConfigs = new()
    {
        ["amd-sev-snp"] = J("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}"),
        ["intel-tdx-dcap"] = J("{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[\"" + new string('a', 96) + "\"]}}"),
        ["azure-maa"] = J("{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"]}}"),
        ["gcp-confidential-space"] = J("{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]},\"policy\":{\"imageDigests\":[\"sha256:aa\"]}}"),
        ["nvidia-gpu-spdm"] = J("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"1\":\"aa\"}}}"),
    };

    static readonly Dictionary<string, string> NoEvidence = new()
    {
        ["amd-sev-snp"] = "no AMD SEV-SNP evidence for this action",
        ["intel-tdx-dcap"] = "no Intel DCAP quote for this action",
        ["azure-maa"] = "no Azure MAA token for this action",
        ["gcp-confidential-space"] = "no GCP Confidential Space token for this action",
        ["nvidia-gpu-spdm"] = "no NVIDIA GPU evidence for this action",
    };

    [Fact]
    public void EveryVendorRefusesAbsentEvidence()
    {
        foreach (var vendor in AttestationVerifiers.Vendors)
        {
            var v = AttestationVerifiers.FromConfig(vendor, MinimalConfigs[vendor]);
            Assert.Equal(vendor, v.Vendor);
            var b = new AttestationBinding("h", "g", 0, "n");
            foreach (var ev in new D?[] { null, new D(), new D { ["token"] = 1L, ["quote"] = 1L, ["report"] = 1L } })
            {
                var r = v.Verify(ev, b, 1);
                Assert.False(r.Ok, vendor);
                Assert.Equal(NoEvidence[vendor], r.Reason);
            }
        }
    }

    [Fact]
    public void ConstructorsRefuseAcceptAllConfigurations()
    {
        Assert.Equal("unknown attestation vendor \"x\"", Why(() => AttestationVerifiers.FromConfig("x", null)));
        Assert.Equal("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'", Why(() => AttestationVerifiers.FromConfig("amd-sev-snp", J("{}"))));
        Assert.Equal("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'", Why(() => AttestationVerifiers.FromConfig("amd-sev-snp", J("{\"family\":\"milan\"}"))));
        Assert.Equal("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)", Why(() => AttestationVerifiers.FromConfig("amd-sev-snp", J("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[]}}"))));
        Assert.Equal("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'", Why(() => AttestationVerifiers.FromConfig("intel-tdx-dcap", J("{}"))));
        Assert.Equal("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)", Why(() => AttestationVerifiers.FromConfig("intel-tdx-dcap", J("{\"binding\":\"report-data\"}"))));
        Assert.Equal("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)", Why(() => AttestationVerifiers.FromConfig("intel-tdx-dcap", J("{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[\"aa\"]}}"))));
        Assert.Equal("createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs", Why(() => AttestationVerifiers.FromConfig("azure-maa", J("{}"))));
        Assert.StartsWith("createAzureMaaVerifier: trustAnchors must configure at least one MAA root", Why(() => AttestationVerifiers.FromConfig("azure-maa", J("{\"trustedIssuers\":[\"i\"]}"))));
        Assert.StartsWith("createAzureMaaVerifier: policy must set a NON-EMPTY", Why(() => AttestationVerifiers.FromConfig("azure-maa", J("{\"trustedIssuers\":[\"i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"a\"]}}"))));
        Assert.Equal("createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs", Why(() => AttestationVerifiers.FromConfig("gcp-confidential-space", J("{}"))));
        Assert.StartsWith("createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor", Why(() => AttestationVerifiers.FromConfig("gcp-confidential-space", J("{\"trustedIssuers\":[\"i\"]}"))));
        Assert.Equal("createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)", Why(() => AttestationVerifiers.FromConfig("gcp-confidential-space", J("{\"trustedIssuers\":[\"i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"a\"]}}"))));
        Assert.Equal("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)", Why(() => AttestationVerifiers.FromConfig("nvidia-gpu-spdm", J("{}"))));
        Assert.StartsWith("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set", Why(() => AttestationVerifiers.FromConfig("nvidia-gpu-spdm", J("{\"rootSpkiSha256\":[\"a\"]}"))));
        Assert.Equal("createNvidiaSpdmVerifier: measurement index out of range", Why(() => AttestationVerifiers.FromConfig("nvidia-gpu-spdm", J("{\"rootSpkiSha256\":[\"a\"],\"policy\":{\"measurements\":{\"256\":\"aa\"}}}"))));
    }

    [Fact]
    public void IdentityOverridesAreMergedOverAMeasuredIdentity()
    {
        var m = AttestUtil.MergeOverrides(AttestUtil.NewMeasured("rt", "op"), J("{\"model_id\":\"m\",\"operator\":\"o\"}"));
        Assert.Equal(("m", "o", "rt"), ((string)m["model_id"]!, (string)m["operator"]!, (string)m["runtime_measurement"]!));
    }

    [Fact]
    public void FirmwareVersionsCompareComponentWise()
    {
        Assert.Equal(-1, FirmwarePolicy.Cmp(FirmwarePolicy.ParseVersion("535.104.5", 10)!, FirmwarePolicy.ParseVersion("535.104.12", 10)!));
        Assert.Equal(0, FirmwarePolicy.Cmp(FirmwarePolicy.ParseVersion("1.2", 10)!, FirmwarePolicy.ParseVersion("1.2.0", 10)!));
        Assert.Equal(1, FirmwarePolicy.Cmp(FirmwarePolicy.ParseVersion("96.00.9f", 16)!, FirmwarePolicy.ParseVersion("96.00.9e", 16)!));
        Assert.Null(FirmwarePolicy.ParseVersion("1.x", 10));
        Assert.Null(FirmwarePolicy.ParseVersion("1.2g", 16));
        Assert.Null(FirmwarePolicy.ParseVersion("", 10));
    }

    // ---- NVIDIA SPDM version rule

    static SpdmReport SpdmReportOf(byte reqVer, byte respVer)
    {
        var b = new byte[37 + 8 + 32 + 2 + 96];
        b[0] = reqVer; b[1] = 0xe0; b[37] = respVer; b[38] = 0x60;
        return NvidiaVerifier.ParseEvidence(b);
    }

    [Theory]
    [InlineData(0x11, 0x11, true)]
    [InlineData(0x12, 0x12, true)]
    [InlineData(0x10, 0x10, false)]
    [InlineData(0x11, 0x12, false)]
    [InlineData(0x12, 0x11, false)]
    public void NvidiaSpdmVersionMustBeAtLeast11AndAgree(int req, int resp, bool ok)
    {
        var why = NvidiaVerifier.VersionProblem(SpdmReportOf((byte)req, (byte)resp));
        if (ok) Assert.Null(why);
        else Assert.Equal($"SPDM version 0x{req:x}/0x{resp:x} is not an accepted GET_MEASUREMENTS version", why);
    }
}
