using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using K = AtlasPca.Corpus.Tests.K05R3AIntelKit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>H9 / H11 / H12: attestation configuration typing. Every refusal is at construction (or, for the Intel evidence, before the
/// missing-collateral branch) and carries the reference's text; nothing falls back to "no policy".</summary>
public class K05HBTests
{
    // ---- H9: NVIDIA

    static JD NvCfg(Action<JD, JD>? tweak = null)
    {
        var pol = new JD { ["measurements"] = new JD { ["1"] = "aa" } };
        var cfg = new JD { ["rootSpkiSha256"] = new JL { "aa" }, ["policy"] = pol };
        tweak?.Invoke(cfg, pol);
        return cfg;
    }

    static string NvRefused(Action<JD, JD> tweak) => Assert.Throws<ArgumentException>(() => NvidiaVerifier.Create(NvCfg(tweak))).Message;

    static JD Col(string key, object? v) => new() { ["rimRootSpkiSha256"] = new JL { "aa" }, [key] = v };

    [Fact]
    public void ANonObjectCollateralRefusesTheVerifier()
    {
        foreach (var bad in new object?[] { "required", new Num("5"), new Num("0"), true, false, "", new JL() })
            Assert.Equal("createNvidiaSpdmVerifier: collateral must be an object", NvRefused((c, _) => c["collateral"] = bad));
    }

    [Fact]
    public void AnAbsentOrNullCollateralStillBuildsWhenMeasurementsArePinned()
    {
        Assert.NotNull(NvidiaVerifier.Create(NvCfg()));
        Assert.NotNull(NvidiaVerifier.Create(NvCfg((c, _) => c["collateral"] = null)));
        Assert.NotNull(NvidiaVerifier.Create(NvCfg((c, _) => c["collateral"] = new JD { ["rimRootSpkiSha256"] = new JL { "aa" } })));
        Assert.Equal("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root", NvRefused((c, _) => c["collateral"] = new JD()));
    }

    [Fact]
    public void ANonStringLeafSubjectRefusesTheVerifier()
    {
        foreach (var bad in new object?[] { new Num("5"), new Num("0"), true, false, new JL(), new JD() })
            Assert.Equal("createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string", NvRefused((_, p) => p["leafSubjectIncludes"] = bad));
        Assert.NotNull(NvidiaVerifier.Create(NvCfg((_, p) => p["leafSubjectIncludes"] = null)));
        Assert.NotNull(NvidiaVerifier.Create(NvCfg((_, p) => p["leafSubjectIncludes"] = "")));
        Assert.NotNull(NvidiaVerifier.Create(NvCfg((_, p) => p["leafSubjectIncludes"] = "GH100")));
    }

    [Fact]
    public void ANonObjectFirmwareRefusesTheHook()
    {
        foreach (var bad in new object?[] { "x", new Num("1"), new Num("0"), true, false, "", new JL() })
            Assert.Equal("nvidiaCollateralHook: firmware must be an object", Assert.Throws<ArgumentException>(() => NvidiaHook.Create(Col("firmware", bad))).Message);
        Assert.NotNull(NvidiaHook.Create(Col("firmware", null)));
        Assert.NotNull(NvidiaHook.Create(Col("firmware", new JD())));
        // reached through the verifier too
        Assert.Equal("nvidiaCollateralHook: firmware must be an object", NvRefused((c, _) => c["collateral"] = Col("firmware", "x")));
    }

    [Fact]
    public void ANonStringFirmwareFloorNamesItsValue()
    {
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion '535'", NvRefused((c, _) => c["collateral"] = Col("firmware", new JD { ["minDriverVersion"] = new Num("535") })));
        Assert.Equal("nvidiaCollateralHook: malformed minVbiosVersion '535'", NvRefused((c, _) => c["collateral"] = Col("firmware", new JD { ["minVbiosVersion"] = new Num("535") })));
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion 'v5'", NvRefused((c, _) => c["collateral"] = Col("firmware", new JD { ["minDriverVersion"] = "v5" })));
        Assert.Equal("nvidiaCollateralHook: malformed minVbiosVersion 'zz'", NvRefused((c, _) => c["collateral"] = Col("firmware", new JD { ["minVbiosVersion"] = "zz" })));
    }

    [Fact]
    public void ADenyListMustBeAnArrayOfParsingStrings()
    {
        string Deny(string key, object? v) => Assert.Throws<ArgumentException>(() => FirmwarePolicy.Compile(new JD { [key] = v })).Message;
        Assert.Equal("nvidiaCollateralHook: malformed denyDriverVersions entry '5'", Deny("denyDriverVersions", new JL { "535.1", new Num("5") }));
        Assert.Equal("nvidiaCollateralHook: malformed denyDriverVersions entry '535.1'", Deny("denyDriverVersions", "535.1"));
        Assert.Equal("nvidiaCollateralHook: malformed denyDriverVersions entry '5'", Deny("denyDriverVersions", new Num("5")));
        Assert.Equal("nvidiaCollateralHook: malformed denyDriverVersions entry 'true'", Deny("denyDriverVersions", true));
        Assert.Equal("nvidiaCollateralHook: malformed denyVbiosVersions entry '5'", Deny("denyVbiosVersions", new JL { "ab", new Num("5") }));
        Assert.Equal("nvidiaCollateralHook: malformed denyVbiosVersions entry 'ab'", Deny("denyVbiosVersions", "ab"));
        Assert.Equal("nvidiaCollateralHook: malformed denyVbiosVersions entry 'null'", Deny("denyVbiosVersions", new JL { null }));
        var ok = FirmwarePolicy.Compile(new JD { ["denyDriverVersions"] = new JL { "535.1" }, ["denyVbiosVersions"] = new JL { "ab" } });
        Assert.Single(ok.DenyD);
        Assert.Single(ok.DenyV);
    }

    [Fact]
    public void RequireCrlIssuersMustListOnlyStrings()
    {
        foreach (var bad in new object?[] { "NVIDIA GH100", new Num("1"), true, new JL { "a", new Num("1") }, new JD() })
            Assert.Equal("nvidiaCollateralHook: requireCrlIssuers must list only strings", Assert.Throws<ArgumentException>(() => NvidiaHook.Create(Col("requireCrlIssuers", bad))).Message);
        Assert.NotNull(NvidiaHook.Create(Col("requireCrlIssuers", null)));
        Assert.NotNull(NvidiaHook.Create(Col("requireCrlIssuers", new JL { "NVIDIA GH100" })));
    }

    // ---- H11 / H12: Intel

    static byte[] U16(int v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)v); return b; }
    static byte[] U32(int v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v); return b; }
    static byte[] Sig(ECDsa k, byte[] m) => k.SignHash(SHA256.HashData(m), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    static AttestationBinding Bind => new("h", "g", 1, "n");
    static readonly string Mrtd = string.Concat(Enumerable.Repeat("11", 48));

    /// <summary>A genuine TDX quote (the collateral kit's PKI) whose report_data is the binding.</summary>
    static byte[] Quote()
    {
        var hdr = new byte[48];
        hdr[0] = 4; hdr[2] = 2; hdr[4] = 0x81;
        var td = new byte[584];
        Array.Fill(td, (byte)0x11, 136, 48);
        AttestUtil.BindingBytes(Bind).CopyTo(td, 520);
        var q = K.AkKey.ExportParameters(false).Q;
        var ak = K.Cat(q.X!, q.Y!);
        var qe = new byte[384];
        SHA256.HashData(ak).CopyTo(qe, 0x140);
        var pem = Encoding.ASCII.GetBytes(K.Pem(K.PckLeaf(Enumerable.Repeat((byte)5, 16).ToArray(), 11)) + K.Pem(K.CaDer) + K.Pem(K.RootDer));
        var outer = K.Cat(qe, Sig(K.PckKey, qe), U16(0), U16(5), U32(pem.Length), pem);
        var sig = K.Cat(Sig(K.AkKey, K.Cat(hdr, td)), ak, U16(6), U32(outer.Length), outer);
        return K.Cat(hdr, td, U32(sig.Length), sig);
    }

    static JD IntelCfg(bool allowMissing, object? polCollateral = null, bool setCollateral = false)
    {
        var pol = new JD { ["mrtds"] = new JL { Mrtd } };
        if (setCollateral) pol["collateral"] = polCollateral;
        return new JD
        {
            ["binding"] = "report-data", ["allowMissingCollateral"] = allowMissing, ["trustAnchorRootCaSpkiSha256"] = K.RootPin, ["policy"] = pol,
        };
    }

    [Fact]
    public void ANonObjectPolicyCollateralRefusesTheVerifier()
    {
        foreach (var bad in new object?[] { "x", new Num("5"), new Num("0"), true, false, "", new JL() })
            Assert.Equal("createIntelDcapVerifier: policy.collateral must be an object",
                Assert.Throws<ArgumentException>(() => IntelVerifier.Create(IntelCfg(false, bad, true))).Message);
        Assert.NotNull(IntelVerifier.Create(IntelCfg(false)));
        Assert.NotNull(IntelVerifier.Create(IntelCfg(false, null, true)));
        Assert.NotNull(IntelVerifier.Create(IntelCfg(false, new JD(), true)));
        Assert.NotNull(IntelVerifier.Create(IntelCfg(false, new JD { ["minTcbEvaluationDataNumber"] = new Num("7") }, true)));
    }

    const string Incomplete = "Intel collateral: collateral incomplete (fail closed)";
    const string Required = "Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)";

    static HardwareResult Verify(bool allowMissing, bool present, object? collateral)
    {
        var ev = new JD { ["quote"] = Convert.ToBase64String(Quote()) };
        if (present) ev["collateral"] = collateral;
        return IntelVerifier.Create(IntelCfg(allowMissing)).Verify(ev, Bind, K.Now);
    }

    [Fact]
    public void ATruthyNonObjectEvidenceCollateralFailsBeforeTheMissingBranch()
    {
        foreach (var allow in new[] { true, false })
            foreach (var bad in new object?[] { "x", new Num("5"), new Num("-1"), true, new JL(), new JL { "a" } })
            {
                var r = Verify(allow, true, bad);
                Assert.False(r.Ok);
                Assert.Equal(Incomplete, r.Reason);
            }
    }

    [Fact]
    public void AFalsyEvidenceCollateralIsMissing()
    {
        foreach (var bad in new object?[] { null, new Num("0"), new Num("-0"), "", false })
        {
            var ok = Verify(true, true, bad);
            Assert.True(ok.Ok, ok.Reason);
            Assert.Equal("unevaluated", ok.HostAsserted!["tcb_status"]);
            Assert.Equal(Required, Verify(false, true, bad).Reason);
        }
        var absent = Verify(true, false, null);
        Assert.True(absent.Ok, absent.Reason);
        Assert.Equal("unevaluated", absent.HostAsserted!["tcb_status"]);
        Assert.Equal(Required, Verify(false, false, null).Reason);
    }
}
