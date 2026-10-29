// AMD SEV-SNP: genuine ATTESTATION_REPORT verification (ECDSA-P384 report signature under the VCEK, VCEK -> ASK -> ARK chain to the
// pinned ARK of the configured family, VCEK <-> report binding, policy) with the same checks, order and reason text as the reference
// verifier. Classical (ECDSA-P384 / RSA-PSS); no network I/O.
using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>What a vendor implementation does for one verification (see <see cref="VendorVerifier"/>).</summary>
internal interface IVendorImpl
{
    HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs);
}

internal sealed class SnpReport
{
    public uint GuestSvn; public ulong Policy; public uint Vmpl, SigAlgo; public ulong ReportedTcb, CommittedTcb, LaunchTcb;
    public byte[] ReportData = Array.Empty<byte>(), Measurement = Array.Empty<byte>(), HostData = Array.Empty<byte>(), ChipId = Array.Empty<byte>();
    public byte[] Signed = Array.Empty<byte>(), SigR = Array.Empty<byte>(), SigS = Array.Empty<byte>();
}

internal sealed class SnpPolicy
{
    public List<string> Measurements = new(), HostData = new(), ChipIds = new();
    public bool AllowDebug, RequireEcdsaP384;
    public double? MinGuestSvn;
    public BigInteger? MinReportedTcb, MinCommittedTcb, MinLaunchTcb;
    public object? RequireVmpl; // null (default 0), "any", or a number

    internal string? Check(SnpReport r)
    {
        if (RequireEcdsaP384 && r.SigAlgo != AttestAmd.SigAlgoEcdsaP384) return $"unexpected signature_algo {r.SigAlgo}";
        if (!AllowDebug && (r.Policy & AttestAmd.PolicyDebugBit) != 0) return "guest policy has the DEBUG bit set (host can inspect the guest)";
        if (MinGuestSvn is double g && r.GuestSvn < g) return $"guest_svn {r.GuestSvn} below minimum {AttestUtil.JsNumString(g)}";
        if (MinReportedTcb is BigInteger a && r.ReportedTcb < a) return "reported_tcb below minimum (rollback?)";
        if (MinCommittedTcb is BigInteger b && r.CommittedTcb < b) return "committed_tcb below minimum (rollback?)";
        if (MinLaunchTcb is BigInteger c && r.LaunchTcb < c) return "launch_tcb below minimum";
        switch (RequireVmpl)
        {
            case null:
                if (r.Vmpl != 0) return $"vmpl {r.Vmpl} is not the required 0";
                break;
            case string want:
                if (want != "any") return $"vmpl {r.Vmpl} is not the required {want}";
                break;
            default:
                if (AttestUtil.AsFinite(RequireVmpl) is not double f || r.Vmpl != f) return $"vmpl {r.Vmpl} is not the required {AttestAmd.JsAnyString(RequireVmpl)}";
                break;
        }
        if (Measurements.Count > 0 && !Measurements.Contains(AttestUtil.Hex(r.Measurement))) return "measurement not in policy allowlist";
        if (HostData.Count > 0 && !HostData.Contains(AttestUtil.Hex(r.HostData))) return "host_data not in policy allowlist";
        if (ChipIds.Count > 0 && !ChipIds.Contains(AttestUtil.Hex(r.ChipId))) return "chip_id not in policy allowlist";
        return null;
    }
}

internal sealed class AmdVerifier : IVendorImpl
{
    // The SPKI SHA-384 (lowercase hex) of each family's ARK, as published by AMD's key distribution service.
    static readonly Dictionary<string, string> ArkSpkiSha384 = new()
    {
        ["milan"] = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        ["genoa"] = "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        ["turin"] = "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    };

    readonly string family, pin, binding;
    readonly SnpPolicy policy;
    readonly object? skew;

    AmdVerifier(string family, string pin, string binding, SnpPolicy policy, object? skew) { this.family = family; this.pin = pin; this.binding = binding; this.policy = policy; this.skew = skew; }

    internal static AmdVerifier Create(JD cfg)
    {
        var pol = cfg.GetValueOrDefault("policy") as JD ?? new JD();
        // the wire config carries the u64 floors as decimal strings: converted before the constructor runs
        var p = new SnpPolicy { RequireEcdsaP384 = pol.GetValueOrDefault("requireEcdsaP384") is not false, AllowDebug = pol.GetValueOrDefault("allowDebug") is true, RequireVmpl = pol.GetValueOrDefault("requireVmpl") };
        if (pol.TryGetValue("minReportedTcb", out var a)) p.MinReportedTcb = AttestAmd.ParseJsBigInt(a);
        if (pol.TryGetValue("minCommittedTcb", out var b)) p.MinCommittedTcb = AttestAmd.ParseJsBigInt(b);
        if (pol.TryGetValue("minLaunchTcb", out var c)) p.MinLaunchTcb = AttestAmd.ParseJsBigInt(c);
        var family = cfg.GetValueOrDefault("family") as string ?? "";
        if (!ArkSpkiSha384.TryGetValue(family, out var pin)) throw new ArgumentException("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'");
        if (cfg.GetValueOrDefault("trustAnchorArkSpkiSha384") is string o) pin = o; // conformance harness only: replaces the built-in pin
        var binding = cfg.GetValueOrDefault("binding") as string ?? "";
        if (binding != "report-data" && binding != "azure-runtime-data") throw new ArgumentException("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        var ms = AttestUtil.AsStrList(pol.GetValueOrDefault("measurements"));
        if (ms == null || ms.Count == 0) throw new ArgumentException("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
        p.Measurements = AttestUtil.LowerAll(ms);
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("hostData")) is { } hd) p.HostData = AttestUtil.LowerAll(hd);
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("chipIds")) is { } ci) p.ChipIds = AttestUtil.LowerAll(ci);
        if (AttestUtil.AsFinite(pol.GetValueOrDefault("minGuestSvn")) is double g) p.MinGuestSvn = g;
        return new AmdVerifier(family, pin, binding, p, cfg.GetValueOrDefault("clockSkewMs"));
    }

    /// <summary>verifyGenuineSevSnpReport: the failure reason, or the parsed report.</summary>
    (string Reason, SnpReport? Report) VerifyReport(byte[] raw, byte[] vcekDer, string askArkPem, long nowMs, AttestationBinding? expected)
    {
        SnpReport rep;
        try { rep = AttestAmd.ParseReport(raw); }
        catch (AttestError e) { return ("report parse failed: " + e.Message, null); }
        if (raw.Length != AttestAmd.ReportLen) return ($"report length {raw.Length} is not the canonical {AttestAmd.ReportLen}", null);
        static bool NonZero(ReadOnlySpan<byte> b) { foreach (var x in b) if (x != 0) return true; return false; }
        if (NonZero(raw.AsSpan(AttestAmd.OffSigS + 72)) || NonZero(raw.AsSpan(AttestAmd.OffSigR + 48, 24)) || NonZero(raw.AsSpan(AttestAmd.OffSigS + 48, 24)))
            return ("report signature block has non-zero reserved bytes", null);
        var (reason, vcekKey, vcekTbs) = AttestAmd.VerifyChain(vcekDer, askArkPem, pin, nowMs, skew);
        if (reason.Length > 0 || vcekKey == null || vcekTbs == null) return ("cert chain invalid: " + reason, null);
        if (!AttestAmd.VerifyReportSignature(rep, vcekKey)) return ("report signature does not verify under VCEK", null);
        var bindErr = AttestAmd.CheckVcekReportBinding(vcekTbs, rep);
        if (bindErr.Length > 0) return (bindErr, null);
        if (expected != null)
        {
            byte[] want;
            try { want = AttestUtil.BindingBytes(expected); }
            catch (AttestError e) { return ("genuine verification error (fail closed): " + e.Message, null); }
            if (!AttestUtil.TimingSafeEq(want, rep.ReportData)) return ("report_data does not bind holder/grant/epoch/nonce", null);
        }
        var pol = policy.Check(rep);
        if (pol != null) return (pol, null);
        return ("", rep);
    }

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        var report = AttestEvidence.Bytes(ev, "report"); var vcek = AttestEvidence.Bytes(ev, "vcekDer"); var askArk = AttestEvidence.Str(ev, "askArkPem");
        if (ev == null || report == null || vcek == null || askArk == null) return HardwareResult.Fail("no AMD SEV-SNP evidence for this action");
        if (expected == null) return HardwareResult.Fail("no expected attestation binding supplied");
        bool direct = binding == "report-data";
        var (reason, rep) = VerifyReport(report, vcek, askArk, nowMs, direct ? expected : null);
        if (rep == null) return HardwareResult.Fail("SEV-SNP report invalid: " + reason);
        if (!direct)
        {
            var rd = AttestEvidence.Bytes(ev, "runtimeData");
            if (rd == null) return HardwareResult.Fail("azure-runtime-data binding needs the runtime-data JSON bytes");
            var why = AttestUtil.CheckAzureRuntimeDataBinding(rep.ReportData, rd, expected);
            if (why != null) return HardwareResult.Fail(why);
        }
        var m = AttestUtil.Hex(rep.Measurement);
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured(m, AttestUtil.Hex(rep.ChipId)),
            new Dictionary<string, string> { ["attestation_type"] = "amd-sev-snp", ["family"] = family, ["measurement"] = m });
    }
}

internal static class AttestEvidence
{
    /// <summary>A string member decoded like Buffer.from(s, "base64"); null when absent or not a string.</summary>
    internal static byte[]? Bytes(JD? ev, string key) => ev?.GetValueOrDefault(key) is string s ? AttestUtil.NodeB64(s) : null;
    internal static string? Str(JD? ev, string key) => ev?.GetValueOrDefault(key) as string;
}

internal static class AttestAmd
{
    // ATTESTATION_REPORT layout (AMD SEV-SNP ABI): offsets, all integers little-endian.
    internal const int OffGuestSvn = 0x004, OffPolicy = 0x008, OffVmpl = 0x030, OffSigAlgo = 0x034, OffReportData = 0x050, OffMeasurement = 0x090,
        OffHostData = 0x0c0, OffReportedTcb = 0x180, OffChipId = 0x1a0, OffCommittedTcb = 0x1e0, OffLaunchTcb = 0x1f0, OffSignedEnd = 0x2a0,
        OffSigR = 0x2a0, OffSigS = 0x2e8, ReportLen = 0x4a0;
    internal const ulong PolicyDebugBit = 1UL << 19;
    internal const uint SigAlgoEcdsaP384 = 1;

    internal static SnpReport ParseReport(byte[] b)
    {
        int minLen = OffSigS + 72;
        if (b.Length < minLen) throw new AttestError($"parseSevSnpReport: report too short ({b.Length} < {minLen})");
        return new SnpReport
        {
            GuestSvn = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(OffGuestSvn)), Policy = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(OffPolicy)),
            Vmpl = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(OffVmpl)), SigAlgo = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(OffSigAlgo)),
            ReportedTcb = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(OffReportedTcb)), CommittedTcb = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(OffCommittedTcb)),
            LaunchTcb = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(OffLaunchTcb)),
            ReportData = b[OffReportData..(OffReportData + 64)], Measurement = b[OffMeasurement..(OffMeasurement + 48)], HostData = b[OffHostData..(OffHostData + 32)],
            ChipId = b[OffChipId..(OffChipId + 64)], Signed = b[..OffSignedEnd], SigR = b[OffSigR..(OffSigR + 72)], SigS = b[OffSigS..(OffSigS + 72)],
        };
    }

    static BigInteger LeToBig(byte[] le) => new(le, isUnsigned: true, isBigEndian: false);

    static readonly BigInteger P384Order = BigInteger.Parse("0ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    static byte[] Fixed(BigInteger v, int n)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var o = new byte[n];
        b.CopyTo(o, n - b.Length);
        return o;
    }

    /// <summary>ECDSA-P384 / SHA-384 over the signed region under the VCEK; AMD stores r and s little-endian.</summary>
    internal static bool VerifyReportSignature(SnpReport r, CertKey vcek)
    {
        BigInteger rr = LeToBig(r.SigR), ss = LeToBig(r.SigS);
        if (rr.Sign <= 0 || rr >= P384Order || ss.Sign <= 0 || ss >= P384Order || vcek.Ec == null) return false;
        try { return vcek.Ec.VerifyHash(AttestUtil.Sha384(r.Signed), Pca.Concat(Fixed(rr, 48), Fixed(ss, 48)), DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception) { return false; }
    }

    const string OidHwid = "1.3.6.1.4.1.3704.1.4", OidBlSpl = "1.3.6.1.4.1.3704.1.3.1", OidTeeSpl = "1.3.6.1.4.1.3704.1.3.2", OidSnpSpl = "1.3.6.1.4.1.3704.1.3.3", OidUcodeSp = "1.3.6.1.4.1.3704.1.3.8";
    const int HwidLen = 64;

    /// <summary>Decodes an SPL extension value: one minimal DER INTEGER 0..255. The failure text, or null.</summary>
    static (int Value, string? Why) DecodeSpl(byte[] v)
    {
        if (v.Length < 3 || v[0] != 0x02) return (0, "is not a DER INTEGER");
        int l = v[1];
        if (l < 1 || l > 2 || v.Length != 2 + l) return (0, "has a wrong-length INTEGER");
        byte c0 = v[2];
        if ((c0 & 0x80) != 0) return (0, "is negative");
        if (l == 2)
        {
            if (c0 != 0x00) return (0, "is out of range (> 255)");
            if ((v[3] & 0x80) == 0) return (0, "is a non-minimal INTEGER");
            return (v[3], null);
        }
        return (c0, null);
    }

    /// <summary>Binds the VCEK body to the report: hwID == chip_id and the four SPLs == the REPORTED_TCB bytes. "" when it binds.</summary>
    internal static string CheckVcekReportBinding(byte[] vcekTbs, SnpReport r)
    {
        ExtTable exts;
        try { exts = AttestDer.ParseTbsExtensions(vcekTbs); }
        catch (AttestError e) { return "VCEK extensions malformed: " + e.Message; }
        var hw = exts.Get(OidHwid);
        if (hw == null) return "VCEK certificate has no CHIP_ID (hwID) extension";
        if (hw.Critical) return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)";
        if (hw.Value.Length != HwidLen) return $"VCEK CHIP_ID (hwID) extension is {hw.Value.Length} bytes, expected {HwidLen}";
        if (!AttestUtil.TimingSafeEq(hw.Value, r.ChipId)) return "VCEK CHIP_ID does not match report chip_id";
        int ByteAt(int i) => (int)((r.ReportedTcb >> (8 * i)) & 0xff);
        foreach (var (oid, name, want) in new[] { (OidBlSpl, "bootloader", ByteAt(0)), (OidTeeSpl, "tee", ByteAt(1)), (OidSnpSpl, "snp", ByteAt(6)), (OidUcodeSp, "microcode", ByteAt(7)) })
        {
            var ext = exts.Get(oid);
            if (ext == null) return $"VCEK certificate has no {name} SPL extension";
            if (ext.Critical) return $"VCEK {name} SPL extension is marked critical (the AMD profile is non-critical)";
            var (got, why) = DecodeSpl(ext.Value);
            if (why != null) return $"VCEK {name} SPL extension {why}";
            if (got != want) return $"VCEK {name} SPL {got} does not match report reported_tcb ({want}) — TCB downgrade?";
        }
        return "";
    }

    /// <summary>VCEK -> ASK -> ARK with the ARK pinned. The failure reason ("" when fine), the VCEK key and tbs.</summary>
    internal static (string Reason, CertKey? Key, byte[]? Tbs) VerifyChain(byte[] vcekDer, string askArkPem, string pin, long nowMs, object? clockSkew)
    {
        static (string, CertKey?, byte[]?) Fail(string r) => (r, null, null);
        static (string, CertKey?, byte[]?) Thrown(string m) => ("AMD chain verification error: " + m, null, null);
        double skew = 0;
        if (clockSkew != null)
        {
            if (AttestUtil.AsFinite(clockSkew) is not double f || f < 0) return Fail("clockSkewMs must be a non-negative number");
            skew = f;
        }
        try
        {
            var vcek = AttestCerts.ParseDer(vcekDer);
            var pems = AttestCerts.PemBlocks(askArkPem);
            if (pems.Count != 2) return Fail("ASK+ARK chain must contain exactly two certificates (ASK then ARK)");
            var ask = AttestCerts.FromPem(pems[0]);
            var ark = AttestCerts.FromPem(pems[1]);
            if (!ark.SelfIssued || !AttestCerts.SigOkBy(ark, ark)) return Fail("second certificate of the chain is not a self-signed ARK (chain out of order?)");
            if (ask.SelfIssued) return Fail("first certificate of the chain is self-signed, not an ASK (chain out of order?)");
            if (!ask.RawSubject.AsSpan().SequenceEqual(vcek.RawIssuer)) return Fail("ASK subject does not match the VCEK issuer");
            var arkKey = AttestCerts.KeyOf(ark);
            if (arkKey.SpkiSha384() != pin.ToLowerInvariant()) return Fail("ARK does not match the pinned AMD trust anchor");
            if (!ask.RawIssuer.AsSpan().SequenceEqual(ark.RawSubject) || !AttestCerts.SigOkBy(ask, ark)) return Fail("ASK is not signed by ARK");
            if (!AttestCerts.SigOkBy(vcek, ask)) return Fail("VCEK is not signed by ASK");

            var labels = new[] { "VCEK", "ASK", "ARK" };
            var ders = new[] { vcekDer, ask.Raw, ark.Raw };
            var roleErr = AttestDer.CheckChainRoles(ders);
            if (roleErr != null) return Fail("AMD chain role check failed: " + roleErr);
            for (int i = 0; i < ders.Length; i++)
            {
                var label = labels[i];
                var exts = AttestDer.ParseCertExtensions(ders[i]);
                foreach (var oid in exts.Oids)
                    if (exts.Map[oid].Critical && !AttestDer.RecognisedCriticalExtensions.Contains(oid)) return Fail($"{label} certificate has an unrecognised critical extension {oid}");
                if (label != "VCEK" && !(exts.Get("2.5.29.19") is { Critical: true })) return Fail($"{label} certificate BasicConstraints is not marked critical");
                var (vFrom, vTo) = AttestDer.DerValidity(ders[i]);
                if (!vFrom.Ok || !vTo.Ok) return Fail($"{label} certificate validity is unparseable");
                if ((double)nowMs + skew < vFrom.Ms) return Fail($"{label} certificate is not yet valid");
                if ((double)nowMs - skew > vTo.Ms) return Fail($"{label} certificate has expired");
            }

            var vk = AttestCerts.KeyOf(vcek);
            if (vk.Type != "ec" || vk.Curve != "secp384r1")
                throw new AttestError($"VCEK is not EC secp384r1 (got {vk.Type}/{(vk.Curve.Length == 0 ? "undefined" : vk.Curve)})");
            vk.EcPointOn("P-384");
            var tbs = AttestDer.TbsOfCertificate(vcekDer);
            return ("", vk, tbs);
        }
        catch (AttestError e) { return Thrown(e.Message); }
    }

    internal static string JsAnyString(object? v) => v switch
    {
        string s => s,
        bool b => b ? "true" : "false",
        _ => AttestUtil.AsFinite(v) is double f ? AttestUtil.JsNumString(f) : v?.ToString() ?? "null",
    };

    /// <summary>BigInt(v) for a JSON value; the error text is the reference's.</summary>
    internal static BigInteger ParseJsBigInt(object? v)
    {
        switch (v)
        {
            case null: throw new ArgumentException("Cannot convert null to a BigInt");
            case bool b: return b ? 1 : 0;
            case string t:
                {
                    var s = AttestUtil.JsTrim(t);
                    if (s.Length == 0) return 0;
                    int radix = 10; var body = s;
                    if (s.Length > 2 && s[0] == '0')
                    {
                        switch (s[1])
                        {
                            case 'x': case 'X': radix = 16; body = s[2..]; break;
                            case 'o': case 'O': radix = 8; body = s[2..]; break;
                            case 'b': case 'B': radix = 2; body = s[2..]; break;
                        }
                    }
                    if (radix == 10 || (body.Length > 0 && body[0] != '+' && body[0] != '-'))
                    {
                        var n = ParseRadix(body, radix);
                        if (n != null) return n.Value;
                    }
                    throw new ArgumentException($"Cannot convert {t} to a BigInt");
                }
            case Num n:
                {
                    if (AttestUtil.AsFinite(n) is not double f || f != Math.Truncate(f)) throw new ArgumentException($"The number {n.Raw} cannot be converted to a BigInt because it is not an integer");
                    if (BigInteger.TryParse(n.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var bi)) return bi;
                    return new BigInteger(f);
                }
        }
        throw new ArgumentException("Cannot convert value to a BigInt");
    }

    static BigInteger? ParseRadix(string s, int radix)
    {
        if (radix == 10) return BigInteger.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var d) && s.All(c => c is >= '0' and <= '9' or '+' or '-') ? d : null;
        if (s.Length == 0) return null;
        BigInteger acc = 0;
        foreach (var c in s)
        {
            int dv = c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'f' ? c - 'a' + 10 : c is >= 'A' and <= 'F' ? c - 'A' + 10 : 99;
            if (dv >= radix) return null;
            acc = acc * radix + dv;
        }
        return acc;
    }
}
