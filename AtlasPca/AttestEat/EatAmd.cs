// The AMD SEV-SNP side of the entity attestation package: the version-tolerant report parse, the projection of a report into EAT evidence and a measured
// identity, and the silicon verification (report signature plus the VCEK -> ASK -> ARK chain) that lifts an appraisal to the hardware-rooted tier.
using System.Buffers.Binary;
using System.Text.RegularExpressions;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.AttestEat;

/// <summary>The outcome of a version-tolerant report parse. Never thrown: an input too short to hold the version is <c>Ok = false</c>.</summary>
public sealed class TolerantParseResult
{
    public bool Ok { get; init; }
    public long Version { get; init; }
    public bool Known { get; init; }
    public bool Degraded { get; init; }
    public List<string> Notes { get; init; } = new();
    /// <summary>The appraisal projection (best effort; present whenever the stable header was readable).</summary>
    public D? Evidence { get; init; }
    internal SnpReport? Report { get; init; }
    /// <summary>True for a known version with a complete buffer (the full parse).</summary>
    public bool HasReport => Report != null;
    /// <summary>The measured identity of the full parse; null when only the stable header was read.</summary>
    public D? Measured => Report == null ? null : EatAmd.MeasuredFromReport(Report);
}

/// <summary>The single verdict of <see cref="EatAmd.VerifyAmdAttestation"/>.</summary>
public sealed class AmdAttestationResult
{
    public bool Ok { get; init; }
    public string? Reason { get; init; }
    /// <summary>The honest label of the hardware root: a classical ECDSA/RSA chain, not post-quantum.</summary>
    public string HardwareRoot { get; init; } = PcaAttestEat.AmdSevSnpHardwareRootLabel;
    /// <summary>The EAT evidence projection (present on success).</summary>
    public D? Evidence { get; init; }
    /// <summary>The hardware-measured identity (present on success).</summary>
    public D? Measured { get; init; }
}

public static class EatAmd
{
    const int FullReportMinLen = AttestAmd.OffSigS + 72;

    static object? P(object? o, string k) => Jx.Prop(o, k);
    static object N(double d) => Jx.NumOut(d);

    /// <summary>The JSON-safe EAT evidence projection of a parsed report: <c>reported_tcb</c> is a decimal string so the u64 survives JSON.</summary>
    internal static D EvidenceFromReport(SnpReport r, uint version) => new()
    {
        ["version"] = N(version),
        ["measurement"] = AttestUtil.Hex(r.Measurement),
        ["reported_tcb"] = r.ReportedTcb.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["guest_svn"] = N(r.GuestSvn),
        ["chip_id"] = AttestUtil.Hex(r.ChipId),
        ["debug"] = (r.Policy & AttestAmd.PolicyDebugBit) != 0,
    };

    /// <summary>The default hardware identity mapping: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID); SEV-SNP carries no weights or model id.</summary>
    internal static D MeasuredFromReport(SnpReport r) => new()
    {
        ["model_id"] = "",
        ["weights_digest"] = "",
        ["weights_measured"] = false,
        ["runtime_measurement"] = AttestUtil.Hex(r.Measurement),
        ["operator"] = AttestUtil.Hex(r.ChipId),
    };

    /// <summary>The EAT evidence projection of a report in the form <see cref="SevSnp.ParseSevSnpReport"/> returns (it carries the raw bytes).</summary>
    public static D EvidenceFromReport(D report)
    {
        var raw = (byte[])report["raw"]!;
        return EvidenceFromReport(AttestAmd.ParseReport(raw), BinaryPrimitives.ReadUInt32LittleEndian(raw));
    }

    /// <summary>The default hardware identity mapping of a report in the form <see cref="SevSnp.ParseSevSnpReport"/> returns.</summary>
    public static D MeasuredFromReport(D report) => MeasuredFromReport(AttestAmd.ParseReport((byte[])report["raw"]!));

    /// <summary>Parses an AMD SEV-SNP report DEFENSIVELY across format versions: a known version (2, 3, 5) with a complete buffer is the full parse; an unknown version or a short
    /// buffer reads the version-stable header fields at their fixed offsets and is marked <c>degraded</c> (appraised no higher than a warning). Never throws.</summary>
    public static TolerantParseResult ParseReportTolerant(byte[]? bytes)
    {
        var notes = new List<string>();
        if (bytes == null) return new TolerantParseResult { Ok = false, Version = 0, Known = false, Degraded = true, Notes = new List<string> { "input is not a Uint8Array" } };
        if (bytes.Length < 4) return new TolerantParseResult { Ok = false, Version = 0, Known = false, Degraded = true, Notes = new List<string> { "buffer too short to read the report version" } };
        var version = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        var known = version <= int.MaxValue && PcaAttestEat.KnownReportVersions.Contains((int)version);

        if (known && bytes.Length >= FullReportMinLen)
        {
            try
            {
                var report = AttestAmd.ParseReport(bytes);
                return new TolerantParseResult { Ok = true, Version = version, Known = true, Degraded = false, Notes = notes, Report = report, Evidence = EvidenceFromReport(report, version) };
            }
            catch (AttestError e) { notes.Add("full parse failed, falling back to the stable header: " + e.Message); }
        }
        else if (!known)
            notes.Add($"unknown report version {version} — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)");
        else
            notes.Add($"buffer length {bytes.Length} < full report {FullReportMinLen} — degraded header-only parse");

        // degraded path: the version-stable fields at fixed offsets, skipping any that run past the buffer
        if (AttestAmd.OffMeasurement + 48 > bytes.Length)
        {
            notes.Add("buffer too short to read the launch measurement");
            return new TolerantParseResult { Ok = false, Version = version, Known = known, Degraded = true, Notes = notes };
        }
        var evidence = new D { ["version"] = N(version), ["measurement"] = AttestUtil.Hex(bytes[AttestAmd.OffMeasurement..(AttestAmd.OffMeasurement + 48)]), ["degraded"] = true };
        if (AttestAmd.OffGuestSvn + 4 <= bytes.Length) evidence["guest_svn"] = N(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(AttestAmd.OffGuestSvn)));
        if (AttestAmd.OffPolicy + 8 <= bytes.Length) evidence["debug"] = (BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(AttestAmd.OffPolicy)) & AttestAmd.PolicyDebugBit) != 0;
        if (AttestAmd.OffReportedTcb + 8 <= bytes.Length) evidence["reported_tcb"] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(AttestAmd.OffReportedTcb)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (AttestAmd.OffChipId + 64 <= bytes.Length) evidence["chip_id"] = AttestUtil.Hex(bytes[AttestAmd.OffChipId..(AttestAmd.OffChipId + 64)]);
        return new TolerantParseResult { Ok = true, Version = version, Known = known, Degraded = true, Notes = notes, Evidence = evidence };
    }

    static readonly Regex PemCert = new(@"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", RegexOptions.CultureInvariant);

    /// <summary>A certificate given as DER bytes or as a PEM string holding exactly one certificate, as DER.</summary>
    static byte[] CertToDer(object? input)
    {
        if (input is byte[] der) return der;
        if (input is not string pem) throw new InvalidDataException("expected a DER byte array or a PEM string");
        var blocks = PemCert.Matches(pem);
        if (blocks.Count != 1) throw new InvalidDataException($"expected exactly one PEM certificate, found {blocks.Count}");
        var inner = Regex.Match(blocks[0].Value, @"-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----").Groups[1].Value;
        if (inner.Length == 0) throw new ArgumentException("pemToDer: no certificate found");
        return AttestUtil.NodeB64(Regex.Replace(inner, @"\s+", ""));
    }

    static string DerToPem(byte[] der) =>
        "-----BEGIN CERTIFICATE-----\n" + Regex.Replace(Convert.ToBase64String(der), "(.{64})", "$1\n") + "\n-----END CERTIFICATE-----\n";

    /// <summary>Composes the AMD SEV-SNP hardware root of trust into one verdict: the report is parsed, the VCEK -> ASK -> ARK chain is verified to the ARK pinned for the
    /// family (or the explicit pin; exactly one of the two), the report signature under the VCEK, the VCEK to report binding and the policy (debug refused unless
    /// <c>allowDebug</c>, the launch measurement when <c>expectedMeasurement</c>), then projected into the EAT evidence and the measured identity. Fails closed; never throws.
    /// <paramref name="rawReport"/> is the report bytes; <paramref name="opts"/>: <c>vcek</c>, <c>ask</c>, <c>ark</c> (DER bytes or one-certificate PEM strings), <c>family?</c> or
    /// <c>trustAnchorArkSpkiSha384?</c>, <c>nowMs</c>, <c>clockSkewMs?</c>, <c>expectedMeasurement?</c>, <c>allowDebug?</c>.</summary>
    public static AmdAttestationResult VerifyAmdAttestation(object? rawReport, object? opts)
    {
        AmdAttestationResult Fail(string why) => new() { Ok = false, Reason = why };
        try
        {
            var familyO = P(opts, "family");
            var pinO = P(opts, "trustAnchorArkSpkiSha384");
            var hasFamily = !Jx.IsUndef(familyO);
            var hasPin = !Jx.IsUndef(pinO);
            if (hasFamily == hasPin) return Fail("exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)");
            string pin;
            if (hasFamily)
            {
                if (!PcaAttestEat.KnownAmdArkSpkiSha384.TryGetValue(JsX.Str(familyO), out var fromFamily)) return Fail($"unknown AMD family {JsX.Str(familyO)} (expected milan | genoa | turin)");
                pin = fromFamily;
            }
            else pin = pinO as string ?? throw new ArgumentException("trustAnchorArkSpkiSha384 must be a string");

            byte[] vcekDer; string askArkPem;
            try
            {
                vcekDer = CertToDer(P(opts, "vcek"));
                askArkPem = DerToPem(CertToDer(P(opts, "ask"))) + DerToPem(CertToDer(P(opts, "ark")));
            }
            catch (Exception e) { return Fail("certificate parse failed: " + e.Message); }

            if (rawReport is not byte[] raw) return Fail("report parse failed: parseSevSnpReport: expected Uint8Array");
            SnpReport rep;
            try { rep = AttestAmd.ParseReport(raw); }
            catch (AttestError e) { return Fail("report parse failed: " + e.Message); }
            // exactly the canonical length, and the signature block beyond r and s reserved-zero: anything else is a second encoding of the same signed report
            if (raw.Length != AttestAmd.ReportLen) return Fail($"report length {raw.Length} is not the canonical {AttestAmd.ReportLen}");
            static bool NonZero(ReadOnlySpan<byte> b) { foreach (var x in b) if (x != 0) return true; return false; }
            if (NonZero(raw.AsSpan(AttestAmd.OffSigS + 72)) || NonZero(raw.AsSpan(AttestAmd.OffSigR + 48, 24)) || NonZero(raw.AsSpan(AttestAmd.OffSigS + 48, 24)))
                return Fail("report signature block has non-zero reserved bytes");

            if (Jx.Fin(P(opts, "nowMs")) is not double nowD) return Fail("cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check");
            var skewO = P(opts, "clockSkewMs");
            var (chainWhy, vcekKey, vcekTbs) = AttestAmd.VerifyChain(vcekDer, askArkPem, pin, (long)Math.Clamp(Math.Floor(nowD), -9e18, 9e18), Jx.IsUndef(skewO) ? null : skewO);
            if (AmdVerifier.ChainRefused(chainWhy, vcekKey, vcekTbs)) return Fail("cert chain invalid: " + chainWhy);
            if (!AttestAmd.VerifyReportSignature(rep, vcekKey!)) return Fail("report signature does not verify under VCEK");
            var bindErr = AttestAmd.CheckVcekReportBinding(vcekTbs!, rep);
            if (bindErr.Length > 0) return Fail(bindErr);

            var policy = new SnpPolicy { RequireEcdsaP384 = true, AllowDebug = P(opts, "allowDebug") is true };
            if (P(opts, "expectedMeasurement") is string em && em.Length > 0) policy.Measurements = new List<string> { em.ToLowerInvariant() };
            var polErr = policy.Check(rep);
            if (polErr != null) return Fail(polErr);

            return new AmdAttestationResult { Ok = true, Evidence = EvidenceFromReport(rep, BinaryPrimitives.ReadUInt32LittleEndian(raw)), Measured = MeasuredFromReport(rep) };
        }
        catch (Exception e) { return Fail("AMD attestation verification error (fail closed): " + e.Message); }
    }
}
