// Intel TDX (DCAP v4, ECDSA-P256): the genuine quote end to end (PCK chain to the pinned Intel SGX Root CA, QE report under the PCK
// leaf, attestation key endorsed by the QE, TD quote signature), the PCA binding in its two modes, and the optional Intel PCS
// collateral (AttestIntelCollateral.cs). Same checks, order and reason text as the reference verifier.
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

internal sealed class DcapQuote
{
    public byte[] Header = Array.Empty<byte>(), TdReportBody = Array.Empty<byte>(), QuoteSignature = Array.Empty<byte>(), AkPubRaw = Array.Empty<byte>();
    public byte[] QeReportBody = Array.Empty<byte>(), QeReportSignature = Array.Empty<byte>(), QeAuthData = Array.Empty<byte>();
    public string PckChainPem = "";
}

internal sealed class PckTcb
{
    public byte[] Fmspc = Array.Empty<byte>();
    public byte[] Sgx = new byte[16]; // 16 SGX TCB component SVNs
    public int Pcesvn;
}

internal sealed class PckChainResult
{
    public bool Ok, Validity; // Validity: the failure was a validity-window failure
    public string Reason = "";
    public AttCert? Leaf;
    public CertKey? LeafKey;
    public int Depth;
}

internal sealed class TdxQuotePolicy
{
    public List<string> Mrtds = new(), Fmspcs = new(), Rtmrs = new(), MrSeams = new(), MrSignerSeams = new();
    public bool HasMrSeams, HasMrSigner, AllowDebug;
}

internal sealed class TdxResult
{
    public bool Ok;
    public string Reason = "";
    public byte[] ReportData = Array.Empty<byte>();
    public string Fmspc = "";
    public PckTcb? Pck;
    public byte[] MrTd = Array.Empty<byte>();
}

internal sealed class IntelVerifier : IVendorImpl
{
    readonly string binding, pin;
    readonly TdxQuotePolicy pol = new();
    readonly bool allowMissing;
    CollateralPolicy? collateralPol;

    IntelVerifier(string binding, string pin, bool allowMissing) { this.binding = binding; this.pin = pin; this.allowMissing = allowMissing; }

    static readonly Regex HexRe = new(@"^[0-9a-fA-F]+\z", RegexOptions.CultureInvariant);

    internal static IntelVerifier Create(JD cfg)
    {
        var binding = cfg.GetValueOrDefault("binding") as string ?? "";
        if (binding != "report-data" && binding != "azure-runtime-data") throw new ArgumentException("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        var pol = cfg.GetValueOrDefault("policy") as JD ?? new JD();
        var mr = AttestUtil.AsStrList(pol.GetValueOrDefault("mrtds"));
        if (mr == null || mr.Count == 0) throw new ArgumentException("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)");
        var mrtds = AttestUtil.LowerAll(mr);
        foreach (var m in mrtds) if (!HexRe.IsMatch(m) || m.Length != 96) throw new ArgumentException("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)");
        var pin = AttestIntel.SgxRootCaSpkiSha256;
        if (cfg.GetValueOrDefault("trustAnchorRootCaSpkiSha256") is string p) pin = p.ToLowerInvariant();
        var v = new IntelVerifier(binding, pin, cfg.GetValueOrDefault("allowMissingCollateral") is true);
        v.pol.Mrtds = mrtds;
        foreach (var name in new[] { "mrSeams", "mrSignerSeams" })
        {
            if (!pol.TryGetValue(name, out var raw)) continue;
            var list = AttestUtil.AsStrList(raw);
            if (list == null || list.Count == 0) throw new ArgumentException($"createIntelDcapVerifier: policy.{name}, if given, must be a NON-EMPTY list");
            foreach (var m in list) if (!HexRe.IsMatch(m) || m.Length != 96) throw new ArgumentException($"createIntelDcapVerifier: every {name} entry must be 96 hex chars (48 bytes)");
            if (name == "mrSeams") { v.pol.MrSeams = AttestUtil.LowerAll(list); v.pol.HasMrSeams = true; }
            else { v.pol.MrSignerSeams = AttestUtil.LowerAll(list); v.pol.HasMrSigner = true; }
        }
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("fmspcs")) is { } fm) v.pol.Fmspcs = AttestUtil.LowerAll(fm);
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("rtmrs")) is { } rt) v.pol.Rtmrs = AttestUtil.LowerAll(rt);
        v.pol.AllowDebug = pol.GetValueOrDefault("allowDebug") is true;
        if (pol.GetValueOrDefault("collateral") is JD cp)
        {
            var c = new CollateralPolicy();
            if (AttestUtil.AsStrList(cp.GetValueOrDefault("acceptStatuses")) is { } acc) { c.AcceptStatuses = acc; c.HasAccept = true; }
            if (AttestUtil.AsFinite(cp.GetValueOrDefault("minTcbEvaluationDataNumber")) is double f) { c.MinEval = f; c.HasMinEval = true; }
            v.collateralPol = c;
        }
        return v;
    }

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        var quote = AttestEvidence.Bytes(ev, "quote");
        if (ev == null || quote == null) return HardwareResult.Fail("no Intel DCAP quote for this action");
        if (expected == null) return HardwareResult.Fail("no expected attestation binding supplied");
        var q = AttestIntel.VerifyGenuineTdxQuote(quote, pin, nowMs, pol, false);
        if (!q.Ok) return HardwareResult.Fail("DCAP quote invalid: " + q.Reason);
        if (binding == "report-data")
        {
            byte[] want;
            try { want = AttestUtil.BindingBytes(expected); }
            catch (AttestError e) { return HardwareResult.Fail("binding not constructible: " + e.Message); }
            if (!AttestUtil.TimingSafeEq(q.ReportData, want)) return HardwareResult.Fail("report_data does not bind holder/grant/epoch/nonce");
        }
        else
        {
            var rd = AttestEvidence.Bytes(ev, "runtimeData");
            if (rd == null) return HardwareResult.Fail("azure-runtime-data binding needs the runtime-data JSON bytes");
            var why = AttestUtil.CheckAzureRuntimeDataBinding(q.ReportData, rd, expected);
            if (why != null) return HardwareResult.Fail(why);
        }
        var host = new Dictionary<string, string> { ["attestation_type"] = "tdx-dcap", ["fmspc"] = q.Fmspc };
        if (ev.GetValueOrDefault("collateral") is JD col)
        {
            var c = IntelCollateral.FromWire(col);
            var res = AttestIntelCollateral.Verify(quote, c, nowMs, collateralPol, pin, pol.AllowDebug);
            if (res.Status.Length > 0) host["tcb_status"] = res.Status;
            if (res.AdvisoryIds.Count > 0) host["advisory_ids"] = string.Join(",", res.AdvisoryIds);
            if (!res.Ok) return HardwareResult.Fail("Intel collateral: " + (res.Reason.Length == 0 ? "rejected" : res.Reason));
        }
        else if (allowMissing) host["tcb_status"] = "unevaluated";
        else return HardwareResult.Fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)");
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured(AttestUtil.Hex(q.MrTd), ""), host);
    }
}

internal static class AttestIntel
{
    /// <summary>Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex).</summary>
    internal const string SgxRootCaSpkiSha256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e";

    const int HeaderLen = 48, TdReportLen = 584, SgxReport = 384, QeAttrOff = 48, QeRdataOff = 0x140;

    internal static DcapQuote ParseQuote(byte[] q)
    {
        if (q.Length < HeaderLen + TdReportLen + 4) throw new AttestError("parseDcapQuote: too short for header + TD report + sig length");
        int U16(int o) => BinaryPrimitives.ReadUInt16LittleEndian(q.AsSpan(o));
        long U32(int o) => BinaryPrimitives.ReadUInt32LittleEndian(q.AsSpan(o));
        int version = U16(0), attKeyType = U16(2);
        long teeType = U32(4);
        if (version != 4) throw new AttestError($"parseDcapQuote: unsupported quote version {version} (expected 4)");
        if (attKeyType != 2) throw new AttestError($"parseDcapQuote: unsupported attestation key type {attKeyType} (expected ECDSA-P256 = 2)");
        if (teeType != 0x81) throw new AttestError($"parseDcapQuote: unexpected TEE type 0x{teeType:x} (expected TDX = 0x81)");
        var o = new DcapQuote { Header = q[..HeaderLen], TdReportBody = q[HeaderLen..(HeaderLen + TdReportLen)] };
        int p = HeaderLen + TdReportLen;
        long sigDataLen = U32(p);
        p += 4;
        long sigEnd = p + sigDataLen;
        if (sigEnd > q.Length) throw new AttestError($"parseDcapQuote: signature data ({sigDataLen}) overruns the quote");
        void Need(long n, string what) { if (p + n > sigEnd) throw new AttestError($"parseDcapQuote: truncated reading {what}"); }
        Need(64, "quote signature");
        o.QuoteSignature = q[p..(p + 64)]; p += 64;
        Need(64, "attestation public key");
        o.AkPubRaw = q[p..(p + 64)]; p += 64;
        Need(6, "outer cert-data header");
        int outerType = U16(p);
        long outerSize = U32(p + 2);
        p += 6;
        if (outerType != 6) throw new AttestError($"parseDcapQuote: outer cert-data type {outerType} (expected QE-report-cert-data = 6)");
        long outerEnd = p + outerSize;
        if (outerEnd > sigEnd) throw new AttestError("parseDcapQuote: outer cert-data overruns signature data");
        Need(SgxReport, "QE report");
        o.QeReportBody = q[p..(p + SgxReport)]; p += SgxReport;
        Need(64, "QE report signature");
        o.QeReportSignature = q[p..(p + 64)]; p += 64;
        Need(2, "QE auth-data size");
        int authSize = U16(p);
        p += 2;
        Need(authSize, "QE auth-data");
        o.QeAuthData = q[p..(p + authSize)]; p += authSize;
        Need(6, "inner cert-data header");
        int innerType = U16(p);
        long innerSize = U32(p + 2);
        p += 6;
        if (innerType != 5) throw new AttestError($"parseDcapQuote: inner cert-data type {innerType} (expected PCK-cert-chain = 5)");
        if (p + innerSize > outerEnd) throw new AttestError("parseDcapQuote: inner cert-data overruns outer cert-data");
        o.PckChainPem = Encoding.Latin1.GetString(q, p, (int)innerSize);
        for (long i = sigEnd; i < q.Length; i++) if (q[i] != 0) throw new AttestError("parseDcapQuote: non-zero bytes after the signature data");
        return o;
    }

    // ---- the Intel SGX extension (byte scan, as the reference does)

    static readonly byte[] OidSgxFmspc = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04 };
    static readonly byte[] OidSgxTcb = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02 };

    /// <summary>Reads one TLV at off; false on any malformed or overrunning length.</summary>
    internal static bool ReadTlvLenient(byte[] buf, int off, out DerTlv t)
    {
        t = default;
        if (off < 0 || off + 2 > buf.Length) return false;
        byte tag = buf[off];
        long l = buf[off + 1];
        int p = off + 2;
        if ((l & 0x80) != 0)
        {
            int n = (int)(l & 0x7f);
            if (n == 0 || n > 4 || p + n > buf.Length) return false;
            l = 0;
            for (int i = 0; i < n; i++) { l = l * 256 + buf[p]; p++; }
        }
        long end = p + l;
        if (end > buf.Length) return false;
        t = new DerTlv(tag, p, (int)end);
        return true;
    }

    /// <summary>Reads the FMSPC and the issued TCB from the PCK leaf's Intel SGX extension.</summary>
    internal static PckTcb ExtractPckFmspcAndTcb(byte[] leaf)
    {
        int fi = leaf.AsSpan().IndexOf(OidSgxFmspc);
        if (fi < 0) throw new AttestError("extractPckFmspcAndTcb: FMSPC OID not found in certificate");
        if (!ReadTlvLenient(leaf, fi + OidSgxFmspc.Length, out var fv) || fv.Tag != 0x04 || fv.End - fv.Start != 6) throw new AttestError("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING");
        var fmspc = leaf[fv.Start..fv.End];
        int ti = leaf.AsSpan().IndexOf(OidSgxTcb);
        if (ti < 0) throw new AttestError("extractPckFmspcAndTcb: TCB OID not found in certificate");
        if (!ReadTlvLenient(leaf, ti + OidSgxTcb.Length, out var seq) || seq.Tag != 0x30) throw new AttestError("extractPckFmspcAndTcb: malformed TCB SEQUENCE");
        var sgx = new byte[16];
        int pcesvn = -1;
        int p = seq.Start, idx = 0;
        while (p < seq.End)
        {
            if (!ReadTlvLenient(leaf, p, out var pair) || pair.Tag != 0x30) throw new AttestError("extractPckFmspcAndTcb: malformed TCB component");
            if (!ReadTlvLenient(leaf, pair.Start, out var oid) || oid.Tag != 0x06) throw new AttestError("extractPckFmspcAndTcb: TCB component missing OID");
            if (!ReadTlvLenient(leaf, oid.End, out var val)) throw new AttestError("extractPckFmspcAndTcb: TCB component missing value");
            int last = leaf[oid.End - 1];
            if (val.Tag == 0x02)
            {
                uint n = 0;
                for (int b = val.Start; b < val.End; b++) n = (n << 8) | leaf[b];
                if (last >= 1 && last <= 16) sgx[last - 1] = (byte)(n & 0xff);
                else if (last == 17) pcesvn = (int)(n & 0xffff);
            }
            p = pair.End;
            idx++;
            if (idx > 64) break;
        }
        if (pcesvn < 0) throw new AttestError("extractPckFmspcAndTcb: PCESVN not found in TCB extension");
        return new PckTcb { Fmspc = fmspc, Sgx = sgx, Pcesvn = pcesvn };
    }

    // ---- PCK chain

    static string K(byte[] b) => Convert.ToBase64String(b);

    /// <summary>Verifies a PEM chain to the pinned Intel SGX Root CA (every certificate valid at nowMs, every link signed, the root
    /// self-signed and pinned, CA roles, no unrecognised critical extension, an EC P-256 leaf).</summary>
    internal static PckChainResult VerifyPckChain(string pckChainPem, string pin, long nowMs)
    {
        static PckChainResult Fail(string r) => new() { Reason = r };
        try
        {
            var blocks = AttestCerts.PemBlocks(pckChainPem);
            if (blocks.Count == 0) return Fail("no PEM certificates in the PCK chain");
            var certs = blocks.Select(AttestCerts.FromPem).ToList();
            var issuers = new HashSet<string>(); var bySubject = new Dictionary<string, AttCert>();
            foreach (var c in certs) { issuers.Add(K(c.RawIssuer)); bySubject[K(c.RawSubject)] = c; }
            var leaf = certs[0];
            foreach (var c in certs) if (!issuers.Contains(K(c.RawSubject))) { leaf = c; break; }
            var ordered = new List<AttCert>();
            var seen = new HashSet<string>();
            AttCert? cur = leaf;
            while (cur != null && !seen.Contains(K(cur.RawSubject)))
            {
                ordered.Add(cur);
                seen.Add(K(cur.RawSubject));
                if (cur.SelfIssued) break;
                cur = bySubject.GetValueOrDefault(K(cur.RawIssuer));
            }
            var root = ordered[^1];
            if (!root.SelfIssued) return Fail("PCK chain does not terminate in a self-signed root");
            if (ordered.Count != certs.Count) return Fail("PCK chain is not a single connected path (orphan/duplicate certificates)");
            foreach (var c in ordered) if (!AttestDer.DerValidAt(c.Raw, nowMs, 0)) return new PckChainResult { Reason = "PCK chain certificate outside its validity period", Validity = true };
            for (int i = 0; i < ordered.Count - 1; i++)
            {
                AttCert child = ordered[i], parent = ordered[i + 1];
                if (!child.RawIssuer.AsSpan().SequenceEqual(parent.RawSubject)) return Fail($"certificate at depth {i} issuer does not match its parent subject");
                if (!AttestCerts.SigOkBy(child, parent)) return Fail($"certificate at depth {i} is not signed by its issuer");
            }
            if (!AttestCerts.SigOkBy(root, root)) return Fail("root certificate is not self-signed");
            var rootKey = AttestCerts.KeyOf(root);
            if (rootKey.SpkiSha256() != pin.ToLowerInvariant()) return Fail("Intel SGX Root CA does not match the pinned trust anchor");
            var ders = ordered.Select(c => c.Raw).ToList();
            var roleFail = AttestDer.CheckChainRoles(ders);
            if (roleFail != null) return Fail(roleFail);
            for (int i = 0; i < ders.Count; i++)
            {
                var crit = AttestDer.UnrecognisedCriticalExtension(ders[i]);
                if (crit != null) return Fail($"PCK chain certificate at depth {i} has an unrecognised critical extension {crit}");
            }
            var lk = AttestCerts.KeyOf(leaf);
            if (lk.Type != "ec") return Fail($"PCK leaf key is not EC (got {lk.Type})");
            lk.EcPointOn("P-256");
            return new PckChainResult { Ok = true, Leaf = leaf, LeafKey = lk, Depth = ordered.Count };
        }
        catch (AttestError e) { return new PckChainResult { Reason = "PCK chain X.509 verification error (fail closed): " + e.Message }; }
    }

    // ---- genuine quote

    static bool VerifyP256Compact(byte[] msg, byte[] sig, ECDsa pub)
    {
        if (sig.Length != 64) return false;
        try { return pub.VerifyHash(AttestUtil.Sha256(msg), sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception) { return false; }
    }

    internal static TdxResult VerifyGenuineTdxQuote(byte[] quote, string pin, long nowMs, TdxQuotePolicy? pol, bool allowDebugOnly)
    {
        static TdxResult Bad(string r) => new() { Reason = r };
        DcapQuote q;
        try { q = ParseQuote(quote); }
        catch (AttestError e) { return Bad("quote parse failed: " + e.Message); }
        var body = q.TdReportBody;
        var chain = VerifyPckChain(q.PckChainPem, pin, nowMs);
        if (!chain.Ok || chain.LeafKey?.Ec == null || chain.Leaf == null) return Bad("PCK chain invalid: " + chain.Reason);
        PckTcb tcb;
        try { tcb = ExtractPckFmspcAndTcb(chain.Leaf.Raw); }
        catch (AttestError e) { return Bad("PCK FMSPC/TCB extraction failed: " + e.Message); }
        if (!VerifyP256Compact(q.QeReportBody, q.QeReportSignature, chain.LeafKey.Ec)) return Bad("QE report signature does not verify under the PCK leaf");
        if ((q.QeReportBody[QeAttrOff] & 0x02) != 0) return Bad("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)");
        var qeReportData = q.QeReportBody.AsSpan(QeRdataOff, 64);
        var akBinding = AttestUtil.Sha256(Pca.Concat(q.AkPubRaw, q.QeAuthData));
        bool zero = true;
        foreach (var b in qeReportData[32..64]) if (b != 0) zero = false;
        if (!AttestUtil.TimingSafeEq(qeReportData[..32].ToArray(), akBinding) || !zero) return Bad("QE report_data does not bind the attestation key (AK not endorsed by this QE)");
        ECDsa akPub;
        try
        {
            akPub = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = q.AkPubRaw[..32], Y = q.AkPubRaw[32..] } });
        }
        catch (Exception) { return Bad("attestation public key is not a valid P-256 point"); }
        if (!VerifyP256Compact(Pca.Concat(q.Header, body), q.QuoteSignature, akPub)) return Bad("TD quote signature does not verify under the attestation key");
        bool allowDebug = allowDebugOnly || (pol != null && pol.AllowDebug);
        if (!allowDebug && (body[120] & 1) != 0) return Bad("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)");
        var mrTd = body[136..184];
        var fmspcHex = AttestUtil.Hex(tcb.Fmspc);
        if (pol != null)
        {
            if (pol.Mrtds.Count > 0 && !pol.Mrtds.Contains(AttestUtil.Hex(mrTd))) return Bad("MRTD not in policy allowlist");
            if (pol.Fmspcs.Count > 0 && !pol.Fmspcs.Contains(fmspcHex)) return Bad("FMSPC not in policy allowlist");
            if (pol.HasMrSeams && !pol.MrSeams.Contains(AttestUtil.Hex(body[16..64]))) return Bad("MRSEAM not in policy allowlist");
            if (pol.HasMrSigner && !pol.MrSignerSeams.Contains(AttestUtil.Hex(body[64..112]))) return Bad("MRSIGNERSEAM not in policy allowlist");
            if (pol.Rtmrs.Count > 0 && !pol.Rtmrs.Contains(AttestUtil.Hex(body[328..376]))) return Bad("RTMR0 not in policy allowlist");
        }
        return new TdxResult { Ok = true, ReportData = body[520..584], Fmspc = fmspcHex, Pck = tcb, MrTd = mrTd };
    }
}
