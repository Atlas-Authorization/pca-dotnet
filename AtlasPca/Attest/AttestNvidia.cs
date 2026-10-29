// NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by the GPU's
// device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge bound through the SPDM
// request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP and a firmware policy). Same
// checks, order and reason text as the reference verifier. Classical (ECDSA-P384 / SHA-384); no network I/O.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal sealed class SpdmReport
{
    public int RequestVersion, ResponseVersion;
    public byte[] RequestNonce = Array.Empty<byte>(), Signature = Array.Empty<byte>(), SignedBytes = Array.Empty<byte>();
    public List<(int Index, byte[] Digest)> Measurements = new();
    public Dictionary<int, byte[]> Opaque = new();
}

internal sealed class NvidiaVerifier : IVendorImpl
{
    const int ReqLen = 37, NonceLen = 32, SigLen = 96, MaxChain = 5;
    internal const int OpaqueDriverVersion = 3, OpaqueVbiosVersion = 6, OpaqueChipInfo = 35;

    List<string> pins = new();
    readonly List<(int Index, string Digest)> want = new();
    string leafSub = "";
    NvidiaHook? hook;

    static int Le16(byte[] b, int o) => b[o] | (b[o + 1] << 8);

    /// <summary>SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree. Returns the failure reason or null.</summary>
    internal static string? VersionProblem(SpdmReport rep) =>
        rep.RequestVersion < 0x11 || rep.ResponseVersion != rep.RequestVersion
            ? $"SPDM version 0x{rep.RequestVersion:x}/0x{rep.ResponseVersion:x} is not an accepted GET_MEASUREMENTS version"
            : null;

    /// <summary>Parses a request||response transcript; it fails on any structural problem.</summary>
    internal static SpdmReport ParseEvidence(byte[] b)
    {
        if (b.Length < ReqLen + 8 + NonceLen + 2 + SigLen) throw new AttestError($"parseNvidiaSpdmEvidence: transcript too short ({b.Length})");
        if (b[1] != 0xe0) throw new AttestError($"parseNvidiaSpdmEvidence: request code 0x{b[1]:x} is not GET_MEASUREMENTS");
        var rep = new SpdmReport { RequestNonce = b[4..(4 + NonceLen)], RequestVersion = b[0] };
        var r = b[ReqLen..];
        if (r[1] != 0x60) throw new AttestError("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS");
        rep.ResponseVersion = r[0];
        int numBlocks = r[4];
        int recLen = r[5] | (r[6] << 8) | (r[7] << 16);
        int o = 8;
        if (o + recLen + NonceLen + 2 + SigLen > r.Length) throw new AttestError("parseNvidiaSpdmEvidence: measurement record length overruns transcript");
        int recEnd = o + recLen;
        while (o < recEnd)
        {
            if (o + 4 > recEnd) throw new AttestError("parseNvidiaSpdmEvidence: truncated measurement block header");
            int index = r[o];
            int size = Le16(r, o + 2);
            int bodyStart = o + 4;
            if (bodyStart + size > recEnd || size < 3) throw new AttestError("parseNvidiaSpdmEvidence: measurement block overruns record");
            int vsize = Le16(r, bodyStart + 1);
            if (3 + vsize > size) throw new AttestError("parseNvidiaSpdmEvidence: DMTF value overruns measurement block");
            rep.Measurements.Add((index, r[(bodyStart + 3)..(bodyStart + 3 + vsize)]));
            o = bodyStart + size;
        }
        if (rep.Measurements.Count != numBlocks) throw new AttestError($"parseNvidiaSpdmEvidence: header says {numBlocks} blocks, parsed {rep.Measurements.Count}");
        o += NonceLen;
        int opaqueLen = Le16(r, o);
        o += 2;
        if (o + opaqueLen + SigLen != r.Length) throw new AttestError("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript");
        int opaqueEnd = o + opaqueLen;
        while (o < opaqueEnd)
        {
            if (o + 4 > opaqueEnd) throw new AttestError("parseNvidiaSpdmEvidence: truncated opaque TLV header");
            int t = Le16(r, o), l = Le16(r, o + 2);
            o += 4;
            if (o + l > opaqueEnd) throw new AttestError("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data");
            rep.Opaque[t] = r[o..(o + l)];
            o += l;
        }
        rep.Signature = r[^SigLen..];
        rep.SignedBytes = b[..^SigLen];
        return rep;
    }

    /// <summary>String.prototype.slice for an ASCII string (negative indices count from the end).</summary>
    static string JsSlice(string s, int fromI, int toI)
    {
        int n = s.Length;
        int Norm(int i) { if (i < 0) { i += n; if (i < 0) i = 0; } return i > n ? n : i; }
        int a = Norm(fromI), b = Norm(toI);
        return a >= b ? "" : s[a..b];
    }

    /// <summary>NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex ("96.00.9f.00.04").</summary>
    internal static string FormatVbiosVersion(byte[] raw)
    {
        var rev = raw.Reverse().ToArray();
        var hx = AttestUtil.Hex(rev);
        int half = hx.Length / 2;
        var temp = JsSlice(hx, half, hx.Length) + JsSlice(hx, half - 2, half);
        var parts = new List<string>();
        for (int i = 0; i < temp.Length; i += 2) parts.Add(temp[i..Math.Min(i + 2, temp.Length)]);
        return string.Join(".", parts);
    }

    /// <summary>Node's X509Certificate.ca: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present.</summary>
    internal static bool CertIsCa(AttCert c)
    {
        try { var i = AttestDer.ReadCertRoleInfo(c.Raw); return i.HasBasicConstraints && i.Ca && (!i.HasKeyUsage || i.KeyCertSign); }
        catch (AttestError) { return false; }
    }

    internal static string SubjectLine(AttCert c) => AttestCerts.NameText(c.RawSubject).Replace("\n", ", ");

    /// <summary>Verifies the device chain (leaf first): every link signed, every issuer a CA, every certificate valid at nowMs, an ECDSA
    /// P-384 key throughout, the root self-signed and pinned by SPKI SHA-256.</summary>
    internal static (List<AttCert>? Chain, string Why) VerifyDeviceChain(string pemText, IReadOnlyList<string> pins, long nowMs)
    {
        var blocks = AttestCerts.PemBlocks(pemText);
        if (blocks.Count == 0) return (null, "device chain unparseable: parsePemChain: no certificates found");
        if (blocks.Count > MaxChain) return (null, $"device chain unparseable: parsePemChain: chain longer than {MaxChain}");
        var chain = new List<AttCert>();
        foreach (var b in blocks)
        {
            try { chain.Add(AttestCerts.FromPem(b)); }
            catch (AttestError e) { return (null, "device chain unparseable: " + e.Message); }
        }
        for (int i = 0; i < chain.Count; i++)
        {
            if (!AttestDer.DerValidAt(chain[i].Raw, nowMs, 0)) return (null, $"device chain cert #{i} is outside its validity window");
            CertKey? k = null;
            try { k = AttestCerts.KeyOf(chain[i]); } catch (AttestError) { }
            if (k == null || k.Type != "ec" || k.Curve != "secp384r1") return (null, $"device chain cert #{i} is not an ECDSA P-384 key");
        }
        for (int i = 0; i < chain.Count - 1; i++)
        {
            var issuer = chain[i + 1];
            if (!CertIsCa(issuer)) return (null, $"device chain cert #{i + 1} issues a certificate but is not a CA");
            if (!AttestCerts.SigOkBy(chain[i], issuer)) return (null, $"device chain link #{i} signature does not verify under its issuer");
        }
        var root = chain[^1];
        if (!CertIsCa(root) || !AttestCerts.SigOkBy(root, root)) return (null, "device chain root is not a self-signed CA");
        CertKey rk;
        try { rk = AttestCerts.KeyOf(root); } catch (AttestError) { return (null, "device chain root is not a self-signed CA"); }
        if (!pins.Any(p => p.ToLowerInvariant() == rk.SpkiSha256())) return (null, "chain root is not a pinned NVIDIA root");
        return (chain, "");
    }

    /// <summary>Number(s) for a measurement-block key / attribute (Ok false: NaN).</summary>
    internal static (double Value, bool Ok) JsNumberFromString(string s)
    {
        var t = AttestUtil.JsTrim(s);
        if (t.Length == 0) return (0, true);
        return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var f) ? (f, true) : (0, false);
    }

    internal static NvidiaVerifier Create(JD cfg)
    {
        var v = new NvidiaVerifier();
        NvidiaHook? hook = null;
        if (cfg.GetValueOrDefault("collateral") is JD col) hook = NvidiaHook.Create(col);
        var pins = AttestUtil.AsStrList(cfg.GetValueOrDefault("rootSpkiSha256"));
        if (pins == null || pins.Count == 0) throw new ArgumentException("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)");
        v.pins = pins;
        var pol = cfg.GetValueOrDefault("policy") as JD ?? new JD();
        var meas = pol.GetValueOrDefault("measurements") as JD ?? new JD();
        if (meas.Count == 0 && hook == null)
            throw new ArgumentException("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)");
        var entries = meas.Select(kv => { var (f, ok) = JsNumberFromString(kv.Key); return (Key: kv.Key, Idx: f, Num: ok, Dig: AttestAmd.JsAnyString(kv.Value).ToLowerInvariant()); }).ToList();
        entries.Sort((a, b) => a.Idx != b.Idx ? a.Idx.CompareTo(b.Idx) : IntentJs.CompareUtf8(a.Key, b.Key));
        foreach (var e in entries)
        {
            if (!e.Num || e.Idx != Math.Truncate(e.Idx) || e.Idx < 0 || e.Idx > 255) throw new ArgumentException("createNvidiaSpdmVerifier: measurement index out of range");
            v.want.Add(((int)e.Idx, e.Dig));
        }
        v.leafSub = pol.GetValueOrDefault("leafSubjectIncludes") as string ?? "";
        v.hook = hook;
        return v;
    }

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        var evidence = AttestEvidence.Bytes(ev, "evidence"); var chainPem = AttestEvidence.Str(ev, "certChainPem");
        if (ev == null || evidence == null || chainPem == null) return HardwareResult.Fail("no NVIDIA GPU evidence for this action");
        var (chain, why) = VerifyDeviceChain(chainPem, pins, nowMs);
        if (chain == null) return HardwareResult.Fail(why);
        var leaf = chain[0];
        if (leafSub.Length > 0 && !AttestCerts.NameText(leaf.RawSubject).Contains(leafSub, StringComparison.Ordinal)) return HardwareResult.Fail($"device leaf subject does not contain '{leafSub}'");
        SpdmReport rep;
        try { rep = ParseEvidence(evidence); }
        catch (AttestError e) { return HardwareResult.Fail("GPU attestation report parse failed: " + e.Message); }
        if (VersionProblem(rep) is { } vp) return HardwareResult.Fail(vp);
        CertKey? lk = null;
        try { lk = AttestCerts.KeyOf(leaf); } catch (AttestError) { }
        bool sigOk = false;
        if (lk?.Ec != null)
        {
            try { sigOk = lk.Ec.VerifyHash(AttestUtil.Sha384(rep.SignedBytes), rep.Signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); } catch (Exception) { }
        }
        if (!sigOk) return HardwareResult.Fail("GPU attestation report signature does not verify under the device identity key");
        if (expected == null) return HardwareResult.Fail("no expected attestation binding supplied");
        byte[] raw;
        try { raw = AttestUtil.BindingBytes(expected); }
        catch (AttestError e) { return HardwareResult.Fail("binding not constructible: " + e.Message); }
        if (!rep.RequestNonce.AsSpan().SequenceEqual(AttestUtil.Sha256(raw))) return HardwareResult.Fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)");
        var byIndex = new Dictionary<int, byte[]>();
        foreach (var (i, d) in rep.Measurements) byIndex[i] = d;
        foreach (var (idx, dig) in want)
        {
            if (!byIndex.TryGetValue(idx, out var m)) return HardwareResult.Fail($"measurement block {idx} missing from report");
            if (AttestUtil.Hex(m) != dig) return HardwareResult.Fail($"measurement block {idx} does not match the pinned digest");
        }
        if (hook != null)
        {
            var w = hook.WithBundle(ev.GetValueOrDefault("collateral") as JD).Run(rep, chain, nowMs);
            if (w.Length > 0) return HardwareResult.Fail(w);
        }
        var sorted = rep.Measurements.OrderBy(m => m.Index).ToList();
        var all = new List<byte>();
        foreach (var m in sorted) all.AddRange(m.Digest);
        var host = new Dictionary<string, string>
        {
            ["attestation_type"] = "nvidia-gpu-cc",
            ["gpu_measurements_sha384"] = AttestUtil.Hex(AttestUtil.Sha384(all.ToArray())),
            ["leaf_subject"] = AttestCerts.NameText(leaf.RawSubject).Replace("\n", ", "),
        };
        if (rep.Opaque.TryGetValue(OpaqueDriverVersion, out var drv)) host["driver_version"] = Encoding.UTF8.GetString(drv).TrimEnd('\0');
        if (rep.Opaque.TryGetValue(OpaqueVbiosVersion, out var vb)) host["vbios_version"] = FormatVbiosVersion(vb);
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured("", ""), host);
    }
}
