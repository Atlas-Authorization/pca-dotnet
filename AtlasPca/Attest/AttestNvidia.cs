// NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by the GPU's
// device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge bound through the SPDM
// request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP and a firmware policy). Same
// checks, order and reason text as the reference verifier. Classical (ECDSA-P384 / SHA-384); no network I/O.
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
    string leafSub = null!; // always set by Create
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

    /// <summary>NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex ("96.00.9f.00.04").</summary>
    internal static string FormatVbiosVersion(byte[] raw)
    {
        var rev = raw.Reverse().ToArray();
        var hx = AttestUtil.Hex(rev);
        int half = hx.Length / 2;
        // JS hex.slice(half - 2, half) is empty below two bytes: slice(-1, 1) over two digits, slice(-2, 0) over none
        var temp = hx[half..] + (half >= 2 ? hx[(half - 2)..half] : "");
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

    const string OidAkid = "2.5.29.35", OidSkid = "2.5.29.14";

    /// <summary>The value of an extension; OpenSSL's decoder treats a repeated one as invalid.</summary>
    static byte[]? OneExt(AttCert c, string oid)
    {
        if (c.Exts.Count(e => e.Oid == oid) > 1) throw new AttestError("repeated extension");
        return c.ExtValue(oid);
    }

    static byte[]? ReadSkid(AttCert c)
    {
        if (OneExt(c, OidSkid) is not { } v) return null;
        var e = AttestCerts.ReadElem(v, 0, v.Length, 0x04);
        return v[e.Start..e.End];
    }

    /// <summary>An AuthorityKeyIdentifier as OpenSSL decodes it: [0] key id, [1] general names, [2] serial, each optional, once and in that order.
    /// It returns the key id, the first directory name (header included) and the serial; anything else throws.</summary>
    static (byte[]? KeyId, byte[]? Dn, byte[]? Serial) ReadAkid(AttCert c)
    {
        byte[]? keyId = null, dn = null, serial = null;
        if (OneExt(c, OidAkid) is not { } v) return (keyId, dn, serial);
        int last = -1;
        foreach (var k in AttestCerts.Kids(v, AttestCerts.ReadElem(v, 0, v.Length, 0x30)))
        {
            int rank = k.Tag switch { 0x80 => 0, 0xa1 => 1, 0x82 => 2, _ => -1 };
            if (rank <= last) throw new AttestError("authority key identifier is malformed");
            last = rank;
            if (rank == 0) keyId = v[k.Start..k.End];
            else if (rank == 2) serial = v[k.Start..k.End];
            else foreach (var g in AttestCerts.Kids(v, k))
            {
                CertExts.GeneralName(v, g);
                if (g.Tag == 0xa4)
                {
                    var name = AttestCerts.ReadElem(v, g.Start, g.End, 0x30);
                    dn ??= v[name.Hdr..name.End];
                }
            }
        }
        return (keyId, dn, serial);
    }

    /// <summary>X509_check_issued: the DN link, the authority key identifier (key id against the issuer's, when it has one; serial and first
    /// directory name against the issuer's serial and issuer name), and keyCertSign on the issuer when it has a keyUsage. A malformed or repeated key
    /// identifier, or any other extension of <see cref="CertExts"/>, on either certificate fails. Names compare by bytes, where OpenSSL compares them canonically.</summary>
    internal static bool CheckIssued(AttCert c, AttCert issuer)
    {
        if (!c.RawIssuer.AsSpan().SequenceEqual(issuer.RawSubject)) return false;
        try
        {
            var skid = ReadSkid(issuer);
            ReadSkid(c);
            ReadAkid(issuer);
            CertExts.Check(c);
            CertExts.Check(issuer);
            var (keyId, dn, serial) = ReadAkid(c);
            if (keyId != null && skid != null && !keyId.AsSpan().SequenceEqual(skid)) return false;
            if (serial != null && !serial.AsSpan().SequenceEqual(issuer.Serial)) return false;
            if (dn != null && !dn.AsSpan().SequenceEqual(issuer.RawIssuer)) return false;
            var info = AttestDer.ReadCertRoleInfo(issuer.Raw);
            return !info.HasKeyUsage || info.KeyCertSign;
        }
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
        var profile = AttestDer.StrictChainError(chain.Select(c => c.Raw).ToList());
        if (profile != null) return (null, "device chain profile: " + profile);
        var root = chain[^1];
        if (!CertIsCa(root) || !AttestCerts.SigOkBy(root, root)) return (null, "device chain root is not a self-signed CA");
        var rk = AttestCerts.KeyOf(root); // the key loop above already read this key
        if (!pins.Any(p => p.ToLowerInvariant() == rk.SpkiSha256())) return (null, "chain root is not a pinned NVIDIA root");
        return (chain, "");
    }

    /// <summary>Number(s) for a measurement-block key / attribute (Ok false: NaN).</summary>
    internal static (double Value, bool Ok) JsNumberFromString(string s)
    {
        // not double.TryParse: it also takes "INFINITY", "NaN" and a trailing NUL, and refuses the hex / octal / binary forms JS reads
        var f = Actions.JsNumber(s, true);
        return double.IsNaN(f) ? (0, false) : (f, true);
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
        // Object.entries order: array-index keys ascending, then the other keys in insertion order (OrderBy is stable); a key above 255 is refused below
        var entries = meas.Select(kv => { var (f, ok) = JsNumberFromString(kv.Key); return (Key: kv.Key, Idx: f, Num: ok, Dig: AttestAmd.JsAnyString(kv.Value).ToLowerInvariant()); })
            .OrderBy(e => e.Idx is >= 0 and <= 255 && e.Key == ((int)e.Idx).ToString() ? e.Idx : 256).ToList();
        foreach (var e in entries)
        {
            if (!e.Num || e.Idx != Math.Truncate(e.Idx) || e.Idx < 0 || e.Idx > 255) throw new ArgumentException("createNvidiaSpdmVerifier: measurement index out of range");
            v.want.Add(((int)e.Idx, e.Dig));
        }
        v.leafSub = pol.GetValueOrDefault("leafSubjectIncludes") is { } ls ? AttestAmd.JsAnyString(ls) : ""; // a non-string must not disable the check
        v.hook = hook;
        return v;
    }

    /// <summary>The report signature under the leaf key (false when that key cannot be read or is not EC).</summary>
    internal static bool LeafSigOk(AttCert leaf, SpdmReport rep)
    {
        CertKey? lk = null;
        try { lk = AttestCerts.KeyOf(leaf); } catch (AttestError) { }
        bool sigOk = false;
        if (lk?.Ec != null)
        {
            try { sigOk = lk.Ec.VerifyHash(AttestUtil.Sha384(rep.SignedBytes), rep.Signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); } catch (Exception) { }
        }
        return sigOk;
    }

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        var evidence = AttestEvidence.Bytes(ev, "evidence"); var chainPem = AttestEvidence.Str(ev, "certChainPem");
        if (ev == null || evidence == null || chainPem == null) return HardwareResult.Fail("no NVIDIA GPU evidence for this action");
        var (chain, why) = VerifyDeviceChain(chainPem, pins, nowMs);
        if (chain == null) return HardwareResult.Fail(why);
        var leaf = chain[0];
        if (!AttestCerts.NameText(leaf.RawSubject).Contains(leafSub, StringComparison.Ordinal)) return HardwareResult.Fail($"device leaf subject does not contain '{leafSub}'");
        SpdmReport rep;
        try { rep = ParseEvidence(evidence); }
        catch (AttestError e) { return HardwareResult.Fail("GPU attestation report parse failed: " + e.Message); }
        if (VersionProblem(rep) is { } vp) return HardwareResult.Fail(vp);
        if (!LeafSigOk(leaf, rep)) return HardwareResult.Fail("GPU attestation report signature does not verify under the device identity key");
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
