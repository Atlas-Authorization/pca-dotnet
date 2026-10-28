// NVIDIA GPU-CC collateral: Reference Integrity Manifests (SWID/CoRIM XML, enveloped XMLDSig, strict profile), the golden measurement
// comparison with NVIDIA's merge / alternatives / NVDEC0 rules, the driver / VBIOS version binding, certificate revocation through
// CRLs and OCSP (RFC 6960), and a firmware policy. Fetching is never automatic: the RIMs, CRLs and OCSP responses arrive with the
// evidence. Same checks, order and reason text as the reference.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal sealed record RimGolden(int Index, bool Active, int Alternatives, int Size, List<string> Hashes);

internal sealed class VerifiedRim
{
    public string Product = "", Version = "";
    public Dictionary<int, RimGolden> Golden = new();
}

internal sealed class FirmwarePolicy
{
    public List<double>? MinD, MinV;
    public List<List<double>> DenyD = new(), DenyV = new();
    public string MinDText = "", MinVText = "";

    static readonly Regex Dec10 = new(@"^[0-9]+(\.[0-9]+)*\z", RegexOptions.CultureInvariant);
    static readonly Regex Hex16 = new(@"^[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*\z", RegexOptions.CultureInvariant);

    internal static List<double>? ParseVersion(string v, int radix)
    {
        if (!(radix == 16 ? Hex16 : Dec10).IsMatch(v)) return null;
        var o = new List<double>();
        foreach (var p in v.Split('.'))
        {
            if (radix == 16) { o.Add(ulong.Parse(p, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture)); continue; }
            o.Add(ulong.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : double.Parse(p, CultureInfo.InvariantCulture));
        }
        return o;
    }

    internal static int Cmp(List<double> a, List<double> b)
    {
        int n = Math.Max(a.Count, b.Count);
        for (int i = 0; i < n; i++)
        {
            double x = i < a.Count ? a[i] : 0, y = i < b.Count ? b[i] : 0;
            double d = x - y;
            if (d != 0) return d < 0 ? -1 : 1;
        }
        return 0;
    }

    internal static FirmwarePolicy Compile(JD fw)
    {
        var p = new FirmwarePolicy();
        List<double> Need(string v, int radix, string what) => ParseVersion(v, radix) ?? throw new ArgumentException($"nvidiaCollateralHook: malformed {what} '{v}'");
        if (fw.GetValueOrDefault("minDriverVersion") is string s1 && s1.Length > 0) { p.MinD = Need(s1, 10, "minDriverVersion"); p.MinDText = s1; }
        if (fw.GetValueOrDefault("minVbiosVersion") is string s2 && s2.Length > 0) { p.MinV = Need(s2, 16, "minVbiosVersion"); p.MinVText = s2; }
        foreach (var s in (fw.GetValueOrDefault("denyDriverVersions") as JL ?? new JL()).OfType<string>()) p.DenyD.Add(Need(s, 10, "denyDriverVersions entry"));
        foreach (var s in (fw.GetValueOrDefault("denyVbiosVersions") as JL ?? new JL()).OfType<string>()) p.DenyV.Add(Need(s, 16, "denyVbiosVersions entry"));
        return p;
    }

    internal string Check(NvidiaRimIds ids)
    {
        var d = ParseVersion(ids.DriverVersion, 10); var v = ParseVersion(ids.VbiosVersion, 16);
        if (d == null) return $"driver version '{ids.DriverVersion}' in the GPU report is not parseable";
        if (v == null) return $"VBIOS version '{ids.VbiosVersion}' in the GPU report is not parseable";
        if (MinD != null && Cmp(d, MinD) < 0) return $"driver {ids.DriverVersion} is below the minimum {MinDText}";
        if (MinV != null && Cmp(v, MinV) < 0) return $"VBIOS {ids.VbiosVersion} is below the minimum {MinVText}";
        foreach (var x in DenyD) if (Cmp(d, x) == 0) return $"driver {ids.DriverVersion} is on the deny list";
        foreach (var x in DenyV) if (Cmp(v, x) == 0) return $"VBIOS {ids.VbiosVersion} is on the deny list";
        return "";
    }
}

internal sealed class NvidiaRimIds
{
    public string Chip = "", Driver = "", Vbios = "", DriverVersion = "", VbiosVersion = "";
}

internal sealed class NvidiaBundle
{
    public string DriverRim = "", VbiosRim = "";
    public List<byte[]> Crls = new(), Ocsp = new();
}

internal sealed class NvidiaHook
{
    List<string> rimPins = new();
    string revocation = "";
    bool hasRevocation, requireCrls = true;
    List<string> requireIssuers = new();
    FirmwarePolicy? firmware;
    NvidiaBundle? bundle;

    const string NsDsig = "http://www.w3.org/2000/09/xmldsig#", AlgC14N11 = "http://www.w3.org/2006/12/xml-c14n11",
        AlgEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature", AlgEcdsa384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        AlgSha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    const int Nvdec0Off = 0x55, NvdecBlock = 35;

    internal static NvidiaHook Create(JD col)
    {
        var h = new NvidiaHook { requireCrls = col.GetValueOrDefault("requireCrls") is not false };
        var pins = AttestUtil.AsStrList(col.GetValueOrDefault("rimRootSpkiSha256"));
        if (pins == null || pins.Count == 0) throw new ArgumentException("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root");
        h.rimPins = pins;
        if (col.GetValueOrDefault("firmware") is JD fw) h.firmware = FirmwarePolicy.Compile(fw);
        if (col.GetValueOrDefault("revocation") is string r) { h.revocation = r; h.hasRevocation = true; }
        h.requireIssuers = (col.GetValueOrDefault("requireCrlIssuers") as JL ?? new JL()).OfType<string>().ToList();
        return h;
    }

    /// <summary>The hook bound to the collateral of one evidence object (null: none supplied).</summary>
    internal NvidiaHook WithBundle(JD? c)
    {
        var cp = (NvidiaHook)MemberwiseClone();
        if (c == null) { cp.bundle = null; return cp; }
        var b = new NvidiaBundle { DriverRim = c.GetValueOrDefault("driverRimXml") as string ?? "", VbiosRim = c.GetValueOrDefault("vbiosRimXml") as string ?? "" };
        foreach (var s in (c.GetValueOrDefault("crls") as JL ?? new JL()).OfType<string>()) b.Crls.Add(AttestUtil.NodeB64(s));
        foreach (var s in (c.GetValueOrDefault("ocsp") as JL ?? new JL()).OfType<string>()) b.Ocsp.Add(AttestUtil.NodeB64(s));
        cp.bundle = b;
        return cp;
    }

    // ---- RIM

    static string StripJsSpace(string s) => new(s.Where(c => !AttestUtil.IsJsSpace(c)).ToArray());

    static string PemOfDerB64(string b64)
    {
        var body = StripJsSpace(b64);
        var lines = new List<string>();
        for (int i = 0; i < body.Length; i += 64) lines.Add(body[i..Math.Min(i + 64, body.Length)]);
        return "-----BEGIN CERTIFICATE-----\n" + string.Join("\n", lines) + "\n-----END CERTIFICATE-----";
    }

    static readonly Regex HashAttrRe = new(@"^Hash[0-9]+\z", RegexOptions.CultureInvariant);
    static readonly Regex LowerHexRe = new(@"^[0-9a-f]+\z", RegexOptions.CultureInvariant);

    /// <summary>Verifies a RIM document and returns its golden measurements. A failure reason, or the manifest.</summary>
    internal static (VerifiedRim? Rim, string Why) VerifyRim(string xml, IReadOnlyList<string> rimPins, long nowMs)
    {
        static (VerifiedRim?, string) Fail(string r) => (null, r);
        if (xml.Length == 0 || xml.Length > 4_000_000) return Fail("RIM: empty or oversized document");
        if (rimPins.Count == 0) return Fail("RIM: no pinned RIM root configured");
        XmlDoc doc;
        try { doc = AttestXml.Parse(xml); }
        catch (AttestError e) { return Fail("RIM: verification error (fail closed): " + e.Message); }
        if (doc.Violation.Length > 0) return Fail("RIM: " + doc.Violation);
        var root = doc.Root!;
        if (root.Local != "SoftwareIdentity") return Fail("RIM: root element is not SoftwareIdentity");
        if (root.DescendantsNs(NsDsig, "Signature") != 1) return Fail("RIM: expected exactly one Signature element");
        var sigs = root.ElementChildrenNs(NsDsig, "Signature");
        if (sigs.Count != 1) return Fail("RIM: the Signature must be a direct child of the root");
        var sig = sigs[0];
        var signedInfo = sig.ElementChildrenNs(NsDsig, "SignedInfo");
        if (signedInfo.Count != 1) return Fail("RIM: expected exactly one SignedInfo");
        var si = signedInfo[0];
        static string AlgOf(List<XmlNode> els) => els.Count == 0 ? "" : els[0].Attr("Algorithm");
        if (AlgOf(si.ElementChildrenNs(NsDsig, "CanonicalizationMethod")) != AlgC14N11) return Fail("RIM: CanonicalizationMethod must be C14N 1.1");
        if (AlgOf(si.ElementChildrenNs(NsDsig, "SignatureMethod")) != AlgEcdsa384) return Fail("RIM: SignatureMethod must be ECDSA-SHA384");
        var refs = si.ElementChildrenNs(NsDsig, "Reference");
        if (refs.Count != 1) return Fail("RIM: expected exactly one Reference");
        var rf = refs[0];
        if (rf.Attr("URI") != "") return Fail("RIM: Reference URI must be \"\" (the whole document)");
        var holder = rf;
        var ts = rf.ElementChildrenNs(NsDsig, "Transforms");
        if (ts.Count > 0) holder = ts[0];
        var transforms = holder.ElementChildrenNs(NsDsig, "Transform").Select(t => t.Attr("Algorithm")).ToList();
        if (transforms.Count != 2 || transforms[0] != AlgEnveloped || transforms[1] != AlgC14N11) return Fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]");
        if (AlgOf(rf.ElementChildrenNs(NsDsig, "DigestMethod")) != AlgSha384) return Fail("RIM: DigestMethod must be SHA-384");
        string digestValue = "", sigValueB64 = "";
        var dv = rf.ElementChildrenNs(NsDsig, "DigestValue");
        if (dv.Count > 0) digestValue = StripJsSpace(dv[0].TextContent());
        var sv = sig.ElementChildrenNs(NsDsig, "SignatureValue");
        if (sv.Count > 0) sigValueB64 = StripJsSpace(sv[0].TextContent());
        if (digestValue.Length == 0 || sigValueB64.Length == 0) return Fail("RIM: missing DigestValue / SignatureValue");

        var certB64 = new List<string>();
        var ki = sig.ElementChildrenNs(NsDsig, "KeyInfo");
        if (ki.Count > 0)
        {
            var xd = ki[0].ElementChildrenNs(NsDsig, "X509Data");
            if (xd.Count > 0) foreach (var c in xd[0].ElementChildrenNs(NsDsig, "X509Certificate")) certB64.Add(c.TextContent());
        }
        if (certB64.Count == 0) return Fail("RIM: no signer certificates in KeyInfo");
        var (chain, why) = NvidiaVerifier.VerifyDeviceChain(string.Join("\n", certB64.Select(PemOfDerB64)), rimPins, nowMs);
        if (chain == null) return Fail("RIM signer chain: " + why);

        var siCanon = AttestXml.Canonicalize(si, si.Parent!.Scope(), null);
        var sigRaw = AttestUtil.NodeB64(sigValueB64);
        if (sigRaw.Length != 96) return Fail("RIM: SignatureValue is not a 96-byte P-384 signature");
        bool sigOk = false;
        try
        {
            var lk = AttestCerts.KeyOf(chain[0]);
            sigOk = lk.Ec != null && lk.Ec.VerifyHash(AttestUtil.Sha384(Encoding.UTF8.GetBytes(siCanon)), sigRaw, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception) { sigOk = false; }
        if (!sigOk) return Fail("RIM: SignedInfo signature does not verify under the signer certificate");

        var canon = AttestXml.Canonicalize(root, new Dictionary<string, string>(StringComparer.Ordinal), sig);
        if (Convert.ToBase64String(AttestUtil.Sha384(Encoding.UTF8.GetBytes(canon))) != digestValue) return Fail("RIM: document digest does not match the signed DigestValue");

        XmlNode? meta = null, payload = null;
        foreach (var c in root.ElementChildren())
        {
            if (meta == null && c.Local == "Meta") meta = c;
            if (payload == null && c.Local == "Payload") payload = c;
        }
        if (meta == null || payload == null) return Fail("RIM: missing Meta / Payload");
        var golden = new Dictionary<int, RimGolden>();
        foreach (var r in payload.ElementChildren())
        {
            if (r.Local != "Resource" || r.Attr("type") != "Measurement") continue;
            var (index, iok) = NvidiaVerifier.JsNumberFromString(r.Attr("index"));
            var (alts, aok) = NvidiaVerifier.JsNumberFromString(r.Attr("alternatives"));
            var (size, sok) = NvidiaVerifier.JsNumberFromString(r.Attr("size"));
            var hs = new List<(int N, string V)>();
            foreach (var a in r.Attrs)
                if (HashAttrRe.IsMatch(a.Local)) hs.Add((int.TryParse(a.Local[4..], NumberStyles.None, CultureInfo.InvariantCulture, out var hn) ? hn : 0, a.Value.ToLowerInvariant()));
            hs = hs.OrderBy(x => x.N).ToList();
            static bool IsInt(double f, bool ok, double min) => ok && Math.Abs(f) < 9e18 && f == (double)(long)f && f >= min;
            if (!IsInt(index, iok, 0) || !IsInt(alts, aok, 1) || !IsInt(size, sok, 1)) return Fail("RIM: malformed Measurement resource");
            var hashes = hs.Select(x => x.V).ToList();
            bool bad = hashes.Count != (int)alts;
            foreach (var h in hashes) if (!LowerHexRe.IsMatch(h) || h.Length != (int)size * 2) bad = true;
            if (bad) return Fail($"RIM: Measurement {(int)index} hash list is inconsistent with alternatives/size");
            if (golden.ContainsKey((int)index)) return Fail($"RIM: duplicate Measurement index {(int)index}");
            golden[(int)index] = new RimGolden((int)index, r.Attr("active").ToLowerInvariant() == "true", (int)alts, (int)size, hashes);
        }
        if (golden.Count == 0) return Fail("RIM: no measurements");
        return (new VerifiedRim { Product = meta.Attr("product"), Version = meta.Attr("colloquialVersion"), Golden = golden }, "");
    }

    // ---- RIM ids named by the (signed) GPU report

    static string OpaqueAscii(byte[]? b) => b == null ? "" : AttestUtil.JsTrim(Encoding.Latin1.GetString(b).TrimEnd('\0'));

    static readonly Regex ChipNameRe = new(@"^[A-Z][A-Z0-9]{2,11}\z", RegexOptions.CultureInvariant);

    static NvidiaRimIds? RimIdsForReport(SpdmReport rep)
    {
        var o = rep.Opaque;
        byte[]? Get(int k) => o.GetValueOrDefault(k);
        var driverVersion = OpaqueAscii(Get(NvidiaVerifier.OpaqueDriverVersion));
        var vb = Get(NvidiaVerifier.OpaqueVbiosVersion);
        var project = OpaqueAscii(Get(17)).ToUpperInvariant(); var projectSku = OpaqueAscii(Get(18)).ToUpperInvariant(); var chipSku = OpaqueAscii(Get(15)).ToUpperInvariant();
        if (driverVersion.Length == 0 || vb == null || project.Length == 0 || projectSku.Length == 0 || chipSku.Length == 0) return null;
        var chip = "GH100";
        if (Get(NvidiaVerifier.OpaqueChipInfo) is { } raw)
        {
            chip = OpaqueAscii(raw);
            if (!ChipNameRe.IsMatch(chip)) return null;
        }
        var vbiosVersion = NvidiaVerifier.FormatVbiosVersion(vb);
        var ids = new NvidiaRimIds { Chip = chip, DriverVersion = driverVersion, VbiosVersion = vbiosVersion };
        ids.Driver = chip == "GH100" ? "NV_GPU_DRIVER_GH100_" + driverVersion : "NV_GPU_CC_DRIVER_" + chip + "_" + driverVersion;
        ids.Vbios = "NV_GPU_VBIOS_" + project + "_" + projectSku + "_" + chipSku + "_" + vbiosVersion.Replace(".", "").ToUpperInvariant();
        return ids;
    }

    /// <summary>Compares a report with the driver and VBIOS RIMs (NVIDIA's merge / alternatives / NVDEC0 rules); "" when it matches.</summary>
    static string CompareReportToRims(SpdmReport rep, VerifiedRim driver, VerifiedRim vbios)
    {
        var merged = new Dictionary<int, RimGolden>();
        foreach (var g in driver.Golden.Values) if (g.Active) merged[g.Index] = g;
        foreach (var i in vbios.Golden.Keys.OrderBy(k => k))
        {
            var g = vbios.Golden[i];
            if (!g.Active) continue;
            if (merged.ContainsKey(g.Index)) return $"driver and VBIOS RIMs both have an active measurement at index {g.Index}";
            merged[g.Index] = g;
        }
        if (merged.Count == 0) return "RIMs carry no active golden measurements";
        var runtime = new Dictionary<int, byte[]>();
        foreach (var (index, digest) in rep.Measurements) runtime[index - 1] = digest;
        if (merged.Count > runtime.Count) return "RIMs list more active measurements than the report carries";
        bool nvdecDisabled = rep.Opaque.TryGetValue(11, out var nvdec) && nvdec.Length > 0 && nvdec[0] == Nvdec0Off;
        int mismatches = 0;
        foreach (var index in merged.Keys.OrderBy(k => k))
        {
            var g = merged[index];
            if (index + 1 == NvdecBlock && nvdecDisabled) continue;
            bool has = runtime.TryGetValue(index, out var digest);
            if (!has || digest!.Length != g.Size || !g.Hashes.Contains(AttestUtil.Hex(digest))) mismatches++;
        }
        return mismatches > 0 ? $"runtime measurements differ from the golden RIM values at {mismatches} index(es)" : "";
    }

    /// <summary>Checks the device chain against CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate may
    /// be listed by its issuer's CRL, and each required issuer must have a verified CRL. "" when it holds.</summary>
    static string CheckChainRevocation(List<AttCert> chain, List<byte[]> crls, long nowMs, List<string> requireIssuers)
    {
        if (crls.Count == 0) return "no CRLs supplied";
        var covered = new HashSet<int>();
        for (int ci = 0; ci < crls.Count; ci++)
        {
            int issuerIdx = -1;
            HashSet<string>? revoked = null;
            var lastReason = "no chain certificate verifies it";
            for (int i = 0; i < chain.Count; i++)
            {
                CertKey k;
                try { k = AttestCerts.KeyOf(chain[i]); } catch (AttestError) { continue; }
                var (rv, why) = AttestIntelCollateral.VerifyCrl(crls[ci], k, nowMs);
                if (why.Length == 0) { issuerIdx = i; revoked = rv; break; }
                if (lastReason == "no chain certificate verifies it" || lastReason.Contains("signature does not verify", StringComparison.Ordinal)) lastReason = why;
            }
            if (issuerIdx < 0 || revoked == null) return $"CRL #{ci} rejected: {lastReason}";
            covered.Add(issuerIdx);
            for (int i = 0; i < chain.Count - 1; i++)
                if (i + 1 == issuerIdx && revoked.Contains(chain[i].SerialHex)) return $"chain certificate '{NvidiaVerifier.SubjectLine(chain[i])}' is revoked";
        }
        foreach (var need in requireIssuers)
            if (!covered.Any(i => AttestCerts.NameText(chain[i].RawSubject).Contains(need, StringComparison.Ordinal))) return $"no verified CRL issued by a certificate matching '{need}'";
        return "";
    }

    /// <summary>The hook proper: the failure reason, or "" when the collateral holds.</summary>
    internal string Run(SpdmReport rep, List<AttCert> chain, long nowMs)
    {
        var ids = RimIdsForReport(rep);
        if (ids == null) return "GPU report does not carry the opaque fields needed to name its RIMs";
        var leaf = chain[0];
        var subject = AttestCerts.NameText(leaf.RawSubject);
        var chipRe = new Regex(@"(^|[^A-Za-z0-9])" + Regex.Escape(ids.Chip) + @"([^A-Za-z0-9]|$)", RegexOptions.CultureInvariant);
        if (!chipRe.IsMatch(subject)) return $"device leaf subject '{subject.Replace("\n", ", ")}' is not a {ids.Chip} device certificate (chip family mismatch)";
        var fw = firmware?.Check(ids) ?? "";
        if (fw.Length > 0) return "firmware policy: " + fw;
        if (bundle == null) return "no RIM collateral supplied for this report";
        var (d, dwhy) = VerifyRim(bundle.DriverRim, rimPins, nowMs);
        var (v, vwhy) = VerifyRim(bundle.VbiosRim, rimPins, nowMs);
        if (d == null) return "driver RIM: " + dwhy;
        if (v == null) return "VBIOS RIM: " + vwhy;
        if (d.Product != ids.Chip) return $"driver RIM product '{d.Product}' does not match the GPU chip '{ids.Chip}' (wrong-family manifest)";
        if (v.Product != ids.Chip) return $"VBIOS RIM product '{v.Product}' does not match the GPU chip '{ids.Chip}' (wrong-family manifest)";
        if (d.Version != ids.DriverVersion) return $"driver RIM version '{d.Version}' does not match the report's driver '{ids.DriverVersion}'";
        if (v.Version.Replace(".", "").ToUpperInvariant() != ids.VbiosVersion.Replace(".", "").ToUpperInvariant()) return $"VBIOS RIM version '{v.Version}' does not match the report's VBIOS '{ids.VbiosVersion}'";
        var cmp = CompareReportToRims(rep, d, v);
        if (cmp.Length > 0) return cmp;
        var mode = hasRevocation ? revocation : requireCrls ? "crl" : "";
        if (bundle.Crls.Count > 0 || mode == "crl" || mode == "both")
        {
            var why = CheckChainRevocation(chain, bundle.Crls, nowMs, requireIssuers);
            if (why.Length > 0) return "revocation: " + why;
        }
        if (bundle.Ocsp.Count > 0 || mode == "ocsp" || mode == "both")
        {
            var why = NvidiaOcsp.CheckChain(chain, bundle.Ocsp, nowMs);
            if (why.Length > 0) return "revocation (OCSP): " + why;
        }
        return "";
    }
}

/// <summary>NVIDIA GPU-CC device-chain revocation through OCSP (RFC 6960): the offline-verifiable equivalent of NVIDIA's own check. For each
/// non-root certificate the supplied responses are verified (responseStatus, CertID, BasicOCSPResponse signature under the issuer or a
/// delegated responder certificate signed by the supplied chain, freshness) and the status must be GOOD where it is required.</summary>
internal static class NvidiaOcsp
{
    const string OidOcspBasic = "1.3.6.1.5.5.7.48.1.1";
    const long DefaultMaxMs = 7L * 24 * 3600 * 1000;

    static readonly Dictionary<string, (string Hash, bool Ec)> SigAlgs = new()
    {
        ["1.2.840.10045.4.3.2"] = ("SHA256", true), ["1.2.840.10045.4.3.3"] = ("SHA384", true), ["1.2.840.10045.4.3.4"] = ("SHA512", true),
        ["1.2.840.113549.1.1.11"] = ("SHA256", false), ["1.2.840.113549.1.1.12"] = ("SHA384", false), ["1.2.840.113549.1.1.13"] = ("SHA512", false),
    };

    static readonly Dictionary<string, string> CertIdHashes = new()
    {
        ["1.3.14.3.2.26"] = "SHA1", ["2.16.840.1.101.3.4.2.1"] = "SHA256", ["2.16.840.1.101.3.4.2.2"] = "SHA384", ["2.16.840.1.101.3.4.2.3"] = "SHA512",
    };

    readonly record struct Node(byte Tag, int Hdr, int Start, int End)
    {
        public bool Constructed => (Tag & 0x20) != 0;
    }

    static Node ReadNode(byte[] b, int off, int limit)
    {
        DerTlv t;
        try
        {
            var sub = limit == b.Length ? b : b[..limit];
            t = AttestDer.TlvAt(sub, off);
        }
        catch (AttestError) { throw new AttestError("not valid DER"); }
        if ((t.Tag & 0x1f) == 0x1f) throw new AttestError("multi-byte tags are not supported");
        return new Node(t.Tag, off, t.Start, t.End);
    }

    static List<Node> Kids(byte[] b, Node n)
    {
        var o = new List<Node>();
        for (int p = n.Start; p < n.End;)
        {
            var k = ReadNode(b, p, n.End);
            o.Add(k);
            p = k.End;
        }
        return o;
    }

    static string OidOf(byte[] b, Node n)
    {
        if (n.Tag != 0x06) throw new AttestError("expected an OBJECT IDENTIFIER");
        return AttestCerts.DottedOid(b, new DerTlv(n.Tag, n.Start, n.End));
    }

    static readonly Regex RevTimeRe = new(@"^[0-9]{14}Z\z", RegexOptions.CultureInvariant);
    static readonly Regex GenTimeRe = new(@"^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z\z", RegexOptions.CultureInvariant);
    static readonly Regex UtcTimeRe = new(@"^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z", RegexOptions.CultureInvariant);

    /// <summary>Reads a DER time in range (no roll-over): epoch ms, or null.</summary>
    static long? TimeMs(string text, bool utc)
    {
        var m = (utc ? UtcTimeRe : GenTimeRe).Match(text);
        if (!m.Success) return null;
        int G(int i) => int.Parse(m.Groups[i].Value, CultureInfo.InvariantCulture);
        int y = G(1);
        if (utc) y += y < 50 ? 2000 : 1900;
        int mo = G(2), d = G(3), h = G(4), mi = G(5), s = G(6);
        if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return null;
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int dim = mo == 2 ? (leap ? 29 : 28) : mo is 4 or 6 or 9 or 11 ? 30 : 31;
        if (d > dim) return null;
        long ms = AttestDer.EpochMs(y, mo, d, h, mi, s);
        if (!utc && m.Groups.Count > 7 && m.Groups[7].Success && m.Groups[7].Value.Length > 0)
            ms += int.Parse((m.Groups[7].Value + "000")[..3], CultureInfo.InvariantCulture);
        return ms;
    }

    /// <summary>Walks the structure: every UTCTime / GeneralizedTime must be a well-formed DER time.</summary>
    static bool TimesWellFormed(byte[] b, Node n)
    {
        if (n.Constructed)
        {
            try { foreach (var k in Kids(b, n)) if (!TimesWellFormed(b, k)) return false; }
            catch (AttestError) { return false; }
            return true;
        }
        if (n.Tag == 0x17 || n.Tag == 0x18) return TimeMs(Encoding.Latin1.GetString(b, n.Start, n.End - n.Start), n.Tag == 0x17) != null;
        return true;
    }

    static byte[] StripLeading0(byte[] b)
    {
        int i = 0;
        while (i < b.Length - 1 && b[i] == 0) i++;
        return b[i..];
    }

    /// <summary>The subjectPublicKey BIT STRING content of a certificate (without the unused-bits octet).</summary>
    static byte[] SpkiKeyBits(AttCert c)
    {
        var spki = AttestCerts.ReadElem(c.RawSpki, 0, c.RawSpki.Length, 0x30);
        var kids = AttestCerts.Kids(c.RawSpki, spki);
        if (kids.Count != 2) throw new AttestError("malformed SubjectPublicKeyInfo");
        return c.RawSpki[(kids[1].Start + 1)..kids[1].End];
    }

    static bool SigOk(string alg, byte[] tbs, byte[] sig, CertKey k)
    {
        if (!SigAlgs.TryGetValue(alg, out var a)) return false;
        var digest = AttestCerts.HashOf(a.Hash, tbs);
        try
        {
            if (k.Ec != null) return a.Ec && k.Ec.VerifyHash(digest, sig, DSASignatureFormat.Rfc3279DerSequence);
            if (k.Rsa != null) return !a.Ec && k.Rsa.VerifyHash(digest, sig, new HashAlgorithmName(a.Hash), RSASignaturePadding.Pkcs1);
        }
        catch (Exception) { }
        return false;
    }

    sealed record Result(bool Ok, string Reason = "", string Status = "");

    static Result Fail(string reason) => new(false, reason);

    /// <summary>Verifies one DER OCSPResponse for <paramref name="cert"/> (issued by <paramref name="issuer"/>); malformation is a failure, never an exception.</summary>
    static Result VerifyResponse(byte[] der, AttCert cert, AttCert issuer, List<AttCert> chain, long nowMs)
    {
        try { return VerifyInner(der, cert, issuer, chain, nowMs); }
        catch (AttestError e) { return Fail("OCSP response rejected: " + e.Message); }
        catch (Exception e) { return Fail("OCSP response rejected: " + e.Message); }
    }

    static Result VerifyInner(byte[] der, AttCert cert, AttCert issuer, List<AttCert> chain, long nowMs)
    {
        Node top;
        try { top = ReadNode(der, 0, der.Length); } catch (AttestError) { return Fail("response is not valid DER"); }
        if (top.End != der.Length) return Fail("trailing bytes after OCSPResponse");
        if (top.Tag != 0x30) throw new AttestError("OCSPResponse is not a SEQUENCE");
        var tk = Kids(der, top);
        if (tk.Count == 0 || tk[0].Tag != 0x0a || tk[0].End - tk[0].Start != 1) throw new AttestError("malformed OCSPResponse");
        int status = der[tk[0].Start];
        if (status != 0) return Fail($"OCSP responseStatus is {status} (not successful)");
        if (tk.Count < 2 || tk[1].Tag != 0xa0) return Fail("successful response carries no responseBytes");
        var rbWrap = Kids(der, tk[1]);
        if (rbWrap.Count != 1 || rbWrap[0].Tag != 0x30) throw new AttestError("malformed responseBytes");
        var rb = Kids(der, rbWrap[0]);
        if (rb.Count != 2 || rb[1].Tag != 0x04) throw new AttestError("malformed responseBytes");
        if (OidOf(der, rb[0]) != OidOcspBasic) return Fail("responseType is not id-pkix-ocsp-basic");
        var basic = der[rb[1].Start..rb[1].End];
        Node bn;
        try { bn = ReadNode(basic, 0, basic.Length); } catch (AttestError) { return Fail("BasicOCSPResponse is not valid DER"); }
        if (bn.Tag != 0x30) throw new AttestError("BasicOCSPResponse is not a SEQUENCE");
        var bk = Kids(basic, bn);
        if (bk.Count < 3 || bk[0].Tag != 0x30 || bk[1].Tag != 0x30 || bk[2].Tag != 0x03) throw new AttestError("malformed BasicOCSPResponse");
        if (!TimesWellFormed(basic, bn)) return Fail("response carries a malformed (out-of-range) ASN.1 time");
        var tbsNode = bk[0];
        var tbsBytes = basic[tbsNode.Hdr..tbsNode.End];
        var algKids = Kids(basic, bk[1]);
        if (algKids.Count == 0) throw new AttestError("malformed signatureAlgorithm");
        var sigAlg = OidOf(basic, algKids[0]);
        if (!SigAlgs.ContainsKey(sigAlg)) return Fail("unsupported OCSP signature algorithm " + sigAlg);
        if (bk[2].End - bk[2].Start < 1) throw new AttestError("malformed signature");
        var sig = basic[(bk[2].Start + 1)..bk[2].End];

        // ResponseData: [0] version?, responderID, producedAt, responses, [1] extensions?
        var rd = Kids(basic, tbsNode);
        int ri = 0;
        if (ri < rd.Count && rd[ri].Tag == 0xa0) ri++;
        if (ri + 3 > rd.Count) throw new AttestError("malformed ResponseData");
        Node rid = rd[ri], produced = rd[ri + 1], responses = rd[ri + 2];
        if (produced.Tag != 0x18 || responses.Tag != 0x30 || (rid.Tag != 0xa1 && rid.Tag != 0xa2)) throw new AttestError("malformed ResponseData");
        long producedAt = TimeMs(Encoding.Latin1.GetString(basic, produced.Start, produced.End - produced.Start), false) ?? 0;

        var subjectSerial = StripLeading0(cert.Serial);
        var issuerKeyBits = SpkiKeyBits(issuer);
        var singles = Kids(basic, responses);
        var matches = new List<(Node Status, long ThisUpdate, long NextUpdate, bool HasNext)>();
        foreach (var s in singles)
        {
            var sk = Kids(basic, s);
            if (sk.Count < 3 || sk[0].Tag != 0x30 || sk[2].Tag != 0x18) throw new AttestError("malformed SingleResponse");
            var cid = Kids(basic, sk[0]);
            if (cid.Count != 4 || cid[0].Tag != 0x30 || cid[1].Tag != 0x04 || cid[2].Tag != 0x04 || cid[3].Tag != 0x02) throw new AttestError("malformed CertID");
            var hk = Kids(basic, cid[0]);
            if (hk.Count == 0) throw new AttestError("malformed CertID hash algorithm");
            if (!CertIdHashes.TryGetValue(OidOf(basic, hk[0]), out var h)) continue;
            var wantName = AttestCerts.HashOf(h, issuer.RawSubject);
            var wantKey = AttestCerts.HashOf(h, issuerKeyBits);
            if (!StripLeading0(basic[cid[3].Start..cid[3].End]).AsSpan().SequenceEqual(subjectSerial)
                || !basic.AsSpan(cid[1].Start, cid[1].End - cid[1].Start).SequenceEqual(wantName)
                || !basic.AsSpan(cid[2].Start, cid[2].End - cid[2].Start).SequenceEqual(wantKey)) continue;
            long tu = TimeMs(Encoding.Latin1.GetString(basic, sk[2].Start, sk[2].End - sk[2].Start), false) ?? 0;
            long next = 0; bool hasNext = false;
            if (sk.Count > 3 && sk[3].Tag == 0xa0)
            {
                try
                {
                    var nk = Kids(basic, sk[3]);
                    if (nk.Count == 1 && nk[0].Tag == 0x18)
                    {
                        next = TimeMs(Encoding.Latin1.GetString(basic, nk[0].Start, nk[0].End - nk[0].Start), false) ?? 0;
                        hasNext = true;
                    }
                }
                catch (AttestError) { }
            }
            matches.Add((sk[1], tu, next, hasNext));
        }
        if (matches.Count == 0) return Fail("no SingleResponse matches the certificate (serial / issuer hashes differ)");
        if (matches.Count > 1) return Fail("ambiguous: multiple SingleResponses match the certificate");
        var one = matches[0];

        // responder authentication
        var issuerKey = AttestCerts.KeyOf(issuer);
        var ridInner = Kids(basic, rid);
        if (ridInner.Count != 1) throw new AttestError("malformed responderID");
        var rIn = ridInner[0];
        bool MatchesResponder(AttCert c)
        {
            if (rid.Tag == 0xa1) return rIn.Tag == 0x30 && basic.AsSpan(rIn.Hdr, rIn.End - rIn.Hdr).SequenceEqual(c.RawSubject);
            byte[] bits;
            try { bits = SpkiKeyBits(c); } catch (AttestError) { return false; }
            return rIn.Tag == 0x04 && basic.AsSpan(rIn.Start, rIn.End - rIn.Start).SequenceEqual(AttestCerts.HashOf("SHA1", bits));
        }
        bool isIssuerId = MatchesResponder(issuer);
        if (!(isIssuerId && SigOk(sigAlg, tbsBytes, sig, issuerKey)))
        {
            var embedded = new List<AttCert>();
            if (bk.Count > 3 && bk[3].Tag == 0xa0)
            {
                try
                {
                    var wrap = Kids(basic, bk[3]);
                    if (wrap.Count == 1)
                        foreach (var c in Kids(basic, wrap[0]))
                            try { embedded.Add(AttestCerts.ParseDer(basic[c.Hdr..c.End])); } catch (AttestError) { }
                }
                catch (AttestError) { }
            }
            var why = "no embedded responder certificate verifies the response";
            AttCert? found = null;
            foreach (var cand in embedded)
            {
                if (!MatchesResponder(cand)) { why = "embedded certificates do not match the responderID"; continue; }
                if (!cand.HasOcspSigningEku()) { why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU"; continue; }
                var (vFrom, vTo) = AttestDer.DerValidity(cand.Raw);
                if (!vFrom.Ok || !vTo.Ok || !(vFrom.Ms <= nowMs && nowMs <= vTo.Ms)) { why = "delegated responder certificate is outside its validity window"; continue; }
                var signers = new List<AttCert> { issuer };
                for (int i = 0; i < chain.Count; i++)
                    if (chain[i].Raw.AsSpan().SequenceEqual(issuer.Raw)) { signers = chain.Skip(i).ToList(); break; }
                bool okSigner = signers.Any(sg => cand.RawIssuer.AsSpan().SequenceEqual(sg.RawSubject) && AttestCerts.SigOkBy(cand, sg));
                if (!okSigner) { why = "delegated responder certificate is not signed by the supplied NVIDIA chain"; continue; }
                CertKey? ck = null;
                try { ck = AttestCerts.KeyOf(cand); } catch (AttestError) { }
                if (ck == null || !SigOk(sigAlg, tbsBytes, sig, ck)) { why = "OCSP response signature does not verify under the delegated responder key"; continue; }
                found = cand;
                break;
            }
            if (found == null) return Fail(isIssuerId ? "OCSP response signature does not verify under the issuer key" : why);
        }

        // freshness
        if (one.ThisUpdate > nowMs) return Fail("response thisUpdate is in the future");
        if (producedAt > nowMs) return Fail("response producedAt is in the future");
        if (one.HasNext)
        {
            if (one.NextUpdate < one.ThisUpdate) return Fail("response nextUpdate is invalid");
            if (nowMs > one.NextUpdate) return Fail("response is stale (past nextUpdate)");
        }
        if (nowMs - one.ThisUpdate > DefaultMaxMs) return Fail("response is older than the maximum accepted age");

        // certStatus: CHOICE [0] good, [1] revoked, [2] unknown
        var st = one.Status;
        if ((st.Tag & 0xc0) != 0x80) return Fail("malformed certStatus");
        switch (st.Tag & 0x1f)
        {
            case 0: return new Result(true, Status: "good");
            case 2: return new Result(true, Status: "unknown");
            case 1:
                {
                    List<Node> items;
                    try { items = Kids(basic, st); } catch (AttestError) { return Fail("malformed revoked certStatus"); }
                    if (items.Count < 1 || !RevTimeRe.IsMatch(Encoding.Latin1.GetString(basic, items[0].Start, items[0].End - items[0].Start))) return Fail("malformed revoked certStatus");
                    return new Result(true, Status: "revoked");
                }
        }
        return Fail("unrecognised certStatus");
    }

    /// <summary>Checks the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails, and
    /// every certificate that advertises an OCSP responder must have a GOOD response.</summary>
    internal static string CheckChain(List<AttCert> chain, List<byte[]> responses, long nowMs)
    {
        if (chain.Count < 2) return "chain too short for OCSP";
        if (responses.Count == 0) return "no OCSP responses supplied";
        int last = chain.Count - 1;
        var required = new HashSet<int>();
        for (int i = 0; i < last; i++) if (chain[i].OcspServers().Count > 0) required.Add(i);
        var statuses = new Dictionary<int, string>();
        for (int i = 0; i < last; i++) statuses[i] = "absent";
        for (int ri = 0; ri < responses.Count; ri++)
        {
            bool matched = false;
            var lastReason = "matches no chain certificate";
            for (int i = 0; i < last; i++)
            {
                var r = VerifyResponse(responses[ri], chain[i], chain[i + 1], chain, nowMs);
                if (!r.Ok)
                {
                    if (!r.Reason.StartsWith("no SingleResponse matches", StringComparison.Ordinal)) return $"OCSP response #{ri} for '{NvidiaVerifier.SubjectLine(chain[i])}' rejected: {r.Reason}";
                    lastReason = r.Reason;
                    continue;
                }
                if (matched) return $"OCSP response #{ri} matches more than one chain certificate";
                matched = true;
                if (statuses[i] != "absent") return $"duplicate OCSP responses for chain certificate #{i}";
                statuses[i] = r.Status;
                if (r.Status == "revoked") return $"chain certificate '{NvidiaVerifier.SubjectLine(chain[i])}' is revoked (OCSP)";
            }
            if (!matched) return $"OCSP response #{ri} rejected: {lastReason}";
        }
        for (int i = 0; i < last; i++)
            if (required.Contains(i) && statuses[i] != "good") return $"no GOOD OCSP response for required certificate '{NvidiaVerifier.SubjectLine(chain[i])}' (status: {statuses[i]})";
        return "";
    }
}
