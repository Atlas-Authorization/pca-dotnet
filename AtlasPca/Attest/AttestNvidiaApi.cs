// The public surface of the NVIDIA GPU confidential-computing attestation modules: the SPDM GET_MEASUREMENTS transcript parse and its summary, the device-chain and report-signature checks, the PCA challenge,
// the Reference Integrity Manifest ids, verification and golden comparison, CRL and OCSP revocation (request building included), the collateral hook, and the guarded fetch helpers over an INJECTED transport
// (nothing here opens a network connection). Values are the JSON tree (a summary is a Dictionary, byte strings are byte[]); a malformed input of a parse or build function is an exception, a verdict is a
// value ({ok, reason}). The verifiers behind it (AttestNvidia.cs, AttestNvidiaCollateral.cs) are the same code the vendor verifier of the attestation layer runs.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One request of a fetch helper (the injected transport answers it).</summary>
public sealed record NvidiaFetchRequest(string Url, string Method, string? ContentType, byte[]? Body);

/// <summary>The transport's answer: the status (2xx is ok) and the body.</summary>
public sealed record NvidiaFetchResponse(int Status, byte[] Body)
{
    public bool Ok => Status is >= 200 and <= 299;
}

public static class NvidiaAttest
{
    public const string SpdmSuite = "nvidia-gpu-spdm-ecdsa-p384-sha384";
    public const string RimBaseUrl = "https://rim.attestation.nvidia.com/v1/rim/";
    public const string OcspUrl = "http://ocsp.ndis.nvidia.com/";
    /// <summary>The default maximum accepted age of an OCSP response (thisUpdate to now): 7 days.</summary>
    public const long OcspDefaultMaxAgeMs = 7L * 24 * 3600 * 1000;
    public static readonly IReadOnlyList<string> Gh100CrlUrls = ["https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"];
    public static readonly IReadOnlyList<string> Gb100CrlUrls = ["https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"];

    /// <summary>The opaque-data TLV field ids the SPDM report surfaces by name.</summary>
    public static readonly IReadOnlyDictionary<string, int> Opaque = new Dictionary<string, int>
    {
        ["CERT_ISSUER_NAME"] = 1, ["CERT_AUTHORITY_KEY_IDENTIFIER"] = 2, ["DRIVER_VERSION"] = 3, ["GPU_INFO"] = 4, ["SKU"] = 5, ["VBIOS_VERSION"] = 6, ["MANUFACTURER_ID"] = 7, ["TAMPER_DETECTION"] = 8,
        ["MSRSCNT"] = 12, ["BOARD_ID"] = 14, ["FWID"] = 20, ["OPAQUE_DATA_VERSION"] = 34, ["CHIP_INFO"] = 35, ["FEATURE_FLAG"] = 36,
    };

    const int MaxChain = 5;
    static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    // ---- certificates ----

    /// <summary>OpenSSL's ASN1_TIME_print: <c>Oct 17 00:00:00 2020 GMT</c> (the day space-padded to two columns).</summary>
    static string TimeText(DerInstant t)
    {
        if (!t.Ok) return "Bad time value";
        var d = DateTimeOffset.FromUnixTimeMilliseconds(t.Ms).UtcDateTime;
        return $"{Months[d.Month - 1]} {d.Day,2} {d:HH:mm:ss} {d.Year} GMT";
    }

    static JD Summary(AttCert c)
    {
        var (nb, na) = AttestDer.DerValidity(c.Raw);
        var serial = c.Serial.SkipWhile((b, i) => b == 0 && i < c.Serial.Length - 1).ToArray();
        return new JD
        {
            ["subject"] = AttestCerts.NameText(c.RawSubject), ["issuer"] = AttestCerts.NameText(c.RawIssuer), ["serial"] = Convert.ToHexString(serial), ["notBefore"] = TimeText(nb), ["notAfter"] = TimeText(na),
            ["spkiSha256"] = AttestUtil.Hex(AttestUtil.Sha256(c.RawSpki)), ["rawSha256"] = AttestUtil.Hex(AttestUtil.Sha256(c.Raw)), ["ca"] = NvidiaVerifier.CertIsCa(c),
        };
    }

    static List<AttCert> ChainOf(string pem)
    {
        var blocks = AttestCerts.PemBlocks(pem);
        if (blocks.Count == 0) throw new ArgumentException("parsePemChain: no certificates found");
        if (blocks.Count > MaxChain) throw new ArgumentException($"parsePemChain: chain longer than {MaxChain}");
        return blocks.Select(AttestCerts.FromPem).ToList();
    }

    /// <summary>SHA-256 of a certificate's SubjectPublicKeyInfo DER, lowercase hex: the pin format of the roots.</summary>
    public static string SpkiSha256Hex(string certPem) => AttestUtil.Hex(AttestUtil.Sha256(AttestCerts.FromPem(certPem).RawSpki));

    /// <summary>Split a PEM bundle into certificates (leaf first) and summarize each: {subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}. Throws on none or more than 5.</summary>
    public static JL ParsePemChain(string pem) => ChainOf(pem).Select(c => (object?)Summary(c)).ToList();

    /// <summary>Verify the device chain (leaf first): every link signed, every issuer a CA, every certificate valid at <paramref name="nowMs"/>, ECDSA P-384 throughout, the root self-signed and pinned by SPKI SHA-256.
    /// {ok: true, leaf, chain} or {ok: false, reason}.</summary>
    public static JD VerifyDeviceChain(string pem, IReadOnlyList<string> rootSpkiSha256, double nowMs)
    {
        var (chain, why) = NvidiaVerifier.VerifyDeviceChain(pem, rootSpkiSha256, (long)nowMs);
        if (chain == null) return new JD { ["ok"] = false, ["reason"] = why };
        return new JD { ["ok"] = true, ["leaf"] = Summary(chain[0]), ["chain"] = chain.Select(c => (object?)Summary(c)).ToList() };
    }

    // ---- the SPDM report ----

    /// <summary>Parse an SPDM request||response transcript into its summary: {request, response {version, code, numBlocks, measurements, responderNonce, opaque (keyed by type), signature}, signedBytesLength, signedBytesSha256}.
    /// Throws on any structural problem.</summary>
    public static JD ParseEvidence(byte[]? bytes)
    {
        if (bytes == null) throw new ArgumentException("parseNvidiaSpdmEvidence: expected Uint8Array");
        var r = NvidiaVerifier.ParseEvidence(bytes);
        var opaque = new JD();
        foreach (var kv in r.Opaque.OrderBy(k => k.Key)) opaque[kv.Key.ToString(CultureInfo.InvariantCulture)] = kv.Value;
        return new JD
        {
            ["request"] = new JD { ["version"] = r.RequestVersion, ["code"] = r.RequestCode, ["param1"] = r.RequestParam1, ["param2"] = r.RequestParam2, ["nonce"] = r.RequestNonce, ["slot"] = r.RequestSlot },
            ["response"] = new JD
            {
                ["version"] = r.ResponseVersion, ["code"] = r.ResponseCode, ["numBlocks"] = r.Measurements.Count,
                ["measurements"] = r.Measurements.Select((m, i) => (object?)new JD { ["index"] = m.Index, ["valueType"] = r.ValueTypes[i], ["digest"] = m.Digest }).ToList(),
                ["responderNonce"] = r.ResponderNonce, ["opaque"] = opaque, ["signature"] = r.Signature,
            },
            ["signedBytesLength"] = r.SignedBytes.Length, ["signedBytesSha256"] = AttestUtil.Hex(AttestUtil.Sha256(r.SignedBytes)),
        };
    }

    /// <summary>NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex.</summary>
    public static string FormatVbiosVersion(byte[] raw) => NvidiaVerifier.FormatVbiosVersion(raw);

    /// <summary>The report signature (ECDSA P-384 / SHA-384, IEEE P1363) of the parsed transcript under the leaf key of the chain. Throws when the transcript or the chain cannot be parsed.</summary>
    public static bool VerifySpdmSignature(byte[] evidence, string chainPem) => NvidiaVerifier.LeafSigOk(ChainOf(chainPem)[0], NvidiaVerifier.ParseEvidence(evidence));

    /// <summary>The 32-byte SPDM challenge that carries the PCA binding: sha256 of the attestation binding of {holderPub, grantRef, epoch, nonce}. Throws when the binding cannot be built.</summary>
    public static byte[] SpdmChallenge(object? expected)
    {
        if (expected is not JD d) throw new ArgumentException("binding: an object is required");
        static string Str(object? v, string what) => v as string ?? throw new ArgumentException($"binding: {what} required");
        var epoch = IntentJs.NumOf(d.GetValueOrDefault("epoch")) ?? throw new ArgumentException("binding: epoch must be a non-negative safe integer");
        return AttestUtil.Sha256(AttestUtil.BindingBytes(new AttestationBinding(Str(d.GetValueOrDefault("holderPub"), "holderPub"), Str(d.GetValueOrDefault("grantRef"), "grantRef"), epoch, Str(d.GetValueOrDefault("nonce"), "nonce"))));
    }

    // ---- reference integrity manifests ----

    static JD RimSummary(VerifiedRim r) => new()
    {
        ["tagId"] = r.TagId, ["product"] = r.Product, ["version"] = r.Version,
        ["golden"] = r.Golden.Values.OrderBy(g => g.Index).Select(g => (object?)new JD { ["index"] = g.Index, ["active"] = g.Active, ["alternatives"] = g.Alternatives, ["size"] = g.Size, ["hashes"] = g.Hashes.Cast<object?>().ToList() }).ToList(),
        ["signerSubject"] = r.SignerSubject,
    };

    /// <summary>Verify a RIM document (SWID/CoRIM XML, enveloped XMLDSig over C14N 1.1, ECDSA P-384 / SHA-384): the signer chain is checked like the device chain against the pinned RIM roots at <paramref name="nowMs"/>.
    /// {ok: true, rim: {tagId, product, version, golden, signerSubject}} or {ok: false, reason}.</summary>
    public static JD VerifyRim(object? xml, IReadOnlyList<string>? rimRootSpkiSha256, double nowMs)
    {
        if (xml is not string x || x.Length == 0 || x.Length > 4_000_000) return new JD { ["ok"] = false, ["reason"] = "RIM: empty or oversized document" };
        var (rim, why) = NvidiaHook.VerifyRim(x, rimRootSpkiSha256 ?? [], (long)nowMs);
        return rim == null ? new JD { ["ok"] = false, ["reason"] = why } : new JD { ["ok"] = true, ["rim"] = RimSummary(rim) };
    }

    /// <summary>The RIM ids a report requires (read from its own signed opaque data): {chip, driver, vbios, driverVersion, vbiosVersion}, or null when the report lacks the fields or names a malformed chip.</summary>
    public static JD? RimIdsForReport(byte[] evidence)
    {
        var ids = NvidiaHook.RimIdsForReport(NvidiaVerifier.ParseEvidence(evidence));
        return ids == null ? null : new JD { ["chip"] = ids.Chip, ["driver"] = ids.Driver, ["vbios"] = ids.Vbios, ["driverVersion"] = ids.DriverVersion, ["vbiosVersion"] = ids.VbiosVersion };
    }

    static List<RimGolden> GoldenOf(object? rim) =>
        (JsonGet(rim, "golden") as JL ?? throw new ArgumentException("a RIM summary was expected")).Select(g =>
        {
            var d = (JD)g!;
            return new RimGolden((int)IntentJs.Lng(d["index"]), d["active"] is true, (int)IntentJs.Lng(d["alternatives"]), (int)IntentJs.Lng(d["size"]), ((JL)d["hashes"]!).Select(h => (string)h!).ToList());
        }).ToList();

    static object? JsonGet(object? o, string k) => o is JD d && d.TryGetValue(k, out var v) ? v : null;

    /// <summary>Compare a report with the driver and VBIOS RIM summaries using NVIDIA's merge, alternatives and NVDEC0 rules: {ok: true, checked} or {ok: false, reason, mismatches?: [{index, source}]}.</summary>
    public static JD CompareReportToRims(byte[] evidence, object? driverRim, object? vbiosRim)
    {
        var rep = NvidiaVerifier.ParseEvidence(evidence);
        var merged = new Dictionary<int, (RimGolden G, string Source)>();
        foreach (var g in GoldenOf(driverRim)) if (g.Active) merged[g.Index] = (g, "driver");
        foreach (var g in GoldenOf(vbiosRim))
        {
            if (!g.Active) continue;
            if (merged.ContainsKey(g.Index)) return new JD { ["ok"] = false, ["reason"] = $"driver and VBIOS RIMs both have an active measurement at index {g.Index}" };
            merged[g.Index] = (g, "vbios");
        }
        if (merged.Count == 0) return new JD { ["ok"] = false, ["reason"] = "RIMs carry no active golden measurements" };
        var runtime = new Dictionary<int, byte[]>();
        foreach (var (index, digest) in rep.Measurements) runtime[index - 1] = digest;
        if (merged.Count > runtime.Count) return new JD { ["ok"] = false, ["reason"] = "RIMs list more active measurements than the report carries" };
        bool nvdecDisabled = rep.Opaque.TryGetValue(11, out var nvdec) && nvdec.Length > 0 && nvdec[0] == 0x55;
        var mismatches = new JL();
        int checkedCount = 0;
        foreach (var index in merged.Keys.OrderBy(i => i))
        {
            var (g, source) = merged[index];
            if (index + 1 == 35 && nvdecDisabled) continue;
            runtime.TryGetValue(index, out var digest);
            checkedCount++;
            if (digest == null || digest.Length != g.Size || !g.Hashes.Contains(AttestUtil.Hex(digest))) mismatches.Add(new JD { ["index"] = index, ["source"] = source });
        }
        if (mismatches.Count > 0) return new JD { ["ok"] = false, ["reason"] = $"runtime measurements differ from the golden RIM values at {mismatches.Count} index(es)", ["mismatches"] = mismatches };
        return new JD { ["ok"] = true, ["checked"] = checkedCount };
    }

    /// <summary>Check the device chain against DER CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate may be listed by its issuer's CRL, each issuer in
    /// <paramref name="requireIssuers"/> must have a verified CRL and <paramref name="requireFor"/> ("cdp" the default, "all", "none" or a list of chain indices) says which certificates need a CRL from their issuer.
    /// {ok: true, verifiedCrls} or {ok: false, reason}.</summary>
    public static JD CheckChainRevocation(string chainPem, IReadOnlyList<byte[]> crls, double nowMs, IReadOnlyList<string>? requireIssuers = null, object? requireFor = null)
    {
        var rf = requireFor is null ? "cdp" : requireFor is "none" ? null : requireFor;
        var why = NvidiaHook.CheckChainRevocation(ChainOf(chainPem), crls.ToList(), (long)nowMs, requireIssuers?.ToList() ?? [], rf);
        return why.Length == 0 ? new JD { ["ok"] = true, ["verifiedCrls"] = crls.Count } : new JD { ["ok"] = false, ["reason"] = why };
    }

    /// <summary>The collateral hook: RIM signature, golden comparison, driver / VBIOS version binding, firmware policy and revocation, for a GPU report and its device chain (not re-verified here: the hook runs
    /// after the verifier checked it). <paramref name="options"/> is the hook configuration (rimRootSpkiSha256, revocation, requireCrls, requireCrlIssuers, requireCrlFor, firmware); an invalid one throws. Returns null
    /// when the collateral holds, else the failure reason.</summary>
    public static string? CollateralHook(JD options, JD? bundle, byte[] evidence, string chainPem, double nowMs)
    {
        var hook = NvidiaHook.Create(options);
        NvidiaBundle? b = null;
        if (bundle != null)
        {
            b = new NvidiaBundle { DriverRim = bundle.GetValueOrDefault("driverRimXml") as string ?? "", VbiosRim = bundle.GetValueOrDefault("vbiosRimXml") as string ?? "" };
            foreach (var c in (bundle.GetValueOrDefault("crls") as JL ?? new JL()).OfType<byte[]>()) b.Crls.Add(c);
            foreach (var c in (bundle.GetValueOrDefault("ocsp") as JL ?? new JL()).OfType<byte[]>()) b.Ocsp.Add(c);
        }
        var why = hook.WithBundle(b).Run(NvidiaVerifier.ParseEvidence(evidence), ChainOf(chainPem), (long)nowMs);
        return why.Length == 0 ? null : why;
    }

    // ---- OCSP ----

    static byte[] Tlv(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(p => p).ToArray();
        var len = body.Length < 0x80 ? new[] { (byte)body.Length } : body.Length < 0x100 ? new byte[] { 0x81, (byte)body.Length } : new byte[] { 0x82, (byte)(body.Length >> 8), (byte)body.Length };
        return [tag, .. len, .. body];
    }

    static byte[] OidDer(string dotted)
    {
        if (dotted.Length == 0) return Tlv(0x06); // the reference writes an unknown hash's missing OID as an empty OBJECT IDENTIFIER
        var p = dotted.Split('.').Select(x => ulong.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        var o = new List<byte> { (byte)(p[0] * 40 + p[1]) };
        foreach (var arc in p.Skip(2))
        {
            var chunks = new Stack<byte>();
            var v = arc;
            chunks.Push((byte)(v & 0x7f));
            while ((v >>= 7) > 0) chunks.Push((byte)(0x80 | (v & 0x7f)));
            o.AddRange(chunks);
        }
        return Tlv(0x06, o.ToArray());
    }

    /// <summary>The DER OCSPRequest for <paramref name="certPem"/> issued by <paramref name="issuerPem"/>: a CertID over the issuer name and key hashes (SHA-384 unless <paramref name="hash"/> says sha1, sha256 or sha512;
    /// the hash algorithm carries an explicit NULL), the serial number, an optional nonce extension (1..32 bytes, in a request extension, never critical), no requestor name and no signature.</summary>
    public static byte[] BuildOcspRequest(string certPem, string issuerPem, byte[]? nonce = null, string? hash = null)
    {
        var cert = AttestCerts.FromPem(certPem);
        var issuer = AttestCerts.FromPem(issuerPem);
        hash ??= "sha384";
        (string Oid, byte[] NameHash, byte[] KeyHash) h = hash switch
        {
            "sha1" => ("1.3.14.3.2.26", SHA1.HashData(issuer.RawSubject), SHA1.HashData(NvidiaOcsp.SpkiKeyBits(issuer))),
            "sha256" => ("2.16.840.1.101.3.4.2.1", SHA256.HashData(issuer.RawSubject), SHA256.HashData(NvidiaOcsp.SpkiKeyBits(issuer))),
            "sha384" => ("2.16.840.1.101.3.4.2.2", SHA384.HashData(issuer.RawSubject), SHA384.HashData(NvidiaOcsp.SpkiKeyBits(issuer))),
            "sha512" => ("2.16.840.1.101.3.4.2.3", SHA512.HashData(issuer.RawSubject), SHA512.HashData(NvidiaOcsp.SpkiKeyBits(issuer))),
            _ => throw new ArgumentException($"unsupported CertID hash {hash}"), // an unlisted hash has no OID: refused, never an empty OID
        };
        var certId = Tlv(0x30, Tlv(0x30, OidDer(h.Oid), Tlv(0x05)), Tlv(0x04, h.NameHash), Tlv(0x04, h.KeyHash), Tlv(0x02, cert.Serial));
        var tbs = new List<byte[]> { Tlv(0x30, Tlv(0x30, certId)) };
        if (nonce != null)
        {
            if (nonce.Length < 1 || nonce.Length > 32) throw new ArgumentException("nonce must be 1..32 bytes");
            tbs.Add(Tlv(0xa2, Tlv(0x30, Tlv(0x30, OidDer("1.3.6.1.5.5.7.48.1.2"), Tlv(0x04, Tlv(0x04, nonce))))));
        }
        return Tlv(0x30, Tlv(0x30, tbs.ToArray()));
    }

    /// <summary>The OCSP responder URLs a certificate advertises in its Authority Information Access extension.</summary>
    public static List<string> CertOcspUrls(string certPem) => AttestCerts.FromPem(certPem).OcspServers();

    /// <summary>Does every UTCTime and GeneralizedTime inside the DER value read as a well-formed DER time with in-range fields (no calendar roll-over)? OCTET STRING and BIT STRING contents are opaque and never inspected.
    /// Throws when the value is not valid DER.</summary>
    public static bool AllAsn1TimesWellFormed(byte[] der) => NvidiaOcsp.TimesWellFormed(der, NvidiaOcsp.ReadNode(der, 0, der.Length));

    /// <summary>The options of <see cref="VerifyOcspResponse"/>: the chain, the index of the certificate the response speaks for and of its issuer (default: the next one), the clock, the maximum age (default 7
    /// days), the tolerated clock skew and a nonce the response must echo exactly.</summary>
    public sealed class OcspVerifyOptions
    {
        public string ChainPem = "";
        public int CertIndex;
        public int? IssuerIndex;
        public double NowMs;
        public double? MaxAgeMs, ClockSkewMs;
        public byte[]? ExpectedNonce;
    }

    /// <summary>Verify one DER OCSPResponse for a certificate of the chain: status, CertID, the BasicOCSPResponse signature under the issuer or a delegated responder the chain signed (OCSPSigning EKU, inside its validity),
    /// the nonce, freshness (thisUpdate, nextUpdate, producedAt, maximum age) and the certificate status. Never throws. {ok: true, status, thisUpdate, nextUpdate?, producedAt, revokedAt?, revocationReason?, responder}
    /// or {ok: false, reason}.</summary>
    public static JD VerifyOcspResponse(byte[] responseDer, OcspVerifyOptions o)
    {
        try
        {
            var chain = ChainOf(o.ChainPem);
            var cert = chain[o.CertIndex];
            var issuer = chain[o.IssuerIndex ?? o.CertIndex + 1];
            var opts = new NvidiaOcsp.OcspOptions(o.MaxAgeMs is double m ? (long)m : NvidiaOcsp.DefaultMaxMs, o.ClockSkewMs is double k ? (long)k : 0, o.ExpectedNonce);
            var r = NvidiaOcsp.VerifyResponse(responseDer, cert, issuer, chain, (long)o.NowMs, opts);
            if (!r.Ok) return new JD { ["ok"] = false, ["reason"] = r.Reason };
            var d = new JD { ["ok"] = true, ["status"] = r.Status, ["thisUpdate"] = r.ThisUpdate };
            if (r.NextUpdate != null) d["nextUpdate"] = r.NextUpdate;
            d["producedAt"] = r.ProducedAt;
            if (r.RevokedAt != null) d["revokedAt"] = r.RevokedAt;
            if (r.RevocationReason != null) d["revocationReason"] = r.RevocationReason;
            d["responder"] = r.Responder;
            return d;
        }
        catch (Exception e) { return new JD { ["ok"] = false, ["reason"] = "OCSP response rejected: " + e.Message }; }
    }

    /// <summary>The policy of <see cref="CheckChainOcsp"/>: <c>RequireGood</c> is "aia" (default: every non-root certificate that advertises a responder), "all" or a list of chain indices.</summary>
    public sealed class ChainOcspOptions
    {
        public object? RequireGood;
        public double? MaxAgeMs, ClockSkewMs;
        public IReadOnlyList<byte[]?>? ExpectedNonces;
    }

    /// <summary>Check the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails, the required certificates must have a GOOD response. {ok: true, verifiedCrls: 0,
    /// verifiedOcsp, statuses} or {ok: false, reason, statuses?}; the statuses are keyed by chain index.</summary>
    public static JD CheckChainOcsp(string chainPem, IReadOnlyList<byte[]> responses, double nowMs, ChainOcspOptions? o = null)
    {
        o ??= new ChainOcspOptions();
        var r = NvidiaOcsp.CheckChainDetailed(ChainOf(chainPem), responses.ToList(), (long)nowMs,
            new NvidiaOcsp.ChainOcspOptions(o.RequireGood, o.MaxAgeMs is double m ? (long)m : NvidiaOcsp.DefaultMaxMs, o.ClockSkewMs is double k ? (long)k : 0, o.ExpectedNonces));
        JD? statuses = r.Statuses == null ? null : r.Statuses.Select((s, i) => (i, s)).ToDictionary(x => x.i.ToString(CultureInfo.InvariantCulture), x => (object?)x.s);
        if (!r.Ok)
        {
            var f = new JD { ["ok"] = false, ["reason"] = r.Reason };
            if (statuses != null) f["statuses"] = statuses;
            return f;
        }
        return new JD { ["ok"] = true, ["verifiedCrls"] = 0, ["verifiedOcsp"] = r.Verified, ["statuses"] = statuses };
    }

    // ---- guarded fetch helpers (explicit use only; the transport is injected) ----

    static readonly Regex RimId = new(@"^[A-Za-z0-9_.-]+\z", RegexOptions.CultureInvariant);

    /// <summary>Fetch a RIM document from the RIM service (a GET of <c>baseUrl + id</c>) and return its XML text. Throws on an invalid id, a non-2xx answer or an answer without a <c>rim</c> string.</summary>
    public static string FetchRim(string id, Func<NvidiaFetchRequest, NvidiaFetchResponse> fetch, string? baseUrl = null)
    {
        if (!RimId.IsMatch(id)) throw new ArgumentException("fetchNvidiaRim: invalid RIM id");
        var res = fetch(new NvidiaFetchRequest((baseUrl ?? RimBaseUrl) + id, "GET", null, null));
        if (!res.Ok) throw new InvalidOperationException($"RIM fetch failed: HTTP {res.Status} for {id}");
        if (Pca.ParseJson(Encoding.UTF8.GetString(res.Body)) is not JD body || body.GetValueOrDefault("rim") is not string rim) throw new InvalidOperationException("RIM fetch: response has no rim field");
        return Encoding.UTF8.GetString(AttestUtil.NodeB64(rim));
    }

    /// <summary>Fetch a DER CRL (a GET). Throws on a non-2xx answer.</summary>
    public static byte[] FetchCrl(string url, Func<NvidiaFetchRequest, NvidiaFetchResponse> fetch)
    {
        var res = fetch(new NvidiaFetchRequest(url, "GET", null, null));
        return res.Ok ? res.Body : throw new InvalidOperationException($"CRL fetch failed: HTTP {res.Status} for {url}");
    }

    /// <summary>POST an OCSPRequest for the certificate to the responder (NVIDIA's unless <paramref name="url"/> says otherwise) and return the request and the response DER. Throws on a non-2xx answer.</summary>
    public static (byte[] Request, byte[] Response) FetchOcsp(string certPem, string issuerPem, Func<NvidiaFetchRequest, NvidiaFetchResponse> fetch, string? url = null, byte[]? nonce = null)
    {
        var request = BuildOcspRequest(certPem, issuerPem, nonce);
        var res = fetch(new NvidiaFetchRequest(url ?? OcspUrl, "POST", "application/ocsp-request", request));
        return res.Ok ? (request, res.Body) : throw new InvalidOperationException($"OCSP fetch failed: HTTP {res.Status}");
    }
}
