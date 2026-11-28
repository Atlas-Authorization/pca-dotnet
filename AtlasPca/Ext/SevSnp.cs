// The public SEV-SNP helpers of the reference (hardware-sevsnp.ts): the report parser (every field), the ECDSA P-384 / SHA-384 report signature, the P-384 key and
// compact-signature helpers, the VCEK certificate helpers and the CHIP_ID / TCB binding, the policy gate, the default identity derivation, the certificate chain and
// genuine-report verification, and the AMD KDS VCEK fetch over an INJECTED transport (this SDK performs no network I/O of its own). They run on the strict readers of
// the AMD verifier (AttestAmd / AttestDer); nothing here is a primitive of its own: the curve arithmetic is BouncyCastle, the signature check is System.Security.Cryptography.
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Nist;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A refusal that carries the reference's error code (<see cref="Code"/>) where the reference's platform parser names one.</summary>
public sealed class SevSnpException(string message, string? code = null) : Exception(message)
{
    public string? Code { get; } = code;
}

/// <summary>The answer of an injected KDS transport.</summary>
public sealed record KdsResponse(bool Ok, int Status, byte[] Body);

/// <summary>Options of <see cref="SevSnp.FetchVcekFromKds"/>: <c>Product</c> (default Milan), <c>BaseUrl</c> (default the AMD KDS), and <c>Fetch</c>, the injected transport (required).</summary>
public sealed class KdsOptions
{
    public string? Product, BaseUrl;
    public Func<string, KdsResponse>? Fetch;
}

public static class SevSnp
{
    public const int SigAlgoEcdsaP384Sha384 = 1;
    public static readonly BigInteger PolicyDebugBit = BigInteger.One << 19;
    public static string AmdMilanArkSpkiSha384 => AmdVerifier.ArkSpkiSha384["milan"];

    static readonly BigInteger P384Order = BigInteger.Parse("0ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384"] = (long)SigAlgoEcdsaP384Sha384, ["SEV_SNP_POLICY_DEBUG_BIT"] = PolicyDebugBit, ["AMD_MILAN_ARK_SPKI_SHA384"] = AmdMilanArkSpkiSha384 };

    /// <summary>Lowercase hex.</summary>
    public static string ToHex(byte[] b) => AttestUtil.Hex(b);

    static readonly Regex PemCert = new(@"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOptions.Singleline | RegexOptions.CultureInvariant);

    /// <summary>Every <c>-----BEGIN CERTIFICATE-----</c> block of the text, unchanged.</summary>
    public static List<string> SplitPemCertificates(string pem) => PemCert.Matches(pem).Select(m => m.Value).ToList();

    // ---- the report ----

    static D Version(byte[] b, int major, int minor, int build) => new() { ["major"] = (int)b[major], ["minor"] = (int)b[minor], ["build"] = (int)b[build] };

    /// <summary>Parse the 1184-byte ATTESTATION_REPORT layout (all integers little-endian): u32 as uint, u64 as ulong, bytes as byte[], the versions as {major, minor, build}; <c>signed</c> is
    /// bytes [0, 0x2a0) and <c>raw</c> the whole input. Throws when the buffer cannot hold the signed region and the r / s fields.</summary>
    public static D ParseSevSnpReport(byte[] b)
    {
        int minLen = AttestAmd.OffSigS + 72;
        if (b.Length < minLen) throw new ArgumentException($"parseSevSnpReport: report too short ({b.Length} < {minLen})");
        uint U32(int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
        ulong U64(int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
        byte[] Sl(int o, int n) => b[o..(o + n)];
        var raw = (byte[])b.Clone();
        return new D
        {
            ["version"] = U32(0x000), ["guest_svn"] = U32(0x004), ["policy"] = U64(0x008), ["vmpl"] = U32(0x030), ["signature_algo"] = U32(0x034), ["current_tcb"] = U64(0x038),
            ["report_data"] = Sl(0x050, 64), ["measurement"] = Sl(0x090, 48), ["host_data"] = Sl(0x0c0, 32), ["reported_tcb"] = U64(0x180), ["chip_id"] = Sl(0x1a0, 64),
            ["committed_tcb"] = U64(0x1e0), ["launch_tcb"] = U64(0x1f0), ["sig_r"] = Sl(0x2a0, 72), ["sig_s"] = Sl(0x2e8, 72), ["signed"] = Sl(0, 0x2a0),
            ["family_id"] = Sl(0x010, 16), ["image_id"] = Sl(0x020, 16), ["platform_info"] = U64(0x040), ["id_key_digest"] = Sl(0x0e0, 48), ["author_key_digest"] = Sl(0x110, 48),
            ["report_id"] = Sl(0x140, 32), ["report_id_ma"] = Sl(0x160, 32), ["cpuid_fam_id"] = (int)b[0x188], ["cpuid_mod_id"] = (int)b[0x189], ["cpuid_step"] = (int)b[0x18a],
            ["current_version"] = Version(b, 0x1ea, 0x1e9, 0x1e8), ["committed_version"] = Version(b, 0x1ee, 0x1ed, 0x1ec),
            ["launch_mit_vector"] = U64(0x1f8), ["current_mit_vector"] = U64(0x200),
            ["signature"] = new D { ["r"] = Sl(0x2a0, 72), ["s"] = Sl(0x2e8, 72) }, ["raw"] = raw,
        };
    }

    static SnpReport Typed(D report) => AttestAmd.ParseReport((byte[])report["raw"]!);

    // ---- P-384 key and signature helpers ----

    /// <summary>The uncompressed SEC1 point (97 bytes) of a P-384 key given as an uncompressed (97 bytes, 0x04) or compressed (49 bytes, 0x02 / 0x03) point. Throws on a malformed or off-curve point.</summary>
    public static byte[] EcdsaP384PublicKey(byte[] sec1)
    {
        bool ok = (sec1.Length == 49 && sec1[0] is 0x02 or 0x03) || (sec1.Length == 97 && sec1[0] == 0x04);
        if (!ok) throw new ArgumentException($"invalid Point, expected length of 49, or uncompressed 97, got {sec1.Length}");
        var curve = NistNamedCurves.GetByName("P-384").Curve;
        var p = curve.DecodePoint(sec1); // throws on an x that is no field element or a point off the curve
        if (p.IsInfinity) throw new ArgumentException("bad point: is zero");
        return p.Normalize().GetEncoded(false);
    }

    /// <summary>The 96-byte big-endian <c>r || s</c> of AMD's 72-byte little-endian signature fields; zero or at least the group order throws.</summary>
    public static byte[] SevSnpSignatureToCompact(byte[] r72, byte[] s72)
    {
        var r = new BigInteger(r72, isUnsigned: true, isBigEndian: false);
        var s = new BigInteger(s72, isUnsigned: true, isBigEndian: false);
        if (r.Sign <= 0 || r >= P384Order) throw new ArgumentException("sev-snp signature: r out of range");
        if (s.Sign <= 0 || s >= P384Order) throw new ArgumentException("sev-snp signature: s out of range");
        return [.. Fixed(r), .. Fixed(s)];
    }

    static byte[] Fixed(BigInteger v)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var o = new byte[48];
        b.CopyTo(o, 48 - b.Length);
        return o;
    }

    /// <summary>ECDSA P-384 over SHA-384 of the signed region [0, 0x2a0) under the VCEK point <paramref name="vcekSec1"/> (a malformed key, null, a zero or out-of-range r or s, a bad signature: false). A high-S
    /// signature is accepted as AMD does not normalise. Never throws.</summary>
    public static bool VerifySevSnpReportSignature(D report, byte[]? vcekSec1)
    {
        try
        {
            if (vcekSec1 == null) return false;
            var rep = Typed(report);
            var r = new BigInteger(rep.SigR, isUnsigned: true, isBigEndian: false);
            var s = new BigInteger(rep.SigS, isUnsigned: true, isBigEndian: false);
            if (r.Sign <= 0 || r >= P384Order || s.Sign <= 0 || s >= P384Order) return false;
            var pt = EcdsaP384PublicKey(vcekSec1);
            using var ec = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP384, Q = new ECPoint { X = pt[1..49], Y = pt[49..97] } });
            byte[] sigBytes = [.. Fixed(r), .. Fixed(s)];
            return ec.VerifyHash(SHA384.HashData(rep.Signed), sigBytes, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception) { return false; }
    }

    /// <summary>The reason a VCEK body does not bind to the report (CHIP_ID, then the four SPLs against the reported TCB bytes; a critical AMD extension is refused), or null when it binds.</summary>
    public static string? CheckVcekReportBinding(byte[] vcekTbs, D report) => AttestAmd.CheckVcekReportBinding(vcekTbs, Typed(report)) is { Length: > 0 } r ? r : null;

    // ---- certificates ----

    /// <summary>The tbsCertificate TLV (header included) of a strict DER certificate. Throws on a non-SEQUENCE, trailing bytes, or a first inner element that is not a SEQUENCE.</summary>
    public static byte[] ExtractTbsCertificate(byte[] certDer)
    {
        try { return AttestDer.TbsOfCertificate(certDer); }
        catch (AttestError e) { throw new ArgumentException(e.Message); }
    }

    /// <summary>The uncompressed point and the TBS bytes of a VCEK certificate. Throws unless the certificate parses and its key is EC secp384r1.</summary>
    public static (byte[] Point, byte[] Tbs) ExtractVcekPublicKey(byte[] vcekDer)
    {
        AttCert cert;
        try { cert = AttestCerts.ParseDer(vcekDer); }
        catch (AttestError) { throw new SevSnpException("error:0480006C:PEM routines::no start line", "ERR_OSSL_PEM_NO_START_LINE"); }
        try
        {
            var key = AttestCerts.KeyOf(cert);
            if (key.Type != "ec" || key.Curve != "secp384r1")
                throw new ArgumentException($"VCEK is not EC secp384r1 (got {key.Type}/{(key.Curve.Length == 0 ? "undefined" : key.Curve)})");
            var point = key.EcPointOn("P-384");
            return (EcdsaP384PublicKey(point), ExtractTbsCertificate(vcekDer));
        }
        catch (AttestError e) { throw new ArgumentException(e.Message); }
    }

    /// <summary>The outcome of <see cref="VerifyAmdCertChain"/>: on success the VCEK point and its TBS bytes.</summary>
    public sealed record AmdChainResult(bool Ok, string? Reason, byte[]? VcekPoint, byte[]? VcekTbs);

    /// <summary>VCEK -> ASK -> ARK with the ARK pinned by the SHA-384 of its SPKI (<paramref name="trustAnchor"/> null: the Milan ARK). Offline; fails closed with the reference's reason.</summary>
    public static AmdChainResult VerifyAmdCertChain(byte[] vcekDer, string askArkPem, string? trustAnchor, long nowMs, object? clockSkewMs = null)
    {
        var (reason, key, tbs) = AttestAmd.VerifyChain(vcekDer, askArkPem, trustAnchor ?? AmdMilanArkSpkiSha384, nowMs, clockSkewMs);
        if (AmdVerifier.ChainRefused(reason, key, tbs)) return new(false, reason, null, null);
        return new(true, null, key!.EcPointOn("P-384"), tbs);
    }

    /// <summary>The result of <see cref="VerifyGenuineSevSnpReport"/>: on success the parsed report and the default measured identity.</summary>
    public sealed record GenuineResult(bool Ok, string? Reason, D? Report, D? Measured);

    /// <summary>Parse and verify a report end to end, offline: canonical length, reserved-zero signature block, the pinned chain, the report signature under the VCEK, the VCEK binding, the
    /// expected holder / grant / epoch / nonce binding (when given) and the policy (when given). Fails closed with the reference's reason.</summary>
    public static GenuineResult VerifyGenuineSevSnpReport(byte[] report, byte[] vcekDer, string askArkPem, string? trustAnchor, long nowMs, object? clockSkewMs = null, AttestationBinding? expected = null, D? policy = null)
    {
        static GenuineResult Fail(string r) => new(false, r, null, null);
        try
        {
            D rep;
            try { rep = ParseSevSnpReport(report); }
            catch (ArgumentException e) { return Fail("report parse failed: " + e.Message); }
            if (report.Length != AttestAmd.ReportLen) return Fail($"report length {report.Length} is not the canonical {AttestAmd.ReportLen}");
            static bool NonZero(ReadOnlySpan<byte> b) { foreach (var x in b) if (x != 0) return true; return false; }
            if (NonZero(report.AsSpan(AttestAmd.OffSigS + 72)) || NonZero(report.AsSpan(AttestAmd.OffSigR + 48, 24)) || NonZero(report.AsSpan(AttestAmd.OffSigS + 48, 24)))
                return Fail("report signature block has non-zero reserved bytes");
            var chain = VerifyAmdCertChain(vcekDer, askArkPem, trustAnchor, nowMs, clockSkewMs);
            if (!chain.Ok) return Fail("cert chain invalid: " + chain.Reason);
            if (!VerifySevSnpReportSignature(rep, chain.VcekPoint)) return Fail("report signature does not verify under VCEK");
            var bindErr = CheckVcekReportBinding(chain.VcekTbs!, rep);
            if (bindErr != null) return Fail(bindErr);
            if (expected != null && !AttestUtil.TimingSafeEq(AttestUtil.BindingBytes(expected), (byte[])rep["report_data"]!)) return Fail("report_data does not bind holder/grant/epoch/nonce");
            if (policy != null && CheckSevSnpPolicy(rep, policy) is { } pe) return Fail(pe);
            return new(true, null, rep, MakeDefaultDeriveIdentity(false)(rep));
        }
        catch (Exception e) { return Fail("genuine verification error (fail closed): " + e.Message); }
    }

    // ---- policy and identity ----

    static List<string> LowerList(object? v)
    {
        var o = new List<string>();
        if (v is not L l || l.Count == 0) return o;
        foreach (var x in l) o.Add(x is string s ? s.ToLowerInvariant() : throw new InvalidOperationException("x.toLowerCase is not a function"));
        return o;
    }

    /// <summary>The reason a report violates the policy, or null. Policy members: <c>requireEcdsaP384</c> (false disables the algorithm gate), <c>allowDebug</c> (true), <c>minGuestSvn</c> (a number),
    /// <c>minReportedTcb</c> / <c>minCommittedTcb</c> / <c>minLaunchTcb</c> (BigInteger), <c>requireVmpl</c> (a number or "any"; default 0), and the lowercase-compared hex lists <c>measurements</c>,
    /// <c>hostData</c>, <c>chipIds</c>. Throws on a null policy or a non-string list element.</summary>
    public static string? CheckSevSnpPolicy(D report, D? policy)
    {
        if (policy == null) throw new InvalidOperationException("Cannot read properties of null (reading 'requireEcdsaP384')");
        var p = new SnpPolicy
        {
            RequireEcdsaP384 = policy.GetValueOrDefault("requireEcdsaP384") is not false, AllowDebug = policy.GetValueOrDefault("allowDebug") is true,
            RequireVmpl = policy.GetValueOrDefault("requireVmpl"), MinGuestSvn = AttestUtil.AsFinite(policy.GetValueOrDefault("minGuestSvn")),
            MinReportedTcb = policy.GetValueOrDefault("minReportedTcb") as BigInteger?, MinCommittedTcb = policy.GetValueOrDefault("minCommittedTcb") as BigInteger?,
            MinLaunchTcb = policy.GetValueOrDefault("minLaunchTcb") as BigInteger?,
        };
        p.Measurements = LowerList(policy.GetValueOrDefault("measurements"));
        p.HostData = LowerList(policy.GetValueOrDefault("hostData"));
        p.ChipIds = LowerList(policy.GetValueOrDefault("chipIds"));
        return p.Check(Typed(report));
    }

    /// <summary>The default report to measured-identity mapping (HOST_DATA is host-asserted, so <c>weights_measured</c> is always false).</summary>
    public static Func<D, D> MakeDefaultDeriveIdentity(bool weightsFromHostData) => report => new D
    {
        ["model_id"] = "", ["weights_digest"] = weightsFromHostData ? ToHex((byte[])report["host_data"]!) : "", ["weights_measured"] = false,
        ["runtime_measurement"] = ToHex((byte[])report["measurement"]!), ["operator"] = ToHex((byte[])report["chip_id"]!),
    };

    // ---- the KDS ----

    /// <summary>The VCEK certificate of a chip at a reported TCB from the AMD KDS, over the injected transport: <c>&lt;base&gt;/&lt;product&gt;/&lt;hex chip id&gt;?blSPL=&amp;teeSPL=&amp;snpSPL=&amp;ucodeSPL=</c>
    /// (the SPLs are TCB bytes 0, 1, 6 and 7). Throws without a transport and on a non-2xx answer.</summary>
    public static byte[] FetchVcekFromKds(byte[] chipId, ulong reportedTcb, KdsOptions? opts = null)
    {
        var product = opts?.Product ?? "Milan";
        var baseUrl = opts?.BaseUrl ?? "https://kdsintf.amd.com/vcek/v1";
        var fetch = opts?.Fetch ?? throw new InvalidOperationException("fetchVcekFromKds: no fetch implementation available");
        int At(int i) => (int)((reportedTcb >> (8 * i)) & 0xff);
        var url = $"{baseUrl}/{product}/{ToHex(chipId)}?blSPL={At(0)}&teeSPL={At(1)}&snpSPL={At(6)}&ucodeSPL={At(7)}";
        var res = fetch(url);
        if (!res.Ok) throw new InvalidOperationException($"KDS VCEK fetch failed: HTTP {res.Status} for {url}");
        return res.Body;
    }
}
