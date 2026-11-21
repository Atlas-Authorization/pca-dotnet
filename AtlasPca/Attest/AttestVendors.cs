// The public names of the hardware attestation verifier modules of the reference (AMD SEV-SNP, Intel TDX DCAP and its PCS collateral,
// Azure MAA, Google Confidential Space): the suite constants, the verifier constructors, the parsers and the network fetchers.
// The verifier logic itself lives in the internal vendor implementations; each member here is the same function under the reference name.
// A fetcher takes the transport as a delegate (a null transport throws, as the SEV-SNP KDS fetcher does): nothing here opens a socket.
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Nist;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class AttestVendors
{
    static T Wrap<T>(Func<T> f)
    {
        try { return f(); }
        catch (AttestError e) { throw new ArgumentException(e.Message); }
    }

    static byte[] Slice(byte[] b, int off, int len) => b[off..(off + len)];

    /// <summary>The JSON Web Key Set of a GET answer: <c>{ keys: [...] }</c> with only the members the verifiers read, string members kept as strings.</summary>
    static D JwksOf(KdsResponse res, string what, string url, string[] members)
    {
        if (!res.Ok) throw new InvalidOperationException($"{what} JWKS fetch failed: HTTP {res.Status} for {url}");
        var body = Pca.ParseJson(Encoding.UTF8.GetString(res.Body));
        if ((body as D)?.GetValueOrDefault("keys") is not L keys) throw new InvalidOperationException($"{what} JWKS fetch: response has no keys array");
        var outKeys = new L();
        foreach (var k in keys)
        {
            if (k is not D kr) continue;
            var o = new D();
            foreach (var m in members)
                if (m != "x5c" && kr.GetValueOrDefault(m) is string s) o[m] = s;
            if (members.Contains("x5c") && AttestUtil.AsStrList(kr.GetValueOrDefault("x5c")) is { } x5c) o["x5c"] = new L(x5c.Cast<object?>());
            outKeys.Add(o);
        }
        return new D { ["keys"] = outKeys };
    }

    /// <summary>The parts of a compact JWS the MAA and Confidential Space verifiers read (header, payload, signing input, signature); nothing is verified.</summary>
    static D ParsedJwt(string token, string parser)
    {
        var p = Wrap(() => AttestJws.ParseJwt(token, parser));
        var hdr = Pca.ParseJson(Encoding.UTF8.GetString(AttestJws.DecodeCanonicalBase64url(token.Split('.')[0]))) as D ?? new D();
        var header = new D { ["alg"] = p.Alg };
        foreach (var m in new[] { "kid", "jku", "typ" })
            if (hdr.GetValueOrDefault(m) is string s) header[m] = s;
        if (p.HasX5c) header["x5c"] = new L(p.X5c.Cast<object?>());
        return new D { ["header"] = header, ["payload"] = p.Payload, ["signingInput"] = p.SigningInput, ["signature"] = p.Signature };
    }

    /// <summary>The suite and pin constants of the vendor modules, as the reference exports them (member names of the reference).</summary>
    public static D Constants() => new()
    {
        ["INTEL_DCAP_SUITE"] = IntelDcap.Suite, ["AZURE_MAA_SUITE"] = AzureMaa.Suite, ["AZURE_MAA_SUITES"] = new L(AzureMaa.Suites.Cast<object?>()),
        ["GCP_CS_SUITE"] = GcpConfidentialSpace.Suite, ["GCP_CS_SUITES"] = new L(GcpConfidentialSpace.Suites.Cast<object?>()),
        ["GCP_CS_DEFAULT_ISSUER"] = GcpConfidentialSpace.DefaultIssuer, ["INTEL_SGX_ROOT_CA_SPKI_SHA256"] = IntelTdx.SgxRootCaSpkiSha256, ["AMD_SNP_SUITE"] = AmdSnp.Suite,
        ["AMD_ARK_SPKI_SHA384"] = AmdSnp.ArkSpkiSha384.ToDictionary(e => e.Key, e => (object?)e.Value),
        ["DEFAULT_ACCEPTED_STATUSES"] = new L(IntelPcsCollateral.DefaultAcceptedStatuses.Cast<object?>()),
    };

    /// <summary>Lowercase hex of a byte string.</summary>
    public static string ToHex(byte[] b) => AttestUtil.Hex(b);

    /// <summary>The DER of the first certificate block of a PEM text (the base64 body with its whitespace removed, decoded as lenient base64); throws when there is none.</summary>
    public static byte[] PemToDer(string pem)
    {
        var m = Regex.Match(pem, @"-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----", RegexOptions.CultureInvariant);
        if (!m.Success || m.Groups[1].Length == 0) throw new ArgumentException("pemToDer: no certificate found");
        return AttestUtil.NodeB64(Regex.Replace(m.Groups[1].Value, @"\s+", ""));
    }

    /// <summary>The uncompressed point of a P-256 public key given as SEC1 (a compressed point is expanded): <c>{ point }</c>. Throws on a malformed or off-curve point.</summary>
    public static D EcdsaP256PublicKey(byte[] sec1) => new() { ["point"] = IntelTdx.EcdsaP256PublicKey(sec1) };

    /// <summary>Check a quote's report_data against the Azure runtime-data JSON and the expected PCA binding: null when it binds, else the reason.</summary>
    public static string? CheckAzureRuntimeDataBinding(byte[] reportData, byte[] runtimeData, AttestationBinding expected) => AttestUtil.CheckAzureRuntimeDataBinding(reportData, runtimeData, expected);

    public static class AmdSnp
    {
        public const string Suite = "amd-sev-snp-ecdsa-p384";

        /// <summary>The SPKI SHA-384 of the ARK of each AMD family, as published by the AMD key distribution service.</summary>
        public static IReadOnlyDictionary<string, string> ArkSpkiSha384 => AmdVerifier.ArkSpkiSha384;

        /// <summary>The verifier of genuine AMD SEV-SNP reports (<see cref="AttestationVerifiers.FromConfig"/> with the vendor <c>amd-sev-snp</c>).</summary>
        public static IVendorVerifier CreateVerifier(D? config) => AttestationVerifiers.FromConfig("amd-sev-snp", config);
    }

    public static class IntelDcap
    {
        public const string Suite = "intel-tdx-dcap-ecdsa-p256";

        public static IVendorVerifier CreateVerifier(D? config) => AttestationVerifiers.FromConfig("intel-tdx-dcap", config);
    }

    public static class IntelTdx
    {
        /// <summary>The SPKI SHA-256 of the Intel SGX Root CA every PCK chain must end in.</summary>
        public const string SgxRootCaSpkiSha256 = AttestIntel.SgxRootCaSpkiSha256;

        /// <summary>The uncompressed SEC1 point (65 bytes) of a P-256 key given as an uncompressed or compressed point. Throws on a malformed or off-curve point.</summary>
        public static byte[] EcdsaP256PublicKey(byte[] sec1)
        {
            bool ok = (sec1.Length == 33 && sec1[0] is 0x02 or 0x03) || (sec1.Length == 65 && sec1[0] == 0x04);
            if (!ok) throw new ArgumentException($"invalid Point, expected length of 33, or uncompressed 65, got {sec1.Length}");
            var p = NistNamedCurves.GetByName("P-256").Curve.DecodePoint(sec1);
            if (p.IsInfinity) throw new ArgumentException("bad point: is zero");
            return p.Normalize().GetEncoded(false);
        }

        /// <summary>A genuine 584-byte TD10 report body, field by field (byte fields are copies). Throws when the body is too short.</summary>
        public static D ParseDcapTdReport(byte[] body)
        {
            if (body.Length < 584) throw new ArgumentException($"parseDcapTdReport: body too short ({body.Length} < 584)");
            return new D
            {
                ["teeTcbSvn"] = Slice(body, 0, 16), ["mrSeam"] = Slice(body, 16, 48), ["mrSignerSeam"] = Slice(body, 64, 48), ["tdAttributes"] = Slice(body, 120, 8),
                ["mrTd"] = Slice(body, 136, 48), ["mrConfigId"] = Slice(body, 184, 48), ["rtmr0"] = Slice(body, 328, 48), ["rtmr1"] = Slice(body, 376, 48),
                ["rtmr2"] = Slice(body, 424, 48), ["rtmr3"] = Slice(body, 472, 48), ["reportData"] = Slice(body, 520, 64), ["raw"] = Slice(body, 0, 584),
            };
        }

        /// <summary>A DCAP v4 ECDSA-P256 TDX quote: the signed region, the attestation key and its QE endorsement, the PEM PCK chain. Throws on anything malformed.</summary>
        public static D ParseDcapQuote(byte[] quote)
        {
            var q = Wrap(() => AttestIntel.ParseQuote(quote));
            return new D
            {
                ["version"] = 4L, ["attKeyType"] = 2L, ["teeType"] = 0x81L, ["header"] = q.Header, ["tdReportBody"] = q.TdReportBody, ["quoteSignature"] = q.QuoteSignature,
                ["akPubRaw"] = q.AkPubRaw, ["qeReportBody"] = q.QeReportBody, ["qeReportSignature"] = q.QeReportSignature, ["qeAuthData"] = q.QeAuthData, ["pckChainPem"] = q.PckChainPem,
            };
        }

        /// <summary>The FMSPC and the issued TCB of a PCK leaf certificate (DER): <c>{ fmspc, sgxTcbComponents (16), pcesvn, cpusvn }</c>. Throws on a missing or malformed Intel SGX extension.</summary>
        public static D ExtractPckFmspcAndTcb(byte[] leafDer)
        {
            var t = Wrap(() => AttestIntel.ExtractPckFmspcAndTcb(leafDer));
            return TcbOf(t);
        }

        internal static D TcbOf(PckTcb t) => new() { ["fmspc"] = t.Fmspc, ["sgxTcbComponents"] = t.Sgx, ["pcesvn"] = (long)t.Pcesvn, ["cpusvn"] = t.Cpusvn };

        static byte[] Point(System.Security.Cryptography.ECDsa k)
        {
            var q = k.ExportParameters(false).Q;
            return Pca.Concat(new byte[] { 4 }, q.X!, q.Y!);
        }

        /// <summary>Verify a genuine Intel TDX quote (PCK chain to the pinned root, QE report, attestation key, TD signature, optional PCA binding, debug, allowlists) at <paramref name="nowMs"/>.
        /// <paramref name="policy"/> is <c>{ mrtds?, fmspcs?, rtmrs?, mrSeams?, mrSignerSeams?, allowDebug? }</c>: an empty mrtds / fmspcs / rtmrs list is not gated, an empty mrSeams / mrSignerSeams list refuses everything.
        /// <c>{ ok, reason? | report, fmspc, pckTcb, akPub, chainDepth, measured }</c>; fails closed.</summary>
        public static D VerifyGenuineTdxQuote(byte[] quote, string? trustAnchorRootCaSpkiSha256, AttestationBinding? expected, D? policy, long nowMs)
        {
            TdxQuotePolicy? pol = null;
            if (policy != null)
            {
                List<string> Low(string k) => AttestUtil.LowerAll(AttestUtil.AsStrList(policy.GetValueOrDefault(k)) ?? new List<string>());
                pol = new TdxQuotePolicy
                {
                    Mrtds = Low("mrtds"), Fmspcs = Low("fmspcs"), Rtmrs = Low("rtmrs"), MrSeams = Low("mrSeams"), MrSignerSeams = Low("mrSignerSeams"),
                    HasMrSeams = policy.GetValueOrDefault("mrSeams") is L, HasMrSigner = policy.GetValueOrDefault("mrSignerSeams") is L, AllowDebug = policy.GetValueOrDefault("allowDebug") is true,
                };
            }
            var r = AttestIntel.VerifyGenuineTdxQuote(quote, trustAnchorRootCaSpkiSha256 ?? SgxRootCaSpkiSha256, nowMs, pol, false, expected);
            if (!r.Ok) return new D { ["ok"] = false, ["reason"] = r.Reason };
            var ak = new byte[65];
            ak[0] = 4;
            Array.Copy(r.AkPubRaw, 0, ak, 1, 64);
            return new D
            {
                ["ok"] = true, ["report"] = ParseDcapTdReport(r.Body), ["fmspc"] = r.Fmspc, ["pckTcb"] = TcbOf(r.Pck!), ["akPub"] = new D { ["point"] = ak },
                ["chainDepth"] = (long)r.Depth, ["measured"] = AttestUtil.NewMeasured(AttestUtil.Hex(r.MrTd), ""),
            };
        }

        /// <summary>X.509-verify a PCK chain (PEM) to the pinned Intel SGX Root CA at <paramref name="nowMs"/>; <c>{ ok, reason?, failure? }</c> and fails closed.</summary>
        public static D VerifyIntelPckChainX509(string pckChainPem, string? trustAnchorRootCaSpkiSha256 = null, long? nowMs = null)
        {
            var r = AttestIntel.VerifyPckChain(pckChainPem, trustAnchorRootCaSpkiSha256 ?? SgxRootCaSpkiSha256, nowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            if (r.Ok) return new D { ["ok"] = true, ["leafKey"] = new D { ["point"] = Point(r.LeafKey!.Ec!) }, ["leafDer"] = r.Leaf!.Raw, ["depth"] = (long)r.Depth };
            var o = new D { ["ok"] = false, ["reason"] = r.Reason };
            if (r.Validity) o["failure"] = "validity";
            return o;
        }
    }

    public static class IntelPcsCollateral
    {
        /// <summary>The TCB statuses a collateral policy accepts unless it says otherwise.</summary>
        public static IReadOnlyList<string> DefaultAcceptedStatuses { get; } = new[] { "UpToDate", "SWHardeningNeeded" };

        /// <summary>A PCS issuer-chain HTTP header value (URL-encoded PEM) as PEM.</summary>
        /// <remarks>decodeURIComponent: a malformed %-escape, or escapes that are not UTF-8, throw "URI malformed".</remarks>
        public static string DecodeIssuerChainHeader(string value)
        {
            var sb = new StringBuilder();
            var strict = new UTF8Encoding(false, true);
            for (int i = 0; i < value.Length;)
            {
                if (value[i] != '%') { sb.Append(value[i++]); continue; }
                var run = new List<byte>();
                while (i < value.Length && value[i] == '%')
                {
                    if (i + 2 >= value.Length || !Uri.IsHexDigit(value[i + 1]) || !Uri.IsHexDigit(value[i + 2])) throw new ArgumentException("URI malformed");
                    run.Add(Convert.ToByte(value.Substring(i + 1, 2), 16));
                    i += 3;
                }
                try { sb.Append(strict.GetString(run.ToArray())); }
                catch (ArgumentException) { throw new ArgumentException("URI malformed"); }
            }
            return sb.ToString();
        }

        /// <summary>Whether a certificate serial (hex) is in a CRL's revoked set (compared without leading zeros, lowercase).</summary>
        public static bool SerialIsRevoked(IReadOnlySet<string> revoked, string serialHex) => revoked.Contains(AttestIntelCollateral.NormSerial(serialHex));

        /// <summary>Verify a CRL (DER) under the issuer key (a DER SubjectPublicKeyInfo) at <paramref name="nowMs"/>: the set of revoked serials, or the reason.</summary>
        public static (bool Ok, IReadOnlySet<string>? Revoked, string? Reason) VerifyCrl(byte[] crlDer, byte[] issuerSpki, long nowMs)
        {
            var (revoked, why) = AttestIntelCollateral.VerifyCrl(crlDer, Wrap(() => AttestCerts.KeyOfSpki(issuerSpki)), nowMs);
            return revoked != null ? (true, revoked, null) : (false, null, why);
        }

        /// <summary>Verify a signed PCS document: <c>{ body }</c> (the object under <paramref name="name"/>, read from the signed bytes) or <c>{ error }</c>. The key is a DER SubjectPublicKeyInfo.</summary>
        public static D VerifySignedJson(string text, string name, byte[] keySpki)
        {
            var (body, why) = AttestIntelCollateral.VerifySignedJson(text, name, Wrap(() => AttestCerts.KeyOfSpki(keySpki)));
            return body != null ? new D { ["body"] = body } : new D { ["error"] = why };
        }

        /// <summary>A collateral member given as bytes: the two JSON documents are their UTF-8 text, the two CRLs their base64 (the wire form).</summary>
        static D WireOf(D c)
        {
            var o = new D(c);
            foreach (var k in new[] { "tcbInfoJson", "qeIdentityJson" })
                if (o.GetValueOrDefault(k) is byte[] b) o[k] = Encoding.UTF8.GetString(b);
            foreach (var k in new[] { "pckCrlDer", "rootCrlDer" })
                if (o.GetValueOrDefault(k) is byte[] b) o[k] = Convert.ToBase64String(b);
            return o;
        }

        /// <summary>Verify a genuine Intel TDX quote and its PCS collateral (<paramref name="collateral"/> in the wire form: tcbInfoJson, tcbInfoIssuerChainPem, qeIdentityJson,
        /// qeIdentityIssuerChainPem, pckCrlDer, rootCrlDer) at <paramref name="nowMs"/>; <paramref name="policy"/> is <c>{ acceptStatuses?, minTcbEvaluationDataNumber? }</c>.
        /// <c>{ ok, reason?, status?, platformStatus?, tdxModuleStatus?, qeStatus?, advisoryIds?, tcbEvaluationDataNumber?, fmspc? }</c>; fails closed.</summary>
        public static D VerifyIntelTdxCollateral(byte[] quote, D? collateral, long nowMs, D? policy = null, string? trustAnchorRootCaSpkiSha256 = null, bool allowDebug = false)
        {
            var r = AttestIntelCollateral.Verify(quote, collateral == null ? null : IntelCollateral.FromWire(WireOf(collateral)), nowMs, policy == null ? null : IntelVerifier.CollateralPolicyOf(policy),
                trustAnchorRootCaSpkiSha256 ?? AttestIntel.SgxRootCaSpkiSha256, allowDebug);
            // evaluation reached (a status is set): the full evaluation is reported even when policy refuses it, as the reference does
            if (r.Status.Length == 0) return new D { ["ok"] = false, ["reason"] = r.Reason };
            var o = new D
            {
                ["ok"] = r.Ok, ["status"] = r.Status, ["platformStatus"] = r.PlatformStatus, ["tdxModuleStatus"] = r.TdxModuleStatus, ["qeStatus"] = r.QeStatus,
                ["advisoryIds"] = new L(r.AdvisoryIds.Cast<object?>()), ["tcbEvaluationDataNumber"] = (long)r.TcbEvaluationDataNumber, ["fmspc"] = r.Fmspc,
            };
            if (!r.Ok) o["reason"] = r.Reason;
            return o;
        }
    }

    public static class AzureMaa
    {
        public static IReadOnlyList<string> Suites { get; } = new[] { "ES256", "RS256" };
        public const string Suite = "azure-maa-jwt";

        public static IVendorVerifier CreateVerifier(D? config) => AttestationVerifiers.FromConfig("azure-maa", config);

        /// <summary>Verify an MAA token-signing x5c chain (base64 DER, leaf first) to the configured anchors (<c>{ rootCertsPem?, rootSpkiSha256? }</c>, at least one) at
        /// <paramref name="nowMs"/>: <c>{ ok, reason? | leafSpkiSha256 }</c>. The root of trust is the anchor, never a certificate of the chain.</summary>
        public static D VerifyX5cChain(IEnumerable<object?> x5c, D anchors, long nowMs, double clockSkewMs = 0)
        {
            var v = MaaVerifier.ForChainCheck(anchors, Math.Max(0, clockSkewMs));
            var (leaf, why) = v.VerifyX5cChain(new L(x5c), nowMs);
            return leaf == null ? new D { ["ok"] = false, ["reason"] = why } : new D { ["ok"] = true, ["leafSpkiSha256"] = AttestCerts.KeyOf(leaf).SpkiSha256(), ["leafDer"] = leaf.Raw };
        }

        /// <summary>Parse a compact MAA JWS (verifies nothing): <c>{ header, payload, signingInput, signature }</c>. Throws on anything malformed.</summary>
        public static D ParseMaaJwt(string token) => ParsedJwt(token, "parseMaaJwt");

        /// <summary>Fetch an MAA instance's JWKS from its <c>/certs</c> endpoint over the supplied transport (it is never auto-invoked).</summary>
        public static D FetchMaaJwks(string issuer, Func<string, KdsResponse>? fetch, string certsPath = "/certs")
        {
            var f = fetch ?? throw new InvalidOperationException("fetchMaaJwks: no fetch implementation available");
            var url = issuer.TrimEnd('/') + certsPath;
            return JwksOf(f(url), "MAA", url, new[] { "kid", "kty", "alg", "x5c" });
        }
    }

    public static class GcpConfidentialSpace
    {
        public static IReadOnlyList<string> Suites { get; } = new[] { "RS256", "ES256" };
        public const string Suite = "gcp-confidential-space-jwt";
        public const string DefaultIssuer = "https://confidentialcomputing.googleapis.com";

        public static IVendorVerifier CreateVerifier(D? config) => AttestationVerifiers.FromConfig("gcp-confidential-space", config);

        /// <summary>Verify a Confidential Space JWK x5c chain (base64 DER, leaf first) to the configured anchors (<c>{ trustedJwks?, trustedKeySpki?, rootCertsPem? }</c>, at least one)
        /// at <paramref name="nowMs"/>: null when it anchors, else the reason.</summary>
        public static string? VerifyJwkX5cChain(IEnumerable<object?> x5c, D anchors, long nowMs, double skewMs = 0)
        {
            var v = GcpVerifier.ForChainCheck(anchors, Math.Max(0, skewMs));
            var why = v.VerifyJwkX5cChain(new L(x5c), nowMs);
            return why.Length == 0 ? null : why;
        }

        /// <summary>The isolation family of a Confidential Space <c>hwmodel</c> (<c>sev-snp</c> or <c>tdx</c>), null when unrecognised.</summary>
        public static string? TeeTypeOfHwModel(string hwmodel)
        {
            if (hwmodel is "GCP_AMD_SEV" or "GCP_AMD_SEV_SNP" or "GCP_AMD_SEV_ES") return "sev-snp";
            if (hwmodel == "GCP_INTEL_TDX") return "tdx";
            var up = hwmodel.ToUpperInvariant();
            if (up.StartsWith("GCP_AMD_SEV", StringComparison.Ordinal)) return "sev-snp";
            if (up.StartsWith("GCP_INTEL_TDX", StringComparison.Ordinal)) return "tdx";
            return null;
        }

        /// <summary>Parse a compact Confidential Space JWS (verifies nothing): <c>{ header, payload, signingInput, signature }</c>. Throws on anything malformed.</summary>
        public static D ParseGcpCsJwt(string token) => ParsedJwt(token, "parseGcpCsJwt");

        /// <summary>Fetch the signing keys of a Confidential Space issuer over the supplied transport: the OpenID configuration names the <c>jwks_uri</c> unless <paramref name="jwksUri"/> is given.</summary>
        public static D FetchGcpConfidentialSpaceJwks(string issuer, Func<string, KdsResponse>? fetch, string? jwksUri = null)
        {
            var f = fetch ?? throw new InvalidOperationException("fetchGcpConfidentialSpaceJwks: no fetch implementation available");
            if (string.IsNullOrEmpty(jwksUri)) // an empty option is as absent as a missing one
            {
                var confUrl = issuer.TrimEnd('/') + "/.well-known/openid-configuration";
                var conf = f(confUrl);
                if (!conf.Ok) throw new InvalidOperationException($"Confidential Space OpenID config fetch failed: HTTP {conf.Status} for {confUrl}");
                jwksUri = (Pca.ParseJson(Encoding.UTF8.GetString(conf.Body)) as D)?.GetValueOrDefault("jwks_uri") is string { Length: > 0 } advertised ? advertised
                    : throw new InvalidOperationException("Confidential Space OpenID config carries no jwks_uri");
            }
            return JwksOf(f(jwksUri), "Confidential Space", jwksUri, new[] { "kid", "kty", "alg", "use", "n", "e", "crv", "x", "y", "x5c" });
        }
    }
}
