// Google Cloud Confidential Space: the attestation token (RS256, ES256 defensively) verified under a signing key anchored in the
// configured trust anchors (a pinned JWKS, SPKI pins or an x5c chain to a configured root), with iss / time window, the
// Confidential Space claims, the eat_nonce binding and the workload image-digest allowlist. Same checks, order and reason text as
// the reference verifier. Classical; no network I/O.
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal sealed class GcpVerifier : IVendorImpl
{
    readonly HashSet<string> issuers = new(StringComparer.Ordinal), spkiPins = new(StringComparer.Ordinal), images = new(StringComparer.Ordinal);
    readonly List<JD?> trustedKeys = new();
    List<string> rootCertsPem = new();
    HashSet<string> teeTypes = new(StringComparer.Ordinal), swVersions = new(StringComparer.Ordinal);
    bool hasTeeTypes, hasSwVersions, allowDebug;
    string swName = "CONFIDENTIAL_SPACE", nonceHash = "";
    double skew;

    static IEnumerable<string> AnyStrings(object? v) => (v as JL ?? new JL()).OfType<string>();

    internal static GcpVerifier Create(JD cfg)
    {
        const string P = "createGcpConfidentialSpaceVerifier: ";
        if (cfg.GetValueOrDefault("trustedIssuers") is not JL issArr || issArr.Count == 0) throw new ArgumentException(P + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs");
        var v = new GcpVerifier();
        foreach (var x in issArr)
        {
            if (x is not string s || s.Length == 0) throw new ArgumentException(P + "every trusted issuer must be a non-empty URL string");
            v.issuers.Add(s);
        }
        var anch = cfg.GetValueOrDefault("trustAnchors") as JD ?? new JD();
        if ((anch.GetValueOrDefault("trustedJwks") as JD)?.GetValueOrDefault("keys") is JL keys)
            foreach (var k in keys) v.trustedKeys.Add(k as JD);
        int spki = AttestMaaLen(anch.GetValueOrDefault("trustedKeySpki"));
        foreach (var s in AnyStrings(anch.GetValueOrDefault("trustedKeySpki"))) v.spkiPins.Add(s.ToLowerInvariant());
        v.rootCertsPem = AttestUtil.AsStrList(anch.GetValueOrDefault("rootCertsPem")) ?? new List<string>();
        if (v.trustedKeys.Count + spki + AttestMaaLen(anch.GetValueOrDefault("rootCertsPem")) == 0)
            throw new ArgumentException(P + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted");
        var pol = cfg.GetValueOrDefault("policy") as JD ?? new JD();
        var digests = AttestUtil.AsStrList(pol.GetValueOrDefault("imageDigests"));
        if (digests == null || digests.Count == 0) throw new ArgumentException(P + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)");
        if (pol.TryGetValue("allowedTeeTypes", out var raw) && raw is JL arr)
        {
            if (arr.Count == 0) throw new ArgumentException(P + "policy.allowedTeeTypes, when present, must be non-empty");
            v.hasTeeTypes = true;
            foreach (var s in arr.OfType<string>()) v.teeTypes.Add(s);
        }
        v.skew = MaaVerifier.SkewOf(cfg);
        foreach (var d in digests) v.images.Add(d.ToLowerInvariant());
        if (pol.GetValueOrDefault("expectedSwName") is string sn) v.swName = sn;
        if (pol.GetValueOrDefault("allowedSwVersions") is JL sv)
        {
            v.hasSwVersions = true;
            foreach (var s in sv.OfType<string>()) v.swVersions.Add(s);
        }
        v.allowDebug = pol.GetValueOrDefault("allowDebug") is true;
        v.nonceHash = pol.GetValueOrDefault("nonceHash") as string ?? "";
        return v;
    }

    static int AttestMaaLen(object? v) => v switch { JL l => l.Count, string s => s.Length, _ => 0 };

    /// <summary>Builds a public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain). The reason on failure.</summary>
    static (CertKey? Key, string Why) JwkKey(JD? jwk)
    {
        jwk ??= new JD();
        try
        {
            if (jwk.GetValueOrDefault("n") is string n && jwk.GetValueOrDefault("e") is string e) return (AttestJws.JwkRsaKey(n, e), "");
            if (jwk.GetValueOrDefault("kty") is "EC" && jwk.GetValueOrDefault("crv") is string crv && jwk.GetValueOrDefault("x") is string x && jwk.GetValueOrDefault("y") is string y) return (AttestJws.JwkEcKey(crv, x, y), "");
            if (jwk.GetValueOrDefault("x5c") is JL x5c && x5c.Count > 0 && x5c[0] is string s)
                return (AttestCerts.KeyOf(AttestCerts.ParseDer(AttestUtil.NodeB64(s))), "");
        }
        catch (AttestError ex) { return (null, "JWKS key is not a usable public key: " + ex.Message); }
        return (null, "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate");
    }

    /// <summary>Verifies a JWK x5c chain to a configured SPKI pin or root certificate; "" when it anchors.</summary>
    string VerifyJwkX5cChain(JL x5c, long nowMs)
    {
        if (x5c.Count == 0) return "empty x5c certificate chain";
        var certs = new List<AttCert>();
        for (int i = 0; i < x5c.Count; i++)
        {
            if (x5c[i] is not string b64 || b64.Length == 0) return $"empty x5c entry at index {i}";
            AttCert c;
            try { c = AttestCerts.ParseDer(AttestUtil.NodeB64(b64)); }
            catch (AttestError e) { return $"malformed x5c certificate at index {i}: {e.Message}"; }
            if (!AttestDer.DerValidAtF(c.Raw, nowMs, skew)) return $"x5c certificate at index {i} is outside its validity window";
            certs.Add(c);
        }
        for (int i = 0; i < certs.Count - 1; i++)
            if (!AttestCerts.SigOkBy(certs[i], certs[i + 1])) return $"x5c link {i} is not signed by the certificate above it";
        foreach (var c in certs)
        {
            try { if (spkiPins.Contains(AttestCerts.KeyOf(c).SpkiSha256())) return ""; } catch (AttestError) { }
        }
        var top = certs[^1];
        foreach (var pemText in rootCertsPem)
        {
            var rk = RootKeyFromPem(pemText);
            if (rk != null && AttestCerts.SigOk(top, rk)) return "";
        }
        return "x5c chain does not anchor in a configured GCP trust root";
    }

    static readonly Regex AnyPemRe = new(@"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END [A-Z0-9 ]+-----", RegexOptions.Singleline | RegexOptions.CultureInvariant);

    /// <summary>Reads a trust root given as a certificate or as a bare public key.</summary>
    static CertKey? RootKeyFromPem(string pemText)
    {
        try { return AttestCerts.KeyOf(AttestCerts.FromPem(pemText)); } catch (AttestError) { }
        var m = AnyPemRe.Match(pemText);
        if (m.Success)
        {
            try { return AttestCerts.KeyOfSpki(Convert.FromBase64String(new string(m.Groups[1].Value.Where(c => !char.IsWhiteSpace(c)).ToArray()))); }
            catch (Exception) { }
        }
        return null;
    }

    /// <summary>The key the token was signed under: by kid if present, else the sole key.</summary>
    static JD? PickJwk(JwtParsed tok, List<JD?> keys)
    {
        if (tok.HasKid && tok.Kid.Length > 0)
        {
            foreach (var k in keys) if (k?.GetValueOrDefault("kid") is string kid && kid == tok.Kid) return k;
            return null;
        }
        return keys.Count == 1 ? keys[0] : null;
    }

    /// <summary>Resolves the token's signing key and confirms it is anchored. The key, or the failure reason.</summary>
    (CertKey? Key, string Why) SigningKey(JwtParsed tok, object? evidenceJwks, long nowMs)
    {
        var evKeys = ((evidenceJwks as JD)?.GetValueOrDefault("keys") as JL ?? new JL()).Select(x => x as JD).ToList();
        var jwk = PickJwk(tok, evKeys);
        bool fromTrusted = false;
        if (jwk == null)
        {
            jwk = PickJwk(tok, trustedKeys);
            fromTrusted = jwk != null;
        }
        bool hasKid = tok.HasKid && tok.Kid.Length > 0;
        if (jwk == null && tok.HasX5c && tok.X5c.Count > 0) jwk = new JD { ["x5c"] = new JL(tok.X5c.Cast<object?>()) };
        if (jwk == null)
            return (null, hasKid ? $"no JWKS key matches the token kid '{tok.Kid}' (untrusted signer)" : "no kid on the token and no unambiguous single signing key available");
        var (key, why) = JwkKey(jwk);
        if (why.Length > 0) return (null, why);
        var spki = key!.SpkiSha256();
        if (fromTrusted || spkiPins.Contains(spki)) return (key, "");
        foreach (var tk in trustedKeys)
        {
            var (tb, w) = JwkKey(tk);
            if (w.Length == 0 && tb!.SpkiSha256() == spki) return (key, "");
        }
        if (jwk.GetValueOrDefault("x5c") is JL x5c && x5c.Count > 0 && (rootCertsPem.Count > 0 || spkiPins.Count > 0))
        {
            var chainErr = VerifyJwkX5cChain(x5c, nowMs);
            if (chainErr.Length == 0) return (key, "");
            return (null, "signing key not trusted: " + chainErr);
        }
        return (null, "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)");
    }

    static string JwsSignature(JwtParsed tok, CertKey k)
    {
        var (kty, crv) = AttestJws.JwkKtyCrv(k);
        switch (tok.Alg)
        {
            case "RS256":
                if (kty != "RSA") return $"RS256 token but signing key is {kty} (not RSA)";
                return AttestJws.Rs256Ok(tok.Signature, tok.SigningInput, k) ? "" : "JWS RS256 signature does not verify under the Confidential Space signing key";
            case "ES256":
                if (kty != "EC" || crv != "P-256") return $"ES256 token but signing key is {kty}/{crv} (not EC P-256)";
                if (tok.Signature.Length != 64) return $"ES256 signature is {tok.Signature.Length} bytes (expected 64: r‖s)";
                return AttestJws.Es256Ok(tok.Signature, tok.SigningInput, k) ? "" : "JWS ES256 signature does not verify under the Confidential Space signing key";
        }
        return $"unsupported JWS alg '{tok.Alg}' (Confidential Space uses RS256)";
    }

    /// <summary>Maps a Confidential Space hwmodel to its isolation family ("" when unrecognised).</summary>
    static string TeeType(string hwmodel)
    {
        switch (hwmodel)
        {
            case "GCP_AMD_SEV": case "GCP_AMD_SEV_SNP": case "GCP_AMD_SEV_ES": return "sev-snp";
            case "GCP_INTEL_TDX": return "tdx";
        }
        var up = hwmodel.ToUpperInvariant();
        if (up.StartsWith("GCP_AMD_SEV", StringComparison.Ordinal)) return "sev-snp";
        if (up.StartsWith("GCP_INTEL_TDX", StringComparison.Ordinal)) return "tdx";
        return "";
    }

    static List<string> NonceCandidates(object? v)
    {
        if (v is string s) return s.Length > 0 ? new List<string> { s } : new List<string>();
        var arr = AttestUtil.AsStrList(v);
        return arr == null ? new List<string>() : arr.Where(x => x.Length > 0).ToList();
    }

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        if (ev == null || ev.GetValueOrDefault("token") is not string token || token.Length == 0) return HardwareResult.Fail("no GCP Confidential Space token for this action");
        JwtParsed tok;
        try { tok = AttestJws.ParseJwt(token, "parseGcpCsJwt"); }
        catch (AttestError e) { return HardwareResult.Fail("Confidential Space token parse failed: " + e.Message); }
        if (tok.Alg != "RS256" && tok.Alg != "ES256") return HardwareResult.Fail($"unsupported JWS alg '{tok.Alg}' (Confidential Space uses RS256)");
        var (key, why) = SigningKey(tok, ev.GetValueOrDefault("jwks"), nowMs);
        if (why.Length > 0) return HardwareResult.Fail("Confidential Space signing key invalid: " + why);
        var sigErr = JwsSignature(tok, key!);
        if (sigErr.Length > 0) return HardwareResult.Fail(sigErr);

        var payload = tok.Payload;
        var issIsStr = payload.GetValueOrDefault("iss") is string;
        var iss = payload.GetValueOrDefault("iss") as string ?? "";
        if (iss.Length == 0 || !issuers.Contains(iss)) return HardwareResult.Fail($"token iss '{(issIsStr ? iss : "undefined")}' is not a configured trusted Google attestation issuer");
        double nowSec = Math.Floor((double)nowMs / 1000), skewSec = Math.Ceiling(skew / 1000);
        var exp = AttestUtil.AsFinite(payload.GetValueOrDefault("exp")); var iat = AttestUtil.AsFinite(payload.GetValueOrDefault("iat")); var nbf = AttestUtil.AsFinite(payload.GetValueOrDefault("nbf"));
        if (exp == null) return HardwareResult.Fail("token has no exp (cannot bound validity — fail closed)");
        if (nowSec - skewSec > exp) return HardwareResult.Fail("Confidential Space token expired");
        if (nbf != null && nowSec + skewSec < nbf) return HardwareResult.Fail("Confidential Space token not yet valid (nbf)");
        if (iat != null && nowSec + skewSec < iat) return HardwareResult.Fail("Confidential Space token issued in the future (iat)");

        var submods = payload.GetValueOrDefault("submods") as JD;
        if (submods?.GetValueOrDefault("confidential_space") is not JD) return HardwareResult.Fail("token carries no submods.confidential_space (not a Confidential Space token)");
        var swname = payload.GetValueOrDefault("swname") as string;
        if (swname == null || swname != swName) return HardwareResult.Fail($"unexpected swname '{swname ?? "undefined"}' (expected '{swName}')");
        if (hasSwVersions)
        {
            var versions = AttestUtil.AsStrList(payload.GetValueOrDefault("swversion"));
            if (versions == null && payload.GetValueOrDefault("swversion") is string sv && sv.Length > 0) versions = new List<string> { sv };
            if (!(versions ?? new List<string>()).Any(swVersions.Contains)) return HardwareResult.Fail("swversion not in policy allowlist");
        }
        var hwmodel = payload.GetValueOrDefault("hwmodel") as string ?? "";
        if (hwmodel.Length == 0) return HardwareResult.Fail("token carries no hwmodel claim");
        var teeType = TeeType(hwmodel);
        if (teeType.Length == 0) return HardwareResult.Fail($"unrecognized hwmodel '{hwmodel}' (not a known AMD SEV-SNP / Intel TDX model)");
        if (hasTeeTypes && !teeTypes.Contains(teeType)) return HardwareResult.Fail($"attestation type '{teeType}' (hwmodel '{hwmodel}') is not in the policy allowlist");
        var dbgstat = payload.GetValueOrDefault("dbgstat") as string;
        if (!allowDebug && dbgstat != "disabled-since-boot") return HardwareResult.Fail($"token dbgstat '{dbgstat ?? "undefined"}' is not 'disabled-since-boot' (debug build — no confidentiality)");
        if (expected == null) return HardwareResult.Fail("no expected attestation binding supplied");
        byte[] raw;
        try { raw = AttestUtil.BindingBytes(expected); }
        catch (AttestError e) { return HardwareResult.Fail("binding not constructible: " + e.Message); }
        var bindingBytes = raw;
        if (nonceHash == "sha256") bindingBytes = AttestUtil.Sha256(raw); else if (nonceHash == "sha512") bindingBytes = AttestUtil.Sha512(raw);
        var candidates = NonceCandidates(payload.GetValueOrDefault("eat_nonce"));
        if (candidates.Count == 0) return HardwareResult.Fail("token carries no eat_nonce claim to bind the PCA challenge");
        bool bound = candidates.Any(c => AttestUtil.DecodeClaimBytes(c) is { } b && AttestUtil.TimingSafeEq(b, bindingBytes));
        if (!bound) return HardwareResult.Fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        var container = submods.GetValueOrDefault("container") as JD ?? new JD();
        var imageDigest = MaaVerifier.FirstString(container, "image_digest");
        if (imageDigest == null) return HardwareResult.Fail("token carries no submods.container.image_digest to measure the workload");
        if (!images.Contains(imageDigest.ToLowerInvariant())) return HardwareResult.Fail("workload image_digest not in policy allowlist");
        var host = new Dictionary<string, string> { ["attestation_type"] = teeType, ["hwmodel"] = hwmodel, ["image_digest"] = imageDigest };
        if (MaaVerifier.FirstString(container, "image_reference") is { } r) host["image_reference"] = r;
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured(imageDigest, ""), host);
    }
}
