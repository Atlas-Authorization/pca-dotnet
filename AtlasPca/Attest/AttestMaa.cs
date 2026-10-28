// Microsoft Azure Attestation (MAA): the signed MAA JWT of an Azure confidential VM (SEV-SNP "sevsnpvm" or TDX "tdxvm"), verified
// under the token-signing x5c chain anchored in a configured MAA root, with the PCA challenge bound through the report-data or
// runtime user-data claim. Same checks, order and reason text as the reference verifier. Classical (ES256 / RS256); no network I/O.
// The key-rotation trust store of the reference (fetching and persisting JWKS) is not part of the verifier: anchors are configured
// explicitly.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal sealed class MaaVerifier : IVendorImpl
{
    sealed class Anchors { public List<string> RootCertsPem = new(), RootSpki = new(); }

    sealed class Policy
    {
        public List<string> SevSnp = new(), Tdx = new(), SevHost = new(), TdxRtmrs = new(), TdxStatuses = new();
        public Dictionary<string, double> MinTcb = new();
        public bool AllowDebug, RuntimeUserData, HasTdxStatuses, HasSev, HasTdx;
        public string ReportDataHash = "";
    }

    readonly HashSet<string> issuers = new(StringComparer.Ordinal);
    readonly Anchors anchors = new();
    readonly Policy policy = new();
    double skew;

    static readonly (string Name, string Claim, string HostKey)[] TcbClaims =
    {
        ("bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"), ("snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"),
        ("microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"), ("tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"),
    };

    static int ListLen(object? v) => v switch { JL l => l.Count, string s => s.Length, _ => 0 };

    internal static double SkewOf(JD cfg) => AttestUtil.AsFinite(cfg.GetValueOrDefault("clockSkewMs")) is double f ? Math.Max(0, f) : 0;

    internal static MaaVerifier Create(JD cfg)
    {
        const string P = "createAzureMaaVerifier: ";
        if (cfg.GetValueOrDefault("trustedIssuers") is not JL issArr || issArr.Count == 0) throw new ArgumentException(P + "trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs");
        var v = new MaaVerifier();
        foreach (var x in issArr)
        {
            if (x is not string s || s.Length == 0) throw new ArgumentException(P + "every trusted issuer must be a non-empty URL string");
            v.issuers.Add(s);
        }
        var anch = cfg.GetValueOrDefault("trustAnchors") as JD ?? new JD();
        if (ListLen(anch.GetValueOrDefault("rootCertsPem")) + ListLen(anch.GetValueOrDefault("rootSpkiSha256")) == 0)
            throw new ArgumentException(P + "trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted");
        v.anchors.RootCertsPem = AttestUtil.AsStrList(anch.GetValueOrDefault("rootCertsPem")) ?? new List<string>();
        v.anchors.RootSpki = AttestUtil.AsStrList(anch.GetValueOrDefault("rootSpkiSha256")) ?? new List<string>();
        var pol = cfg.GetValueOrDefault("policy") as JD;
        List<string> sev = new(), tdx = new();
        if (pol != null)
        {
            sev = AttestUtil.AsStrList(pol.GetValueOrDefault("sevSnpMeasurements")) ?? new List<string>();
            tdx = AttestUtil.AsStrList(pol.GetValueOrDefault("tdxMrtds")) ?? new List<string>();
        }
        v.policy.HasSev = sev.Count > 0; v.policy.HasTdx = tdx.Count > 0;
        if (pol == null || (!v.policy.HasSev && !v.policy.HasTdx)) throw new ArgumentException(P + "policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)");
        v.policy.SevSnp = AttestUtil.LowerAll(sev); v.policy.Tdx = AttestUtil.LowerAll(tdx);
        if (pol.TryGetValue("sevSnpMinTcb", out var raw))
        {
            if (raw is not JD m) throw new ArgumentException(P + "policy.sevSnpMinTcb must be an object");
            foreach (var k in m.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                if (!TcbClaims.Any(c => c.Name == k)) throw new ArgumentException($"{P}policy.sevSnpMinTcb.{k} is not a known field (bootloader | snp | microcode | tee)");
                if (AttestUtil.AsFinite(m[k]) is not double f || f != Math.Truncate(f) || f < 0) throw new ArgumentException($"{P}policy.sevSnpMinTcb.{k} must be a non-negative integer");
                v.policy.MinTcb[k] = f;
            }
        }
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("sevSnpHostData")) is { } sh) v.policy.SevHost = AttestUtil.LowerAll(sh);
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("tdxRtmrs")) is { } tr) v.policy.TdxRtmrs = AttestUtil.LowerAll(tr);
        v.policy.AllowDebug = pol.GetValueOrDefault("allowDebug") is true;
        v.policy.RuntimeUserData = pol.GetValueOrDefault("runtimeUserDataBinding") is true;
        if (AttestUtil.AsStrList(pol.GetValueOrDefault("tdxAllowedTcbStatuses")) is { } ts) { v.policy.TdxStatuses = ts; v.policy.HasTdxStatuses = true; }
        v.policy.ReportDataHash = pol.GetValueOrDefault("reportDataHash") as string ?? "";
        v.skew = SkewOf(cfg);
        return v;
    }

    // ---- x5c chain

    /// <summary>Verifies an x5c chain (base64 DER, leaf first) to a configured trust anchor. The leaf, or the failure reason.</summary>
    (AttCert? Leaf, string Why) VerifyX5cChain(JL x5c, long nowMs)
    {
        if (x5c.Count == 0) return (null, "empty x5c certificate chain");
        try
        {
            var certs = new List<AttCert>();
            for (int i = 0; i < x5c.Count; i++)
            {
                if (x5c[i] is not string b64 || b64.Length == 0) return (null, $"empty x5c entry at index {i}");
                AttCert c;
                try { c = AttestCerts.ParseDer(AttestUtil.NodeB64(b64)); }
                catch (AttestError e) { return (null, $"malformed x5c certificate at index {i}: {e.Message}"); }
                if (!AttestDer.DerValidAtF(c.Raw, nowMs, skew)) return (null, $"x5c certificate at index {i} is outside its validity window");
                certs.Add(c);
            }
            var fingerprints = new HashSet<string>(StringComparer.Ordinal);
            foreach (var fp in anchors.RootSpki) if (fp.Length > 0) fingerprints.Add(fp.ToLowerInvariant());
            var roots = new List<AttCert>();
            foreach (var pem in anchors.RootCertsPem)
            {
                var c = AttestCerts.FromPem(pem);
                var k = AttestCerts.KeyOf(c);
                roots.Add(c);
                fingerprints.Add(k.SpkiSha256());
            }
            if (fingerprints.Count == 0 && roots.Count == 0) return (null, "no MAA trust anchor configured (fail closed)");
            int anchorIdx = -1;
            for (int j = 0; j < certs.Count; j++)
            {
                if (fingerprints.Contains(AttestCerts.KeyOf(certs[j]).SpkiSha256())) { anchorIdx = j; break; }
            }
            if (anchorIdx >= 0)
            {
                for (int i = 0; i < anchorIdx; i++)
                    if (!AttestCerts.SigOkBy(certs[i], certs[i + 1])) return (null, $"x5c link {i} is not signed by the certificate above it");
                return (certs[0], "");
            }
            for (int i = 0; i < certs.Count - 1; i++)
                if (!AttestCerts.SigOkBy(certs[i], certs[i + 1])) return (null, $"x5c link {i} is not signed by the certificate above it");
            var top = certs[^1];
            foreach (var r in roots) if (AttestCerts.SigOkBy(top, r)) return (certs[0], "");
            return (null, "x5c chain does not anchor in a configured MAA trust root");
        }
        catch (AttestError e) { return (null, "x5c chain verification error (fail closed): " + e.Message); }
    }

    /// <summary>The JWKS entry matched by kid, else the header's own x5c.</summary>
    static (JL? Chain, string Why) ResolveSigningX5c(JwtParsed tok, object? jwks)
    {
        var keys = (jwks as JD)?.GetValueOrDefault("keys") as JL ?? new JL();
        JL ChainOf(object? k) => (k as JD)?.GetValueOrDefault("x5c") as JL ?? new JL();
        if (keys.Count > 0)
        {
            if (!tok.HasKid || tok.Kid.Length == 0)
            {
                if (keys.Count != 1) return (null, "token has no kid and the JWKS publishes multiple keys (ambiguous)");
                var c0 = ChainOf(keys[0]);
                if (c0.Count > 0) return (c0, "");
                return (null, "JWKS key carries no x5c chain");
            }
            foreach (var k in keys)
            {
                if ((k as JD)?.GetValueOrDefault("kid") is string kid && kid == tok.Kid)
                {
                    var c = ChainOf(k);
                    if (c.Count > 0) return (c, "");
                    return (null, $"JWKS key '{tok.Kid}' carries no x5c chain");
                }
            }
            return (null, $"no JWKS key matches the token kid '{tok.Kid}' (untrusted signer)");
        }
        if (tok.HasX5c && tok.X5c.Count > 0) return (new JL(tok.X5c.Cast<object?>()), "");
        return (null, "no signing x5c available (no JWKS and no header x5c)");
    }

    static string JwsSignature(JwtParsed tok, AttCert leaf)
    {
        CertKey k;
        try { k = AttestCerts.KeyOf(leaf); }
        catch (AttestError e) { return "x5c chain verification error (fail closed): " + e.Message; }
        var (kty, crv) = AttestJws.JwkKtyCrv(k);
        switch (tok.Alg)
        {
            case "ES256":
                if (kty != "EC" || crv != "P-256") return $"ES256 token but signing key is {kty}/{crv} (not EC P-256)";
                if (tok.Signature.Length != 64) return $"ES256 signature is {tok.Signature.Length} bytes (expected 64: r‖s)";
                return AttestJws.Es256Ok(tok.Signature, tok.SigningInput, k) ? "" : "JWS ES256 signature does not verify under the MAA signing key";
            case "RS256":
                if (kty != "RSA") return $"RS256 token but signing key is {kty} (not RSA)";
                return AttestJws.Rs256Ok(tok.Signature, tok.SigningInput, k) ? "" : "JWS RS256 signature does not verify under the MAA signing key";
        }
        return $"unsupported JWS alg '{tok.Alg}' (MAA uses ES256 / RS256)";
    }

    internal static string? FirstString(JD rec, params string[] keys)
    {
        foreach (var k in keys) if (rec.GetValueOrDefault(k) is string s && s.Length > 0) return s;
        return null;
    }

    static byte[] TransformBinding(byte[] binding, string mode) => mode switch { "sha256" => AttestUtil.Sha256(binding), "sha512" => AttestUtil.Sha512(binding), _ => binding };

    public HardwareResult Verify(JD? ev, AttestationBinding? expected, long nowMs)
    {
        if (ev == null || ev.GetValueOrDefault("token") is not string token || token.Length == 0) return HardwareResult.Fail("no Azure MAA token for this action");
        JwtParsed tok;
        try { tok = AttestJws.ParseJwt(token, "parseMaaJwt"); }
        catch (AttestError e) { return HardwareResult.Fail("MAA token parse failed: " + e.Message); }
        if (tok.Alg != "ES256" && tok.Alg != "RS256") return HardwareResult.Fail($"unsupported JWS alg '{tok.Alg}' (MAA uses ES256 / RS256)");
        var (x5c, why) = ResolveSigningX5c(tok, ev.GetValueOrDefault("jwks"));
        if (x5c == null) return HardwareResult.Fail(why);
        var (leaf, why2) = VerifyX5cChain(x5c, nowMs);
        if (leaf == null) return HardwareResult.Fail("MAA signing chain invalid: " + why2);
        var sigErr = JwsSignature(tok, leaf);
        if (sigErr.Length > 0) return HardwareResult.Fail(sigErr);

        var payload = tok.Payload;
        var issIsStr = payload.GetValueOrDefault("iss") is string;
        var iss = payload.GetValueOrDefault("iss") as string ?? "";
        if (iss.Length == 0 || !issuers.Contains(iss)) return HardwareResult.Fail($"token iss '{(issIsStr ? iss : "undefined")}' is not a configured trusted MAA instance");
        double nowSec = Math.Floor((double)nowMs / 1000), skewSec = Math.Ceiling(skew / 1000);
        var exp = AttestUtil.AsFinite(payload.GetValueOrDefault("exp")); var iat = AttestUtil.AsFinite(payload.GetValueOrDefault("iat")); var nbf = AttestUtil.AsFinite(payload.GetValueOrDefault("nbf"));
        if (exp == null) return HardwareResult.Fail("token has no exp (cannot bound validity — fail closed)");
        if (nowSec - skewSec > exp) return HardwareResult.Fail("MAA token expired");
        if (nbf != null && nowSec + skewSec < nbf) return HardwareResult.Fail("MAA token not yet valid (nbf)");
        if (iat != null && nowSec + skewSec < iat) return HardwareResult.Fail("MAA token issued in the future (iat)");

        var teeClaims = payload.GetValueOrDefault("x-ms-isolation-tee") as JD ?? payload;
        var isolation = teeClaims.GetValueOrDefault("x-ms-attestation-type") as string ?? payload.GetValueOrDefault("x-ms-attestation-type") as string;
        if (isolation == null || (isolation != "sevsnpvm" && isolation != "tdxvm"))
            return HardwareResult.Fail($"unexpected x-ms-attestation-type '{isolation ?? "undefined"}' (expected sevsnpvm | tdxvm)");

        if (expected == null) return HardwareResult.Fail("no expected attestation binding supplied");
        byte[] raw;
        try { raw = AttestUtil.BindingBytes(expected); }
        catch (AttestError e) { return HardwareResult.Fail("binding not constructible: " + e.Message); }
        if (policy.RuntimeUserData)
        {
            if (payload.GetValueOrDefault("x-ms-runtime") is not JD runtime) return HardwareResult.Fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)");
            var ud = runtime.GetValueOrDefault("user-data") as string ?? "";
            if (ud.Length == 0) return HardwareResult.Fail("x-ms-runtime carries no user-data to bind the PCA challenge");
            var got = AttestUtil.DecodeClaimBytes(ud);
            if (got == null || !AttestUtil.TimingSafeEq(got, raw)) return HardwareResult.Fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        }
        else
        {
            var bindingBytes = TransformBinding(raw, policy.ReportDataHash);
            var keys = isolation == "sevsnpvm" ? new[] { "x-ms-sevsnpvm-reportdata" } : new[] { "tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata" };
            var claim = FirstString(teeClaims, keys);
            if (claim == null) return HardwareResult.Fail("token carries no report-data claim to bind the PCA challenge");
            var got = AttestUtil.DecodeClaimBytes(claim);
            if (got == null) return HardwareResult.Fail("report-data claim is not decodable (hex/base64)");
            if (!AttestUtil.TimingSafeEq(got, bindingBytes)) return HardwareResult.Fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        }
        return isolation == "sevsnpvm" ? SevSnpResult(teeClaims) : TdxResult(teeClaims);
    }

    HardwareResult SevSnpResult(JD tee)
    {
        if (!policy.HasSev) return HardwareResult.Fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)");
        var measurement = FirstString(tee, "x-ms-sevsnpvm-launchmeasurement");
        if (measurement == null) return HardwareResult.Fail("sevsnpvm token carries no launch-measurement claim");
        var mHex = measurement.ToLowerInvariant();
        if (!policy.SevSnp.Contains(mHex)) return HardwareResult.Fail("SEV-SNP launch measurement not in policy allowlist");
        if (tee.GetValueOrDefault("x-ms-sevsnpvm-is-debuggable") is true && !policy.AllowDebug) return HardwareResult.Fail("SEV-SNP guest is debuggable (no confidentiality)");
        var hostData = FirstString(tee, "x-ms-sevsnpvm-hostdata");
        if (policy.SevHost.Count > 0 && (hostData == null || !policy.SevHost.Contains(hostData.ToLowerInvariant()))) return HardwareResult.Fail("SEV-SNP host-data not in policy allowlist");
        var reported = new Dictionary<string, string>();
        foreach (var (name, claim, hostKey) in TcbClaims)
        {
            var fo = AttestUtil.AsFinite(tee.GetValueOrDefault(claim));
            bool isSvn = fo is double fv && fv == Math.Truncate(fv) && fv >= 0;
            double f = fo ?? 0;
            if (isSvn) reported[hostKey] = AttestUtil.JsNumString(f);
            if (!policy.MinTcb.TryGetValue(name, out var floor)) continue;
            if (!isSvn) return HardwareResult.Fail($"SEV-SNP {name} SVN claim '{claim}' is missing or not a non-negative integer (policy requires a minimum)");
            if (f < floor) return HardwareResult.Fail($"SEV-SNP {name} SVN {AttestUtil.JsNumString(f)} is below the policy minimum {AttestUtil.JsNumString(floor)}");
        }
        var host = new Dictionary<string, string> { ["attestation_type"] = "sevsnpvm" };
        foreach (var (k, val) in reported) host[k] = val;
        if (hostData != null) host["host_data"] = hostData.ToLowerInvariant();
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured(mHex, ""), host);
    }

    HardwareResult TdxResult(JD tee)
    {
        if (!policy.HasTdx) return HardwareResult.Fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)");
        var mrtd = FirstString(tee, "tdx_mrtd", "x-ms-tdx-mrtd");
        if (mrtd == null) return HardwareResult.Fail("tdxvm token carries no MRTD claim");
        var mrtdHex = mrtd.ToLowerInvariant();
        if (!policy.Tdx.Contains(mrtdHex)) return HardwareResult.Fail("TDX MRTD not in policy allowlist");
        bool tdDebug = tee.GetValueOrDefault("tdx_td_attributes_debug") is true;
        var dbgstat = tee.GetValueOrDefault("dbgstat") as string;
        if (!policy.AllowDebug && (tdDebug || (dbgstat != null && dbgstat != "disabled"))) return HardwareResult.Fail("TDX guest is debuggable (no confidentiality)");
        var tcbStatus = tee.GetValueOrDefault("attester_tcb_status") as string;
        if (tcbStatus != null)
        {
            var accepted = policy.HasTdxStatuses ? policy.TdxStatuses : new List<string> { "UpToDate", "SWHardeningNeeded" };
            if (!accepted.Contains(tcbStatus)) return HardwareResult.Fail($"TDX platform TCB status '{tcbStatus}' is not accepted by policy");
        }
        var rtmr0 = FirstString(tee, "tdx_rtmr0", "x-ms-tdx-rtmr0");
        if (policy.TdxRtmrs.Count > 0 && (rtmr0 == null || !policy.TdxRtmrs.Contains(rtmr0.ToLowerInvariant()))) return HardwareResult.Fail("TDX RTMR0 not in policy allowlist");
        var host = new Dictionary<string, string> { ["attestation_type"] = "tdxvm" };
        if (!string.IsNullOrEmpty(tcbStatus)) host["tcb_status"] = tcbStatus;
        if (rtmr0 != null) host["rtmr0"] = rtmr0.ToLowerInvariant();
        return new HardwareResult(true, true, null, AttestUtil.NewMeasured(mrtdHex, ""), host);
    }
}
