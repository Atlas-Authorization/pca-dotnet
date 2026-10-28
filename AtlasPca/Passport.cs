// Signed agent passport verification (wire level), the native counterpart of verifyPassport in @atlasauth/pca: same reason
// codes and check order (packages/pca/src/passport.ts); the reason text is not part of the contract. Every signature suite this
// SDK verifies for PCActns is accepted, the post-quantum ones only under a PQ key pinned for the issuer (PqPins); a suite it
// does not implement is refused with unsupported_suite.
// Hardware evidence: the age rule, the binding handed to the verifier and the identity comparison are enforced here. The
// verifier is the integrator's Attest or, when none is given, the built-in vendor verifier of DefaultHardware (an integrator
// Attest always wins). With neither, a hardware_rooted passport that passes every other check is refused with
// hardware_verifier_missing (fail closed, never a software pass).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>What the quote's bound value must equal: holder = the subject key, grant = <c>passport:&lt;id&gt;</c>, epoch 0, nonce = the evidence nonce.</summary>
public sealed record PassportBinding(string HolderPub, string GrantRef, long Epoch, string Nonce);

/// <summary>A hardware verifier's answer. <see cref="Measured"/> holds model_id, operator, weights_digest, weights_measured,
/// runtime_measurement, system_prompt_digest and tool_manifest_digest as the hardware measured them.</summary>
public sealed record PassportAttestation(bool Ok, bool Bound, JD? Measured);

/// <summary>The built-in hardware verifier of <see cref="Passports.Verify"/>, used when no integrator <c>Attest</c> is given.
/// <see cref="Evidence"/> returns the vendor evidence object for the passport's evidence document (null: none); when it is null the
/// passport's evidence document itself is the vendor evidence.</summary>
public sealed record DefaultHardware(IVendorVerifier Verifier, Func<JD, JD?>? Evidence = null);

public sealed class PassportOptions
{
    /// <summary>Issuer keys (b64u Ed25519) you trust. Empty trusts nobody (fail closed).</summary>
    public IReadOnlyList<string> TrustedIssuers { get; set; } = Array.Empty<string>();
    public long NowMs { get; set; }
    /// <summary>Tolerance on nbf / exp, ms (default 0, capped at 60000).</summary>
    public long? ClockSkewMs { get; set; }
    /// <summary>Oldest acceptable hardware evidence, ms (default 24 h).</summary>
    public long? MaxEvidenceAgeMs { get; set; }
    /// <summary>When set, the passport's <c>sub</c> must equal it.</summary>
    public string? Subject { get; set; }
    /// <summary>Issuer key -&gt; the PQ public key pinned for it (required for every non-Ed25519 suite).</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>Verifies hardware evidence (a vendor verifier). Null: none configured (<see cref="DefaultHardware"/> is then used).</summary>
    public Func<JD, PassportBinding, PassportAttestation>? Attest { get; set; }
    public DefaultHardware? DefaultHardware { get; set; }
    /// <summary><c>(id, iss, sub) -&gt; revoked?</c>; null is no revocation source (revocation_unavailable); a throw denies.</summary>
    public Func<string, string, string, bool>? Revoked { get; set; }
}

/// <summary>The outcome of <see cref="Passports.Verify"/>: <c>Reason</c> is null when the passport verified.</summary>
public sealed record PassportVerdict(string? Reason, JD? Passport = null, string? Iss = null, string? Sub = null, long Exp = 0, bool HardwareVerified = false)
{
    public bool Ok => Reason == null;
}

public static class Passports
{
    public const string SigDomain = "atlas-pca/passport-sig/v1\0";
    public const long DefaultEvidenceAgeMs = 24L * 3600_000;
    public const long MaxSkewMs = 60_000;

    static string? Str(object? v) => v is string s && s.Length > 0 ? s : null;

    static bool Safe(object? v) => IntentJs.IsSafeInteger(v);

    /// <summary>The content fingerprint of the identity fields (the passport id): <c>passportFingerprint</c>.</summary>
    public static string Fingerprint(JD p)
    {
        var fp = new JD { ["d"] = "atlas-pca/passport/v1", ["operator"] = IntentJs.Get(p, "operator"), ["hardware_rooted"] = IntentJs.Get(p, "hardware_rooted") };
        foreach (var k in new[] { "model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement" })
            fp[k] = p.TryGetValue(k, out var v) ? v : null;
        return Pca.HashCanonical(fp);
    }

    /// <summary>Verify a signed passport. Fails closed with a distinct reason; never throws.</summary>
    public static PassportVerdict Verify(object? sp, PassportOptions o)
    {
        static PassportVerdict Bad(string r) => new(r);
        try
        {
            if (sp is not JD s || s.GetValueOrDefault("typ") is not "atlas-pca/passport" || s.GetValueOrDefault("passport") is not JD p) return Bad("malformed");
            if (!(s.TryGetValue("ver", out var ver) && Safe(ver) && IntentJs.NumOf(ver) == 1)) return Bad("unsupported_version");
            bool algPresent = s.TryGetValue("alg", out var alg);
            if (algPresent && IntentJs.SuiteError(alg, true) != null) return Bad("unsupported_suite");
            string? iss = Str(s.GetValueOrDefault("iss")), sub = Str(s.GetValueOrDefault("sub"));
            string? id = Str(p.GetValueOrDefault("id"));
            if (iss == null || sub == null || Str(s.GetValueOrDefault("sig")) == null || id == null
                || Str(p.GetValueOrDefault("model_id")) == null || Str(p.GetValueOrDefault("operator")) == null || p.GetValueOrDefault("hardware_rooted") is not bool hw) return Bad("malformed");
            if (!(Safe(s.GetValueOrDefault("nbf")) && Safe(s.GetValueOrDefault("exp")) && Safe(s.GetValueOrDefault("iat")))) return Bad("malformed");
            long nbf = IntentJs.Lng(s["nbf"]), exp = IntentJs.Lng(s["exp"]);
            if (exp <= nbf || Math.Abs(o.NowMs) > Pca.MaxSafeInt) return Bad("malformed");
            if (!o.TrustedIssuers.Contains(iss)) return Bad("unknown_issuer");
            var body = s.Where(kv => kv.Key is not ("sig" or "pq_sig")).ToDictionary(kv => kv.Key, kv => kv.Value);
            byte[] msg;
            try { msg = IntentJs.Message(SigDomain, body); }
            catch (Exception) { return Bad("malformed"); }
            if (!IntentJs.VerifyPinnedSuite(alg, algPresent, iss, s.GetValueOrDefault("pq_pk"), msg, s["sig"], s.GetValueOrDefault("pq_sig"), o.PqPins)) return Bad("bad_signature");
            string want;
            try { want = Fingerprint(p); } catch (Exception) { return Bad("id_mismatch"); }
            if (want != id) return Bad("id_mismatch");
            long skew = o.ClockSkewMs is long c ? Math.Min(Math.Max(c, 0), MaxSkewMs) : 0;
            if (o.NowMs + skew < nbf) return Bad("not_yet_valid");
            if (o.NowMs - skew >= exp) return Bad("expired");
            if (o.Subject != null && o.Subject != sub) return Bad("subject_mismatch");
            if (o.Revoked == null) return Bad("revocation_unavailable");
            bool revoked;
            try { revoked = o.Revoked(id, iss, sub); }
            catch (Exception) { return Bad("revocation_unavailable"); }
            if (revoked) return Bad("revoked");
            if (hw)
            {
                var ev = s.GetValueOrDefault("evidence") as JD;
                var doc = ev?.GetValueOrDefault("document") as JD;
                if (doc == null || Str(doc.GetValueOrDefault("nonce")) is not { } nonce) return Bad("hardware_evidence_missing");
                if (!Safe(ev!.GetValueOrDefault("at"))) return Bad("hardware_evidence_missing");
                long at = IntentJs.Lng(ev["at"]);
                long maxAge = o.MaxEvidenceAgeMs ?? DefaultEvidenceAgeMs;
                if (maxAge < 0 || o.NowMs - at > maxAge || at - o.NowMs > skew) return Bad("hardware_evidence_stale");
                var attest = o.Attest;
                if (attest == null && o.DefaultHardware is { } dh)
                    attest = (d, b) =>
                    {
                        var evidence = dh.Evidence != null ? dh.Evidence(d) : d;
                        var r = dh.Verifier.Verify(evidence, new AttestationBinding(b.HolderPub, b.GrantRef, b.Epoch, b.Nonce), o.NowMs);
                        return new PassportAttestation(r.Ok, r.Bound, r.Measured);
                    };
                if (attest == null) return Bad("hardware_verifier_missing");
                PassportAttestation r2;
                try { r2 = attest(doc, new PassportBinding(sub, "passport:" + id, 0, nonce)); }
                catch (Exception) { return Bad("hardware_attestation_failed"); }
                if (r2 == null || !r2.Ok || !r2.Bound) return Bad("hardware_attestation_failed");
                if (!IdentityMatches(p, r2.Measured)) return Bad("hardware_identity_mismatch");
            }
            return new PassportVerdict(null, p, iss, sub, exp, hw);
        }
        catch (Exception) { return Bad("malformed"); }
    }

    /// <summary>The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
    /// measurement when the passport states them; measured weights when it claims them).</summary>
    static bool IdentityMatches(JD p, JD? m)
    {
        if (m == null) return false;
        bool Eq(string k) => p.GetValueOrDefault(k) is string a && m.GetValueOrDefault(k) is string b && a == b;
        if (!Eq("model_id") || !Eq("operator")) return false;
        foreach (var k in new[] { "weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest" })
            if (p.ContainsKey(k) && !Eq(k)) return false;
        if (p.GetValueOrDefault("weights_measured") is true && m.GetValueOrDefault("weights_measured") is not true) return false;
        return true;
    }
}
