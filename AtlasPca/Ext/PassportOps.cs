// The agent passport of the reference (passport.ts) over the JSON tree: the content fingerprint and issuing, the match against a grant's agent binding (reasons and their order are the contract), the registry,
// the trust score, the evidence binding, the signed passport (Ed25519, ML-DSA, hybrid) with optional hardware evidence, its verification (a distinct reason and detail for every refusal, never a throw) and the assurance
// label. The typed Passports class remains the integrator-facing verifier; this is the reference's own surface. The legacy unbound-PQ opt-out does not exist here.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A passport registry keyed by id (first-appearance order; a later duplicate id replaces the earlier in place).</summary>
public sealed class PassportIndex
{
    readonly List<D> _list = new();
    readonly Dictionary<string, int> _ix = new(StringComparer.Ordinal);

    internal PassportIndex(object? passports)
    {
        if (passports is not L l) throw new InvalidOperationException("passports is not iterable");
        foreach (var po in l)
        {
            var p = po as D ?? throw new InvalidOperationException("Cannot read properties of " + (po == null ? "null" : "a non-object") + " (reading 'id')");
            var id = p.GetValueOrDefault("id") as string ?? JsJson.ToJsString(p.GetValueOrDefault("id"));
            if (_ix.TryGetValue(id, out var i)) _list[i] = p;
            else { _ix[id] = _list.Count; _list.Add(p); }
        }
    }

    public D? Get(string id) => _ix.TryGetValue(id, out var i) ? _list[i] : null;
    public bool Has(string id) => _ix.ContainsKey(id);
    public List<D> All() => new(_list);
}

public static class PassportOps
{
    public const string SigDomain = "atlas-pca/passport-sig/v1\0";
    public const int Version = 1;
    public const long DefaultEvidenceAgeMs = 24L * 3600_000;
    const double MaxSkewMs = 60_000;

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["PASSPORT_SIG_DOMAIN"] = SigDomain, ["PASSPORT_VERSION"] = IntentJs.OfLong(Version), ["DEFAULT_PASSPORT_EVIDENCE_AGE_MS"] = IntentJs.OfLong(DefaultEvidenceAgeMs) };

    static object Undef => AttestationSoft.Undef;
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    static string Js(object? x) => AttestationSoft.Js(x);
    static bool Truthy(object? x) => AttestationSoft.Truthy(x);
    static bool Seq(object? a, object? b) => AttestationSoft.Seq(a, b);
    static bool Safe(object? x) => IntentJs.IsSafeInteger(x);

    static object? Need(D p, string k) => p.TryGetValue(k, out var v) ? v : throw new InvalidOperationException("canonicalize: unsupported type undefined");

    /// <summary>The content address of the identity fields: the strict hash of <c>{d, model_id, weights_digest, system_prompt_digest, tool_manifest_digest, runtime_measurement, operator, hardware_rooted}</c>
    /// (the optional digests count as null when absent). Throws on a null passport and on a missing model_id, operator or hardware_rooted.</summary>
    public static string PassportFingerprint(object? passport)
    {
        if (passport is not D p) throw new InvalidOperationException("Cannot read properties of " + (passport == null ? "null" : "a non-object") + " (reading 'model_id')");
        object? Opt(string k) => p.GetValueOrDefault(k);
        return Pca.HashCanonical(new D
        {
            ["d"] = "atlas-pca/passport/v1", ["model_id"] = Need(p, "model_id"), ["weights_digest"] = Opt("weights_digest"), ["system_prompt_digest"] = Opt("system_prompt_digest"),
            ["tool_manifest_digest"] = Opt("tool_manifest_digest"), ["runtime_measurement"] = Opt("runtime_measurement"), ["operator"] = Need(p, "operator"), ["hardware_rooted"] = Need(p, "hardware_rooted"),
        });
    }

    /// <summary>The identity plus its fingerprint as <c>id</c>.</summary>
    public static D IssuePassport(object? identity)
    {
        var id = PassportFingerprint(identity);
        return new D((D)identity!) { ["id"] = id };
    }

    /// <summary>The binding a hardware quote must carry: <c>{holderPub: subject, grantRef: "passport:" + id, epoch: 0, nonce}</c>.</summary>
    public static D PassportEvidenceBinding(object? passportId, object? subject, object? nonce) => new() { ["holderPub"] = subject, ["grantRef"] = "passport:" + (ReferenceEquals(passportId, Undef) ? "undefined" : JsX.Str(passportId)), ["epoch"] = IntentJs.OfLong(0), ["nonce"] = nonce };

    static bool Includes(object? list, object? v) => list is L l && l.Any(e => Seq(e, v));

    /// <summary>Whether the passport satisfies a grant's agent binding: <c>{ok, reasons}</c> (the reason texts and their order are exact). A pinned value the passport lacks, an unmet hardware demand and a malformed
    /// <c>min_measurement</c> fail closed. Throws on a null passport or binding.</summary>
    public static D MatchesBinding(object? passport, object? binding)
    {
        if (binding is not D b) throw new InvalidOperationException("Cannot read properties of " + (binding == null ? "null" : "a non-object") + " (reading 'model_allowlist')");
        if (passport is not D p) throw new InvalidOperationException("Cannot read properties of " + (passport == null ? "null" : "a non-object") + " (reading 'weights_digest')");
        var reasons = new L();
        void Need(string listKey, string valueKey, string label)
        {
            if (b.GetValueOrDefault(listKey) is not L { Count: > 0 } list) return;
            var value = G(p, valueKey);
            if (ReferenceEquals(value, Undef)) reasons.Add($"{label} required by binding but absent from passport");
            else if (!Includes(list, value)) reasons.Add($"{label} '{Js(value)}' not in allowlist");
        }
        if (b.GetValueOrDefault("model_allowlist") is L { Count: > 0 } ma && !Includes(ma, G(p, "model_id"))) reasons.Add($"model_id '{Js(G(p, "model_id"))}' not in allowlist");
        Need("weights_allowlist", "weights_digest", "weights_digest");
        Need("system_prompt_allowlist", "system_prompt_digest", "system_prompt_digest");
        Need("tool_manifest_allowlist", "tool_manifest_digest", "tool_manifest_digest");
        if (b.TryGetValue("operator", out var op) && !Seq(G(p, "operator"), op)) reasons.Add($"operator '{Js(G(p, "operator"))}' != required '{Js(op)}'");
        if (Truthy(b.GetValueOrDefault("require_hardware")) && !Truthy(p.GetValueOrDefault("hardware_rooted"))) reasons.Add("binding requires a hardware-rooted attestation");
        if (Truthy(b.GetValueOrDefault("require_measured_weights")) && !Truthy(p.GetValueOrDefault("weights_measured"))) reasons.Add("binding requires hardware-measured weights");
        if (b.TryGetValue("min_measurement", out var mm))
        {
            if (mm is string want)
            {
                if (!Seq(G(p, "runtime_measurement"), want)) reasons.Add("runtime_measurement does not equal the pinned measurement");
            }
            else
            {
                var bound = mm is D md && md.Count == 1 ? G(md, "svn") : Undef;
                if (!Safe(bound) || IntentJs.NumOf(bound)!.Value < 0 || IntentJs.IsNegZero(IntentJs.NumOf(bound)!.Value))
                    reasons.Add("min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)");
                else
                {
                    var rm = G(p, "runtime_measurement");
                    double svn = rm is string s && Regex.IsMatch(s, @"\A(?:0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant) ? double.Parse(s, System.Globalization.CultureInfo.InvariantCulture) : double.NaN;
                    if (!(double.IsFinite(svn) && svn <= IntentJs.MaxSafe) || svn < IntentJs.NumOf(bound)!.Value) reasons.Add($"runtime SVN {Js(rm)} < required {JsJson.ToJsString(bound)}");
                }
            }
        }
        return new D { ["ok"] = reasons.Count == 0, ["reasons"] = reasons };
    }

    /// <summary>A registry over the passports (see <see cref="PassportIndex"/>).</summary>
    public static PassportIndex BuildRegistry(object? passports) => new(passports);

    /// <summary>A coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation): hardware rooted 0.4, a weights digest 0.1 (0.2 when measured), a prompt digest 0.1, a tool
    /// manifest digest 0.1, a known operator 0.2.</summary>
    public static double TrustScore(object? passport, object? opts = null)
    {
        if (passport is not D p) throw new InvalidOperationException("Cannot read properties of " + (passport == null ? "null" : "a non-object") + " (reading 'hardware_rooted')");
        double s = 0;
        if (Truthy(p.GetValueOrDefault("hardware_rooted"))) s += 0.4;
        if (Truthy(p.GetValueOrDefault("weights_digest"))) s += Truthy(p.GetValueOrDefault("weights_measured")) ? 0.2 : 0.1;
        if (Truthy(p.GetValueOrDefault("system_prompt_digest"))) s += 0.1;
        if (Truthy(p.GetValueOrDefault("tool_manifest_digest"))) s += 0.1;
        var knownOps = G(opts, "knownOperators");
        // Array.includes (strict equality) on a list, String.includes (substring of the text) on a string
        if ((knownOps is L known && Includes(known, G(p, "operator"))) || (knownOps is string knownText && knownText.Contains(ReferenceEquals(G(p, "operator"), Undef) ? "undefined" : JsX.Str(G(p, "operator")), StringComparison.Ordinal))) s += 0.2;
        return Math.Max(0, Math.Min(1, s));
    }

    static byte[] Message(D body) => IntentJs.Message(SigDomain, body);

    /// <summary>A signed passport: <c>{typ, ver, passport, iss, sub, iat, nbf, exp, evidence?, alg?, pq_pk?, sig, pq_sig?}</c>. The passport id must be the fingerprint of its identity (use <see cref="IssuePassport"/>) and a
    /// hardware-rooted passport needs <paramref name="evidence"/> <c>{document, at?}</c> (<c>at</c> defaults to <c>iat</c>). <c>iat</c> defaults to the passport's <c>issued_at</c> and <c>nbf</c> to <c>iat</c>; all times must be safe
    /// integers with <c>exp &gt; nbf</c>. Throws on any violation.</summary>
    public static D SignPassport(D passport, byte[] issuerSecret, object? subject, object? iat, object? nbf, object? exp, D? evidence = null, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (!Equals(passport.GetValueOrDefault("id"), PassportFingerprint(passport))) throw new InvalidOperationException("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)");
        if (Truthy(passport.GetValueOrDefault("hardware_rooted")) && evidence == null) throw new InvalidOperationException("signPassport: hardware_rooted requires attestation evidence (fail closed)");
        if (evidence != null && evidence.TryGetValue("at", out var at0) && !Safe(at0)) throw new ArgumentException("signPassport: evidence.at must be a safe integer");
        if (IntentJs.SuiteOf(alg, alg != null) is not { } resolved) throw new InvalidOperationException($"signPassport: unknown signature alg '{alg}'");
        var iatV = iat ?? passport.GetValueOrDefault("issued_at");
        var nbfV = nbf ?? iatV;
        D? ev = null;
        if (evidence != null) { ev = new D(evidence); if (!ev.TryGetValue("at", out var a1) || a1 == null) ev["at"] = iatV; }
        if (!(Safe(iatV) && Safe(nbfV) && Safe(exp)) || !(IntentJs.NumOf(exp)!.Value > IntentJs.NumOf(nbfV)!.Value)) throw new ArgumentException("signPassport: iat/nbf/exp must be safe integers with exp > nbf");
        using var key = EdKey.FromSeed(issuerSecret);
        var body = new D { ["typ"] = "atlas-pca/passport", ["ver"] = IntentJs.OfLong(Version), ["passport"] = new D(passport), ["iss"] = key.Id };
        if (subject != null) body["sub"] = subject;
        body["iat"] = iatV; body["nbf"] = nbfV; body["exp"] = exp;
        if (ev != null) body["evidence"] = ev;
        body = IntentJs.BindSuiteFields(body, alg, alg != null, PqSuites.SuitePqPublicKey(alg, keys), PqSuites.SuitePqPublicKey(alg, keys) != null);
        var fields = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(issuerSecret, keys), Message(body));
        var signed = new D(body) { ["sig"] = fields.Sig };
        if (fields.PqSig != null) signed["pq_sig"] = fields.PqSig;
        _ = resolved;
        return signed;
    }

    static D Bad(string reason, object? detail = null)
    {
        var o = new D { ["ok"] = false, ["reason"] = reason };
        if (Truthy(detail) && !ReferenceEquals(detail, Undef)) o["detail"] = detail;
        return o;
    }

    static bool IsStr(object? x) => x is string { Length: > 0 };

    /// <summary>Verify a signed passport: <c>{ok: true, passport, iss, sub, exp, hardware_verified}</c> or <c>{ok: false, reason, detail?}</c> (malformed, unsupported_version, unsupported_suite, unknown_issuer,
    /// bad_signature, id_mismatch, not_yet_valid, expired, subject_mismatch, revoked, revocation_unavailable, hardware_evidence_missing, hardware_evidence_stale, hardware_verifier_missing,
    /// hardware_attestation_failed, hardware_identity_mismatch). Options: <c>trustedIssuers</c>, <c>now</c>, <c>clockSkewMs</c> (capped at 60 s), <c>subject</c>, <c>maxEvidenceAgeMs</c> (default 24 h), <c>pqPins</c>,
    /// <c>revocation</c> (Func&lt;D, object?&gt;: {id, iss, sub} to revoked; absent or throwing refuses) and <c>attestationVerifier</c> (an <see cref="IHardwareAttestation"/>). Never throws.</summary>
    public static D VerifyPassport(object? sp, D o)
    {
        try
        {
            if (sp is not D s || s.GetValueOrDefault("typ") is not "atlas-pca/passport" || s.GetValueOrDefault("passport") == null) return Bad("malformed");
            if (!(s.TryGetValue("ver", out var ver) && IntentJs.NumOf(ver) == Version)) return Bad("unsupported_version", Js(G(s, "ver")));
            if (s.TryGetValue("alg", out var alg) && IntentJs.SuiteError(alg, true) != null) return Bad("unsupported_suite", Js(alg));
            var p = s["passport"] as D ?? new D();
            if (!IsStr(s.GetValueOrDefault("iss")) || !IsStr(s.GetValueOrDefault("sub")) || !IsStr(s.GetValueOrDefault("sig")) || !IsStr(p.GetValueOrDefault("id")) || !IsStr(p.GetValueOrDefault("model_id"))
                || !IsStr(p.GetValueOrDefault("operator")) || p.GetValueOrDefault("hardware_rooted") is not bool hw) return Bad("malformed");
            string iss = (string)s["iss"]!, sub = (string)s["sub"]!, id = (string)p["id"]!;
            var now = o.GetValueOrDefault("now");
            if (!(Safe(s.GetValueOrDefault("iat")) && Safe(s.GetValueOrDefault("nbf")) && Safe(s.GetValueOrDefault("exp")) && Safe(now)) || !(IntentJs.NumOf(s["exp"])!.Value > IntentJs.NumOf(s["nbf"])!.Value)) return Bad("malformed", "times");
            double nowD = IntentJs.NumOf(now)!.Value, nbf = IntentJs.NumOf(s["nbf"])!.Value, exp = IntentJs.NumOf(s["exp"])!.Value;
            if (!(o.GetValueOrDefault("trustedIssuers") is L ti && ti.Any(t => Seq(t, iss)))) return Bad("unknown_issuer");
            var body = s.Where(e => e.Key is not ("sig" or "pq_sig")).ToDictionary(e => e.Key, e => e.Value);
            var pins = o.GetValueOrDefault("pqPins") is D pd ? pd.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;
            if (!IntentJs.VerifyPinnedSuite(s.GetValueOrDefault("alg"), s.ContainsKey("alg"), iss, s.GetValueOrDefault("pq_pk"), Message(body), s["sig"], s.GetValueOrDefault("pq_sig"), pins)) return Bad("bad_signature");
            if (id != PassportFingerprint(p)) return Bad("id_mismatch");
            double skew = Math.Min(Math.Max(o.GetValueOrDefault("clockSkewMs") is { } cs ? JsJson.ToJsNumber(cs) : 0, 0), MaxSkewMs);
            if (!(nowD + skew >= nbf)) return Bad("not_yet_valid");
            if (!(nowD - skew < exp)) return Bad("expired");
            if (o.TryGetValue("subject", out var subj) && !Seq(subj, sub)) return Bad("subject_mismatch");
            if (o.GetValueOrDefault("revocation") is not Func<D, object?> revocation) return Bad("revocation_unavailable", "no revocation source");
            bool revoked;
            try { revoked = revocation(new D { ["id"] = id, ["iss"] = iss, ["sub"] = sub }) is true; }
            catch (Exception) { return Bad("revocation_unavailable"); }
            if (revoked) return Bad("revoked");
            if (hw)
            {
                var ev = s.GetValueOrDefault("evidence") as D ?? new D();
                var doc = ev.GetValueOrDefault("document") as D;
                if (!IsStr(doc?.GetValueOrDefault("nonce"))) return Bad("hardware_evidence_missing");
                var at = ev.GetValueOrDefault("at");
                if (!Safe(at)) return Bad("hardware_evidence_missing", "evidence.at");
                double atD = IntentJs.NumOf(at)!.Value;
                var maxAgeO = o.GetValueOrDefault("maxEvidenceAgeMs");
                double maxAge = maxAgeO == null ? DefaultEvidenceAgeMs : IntentJs.NumOf(maxAgeO) ?? double.NaN;
                if (!double.IsFinite(maxAge) || maxAge < 0 || !(nowD - atD <= maxAge) || !(atD - nowD <= skew)) return Bad("hardware_evidence_stale");
                if (o.GetValueOrDefault("attestationVerifier") is not IHardwareAttestation verifier) return Bad("hardware_verifier_missing");
                object? r;
                try
                {
                    var expected = PassportEvidenceBinding(id, sub, (string)doc!["nonce"]!);
                    expected["nonceIssuedAt"] = now;
                    r = verifier.Verify(new D { ["document"] = doc, ["ctx"] = new D(), ["nowMs"] = now, ["expected"] = expected });
                }
                catch (Exception e) { return Bad("hardware_attestation_failed", string.IsNullOrEmpty(e.Message) ? "error" : e.Message); }
                if (r is not D rd || rd.GetValueOrDefault("ok") is not true || rd.GetValueOrDefault("bound") is not true) return Bad("hardware_attestation_failed", r is D rr ? rr.GetValueOrDefault("reason") : null);
                if (!IdentityMatches(p, rd.GetValueOrDefault("measured"))) return Bad("hardware_identity_mismatch");
            }
            return new D { ["ok"] = true, ["passport"] = p, ["iss"] = iss, ["sub"] = sub, ["exp"] = s["exp"], ["hardware_verified"] = hw };
        }
        catch (Exception e) { return Bad("malformed", string.IsNullOrEmpty(e.Message) ? "error" : e.Message); }
    }

    static bool IdentityMatches(D p, object? measured)
    {
        if (measured is not D m) return false;
        if (!Seq(G(m, "model_id"), G(p, "model_id")) || !Seq(G(m, "operator"), G(p, "operator"))) return false;
        foreach (var k in new[] { "weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest" })
            if (p.ContainsKey(k) && !Seq(G(m, k), p[k])) return false;
        return !(p.GetValueOrDefault("weights_measured") is true && m.GetValueOrDefault("weights_measured") is not true);
    }

    /// <summary>The assurance label of a verified passport: <c>{level: "software"}</c> unless its hardware evidence verified, else the verifier's label (level <c>unknown</c> when it has none), with its vendor.</summary>
    public static D PassportAssurance(D verdict, object? verifier = null)
    {
        if (!Truthy(verdict.GetValueOrDefault("hardware_verified"))) return new D { ["level"] = "software" };
        var l = AssuranceLabels.Of(verifier);
        var o = new D { ["level"] = l?.Level ?? "unknown" };
        if (!string.IsNullOrEmpty(l?.Vendor)) o["vendor"] = l!.Vendor;
        return o;
    }
}
