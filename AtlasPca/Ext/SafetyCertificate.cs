// The safety certificate of the reference (safety-certificate.ts): a guardian-signed statement that the risk parameters of a grant bound the total risk of
// autonomous actions between two human co-signs by B_max / kappa. The certificate states an arithmetic consequence of the signed parameters, never that
// an agent is safe; a verifier recomputes the bound and refuses any certificate whose stated bound differs. Values are the JSON tree; the verdict is total.
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class SafetyCertificate
{
    public const string Domain = "atlas-pca/safety-cert/v1\0";
    public const int Version = 1;
    public const string Scope = "risk-budget-bound";
    public const int MaxChecks = 64;
    const int MaxCheckId = 64, MaxEvidenceUrl = 2048;

    static readonly object Undef = new();
    static bool Has(object? v) => !ReferenceEquals(v, Undef);

    static object? Prop(object? o, string k)
    {
        if (o == null || !Has(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static object? PropOpt(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;

    static object NumOut(double d) => double.IsFinite(d) ? Facade.JsNumber(d) : d;

    static bool IsNumber(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d);

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["MAX_SAFETY_CHECKS"] = IntentJs.OfLong(MaxChecks), ["SAFETY_CERT_DOMAIN"] = Domain, ["SAFETY_CERT_SCOPE"] = Scope, ["SAFETY_CERT_VERSION"] = IntentJs.OfLong(Version) };

    /// <summary>B_max / kappa of <c>{bMax, kappa}</c> (0 when kappa is not positive); a value that is not a number is coerced as JavaScript does.</summary>
    public static double Bound(object? p)
    {
        var bm = Prop(p, "bMax");
        var kp = Prop(p, "kappa");
        double bMax = Has(bm) ? JsJson.ToJsNumber(bm) : double.NaN, kappa = Has(kp) ? JsJson.ToJsNumber(kp) : double.NaN;
        return kappa > 0 ? Math.Max(0, bMax) / kappa : 0;
    }

    /// <summary>The fixed wording of the claim: an arithmetic consequence of the signed parameters, not a claim that the agent or the system is safe.</summary>
    public static string Statement(object? bound) =>
        "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ " +
        JsJson.ToJsString(bound) + " (= B_max / κ). This is not a claim that the agent or the system is safe.";

    // ---- checks

    static bool IsObject(object? c) => c is D or L;

    /// <summary>Why a list of checks is refused, or null: at most 64, unique ids of 1..64 characters, a known status, a safe-integer time and an evidence link (a lowercase
    /// SHA-256 or a plain https URL of at most 2048 characters without credentials).</summary>
    public static string? ValidateChecks(object? checks)
    {
        if (checks is not L list) return "checks must be an array";
        if (list.Count > MaxChecks) return $"more than {MaxChecks} checks";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in list)
        {
            if (!IsObject(c)) return "check is not an object";
            if (PropOpt(c, "id") is not string id || id.Length == 0 || id.Length > MaxCheckId) return "check id must be a 1..64 char string";
            if (!seen.Add(id)) return $"duplicate check id '{id}'";
            if (PropOpt(c, "status") is not ("passed" or "failed" or "not_run")) return $"check '{id}' has an invalid status";
            if (!IntentJs.IsNonNeg(PropOpt(c, "at"))) return $"check '{id}' has an invalid time";
            var e = PropOpt(c, "evidence");
            if (!IsObject(e) || PropOpt(e, "ref") is not string r) return $"check '{id}' has no evidence link";
            switch (PropOpt(e, "kind"))
            {
                case "sha256":
                    if (r.Length != 64 || !r.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f')) return $"check '{id}' evidence digest is not 64 lowercase hex";
                    break;
                case "url":
                    if (r.Length > MaxEvidenceUrl || !PlainHttps(r)) return $"check '{id}' evidence URL must be a plain https URL";
                    break;
                default: return $"check '{id}' has an invalid evidence kind";
            }
        }
        return null;
    }

    // a plain https URL as the URL Standard parses it (the reference platform's new URL): scheme https, no credentials
    static bool PlainHttps(string s) => WhatwgPlainUrl.IsPlainHttps(s);

    // ---- the certificate

    static D ClaimOf(object? c)
    {
        if (c == null) throw new InvalidOperationException("Cannot destructure null");
        var claim = c is D d ? new D(d) : new D();
        claim.Remove("sig");
        claim.Remove("pq_sig");
        return claim;
    }

    /// <summary>The bytes the guardian signs: <c>"atlas-pca/safety-cert/v1\0" || canonical(claim)</c> (the certificate without <c>sig</c> and <c>pq_sig</c>; lenient canonical form).
    /// Throws on a value the canonical form refuses.</summary>
    public static byte[] Message(object? certOrClaim) =>
        [.. Encoding.UTF8.GetBytes(Domain), .. Encoding.UTF8.GetBytes(JsCanon.Lenient(ClaimOf(certOrClaim)) ?? throw new InvalidOperationException("canonicalize: non-finite number"))];

    /// <summary>Issue a certificate for <paramref name="policy"/> (a risk policy object). <paramref name="alg"/> null is ed25519; another suite needs its PQ key material in
    /// <paramref name="suiteKeys"/> and binds <c>alg</c> and <c>pq_pk</c> into the signed claim. <paramref name="checks"/>, <paramref name="grantRef"/> and
    /// <paramref name="instance"/> null are absent. Throws on a malformed policy, malformed checks, an unknown alg or a value the canonical form refuses.</summary>
    public static D Issue(object? policy, byte[] guardianSecret, string? grantRef, string? instance, object? checks, object? issuedAt, string? alg = null, SuiteSecretKeys? suiteKeys = null)
    {
        if (Pca.ValidateRiskPolicy(policy) is { } bad) throw new ArgumentException("issueSafetyCertificate: " + bad);
        if (alg != null && !Pq.RegisteredSuites.Contains(alg)) throw new ArgumentException($"issueSafetyCertificate: unknown signature alg '{alg}'");
        if (checks != null && ValidateChecks(checks) is { } badChecks) throw new ArgumentException("issueSafetyCertificate: " + badChecks);
        var p = (D)policy!;
        var bound = Bound(p);
        var pqPk = PqSuites.SuitePqPublicKey(alg, suiteKeys);
        var claim = new D { ["v"] = IntentJs.OfLong(Version), ["statement"] = Statement(NumOut(bound)), ["scope"] = Scope };
        if (checks != null)
            claim["checks"] = ((L)checks).Select(c => (object?)new D
            {
                ["id"] = Prop(c, "id"), ["status"] = Prop(c, "status"),
                ["evidence"] = new D { ["kind"] = Prop(Prop(c, "evidence"), "kind"), ["ref"] = Prop(Prop(c, "evidence"), "ref") }, ["at"] = Prop(c, "at"),
            }).ToList();
        var weights = new D((D)p["weights"]!);
        claim["params"] = new D
        {
            ["bMax"] = p["bMax"], ["kappa"] = p["kappa"], ["theta1"] = p["theta1"], ["theta2"] = p["theta2"], ["lambda"] = p["lambda"], ["rho"] = p["rho"], ["weights"] = weights,
        };
        claim["bound"] = NumOut(bound);
        claim["blastRadiusPerCheckpoint"] = NumOut(bound);
        if (grantRef != null) claim["grant_ref"] = grantRef;
        if (instance != null) claim["instance"] = instance;
        claim["issued_at"] = issuedAt ?? Facade.JsNumber(AtlasPca.ReplayClock.NowMs());
        var key = EdKey.FromSeed(guardianSecret);
        claim["guardian"] = key.Id;
        claim = IntentJs.BindSuiteFields(claim, alg, alg != null, pqPk, pqPk != null);
        var fields = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(guardianSecret, suiteKeys), Message(claim));
        var cert = new D(claim) { ["sig"] = fields.Sig };
        if (fields.PqSig != null) cert["pq_sig"] = fields.PqSig;
        return cert;
    }

    static D Verdict(bool ok, string? reason = null, double? recomputed = null)
    {
        var d = new D { ["ok"] = ok };
        if (reason != null) d["reason"] = reason;
        if (recomputed is double r) d["recomputedBound"] = NumOut(r);
        return d;
    }

    static IReadOnlyDictionary<string, string>? Pins(object? v) =>
        v is D d ? d.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>Verify a certificate offline: shape, scope, checks, the parameters, the stated bound against the one recomputed from them, the pinned guardian, the signature
    /// (a post-quantum suite only under a pin of the verifier: <c>opts.pqPins</c>; the legacy unbound opt-out does not exist here), the age policy and the required checks.
    /// <paramref name="opts"/>: <c>{guardian?, requireChecks?, maxAgeMs?, now?, pqPins?}</c> (null: none). Never throws.</summary>
    public static D Verify(object? cert, object? opts)
    {
        double? recomputed = null;
        try
        {
            if (cert is not D c || !IntentJs.IsNumber(c.GetValueOrDefault("v")) || IntentJs.NumOf(c["v"]) != Version) return Verdict(false, "malformed certificate");
            if (c.GetValueOrDefault("sig") is not string sig || c.GetValueOrDefault("guardian") is not string guardian) return Verdict(false, "missing guardian/signature");
            if (c.GetValueOrDefault("scope") is not Scope) return Verdict(false, "unknown scope");
            if (c.TryGetValue("checks", out var checks) && ValidateChecks(checks) is { } badChecks) return Verdict(false, "invalid checks: " + badChecks);
            var prm = c.GetValueOrDefault("params");
            if (Pca.ValidateRiskPolicy(prm is D pd ? new D(pd) : new D()) is { } bad) return Verdict(false, "invalid parameters: " + bad);
            recomputed = Bound(prm);
            var stated = c.GetValueOrDefault("bound");
            if (!IsNumber(stated) || IntentJs.NumOf(stated) != recomputed) return Verdict(false, "stated bound does not equal B_max/κ recomputed from the parameters", recomputed);
            if (IntentJs.NumOf(c.GetValueOrDefault("blastRadiusPerCheckpoint")) != recomputed) return Verdict(false, "blastRadiusPerCheckpoint does not equal the recomputed bound", recomputed);
            var pin = PropOpt(opts, "guardian");
            if (Has(pin) && !(pin is string ps && ps == guardian)) return Verdict(false, "guardian key is not the pinned key", recomputed);
            var alg = c.GetValueOrDefault("alg");
            if (c.ContainsKey("alg") && !(alg is string a && Pq.RegisteredSuites.Contains(a))) return Verdict(false, "unknown signature alg", recomputed);
            if (!IntentJs.VerifyPinnedSuite(alg, c.ContainsKey("alg"), guardian, c.GetValueOrDefault("pq_pk"), Message(c), sig, c.GetValueOrDefault("pq_sig"), Pins(PropOpt(opts, "pqPins"))))
                return Verdict(false, "guardian signature does not verify", recomputed);
            var maxAge = PropOpt(opts, "maxAgeMs");
            if (Has(maxAge))
            {
                var nowO = PropOpt(opts, "now");
                var now = !Has(nowO) || nowO == null ? Facade.JsNumber(AtlasPca.ReplayClock.NowMs()) : nowO;
                var issued = c.GetValueOrDefault("issued_at");
                if (!IsNumber(maxAge) || !IsNumber(now) || !IsNumber(issued)) return Verdict(false, "invalid age policy or issue time", recomputed);
                double iss = IntentJs.NumOf(issued)!.Value, nw = IntentJs.NumOf(now)!.Value;
                if (iss > nw) return Verdict(false, "certificate is issued in the future", recomputed);
                if (nw - iss > IntentJs.NumOf(maxAge)!.Value) return Verdict(false, "certificate is older than maxAgeMs", recomputed);
            }
            var require = PropOpt(opts, "requireChecks");
            if (Has(require) && require != null)
            {
                if (require is not L ids) throw new InvalidOperationException("opts.requireChecks is not iterable");
                foreach (var idO in ids)
                {
                    var found = (c.GetValueOrDefault("checks") as L)?.FirstOrDefault(k => Equals(PropOpt(k, "id"), idO));
                    if (found == null) return Verdict(false, $"required check '{JsJson.ToJsString(idO)}' is not present", recomputed);
                    if (PropOpt(found, "status") is not "passed") return Verdict(false, $"required check '{JsJson.ToJsString(idO)}' is {JsJson.ToJsString(PropOpt(found, "status"))}", recomputed);
                }
            }
            return Verdict(true, null, recomputed);
        }
        catch (Exception e) { return Verdict(false, "malformed certificate: " + e.Message); }
    }

    /// <summary>The certificate as canonical JSON text (lenient canonical form).</summary>
    public static string Encode(object? cert) => JsCanon.Lenient(cert) ?? throw new InvalidOperationException("canonicalize: non-finite number");

    /// <summary>A certificate from text, or null: at most 1 MiB, a JSON object with <c>v</c> 1, string <c>sig</c> and <c>guardian</c> and an object <c>params</c>. Nothing is verified.</summary>
    public static D? Decode(object? text)
    {
        try
        {
            if (text is not string s || Encoding.UTF8.GetByteCount(s) > PcaConstants.MaxJsonBytes) return null;
            if (Pca.ParseJson(s) is not D v) return null;
            if (!(IntentJs.NumOf(v.GetValueOrDefault("v")) == Version) || v.GetValueOrDefault("sig") is not string || v.GetValueOrDefault("guardian") is not string) return null;
            return v.GetValueOrDefault("params") is D or L ? v : null;
        }
        catch (Exception) { return null; }
    }

    /// <summary>The evidence row a compliance report carries for a certificate that verifies under <paramref name="opts"/>: <c>{control, guardian, issued_at, bound, checks:
    /// [{id, status, evidence}]}</c> (a SHA-256 reference is shown as <c>sha256:&lt;hex&gt;</c>); null for a certificate that does not verify.</summary>
    public static D? ForCompliance(object? cert, object? opts)
    {
        if (Verify(cert, opts)["ok"] is not true) return null;
        var c = (D)cert!;
        return new D
        {
            ["control"] = Scope, ["guardian"] = c["guardian"], ["issued_at"] = c["issued_at"], ["bound"] = c["bound"],
            ["checks"] = ((c.GetValueOrDefault("checks") as L) ?? new L()).Select(k =>
            {
                var e = Prop(k, "evidence");
                return (object?)new D { ["id"] = Prop(k, "id"), ["status"] = Prop(k, "status"), ["evidence"] = Prop(e, "kind") is "sha256" ? "sha256:" + Prop(e, "ref") : Prop(e, "ref") };
            }).ToList(),
        };
    }
}
