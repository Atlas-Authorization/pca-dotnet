// Entity attestation tokens (RFC 9711) and the RATS (RFC 9334) appraisal: the constants, the channel binding (RA-TLS), the freshness and channel-binding
// gates over verified claims, the appraisal of evidence against endorsements and reference values into a trust tier, the projection of an appraisal into a
// verdict, and the canonical bytes a verdict co-signature covers. Claims, reference values and endorsements are parsed-JSON trees; every gate fails closed.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.AttestEat;

public static class PcaAttestEat
{
    /// <summary>EAT media type as a JWT <c>typ</c> header (RFC 9711 registers <c>application/eat+jwt</c>).</summary>
    public const string EatTyp = "eat+jwt";
    public const string DefaultEatAlg = "EdDSA";
    /// <summary>Default ceiling (ms) on an EAT's age at verification: 5 minutes.</summary>
    public const long DefaultMaxAgeMs = 5 * 60_000;
    /// <summary>Domain separator mixed into a channel id before hashing it into a <c>cnf.tls_exporter</c>.</summary>
    public const string ChannelBindingDomain = "atlas-pca/eat-channel/v1";
    /// <summary>The end (exclusive) of an AMD SEV-SNP attestation report's signed region.</summary>
    public const int AmdSevSnpSignedRegionEnd = 0x2a0;
    /// <summary>The honest label of the AMD hardware root: a classical root, not post-quantum.</summary>
    public const string AmdSevSnpHardwareRootLabel = "amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)";
    public static readonly IReadOnlyList<int> KnownReportVersions = new[] { 2, 3, 5 };
    public const string PqCoSignDomain = "atlas-pca/attest-cosign/v1";
    public const string DefaultPqCoSignSuite = "ml-dsa-65";
    public static readonly IReadOnlyList<string> PqCoSignSuites = new[]
    {
        "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
        "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s",
    };

    /// <summary>The known AMD ARK trust anchors per family, as the SHA-384 (lowercase hex) of each ARK's SubjectPublicKeyInfo.</summary>
    public static IReadOnlyDictionary<string, string> KnownAmdArkSpkiSha384 => new Dictionary<string, string>
    {
        ["milan"] = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        ["genoa"] = "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        ["turin"] = "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    };

    static object N(double d) => Jx.NumOut(d);
    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static bool IsUndef(object? x) => Jx.IsUndef(x);
    static object? P(object? o, string k) => Jx.Prop(o, k);
    static object? Opt(object? o, string k) => Jx.Opt(o, k);
    static bool NonEmptyString(object? x) => x is string s && s.Length > 0;
    static bool IsArr(object? x, out L list) { list = x as L ?? new L(); return x is L; }
    static InvalidOperationException TypeErr(string m) => JsX.TypeError(m);

    /// <summary>Constant-time string equality over the UTF-8 bytes (a non-string argument is a TypeError, as Buffer.from is in the reference).</summary>
    static bool StrEq(object? a, object? b)
    {
        if (a is not string x || b is not string y) throw TypeErr("The first argument must be of type string");
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(x), Encoding.UTF8.GetBytes(y));
    }

    // ---- channel binding (RA-TLS) ----

    /// <summary>The <c>cnf.tls_exporter</c> for a TLS channel id: <c>b64u(sha256(domain || channelId))</c>; plus <c>jkt</c> when a holder-key thumbprint is given.</summary>
    public static D DeriveChannelCnf(object? channelId, object? holderKeyThumbprint = null)
    {
        if (channelId is not string cid || cid.Length == 0) throw new ArgumentException("deriveChannelCnf: channelId is required");
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(ChannelBindingDomain).Concat(Encoding.UTF8.GetBytes(cid)).ToArray());
        var cnf = Obj(("tls_exporter", Pca.B64u(h)));
        if (NonEmptyString(holderKeyThumbprint)) cnf["jkt"] = holderKeyThumbprint;
        return cnf;
    }

    /// <summary>Binds attestation evidence to a TLS channel id and a per-session freshness nonce: <c>{evidence, nonce, cnf}</c>.</summary>
    public static D BindChannel(object? evidence, object? channelId, object? nonce)
    {
        if (!NonEmptyString(nonce)) throw new ArgumentException("bindChannel: a per-session nonce is required for freshness");
        return Obj(("evidence", evidence), ("nonce", nonce), ("cnf", DeriveChannelCnf(channelId)));
    }

    /// <summary>RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url.</summary>
    public static string Ed25519Jkt(string holderPubB64u) =>
        Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + holderPubB64u + "\"}")));

    // ---- freshness + channel binding gates ----

    static D Check(bool ok, string? reason = null) => reason == null ? Obj(("ok", ok)) : Obj(("ok", ok), ("reason", reason));

    /// <summary>ANTI-REPLAY freshness over verified claims: the <c>eat_nonce</c> must equal the server-issued challenge and <c>iat</c> must be within
    /// <c>[now - maxAgeMs, now]</c> (allowing <c>clockSkewMs</c>). Options: <c>expectedNonce</c>, <c>maxAgeMs</c>, <c>now?</c> (epoch ms), <c>clockSkewMs?</c>.</summary>
    public static D VerifyFreshness(object? eat, object? opts, Func<double>? clock = null)
    {
        var nowO = P(opts, "now");
        var now = Jx.Fin(nowO) is double nd ? nd : (clock?.Invoke() ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var skewO = P(opts, "clockSkewMs");
        // A present skew that is not a finite number (NaN, Infinity, a string, null) would disable the age window: refuse it.
        if (!IsUndef(skewO) && Jx.Fin(skewO) == null) return Check(false, "invalid clockSkewMs (must be a finite number)");
        var skew = IsUndef(skewO) ? 0 : Math.Max(0, Jx.Fin(skewO)!.Value);
        if (P(opts, "expectedNonce") is not string expected || expected.Length == 0) return Check(false, "no expected (server-issued) nonce supplied (fail closed)");
        if (P(eat, "eat_nonce") is not string nonce || nonce.Length == 0) return Check(false, "EAT carries no eat_nonce — cannot establish freshness (replayable)");
        if (!StrEq(nonce, expected)) return Check(false, "eat_nonce does not match the server-issued challenge (replayed or relayed evidence)");
        if (Jx.Fin(P(eat, "iat")) is not double iat) return Check(false, "EAT has no valid iat (cannot establish age)");
        if (Jx.Fin(P(opts, "maxAgeMs")) is not double maxAge || maxAge <= 0) return Check(false, "invalid maxAgeMs");
        var iatMs = iat * 1000;
        if (iatMs - skew > now) return Check(false, "EAT iat is in the future");
        if (now - iatMs > maxAge + skew) return Check(false, "EAT is stale (iat older than maxAgeMs) — expired/replayed attestation");
        return Check(true);
    }

    /// <summary>CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from <c>channelId</c> and/or an explicit <c>expectedCnf</c>) must be present
    /// and equal in the token's <c>cnf</c>. A token with no <c>cnf</c>, or one bound to another channel or key, fails closed.</summary>
    public static D VerifyChannelBinding(object? eat, object? opts)
    {
        string? expExporter = null, expJkt = null;
        if (P(opts, "channelId") is string cid && cid.Length > 0) expExporter = (string)DeriveChannelCnf(cid)["tls_exporter"]!;
        var ec = P(opts, "expectedCnf");
        if (!IsUndef(ec))
        {
            if (P(ec, "tls_exporter") is string te) expExporter = te;
            if (P(ec, "jkt") is string jk) expJkt = jk;
        }
        if (expExporter == null && expJkt == null) return Check(false, "no expected channel binding supplied (fail closed)");
        var cnf = P(eat, "cnf");
        if (!Truthy(cnf) || (IsUndef(P(cnf, "tls_exporter")) && IsUndef(P(cnf, "jkt"))))
            return Check(false, "EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)");
        if (expExporter != null && (IsUndef(P(cnf, "tls_exporter")) || !StrEq(P(cnf, "tls_exporter"), expExporter))) return Check(false, "TLS-exporter channel binding mismatch (evidence lifted to another channel?)");
        if (expJkt != null && (IsUndef(P(cnf, "jkt")) || !StrEq(P(cnf, "jkt"), expJkt))) return Check(false, "holder-key thumbprint (cnf.jkt) mismatch");
        return Check(true);
    }

    static bool Truthy(object? x) => x != null && !IsUndef(x) && JsX.Truthy(x);

    // ---- RATS appraisal ----

    static bool Trustworthy(string tier) => tier is "affirming-hw-rooted" or "affirming" or "warning";

    /// <summary>Packs a TCB version into a comparable integer, or null for an unknown shape (fail closed): a packed number, a decimal string, or the structured components.</summary>
    static BigInteger? PackTcb(object? v)
    {
        if (Jx.IsNum(v)) { var d = Jx.ToNumber(v); return double.IsFinite(d) && d >= 0 ? new BigInteger(Math.Floor(d)) : null; }
        if (v is string s)
        {
            var t = JsX.JsTrim(s);
            return t.Length > 0 && t.All(c => c is >= '0' and <= '9') ? BigInteger.Parse(t, System.Globalization.CultureInfo.InvariantCulture) : null; // non-numeric: unknown format
        }
        if (v is not D) return null; // true / [] / null are not a TCB version
        BigInteger? Comp(object? x)
        {
            if (IsUndef(x)) return BigInteger.Zero;
            if (!Jx.IsNum(x)) return null;
            var d = Jx.ToNumber(x);
            return double.IsFinite(d) && Math.Floor(d) == d && d >= 0 && !(d == 0 && double.IsNegative(d)) && d <= 255 ? new BigInteger(d) : null;
        }
        var bl = Comp(P(v, "bootloader")); var tee = Comp(P(v, "tee")); var snp = Comp(P(v, "snp")); var uc = Comp(P(v, "microcode"));
        if (bl == null || tee == null || snp == null || uc == null) return null;
        return bl | (tee << 8) | (snp << 48) | (uc << 56);
    }

    static string Lc(object? s) => s is string x ? x.ToLowerInvariant() : throw TypeErr("s.toLowerCase is not a function");

    static bool IncludesLc(L list, string value) => list.Select(Lc).ToList().Contains(value.ToLowerInvariant()); // the reference maps every entry first

    /// <summary><c>list.find(e =&gt; e.type === ...)?.value</c> over an optional <c>measurements</c> array.</summary>
    static object? FindMeasurement(object? measurements, params string[] types)
    {
        if (measurements == null || IsUndef(measurements)) return Jx.Undef;
        if (measurements is not L l) throw TypeErr("eat.measurements?.find is not a function");
        foreach (var e in l) if (P(e, "type") is string t && types.Contains(t)) return P(e, "value");
        return Jx.Undef;
    }

    internal static object? LaunchMeasurement(object? eat)
    {
        var measured = P(eat, "measured");
        if (Truthy(measured) && P(measured, "runtime_measurement") is string rm && rm.Length > 0) return rm;
        var sev = P(eat, "sevsnp");
        if (Truthy(sev) && P(sev, "measurement") is string sm) return sm;
        return FindMeasurement(P(eat, "measurements"), "launch", "measurement");
    }

    static object? WeightsMeasurement(object? eat)
    {
        var measured = P(eat, "measured");
        if (Truthy(measured) && P(measured, "weights_digest") is string wd && wd.Length > 0) return wd;
        return FindMeasurement(P(eat, "measurements"), "weights");
    }

    static bool? IsDebugDisabled(object? eat)
    {
        var dbg = P(eat, "dbgstat");
        // a present dbgstat that is not an RFC 9711 value (hand-built claims) is unknown, never "disabled"
        if (!IsUndef(dbg)) return dbg is string s && EatToken.DbgstatValues.Contains(s) ? s != "enabled" : null;
        var sev = P(eat, "sevsnp");
        if (Truthy(sev) && P(sev, "debug") is bool b) return b == false;
        return null;
    }

    static bool NonEmptyList(object? x) => x is L l && l.Count > 0;

    /// <summary>APPRAISES an EAT's EVIDENCE against RATS reference values and endorsements into a trust tier: endorsements gate WHO the attester is (a mismatch is
    /// <c>rejected</c>); reference values gate WHAT state the evidence shows (an actively bad value is <c>contraindicated</c>, a required value that is absent or in an
    /// unknown format is <c>rejected</c>); degraded evidence that otherwise passes is a <c>warning</c>; an empty policy is <c>rejected</c>. A null policy argument is "none given";
    /// the reference refuses an explicit null, so a caller that holds a JSON null should refuse it first.</summary>
    public static D Appraise(object? evidence, object? referenceValues = null, object? endorsements = null, object? extras = null)
    {
        referenceValues ??= new D(); endorsements ??= new D(); extras ??= new D();
        var reasons = new L();
        D Result(string tier, string reason) => Obj(("tier", tier), ("trustworthy", Trustworthy(tier)), ("reasons", new L(reasons) { reason }));

        var issuers = P(endorsements, "issuers"); var oemids = P(endorsements, "oemids"); var operators = P(endorsements, "operators");
        var hasEndorsements = NonEmptyList(issuers) || NonEmptyList(oemids) || NonEmptyList(operators);
        var hasReference = NonEmptyList(P(referenceValues, "measurements")) || NonEmptyList(P(referenceValues, "models")) || NonEmptyList(P(referenceValues, "weightsMeasurements"))
            || P(referenceValues, "requireMeasuredWeights") is true || !IsUndef(P(referenceValues, "minTcb")) || Jx.IsNum(P(referenceValues, "minGuestSvn")) || P(referenceValues, "requireDebugDisabled") is true;
        if (!hasEndorsements && !hasReference)
            return Obj(("tier", "rejected"), ("trustworthy", false), ("reasons", new L { "empty appraisal policy: no endorsements or reference values to appraise against (fail closed)" }));

        // endorsements (WHO): rejected on mismatch
        if (issuers is L il && il.Count > 0)
        {
            var iss = P(evidence, "iss");
            if (!il.Any(x => JsX.StrictEq(x, iss))) return Result("rejected", $"issuer {JsX.Str(iss)} is not an endorsed attester");
            reasons.Add("issuer endorsed");
        }
        if (oemids is L ol && ol.Count > 0)
        {
            if (P(evidence, "oemid") is not string oem || !ol.Any(x => JsX.StrictEq(x, oem))) return Result("rejected", "oemid absent or not endorsed (fail closed)");
            reasons.Add("oemid endorsed");
        }
        if (operators is L pl && pl.Count > 0)
        {
            if (Opt(P(evidence, "measured"), "operator") is not string op || op.Length == 0 || !pl.Any(x => JsX.StrictEq(x, op))) return Result("rejected", "hardware operator absent or not endorsed (fail closed)");
            reasons.Add("operator endorsed");
        }

        // reference values (WHAT): a bad value is contraindicated; an absent or unknown required one is rejected
        if (P(referenceValues, "measurements") is L ms && ms.Count > 0)
        {
            var m = LaunchMeasurement(evidence);
            if (IsUndef(m)) return Result("rejected", "no launch measurement in evidence to compare against reference values (fail closed)");
            if (m is not string mStr) throw TypeErr("m.toLowerCase is not a function");
            if (!IncludesLc(ms, mStr)) return Result("contraindicated", "launch measurement not in reference values");
            reasons.Add("launch measurement matches a reference value");
        }
        if (P(referenceValues, "models") is L models && models.Count > 0)
        {
            if (Opt(P(evidence, "measured"), "model_id") is not string model || model.Length == 0) return Result("rejected", "no model id in evidence (fail closed)");
            if (!models.Any(x => JsX.StrictEq(x, model))) return Result("contraindicated", "model id not in reference values (model swap?)");
            reasons.Add("model id matches a reference value");
        }
        if (P(referenceValues, "requireMeasuredWeights") is true)
        {
            if (!(Opt(P(evidence, "measured"), "weights_measured") is true)) return Result("contraindicated", "weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)");
            reasons.Add("weights digest is hardware-measured");
        }
        if (P(referenceValues, "weightsMeasurements") is L wm && wm.Count > 0)
        {
            var w = WeightsMeasurement(evidence);
            if (IsUndef(w) || (w is string ws0 && ws0.Length == 0)) return Result("rejected", "no measured-weights digest in evidence (fail closed)");
            if (w is not string wStr) throw TypeErr("w.toLowerCase is not a function");
            if (!IncludesLc(wm, wStr)) return Result("contraindicated", "weights measurement not in reference values (model swap / fine-tune?)");
            reasons.Add("weights measurement matches a reference value");
        }
        var minTcbO = P(referenceValues, "minTcb");
        if (!IsUndef(minTcbO))
        {
            var min = PackTcb(minTcbO);
            if (min == null) return Result("rejected", "reference minTcb is not a comparable TCB version");
            var rawTcb = Opt(P(evidence, "sevsnp"), "reported_tcb");
            var got = IsUndef(rawTcb) ? null : PackTcb(rawTcb);
            if (got == null) return Result("rejected", "evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)");
            if (got < min) return Result("contraindicated", "reported TCB is below the reference minimum (downgrade / rollback)");
            reasons.Add("TCB at or above reference minimum");
        }
        var minSvn = P(referenceValues, "minGuestSvn");
        if (Jx.IsNum(minSvn))
        {
            if (Jx.Fin(Opt(P(evidence, "sevsnp"), "guest_svn")) is not double svn) return Result("rejected", "guest_svn absent (fail closed)");
            if (svn < Jx.ToNumber(minSvn)) return Result("contraindicated", $"guest_svn {JsX.JsNumString(svn)} below reference minimum {JsX.Str(minSvn)}");
            reasons.Add("guest_svn at or above reference minimum");
        }
        if (P(referenceValues, "requireDebugDisabled") is true)
        {
            var disabled = IsDebugDisabled(evidence);
            if (disabled == null) return Result("rejected", "debug status unknown — failing closed");
            if (disabled == false) return Result("contraindicated", "debug is enabled (host can inspect the guest — no confidentiality)");
            reasons.Add("debug disabled");
        }

        // all checks passed: degraded evidence is a warning; a verified AMD silicon signature is the hardware-rooted tier
        if (Opt(P(evidence, "sevsnp"), "degraded") is true)
            return Obj(("tier", "warning"), ("trustworthy", true), ("reasons", new L(reasons) { "evidence came from a degraded (version-tolerant) parse — review" }));
        if (P(extras, "hardwareVerified") is true)
        {
            var lo = P(extras, "hardwareRootLabel");
            var label = lo == null || IsUndef(lo) ? AmdSevSnpHardwareRootLabel : JsX.Str(lo);
            return Obj(("tier", "affirming-hw-rooted"), ("trustworthy", true), ("reasons", new L(reasons) { $"AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — {label}" }));
        }
        return Obj(("tier", "affirming"), ("trustworthy", true), ("reasons", reasons));
    }

    // ---- verdicts ----

    /// <summary>Type guard: one of the accepted post-quantum co-sign suites (the pure-classical ed25519 suite is not one).</summary>
    public static bool IsPqCoSignSuite(object? x) => x is string s && PqCoSignSuites.Contains(s);

    /// <summary>Builds an attestation verdict from an appraisal result and the attestation's EAT claims.</summary>
    public static D VerdictFromAppraisal(object? result, object? claims)
    {
        var v = new D();
        Jx.Set(v, "tier", P(result, "tier")); Jx.Set(v, "trustworthy", P(result, "trustworthy"));
        var measured = P(claims, "measured");
        if (!IsUndef(measured)) v["measured"] = measured;
        var rm = Opt(measured, "runtime_measurement");
        var measurement = Truthy(rm) && rm is string rs && rs.Length > 0 ? rm : Opt(P(claims, "sevsnp"), "measurement");
        if (NonEmptyString(measurement)) v["measurement"] = measurement;
        if (P(claims, "eat_nonce") is string nonce) v["nonce"] = nonce;
        if (Jx.Fin(P(claims, "iat")) != null) v["iat"] = P(claims, "iat");
        if (P(claims, "iss") is string iss) v["issuer"] = iss;
        return v;
    }

    static object? Str(object? x) => x is string ? x : null;

    /// <summary>The CANONICAL, DETERMINISTIC bytes a verdict co-signature is computed over: <c>utf8(JSON.stringify(obj))</c> with <c>obj</c> in a fixed field order, a
    /// domain-separation <c>typ</c> and every optional field emitted explicitly (value or null).</summary>
    public static byte[] CanonicalVerdictBytes(object? verdict, object? cosignedAt)
    {
        var tier = P(verdict, "tier");
        var trustworthy = P(verdict, "trustworthy") is true;
        var measurement = Str(P(verdict, "measurement"));
        var mo = P(verdict, "measured");
        object? measured = null;
        if (!IsUndef(mo))
        {
            var wm = P(mo, "weights_measured");
            var c = new D();
            Jx.Set(c, "model_id", P(mo, "model_id")); Jx.Set(c, "weights_digest", P(mo, "weights_digest"));
            c["weights_measured"] = wm is bool ? wm : null;
            Jx.Set(c, "runtime_measurement", P(mo, "runtime_measurement")); Jx.Set(c, "operator", P(mo, "operator"));
            c["system_prompt_digest"] = Str(P(mo, "system_prompt_digest")); c["tool_manifest_digest"] = Str(P(mo, "tool_manifest_digest"));
            measured = c;
        }
        var obj = new D { ["typ"] = PqCoSignDomain };
        Jx.Set(obj, "tier", tier);
        obj["trustworthy"] = trustworthy; obj["measurement"] = measurement; obj["measured"] = measured; obj["nonce"] = Str(P(verdict, "nonce"));
        obj["iat"] = Jx.Fin(P(verdict, "iat")) != null ? P(verdict, "iat") : null;
        obj["issuer"] = Str(P(verdict, "issuer"));
        Jx.Set(obj, "cosignedAt", cosignedAt);
        return Encoding.UTF8.GetBytes(AtlasPca.Js.JsJson.Stringify(obj));
    }
}
