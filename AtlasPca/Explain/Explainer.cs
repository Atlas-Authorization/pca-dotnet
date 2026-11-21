using System.Text.RegularExpressions;
using AtlasPca.Js;
using static AtlasPca.Explain.ExplainJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Explain;

/// <summary>Self-explaining PCA decisions: a proof-trace of a PCActn verification (the nine normative checks), a Policy-VM decision (which
/// predicate granted it, which caveat narrowed or denied it, the risk band and the budget path) and an attenuation trace of a delegation
/// chain. Pure and read-only; it consumes the verifier's own result shapes, never re-authorizes, and a malformed input degrades to a
/// best-effort explanation. Explanations are JSON trees (a member that would be undefined is absent); the <c>*ToText</c> renderers take
/// them back. <see cref="CleanText"/> removes what looks like a credential from text built out of untrusted fields.</summary>
public static class Explainer
{
    public const int MaxText = 400;
    const long PcactnVersion = 2;
    const long PcactnMaxLifetimeMs = 3_600_000;
    const long PcactnMaxSkewMs = 60_000;

    public static readonly IReadOnlyList<string> VerifyCheckOrder = new[]
    {
        "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format",
    };

    static readonly Dictionary<string, string> CheckTitle = new(StringComparer.Ordinal)
    {
        ["wire"] = "wire format", ["version"] = "version", ["audience"] = "audience binding", ["validity"] = "freshness window", ["cap_chain"] = "capability chain",
        ["grant_ref_bound"] = "grant reference binding", ["plan_inclusion"] = "plan inclusion", ["leaf_signature"] = "leaf signature", ["counter_format"] = "counter format",
        ["counter"] = "counter format", ["replay"] = "replay", ["plan_root_authorized"] = "plan-root authorization", ["taint_gate"] = "taint gate",
        ["attestation"] = "agent attestation", ["threshold"] = "threshold signature", ["revocation"] = "revocation", ["zk_compliance"] = "zk compliance",
        ["bond"] = "bond", ["malformed"] = "structure",
    };

    // ---- cleanText ----------------------------------------------------------------------------------------------------------

    // JavaScript \s, \w and \b spelled out: \b before a word character is "not preceded by a word character"; /i is spelled with letter classes
    // (the non-Unicode JavaScript case folding never maps a non-ASCII character onto an ASCII letter)
    const string Ws = @"\t\n\v\f\r    - \u2028\u2029  　﻿";
    const string Wd = "A-Za-z0-9_";
    const string NotWord = "(?<![" + Wd + "])";
    const RegexOptions Ro = RegexOptions.CultureInvariant;

    static string CI(string word) => string.Concat(word.Select(c => char.IsLetter(c) ? $"[{char.ToLowerInvariant(c)}{char.ToUpperInvariant(c)}]" : c.ToString()));

    static readonly Regex JwtRe = new(NotWord + @"eyJ[" + Wd + @"-]{5,}\.[" + Wd + @"-]{5,}\.[" + Wd + "-]*", Ro);
    static readonly Regex BearerRe = new(NotWord + "(" + CI("Bearer") + "|" + CI("Basic") + "|" + CI("Token") + ")[" + Ws + "]+[" + Wd + @".~+/=-]{6,}", Ro);
    static readonly Regex UserInfoRe = new("([A-Za-z][A-Za-z0-9+.-]*://)[^" + Ws + "/@]*:[^" + Ws + "/@]*@", Ro);
    static readonly Regex PairRe = new(NotWord + "((?:" + string.Join("|", new[] { "token", "secret", "password", "passwd", "pwd", "api[_-]?key", "key", "signature", "sig", "credential", "authorization", "auth" }.Select(w => w.StartsWith("api") ? CI("api") + "[_-]?" + CI("key") : CI(w))) + @")[""']?[" + Ws + @"]*[:=][" + Ws + @"]*)(""[^""]*""|'[^']*'|[^" + Ws + @"""'&,;]+)", Ro);
    static readonly Regex LongRunRe = new("[A-Za-z0-9_-]{40,}", Ro);

    /// <summary>Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
    /// <c>token=</c> / <c>password=</c> style pairs and long unbroken token runs) and cut the result to 400 characters. A net, not a proof.</summary>
    public static string CleanText(object? text)
    {
        var t = S(text);
        t = JwtRe.Replace(t, "[redacted]");
        t = BearerRe.Replace(t, "$1 [redacted]");
        t = UserInfoRe.Replace(t, "$1[redacted]@");
        t = PairRe.Replace(t, "$1[redacted]");
        t = LongRunRe.Replace(t, "[redacted]");
        return t.Length > MaxText ? t[..MaxText] + "..." : t;
    }

    // ---- shared helpers -----------------------------------------------------------------------------------------------------

    /// <summary>Abbreviate a long key for display: first n characters and an ellipsis.</summary>
    static string Short(object? key, int n = 10)
    {
        if (key is not string s || s.Length == 0) return "<none>";
        return s.Length <= n + 1 ? s : s[..n] + "…";
    }

    static double JsRound(double v) { var f = Math.Floor(v); return v - f >= 0.5 ? f + 1 : f; }

    /// <summary>Compact number: integers stay integers, fractions round to 4 decimals; anything else is String(x).</summary>
    static string NumText(object? x)
    {
        if (x is Num n)
        {
            var d = JsJson.ToJsNumber(n);
            if (double.IsFinite(d)) return d == Math.Floor(d) ? Str(d) : Str(JsRound(d * 1e4) / 1e4);
        }
        return S(x);
    }

    /// <summary>num(x) for a computed double (NaN and the infinities print through String()).</summary>
    static string NumTextD(double d) => double.IsFinite(d) ? (d == Math.Floor(d) ? Str(d) : Str(JsRound(d * 1e4) / 1e4)) : Str(d);

    /// <summary>The member of a tree map, or undefined when absent (a present null stays null).</summary>
    static object? Gd(D d, string k) => d.TryGetValue(k, out var v) ? v : Undef;

    static string ValueSummary(D rest)
    {
        var parts = new List<string>();
        foreach (var k in IntentJs.JsKeys(rest.Keys).Take(6))
        {
            var v = rest[k];
            parts.Add($"{k}={(v is D || v is L ? JsJson.Stringify(v) : NumText(v))}");
        }
        return string.Join(", ", parts);
    }

    static (string Type, D Fields) CaveatParts(object? cv)
    {
        var type = Q(cv, "type") is string t ? t : "<malformed>";
        var rest = new D();
        if (cv is D d)
        {
            foreach (var k in d.Keys) if (k != "type") rest[k] = d[k];
        }
        else if (cv is L l)
        {
            for (int i = 0; i < l.Count; i++) rest[i.ToString(System.Globalization.CultureInfo.InvariantCulture)] = l[i];
        }
        return (type, rest);
    }

    static string CondToText(object? c, int depth = 0)
    {
        if (!IsObject(c)) return "<malformed>";
        if (depth > 6) return "…";
        if (In(c, "all_of") && Q(c, "all_of") is L all) return "(" + string.Join(" AND ", all.Select(x => CondToText(x, depth + 1))) + ")";
        if (In(c, "any_of") && Q(c, "any_of") is L any) return "(" + string.Join(" OR ", any.Select(x => CondToText(x, depth + 1))) + ")";
        if (In(c, "not")) return "NOT " + CondToText(Q(c, "not"), depth + 1);
        var rf = Q(c, "ref");
        var operand = !IsUndef(rf) ? "→" + S(rf) : In(c, "value") ? NumText(Q(c, "value")) : "";
        return JsTrim($"{S(Q(c, "field"))} {S(Q(c, "op"))} {operand}");
    }

    static string WhereSummary(object? where)
    {
        if (where is not L l || l.Count == 0) return "any (no where-bound)";
        return string.Join(" AND ", l.Select(c => CondToText(c)));
    }

    static bool IsBudgetAlloc(object? cv) => cv is D d && d.GetValueOrDefault("type") is string t && t == "budget_alloc"
        && d.GetValueOrDefault("limit") is Num n && JsJson.ToJsNumber(n) is var x && double.IsFinite(x) && x >= 0;

    // ---- explainVerification ------------------------------------------------------------------------------------------------

    static D Entry(string name, object? status, string title, string detail) => new() { ["name"] = name, ["status"] = status, ["title"] = title, ["detail"] = detail };

    static D VerificationOf(string verdict, bool allow, List<D> checks, D? decisive, string summary)
    {
        bool St(D c, string s) => c["status"] is string x && x == s;
        var d = new D
        {
            ["kind"] = "verification",
            ["verdict"] = verdict,
            ["allow"] = allow,
            ["checks"] = checks.Cast<object?>().ToList(),
            ["passed"] = checks.Where(c => St(c, "pass")).Select(c => c["name"]).ToList(),
            ["failed"] = checks.Where(c => St(c, "fail")).Select(c => c["name"]).ToList(),
            ["notEnforced"] = checks.Where(c => St(c, "not-enforced")).Select(c => c["name"]).ToList(),
        };
        if (decisive != null) d["decisive"] = decisive;
        d["summary"] = summary;
        return d;
    }

    static D DeniedVerification(string why)
    {
        var e = Entry("malformed", "fail", CheckTitle["malformed"], why);
        e["remedy"] = "pass the PCActn and the verifier result you verified.";
        e["decisive"] = true;
        return VerificationOf("deny", false, new List<D> { e }, e, "Denied: " + why);
    }

    /// <summary>Explain the offline verification of a PCActn: walk the checks in normative order; for each pass summarize what held, and for the
    /// FIRST failing check pinpoint it (which hop, which audience mismatch, which validity sub-case ...) with a concrete remedy.
    /// <c>opts.now</c> (epoch ms) lets the validity pinpoint tell "expired" from "clock skew". Never throws.</summary>
    public static D ExplainVerification(object? pcActn, object? verifyResult, object? opts)
    {
        if (!IsObject(pcActn) || !IsObject(verifyResult)) return DeniedVerification("the PCActn or the verifier result is missing");
        try { return VerificationInner(pcActn, verifyResult, opts); }
        catch (Exception) { return DeniedVerification("the PCActn or the verifier result is malformed"); }
    }

    public static D ExplainVerification(object? pcActn, object? verifyResult) => ExplainVerification(pcActn, verifyResult, new D());

    static string? ReasonTail(string name, object? vr)
    {
        if (G(vr, "reason") is not string r) return null;
        var pre = name + ": ";
        return r.StartsWith(pre, StringComparison.Ordinal) ? r[pre.Length..] : null;
    }

    static (string Detail, string Remedy) ValidityPinpoint(object? p, object? now)
    {
        var exp = Q(p, "exp"); var iat = Q(p, "iat");
        var lifetime = Sub(exp, iat);
        if (!Gt(exp, iat)) return ($"exp {S(exp)} ≤ iat {S(iat)}: empty validity window", "set exp strictly greater than iat.");
        if (lifetime > PcactnMaxLifetimeMs)
            return ($"lifetime {Str(lifetime)}ms exceeds the {PcactnMaxLifetimeMs}ms maximum", $"shorten the window to ≤ {PcactnMaxLifetimeMs}ms (buildPCActn ttlMs).");
        if (!IsUndef(now))
        {
            if (Gt(iat, Add(now, PcactnMaxSkewMs)))
                return ($"iat {S(iat)} is {Str(Sub(iat, now))}ms in the future (> {PcactnMaxSkewMs}ms clock-skew allowance)", "fix the signer clock; do not pre-date actions.");
            if (Gt(now, exp))
                return ($"expired {Str(Sub(now, exp))}ms ago (exp {S(exp)}, now {S(now)})", "build a fresh action — a PCActn lifetime is short by design.");
        }
        return ("validity window invalid", "build a fresh action with a valid iat/exp window.");
    }

    static readonly Regex HopRe = new("hop ([0-9]+)", Ro);

    static (string Detail, string Remedy, double? Hop) CapChainPinpoint(object? p)
    {
        var chain = Q(p, "cap_chain");
        (string Why, bool Ok) res = chain is L cl ? Pca.VerifyChain(cl, null, false) : ("cap_chain is not an array", false);
        var reason = res.Ok ? "chain root is not the grant this verifier expects" : (string.IsNullOrEmpty(res.Why) ? "capability chain invalid" : res.Why);
        double? hop = null;
        var m = HopRe.Match(reason);
        if (m.Success) hop = double.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        var remedy = "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.";
        if (reason.Contains("root issuer", StringComparison.Ordinal) || reason.Contains("not the grant", StringComparison.Ordinal)) remedy = "root the chain at the principal key that minted the grant.";
        else if (reason.Contains("widens", StringComparison.Ordinal)) remedy = "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.";
        else if (reason.Contains("caveat", StringComparison.Ordinal)) remedy = "attenuation is append-only: never drop, reorder or edit a parent caveat.";
        else if (reason.Contains("signature", StringComparison.Ordinal)) remedy = "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).";
        return (reason, remedy, hop);
    }

    static (string Detail, string Remedy, double? Hop) LeafSigPinpoint(object? p)
    {
        var chain = Q(p, "cap_chain");
        int idx = chain is L cl ? cl.Count - 1 : -1;
        var leaf = idx >= 0 ? ((L)chain!)[idx] : Undef;
        var alg = Q(p, "alg"); if (Nullish(alg)) alg = "ed25519";
        var remedy = "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.";
        if (!Truthy(leaf)) return ("no leaf capability to check the signature against (empty/invalid chain)", remedy, null);
        return ($"leaf hop #{idx} signature (holder {Short(G(leaf, "holder"))}, suite {S(alg)}) does not verify", remedy, idx);
    }

    static (string Detail, string Remedy, double? Hop) Pinpoint(string name, object? p, object? vr, object? now)
    {
        var tail = ReasonTail(name, vr);
        switch (name)
        {
            case "wire":
                return (tail ?? "wire structure / strict-canonical-form check failed", "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.", null);
            case "version":
                return (tail ?? $"unsupported ver {NumText(Q(p, "ver"))} (verifier requires {PcactnVersion})", $"re-mint the action at wire version {PcactnVersion}.", null);
            case "audience":
                return (tail ?? $"aud {Json(Q(p, "aud"))} does not match this resource server / instance", "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).", null);
            case "validity":
            {
                var v = ValidityPinpoint(p, now);
                return (tail ?? v.Detail, v.Remedy, null);
            }
            case "cap_chain":
            {
                var c = CapChainPinpoint(p);
                return (tail ?? c.Detail, c.Remedy, c.Hop);
            }
            case "grant_ref_bound":
                return (tail ?? $"grant_ref {Short(Q(p, "grant_ref"))} is not the id of the root capability in cap_chain",
                    "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.", null);
            case "plan_inclusion":
            {
                var action = Q(p, "action"); var plan = Q(p, "plan");
                return (tail ?? $"action (verb {Json(Q(action, "verb"))} on {Json(Q(action, "resource"))}) is not node {Json(Q(plan, "node_id"))} of committed plan {Short(Q(plan, "root"))}",
                    "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).", null);
            }
            case "leaf_signature":
            {
                var l = LeafSigPinpoint(p);
                return (tail ?? l.Detail, l.Remedy, l.Hop);
            }
            case "counter":
            case "counter_format":
                return (tail ?? $"counter {NumText(Q(p, "counter"))} is missing or not a non-negative safe integer", "use a strictly increasing per-holder counter; a repeated counter is a replay.", null);
            case "malformed":
                return (tail ?? "the PCActn is structurally malformed", "rebuild the action with the SDK; do not construct the wire object by hand.", null);
            default:
                return (tail ?? $"{name} check failed", $"satisfy the {name} requirement (supply the corresponding verifier hook / proof).", null);
        }
    }

    static string PassDetail(string name, object? p)
    {
        switch (name)
        {
            case "wire": return "wire structure + strict canonical form valid";
            case "version": return $"ver {NumText(Q(p, "ver"))} supported";
            case "audience": return $"aud {Json(Q(p, "aud"))} matches this resource server";
            case "validity": return $"fresh: iat/exp window valid (lifetime {NumTextD(Sub(Q(p, "exp"), Q(p, "iat")) / 1000)}s)";
            case "cap_chain":
            {
                var chain = Q(p, "cap_chain");
                int len = chain is L l ? l.Count : 0;
                var root = chain is L l2 ? (l2.Count > 0 ? l2[0] : Undef) : Undef;
                return $"{len}-hop chain verifies; root issuer {Short(Q(root, "issuer"))}";
            }
            case "grant_ref_bound": return $"grant_ref {Short(Q(p, "grant_ref"))} is the id of the chain root";
            case "plan_inclusion": { var plan = Q(p, "plan"); return $"action is node {Json(Q(plan, "node_id"))} of committed plan {Short(Q(plan, "root"))}"; }
            case "leaf_signature":
            {
                var chain = Q(p, "cap_chain");
                var leaf = chain is L l && l.Count > 0 ? l[^1] : Undef;
                var alg = Q(p, "alg"); if (Nullish(alg)) alg = "ed25519";
                return $"leaf holder {Short(Q(leaf, "holder"))} signature valid (suite {S(alg)})";
            }
            case "counter":
            case "counter_format": return $"counter {NumText(Q(p, "counter"))} well-formed";
            default: return "ok";
        }
    }

    static D CleanCheck(D c)
    {
        var d = new D(c);
        d["detail"] = CleanText(c["detail"]);
        return d;
    }

    static D VerificationInner(object? p, object? vr, object? opts)
    {
        var checksRaw = Q(vr, "checks");
        object? statuses = Nullish(checksRaw) ? new D() : checksRaw;
        var ordered = new List<string>(VerifyCheckOrder);
        var seen = new HashSet<string>(VerifyCheckOrder, StringComparer.Ordinal);
        foreach (var n in Keys(statuses)) if (!seen.Contains(n)) ordered.Add(n);

        string? decisiveName = null;
        foreach (var n in ordered) if (Q(statuses, n) is string s && s == "fail") { decisiveName = n; break; }

        var checks = new List<D>();
        D? decisive = null;
        foreach (var name in ordered)
        {
            var raw = Q(statuses, name);
            object? status = Nullish(raw) ? "skipped" : raw;
            var title = CheckTitle.TryGetValue(name, out var tt) ? tt : name;
            string detail; string? remedy = null; double? hop = null;
            if (status is string st && st == "fail")
            {
                var pin = Pinpoint(name, p, vr, G(opts, "now"));
                detail = pin.Detail; remedy = pin.Remedy; hop = pin.Hop;
            }
            else if (status is string st2 && st2 == "pass") detail = PassDetail(name, p);
            else if (status is string st3 && st3 == "not-enforced") detail = "not enforced by this verifier (no hook / opt-out)";
            else if (status is string st4 && st4 == "unsupported") detail = "the PCActn carries a feature this verifier does not implement (never a pass)";
            else detail = "not reached (a terminal earlier check stopped evaluation)";
            var entry = Entry(name, status, title, detail);
            if (remedy != null) entry["remedy"] = remedy;
            if (hop != null) entry["hop"] = NumOf(hop.Value);
            if (name == decisiveName) { entry["decisive"] = true; decisive = entry; }
            checks.Add(entry);
        }

        // Allow only on an explicit `allow: true` that no check contradicts; a result with no per-check statuses proves nothing.
        var hasChecks = checksRaw is D;
        var allowRaw = Q(vr, "allow");
        var claimedAllow = allowRaw is true && hasChecks;
        var contradicted = claimedAllow && decisiveName != null;
        var verdict = claimedAllow && !contradicted ? "allow" : "deny";
        string summary;
        if (verdict == "allow") summary = $"All {checks.Count(c => c["status"] is string x && x == "pass")} evaluated checks passed (no check failed).";
        else if (allowRaw is true && !hasChecks) summary = "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).";
        else if (contradicted) summary = $"Denied: the verifier result says allow but the \"{(decisive != null ? (string)decisive["title"]! : decisiveName)}\" check failed (inconsistent result, treated as a denial).";
        else if (decisive != null) summary = $"Denied at the \"{decisive["title"]}\" check: {decisive["detail"]}";
        else summary = $"Denied: {(Q(vr, "reason") is string rs ? rs : "a check failed")}";

        return VerificationOf(verdict, verdict == "allow", checks.Select(CleanCheck).ToList(), decisive != null ? CleanCheck(decisive) : null, CleanText(summary));
    }

    /// <summary>Plain-text rendering of an explanation returned by <see cref="ExplainVerification(object?, object?, object?)"/>.</summary>
    public static string VerificationToText(D e)
    {
        var lines = new List<string>
        {
            "PCA verification — " + ((string)e["verdict"]!).ToUpperInvariant(),
            (string)e["summary"]!,
            "",
        };
        foreach (var c in ((L)e["checks"]!).Cast<D>())
        {
            var glyph = c["status"] is string s ? s switch { "pass" => "✓", "fail" => "✗", "not-enforced" => "·", "unsupported" => "?", "skipped" => "–", _ => "undefined" } : "undefined";
            var mark = c.GetValueOrDefault("decisive") is true ? " ◀ DECISIVE" : "";
            lines.Add($"  {glyph} {((string)c["name"]!).PadRight(16)} {c["detail"]}{mark}");
            if (c.GetValueOrDefault("decisive") is true && c.GetValueOrDefault("remedy") is string r && r.Length > 0) lines.Add($"      ↳ fix: {r}");
        }
        return string.Join("\n", lines);
    }

    // ---- explainDecision ----------------------------------------------------------------------------------------------------

    static string CaveatRemedy(string type, D rest)
    {
        object? R(string k) => rest.TryGetValue(k, out var v) ? v : Undef;
        return type switch
        {
            "expires" => $"the grant expired at {NumText(R("at"))} (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.",
            "not_before" => $"the grant is not valid until {NumText(R("at"))} (epoch ms); retry after that time.",
            "rate" => $"rate limit {NumText(R("max"))}/{NumText(R("per_secs"))}s reached; wait for the window to clear or raise the 'rate' caveat.",
            "max_blast_radius" => $"the action's blast radius exceeds the caveat max {NumText(R("max"))}; narrow the action or raise 'max_blast_radius'.",
            "reversibility_max" => $"the action is more severe than the allowed class '{S(R("class"))}'; only that class or lower is permitted.",
            "delegation_depth" => $"delegation depth exceeds max {NumText(R("max"))}; act from a shallower hop or raise 'delegation_depth'.",
            _ => $"caveat '{type}' is not satisfied; check its parameters against the action/context.",
        };
    }

    static string CaveatDetail(string type, D rest, bool satisfied)
    {
        var bound = ValueSummary(rest);
        var verb = satisfied ? "held" : "NARROWED/DENIED";
        return bound.Length > 0 ? $"{type}({bound}) {verb}" : $"{type} {verb}";
    }

    static readonly Regex NotSatisfiedRe = new(@"caveat\(s\) not satisfied: ([^\n\r\u2028\u2029]+)\z", Ro);

    static HashSet<string> FailedCaveatTypesFromReasons(L reasons)
    {
        var outp = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in reasons)
        {
            var m = NotSatisfiedRe.Match(S(r));
            if (!m.Success) continue;
            foreach (var t in m.Groups[1].Value.Split(',')) { var tt = JsTrim(t); if (tt.Length > 0) outp.Add(tt); }
        }
        return outp;
    }

    static string RiskBand(object? r, object? theta1, object? theta2, object? tier)
    {
        if (IsUndef(theta1) || IsUndef(theta2)) return $"effective tier t={S(tier)}";
        if (Le(r, theta1)) return $"r {NumText(r)} ≤ θ1 {NumText(theta1)} → claim band (t=1)";
        if (Le(r, theta2)) return $"θ1 {NumText(theta1)} < r {NumText(r)} ≤ θ2 {NumText(theta2)} → standard band (t=2)";
        return $"r {NumText(r)} > θ2 {NumText(theta2)} → strong band (t=3)";
    }

    static (bool Allowed, object? Matched, string? Reason) EvaluatePredicates(object? predicates, object? actionCtx)
    {
        var ctx = actionCtx as D;
        try
        {
            if (predicates is not L pl || pl.Count == 0) return (false, null, "envelope grants no predicates");
            foreach (var p in pl) if (Predicates.PredicateMatches(p, ctx)) return (true, p, null);
            var a = Q(actionCtx, "action");
            var limit = Predicates.FirstUnmetLimit(predicates, ctx);
            if (limit != null) return (false, null, $"{limit} not satisfied for {S(Q(a, "verb"))} on {S(Q(a, "resource"))}");
            return (false, null, $"no predicate permits {S(Q(a, "verb"))} on {S(Q(a, "resource"))}");
        }
        catch (Exception) { return (false, null, "predicate evaluation error (fail closed)"); }
    }

    /// <summary>The camelCase caveat context mapped onto the evaluator's own snake_case keys, plus the action.</summary>
    static D StockContext(object? caveatCtx, object? actionCtx)
    {
        var d = new D();
        if (caveatCtx is D c)
        {
            foreach (var (from, to) in new[] { ("now", "now"), ("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"), ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times") })
                if (c.TryGetValue(from, out var v)) d[to] = v;
        }
        if (Q(actionCtx, "action") is D a) d["action"] = a;
        return d;
    }

    static D NoDecision(string reason) => new()
    {
        ["admit"] = false,
        ["needStepUp"] = false,
        ["releaseGuardianShare"] = false,
        ["r"] = new Num("1"),
        ["requiredThreshold"] = new D { ["t"] = new Num("3"), ["proof"] = "human", ["optimisticAllowed"] = false },
        ["budget"] = new D { ["B"] = new Num("0"), ["tau"] = new Num("0"), ["asOf"] = new Num("0") },
        ["reasons"] = new L { reason },
    };

    /// <summary>Explain a Policy-VM decision: the granting predicate and its where bound, each caveat's outcome, the risk band, the admission and
    /// budget path, and (short of auto-admit) the single decisive reason with a remedy. <paramref name="opts"/> is <c>{envelope?, context?: {action?,
    /// caveat?, chain?}}</c>; with them the predicate and each caveat are re-derived from the real evaluators, without them the decision's own
    /// <c>reasons</c> are used. A missing or malformed decision is a denial, never a throw and never an allow.</summary>
    public static D ExplainDecision(object? pcActn, object? decision, object? opts)
    {
        if (!IsObject(decision) || !IsObject(Q(decision, "requiredThreshold"))) return DecisionInner(NoDecision("no policy decision supplied (default-deny)"), opts);
        try { return DecisionInner(decision, opts); }
        catch (Exception) { return DecisionInner(NoDecision("the policy decision could not be explained (default-deny)"), new D()); }
    }

    public static D ExplainDecision(object? pcActn, object? decision) => ExplainDecision(pcActn, decision, new D());

    static D DecisionInner(object? decision, object? opts)
    {
        var env = G(opts, "envelope");
        var ctxRaw = G(opts, "context");
        object? ctx = Nullish(ctxRaw) ? new D() : ctxRaw;
        var reasonsRaw = Q(decision, "reasons");
        var reasons = reasonsRaw as L ?? new L();

        var admitted = Q(decision, "admit") is true;
        var release = Q(decision, "releaseGuardianShare");
        var disposition = admitted ? "auto-admit" : release is true ? "step-up" : "denied";
        var verdict = admitted ? "allow" : "deny";

        // ---- authority: the granting predicate ----
        var grant = new D();
        if (!IsUndef(release)) grant["granted"] = release;
        var chain = G(ctx, "chain");
        var rootCap = Qi(chain, 0);
        if (Truthy(rootCap)) { var id = G(rootCap, "id"); if (!IsUndef(id)) grant["capabilityId"] = id; }
        var action = G(ctx, "action");
        if (Truthy(env) && Truthy(action))
        {
            var pr = EvaluatePredicates(G(env, "predicates"), action);
            if (pr.Allowed && pr.Matched != null)
            {
                grant["granted"] = true;
                grant["predicate"] = pr.Matched;
                var idx = ((L)G(env, "predicates")!).FindIndex(x => ReferenceEquals(x, pr.Matched));
                grant["predicateIndex"] = new Num(idx.ToString(System.Globalization.CultureInfo.InvariantCulture));
                grant["where"] = WhereSummary(Q(pr.Matched, "where"));
            }
            else
            {
                grant["granted"] = false;
                grant["reason"] = pr.Reason ?? "no predicate permits this action";
            }
        }
        else if (!Truthy(release))
        {
            var found = reasons.FirstOrDefault(r => Includes(r, "predicate") || Includes(r, "not permitted"));
            if (found != null) grant["reason"] = found;
        }

        // ---- caveats: per-caveat outcome ----
        var caveats = new List<D>();
        var failedFromReasons = FailedCaveatTypesFromReasons(reasons);
        var caveatCtx = G(ctx, "caveat");
        var canEval = !IsUndef(env) && !IsUndef(caveatCtx) && !IsUndef(action);

        var envCaveats = Q(env, "caveats");
        var grantCaveats = Nullish(envCaveats) ? new L() : envCaveats;
        var rootCapCaveatCount = RootCapCaveatCount(chain);
        var delegatedCaveats = new L();
        if (Truthy(chain) && Len(chain) is Num cn && JsJson.ToJsNumber(cn) > 1)
        {
            var leafCaveats = Q(Qi(chain, (int)JsJson.ToJsNumber(cn) - 1), "caveats");
            var lc = Nullish(leafCaveats) ? new L() : leafCaveats;
            delegatedCaveats = Iter(Slice(lc, rootCapCaveatCount)).ToList();
        }

        D Classify(object? cv, bool delegated)
        {
            var (type, rest) = CaveatParts(cv);
            object? satisfied;
            if (canEval && Truthy(caveatCtx) && Truthy(action))
                satisfied = Pca.EvaluateAgentCaveats(new L { cv }, StockContext(caveatCtx, action), action as D).Ok;
            else
                satisfied = failedFromReasons.Contains(type) ? false : release;
            var o = new D { ["type"] = type };
            if (!IsUndef(satisfied)) o["satisfied"] = satisfied;
            o["value"] = rest;
            o["detail"] = CaveatDetail(type, rest, Truthy(satisfied));
            o["delegated"] = delegated;
            if (!Truthy(satisfied)) o["remedy"] = CaveatRemedy(type, rest);
            return o;
        }
        foreach (var cv in Iter(grantCaveats)) caveats.Add(Classify(cv, false));
        foreach (var cv in delegatedCaveats) caveats.Add(Classify(cv, true));

        // ---- risk / tier ----
        var rt = Q(decision, "requiredThreshold");
        var rr = Q(decision, "r");
        var riskPolicy = Nullish(env) ? Undef : G(env, "risk_policy");
        var theta1 = Nullish(env) ? Undef : G(riskPolicy, "theta1");
        var theta2 = Nullish(env) ? Undef : G(riskPolicy, "theta2");
        var risk = new D();
        if (!IsUndef(rr)) risk["r"] = rr;
        var tier = G(rt, "t");
        if (!IsUndef(tier)) risk["tier"] = tier;
        var proof = G(rt, "proof");
        if (!IsUndef(proof)) risk["proof"] = proof;
        var opt = G(rt, "optimisticAllowed");
        if (!IsUndef(opt)) risk["optimisticAllowed"] = opt;
        risk["band"] = RiskBand(rr, theta1, theta2, tier);
        if (Truthy(env))
        {
            var t1 = G(G(env, "risk_policy"), "theta1"); var t2 = G(G(env, "risk_policy"), "theta2");
            if (!IsUndef(t1)) risk["theta1"] = t1;
            if (!IsUndef(t2)) risk["theta2"] = t2;
        }

        // ---- admission / budget ----
        var kappa = Nullish(env) ? Undef : G(riskPolicy, "kappa");
        double? costVal = IsUndef(kappa) ? null : Risk.Cost(IsNumber(rr) ? ToN(rr) : double.NaN, IsNumber(kappa) ? ToN(kappa) : double.NaN);
        var budgetDepleted = reasons.Any(r => Includes(r, "budget depleted"));
        string path;
        if (admitted) path = $"auto-admitted at t={S(tier)} ({S(proof)}); metered";
        else if (!Truthy(release)) path = "guardian share withheld — policy not satisfied (no autonomous or guardian path)";
        else if (budgetDepleted) path = "trust budget cannot cover the cost — step-up to t=3 (human recharge) required";
        else path = $"step-up to t={S(tier)} ({S(proof)}) co-signature required";
        var admission = new D { ["admit"] = admitted };
        var nsu = Q(decision, "needStepUp");
        if (!IsUndef(nsu)) admission["needStepUp"] = nsu;
        if (!IsUndef(release)) admission["releaseGuardianShare"] = release;
        var bud = Q(decision, "budget");
        if (!IsUndef(bud)) admission["budget"] = bud;
        admission["path"] = path;
        if (costVal != null) admission["cost"] = double.IsFinite(costVal.Value) ? NumOf(costVal.Value) : null;
        if (!IsUndef(kappa)) admission["kappa"] = kappa;

        // ---- the single decisive reason ----
        D? decisive = null;
        if (!admitted)
        {
            if (!Truthy(grant.GetValueOrDefault("granted")))
                decisive = new D { ["reason"] = Nullish(Gd(grant, "reason")) ? "action not permitted by the envelope predicates (default-deny)" : S(grant["reason"]), ["remedy"] = "grant a predicate that permits this verb+resource (and satisfies its where bound)." };
            else
            {
                var firstFailed = caveats.FirstOrDefault(c => !Truthy(c.GetValueOrDefault("satisfied")));
                if (firstFailed != null)
                {
                    decisive = new D { ["reason"] = $"caveat '{firstFailed["type"]}' narrowed the authority away: {firstFailed["detail"]}" };
                    if (firstFailed.GetValueOrDefault("remedy") is string fr && fr.Length > 0) decisive["remedy"] = fr;
                }
                else if (budgetDepleted)
                    decisive = new D { ["reason"] = $"risk {NumText(rr)} is admissible but the trust budget cannot cover cost κ·r{(costVal != null ? "=" + NumTextD(costVal.Value) : "")}", ["remedy"] = "recharge the budget with a human co-sign, or lower the action risk." };
                else
                    decisive = new D
                    {
                        ["reason"] = $"risk {NumText(rr)} exceeds the auto threshold → step-up to t={S(tier)} ({S(proof)})",
                        ["remedy"] = tier is Num tn && JsJson.ToJsNumber(tn) == 3 ? "obtain a human step-up co-signature." : "obtain the guardian/principal co-signature for this tier.",
                    };
            }
        }

        string summary;
        if (admitted)
            summary = $"Auto-admitted: {(Truthy(grant.GetValueOrDefault("predicate")) ? "predicate #" + S(grant.GetValueOrDefault("predicateIndex")) : "policy")} grants it, all caveats held, risk r={NumText(rr)} is in the t={S(tier)} band and the budget covers it.";
        else if (decisive != null)
            summary = $"{(verdict == "deny" && disposition == "denied" ? "Denied" : "Needs step-up")}: {decisive["reason"]}";
        else summary = $"Not auto-admitted (t={S(tier)}).";

        var cleanedCaveats = caveats.Select(c => { var d = new D(c); d["detail"] = CleanText(c["detail"]); return (object?)d; }).ToList();
        D? cleanedDecisive = null;
        if (decisive != null) { cleanedDecisive = new D(decisive); cleanedDecisive["reason"] = CleanText(decisive["reason"]); }

        var res = new D
        {
            ["kind"] = "decision",
            ["verdict"] = verdict,
            ["disposition"] = disposition,
            ["grant"] = grant,
            ["caveats"] = cleanedCaveats,
            ["risk"] = risk,
            ["admission"] = admission,
        };
        if (cleanedDecisive != null) res["decisive"] = cleanedDecisive;
        res["reasons"] = reasons.Select(r => (object?)CleanText(S(r))).ToList();
        res["summary"] = CleanText(summary);
        return res;
    }

    /// <summary>ctx.chain?.[0]?.caveats.length ?? 0 (a root capability with no caveats member throws).</summary>
    static int RootCapCaveatCount(object? chain)
    {
        var root = Qi(chain, 0);
        if (Nullish(root)) return 0;
        var cavs = G(root, "caveats");
        var len = Len(cavs);
        return len is Num n ? (int)JsJson.ToJsNumber(n) : 0;
    }

    static string JoinVerb(object? verb) => verb is L l ? string.Join("|", l.Select(x => x == null ? "" : S(x))) : S(verb);

    /// <summary>Plain-text rendering of an explanation returned by <see cref="ExplainDecision(object?, object?, object?)"/>.</summary>
    public static string DecisionToText(D e)
    {
        var lines = new List<string>
        {
            $"PCA decision — {((string)e["verdict"]!).ToUpperInvariant()} ({e["disposition"]})",
            (string)e["summary"]!,
            "",
        };
        var grant = (D)e["grant"]!;
        if (Truthy(grant.GetValueOrDefault("granted")) && Truthy(grant.GetValueOrDefault("predicate")))
        {
            var p = grant["predicate"];
            var res = Q(p, "resource");
            lines.Add($"  authority : predicate #{S(Gd(grant, "predicateIndex"))} of grant {Short(Gd(grant, "capabilityId"))} grants {JoinVerb(Q(p, "verb"))} on {(Nullish(res) ? "*" : S(res))}");
            lines.Add($"              where {S(Gd(grant, "where"))}");
        }
        else
        {
            var reason = grant.GetValueOrDefault("reason");
            lines.Add($"  authority : NOT granted — {(Nullish(reason) ? "no predicate permits this action" : S(reason))}");
        }

        var caveats = (L)e["caveats"]!;
        if (caveats.Count == 0) lines.Add("  caveats   : none");
        else
            foreach (var c in caveats.Cast<D>())
            {
                var sat = Truthy(c.GetValueOrDefault("satisfied"));
                lines.Add($"  caveat {(sat ? "✓" : "✗")}  : {c["detail"]}{(c["delegated"] is true ? " [delegated]" : "")}");
                if (!sat && c.GetValueOrDefault("remedy") is string r && r.Length > 0) lines.Add($"              ↳ fix: {r}");
            }

        var risk = (D)e["risk"]!;
        lines.Add($"  risk      : {risk["band"]}; proof={S(Gd(risk, "proof"))}, optimistic={S(Gd(risk, "optimisticAllowed"))}");
        var a = (D)e["admission"]!;
        var costStr = a.ContainsKey("cost") ? $", cost κ·r={NumText(a["cost"])} (κ={NumText(Gd(a, "kappa"))})" : "";
        lines.Add($"  budget    : {a["path"]}{costStr}; B after={NumText(G(Gd(a, "budget"), "B"))}");

        if (e.GetValueOrDefault("decisive") is D dec)
        {
            lines.Add("");
            lines.Add($"  ◀ DECISIVE: {dec["reason"]}");
            if (dec.GetValueOrDefault("remedy") is string r && r.Length > 0) lines.Add($"      ↳ fix: {r}");
        }
        return string.Join("\n", lines);
    }

    // ---- explainChain -------------------------------------------------------------------------------------------------------

    static string HopNarrowedSummary(bool isRoot, List<object?> added)
    {
        var bits = new List<string>();
        foreach (var cv in added)
        {
            var (type, rest) = CaveatParts(cv);
            if (type == "envelope")
            {
                var predicates = rest.GetValueOrDefault("predicates") is L pl ? pl.Count : 0;
                var inner = rest.GetValueOrDefault("caveats") is L cl ? cl.Count : 0;
                bits.Add($"envelope ({predicates} predicate(s), {inner} caveat(s))");
            }
            else if (IsBudgetAlloc(cv)) bits.Add($"budget_alloc(B_sub={NumText(((D)cv!)["limit"])})");
            else
            {
                var bound = ValueSummary(rest);
                bits.Add(bound.Length > 0 ? $"+{type}({bound})" : $"+{type}");
            }
        }
        if (bits.Count == 0) return isRoot ? "root grant (no caveats)" : "rebind only (no new caveats)";
        return (isRoot ? "grants " : "narrows: ") + string.Join(", ", bits);
    }

    public static List<D> BudgetAllocNodes(object? chain)
    {
        var outp = new List<D>();
        if (chain is not L ch || ch.Count == 0) return outp;
        var leaf = ch[^1];
        if (G(leaf, "caveats") is not L lc) return outp;
        int hop = 0;
        for (int ci = 0; ci < lc.Count; ci++)
        {
            while (hop < ch.Count - 1 && CaveatCountOf(ch[hop]) <= ci) hop++;
            var cv = lc[ci];
            if (!(cv is D cd) || !(cd.GetValueOrDefault("type") is string t && t == "budget_alloc")) continue;
            if (cd.GetValueOrDefault("limit") is not Num ln || JsJson.ToJsNumber(ln) is var lim && (!double.IsFinite(lim) || lim < 0)) continue;
            var introducing = ch[hop];
            var id = G(introducing, "id");
            var node = new D
            {
                ["nodePath"] = Pca.HashCanonical(new D { ["d"] = "atlas-pca/budget-node/v1", ["cap"] = id, ["i"] = new Num(ci.ToString(System.Globalization.CultureInfo.InvariantCulture)) }),
            };
            if (!IsUndef(id)) node["capId"] = id;
            var holder = G(introducing, "holder");
            if (!IsUndef(holder)) node["holder"] = holder;
            node["depth"] = new Num(hop.ToString(System.Globalization.CultureInfo.InvariantCulture));
            node["caveatIndex"] = new Num(ci.ToString(System.Globalization.CultureInfo.InvariantCulture));
            node["limit"] = ln;
            outp.Add(node);
        }
        return outp;
    }

    /// <summary>(chain[hop].caveats?.length ?? 0)</summary>
    static int CaveatCountOf(object? cap)
    {
        var cavs = G(cap, "caveats");
        return Nullish(cavs) ? 0 : Len(cavs) is Num n ? (int)JsJson.ToJsNumber(n) : 0;
    }

    static D ChainInner(object? chain)
    {
        var hops = new L();
        var safe = chain as L ?? new L();
        for (int i = 0; i < safe.Count; i++)
        {
            var cap = safe[i];
            if (!Truthy(cap)) continue;
            var isRoot = i == 0;
            var parent = i > 0 ? safe[i - 1] : Undef;
            int parentLen = Truthy(parent) && Q(parent, "caveats") is L pc ? pc.Count : 0;
            var own = Q(cap, "caveats") as L ?? new L();
            var added = isRoot ? own : own.Count >= parentLen ? own.Skip(parentLen).ToList() : new L();
            var budgetCv = added.FirstOrDefault(IsBudgetAlloc);
            var hop = new D { ["index"] = new Num(i.ToString(System.Globalization.CultureInfo.InvariantCulture)), ["isRoot"] = isRoot };
            var issuer = Q(cap, "issuer"); var holder = Q(cap, "holder");
            if (!IsUndef(issuer)) hop["issuer"] = issuer;
            if (!IsUndef(holder)) hop["holder"] = holder;
            hop["issuerShort"] = Short(issuer);
            hop["holderShort"] = Short(holder);
            var alg = Q(cap, "alg"); hop["alg"] = Nullish(alg) ? "ed25519" : alg;
            hop["addedCaveats"] = added;
            hop["addedCaveatTypes"] = added.Select(cv => (object?)CaveatParts(cv).Type).ToList();
            hop["narrowed"] = CleanText(HopNarrowedSummary(isRoot, added));
            if (budgetCv != null) hop["budgetAlloc"] = ((D)budgetCv)["limit"];
            hops.Add(hop);
        }

        var root = Qi(safe, 0);
        var leaf = safe.Count > 0 ? safe[^1] : Undef;
        var nodes = BudgetAllocNodes(safe);
        var summary = safe.Count == 0
            ? "empty chain (no authority)"
            : $"{Short(Q(root, "issuer"))} (principal) delegated through {safe.Count - 1} hop(s) to the acting holder {Short(Q(leaf, "holder"))}; {nodes.Count} budget node(s).";
        var d = new D { ["kind"] = "chain", ["depth"] = new Num(safe.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)), ["hops"] = hops };
        var ri = Q(root, "issuer"); var lh = Q(leaf, "holder");
        if (!IsUndef(ri)) d["rootIssuer"] = ri;
        if (!IsUndef(lh)) d["leafHolder"] = lh;
        d["budgetNodes"] = nodes.Cast<object?>().ToList();
        d["summary"] = summary;
        return d;
    }

    /// <summary>Render a capability delegation chain as an ordered attenuation trace: issuer to holder per hop and what each hop narrowed. With
    /// <paramref name="verify"/> the chain is also checked (<paramref name="expectedRootIssuer"/> pins the root); without it the trace shows what
    /// the chain CLAIMS. Read-only.</summary>
    public static D ExplainChain(object? chain, bool verify = false, string? expectedRootIssuer = null)
    {
        var o = ChainInner(chain);
        if (!verify) return o;
        bool ok = false;
        string? reason = "chain is not an array";
        try
        {
            if (chain is L cl)
            {
                var res = Pca.VerifyChain(cl, expectedRootIssuer, expectedRootIssuer != null);
                ok = res.Ok;
                reason = res.Ok ? null : res.Why;
            }
        }
        catch (Exception) { reason = "chain could not be verified"; }
        var v = new D { ["ok"] = ok };
        if (reason != null) v["reason"] = CleanText(reason);
        // the verification member is set first on the reference class; order is not significant in the JSON tree
        o["verification"] = v;
        return o;
    }

    /// <summary>Plain-text rendering of an explanation returned by <see cref="ExplainChain"/>.</summary>
    public static string ChainToText(D e)
    {
        var lines = new List<string> { $"PCA delegation chain — {NumText(e["depth"])} hop(s) (attenuation trace)" };
        var ver = e.GetValueOrDefault("verification") as D;
        lines.Add(ver == null ? "UNVERIFIED: this trace shows what the chain claims; no signature or link was checked."
            : ver["ok"] is true ? "verified: signatures, links and caveat rules hold."
            : $"NOT VALID: {(ver.GetValueOrDefault("reason") is string r ? r : "the chain failed verification")}");
        lines.Add((string)e["summary"]!);
        lines.Add("");
        foreach (var h in ((L)e["hops"]!).Cast<D>())
        {
            var tag = h["isRoot"] is true ? "root " : "deleg";
            lines.Add($"  #{NumText(h["index"])} {tag} {h["issuerShort"]} ──▶ {h["holderShort"]}   {h["narrowed"]}");
        }
        var nodes = (L)e["budgetNodes"]!;
        if (nodes.Count > 0)
        {
            var tree = string.Join(" → ", nodes.Cast<D>().Select(n => $"depth {NumText(n["depth"])} B_sub={NumText(n["limit"])}"));
            lines.Add("");
            lines.Add($"  budget subtree: {tree}");
        }
        return string.Join("\n", lines);
    }
}
