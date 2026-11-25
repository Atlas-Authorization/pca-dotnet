using System.Globalization;
using System.Text;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Compliance;

/// <summary>Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use
/// (EU AI Act Art. 12 / 50, ISO/IEC 42001 clauses, SOC 2 CC6), plus the console-activity framework report (EU AI Act, SOC 2, GDPR).
/// Inputs are parsed JSON trees; property reads follow JavaScript semantics (an absent member is <see cref="InteropJs.JsX.Undef"/>,
/// reading through null throws) so the reports match the reference text for text. An evidence mapping, not a legal certification.</summary>
public static partial class PcaCompliance
{
    public static readonly IReadOnlyList<string> ComplianceFrameworks = new[] { "eu-ai-act", "iso-42001", "soc2" };
    static readonly string[] FrameworkIds = { "eu-ai-act", "soc2", "gdpr" };

    // ---- JavaScript semantics ----
    static object? Own(object? o, string k) => o is D m ? (m.TryGetValue(k, out var v) ? v : Undef) : Undef;
    static bool Nullish(object? v) => v == null || ReferenceEquals(v, Undef);
    static bool IsNum(object? v) => IntentJs.NumOf(v) != null;
    static bool Finite(object? v) => IntentJs.IsFinite(v);
    static double Dbl(object? v) => IntentJs.NumOf(v)!.Value;

    static bool Truthy(object? v)
    {
        if (v == null || ReferenceEquals(v, Undef)) return false;
        if (v is bool b) return b;
        if (v is string s) return s.Length > 0;
        return IntentJs.NumOf(v) is double d ? !(d == 0 || double.IsNaN(d)) : true;
    }

    static double ToNum(object? v) => ReferenceEquals(v, Undef) ? double.NaN : JsJson.ToJsNumber(v);

    static bool Gt(object? a, object? b) =>
        a is string x && b is string y ? string.CompareOrdinal(x, y) > 0 : ToNum(a) > ToNum(b);

    static string NumStr(object? v) => JsNumString(Dbl(v));

    static double JsRound(double v)
    {
        var r = Math.Floor(v);
        return v - r >= 0.5 ? r + 1 : r;
    }

    static bool IsInteger(object? v) => Finite(v) && Dbl(v) == Math.Floor(Dbl(v));

    /// <summary><c>v.length</c> (string: UTF-16 units; array: items); null when undefined; throws on null / undefined.</summary>
    static int? Length(object? v)
    {
        if (Nullish(v)) throw TypeError($"cannot read properties of {(v == null ? "null" : "undefined")} (reading 'length')");
        return v switch { string s => s.Length, L l => l.Count, _ => null };
    }

    /// <summary>A <c>Set</c> with SameValueZero identity: primitives by value, objects each distinct.</summary>
    sealed class JsSet
    {
        readonly HashSet<string> keys = new(StringComparer.Ordinal);
        int n;
        public void Add(object? v)
        {
            if (ReferenceEquals(v, Undef)) keys.Add("u");
            else if (v == null) keys.Add("z");
            else if (v is bool b) keys.Add(b ? "bt" : "bf");
            else if (v is string s) keys.Add("s" + s);
            else if (IntentJs.NumOf(v) is double d) keys.Add(double.IsNaN(d) ? "nNaN" : "n" + JsNumString(d == 0 ? 0 : d));
            else keys.Add("o" + (++n).ToString(CultureInfo.InvariantCulture));
        }
        public int Size => keys.Count;
    }

    static string Pretty(object? v, string b = "")
    {
        if (v is L l)
        {
            if (l.Count == 0) return "[]";
            var ind = b + "  ";
            return "[\n" + string.Join(",\n", l.Select(x => ind + (ReferenceEquals(x, Undef) ? "null" : Pretty(x, ind)))) + "\n" + b + "]";
        }
        if (v is D m)
        {
            var keys = IntentJs.JsKeys(m.Keys).Where(k => !ReferenceEquals(m[k], Undef)).ToList();
            if (keys.Count == 0) return "{}";
            var ind = b + "  ";
            return "{\n" + string.Join(",\n", keys.Select(k => ind + JsJson.Quote(k) + ": " + Pretty(m[k], ind))) + "\n" + b + "}";
        }
        return JsJson.Stringify(v);
    }

    static string Iso(object? ms)
    {
        if (!Finite(ms)) return "(unknown time)";
        try { return ToIsoString(ms); }
        catch (ArgumentException) { return "(unrepresentable time)"; }
    }

    static D Ts(object? ms) => new() { ["epochMs"] = ms, ["iso"] = Iso(ms) };

    static long NowMs(Func<long>? clock) => clock != null ? clock() : AtlasPca.ReplayClock.NowMs();

    /// <summary>Abbreviate a long key for display (UTF-16 units).</summary>
    static string Short(object? key, int n = 12)
    {
        if (key is not string s || s.Length == 0) return "(none)";
        return s.Length <= n + 1 ? s : s[..n] + "…";
    }

    static string Numstr(object? x)
    {
        if (!Finite(x)) return Str(x);
        if (IsInteger(x)) return NumStr(x);
        return JsNumString(JsRound(Dbl(x) * 1e4) / 1e4);
    }

    static string Tpl(object? v) => Str(v);

    static string I(int n) => n.ToString(CultureInfo.InvariantCulture);

    // ---- AuditEvent ----
    static bool IsBudgetAlloc(object? cv) =>
        cv is D m && m.TryGetValue("type", out var t) && t is string ts && ts == "budget_alloc"
        && m.TryGetValue("limit", out var lim) && Finite(lim) && Dbl(lim) >= 0;

    /// <summary>A bounded, human-readable rendering of one caveat.</summary>
    public static string DescribeCaveat(object? cv)
    {
        if (cv is not D m || !m.TryGetValue("type", out var tv) || tv is not string type) return "(malformed caveat)";
        if (type == "envelope")
        {
            m.TryGetValue("predicates", out var preds);
            m.TryGetValue("caveats", out var inner);
            return $"policy envelope ({I(preds is L pl ? pl.Count : 0)} predicate(s), {I(inner is L il ? il.Count : 0)} caveat(s))";
        }
        if (IsBudgetAlloc(cv)) return "budget allocation ≤ " + Numstr(m["limit"]);
        var parts = new List<string>();
        foreach (var k in IntentJs.JsKeys(m.Keys).Take(8))
        {
            if (k == "type") continue;
            var v = m[k];
            parts.Add(k + "=" + (v is D or L ? JsJson.Stringify(v) : Numstr(v)));
        }
        return parts.Count > 0 ? type + "(" + string.Join(", ", parts) + ")" : type;
    }

    /// <summary>The delegation hops: issuer to holder and the caveats each hop ADDED (append-only diff against its parent).</summary>
    public static L BuildDelegationHops(object? chain)
    {
        var safe = chain as L ?? new L();
        var hops = new L();
        for (int i = 0; i < safe.Count; i++)
        {
            var cap = safe[i];
            if (!Truthy(cap)) continue;
            var isRoot = i == 0;
            var parent = i > 0 ? safe[i - 1] : null;
            var pcv = Truthy(parent) ? Own(parent, "caveats") : Undef;
            var parentLen = pcv is L pl ? pl.Count : 0;
            var own = Own(cap, "caveats") as L ?? new L();
            var added = isRoot ? own : own.Count >= parentLen ? own.GetRange(parentLen, own.Count - parentLen) : new L();
            var scope = new L();
            foreach (var c in added) scope.Add(DescribeCaveat(c));
            var budgetCv = added.FirstOrDefault(IsBudgetAlloc);
            var issuer = Own(cap, "issuer");
            var holder = Own(cap, "holder");
            var joined = string.Join("; ", scope);
            var narrative = isRoot
                ? $"Principal {Short(issuer)} granted authority to {Short(holder)}{(scope.Count > 0 ? " under: " + joined : "")}."
                : $"{Short(issuer)} delegated to {Short(holder)}{(scope.Count > 0 ? ", narrowing scope: " + joined : " (rebind only, no new constraints)")}.";
            var hop = new D { ["index"] = i, ["isRoot"] = isRoot, ["scope"] = scope, ["caveats"] = added, ["narrative"] = narrative };
            if (!ReferenceEquals(issuer, Undef)) hop["issuer"] = issuer;
            if (!ReferenceEquals(holder, Undef)) hop["holder"] = holder;
            if (budgetCv != null) hop["budgetAlloc"] = ((D)budgetCv)["limit"];
            hops.Add(hop);
        }
        return hops;
    }

    /// <summary>The signed co-signature (human override) of a PCActn's threshold signature, if any (null: none).</summary>
    public static D? BuildHumanOverride(object? threshold, object? requiredTier, object? thresholdCheck)
    {
        var sh = Truthy(threshold) ? Own(threshold, "shares") : Undef;
        var shares = sh as L ?? new L();
        if (shares.Count == 0) return null;
        // threshold is outside the signed body: never report a signed approval (or name approvers) from unverified shares
        if (!(thresholdCheck is string tc && tc == "pass"))
            return new D
            {
                ["humanApproved"] = false, ["approvers"] = new L(), ["guardianCosigners"] = new L(), ["roles"] = new L(), ["requiredTier"] = requiredTier,
                ["narrative"] = $"{I(shares.Count)} co-signature share(s) were presented but NOT verified (threshold check: {(Nullish(thresholdCheck) ? "absent" : Tpl(thresholdCheck))}); no human approval is recorded.",
            };
        var approvers = new L(); var guardians = new L(); var roles = new L();
        foreach (var s in shares)
        {
            if (!Truthy(s) || Own(s, "role") is not string role) continue;
            roles.Add(role);
            var pk = ((D)s!).GetValueOrDefault("publicKey");
            if (role == "principal" && pk is string) approvers.Add(pk);
            if (role == "guardian" && pk is string) guardians.Add(pk);
        }
        var approved = approvers.Count > 0;
        var narrative = approved
            ? $"Step-up approved by a signed human co-signature from principal {Short(approvers[0])}{(guardians.Count > 0 ? $" (plus {I(guardians.Count)} guardian co-sign)" : "")} at tier t={Tpl(requiredTier)}."
            : $"Co-signed by {I(guardians.Count)} guardian share(s) at tier t={Tpl(requiredTier)} (no human principal signature present).";
        return new D { ["humanApproved"] = approved, ["approvers"] = approvers, ["guardianCosigners"] = guardians, ["roles"] = roles, ["requiredTier"] = requiredTier, ["narrative"] = narrative };
    }

    static object? FirstReasonOr(object? decision, string fallback)
    {
        var rs = Own(decision, "reasons") as L ?? new L();
        return rs.Count > 0 && rs[0] is string ? rs[0] : fallback;
    }

    /// <summary>The auditor-facing outcome from the proof's verification and the Policy-VM decision.</summary>
    public static (string Outcome, object? Reason) ResolveOutcome(object? verify, object? decision)
    {
        if (!Truthy(verify) || !(Own(verify, "allow") is bool a && a))
        {
            var r = Opt(verify, "reason");
            return ("deny", Nullish(r) ? "proof failed verification" : r);
        }
        if (!Truthy(decision)) return ("allow", "proof verified; no policy decision supplied");
        if (Truthy(Own(decision, "admit"))) return ("allow", FirstReasonOr(decision, "auto-admitted within policy and budget"));
        if (Truthy(Own(decision, "releaseGuardianShare"))) return ("step-up", FirstReasonOr(decision, "policy satisfied but a co-signature is required"));
        return ("deny", FirstReasonOr(decision, "policy did not release authority (default-deny)"));
    }

    static string SafeDigest(object? p)
    {
        if (ReferenceEquals(p, Undef)) return "(undigestible)";
        try { return Pca.HashCanonical(p); }
        catch (Exception) { return "(undigestible)"; }
    }

    /// <summary>A normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision. <paramref name="inp"/> is
    /// <c>{pcactn, verify, decision?, now?, session?}</c>; <c>now</c> (epoch ms) defaults to the clock.</summary>
    public static D ToAuditEvent(object? inp, Func<long>? clock = null)
    {
        var p = At(inp, "pcactn");
        var verify = Own(inp, "verify");
        if (Nullish(verify)) verify = new D { ["allow"] = false, ["checks"] = new D() };
        var decision = Own(inp, "decision");
        var now = Own(inp, "now");
        if (Nullish(now)) now = new Num(NowMs(clock).ToString(CultureInfo.InvariantCulture));
        var chain = Opt(p, "cap_chain") as L;
        var hops = BuildDelegationHops(chain);
        var leaf = chain != null && chain.Count > 0 ? chain[^1] : Undef;
        var root = chain != null && chain.Count > 0 ? chain[0] : Undef;
        var (outcome, reason) = ResolveOutcome(verify, decision);
        var tier = Opt(Opt(decision, "requiredThreshold"), "t");
        var requiredTier = Nullish(tier) ? new Num("1") : tier;
        var checksRaw = Own(verify, "checks");
        var human = BuildHumanOverride(Opt(p, "threshold"), requiredTier, Opt(checksRaw, "threshold"));
        var checks = Nullish(checksRaw) ? new D() : checksRaw;
        var cryptoOk = Own(checks, "wire") is string w && w == "pass" && Own(checks, "leaf_signature") is string ls && ls == "pass";

        var action = Opt(p, "action");
        var verb = Opt(action, "verb") is string vs ? vs : "(unknown verb)";
        var resource = Opt(action, "resource") is string rs ? rs : "(unknown resource)";
        var grantRef = Opt(p, "grant_ref") is string gr ? gr : "(none)";
        var sig = Opt(p, "sig"); var alg = Opt(p, "alg"); var planRoot = Opt(Opt(p, "plan"), "root");
        var pd = Opt(action, "params_digest"); var counter = Opt(p, "counter"); var nonce = Opt(p, "nonce");
        var evidence = new D
        {
            ["pcactnDigest"] = SafeDigest(p),
            ["leafSignature"] = sig is string ss ? ss : "(unsigned)",
            ["signatureSuite"] = alg is string asu ? asu : "ed25519",
            ["planRoot"] = planRoot is string pr ? pr : "(none)",
            ["paramsDigest"] = pd is string pds ? pds : "(none)",
            ["grantRef"] = grantRef,
            ["counter"] = IsNum(counter) ? counter : new Num("-1"),
            ["cryptographicallyVerifiable"] = cryptoOk,
        };
        if (nonce is string ns) evidence["nonce"] = ns;

        var risk = new D();
        if (Truthy(decision))
        {
            var rt = Own(decision, "requiredThreshold");
            foreach (var (key, val) in new[] { ("r", Own(decision, "r")), ("tier", Opt(rt, "t")), ("proof", Opt(rt, "proof")), ("budget", Own(decision, "budget")) })
                if (!ReferenceEquals(val, Undef)) risk[key] = val;
        }

        var word = outcome == "allow" ? "ALLOWED" : outcome == "deny" ? "DENIED" : "STEP-UP";
        var narrative = $"Agent {Short(Opt(leaf, "holder"))} {word} to {verb} on {resource} ({I(hops.Count)}-hop chain rooted at principal {Short(Opt(root, "issuer"))}; "
            + (cryptoOk ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (human != null && human["humanApproved"] is true ? "; human-signed step-up" : "") + $"). {Tpl(reason)}";

        var holder = Opt(leaf, "holder");
        var principal = Opt(root, "issuer");
        var sess = Own(inp, "session");
        var rc = Opt(action, "reversibility_class");
        var iat = Opt(p, "iat"); var exp = Opt(p, "exp");
        var agent = new D { ["holder"] = holder is string hs ? hs : "(none)", ["session"] = Nullish(sess) ? grantRef : sess };
        if (principal is string prs) agent["principal"] = prs;
        var ev = new D
        {
            ["schema"] = "atlas-pca/audit-event/v1",
            ["recordedAt"] = Ts(now),
            ["agent"] = agent,
            ["delegation"] = new D { ["depth"] = Math.Max(0, hops.Count - 1), ["hops"] = hops },
            ["action"] = new D { ["verb"] = verb, ["resource"] = resource, ["paramsDigest"] = evidence["paramsDigest"], ["reversibilityClass"] = rc is string rcs ? rcs : "(unknown)", ["summary"] = verb + " on " + resource },
            ["decision"] = new D { ["outcome"] = outcome, ["reason"] = reason, ["proofVerified"] = Own(verify, "allow") is bool pv && pv, ["checks"] = checks },
            ["risk"] = risk,
            ["timestamps"] = new D { ["issuedAt"] = Ts(IsNum(iat) ? iat : double.NaN), ["expiresAt"] = Ts(IsNum(exp) ? exp : double.NaN) },
            ["evidence"] = evidence,
            ["narrative"] = narrative,
        };
        if (human != null) ev["humanOverride"] = human;
        return ev;
    }

    // ---- control mappings ----
    static void AssertFramework(object? framework)
    {
        if (!(framework is string s && ComplianceFrameworks.Contains(s)))
            throw new ArgumentException($"pca-compliance: unknown framework '{Tpl(framework)}' (have: {string.Join(", ", ComplianceFrameworks)})");
    }

    /// <summary>The whole control-mapping table.</summary>
    public static L ControlMappings() => Table().Cast<object?>().ToList();

    /// <summary>The control mappings of one framework (throws on an unknown framework).</summary>
    public static L ControlMappings(object? framework)
    {
        AssertFramework(framework);
        return Table().Where(m => (string)m["framework"]! == (string)framework!).Cast<object?>().ToList();
    }

    /// <summary>The framework ids and the whole table, as the reference exports them.</summary>
    public static D Constants() => new()
    {
        ["COMPLIANCE_FRAMEWORKS"] = ComplianceFrameworks.Cast<object?>().ToList(),
        ["CONTROL_MAPPINGS"] = ControlMappings(),
    };
}
