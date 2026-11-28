// Agent-native authority primitives (the TypeScript agent-native module): uncertainty attestation, rationale binding, the semantic
// firewall, capability introspection and authority leases. Pure and deterministic: no clocks (callers pass now), no randomness
// except the default rationale salt. The verifying and evaluating functions are total and fail closed; only the authoring helpers
// (BindRationale, ToolSchemaCaveat, GrantLease, PredicatesCaveat) throw ArgumentException. Values are JSON trees (Dictionary / List /
// string / Num / bool / null), the same shape as the reference, so artefacts round-trip with every other implementation.
// Signers.SignCaution / Signers.SignHeartbeat sign; Pca.ValidateArgSchema / Pca.EvaluateToolSchema(Json) check tool schemas.
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class Pca
{
    /// <summary>Evaluate a JSON tool call <c>{tool, args, toolSignature?, toolSignatureDigest?}</c> against a <c>tool_schema</c> caveat, with the reference's
    /// presence rules: a member that is PRESENT (even JSON null) is checked, an absent one is not (the typed <see cref="ToolCall"/> reads null as absent).
    /// Same reasons as <see cref="EvaluateToolSchema"/>. Never throws.</summary>
    public static (bool Ok, string? Reason) EvaluateToolSchemaJson(object? caveat, object? call)
    {
        try
        {
            if (caveat is not JD cv || IntentJs.Get(cv, "type") is not "tool_schema" || IntentJs.Get(cv, "tool") is not string tool || tool.Length == 0)
                return (false, "malformed tool_schema caveat");
            var verr = ValidateArgSchema(IntentJs.Get(cv, "schema"));
            if (verr != null) return (false, "malformed tool_schema caveat: " + verr);
            var schema = (JD)cv["schema"]!;
            if (!Equals(HashCanonical(schema), IntentJs.Get(cv, "schema_digest"))) return (false, "schema digest mismatch");
            var sig = IntentRevocation.JsText(IntentJs.Get(cv, "signature_digest"), cv.ContainsKey("signature_digest"));
            if (!Equals(HashCanonical(new JD { ["tool"] = tool, ["signature_digest"] = sig, ["schema"] = schema }), IntentJs.Get(cv, "binding_digest")))
                return (false, "binding digest mismatch");
            if (call is not JD c || c.GetValueOrDefault("tool") is not string ctool || c.GetValueOrDefault("args") is not JD args) return (false, "malformed call");
            if (ctool != tool) return (false, $"tool {Show(ctool)} not authorized");
            if (c.TryGetValue("toolSignature", out var ts) && !Equals(HashCanonical(ts), IntentJs.Get(cv, "signature_digest")))
                return (false, "tool signature differs from the authorized signature");
            if (c.TryGetValue("toolSignatureDigest", out var td) && !Equals(td, IntentJs.Get(cv, "signature_digest")))
                return (false, "signed tool_binding differs from the authorized tool signature");
            var e = CheckObject((JD)schema["props"]!, IntentJs.Get(schema, "required"), args, "args", 1, new Budget());
            return e != null ? (false, e) : (true, null);
        }
        catch (Exception) { return (false, "evaluation error (fail closed)"); }
    }

    /// <summary>The reference's <c>show</c>: a JSON-quoted key cut to 48 UTF-16 code units plus an ellipsis.</summary>
    internal static string ShowKey(string k) => Show(k);
}

/// <summary>The agent-native primitives. <see cref="RenewCapabilityLease"/> is the reference's pure <c>renewLease(lease, heartbeat, now)</c>; the grants
/// registry keeps its own renewal.</summary>
public static class AgentNative
{
    // ---- constants ----

    public const string CaveatEnvelope = "envelope";
    public const string CaveatExpires = "expires";
    public const string CaveatNotBefore = "not_before";
    public const string CaveatRate = "rate";
    public const string CaveatMaxBlastRadius = "max_blast_radius";
    public const string CaveatReversibilityMax = "reversibility_max";
    public const string CaveatDelegationDepth = "delegation_depth";
    public const string CaveatPredicates = "predicates";
    public const string CaveatToolSchema = "tool_schema";
    public const string CaveatMaxSpend = "max_spend";
    public const int MaxCautionReasonLen = Signers.MaxCautionReasonLength;
    public const int MinSaltBytes = 16;
    public const int MinSaltDistinctBytes = 8;
    public const int MaxRationaleLen = 8192;
    public const int MaxSchemaDepth = Pca.MaxSchemaDepth;
    public const int MaxSchemaNodes = Pca.MaxSchemaNodes;
    public const int MaxObjectProps = Pca.MaxObjectProps;
    public const int MaxEnumValues = Pca.MaxEnumValues;
    public const int DefaultMaxArrayItems = Pca.DefaultMaxArrayItems;
    public const int AbsoluteMaxArrayItems = Pca.AbsoluteMaxArrayItems;
    public const int DefaultMaxStringLen = Pca.DefaultMaxStringLen;
    public const int AbsoluteMaxStringLen = Pca.AbsoluteMaxStringLen;
    public const int MaxValueNodes = Pca.MaxValueNodes;
    /// <summary>Max tolerated skew between a heartbeat's <c>at</c> (or the clock vs the last renewal) and server <c>now</c>.</summary>
    public const long HeartbeatSkewMs = 30_000;
    /// <summary>Longest lease ttl accepted (7 days).</summary>
    public const long MaxLeaseTtlMs = 7L * 24 * 3_600_000;

    /// <summary>Every constant above by its reference name (the corpus <c>constants</c> case).</summary>
    public static JD Constants() => new()
    {
        ["CAVEAT_ENVELOPE"] = CaveatEnvelope, ["CAVEAT_EXPIRES"] = CaveatExpires, ["CAVEAT_NOT_BEFORE"] = CaveatNotBefore, ["CAVEAT_RATE"] = CaveatRate,
        ["CAVEAT_MAX_BLAST_RADIUS"] = CaveatMaxBlastRadius, ["CAVEAT_REVERSIBILITY_MAX"] = CaveatReversibilityMax,
        ["CAVEAT_DELEGATION_DEPTH"] = CaveatDelegationDepth, ["CAVEAT_PREDICATES"] = CaveatPredicates, ["CAVEAT_TOOL_SCHEMA"] = CaveatToolSchema,
        ["CAVEAT_MAX_SPEND"] = CaveatMaxSpend, ["MAX_CAUTION_REASON_LEN"] = MaxCautionReasonLen, ["MIN_SALT_BYTES"] = MinSaltBytes,
        ["MIN_SALT_DISTINCT_BYTES"] = MinSaltDistinctBytes, ["MAX_RATIONALE_LEN"] = MaxRationaleLen, ["MAX_SCHEMA_DEPTH"] = MaxSchemaDepth,
        ["MAX_SCHEMA_NODES"] = MaxSchemaNodes, ["MAX_OBJECT_PROPS"] = MaxObjectProps, ["MAX_ENUM_VALUES"] = MaxEnumValues,
        ["DEFAULT_MAX_ARRAY_ITEMS"] = DefaultMaxArrayItems, ["ABSOLUTE_MAX_ARRAY_ITEMS"] = AbsoluteMaxArrayItems,
        ["DEFAULT_MAX_STRING_LEN"] = DefaultMaxStringLen, ["ABSOLUTE_MAX_STRING_LEN"] = AbsoluteMaxStringLen, ["MAX_VALUE_NODES"] = MaxValueNodes,
        ["HEARTBEAT_SKEW_MS"] = HeartbeatSkewMs, ["MAX_LEASE_TTL_MS"] = MaxLeaseTtlMs,
    };

    // ---- helpers ----

    /// <summary>A finite JSON number as a double (a bool or a string is never a number), else null.</summary>
    static double? Fin(object? o) => IntentJs.NumOf(o) is double d && double.IsFinite(d) ? d : null;

    static bool NonEmpty(object? x) => x is string { Length: > 0 };

    static byte[] MsgOf(string domain, object? body) => Pca.Canon(new JD { ["d"] = domain, ["b"] = body });

    static double Clamp01(double x) => Math.Min(1, Math.Max(0, x));

    /// <summary><c>Number.isInteger</c> on a JSON value (a non-number is false).</summary>
    static bool IsInteger(object? o) => Fin(o) is double d && Math.Floor(d) == d;

    static bool IsNonNegInteger(object? o) => IsInteger(o) && Fin(o)!.Value >= 0 && !IntentJs.IsNegZero(Fin(o)!.Value);

    static string Hash(object? v) => Pca.HashCanonical(v);

    /// <summary><c>JSON.parse(canonicalize(x))</c>: a deep copy through the LENIENT canonical form (throws on a non-finite number).</summary>
    static object? CloneLenient(object? x) => Pca.ParseJson(JsCanon.Lenient(x) ?? throw new ArgumentException("canonicalize: non-finite number"));

    /// <summary>JavaScript <c>===</c> on JSON scalars (numbers by double value, null equals null).</summary>
    static bool JsEq(object? a, object? b)
    {
        var fa = IntentJs.NumOf(a); var fb = IntentJs.NumOf(b);
        if (fa != null || fb != null) return fa != null && fb != null && fa.Value == fb.Value;
        if (a == null || b == null) return a == null && b == null;
        if (a is bool || b is bool) return a is bool x && b is bool y && x == y;
        return a is string s && b is string t && string.Equals(s, t, StringComparison.Ordinal);
    }

    // ======================================================================================================================
    // 1. Uncertainty attestation (monotone self-escalation)
    // ======================================================================================================================

    static readonly string[] CautionKeys = { "action_digest", "caution", "reason", "holder", "sig" };

    static string? CautionBodyError(JD b)
    {
        if (!NonEmpty(b.GetValueOrDefault("action_digest"))) return "action_digest required";
        if (!NonEmpty(b.GetValueOrDefault("holder"))) return "holder required";
        if (Fin(b.GetValueOrDefault("caution")) is not double c || c < 0 || c > 1) return "caution must be a finite number in [0,1]";
        if (b.ContainsKey("reason") && !(b["reason"] is string r && r.Length <= MaxCautionReasonLen && Rx.Get(@"\A[A-Za-z0-9_.:-]+\z", RegexOptions.CultureInvariant).IsMatch(r))) return "invalid reason";
        return null;
    }

    /// <summary>Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by <c>claim.holder</c>, bound to
    /// <paramref name="expectedActionDigest"/> (when given, i.e. not null) and signed by <paramref name="expectedHolder"/> (when given). Total.</summary>
    public static bool VerifyCaution(object? claim, object? expectedActionDigest = null, object? expectedHolder = null) =>
        VerifyCautionImpl(claim, expectedActionDigest != null, expectedActionDigest, expectedHolder != null, expectedHolder);

    static bool VerifyCautionImpl(object? claimO, bool hasDigest, object? digest, bool hasHolder, object? holder)
    {
        try
        {
            if (claimO is not JD claim || claim.GetValueOrDefault("sig") is not string sig) return false;
            if (claim.Keys.Any(k => !CautionKeys.Contains(k))) return false;
            if (CautionBodyError(claim) != null) return false;
            if (hasDigest && !Equals(claim["action_digest"], digest)) return false;
            if (hasHolder && !Equals(claim["holder"], holder)) return false;
            var body = new JD(claim);
            body.Remove("sig");
            return IntentJs.VerifyEd(claim["holder"], MsgOf(Signers.CautionDomain, body), sig);
        }
        catch (Exception) { return false; }
    }

    /// <summary><c>max(agentDeclaredCaution, serverRisk)</c>: always at least <paramref name="serverRisk"/> (clamped to [0,1]) and non-decreasing in the
    /// declared value. An unusable declaration (null, NaN, an infinity, a non-number) is ignored; an unusable <paramref name="serverRisk"/> fails closed to 1.</summary>
    public static double CombineCaution(object? agentDeclaredCaution, object? serverRisk)
    {
        var s = Fin(serverRisk) is double sv ? Clamp01(sv) : 1;
        return Fin(agentDeclaredCaution) is double d ? Math.Max(Clamp01(d), s) : s;
    }

    /// <summary>As <see cref="CombineCaution"/> for a signed claim: only a valid claim bound to THIS action (and, when <paramref name="expectedHolder"/> is
    /// not null, to THIS holder) is honoured. Returns <c>{effectiveRisk, honoured, escalated}</c>.</summary>
    public static JD CombineSignedCaution(object? claim, object? actionDigest, object? serverRisk, object? expectedHolder = null)
    {
        var s = Fin(serverRisk) is double sv ? Clamp01(sv) : 1;
        var ok = claim != null && VerifyCautionImpl(claim, true, actionDigest, expectedHolder != null, expectedHolder);
        var eff = CombineCaution(ok ? ((JD)claim!).GetValueOrDefault("caution") : null, s);
        return new JD { ["effectiveRisk"] = eff, ["honoured"] = ok, ["escalated"] = eff > s };
    }

    /// <summary>Exhaustive-grid check of the monotonicity property: <c>{ok: true}</c>, or <c>{ok: false, counterexample: [d, s]}</c>.</summary>
    public static JD CheckCautionMonotone(object? grid)
    {
        if (grid is not JL gl) throw new ArgumentException("checkCautionMonotone: grid must be an array");
        var g = gl.Select(Fin).Where(x => x != null).Select(x => x!.Value).ToList();
        foreach (var s in g)
            foreach (var d in g)
            {
                var e = CombineCaution(d, s);
                if (e < Clamp01(s)) return new JD { ["ok"] = false, ["counterexample"] = new JL { d, s } };
                foreach (var d2 in g)
                    if (d2 >= d && CombineCaution(d2, s) < e) return new JD { ["ok"] = false, ["counterexample"] = new JL { d2, s } };
            }
        return new JD { ["ok"] = true };
    }

    // ======================================================================================================================
    // 2. Rationale binding (commit / reveal)
    // ======================================================================================================================

    /// <summary>Entropy floor of a commitment salt: base64url (no padding, canonical) that decodes to at least 16 bytes with at least 8 distinct byte
    /// values, at most 256 characters.</summary>
    public static bool IsStrongSalt(object? salt)
    {
        if (salt is not string s || s.Length == 0 || s.Length > 256) return false;
        foreach (var c in s) if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-')) return false;
        var b = Pca.B64uDecode(s);
        return b != null && b.Length >= MinSaltBytes && b.Distinct().Count() >= MinSaltDistinctBytes;
    }

    static string CommitDigest(string actionDigest, object? salt, string rationale) =>
        Hash(new JD { ["d"] = "atlas-pca/rationale/v1", ["a"] = actionDigest, ["s"] = salt, ["r"] = rationale });

    /// <summary><see cref="BindRationale(object?, object?, object?)"/> with a fresh 32-byte random salt.</summary>
    public static JD BindRationale(object? action, object? rationale) => BindRationale(action, rationale, Pca.B64u(RandomNumberGenerator.GetBytes(32)));

    /// <summary>The agent commits to its stated reason: returns <c>{commitment: {v, action_digest, commitment}, reveal: {rationale, salt}}</c>. Publish the
    /// commitment, KEEP the reveal. Throws on a non-string or oversized rationale, a weak salt (<see cref="IsStrongSalt"/>) or a non-canonicalizable action.</summary>
    public static JD BindRationale(object? action, object? rationale, object? salt)
    {
        if (rationale is not string r) throw new ArgumentException("bindRationale: rationale must be a string");
        if (r.Length > MaxRationaleLen) throw new ArgumentException("bindRationale: rationale too long");
        if (!IsStrongSalt(salt)) throw new ArgumentException($"bindRationale: salt must be b64u of >={MinSaltBytes} bytes with >={MinSaltDistinctBytes} distinct values");
        var ad = Hash(action);
        return new JD
        {
            ["commitment"] = new JD { ["v"] = 1L, ["action_digest"] = ad, ["commitment"] = CommitDigest(ad, salt, r) },
            ["reveal"] = new JD { ["rationale"] = r, ["salt"] = salt },
        };
    }

    static bool IsOne(object? v) => v is Num or int or long or double && IntentJs.NumOf(v) == 1.0;

    /// <summary>Does the revealed rationale open the commitment? A reveal with a weak salt is rejected even if it hashes correctly. Total.</summary>
    public static bool VerifyRationale(object? commitment, object? reveal) => VerifyRationaleImpl(commitment, reveal, false, null);

    /// <summary>As <see cref="VerifyRationale(object?, object?)"/>, additionally requiring the commitment to be for this very <paramref name="action"/>.</summary>
    public static bool VerifyRationale(object? commitment, object? reveal, object? action) => VerifyRationaleImpl(commitment, reveal, true, action);

    static bool VerifyRationaleImpl(object? commitment, object? reveal, bool hasAction, object? action)
    {
        try
        {
            if (commitment is not JD c || reveal is not JD r) return false;
            if (!IsOne(c.GetValueOrDefault("v")) || !NonEmpty(c.GetValueOrDefault("action_digest")) || !NonEmpty(c.GetValueOrDefault("commitment"))) return false;
            if (r.GetValueOrDefault("rationale") is not string rat || rat.Length > MaxRationaleLen || !IsStrongSalt(r.GetValueOrDefault("salt"))) return false;
            if (hasAction && !Equals(Hash(action), c["action_digest"])) return false;
            return Equals(CommitDigest((string)c["action_digest"]!, r["salt"], rat), c["commitment"]);
        }
        catch (Exception) { return false; }
    }

    static JD Audit(string verdict, bool slashable, JD evidence) => new() { ["verdict"] = verdict, ["slashable"] = slashable, ["evidence"] = evidence };

    /// <summary>After-the-fact audit. <paramref name="judge"/> returns exactly <c>true</c> for a consistent rationale (anything else is a false one); a throwing
    /// judge is <c>judge_error</c>. <paramref name="reveal"/> may be null (never opened). Returns <c>{verdict, slashable, evidence}</c>; <c>malformed</c>,
    /// <c>wrong_action</c> and <c>judge_error</c> are never slashable. Total.</summary>
    public static JD AuditRationale(object? commitment, object? action, object? reveal, Func<string, object?, object?> judge)
    {
        var cm = commitment as JD;
        var evidence = new JD
        {
            ["commitment"] = cm != null && cm.GetValueOrDefault("commitment") is string c1 ? c1 : "",
            ["action_digest"] = cm != null && cm.GetValueOrDefault("action_digest") is string c2 ? c2 : "",
        };
        try
        {
            if (cm == null || !IsOne(cm.GetValueOrDefault("v")) || !NonEmpty(cm.GetValueOrDefault("action_digest")) || !NonEmpty(cm.GetValueOrDefault("commitment")))
                return Audit("malformed", false, evidence);
            if (!Equals(Hash(action), cm["action_digest"])) return Audit("wrong_action", false, evidence);
            if (reveal == null || !VerifyRationaleImpl(commitment, reveal, true, action)) return Audit("unopened", true, evidence);
            var rationale = (string)((JD)reveal)["rationale"]!;
            var opened = new JD(evidence) { ["rationale"] = rationale };
            bool ok;
            try { ok = judge(rationale, action) is true; }
            catch (Exception) { return Audit("judge_error", false, opened); }
            return Audit(ok ? "consistent" : "false_rationale", !ok, opened);
        }
        catch (Exception) { return Audit("malformed", false, evidence); }
    }

    // ======================================================================================================================
    // 3. Semantic firewall
    // ======================================================================================================================

    static string BindingOf(object? tool, object? signatureDigest, object? schema) =>
        Hash(new JD { ["tool"] = tool, ["signature_digest"] = signatureDigest, ["schema"] = schema });

    /// <summary>Build a <c>tool_schema</c> caveat for one tool: authority exists only for that exact tool, signature and (nested) argument schema. Throws when the
    /// signature names no tool, the schema is invalid (<see cref="Pca.ValidateArgSchema"/>) or anything is not canonicalizable. The schema is deep-cloned in canonical form.</summary>
    public static JD ToolSchemaCaveat(object? toolSignature, object? argSchema)
    {
        var tool = toolSignature is string s ? s : toolSignature is JD sd && sd.GetValueOrDefault("name") is string n ? n : "";
        if (tool.Length == 0) throw new ArgumentException("toolSchemaCaveat: tool name required");
        var err = Pca.ValidateArgSchema(argSchema);
        if (err != null) throw new ArgumentException("toolSchemaCaveat: " + err);
        var schema = CloneLenient(argSchema);
        var sig = Hash(toolSignature);
        return new JD
        {
            ["type"] = CaveatToolSchema, ["tool"] = tool, ["signature_digest"] = sig, ["schema"] = schema,
            ["schema_digest"] = Hash(schema), ["binding_digest"] = BindingOf(tool, sig, schema),
        };
    }

    /// <summary>Evaluator for a <c>tool_schema</c> caveat; <c>ctx = {toolCall}</c>. Anything else is unsatisfied.</summary>
    public static bool ToolSchemaEvaluator(object? caveat, object? ctx) =>
        ctx is JD c && c.GetValueOrDefault("toolCall") is JD call && Pca.EvaluateToolSchemaJson(caveat, call).Ok;

    /// <summary>The delegated-narrowing caveat <c>{type: "predicates", allow}</c> (deep-cloned canonical form; throws on a non-finite number).</summary>
    public static JD PredicatesCaveat(object? allow) => new() { ["type"] = CaveatPredicates, ["allow"] = CloneLenient(allow) };

    /// <summary>The action's spend in USD as <c>max_spend</c> reads it (see <see cref="Caveats.ActionSpendUsd"/>); null when there is no readable spend.</summary>
    public static double? ActionSpendUsd(object? action) => Caveats.ActionSpendUsd(action);

    /// <summary>Superset of the stock caveat evaluator: adds <c>predicates</c> (needs <c>ctx.action</c>), <c>max_spend</c> (needs <c>ctx.action</c>) and
    /// <c>tool_schema</c> (needs <c>ctx.toolCall</c>); anything else defers to the stock evaluator (unknown types fail closed). Total.</summary>
    public static bool AgentNativeCaveatEvaluator(object? caveat, object? ctx)
    {
        try
        {
            if (caveat is not JD cv || ctx is not JD c) return false;
            var t = cv.GetValueOrDefault("type");
            if (t is CaveatToolSchema) return ToolSchemaEvaluator(cv, c);
            if (t is CaveatPredicates)
            {
                if (c.GetValueOrDefault("action") is not JD a || cv.GetValueOrDefault("allow") is not JL allow) return false;
                return allow.Any(p => Predicates.PredicateMatches(p, a));
            }
            if (t is CaveatMaxSpend)
            {
                var spend = ActionSpendUsd(c.GetValueOrDefault("action")); // the spend of ctx.action (an action context carrying its own action)
                return Fin(cv.GetValueOrDefault("usd")) is double lim && spend != null && spend.Value <= lim;
            }
            // the stock evaluator reads this context in snake case; the reference's callers hand it the camel-case names
            var sc = new JD(c);
            foreach (var (camel, snake) in new[] { ("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"), ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times") })
                if (c.TryGetValue(camel, out var cvv) && !sc.ContainsKey(snake)) sc[snake] = cvv;
            return Caveats.EvaluateCaveats(new JL { cv }, sc).Ok;
        }
        catch (Exception) { return false; }
    }

    // ======================================================================================================================
    // 4. Capability introspection
    // ======================================================================================================================

    static readonly string[] Rev = { "reversible", "rate_limited", "irreversible" };
    static readonly object Undecided = new();

    static JL SortedUnique(IEnumerable<object?> items)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var l = new List<string>();
        foreach (var o in items) if (seen.Add((string)o!)) l.Add((string)o!);
        l.Sort(IntentJs.CompareUtf8);
        return new JL(l.Cast<object?>());
    }

    static JL IntersectVerbs(JL a, JL b)
    {
        if (a.Contains("*")) return SortedUnique(b);
        if (b.Contains("*")) return SortedUnique(a);
        return SortedUnique(a.Where(b.Contains));
    }

    /// <summary>Intersect two resource patterns: null = empty, <see cref="Undecided"/> = cannot decide symbolically (regex).</summary>
    static object? InterRes(string a, string b)
    {
        if (a == b) return a;
        if (a.StartsWith("re:", StringComparison.Ordinal) || b.StartsWith("re:", StringComparison.Ordinal)) return Undecided;
        if (a == "*") return b;
        if (b == "*") return a;
        bool ap = a.EndsWith('*'), bp = b.EndsWith('*');
        if (ap && bp)
        {
            var pa = a[..^1]; var pb = b[..^1];
            return pb.StartsWith(pa, StringComparison.Ordinal) ? b : pa.StartsWith(pb, StringComparison.Ordinal) ? a : null;
        }
        if (ap) return b.StartsWith(a[..^1], StringComparison.Ordinal) ? b : null;
        if (bp) return a.StartsWith(b[..^1], StringComparison.Ordinal) ? a : null;
        return null;
    }

    /// <summary>Collapse a conjunction of resource patterns; null = unsatisfiable.</summary>
    static JL? CollapseResources(JL list)
    {
        string? lit = null;
        var res = new List<string>();
        foreach (var po in list)
        {
            var p = (string)po!;
            if (p.StartsWith("re:", StringComparison.Ordinal)) { if (!res.Contains(p)) res.Add(p); continue; }
            if (lit == null) lit = p;
            else
            {
                var r = InterRes(lit, p);
                if (r == null || ReferenceEquals(r, Undecided)) return null;
                lit = (string)r;
            }
        }
        res.Sort(IntentJs.CompareUtf8);
        var o = new JL();
        if (lit != null && lit != "*") o.Add(lit);
        o.AddRange(res);
        if (o.Count == 0) o.Add("*");
        return o;
    }

    static JD Scope(JL verbs, JL resources, JL where) => new() { ["verbs"] = verbs, ["resources"] = resources, ["where"] = where };

    static JD Universe() => Scope(new JL { "*" }, new JL { "*" }, new JL());

    static JD? ScopeOfPredicate(object? p)
    {
        if (p is not JD pm) return null;
        JL verbs;
        var v = pm.GetValueOrDefault("verb");
        if (v is string vs) verbs = new JL { vs };
        else if (v is JL vl && vl.All(x => x is string)) verbs = new JL(vl);
        else return null;
        if (pm.ContainsKey("resource") && pm["resource"] is not string) return null;
        JL where;
        if (!pm.ContainsKey("where")) where = new JL();
        else if (pm["where"] is JL w) where = w;
        else return null;
        return Scope(SortedUnique(verbs), new JL { pm.ContainsKey("resource") ? pm["resource"] : "*" }, where);
    }

    static List<JD> IntersectScopes(List<JD> a, List<JD> b)
    {
        var o = new Dictionary<string, JD>(StringComparer.Ordinal);
        foreach (var x in a)
            foreach (var y in b)
            {
                var verbs = IntersectVerbs((JL)x["verbs"]!, (JL)y["verbs"]!);
                if (verbs.Count == 0) continue;
                var resources = CollapseResources(new JL(((JL)x["resources"]!).Concat((JL)y["resources"]!)));
                if (resources == null) continue;
                var s = Scope(verbs, resources, new JL(((JL)x["where"]!).Concat((JL)y["where"]!)));
                o[Hash(s)] = s;
            }
        return o.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Value).ToList();
    }

    static bool ScopeMatches(JD s, object? verb, object? resource, object? prm)
    {
        var verbs = (JL)s["verbs"]!;
        if (!verbs.Contains("*") && !verbs.Contains(verb)) return false;
        var action = new JD { ["verb"] = verb, ["resource"] = resource };
        if (prm != null) action["params"] = prm;
        var ctx = new JD { ["action"] = action };
        foreach (var r in (JL)s["resources"]!) if (!Predicates.PredicateMatches(new JD { ["verb"] = "*", ["resource"] = r }, ctx)) return false;
        var where = (JL)s["where"]!;
        if (prm != null && where.Count > 0) return Predicates.PredicateMatches(new JD { ["verb"] = "*", ["where"] = where }, ctx);
        return true;
    }

    /// <summary>Is this caveat one the verifier (stock evaluator + this module's superset) can satisfy at all?</summary>
    static bool WellFormedCaveat(JD cv) => cv.GetValueOrDefault("type") switch
    {
        CaveatExpires or CaveatNotBefore => Fin(cv.GetValueOrDefault("at")) != null,
        CaveatRate => Fin(cv.GetValueOrDefault("max")) != null && Fin(cv.GetValueOrDefault("per_secs")) is double p && p > 0,
        CaveatMaxBlastRadius or CaveatDelegationDepth => Fin(cv.GetValueOrDefault("max")) != null,
        CaveatReversibilityMax => cv.GetValueOrDefault("class") is string k && Rev.Contains(k),
        CaveatPredicates => cv.GetValueOrDefault("allow") is JL al && al.All(x => ScopeOfPredicate(x) != null),
        CaveatToolSchema => NonEmpty(cv.GetValueOrDefault("tool")),
        "budget_alloc" => Fin(cv.GetValueOrDefault("limit")) is double l && l >= 0,
        CaveatMaxSpend => Fin(cv.GetValueOrDefault("usd")) is double u && u >= 0,
        _ => false,
    };

    static JD EmptyEnvelope() => new()
    {
        ["ok"] = false, ["hasEnvelope"] = false, ["scopes"] = new JL(), ["verbs"] = new JL(), ["resources"] = new JL(),
        ["opaqueResourceConstraints"] = new JL(), ["tools"] = new JL(), ["toolSchemas"] = new JL(), ["unsatisfiable"] = new JL(),
        ["caveats"] = new JL(), ["remainingBudgetHints"] = new JD(),
    };

    /// <summary>What an attenuated chain permits NOW: the intersection across every hop of the root <c>envelope.predicates</c>, each appended
    /// <c>predicates</c> / <c>tool_schema</c> caveat and the built-in caveats, exactly the set the verifier would accept. Returns the
    /// <c>AuthorityEnvelope</c> as a JSON object <c>{ok, reason?, hasEnvelope, scopes, verbs, resources, opaqueResourceConstraints, tools, toolSchemas,
    /// unsatisfiable, caveats, remainingBudgetHints}</c>; <c>scopes</c> / <c>verbs</c> / <c>resources</c> / <c>tools</c> are null when unrestricted. A caveat the
    /// verifier cannot satisfy makes the envelope unsatisfiable (nothing is permitted). <paramref name="policy"/> may carry <c>allowedSuites</c>, <c>pqPins</c>,
    /// <c>trustedRoot</c>. A chain that does not verify gives <c>ok: false</c> with the verifier's reason. Deterministic (<c>now</c> supplied) and total.</summary>
    public static JD DescribeEnvelope(object? chain, object? now = null, string? expectedRootIssuer = null, JD? policy = null)
    {
        try
        {
            var ch = chain as JL ?? new JL();
            var allowed = policy?.GetValueOrDefault("allowedSuites") is JL al ? al.Select(x => (string)x!).ToList() : null;
            var pins = policy?.GetValueOrDefault("pqPins") is JD pd ? pd.ToDictionary(kv => kv.Key, kv => (string)kv.Value!) : null;
            var trusted = policy?.GetValueOrDefault("trustedRoot") as JD;
            var (why, vok) = Pca.VerifyChain(ch, expectedRootIssuer, expectedRootIssuer != null, allowed, pins, trusted);
            if (!vok)
            {
                var bad = EmptyEnvelope();
                bad["reason"] = why;
                return bad;
            }
            var root = (JD)ch[0]!;
            var leaf = (JD)ch[^1]!;
            var env0 = Pca.ReadEnvelope(root);
            var env = EmptyEnvelope();
            env["ok"] = true;
            env["hasEnvelope"] = env0 != null;
            env["caveats"] = leaf["caveats"];
            var h = (JD)env["remainingBudgetHints"]!;

            List<JD>? scopes = null;
            JL? tools = null;
            var seenEnvelope = false;
            var bad2 = new List<string>();
            var toolSchemas = new JL();
            double? expiresAt = null, notBefore = null, maxBlast = null, depthRem = null, budgetAlloc = null, maxSpend = null;
            (double Max, double Per)? maxRate = null;
            string? revMax = null;

            void Fold(object? cvO, bool inEnvelope)
            {
                if (cvO is not JD cv || cv.GetValueOrDefault("type") is not string type) { bad2.Add("<malformed>"); return; }
                if (type == CaveatEnvelope)
                {
                    // only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied
                    if (seenEnvelope || inEnvelope) bad2.Add(CaveatEnvelope);
                    seenEnvelope = true;
                    return;
                }
                if (!WellFormedCaveat(cv)) { bad2.Add(type); return; }
                switch (type)
                {
                    case CaveatPredicates:
                        scopes = IntersectScopes(scopes ?? new List<JD> { Universe() }, ((JL)cv["allow"]!).Select(p => ScopeOfPredicate(p)!).ToList());
                        break;
                    case CaveatToolSchema:
                        toolSchemas.Add(cv);
                        var consistent = Pca.ValidateArgSchema(cv.GetValueOrDefault("schema")) == null
                            && Equals(Hash(cv.GetValueOrDefault("schema")), cv.GetValueOrDefault("schema_digest"))
                            && Equals(BindingOf(cv["tool"], IntentRevocation.JsText(cv.GetValueOrDefault("signature_digest"), cv.ContainsKey("signature_digest")), cv.GetValueOrDefault("schema")), cv.GetValueOrDefault("binding_digest"));
                        if (!consistent) { tools = new JL(); bad2.Add(CaveatToolSchema); }
                        else tools = tools == null ? new JL { cv["tool"] } : new JL(tools.Where(t => Equals(t, cv["tool"])));
                        break;
                    case CaveatExpires: { var at = Fin(cv["at"])!.Value; expiresAt = expiresAt is double e ? Math.Min(e, at) : at; break; }
                    case CaveatNotBefore: { var at = Fin(cv["at"])!.Value; notBefore = notBefore is double e ? Math.Max(e, at) : at; break; }
                    case CaveatRate:
                    {
                        double m = Fin(cv["max"])!.Value, p = Fin(cv["per_secs"])!.Value;
                        // the lower sustained rate (max / per_secs) binds; ties go to the smaller max
                        if (maxRate is not { } cur || m / p < cur.Max / cur.Per || (m / p == cur.Max / cur.Per && m < cur.Max)) maxRate = (m, p);
                        break;
                    }
                    case CaveatMaxBlastRadius: { var m = Fin(cv["max"])!.Value; maxBlast = maxBlast is double e ? Math.Min(e, m) : m; break; }
                    case CaveatReversibilityMax:
                    {
                        var i = Array.IndexOf(Rev, (string)cv["class"]!);
                        var j = revMax == null ? Rev.Length : Array.IndexOf(Rev, revMax);
                        if (i < j) revMax = Rev[i];
                        break;
                    }
                    case CaveatDelegationDepth:
                    {
                        var rem = Fin(cv["max"])!.Value - (ch.Count - 1);
                        depthRem = depthRem is double e ? Math.Min(e, rem) : rem;
                        break;
                    }
                    case "budget_alloc": { var l = Fin(cv["limit"])!.Value; budgetAlloc = budgetAlloc is double e ? Math.Min(e, l) : l; break; }
                    case CaveatMaxSpend: { var l = Fin(cv["usd"])!.Value; maxSpend = maxSpend is double e ? Math.Min(e, l) : l; break; }
                }
            }

            if (env0 != null)
            {
                var baseScopes = new List<JD>();
                foreach (var p in (JL)env0["predicates"]!)
                {
                    var s = ScopeOfPredicate(p);
                    if (s == null) bad2.Add("envelope.predicates"); else baseScopes.Add(s);
                }
                scopes = IntersectScopes(baseScopes, new List<JD> { Universe() });
                foreach (var cv in (JL)env0["caveats"]!) Fold(cv, true);
            }
            foreach (var cv in (JL)leaf["caveats"]!) Fold(cv, false);

            var opaque = new List<object?>();
            if (scopes != null)
            {
                var vs = new List<object?>(); var rs = new List<object?>();
                foreach (var s in scopes)
                {
                    vs.AddRange((JL)s["verbs"]!);
                    foreach (var r in (JL)s["resources"]!) { rs.Add(r); if (((string)r!).StartsWith("re:", StringComparison.Ordinal)) opaque.Add(r); }
                }
                env["scopes"] = new JL(scopes.Cast<object?>());
                env["verbs"] = SortedUnique(vs);
                env["resources"] = SortedUnique(rs);
            }
            else { env["scopes"] = null; env["verbs"] = null; env["resources"] = null; }
            env["opaqueResourceConstraints"] = SortedUnique(opaque);
            env["tools"] = tools == null ? null : SortedUnique(tools);
            env["toolSchemas"] = toolSchemas;
            var unsat = SortedUnique(bad2.Cast<object?>());
            env["unsatisfiable"] = unsat;
            if (unsat.Count > 0)
            {
                env["scopes"] = new JL(); env["verbs"] = new JL(); env["resources"] = new JL(); env["tools"] = new JL();
                env["reason"] = "unsatisfiable caveat(s): " + string.Join(", ", unsat.Cast<string>());
            }
            if (expiresAt is double ea) h["expiresAt"] = ea;
            if (expiresAt is double ea2 && Fin(now) is double nowF) h["expiresIn"] = ea2 - nowF;
            if (maxRate is { } mr) h["maxRate"] = new JD { ["max"] = mr.Max, ["per_secs"] = mr.Per };
            if (maxBlast is double mb) h["maxBlastRadius"] = mb;
            if (revMax != null) h["reversibilityMax"] = revMax;
            if (depthRem is double dr) h["delegationDepthRemaining"] = dr;
            if (notBefore is double nb) h["notBefore"] = nb;
            if (budgetAlloc is double ba) h["budgetAlloc"] = ba;
            if (maxSpend is double ms) h["maxSpendUsd"] = ms;
            return env;
        }
        catch (Exception)
        {
            var m = EmptyEnvelope();
            m["reason"] = "introspection error (fail closed)";
            return m;
        }
    }

    /// <summary>Pre-flight an agent can run before attempting. False is definitive (the verifier will refuse); true means the symbolic envelope allows it.
    /// When <paramref name="prm"/> is given the <c>where</c> conditions are evaluated too (fail closed); <paramref name="now"/> and <paramref name="prm"/> are
    /// null when not given. Total.</summary>
    public static bool EnvelopePermits(object? envO, object? verb, object? resource, object? now = null, object? prm = null)
    {
        try
        {
            if (envO is not JD e) return false;
            if (!IntentRevocation.Truthy(e.GetValueOrDefault("ok")) || ((JL)e["unsatisfiable"]!).Count > 0) return false;
            if (!e.ContainsKey("scopes")) return false;
            if (e["scopes"] != null && !((JL)e["scopes"]!).Any(s => ScopeMatches((JD)s!, verb, resource, prm))) return false;
            var h = (JD)e["remainingBudgetHints"]!;
            if (h.ContainsKey("delegationDepthRemaining") && IntentJs.NumOf(h["delegationDepthRemaining"]) is double dd && !(double.IsFinite(dd) && dd >= 0)) return false;
            if (h.ContainsKey("maxSpendUsd") && IntentJs.NumOf(h["maxSpendUsd"]) is double ms && prm != null)
            {
                var spend = ActionSpendUsd(new JD { ["action"] = new JD { ["params"] = prm } });
                if (spend == null || !(spend.Value <= ms)) return false;
            }
            if (now != null)
            {
                if (Fin(now) is not double n) return false;
                if (h.ContainsKey("expiresAt") && IntentJs.NumOf(h["expiresAt"]) is double ex && !(double.IsFinite(ex) && n < ex)) return false;
                if (h.ContainsKey("notBefore") && IntentJs.NumOf(h["notBefore"]) is double nb && !(double.IsFinite(nb) && n >= nb)) return false;
            }
            return true;
        }
        catch (Exception) { return false; }
    }

    static JD Firewall(bool ok, string? reason)
    {
        var m = new JD { ["ok"] = ok };
        if (reason != null) m["reason"] = reason;
        return m;
    }

    /// <summary>Pre-flight for a tool call: the tool must be in <c>env.tools</c> and satisfy EVERY <c>tool_schema</c> caveat. Returns <c>{ok, reason?}</c>.</summary>
    public static JD EnvelopePermitsToolCall(object? envO, object? call)
    {
        try
        {
            var e = (JD)envO!;
            if (!IntentRevocation.Truthy(e.GetValueOrDefault("ok")) || ((JL)e["unsatisfiable"]!).Count > 0)
                return Firewall(false, e.GetValueOrDefault("reason") is { } rs ? IntentRevocation.JsText(rs, true) : "envelope not usable");
            if (e.GetValueOrDefault("tools") is { } tools)
            {
                if (call == null) throw new InvalidOperationException("call is null"); // the reference reads call.tool
                var c = call as JD;
                var has = c != null && c.ContainsKey("tool");
                if (!(has && ((JL)tools).Contains(c!["tool"])))
                    return Firewall(false, "tool " + Pca.ShowKey(IntentRevocation.JsText(has ? c!["tool"] : null, has)) + " not authorized");
            }
            foreach (var tc in (JL)e["toolSchemas"]!)
            {
                var r = Pca.EvaluateToolSchemaJson(tc, call);
                if (!r.Ok) return Firewall(false, r.Reason);
            }
            return Firewall(true, null);
        }
        catch (Exception) { return Firewall(false, "evaluation error (fail closed)"); }
    }

    // ======================================================================================================================
    // 5. Authority lease
    // ======================================================================================================================

    /// <summary>Issue a lease <c>{cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at, hard_expires_at?, max_renewals?}</c> from
    /// <c>{cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}</c>. Throws unless the ids are non-empty, <c>now</c> finite, 0 &lt; ttl_ms &lt;=
    /// <see cref="MaxLeaseTtlMs"/>, <c>hard_expires_at</c> (if any) finite and after <c>now</c>, and <c>max_renewals</c> (if any) a non-negative integer.</summary>
    public static JD GrantLease(object? argsO)
    {
        if (argsO is not JD a || !NonEmpty(a.GetValueOrDefault("cap_id")) || !NonEmpty(a.GetValueOrDefault("holder"))) throw new ArgumentException("grantLease: cap_id and holder required");
        if (Fin(a.GetValueOrDefault("now")) is not double now || Fin(a.GetValueOrDefault("ttl_ms")) is not double ttl || ttl <= 0 || ttl > MaxLeaseTtlMs)
            throw new ArgumentException("grantLease: invalid now/ttl_ms");
        double? hard = null;
        if (a.ContainsKey("hard_expires_at"))
        {
            hard = Fin(a["hard_expires_at"]);
            if (hard == null || hard.Value <= now) throw new ArgumentException("grantLease: hard_expires_at must be finite and in the future");
        }
        if (a.ContainsKey("max_renewals") && !IsNonNegInteger(a["max_renewals"])) throw new ArgumentException("grantLease: invalid max_renewals");
        var exp = hard == null ? now + ttl : Math.Min(now + ttl, hard.Value);
        var l = new JD
        {
            ["cap_id"] = a["cap_id"], ["holder"] = a["holder"], ["issued_at"] = a["now"], ["renewed_at"] = a["now"], ["ttl_ms"] = a["ttl_ms"],
            ["renewals"] = 0L, ["last_seq"] = 0L, ["expires_at"] = exp,
        };
        if (hard != null) l["hard_expires_at"] = a["hard_expires_at"];
        if (a.ContainsKey("max_renewals")) l["max_renewals"] = a["max_renewals"];
        return l;
    }

    /// <summary>Structural + invariant check of a lease record: an error or null.</summary>
    static string? LeaseError(object? lo)
    {
        if (lo is not JD l || !NonEmpty(l.GetValueOrDefault("cap_id")) || !NonEmpty(l.GetValueOrDefault("holder"))) return "malformed lease";
        if (Fin(l.GetValueOrDefault("issued_at")) is null || Fin(l.GetValueOrDefault("renewed_at")) is not double renewed
            || Fin(l.GetValueOrDefault("ttl_ms")) is not double ttl || Fin(l.GetValueOrDefault("expires_at")) is not double exp) return "malformed lease";
        if (ttl <= 0 || ttl > MaxLeaseTtlMs) return "malformed lease";
        if (!IsNonNegInteger(l.GetValueOrDefault("renewals")) || !IsNonNegInteger(l.GetValueOrDefault("last_seq"))) return "malformed lease";
        if (l.ContainsKey("max_renewals") && !IsNonNegInteger(l["max_renewals"])) return "malformed lease";
        if (l.ContainsKey("hard_expires_at"))
        {
            if (Fin(l["hard_expires_at"]) is not double hard) return "malformed lease";
            if (exp > hard) return "lease exceeds hard expiry";
        }
        // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
        if (exp > renewed + ttl) return "malformed lease";
        return null;
    }

    static JD Dead(string reason) => new() { ["live"] = false, ["expiresIn"] = 0L, ["reason"] = reason };

    /// <summary>Live iff the record is well-formed, the clock has not rolled back more than the skew window past the last renewal and <c>now &lt; expires_at</c>.
    /// Returns <c>{live, expiresIn, reason?}</c>; every dead state has <c>expiresIn</c> 0. Total.</summary>
    public static JD LeaseState(object? lease, object? now)
    {
        if (Fin(now) is not double n) return Dead("invalid clock");
        var e = LeaseError(lease);
        if (e != null) return Dead(e);
        var l = (JD)lease!;
        if (n < Fin(l["renewed_at"])!.Value - HeartbeatSkewMs) return Dead("clock before last renewal");
        var expiresIn = Fin(l["expires_at"])!.Value - n;
        if (expiresIn <= 0) return Dead("lease lapsed");
        return new JD { ["live"] = true, ["expiresIn"] = expiresIn };
    }

    static readonly string[] HbKeys = { "cap_id", "seq", "at", "holder", "lease_issued_at", "sig" };

    static JD RenewFail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>The reference's pure <c>renewLease(lease, heartbeat, now)</c> (the grants registry keeps its own renewal): renew on a valid, fresh, in-order,
    /// holder-signed heartbeat for THIS lease grant. A lapsed, malformed or clock-anomalous lease is dead for good. Never extends past
    /// <c>hard_expires_at</c>, never shortens, consumes the renewal budget. Returns <c>{ok: true, lease}</c> or <c>{ok: false, reason}</c>. Total.</summary>
    public static JD RenewCapabilityLease(object? leaseO, object? hbO, object? nowO)
    {
        try
        {
            var st = LeaseState(leaseO, nowO);
            if (st["live"] is not true) return RenewFail(st["reason"] is "lease lapsed" ? "lease lapsed" : $"lease not live: {st["reason"]}");
            var lease = (JD)leaseO!;
            var now = Fin(nowO)!.Value;
            if (hbO is not JD hb || hb.Keys.Any(k => !HbKeys.Contains(k)) || hb.GetValueOrDefault("sig") is not string sig) return RenewFail("malformed heartbeat");
            if (!JsEq(hb.GetValueOrDefault("cap_id"), lease["cap_id"]) || !JsEq(hb.GetValueOrDefault("holder"), lease["holder"])
                || !JsEq(hb.GetValueOrDefault("lease_issued_at"), lease["issued_at"])) return RenewFail("heartbeat not for this lease");
            var seq = hb.GetValueOrDefault("seq");
            if (!IntentJs.IsSafeInteger(seq) || IntentJs.NumOf(seq)!.Value <= Fin(lease["last_seq"])!.Value) return RenewFail("stale or replayed heartbeat");
            if (Fin(hb.GetValueOrDefault("at")) is not double at || !double.IsFinite(now) || !(Math.Abs(at - now) <= HeartbeatSkewMs)) return RenewFail("heartbeat outside skew window");
            var body = new JD(hb);
            body.Remove("sig");
            if (!IntentJs.VerifyEd(lease["holder"], MsgOf(Signers.HeartbeatDomain, body), sig)) return RenewFail("bad heartbeat signature");
            if (lease.ContainsKey("max_renewals") && Fin(lease["renewals"])!.Value >= Fin(lease["max_renewals"])!.Value) return RenewFail("renewal budget exhausted");
            var exp = now + Fin(lease["ttl_ms"])!.Value;
            if (lease.ContainsKey("hard_expires_at")) exp = Math.Min(exp, Fin(lease["hard_expires_at"])!.Value);
            if (!double.IsFinite(exp)) return RenewFail("malformed lease");
            var next = new JD(lease)
            {
                ["renewals"] = Fin(lease["renewals"])!.Value + 1,
                ["last_seq"] = seq,
                ["renewed_at"] = Math.Max(now, Fin(lease["renewed_at"])!.Value),
                ["expires_at"] = Math.Max(exp, Fin(lease["expires_at"])!.Value),
            };
            return new JD { ["ok"] = true, ["lease"] = next };
        }
        catch (Exception) { return RenewFail("malformed heartbeat"); }
    }
}
