using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Siem;

/// <summary>A single serialized event ready to ship: the structured object (OCSF / ECS; null for CEF) plus a one-line payload.</summary>
public sealed record SiemEvent(string? Format, D? Object, string Line)
{
    public D ToJson()
    {
        var m = new D { ["format"] = Format };
        if (Object != null) m["object"] = Object;
        m["line"] = Line;
        return m;
    }
}

/// <summary>The outcome of a delivery: <c>Ok</c> plus the (credential-scrubbed) <c>Error</c> when it failed.</summary>
public sealed record SinkResult(bool Ok, string? Error = null)
{
    public D ToJson()
    {
        var m = new D { ["ok"] = Ok };
        if (Error != null) m["error"] = Error;
        return m;
    }
}

/// <summary>A pluggable SIEM destination. <c>Format</c> is the schema it expects; <see cref="DeliverAsync"/> ships a batch of already-serialized events.
/// A sink SHOULD NOT throw (the exporters guard against it regardless) and MUST NOT block the caller's authorization path.</summary>
public interface ISiemSink
{
    string Name { get; }
    string? Format { get; }
    Task<SinkResult> DeliverAsync(IReadOnlyList<SiemEvent> events);
}

/// <summary>The request an HTTP sink sends (and <see cref="Signal"/> to cancel it on a timeout).</summary>
public sealed class FetchInit
{
    public string Method { get; }
    public Dictionary<string, string> Headers { get; }
    public string Body { get; }
    public CancellationToken Signal { get; }
    internal FetchInit(string method, Dictionary<string, string> headers, string body, CancellationToken signal) { Method = method; Headers = headers; Body = body; Signal = signal; }
}

/// <summary>The minimal shape of a fetch response this package reads.</summary>
public sealed record FetchLikeResponse(bool Ok, int Status, string? StatusText = null);

/// <summary>An injectable fetch (HttpClient by default, a mock in tests).</summary>
public delegate Task<FetchLikeResponse> FetchLike(string url, FetchInit init);

/// <summary>Options of <see cref="SiemExport.HttpSinkOf"/>; <c>Serialize</c> carries the serializer options <c>{signature: "full" | "prefix" | "omit"}</c>.</summary>
public sealed class HttpSinkOptions
{
    public string? Format;
    /// <summary>Extra headers (e.g. Splunk <c>Authorization: Splunk &lt;token&gt;</c>, a Datadog <c>DD-API-KEY</c>).</summary>
    public Dictionary<string, string>? Headers;
    public FetchLike? Fetch;
    /// <summary>Override the Content-Type (default: NDJSON for ocsf / ecs, text/plain for cef).</summary>
    public string? ContentType;
    public string? Name;
    /// <summary>Give up on a delivery after this many ms (default 10000).</summary>
    public double? TimeoutMs;
    public object? Serialize;
}

public sealed class ConsoleSinkOptions
{
    public string? Format;
    public Action<string>? Logger;
    public string? Name;
}

public sealed class ExportOptions
{
    /// <summary>Called (log + drop) when delivery fails; wrapped so it can never throw back into the caller. The message is scrubbed of credentials.</summary>
    public Action<Exception, string, int>? OnError;
    /// <summary>Passed to the serializers (default: the signature is logged as a 16-character prefix).</summary>
    public object? Serialize;
}

public sealed record ExportResult(bool Ok, int Delivered, string? Format, string? Error = null, int Skipped = 0)
{
    public D ToJson()
    {
        var m = new D { ["ok"] = Ok, ["delivered"] = new Num(Delivered.ToString(CultureInfo.InvariantCulture)) };
        if (Format != null) m["format"] = Format;
        if (Error != null) m["error"] = Error;
        if (Skipped > 0) m["skipped"] = new Num(Skipped.ToString(CultureInfo.InvariantCulture));
        return m;
    }
}

/// <summary>
/// A SIEM export for PCA authorization decisions: every verify / deny becomes a security event in OCSF, ArcSight CEF or Elastic Common Schema, citing the
/// cryptographic proof digest and the full delegation chain. Everything is pure and read-only over the decision record (a JSON tree: <c>pcactn</c>,
/// <c>verify</c>, <c>decision</c>, <c>now</c>, <c>session</c>) and mirrors the TypeScript exports of the same name. Shipping never throws into the caller's
/// authorization path.
/// </summary>
public static class SiemExport
{
    /// <summary>A JavaScript <c>undefined</c>: an absent member (JSON null stays null).</summary>
    static readonly object Undef = AtlasPca.InteropJs.JsX.Undef; // one sentinel for every JS-semantics helper (JsX.Truthy reads it)

    sealed record Severity(int Id, string Name, int Cef);

    static readonly Severity SevInfo = new(1, "Informational", 1), SevLow = new(2, "Low", 3), SevMedium = new(3, "Medium", 5), SevHigh = new(4, "High", 8);

    /// <summary>Normative checks whose failure means a real security event (tamper / forged authority), not a policy veto.</summary>
    static readonly string[] SecurityChecks = { "wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay" };

    // ---- JavaScript-flavoured reads ------------------------------------------------------------------------------

    /// <summary><c>o?.[k]</c>: Undef for a non-object or an absent member, JSON null when the member is null.</summary>
    static object? G(object? o, string k) => o is D m ? (m.TryGetValue(k, out var v) ? v : Undef) : Undef;

    static bool Nullish(object? v) => v == null || ReferenceEquals(v, Undef);

    static string Str(object? v, string fallback) => v is string s && s.Length > 0 ? s : fallback;

    static double? FiniteNum(object? v)
    {
        if (ReferenceEquals(v, Undef)) return null;
        return IntentJs.NumOf(v) is double d && double.IsFinite(d) ? d : null;
    }

    /// <summary>Abbreviate a long b64u key for display in narratives / CEF names.</summary>
    static string ShortKey(object? key)
    {
        if (key is not string k || k.Length == 0) return "(none)";
        return k.Length <= 13 ? k : k[..12] + "…";
    }

    static Num NumJ(double d) => new(IntentJs.IsNegZero(d) ? "-0" : JsJson.NumberToString(d));
    static Num IntJ(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    static void Put(D m, string k, object? v) { if (!ReferenceEquals(v, Undef)) m[k] = v; }
    static void PutOpt(D m, string k, object? v) { if (!Nullish(v)) m[k] = v; }

    // ---- normalization -------------------------------------------------------------------------------------------

    sealed class Hop
    {
        public int Index; public bool IsRoot; public string Issuer = "", Holder = ""; public int AddedCaveats;
        public D AsChain() => new() { ["index"] = IntJ(Index), ["is_root"] = IsRoot, ["issuer"] = Issuer, ["holder"] = Holder, ["added_caveats"] = IntJ(AddedCaveats) };
        public D AsView() => new() { ["index"] = IntJ(Index), ["isRoot"] = IsRoot, ["issuer"] = Issuer, ["holder"] = Holder, ["addedCaveats"] = IntJ(AddedCaveats) };
    }

    sealed class Normalized
    {
        public double Now;
        public string Outcome = "", Reason = "";
        public bool CryptographicallyVerifiable;
        public object? Checks;
        public string AgentHolder = "";
        public string? Principal;
        public string Session = "";
        public List<Hop> Hops = new();
        public int Depth;
        public string ChainString = "", Verb = "", Resource = "", ParamsDigest = "", ReversibilityClass = "", GrantRef = "";
        public double Counter;
        public string? Nonce;
        public string PlanRoot = "", SignatureSuite = "", LeafSignature = "", ProofDigest = "";
        public double? RiskScore;
        public object? Tier = Undef;
        public object? ProofStrength = Undef;
        public double? Caution;
        public string? BondRef;
        public bool HumanApproved;
        public List<object?> Approvers = new(), GuardianCosigners = new(), Roles = new();
        public Severity Severity = SevInfo;
        public double Iat, Exp;
    }

    static string SafeDigest(object? p)
    {
        if (ReferenceEquals(p, Undef)) return "(undigestible)";
        try { return Pca.HashCanonical(p); }
        catch (Exception) { return "(undigestible)"; }
    }

    static string FirstReasonOr(object? decision, string fallback)
    {
        if (G(decision, "reasons") is L rs && rs.Count > 0 && rs[0] is string first && first.Length > 0) return first;
        return fallback;
    }

    static (string Outcome, string Reason) ResolveOutcome(object? verify, object? decision)
    {
        if (!JsX.Truthy(verify) || G(verify, "allow") is not true) return ("deny", Str(G(verify, "reason"), "proof failed verification"));
        if (!JsX.Truthy(decision)) return ("allow", "proof verified; no policy decision supplied");
        if (JsX.Truthy(G(decision, "admit"))) return ("allow", FirstReasonOr(decision, "auto-admitted within policy and budget"));
        if (JsX.Truthy(G(decision, "releaseGuardianShare"))) return ("step-up", FirstReasonOr(decision, "policy satisfied but a co-signature is required"));
        return ("deny", FirstReasonOr(decision, "policy did not release authority (default-deny)"));
    }

    static List<Hop> BuildHops(L chain)
    {
        var hops = new List<Hop>();
        for (int i = 0; i < chain.Count; i++)
        {
            var cap = chain[i];
            if (!JsX.Truthy(cap)) continue;
            var parent = i > 0 ? chain[i - 1] : null;
            int parentLen = JsX.Truthy(parent) && G(parent, "caveats") is L pc ? pc.Count : 0;
            int ownLen = G(cap, "caveats") is L oc ? oc.Count : 0;
            hops.Add(new Hop { Index = i, IsRoot = i == 0, Issuer = Str(G(cap, "issuer"), "(none)"), Holder = Str(G(cap, "holder"), "(none)"), AddedCaveats = i == 0 ? ownLen : Math.Max(0, ownLen - parentLen) });
        }
        return hops;
    }

    static void ReadOverride(Normalized n, object? threshold, object? thresholdCheck)
    {
        var shares = JsX.Truthy(threshold) ? G(threshold, "shares") : Undef;
        var list = shares as L ?? new L();
        // `threshold` sits outside the signed body: its shares prove nothing until a threshold verifier passed
        if (thresholdCheck is not "pass") return;
        foreach (var s in list)
        {
            if (!JsX.Truthy(s) || G(s, "role") is not string role) continue;
            n.Roles.Add(role);
            var pk = G(s, "publicKey");
            if (role == "principal" && pk is string) n.Approvers.Add(pk);
            if (role == "guardian" && pk is string) n.GuardianCosigners.Add(pk);
        }
        n.HumanApproved = n.Approvers.Count > 0;
    }

    static bool IsNumber(object? v, double want) => !ReferenceEquals(v, Undef) && IntentJs.NumOf(v) is double d && d == want;

    static Severity SeverityFor(string outcome, object? checks, object? tier)
    {
        if (outcome == "deny") return SecurityChecks.Any(k => G(checks, k) is "fail") ? SevHigh : SevMedium;
        if (outcome == "step-up") return SevMedium;
        return IsNumber(tier, 3) ? SevMedium : IsNumber(tier, 2) ? SevLow : SevInfo;
    }

    static string ShownSignature(string sig, object? mode)
    {
        if (mode is "full") return sig;
        if (mode is "omit") return "(omitted)";
        return sig.Length <= 16 ? sig : sig[..16] + "…";
    }

    /// <summary>One total pass: extract everything the exporters need. Never throws; degrades to best-effort values.</summary>
    static Normalized Normalize(object? record, object? opts)
    {
        var p = G(record, "pcactn");
        var vraw = G(record, "verify");
        var verify = Nullish(vraw) ? null : vraw;
        var checksRaw = verify == null ? Undef : G(verify, "checks");
        var checks = Nullish(checksRaw) ? new D() : checksRaw;
        double now = FiniteNum(G(record, "now")) ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var chain = G(p, "cap_chain") as L ?? new L();
        var hops = BuildHops(chain);
        var leaf = chain.Count == 0 ? Undef : chain[^1];
        var root = chain.Count == 0 ? Undef : chain[0];

        var decision = G(record, "decision");
        var (outcome, reason) = ResolveOutcome(ReferenceEquals(vraw, Undef) ? null : vraw, decision);
        var rt = G(G(decision, "requiredThreshold"), "t");
        var n = new Normalized { Outcome = outcome, Reason = reason };
        ReadOverride(n, G(p, "threshold"), G(checks, "threshold"));

        var grantRef = Str(G(p, "grant_ref"), "(none)");
        var rootIssuer = G(root, "issuer");
        n.Principal = rootIssuer is string ri && ri.Length > 0 ? ri : null;
        n.AgentHolder = Str(G(leaf, "holder"), "(none)");
        var parts = new List<string> { ShortKey(n.Principal ?? "(principal?)") };
        foreach (var h in hops) parts.Add(ShortKey(h.Holder));

        n.Now = now;
        n.CryptographicallyVerifiable = G(checks, "wire") is "pass" && G(checks, "leaf_signature") is "pass";
        n.Checks = checks;
        n.Session = Str(G(record, "session"), grantRef);
        n.Hops = hops;
        n.Depth = hops.Count > 0 ? hops.Count - 1 : 0;
        n.ChainString = string.Join(" -> ", parts);
        var action = G(p, "action");
        n.Verb = Str(G(action, "verb"), "(unknown verb)");
        n.Resource = Str(G(action, "resource"), "(unknown resource)");
        n.ParamsDigest = Str(G(action, "params_digest"), "(none)");
        n.ReversibilityClass = Str(G(action, "reversibility_class"), "(unknown)");
        n.GrantRef = grantRef;
        n.Counter = FiniteNum(G(p, "counter")) ?? -1.0;
        n.Nonce = G(p, "nonce") as string;
        n.PlanRoot = Str(G(G(p, "plan"), "root"), "(none)");
        n.SignatureSuite = Str(G(p, "alg"), "ed25519");
        n.LeafSignature = ShownSignature(Str(G(p, "sig"), "(unsigned)"), G(opts, "signature"));
        n.ProofDigest = SafeDigest(p);
        n.RiskScore = FiniteNum(G(decision, "r"));
        n.Tier = rt;
        n.ProofStrength = G(G(decision, "requiredThreshold"), "proof");
        n.Caution = FiniteNum(G(p, "caution"));
        n.BondRef = G(p, "bond_ref") as string;
        n.Severity = SeverityFor(outcome, checks, rt);
        n.Iat = FiniteNum(G(p, "iat")) ?? now;
        n.Exp = FiniteNum(G(p, "exp")) ?? now;
        return n;
    }

    static D HumanOverride(Normalized n) => new()
    {
        ["human_approved"] = true,
        ["approvers"] = new L(n.Approvers),
        ["guardian_cosigners"] = new L(n.GuardianCosigners),
        ["roles"] = new L(n.Roles),
    };

    /// <summary>The PCA-specific block every schema carries verbatim (the cryptographic edge).</summary>
    static D PcaExtensions(Normalized n)
    {
        var m = new D
        {
            ["proof_digest"] = n.ProofDigest,
            ["leaf_signature"] = n.LeafSignature,
            ["signature_suite"] = n.SignatureSuite,
            ["cryptographically_verifiable"] = n.CryptographicallyVerifiable,
            ["plan_root"] = n.PlanRoot,
            ["params_digest"] = n.ParamsDigest,
            ["grant_ref"] = n.GrantRef,
            ["counter"] = NumJ(n.Counter),
        };
        PutOpt(m, "nonce", n.Nonce);
        m["reversibility_class"] = n.ReversibilityClass;
        if (n.RiskScore is double rs) m["risk_score"] = NumJ(rs);
        Put(m, "risk_tier", n.Tier);
        Put(m, "required_proof", n.ProofStrength);
        if (n.Caution is double c) m["caution"] = NumJ(c);
        PutOpt(m, "bond_ref", n.BondRef);
        m["delegation_depth"] = IntJ(n.Depth);
        m["delegation_chain"] = new L(n.Hops.Select(h => (object?)h.AsChain()));
        m["checks"] = n.Checks;
        if (n.HumanApproved) m["human_override"] = HumanOverride(n);
        return m;
    }

    // ---- OCSF ----------------------------------------------------------------------------------------------------

    const int OcsfClassUid = 3003;
    const string OcsfSchemaVersion = "1.1.0";

    static D UserObj(int typeId, string type, string uid, string name) => new() { ["type_id"] = IntJ(typeId), ["type"] = type, ["uid"] = uid, ["name"] = name };
    static D Observable(string name, string type, int typeId, string value) => new() { ["name"] = name, ["type"] = type, ["type_id"] = IntJ(typeId), ["value"] = value };

    /// <summary>Map a PCA decision to an OCSF 1.x Authorize Session event (Identity and Access Management, class 3003).</summary>
    public static D ToOcsfEvent(object? record, object? opts = null)
    {
        var n = Normalize(record, opts);
        int activityId, actionId, statusId;
        string activityName, actionName, statusName, statusDetail;
        switch (n.Outcome)
        {
            case "allow": activityId = 1; activityName = "Allow"; actionId = 1; actionName = "Allowed"; statusId = 1; statusName = "Success"; statusDetail = n.Reason; break;
            case "deny": activityId = 2; activityName = "Deny"; actionId = 2; actionName = "Denied"; statusId = 2; statusName = "Failure"; statusDetail = n.Reason; break;
            default: activityId = 3; activityName = "Step-Up"; actionId = 99; actionName = "Other"; statusId = 99; statusName = "Other"; statusDetail = "step-up / co-signature required: " + n.Reason; break;
        }
        const string className = "Authorize Session";
        var session = new D { ["uid"] = n.Session };
        PutOpt(session, "issuer", n.Principal);
        return new D
        {
            ["activity_id"] = IntJ(activityId),
            ["activity_name"] = activityName,
            ["category_uid"] = IntJ(3),
            ["category_name"] = "Identity & Access Management",
            ["class_uid"] = IntJ(OcsfClassUid),
            ["class_name"] = className,
            ["type_uid"] = IntJ(OcsfClassUid * 100L + activityId),
            ["type_name"] = className + ": " + activityName,
            ["action_id"] = IntJ(actionId),
            ["action"] = actionName,
            ["severity_id"] = IntJ(n.Severity.Id),
            ["severity"] = n.Severity.Name,
            ["status_id"] = IntJ(statusId),
            ["status"] = statusName,
            ["status_detail"] = statusDetail,
            ["time"] = NumJ(n.Iat),
            ["actor"] = new D
            {
                ["user"] = UserObj(99, "Agent", n.AgentHolder, ShortKey(n.AgentHolder)),
                ["invoked_by"] = n.Principal ?? "(none)",
                ["session"] = session,
                ["app_name"] = "PCA",
            },
            ["user"] = UserObj(1, "User", n.Principal ?? "(none)", ShortKey(n.Principal)),
            ["resources"] = new L { new D { ["type"] = "pca.resource", ["name"] = n.Resource, ["uid"] = n.Resource } },
            ["api"] = new D { ["operation"] = n.Verb, ["service"] = new D { ["name"] = "PCA" } },
            ["metadata"] = new D
            {
                ["version"] = OcsfSchemaVersion,
                ["product"] = new D { ["name"] = "PCA", ["vendor_name"] = "Atlas", ["version"] = OcsfSchemaVersion },
                ["logged_time"] = NumJ(n.Now),
                ["uid"] = n.ProofDigest,
                ["labels"] = new L { "pca", "outcome:" + n.Outcome, "suite:" + n.SignatureSuite },
            },
            ["observables"] = new L
            {
                Observable("actor.user.uid", "User Name", 4, n.AgentHolder),
                Observable("pca.proof.digest", "Hash", 8, n.ProofDigest),
                Observable("resources.uid", "Resource UID", 10, n.Resource),
            },
            ["count"] = IntJ(1),
            ["message"] = Narrative(n),
            ["unmapped"] = PcaExtensions(n),
        };
    }

    // ---- CEF -----------------------------------------------------------------------------------------------------

    /// <summary>Escape a CEF header field: backslash and pipe are reserved.</summary>
    static string CefHeaderEscape(string s) => Regex.Replace(s.Replace("\\", "\\\\").Replace("|", "\\|"), "[\r\n]+", " ");

    /// <summary>Escape a CEF extension value: backslash, equals and newlines are reserved.</summary>
    static string CefExtValueEscape(string s) => s.Replace("\\", "\\\\").Replace("=", "\\=").Replace("\r\n", "\\n").Replace("\r", "\\n").Replace("\n", "\\n");

    static void Ext(List<string> o, string k, string v) => o.Add(k + "=" + CefExtValueEscape(v));

    /// <summary>The entries of <c>Object.entries(v)</c> rendered <c>key:value</c> (an object, an array or the characters of a string).</summary>
    static List<string> CheckPairs(object? v) => JsX.Keys(v).Select(k => k + ":" + JsJson.ToJsString(JsX.ValueOf(v, k))).ToList();

    /// <summary>Map a PCA decision to a single ArcSight CEF line: <c>CEF:0|Atlas|PCA|&lt;wireVer&gt;|pca-authz-&lt;outcome&gt;|&lt;name&gt;|&lt;sev&gt;|ext...</c>, with the
    /// proof digest, the delegation chain, the risk tier and proof strength as custom fields.</summary>
    public static string ToCef(object? record, object? opts = null)
    {
        var n = Normalize(record, opts);
        var wireVer = FiniteNum(G(G(record, "pcactn"), "ver"));
        var deviceVersion = wireVer is double wv ? JsJson.NumberToString(wv) : "2";
        var signatureId = "pca-authz-" + n.Outcome;
        var name = $"PCA authorization {n.Outcome}: {n.Verb} on {n.Resource}";
        var header = string.Join("|", "CEF:0", CefHeaderEscape("Atlas"), CefHeaderEscape("PCA"), CefHeaderEscape(deviceVersion), CefHeaderEscape(signatureId), CefHeaderEscape(name), n.Severity.Cef.ToString(CultureInfo.InvariantCulture));
        var principal = n.Principal ?? "(none)";
        var x = new List<string>();
        Ext(x, "act", n.Outcome);
        Ext(x, "outcome", n.Outcome);
        Ext(x, "suser", principal);
        Ext(x, "suid", principal);
        Ext(x, "duser", n.AgentHolder);
        Ext(x, "duid", n.AgentHolder);
        Ext(x, "destinationServiceName", n.Verb);
        Ext(x, "rt", JsJson.NumberToString(n.Now));
        Ext(x, "start", JsJson.NumberToString(n.Iat));
        Ext(x, "end", JsJson.NumberToString(n.Exp));
        Ext(x, "externalId", n.Nonce ?? JsJson.NumberToString(n.Counter));
        Ext(x, "request", n.Resource);
        Ext(x, "requestMethod", n.Verb);
        Ext(x, "cs1Label", "pcaProofDigest");
        Ext(x, "cs1", n.ProofDigest);
        Ext(x, "cs2Label", "pcaDelegationChain");
        Ext(x, "cs2", n.ChainString);
        Ext(x, "cs3Label", "pcaProofStrength");
        Ext(x, "cs3", Nullish(n.ProofStrength) ? "n/a" : JsJson.ToJsString(n.ProofStrength));
        Ext(x, "cs4Label", "pcaSignatureSuite");
        Ext(x, "cs4", n.SignatureSuite);
        Ext(x, "cs5Label", "pcaVerifyChecks");
        Ext(x, "cs5", string.Join(";", CheckPairs(n.Checks)));
        Ext(x, "cs6Label", "pcaGrantRef");
        Ext(x, "cs6", n.GrantRef);
        Ext(x, "cn1Label", "pcaRiskScore");
        Ext(x, "cn1", n.RiskScore is double r ? JsJson.NumberToString(r) : "");
        Ext(x, "cn2Label", "pcaDelegationDepth");
        Ext(x, "cn2", n.Depth.ToString(CultureInfo.InvariantCulture));
        Ext(x, "cn3Label", "pcaRiskTier");
        Ext(x, "cn3", Nullish(n.Tier) ? "" : JsJson.ToJsString(n.Tier));
        Ext(x, "flexString1Label", "pcaHumanApproved");
        Ext(x, "flexString1", n.HumanApproved ? "true" : "false");
        Ext(x, "cat", "authorization");
        Ext(x, "msg", n.Reason);
        return header + "|" + string.Join(" ", x);
    }

    // ---- ECS -----------------------------------------------------------------------------------------------------

    const string EcsVersion = "8.11.0";

    static L Dedupe(IEnumerable<object?> items)
    {
        var o = new L();
        foreach (var v in items) if (!o.Any(x => x is string a && v is string b && a == b)) o.Add(v);
        return o;
    }

    /// <summary>Map a PCA decision to an Elastic Common Schema event (category iam; the PCA edge under <c>pca.*</c>).</summary>
    public static D ToEcs(object? record, object? opts = null)
    {
        var n = Normalize(record, opts);
        var users = new List<object?> { n.AgentHolder };
        if (!string.IsNullOrEmpty(n.Principal)) users.Add(n.Principal);
        users.AddRange(n.Approvers);
        var type = n.Outcome == "allow" ? "allowed" : n.Outcome == "deny" ? "denied" : "info";
        var outcome = n.Outcome == "allow" ? "success" : n.Outcome == "deny" ? "failure" : "unknown";
        var ev = new D
        {
            ["kind"] = "event",
            ["category"] = new L { "iam" },
            ["type"] = new L { type },
            ["action"] = n.Verb,
            ["outcome"] = outcome,
            ["module"] = "pca",
            ["dataset"] = "pca.authorization",
            ["provider"] = "pca",
            ["id"] = n.ProofDigest,
            ["severity"] = IntJ(n.Severity.Cef),
            ["reason"] = n.Reason,
        };
        if (n.RiskScore is double rs) ev["risk_score"] = NumJ(rs);

        var proof = new D
        {
            ["digest"] = n.ProofDigest,
            ["leaf_signature"] = n.LeafSignature,
            ["signature_suite"] = n.SignatureSuite,
            ["cryptographically_verifiable"] = n.CryptographicallyVerifiable,
            ["plan_root"] = n.PlanRoot,
            ["params_digest"] = n.ParamsDigest,
        };
        var risk = new D();
        if (n.RiskScore is double sc) risk["score"] = NumJ(sc);
        Put(risk, "tier", n.Tier);
        Put(risk, "required_proof", n.ProofStrength);
        if (n.Caution is double ca) risk["caution"] = NumJ(ca);
        var pca = new D
        {
            ["outcome"] = n.Outcome,
            ["proof"] = proof,
            ["risk"] = risk,
            ["delegation"] = new D { ["depth"] = IntJ(n.Depth), ["chain"] = n.ChainString, ["hops"] = new L(n.Hops.Select(h => (object?)h.AsView())) },
            ["grant_ref"] = n.GrantRef,
            ["counter"] = NumJ(n.Counter),
        };
        PutOpt(pca, "nonce", n.Nonce);
        pca["reversibility_class"] = n.ReversibilityClass;
        PutOpt(pca, "bond_ref", n.BondRef);
        pca["checks"] = n.Checks;
        if (n.HumanApproved) pca["human_override"] = HumanOverride(n);

        return new D
        {
            ["@timestamp"] = IsoOf(n.Iat),
            ["ecs.version"] = EcsVersion,
            ["event"] = ev,
            ["user"] = new D
            {
                ["id"] = n.AgentHolder,
                ["name"] = ShortKey(n.AgentHolder),
                ["roles"] = new L { "agent" },
                ["effective"] = new D { ["id"] = n.Principal ?? "(none)", ["name"] = ShortKey(n.Principal) },
            },
            ["service"] = new D { ["name"] = "pca", ["type"] = "authorization" },
            ["related"] = new D { ["user"] = Dedupe(users), ["hash"] = Dedupe(new object?[] { n.ProofDigest, n.LeafSignature }) },
            ["message"] = Narrative(n),
            ["pca"] = pca,
        };
    }

    const string EpochIso = "1970-01-01T00:00:00.000Z";

    /// <summary><c>new Date(ms).toISOString()</c>, or the epoch for a time outside the Date range.</summary>
    internal static string IsoOf(double ms)
    {
        if (double.IsNaN(ms) || double.IsInfinity(ms)) return EpochIso;
        double tr = Math.Truncate(ms);
        if (Math.Abs(tr) > 8.64e15) return EpochIso;
        long t = (long)tr;
        long days = Math.DivRem(t, 86_400_000L, out long rem);
        if (rem < 0) { rem += 86_400_000L; days--; }
        // civil date from days since 1970-01-01 (proleptic Gregorian)
        long z = days + 719468;
        long era = (z >= 0 ? z : z - 146096) / 146097;
        long doe = z - era * 146097;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long d = doy - (153 * mp + 2) / 5 + 1;
        long m = mp < 10 ? mp + 3 : mp - 9;
        if (m <= 2) y++;
        var year = y is >= 0 and <= 9999 ? y.ToString("D4", CultureInfo.InvariantCulture) : (y < 0 ? "-" : "+") + Math.Abs(y).ToString("D6", CultureInfo.InvariantCulture);
        long h = rem / 3_600_000L, mi = rem / 60_000L % 60, s = rem / 1000L % 60, msPart = rem % 1000;
        return string.Format(CultureInfo.InvariantCulture, "{0}-{1:D2}-{2:D2}T{3:D2}:{4:D2}:{5:D2}.{6:D3}Z", year, m, d, h, mi, s, msPart);
    }

    /// <summary>One-sentence plain-English narration of the whole event (shared across schemas).</summary>
    static string Narrative(Normalized n)
    {
        var word = n.Outcome == "allow" ? "ALLOWED" : n.Outcome == "deny" ? "DENIED" : "STEP-UP";
        return $"Agent {ShortKey(n.AgentHolder)} {word} to {n.Verb} on {n.Resource} ({n.Hops.Count}-hop chain rooted at principal {ShortKey(n.Principal)}; "
            + (n.CryptographicallyVerifiable ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (n.HumanApproved ? "; human-signed step-up" : "") + "). " + n.Reason;
    }

    // ---- sinks ---------------------------------------------------------------------------------------------------

    /// <summary>Serialize a decision record into the given schema ("ocsf", "cef" or "ecs"; anything but cef / ocsf is ECS).</summary>
    public static SiemEvent FormatDecision(object? record, string? format, object? opts = null)
    {
        if (format == "cef") return new SiemEvent(format, null, ToCef(record, opts));
        var obj = format == "ocsf" ? ToOcsfEvent(record, opts) : ToEcs(record, opts);
        return new SiemEvent(format, obj, JsJson.Stringify(obj));
    }

    static string? ContentTypeOf(string? format) => format is "ocsf" or "ecs" ? "application/x-ndjson" : format == "cef" ? "text/plain; charset=utf-8" : null;

    // JavaScript whitespace (what \s matches), spelled out because the .NET \s differs.
    const string Ws = @" \t\n\u000B\f\r\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
    // \b before a word character, spelled out because the .NET \b is Unicode-aware.
    const string Wb = "(?<![A-Za-z0-9_])";

    /// <summary>A literal word matched case-insensitively over ASCII letters only (the JavaScript i flag without u does not fold the Kelvin sign into k).</summary>
    static string Ci(string word) => string.Concat(word.Select(c => char.IsAsciiLetter(c) ? $"[{char.ToLowerInvariant(c)}{char.ToUpperInvariant(c)}]" : Regex.Escape(c.ToString())));

    static readonly Regex UrlUserinfo = new(@"([A-Za-z][A-Za-z0-9+.\-]*://)[^" + Ws + @"/@]*:[^" + Ws + @"/@]*@", RegexOptions.CultureInvariant);
    static readonly Regex AuthHeader = new(Wb + "(" + Ci("authorization") + "[\"']?[" + Ws + "]*[:=][" + Ws + "]*)[^\\n\"']*", RegexOptions.CultureInvariant);
    static readonly Regex Scheme = new(Wb + "(" + Ci("Bearer") + "|" + Ci("Basic") + "|" + Ci("Splunk") + "|" + Ci("Token") + ")[" + Ws + @"]+[A-Za-z0-9_.~+/=\-]{6,}", RegexOptions.CultureInvariant);
    static readonly Regex Keyed = new(Wb + "((?:" + string.Join("|", new[] { Ci("token"), Ci("secret"), Ci("password"), Ci("passwd"), Ci("pwd"), Ci("api") + "[_-]?" + Ci("key"), Ci("dd-api-key"), Ci("key"), Ci("signature"), Ci("sig"), Ci("credential") })
        + ")[\"']?[" + Ws + "]*[:=][" + Ws + "]*)(\"[^\"]*\"|'[^']*'|[^" + Ws + "\"'&,;]+)", RegexOptions.CultureInvariant);
    static readonly Regex LongRun = new("[A-Za-z0-9_-]{32,}", RegexOptions.CultureInvariant);

    /// <summary>Remove credentials from an error message before it is returned or handed to <c>OnError</c>: URL userinfo, token / key style pairs, bearer
    /// credentials and long token-like runs; at most 300 characters.</summary>
    public static string ScrubError(string? message)
    {
        var t = message ?? "null";
        t = UrlUserinfo.Replace(t, m => m.Groups[1].Value + "[redacted]@");
        t = AuthHeader.Replace(t, m => m.Groups[1].Value + "[redacted]");
        t = Scheme.Replace(t, m => m.Groups[1].Value + " [redacted]");
        t = Keyed.Replace(t, m => m.Groups[1].Value + "[redacted]");
        t = LongRun.Replace(t, "[redacted]");
        return t.Length > 300 ? t[..300] + "..." : t;
    }

    static string MessageOf(Exception e) => e is AggregateException { InnerException: { } inner } ? inner.Message : e.Message;

    static readonly HttpClient SharedClient = new();

    /// <summary>A fetch over HttpClient: one request, the status line mapped to <see cref="FetchLikeResponse"/>.</summary>
    public static FetchLike DefaultFetch() => async (url, init) =>
    {
        using var req = new HttpRequestMessage(new HttpMethod(init.Method), url) { Content = new StringContent(init.Body, Encoding.UTF8) };
        req.Content.Headers.Remove("Content-Type");
        foreach (var (k, v) in init.Headers)
            if (!req.Headers.TryAddWithoutValidation(k, v)) req.Content.Headers.TryAddWithoutValidation(k, v);
        using var res = await SharedClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, init.Signal).ConfigureAwait(false);
        return new FetchLikeResponse(res.IsSuccessStatusCode, (int)res.StatusCode, res.ReasonPhrase);
    };

    sealed class HttpSink : ISiemSink
    {
        readonly string url;
        readonly HttpSinkOptions options;
        public string Name { get; }
        public string? Format { get; }

        public HttpSink(string url, HttpSinkOptions options)
        {
            this.url = url; this.options = options;
            Format = options.Format;
            Name = options.Name ?? $"http:{Format}";
        }

        public async Task<SinkResult> DeliverAsync(IReadOnlyList<SiemEvent> events)
        {
            try
            {
                var doFetch = options.Fetch ?? DefaultFetch();
                var body = string.Join("\n", events.Select(e => e.Line));
                var headers = new Dictionary<string, string>();
                var ct = options.ContentType ?? ContentTypeOf(Format);
                if (ct != null) headers["content-type"] = ct;
                if (options.Headers != null) foreach (var (k, v) in options.Headers) headers[k] = v;
                double t = options.TimeoutMs ?? 10_000.0;
                int ms = double.IsFinite(t) && t > 0 ? (int)Math.Min(t, int.MaxValue) : 10_000;
                using var cts = new CancellationTokenSource();
                var fetchTask = Task.Run(() => doFetch(url, new FetchInit("POST", headers, body, cts.Token)));
                var timeout = Task.Delay(ms);
                if (await Task.WhenAny(fetchTask, timeout).ConfigureAwait(false) == timeout)
                {
                    cts.Cancel();
                    _ = fetchTask.ContinueWith(x => { _ = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted); // a late failure of the abandoned fetch is not observed
                    return new SinkResult(false, "delivery timed out");
                }
                var res = await fetchTask.ConfigureAwait(false);
                if (res.Ok) return new SinkResult(true);
                return new SinkResult(false, ScrubError($"HTTP {res.Status}{(string.IsNullOrEmpty(res.StatusText) ? "" : " " + res.StatusText)}"));
            }
            catch (Exception e) { return new SinkResult(false, ScrubError(MessageOf(e))); }
        }
    }

    /// <summary>An HTTP sink that batches events into one POST: NDJSON for OCSF / ECS, the raw CEF lines for CEF (the body is the lines joined by newlines).
    /// Delivery never throws: a network error, a timeout or a non-2xx status is returned as a failure result.</summary>
    public static ISiemSink HttpSinkOf(string url, HttpSinkOptions options) => new HttpSink(url, options);

    sealed class ConsoleSink : ISiemSink
    {
        readonly Action<string> logger;
        public string Name { get; }
        public string? Format { get; }

        public ConsoleSink(ConsoleSinkOptions? o)
        {
            Format = o?.Format ?? "ocsf";
            logger = o?.Logger ?? Console.WriteLine;
            Name = o?.Name ?? $"console:{Format}";
        }

        public Task<SinkResult> DeliverAsync(IReadOnlyList<SiemEvent> events)
        {
            try
            {
                foreach (var e in events) logger(e.Line);
                return Task.FromResult(new SinkResult(true));
            }
            catch (Exception e) { return Task.FromResult(new SinkResult(false, ScrubError(MessageOf(e)))); }
        }
    }

    /// <summary>A sink that writes each event's serialized line to a logger (default standard output). Never throws.</summary>
    public static ISiemSink ConsoleSinkOf(ConsoleSinkOptions? options = null) => new ConsoleSink(options);

    // ---- export orchestration --------------------------------------------------------------------------------------

    static void SafeOnError(ExportOptions? options, Exception error, string sink, int count)
    {
        if (options?.OnError == null) return;
        try { options.OnError(error, sink, count); }
        catch (Exception) { /* an onError that throws must not touch the auth path */ }
    }

    /// <summary>Export one PCA decision to a sink. Fail-safe: errors are reported via OnError and returned, never thrown.</summary>
    public static Task<ExportResult> ExportDecisionAsync(object? record, ISiemSink sink, ExportOptions? options = null) => ExportBatchAsync(new List<object?> { record }, sink, options);

    /// <summary>Export a batch of PCA decisions to a sink in one delivery. Fail-safe, exactly like <see cref="ExportDecisionAsync"/>.</summary>
    public static async Task<ExportResult> ExportBatchAsync(IReadOnlyList<object?> records, ISiemSink sink, ExportOptions? options = null)
    {
        var format = sink?.Format;
        int count = 0;
        try
        {
            // one record that cannot be serialized must not take the others' audit trail with it
            var events = new List<SiemEvent>();
            int skipped = 0;
            foreach (var r in records)
            {
                try { events.Add(FormatDecision(r, format, options?.Serialize)); }
                catch (Exception e)
                {
                    skipped++;
                    SafeOnError(options, new Exception(ScrubError("record could not be serialized: " + MessageOf(e))), sink!.Name, 1);
                }
            }
            count = events.Count;
            if (events.Count == 0 && skipped > 0) return new ExportResult(false, 0, format, "no record could be serialized", skipped);
            var res = await sink!.DeliverAsync(events).ConfigureAwait(false);
            if (res.Ok) return new ExportResult(true, events.Count, format, null, skipped);
            var err = new Exception(ScrubError(res.Error ?? "sink reported a delivery failure"));
            SafeOnError(options, err, sink.Name, events.Count);
            return new ExportResult(false, 0, format, err.Message, skipped);
        }
        catch (Exception e)
        {
            var err = new Exception(ScrubError(MessageOf(e)));
            SafeOnError(options, err, sink?.Name ?? "(unknown sink)", count);
            return new ExportResult(false, 0, format, err.Message);
        }
    }
}
