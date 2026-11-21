using System.Security.Cryptography;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.A2aPkg;

/// <summary>The A2A (Agent2Agent) adapter for PCA: proof-carrying Tasks, signed Agent Cards, the AP2 payment-mandate envelope, the AUTH_REQUIRED
/// mapping, per-hop delegation, push tokens, signed task-update receipts and the extended Agent Card. Pure functions over parsed JSON (D, L, string,
/// bool, Num, null); every verifier is fail-closed. The needs / chain-extension / push / receipt verification core lives in <see cref="A2a"/>; this
/// class adds the rest and delegates to it.
/// A PCActn is verified by a <see cref="PcaVerifier"/>: the default (<see cref="CoreVerifier"/>) runs the core verifier plus the checks the options
/// carry (plan authorization from <c>context.planAuthorized</c>, the params digest, a revocation predicate, PQ pins) and then demands every required
/// check to PASS; a check the verifier cannot evaluate (no revocation predicate, no authorized plan) is never reported and so fails closed.</summary>
public static class A2aPca
{
    public const string PcaA2aExtensionUri = "https://atlasauth.net/a2a/ext/pca/v2";
    public const string TaskStateAuthRequired = "TASK_STATE_AUTH_REQUIRED";
    public const string TaskStateInputRequired = "TASK_STATE_INPUT_REQUIRED";
    public const string A2aReceiptDomain = A2a.ReceiptDomain;
    public const string ReceiptKey = PcaA2aExtensionUri + "#receipt";
    const string NeedKey = PcaA2aExtensionUri + "#need";
    const string PcaPassportHeader = "pca_passport";

    /// <summary><c>@context</c> of the PCA payment-mandate envelope (a PCA-defined envelope, not an AP2 credential).</summary>
    public static IReadOnlyList<string> A2aAp2Context => new[] { "https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2" };
    public static IReadOnlyList<string> DefaultRequiredChecks => new[] { "counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" };
    static HashSet<string> Terminal => new() { "TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED" };
    static HashSet<string> States => new(Terminal) { "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED" };

    // ---- JavaScript-ish helpers ----

    /// <summary><c>[...x]</c>: a list copy; a string spreads by code point; null / non-iterables throw.</summary>
    internal static L SpreadList(object? x)
    {
        if (x is L l) return new L(l);
        if (x is string s)
        {
            var o = new L();
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(s.Substring(i, 2)); i++; }
                else o.Add(s[i].ToString());
            }
            return o;
        }
        throw JsX.TypeError("not iterable");
    }

    static bool InSet(HashSet<string> set, object? o) => o is string s && set.Contains(s);

    static bool SafeNat(object? o) => JsX.SafeInt(o) && JsX.NumOf(o)!.Value >= 0;

    static D Refuse(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    // ---- 1. proof-carrying Tasks ----

    static D WithPca(object? metadata, object? pcActn)
    {
        var m = JsX.Spread(metadata ?? new D());
        m[PcaA2aExtensionUri] = pcActn;
        return m;
    }

    /// <summary>Read a PCActn out of a metadata bag (fail-closed: a missing / non-object value yields null).</summary>
    static D? ReadPca(object? metadata) => metadata is D m && m.GetValueOrDefault(PcaA2aExtensionUri) is D v ? v : null;

    /// <summary>Attach a PCActn to a Task (a copy; the input is not mutated).</summary>
    public static D AttachPcaToA2ATask(object? task, object? pcActn)
    {
        var md = JsX.JsonOf(JsX.At(task, "metadata"));
        var o = JsX.Spread(task);
        o["metadata"] = WithPca(md, pcActn);
        return o;
    }

    /// <summary>Attach a PCActn to a single Message (a copy).</summary>
    public static D AttachPcaToA2AMessage(object? message, object? pcActn) => AttachPcaToA2ATask(message, pcActn);

    /// <summary>The PCActn carried on a Task: task metadata, then the current status message, then the most recent history message. Null when none.</summary>
    public static D? ExtractPca(object? task)
    {
        if (task == null) return null;
        var onTask = ReadPca(JsX.JsonOf(JsX.Opt(task, "metadata")));
        if (onTask != null) return onTask;
        var status = JsX.JsonOf(JsX.Opt(task, "status"));
        if (status is D)
        {
            var onStatus = ReadPca(JsX.JsonOf(JsX.Opt(JsX.JsonOf(JsX.Opt(status, "message")), "metadata")));
            if (onStatus != null) return onStatus;
        }
        if (JsX.JsonOf(JsX.Opt(task, "history")) is L h)
        {
            for (int i = h.Count - 1; i >= 0; i--)
            {
                var onMsg = ReadPca(JsX.JsonOf(JsX.Opt(h[i], "metadata")));
                if (onMsg != null) return onMsg;
            }
        }
        return null;
    }

    /// <summary>The PCActn carried on a single Message (fail-closed).</summary>
    public static D? ExtractPcaFromMessage(object? message) => message == null ? null : ReadPca(JsX.JsonOf(JsX.Opt(message, "metadata")));

    // ---- verification ----

    /// <summary>What a <see cref="PcaVerifier"/> is asked.</summary>
    public sealed class Request
    {
        public D Grant { get; init; } = new();
        public string? Aud { get; init; }
        public long Now { get; init; }
        public D Context { get; init; } = new();
        public IReadOnlyCollection<string>? AllowedSuites { get; init; }
        public D? PqPins { get; init; }
        public IReadOnlyList<string> Require { get; init; } = Array.Empty<string>();
        public Func<D, D, bool>? IsRevoked { get; init; }
    }

    /// <summary>A verifier's verdict: <c>Checks</c> name to "pass" | "fail" (a check it does not evaluate is absent).</summary>
    public sealed class Outcome
    {
        public bool Allow { get; }
        public Dictionary<string, string> Checks { get; }
        public List<string> Reasons { get; }
        public Outcome(bool allow, Dictionary<string, string> checks, List<string> reasons) { Allow = allow; Checks = checks; Reasons = reasons; }
        internal D ToMap() => new()
        {
            ["allow"] = Allow,
            ["checks"] = Checks.ToDictionary(e => e.Key, e => (object?)e.Value),
            ["reasons"] = Reasons.Cast<object?>().ToList(),
        };
    }

    /// <summary>The full PCActn verifier plugged into the A2A surfaces. A throw is a refusal.</summary>
    public delegate Outcome PcaVerifier(D pcActn, Request request);

    /// <summary>The default verifier: the core verifier plus plan authorization, params digest, revocation and PQ pins; every required check must pass.</summary>
    public static PcaVerifier CoreVerifier => Core;

    static Outcome Core(D p, Request r)
    {
        var checks = new Dictionary<string, string>();
        var reasons = new List<string>();
        var root = (p.GetValueOrDefault("plan") as D)?.GetValueOrDefault("root");
        var pa = r.Context.GetValueOrDefault("planAuthorized");
        var roots = pa is true && root is string rs ? new PlanRootPolicy(new[] { rs }, false)
            : pa is bool ? new PlanRootPolicy(Array.Empty<string>(), false) : new PlanRootPolicy();
        var v = Pca.VerifyPcactnCore(p, r.Grant, r.Now, r.Aud!, r.AllowedSuites, null, null, null, roots);
        bool allow = v.Allow;
        foreach (var (k, ok) in v.Checks) checks[k] = ok ? "pass" : "fail";
        if (!string.IsNullOrEmpty(v.Reason)) reasons.Add(v.Reason);
        if (r.PqPins != null)
        {
            var issuer = r.Grant.GetValueOrDefault("issuer");
            var alg = r.Grant.GetValueOrDefault("alg");
            var pin = issuer is string iss ? r.PqPins.GetValueOrDefault(iss) : null;
            bool classical = alg == null || alg is string a && a == "ed25519";
            bool ok = pin == null ? classical : !classical && pin is string ps && r.Grant.GetValueOrDefault("pq_pk") is string pk && ps == pk;
            checks["pq_pin"] = ok ? "pass" : "fail";
            if (!ok) { allow = false; reasons.Add("pq_pin: the grant's post-quantum key is not the pinned one for its issuer"); }
        }
        if (r.Context.GetValueOrDefault("params") is D prms)
        {
            var want = (p.GetValueOrDefault("action") as D)?.GetValueOrDefault("params_digest");
            bool ok;
            try { ok = want is string ws && Pca.ParamsDigest(prms) == ws; } catch (Exception) { ok = false; }
            checks["params_digest"] = ok ? "pass" : "fail";
            if (!ok) { allow = false; reasons.Add("params_digest: the params do not open action.params_digest"); }
        }
        if (r.IsRevoked != null)
        {
            bool ok;
            try { ok = !r.IsRevoked(p, r.Grant); } catch (Exception) { ok = false; }
            checks["revocation"] = ok ? "pass" : "fail";
            if (!ok) { allow = false; reasons.Add("revocation: the proof or its chain is revoked (or the revocation check failed)"); }
        }
        foreach (var name in r.Require)
        {
            if (!(checks.GetValueOrDefault(name) == "pass"))
            {
                allow = false;
                reasons.Add($"{name}: required check did not pass ({(checks.ContainsKey(name) ? "failed" : "not enforced")})");
            }
        }
        return new Outcome(allow, checks, reasons);
    }

    /// <summary>Options shared by every PCActn verification surface. One of <c>Grant</c> / <c>ExpectedRootIssuer</c> is required.</summary>
    public sealed class VerifyOptions
    {
        /// <summary>This resource server / Atlas instance id; compared against the PCActn's signed aud.</summary>
        public string? Aud { get; set; }
        /// <summary>Verification clock (epoch ms); null: the wall clock.</summary>
        public long? Now { get; set; }
        /// <summary>The grant from YOUR store: the chain root must be byte-identical to it.</summary>
        public D? Grant { get; set; }
        /// <summary>The principal the chain must be rooted at (b64u).</summary>
        public string? ExpectedRootIssuer { get; set; }
        /// <summary>Verifier-side issuer to pq_pk pins.</summary>
        public D? PqPins { get; set; }
        public IReadOnlyCollection<string>? AllowedSuites { get; set; }
        /// <summary>The resource server's view of the action (<c>params</c>, <c>plan</c>, <c>planAuthorized</c>, ...), per PCActn.</summary>
        public Func<D, D>? Context { get; set; }
        /// <summary>Checks that must PASS; null: <see cref="DefaultRequiredChecks"/>.</summary>
        public IReadOnlyList<string>? RequireChecks { get; set; }
        /// <summary>Revocation predicate (pcActn, grant) -> revoked?; absent: the revocation check is not enforced and a default-required run refuses.</summary>
        public Func<D, D, bool>? IsRevoked { get; set; }
        /// <summary>The verifier; null: <see cref="CoreVerifier"/>.</summary>
        public PcaVerifier? Verifier { get; set; }
        /// <summary>The human-present signer set of <see cref="VerifyA2APaymentMandate"/>.</summary>
        public L? HumanSignerSet { get; set; }
        /// <summary><see cref="PcaA2AMiddleware"/>: false lets a Task with NO proof through (a present proof must still verify). Default true.</summary>
        public bool RequireProof { get; set; } = true;
        /// <summary>A shallow copy.</summary>
        public VerifyOptions Copy() => (VerifyOptions)MemberwiseClone();
    }

    /// <summary>Thrown when an A2A verifier is configured without any authority (<c>Grant</c> or <c>ExpectedRootIssuer</c>).</summary>
    public sealed class A2AAuthorityError : Exception
    {
        public string Code => "authority_required";
        public A2AAuthorityError() : base("pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority") { }
    }

    static void AssertAuthority(VerifyOptions? o)
    {
        bool hasGrant = o?.Grant != null;
        bool hasIssuer = !string.IsNullOrEmpty(o?.ExpectedRootIssuer);
        if (!hasGrant && !hasIssuer) throw new A2AAuthorityError();
    }

    /// <summary>The result of verifying a proof-carrying A2A artifact.</summary>
    public sealed class Verification
    {
        public bool Ok { get; }
        public string? Reason { get; }
        public D? Result { get; }
        public object? PcActn { get; }
        // the PCActn member is written when the caller's argument was given, even as null (a JavaScript null stays, undefined is dropped)
        internal bool PcActnGiven { get; init; }
        internal Verification(bool ok, string? reason, D? result, object? pcActn) { Ok = ok; Reason = reason; Result = result; PcActn = pcActn; }
        /// <summary>The JSON form: <c>ok</c>, then <c>reason</c>, <c>result</c>, <c>pcActn</c> when present.</summary>
        public D ToMap()
        {
            var m = new D { ["ok"] = Ok };
            if (Reason != null) m["reason"] = Reason;
            if (Result != null) m["result"] = Result;
            if (PcActn != null || PcActnGiven) m["pcActn"] = PcActn;
            return m;
        }
    }

    static Verification Bad(string reason, object? pcActn) => new(false, reason, null, pcActn);
    static Verification BadGiven(string reason, object? pcActn) => new(false, reason, null, pcActn) { PcActnGiven = true };

    static Verification VerifyPcActn(object? pcActn, VerifyOptions opts)
    {
        AssertAuthority(opts);
        if (pcActn is not D && pcActn is not L) return Bad("PCActn is not an object", null);
        var chain = pcActn is D pd ? pd.GetValueOrDefault("cap_chain") : null;
        var root = chain is L cl && cl.Count > 0 ? cl[0] : null;
        if (!JsX.Truthy(root)) return Bad("PCActn carries no capability chain", pcActn);
        if (opts.ExpectedRootIssuer != null && !JsX.StrictEq(JsX.JsonOf(JsX.Opt(root, "issuer")), opts.ExpectedRootIssuer))
            return Bad("chain root issuer does not match the expected principal", pcActn);
        // Without a stored grant, the root is admitted only under the pinned principal; a non-Ed25519 root then needs a PQ pin.
        var grant = opts.Grant ?? (root as D ?? new D());
        var pqPins = opts.Grant == null ? (opts.PqPins ?? new D()) : opts.PqPins;
        var context = opts.Context != null ? opts.Context((D)pcActn) : new D();
        context ??= new D();
        var req = new Request
        {
            Grant = grant, Aud = opts.Aud, Now = opts.Now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Context = context,
            AllowedSuites = opts.AllowedSuites, PqPins = pqPins, Require = opts.RequireChecks ?? DefaultRequiredChecks, IsRevoked = opts.IsRevoked,
        };
        Outcome outcome;
        try { outcome = (opts.Verifier ?? CoreVerifier)((D)pcActn, req); }
        catch (Exception e) { outcome = new Outcome(false, new Dictionary<string, string>(), new List<string> { "verifier error (fail closed): " + e.GetType().Name }); }
        var reason = outcome.Allow ? null : outcome.Reasons.Count == 0 ? "PCActn verification failed" : string.Join("; ", outcome.Reasons);
        var result = outcome.ToMap();
        if (reason != null) result["reason"] = reason;
        return outcome.Allow ? new Verification(true, null, result, pcActn) : new Verification(false, reason, result, pcActn);
    }

    /// <summary>Verify the proof-carrying action on an A2A Task; fail-closed (no PCActn, or one that does not verify, is rejected).</summary>
    public static Verification VerifyA2ATask(object? task, VerifyOptions opts)
    {
        AssertAuthority(opts);
        var pcActn = ExtractPca(task);
        if (pcActn == null) return Bad("no proof-carrying action attached to this task", null);
        return VerifyPcActn(pcActn, opts);
    }

    /// <summary>A guard that verifies the proof on each incoming Task. A present but invalid proof is always rejected;
    /// <c>RequireProof</c> false lets a Task with NO proof through.</summary>
    public static Func<object?, Verification> PcaA2AMiddleware(VerifyOptions opts)
    {
        AssertAuthority(opts);
        var require = opts.RequireProof;
        return task =>
        {
            var pcActn = ExtractPca(task);
            if (pcActn == null) return require ? Bad("proof-carrying action required but none attached to task", null) : new Verification(true, null, null, null);
            return VerifyPcActn(pcActn, opts);
        };
    }

    // ---- 2. signed Agent Cards ----

    /// <summary>RFC 8785 canonical bytes (see <see cref="A2aCard.JcsBytes"/>).</summary>
    public static byte[] JcsBytes(object? value) => A2aCard.JcsBytes(value);

    /// <summary>The A2A 1.0 <c>AgentCard</c> problems (see <see cref="A2aCard.ValidateAgentCard1"/>).</summary>
    public static List<string> ValidateAgentCard1(object? card) => A2aCard.ValidateAgentCard1(card);

    /// <summary>The canonical bytes a card signature covers: the card with <c>signatures</c> removed (RFC 8785).</summary>
    public static byte[] CardSigningBytes(object? card)
    {
        var rest = JsX.Spread(card);
        rest.Remove("signatures");
        return A2aCard.JcsBytes(rest);
    }

    /// <summary><c>Alg</c> default EdDSA; <c>Passport</c> (<c>id</c>, optional <c>uri</c>); <c>Kid</c>; <c>Profile</c> "pca-detached" | "a2a-1.0"; <c>Schema</c> "a2a-1.0".</summary>
    public sealed class IssueOptions
    {
        public string? Alg { get; set; }
        public D? Passport { get; set; }
        public string? Kid { get; set; }
        public string? Profile { get; set; }
        public string? Schema { get; set; }
    }

    /// <summary>Issue a signed Agent Card: embed the passport reference, sign the canonicalized card (minus <c>signatures</c>) with the JWK, append the
    /// <c>{protected, signature}</c>. Throws ArgumentException for an invalid card schema, a missing kid under the a2a-1.0 profile or a card with no
    /// canonical form; a Jose exception for a key that cannot sign.</summary>
    public static D IssueSignedAgentCard(object? card, object? signingKey, IssueOptions? opts = null)
    {
        opts ??= new IssueOptions();
        var alg = opts.Alg ?? "EdDSA";
        object? passport;
        bool passportIdMissing = false; // the reference puts an undefined id into the card, which then has no canonical form
        if (opts.Passport != null)
        {
            passportIdMissing = !opts.Passport.ContainsKey("id");
            var pp = new D();
            if (opts.Passport.ContainsKey("id")) pp["id"] = opts.Passport["id"];
            if (opts.Passport.GetValueOrDefault("uri") != null) pp["uri"] = opts.Passport["uri"];
            passport = pp;
        }
        else passport = JsX.JsonOf(JsX.At(card, "pcaPassport"));
        var toSign = JsX.Spread(card);
        if (JsX.Truthy(passport)) toSign["pcaPassport"] = passport;
        if (opts.Schema == "a2a-1.0")
        {
            var problems = A2aCard.ValidateAgentCard1(toSign);
            if (problems.Count > 0) throw new ArgumentException("issueSignedAgentCard: the card does not match the A2A 1.0 schema: " + string.Join("; ", problems));
        }
        if (passportIdMissing) throw new ArgumentException("jcs: unsupported type undefined");
        var payload = CardSigningBytes(toSign);
        bool spec = opts.Profile == "a2a-1.0";
        if (spec && string.IsNullOrEmpty(opts.Kid)) throw new ArgumentException("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
        D? header = null;
        if (JsX.Truthy(passport) && !ReferenceEquals(JsX.At(passport, "id"), JsX.Undef)) header = new D { [PcaPassportHeader] = JsX.At(passport, "id") };
        if (signingKey is not D jwk) throw new ArgumentException("issueSignedAgentCard: the signing key must be a JWK");
        var signature = A2aJws.SignDetached(payload, jwk, alg, opts.Kid, spec, header);
        var sigs = toSign.GetValueOrDefault("signatures") == null ? new L() : SpreadList(toSign["signatures"]);
        sigs.Add(signature);
        toSign["signatures"] = sigs;
        return toSign;
    }

    /// <summary><c>Jwks</c> (a JWKS) or <c>Key</c> (a JWK map; <c>HasKey</c> when the member is present), the importJWK <c>Alg</c> (default EdDSA) and the optional <c>Schema</c> "a2a-1.0".</summary>
    public sealed class VerifyCardOptions
    {
        public object? Jwks { get; set; }
        public bool HasKey { get; set; }
        public object? Key { get; set; }
        public string? Alg { get; set; }
        public string? Schema { get; set; }
    }

    /// <summary>Validate an Agent Card against its signatures. Fail-closed: no signatures, an unresolvable key or ANY signature that does not verify is a
    /// refusal. Result: <c>ok</c>, <c>reason</c> on a refusal; on success the <c>passportRef</c> the signature commits to and the card's <c>passport</c>.
    /// The wording after the first colon of a library failure is this port's own, not the reference library's.</summary>
    public static D VerifyAgentCard(object? card, VerifyCardOptions opts) => VerifyCard(card, opts, false);

    /// <summary>Shared by the A2A and agent-card verifiers; <paramref name="agentCardPkg"/> adds the live proof pointer and the agent-card wording of a malformed signature.</summary>
    public static D VerifyCard(object? card, VerifyCardOptions opts, bool agentCardPkg)
    {
        if (card is not D && card is not L) return Refuse("agent card is not an object");
        var signatures = card is D cd ? cd.GetValueOrDefault("signatures") : null;
        if (signatures is not L sigs || sigs.Count == 0) return Refuse("agent card carries no signatures");
        if (opts.Schema == "a2a-1.0")
        {
            var problems = A2aCard.ValidateAgentCard1(card);
            if (problems.Count > 0) return Refuse("agent card does not match the A2A 1.0 schema: " + string.Join("; ", problems));
        }
        var (resolver, error) = A2aJws.ResolveVerifyKey(opts.Jwks, opts.HasKey, opts.Key, opts.Alg);
        if (error != null) return Refuse(error);
        byte[] payload;
        try { payload = CardSigningBytes(card); }
        catch (ArgumentException e) { return Refuse("agent card has no canonical form: " + e.Message); }
        string? passportRef = null;
        for (int i = 0; i < sigs.Count; i++)
        {
            var sig = sigs[i];
            if (!agentCardPkg)
            {
                if (!JsX.Truthy(sig) || !(sig is D sd && sd.GetValueOrDefault("protected") is string && sd.GetValueOrDefault("signature") is string)) return Refuse($"signature {i} is malformed");
            }
            else if (!JsX.Truthy(sig)) return Refuse($"signature {i} is missing");
            var r = A2aJws.VerifyDetached(payload, sig, resolver!);
            if (!r.Ok) return Refuse($"signature {i} did not verify: {r.Reason}");
            if (passportRef == null && r.ProtectedHeader!.GetValueOrDefault(PcaPassportHeader) is string pr) passportRef = pr;
        }
        var o = new D { ["ok"] = true };
        if (passportRef != null) o["passportRef"] = passportRef;
        var pp = card is D cd2 ? cd2.GetValueOrDefault("pcaPassport") : null;
        if (JsX.Truthy(pp)) o["passport"] = pp;
        if (agentCardPkg)
        {
            var proof = card is D cd3 ? cd3.GetValueOrDefault("pcaProof") : null;
            if (JsX.Truthy(proof)) o["pcaProof"] = proof;
        }
        return o;
    }

    // ---- 3. AP2 payment profile ----

    static object? LeafOfChain(object? chain) => chain is L l && l.Count > 0 ? l[^1] : JsX.Undef;

    static object? LeafHolderOf(object? chain)
    {
        var leaf = LeafOfChain(chain);
        return ReferenceEquals(leaf, JsX.Undef) ? JsX.Undef : JsX.Opt(leaf, "holder");
    }

    /// <summary>True only when the PCActn carries threshold shares that verify at t=3 under <paramref name="signerSetO"/> (agent + guardian + principal, one
    /// distinct key per role). Stricter than the reference in one respect: EVERY explicit share must verify (a stray invalid share refuses), and the agent may
    /// be the leaf signature only for an Ed25519 leaf whose signer-set entry registers no post-quantum key. Never throws.</summary>
    internal static bool VerifiedHumanPresent(D pcActn, object? signerSetO)
    {
        try
        {
            if (signerSetO is not L signerSet) return false;
            var msg = Pca.ThresholdMessage(pcActn);
            var shares = pcActn.GetValueOrDefault("threshold") is D td && td.GetValueOrDefault("shares") is L sl ? sl : new L();
            var good = new HashSet<string>();
            foreach (var s in shares)
            {
                if (s is not D sd || sd.GetValueOrDefault("role") is not string role) return false;
                var entry = new D { ["role"] = role, ["t"] = new Num("3"), ["signer_set"] = signerSet, ["threshold_message"] = Pca.B64u(msg), ["share"] = sd };
                if (!Pca.VerifyThresholdShare(entry)) return false;
                good.Add(role);
            }
            if (!good.Contains("agent") && AgentLeafBaseline(pcActn, signerSet, msg)) good.Add("agent");
            return good.Contains("agent") && good.Contains("guardian") && good.Contains("principal");
        }
        catch (Exception) { return false; }
    }

    static bool AgentLeafBaseline(D p, L signerSet, byte[] msg)
    {
        var holder = LeafHolderOf(p.GetValueOrDefault("cap_chain"));
        var sig = p.GetValueOrDefault("sig");
        var alg = p.GetValueOrDefault("alg");
        if (holder is not string h || sig is not string sg || (alg != null && !(alg is string a && a == "ed25519"))) return false;
        bool registered = false;
        foreach (var e in signerSet)
        {
            var m = (D)e!;
            if (m.GetValueOrDefault("role") is string r && r == "agent" && m.GetValueOrDefault("publicKey") is string pk && pk == h)
            {
                if (m.ContainsKey("pq_pk")) return false;
                registered = true;
            }
        }
        if (!registered) return false;
        var pkb = Pca.B64uDecode(h, 32);
        var sgb = Pca.B64uDecode(sg, 64);
        return pkb != null && sgb != null && Pca.VerifyEd25519Strict(pkb, msg, sgb);
    }

    /// <summary>Map a PCActn to an AP2 Payment Mandate. <paramref name="opts"/>: <c>amount {currency, value}</c> (value a non-negative integer in minor units),
    /// <c>paymentMethod</c>, <c>merchant</c>, <c>humanPresent</c>, <c>humanSignerSet</c>, <c>issuerPublic</c>, <c>now</c>. Throws ArgumentException on a bad amount or no issuer.</summary>
    public static D A2aPaymentMandateFromPca(object? pcActnO, D opts)
    {
        var leaf = LeafHolderOf(JsX.At(pcActnO, "cap_chain"));
        var issuerO = opts.GetValueOrDefault("issuerPublic") ?? leaf;
        if (ReferenceEquals(issuerO, JsX.Undef)) throw new ArgumentException("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain");
        var amount = opts.GetValueOrDefault("amount");
        var value = JsX.At(amount, "value");
        if (!SafeNat(value)) throw new ArgumentException("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units");
        object? humanPresent = opts.GetValueOrDefault("humanPresent") ?? (JsX.Truthy(opts.GetValueOrDefault("humanSignerSet")) && pcActnO is D pd && VerifiedHumanPresent(pd, opts["humanSignerSet"]));
        var now = opts.GetValueOrDefault("now") ?? (object)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var xpca = new D { ["pcactn_digest"] = Pca.HashCanonical(pcActnO) };
        var action = JsX.At(pcActnO, "action");
        foreach (var (k, v) in new (string, object?)[] { ("aud", JsX.At(pcActnO, "aud")), ("verb", JsX.At(action, "verb")), ("resource", JsX.At(action, "resource")),
            ("params_digest", JsX.At(action, "params_digest")), ("grant_ref", JsX.At(pcActnO, "grant_ref")) })
            if (!ReferenceEquals(v, JsX.Undef)) xpca[k] = v;
        xpca["leaf_holder"] = leaf == null || ReferenceEquals(leaf, JsX.Undef) ? issuerO : leaf;
        var contents = new D
        {
            ["amount"] = JsX.Spread(amount),
            ["payment_method"] = JsX.Spread(opts.GetValueOrDefault("paymentMethod") ?? new D()),
            ["human_present"] = humanPresent,
        };
        if (opts.ContainsKey("merchant")) contents["merchant"] = opts["merchant"];
        contents["x_pca"] = xpca;
        return new D
        {
            ["@context"] = A2aAp2Context.Cast<object?>().ToList(),
            ["type"] = new L { "VerifiableCredential", "PaymentMandate" },
            ["issuer"] = issuerO,
            ["issuanceDate"] = JsX.ToIsoString(now),
            ["credentialSubject"] = contents,
        };
    }

    /// <summary>Read the PCA binding back out of an AP2 Payment Mandate (the round trip of <c>x_pca</c>).</summary>
    public static D PcaBindingFromA2APaymentMandate(object? mandate) => JsX.Spread(JsX.At(JsX.At(mandate, "credentialSubject"), "x_pca"));

    static string? MandateBindingError(object? m, object? pcActn, D prms, VerifyOptions opts)
    {
        var x = JsX.JsonOf(JsX.At(m, "x_pca"));
        if (x is not D xd) return "payment mandate carries no x_pca binding";
        var action = JsX.Opt(pcActn, "action");
        var leafHolder = LeafOfChain(JsX.Opt(pcActn, "cap_chain")) is D leaf ? JsX.Opt(leaf, "holder") : JsX.Undef;
        var undef = JsX.Undef;
        // for a non-object chain / action the member reads as undefined, which never equals a string
        var bound = new (string, object?)[]
        {
            ("aud", JsX.Opt(pcActn, "aud")), ("verb", ReferenceEquals(action, undef) ? undef : JsX.Opt(action, "verb")),
            ("resource", ReferenceEquals(action, undef) ? undef : JsX.Opt(action, "resource")),
            ("params_digest", ReferenceEquals(action, undef) ? undef : JsX.Opt(action, "params_digest")), ("grant_ref", JsX.Opt(pcActn, "grant_ref")), ("leaf_holder", leafHolder),
        };
        foreach (var (k, v) in bound)
        {
            var have = JsX.At(xd, k);
            if (have is not string || !JsX.StrictEq(have, v)) return $"payment mandate x_pca.{k} is not the PCActn's";
        }
        var amt = JsX.JsonOf(JsX.At(m, "amount"));
        var av = amt is D ? JsX.At(amt, "value") : undef;
        if (amt is not D || !IntentJs.IsNonNeg(av) || JsX.At(amt, "currency") is not string)
            return "payment mandate amount is malformed (value must be a non-negative integer in minor units)";
        var pa = prms.TryGetValue("amount", out var pav) ? pav : undef;
        if (ReferenceEquals(pa, undef) || !IntentJs.IsNonNeg(pa)) return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to";
        if (prms.GetValueOrDefault("currency") is not string) return "the PCActn params carry no currency to bind the mandate currency to";
        if (!JsX.StrictEq(av, pa) || !JsX.StrictEq(JsX.At(amt, "currency"), prms["currency"])) return "payment mandate amount / currency differ from the authorized PCActn params";
        var merchant = JsX.At(m, "merchant");
        var pMerchant = prms.TryGetValue("merchant", out var pmv) ? pmv : undef;
        if (!JsX.StrictEq(merchant, pMerchant)) return "payment mandate merchant differs from the authorized PCActn params";
        if (prms.ContainsKey("payment_method"))
        {
            bool same;
            try
            {
                var mpm = JsX.At(m, "payment_method");
                same = !ReferenceEquals(mpm, undef) && Pca.HashCanonical(mpm) == Pca.HashCanonical(prms["payment_method"]);
            }
            catch (Exception) { same = false; }
            if (!same) return "payment mandate payment_method differs from the authorized PCActn params";
        }
        if (JsX.At(m, "human_present") is not bool hp) return "payment mandate human_present must be a boolean";
        if (hp && !(opts.HumanSignerSet != null && pcActn is D pad && VerifiedHumanPresent(pad, opts.HumanSignerSet)))
            return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)";
        return null;
    }

    /// <summary>Verify an AP2 Payment Mandate against the PCActn it references (the mandate is unsigned: the PCActn must authorize every field a payer acts
    /// on). <c>opts.Context</c> must yield the action's plaintext <c>params</c>; the <c>params_digest</c> check is required on this path.</summary>
    public static Verification VerifyA2APaymentMandate(object? mandate, object? pcActn, VerifyOptions opts)
    {
        AssertAuthority(opts);
        object? bound;
        string digest;
        try
        {
            var cs = JsX.At(mandate, "credentialSubject");
            var xp = JsX.At(cs, "x_pca");
            bound = JsX.At(xp, "pcactn_digest");
            digest = Pca.HashCanonical(pcActn);
        }
        catch (Exception e) { return Bad("malformed payment mandate or PCActn: " + e.Message, null); }
        if (!JsX.StrictEq(bound, digest)) return BadGiven("payment mandate is not bound to this PCActn (pcactn_digest mismatch)", pcActn);
        if (pcActn is not D && pcActn is not L) return Bad("PCActn is not an object", null);
        var context = opts.Context != null ? opts.Context(pcActn as D ?? new D()) : new D();
        if (context == null) throw JsX.TypeError("context is null");
        if (context.GetValueOrDefault("params") is not D prms) return BadGiven("context.params (the PCActn params plaintext) is required to bind the payment mandate", pcActn);
        var why = MandateBindingError(JsX.At(mandate, "credentialSubject"), pcActn, prms, opts);
        if (why != null) return BadGiven(why, pcActn);
        var require = new List<string>(opts.RequireChecks ?? DefaultRequiredChecks);
        if (!require.Contains("params_digest")) require.Add("params_digest");
        var o = opts.Copy();
        var ctx = context;
        o.Context = _ => ctx;
        o.RequireChecks = require;
        return VerifyPcActn(pcActn, o);
    }

    // ---- AUTH_REQUIRED mapping, extension, delegation, push ----

    /// <summary>The <c>AgentExtension</c> object to put in <c>capabilities.extensions</c>.</summary>
    public static D PcaExtensionDeclaration(object? prms, bool required = true) => new()
    {
        ["uri"] = PcaA2aExtensionUri,
        ["description"] = "Per-action proofs of authority (PCActn) on tasks and messages",
        ["required"] = required,
        ["params"] = prms,
    };

    static D ExtFail(string code) => new() { ["ok"] = false, ["code"] = code };

    static HashSet<string> ParamKeys => new() { "aud", "suites", "grants", "policy_digest" };

    /// <summary>Read and validate the PCA extension from an Agent Card: <c>{ok:true, required, params, grants}</c> or <c>{ok:false, code}</c>.</summary>
    public static D ReadPcaExtension(object? card)
    {
        var caps = card is D cd ? cd.GetValueOrDefault("capabilities") : null;
        var exts = caps is D kd ? kd.GetValueOrDefault("extensions") : null;
        if (exts is not L el) return ExtFail("not_declared");
        var found = el.Where(e => e is D ed && ed.GetValueOrDefault("uri") is string u && u == PcaA2aExtensionUri).ToList();
        if (found.Count == 0) return ExtFail("not_declared");
        if (found.Count > 1) return ExtFail("bad_declaration");
        var e0 = (D)found[0]!;
        if (e0.ContainsKey("required") && e0["required"] is not bool) return ExtFail("bad_declaration");
        if (e0.GetValueOrDefault("params") is not D p) return ExtFail("bad_params");
        var keys = ParamKeys;
        if (p.Keys.Any(k => !keys.Contains(k))) return ExtFail("bad_params");
        if (p.GetValueOrDefault("aud") is not string aud || aud.Length == 0 || aud.Length > 512) return ExtFail("bad_params");
        if (p.ContainsKey("suites") && !(p["suites"] is L sl && sl.Count <= 16 && sl.All(x => x is string xs && xs.Length > 0 && xs.Length <= 64))) return ExtFail("bad_params");
        if (p.ContainsKey("policy_digest") && !(p["policy_digest"] is string pd && pd.Length > 0 && pd.Length <= 128)) return ExtFail("bad_params");
        IReadOnlyList<D> grants = new List<D>();
        if (p.ContainsKey("grants"))
        {
            var g = PcaGrant.Parse(p["grants"]);
            if (g.Code != null) return ExtFail("bad_grants");
            grants = g.Details;
        }
        return new D { ["ok"] = true, ["required"] = e0.GetValueOrDefault("required") is true, ["params"] = p, ["grants"] = grants.Cast<object?>().ToList() };
    }

    /// <summary>True iff the <c>A2A-Extensions</c> service parameter lists the PCA extension (exact URI match in a comma-separated list).</summary>
    public static bool ClientOptsIntoPca(object? header) => header is string h && h.Split(',').Any(u => JsX.JsTrim(u) == PcaA2aExtensionUri);

    /// <summary>AUTH_REQUIRED in the 1.0 enum spelling; the pre-1.0 <c>auth-required</c> is also read.</summary>
    public static bool IsAuthRequired(object? state) => state is string s && (s == TaskStateAuthRequired || s == "auth-required");

    /// <summary>The unpadded base64url of the strict canonical JSON of a valid need; ArgumentException on a malformed need or an over-long value.</summary>
    static string EncodePcaNeed(D need)
    {
        var code = A2a.NeedError(need);
        if (code != null) throw new ArgumentException($"encodePcaNeed: malformed need ({code})");
        var enc = Pca.B64u(Pca.Canon(need));
        if (enc.Length > 2048) throw new ArgumentException("encodePcaNeed: the need is too large for a header");
        return enc;
    }

    /// <summary>The TaskStatus an agent sets to ask for authority: state AUTH_REQUIRED, a message with the typed need under the extension key.
    /// <paramref name="need"/> is validated by the need codec (ArgumentException when malformed); <paramref name="o"/>: <c>messageId</c>, <c>now</c> (epoch ms), <c>text</c>.</summary>
    public static D AuthRequiredStatus(D need, D o)
    {
        var enc = EncodePcaNeed(need); // validates and bounds
        var msg = new D();
        if (o.ContainsKey("messageId")) msg["messageId"] = o["messageId"];
        msg["role"] = "agent";
        msg["parts"] = new L { new D { ["kind"] = "text", ["text"] = o.GetValueOrDefault("text") ?? $"Authority needed: {need["verb"]} on {need["resource"]}" } };
        msg["extensions"] = new L { PcaA2aExtensionUri };
        msg["metadata"] = new D { [NeedKey] = enc };
        return new D { ["state"] = TaskStateAuthRequired, ["timestamp"] = JsX.ToIsoString(o.GetValueOrDefault("now")), ["message"] = msg };
    }

    static D Decoded(object? value)
    {
        var (need, code) = A2a.DecodeNeed(value);
        return need != null ? new D { ["ok"] = true, ["need"] = need } : new D { ["ok"] = false, ["code"] = code };
    }

    /// <summary>The need parked in a task status message, decoded (<c>{ok, need}</c> or <c>{ok:false, code}</c>); null when there is none.</summary>
    public static D? ReadAuthRequiredNeed(object? task)
    {
        var status = task is D t ? t.GetValueOrDefault("status") : null;
        var msg = status is D s ? s.GetValueOrDefault("message") : null;
        var md = msg is D m ? m.GetValueOrDefault("metadata") : null;
        return md is D d && d.ContainsKey(NeedKey) ? Decoded(d[NeedKey]) : null;
    }

    /// <summary>The answer message to put on the Task: a PCActn for exactly the parked need, plus the need's digest.</summary>
    public static D AnswerMessage(object? need, object? pcActn, object? messageId) => new()
    {
        ["role"] = "user",
        ["messageId"] = messageId,
        ["parts"] = new L { new D { ["kind"] = "text", ["text"] = "authority provided" } },
        // the digest is over whatever was given: the reference does not validate it here
        ["metadata"] = new D { [PcaA2aExtensionUri] = pcActn, [NeedKey] = Pca.HashCanonical(new D { ["d"] = "atlas-pca/need/v1", ["need"] = need }) },
    };

    /// <summary>Marks "no proof action" (JavaScript undefined) for <see cref="ResumeGate"/>.</summary>
    public static readonly object NoProof = new();

    /// <summary>The pure gate of <see cref="ResumeAuthRequired"/>, in the order the checks run. <paramref name="needEncoded"/> and
    /// <paramref name="answerNeedDigest"/>: JSON values (an absent member is null); <paramref name="proofAction"/>: <see cref="NoProof"/> for none;
    /// a JSON null throws (the reference dereferences it). Returns the first refusal code, or null.</summary>
    public static string? ResumeGate(object? state, object? needEncoded, object? answerNeedDigest, object? proofAction)
    {
        if (!IsAuthRequired(state)) return "task_not_auth_required";
        var need = A2a.DecodeNeed(needEncoded).Need;
        if (need == null) return "no_valid_need";
        if (!(answerNeedDigest is string ad && ad == A2a.NeedDigest(need))) return "answer_not_bound_to_need";
        if (ReferenceEquals(proofAction, NoProof)) return "no_proof";
        if (proofAction == null) throw JsX.TypeError("cannot read properties of null (reading 'verb')");
        var verb = proofAction is D pd ? pd.GetValueOrDefault("verb") : null;
        var resource = proofAction is D pr ? pr.GetValueOrDefault("resource") : null;
        if (!(verb is string vs && vs == (string)need["verb"]!) || !(resource is string rs && rs == (string)need["resource"]!)) return "action_mismatch";
        return null;
    }

    /// <summary>Does <paramref name="next"/> (capability ids, root first) extend <paramref name="prev"/>?</summary>
    public static bool ChainExtends(IReadOnlyList<object?> prev, IReadOnlyList<object?> next)
    {
        if (next.Count < prev.Count) return false;
        for (int k = 0; k < prev.Count; k++) if (!JsX.StrictEq(prev[k], next[k])) return false;
        return true;
    }

    static D ChainFail(int hop, string reason) => new() { ["ok"] = false, ["failedHop"] = new Num(hop.ToString()), ["reason"] = reason };

    /// <summary>The chain rule of <see cref="VerifyA2ADelegation"/>: <c>{ok:true}</c> or <c>{ok:false, failedHop, reason}</c>.</summary>
    public static D CheckChainExtension(object? chainsO)
    {
        if (chainsO == null) throw JsX.TypeError("cannot read properties of null (reading 'length')");
        // a string has a length and character "hops" (never arrays); other non-arrays have no length, so nothing is checked
        if (chainsO is string s) return s.Length == 0 ? new D { ["ok"] = true } : ChainFail(0, "no_chain");
        if (chainsO is not L chains) return new D { ["ok"] = true };
        for (int i = 0; i < chains.Count; i++)
        {
            if (chains[i] is not L ids || ids.Count == 0) return ChainFail(i, "no_chain");
            if (i > 0 && !ChainExtends((L)chains[i - 1]!, ids)) return ChainFail(i, "chain_does_not_extend_previous_hop");
        }
        return new D { ["ok"] = true };
    }

    /// <summary>Resume a Task parked in AUTH_REQUIRED: only when the Task is in AUTH_REQUIRED, its status carries a decodable need, the answer cites that
    /// need's digest, carries a PCActn for the need's exact verb and resource, and that PCActn passes the full verifier. <c>{ok:true, verification}</c> or <c>{ok:false, reason}</c>.</summary>
    public static D ResumeAuthRequired(object? task, object? answer, VerifyOptions opts)
    {
        var status = JsX.JsonOf(JsX.Opt(task, "status"));
        var smsg = status is D sd ? sd.GetValueOrDefault("message") : null;
        var smd = smsg is D mm ? mm.GetValueOrDefault("metadata") : null;
        var statusMd = smd as D ?? new D();
        var md = (answer is D ad ? ad.GetValueOrDefault("metadata") : null) as D ?? new D();
        var p = ExtractPcaFromMessage(answer);
        var state = status is D st ? st.GetValueOrDefault("state") : null;
        var proofAction = p == null ? NoProof : p.ContainsKey("action") ? p["action"] : NoProof;
        var refusal = ResumeGate(state, statusMd.GetValueOrDefault(NeedKey), md.GetValueOrDefault(NeedKey), proofAction);
        if (refusal != null) return Refuse(refusal);
        var t = new D
        {
            ["id"] = JsX.JsonOf(JsX.Opt(task, "id")),
            ["status"] = new D { ["state"] = "TASK_STATE_WORKING" },
            ["metadata"] = new D { [PcaA2aExtensionUri] = p },
        };
        var v = VerifyA2ATask(t, opts);
        return v.Ok ? new D { ["ok"] = true, ["verification"] = v.ToMap() } : Refuse(v.Reason ?? "proof_rejected");
    }

    /// <summary>One hop of <see cref="VerifyA2ADelegation"/>: the Task and the options (own audience and authority) it is verified under.</summary>
    public sealed record Hop(object? Task, VerifyOptions Opts);

    static D HopFail(int hop, string reason, L chains) => new() { ["ok"] = false, ["failedHop"] = new Num(hop.ToString()), ["reason"] = reason, ["chains"] = chains };

    /// <summary>Verify a chain of delegated Tasks, one per A2A hop. Every hop is verified on its own (own PCActn, audience and authority); each hop's
    /// capability chain must EXTEND the previous hop's. Stops at the first failure; empty input fails closed. Result: <c>{ok, failedHop?, reason?, chains}</c>.</summary>
    public static D VerifyA2ADelegation(IReadOnlyList<Hop> hops)
    {
        var chains = new L();
        if (hops.Count == 0) return new D { ["ok"] = false, ["reason"] = "no_hops", ["chains"] = chains };
        for (int i = 0; i < hops.Count; i++)
        {
            var h = hops[i];
            var v = VerifyA2ATask(h.Task, h.Opts);
            if (!v.Ok) return HopFail(i, v.Reason ?? "rejected", chains);
            var p = ExtractPca(h.Task);
            if (p?.GetValueOrDefault("cap_chain") is not L cc) return HopFail(i, "no_chain", chains);
            var ids = new L();
            foreach (var c in cc) ids.Add(JsX.JsonOf(JsX.At(c, "id")));
            if (i > 0 && !ChainExtends((L)chains[i - 1]!, ids)) return HopFail(i, "chain_does_not_extend_previous_hop", chains);
            chains.Add(ids);
        }
        return new D { ["ok"] = true, ["chains"] = chains };
    }

    /// <summary>The per-task push token (A2A 3.1.7): a hash of the task id, the digest of the authorizing chain and a secret salt of at least 16 characters (else ArgumentException).</summary>
    public static string PcaPushToken(object? taskId, IReadOnlyList<string> chainIds, object? salt)
    {
        if (salt is not string s || s.Length < 16) throw new ArgumentException("pcaPushToken: the salt must be a secret of at least 16 characters");
        return Pca.HashCanonical(new D { ["d"] = "atlas-pca/a2a-push/v1", ["task_id"] = taskId, ["chain"] = PcaGrant.ChainDigest(chainIds), ["salt"] = s });
    }

    /// <summary>Receiver-side check of a delivered push notification: the token must equal the one recomputed from the task, chain and salt, and the payload must be
    /// about that task. <c>{ok:true}</c> or <c>{ok:false, reason}</c> (no_token, token_mismatch, task_mismatch). A short salt with a presented token throws, as the reference does.</summary>
    public static D CheckPushNotification(string taskId, IReadOnlyList<string> chainIds, object? salt, object? token, object? payload)
    {
        if (token is not string t || t.Length == 0) return Refuse("no_token");
        var want = PcaPushToken(taskId, chainIds, salt);
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(want), Encoding.UTF8.GetBytes(t))) return Refuse("token_mismatch");
        var r = A2a.CheckPush(taskId, chainIds, (string)salt!, token, payload);
        return r != null ? Refuse(r) : new D { ["ok"] = true };
    }

    /// <summary>The one error A2A servers return for "no such task" and "not yours" alike (no existence leak).</summary>
    public static D UniformTaskNotFound() => new() { ["code"] = "TaskNotFoundError", ["message"] = "task not found" };

    // ---- signed task-update receipts ----

    /// <summary>The content address the next receipt cites as <c>prev</c>.</summary>
    public static string ReceiptDigest(object? r) => A2a.ReceiptDigest(r);

    /// <summary>Sign a receipt with an Ed25519 seed. <paramref name="prev"/>: the previous receipt of the same task (null for the first). Throws ArgumentException on
    /// malformed input, a task id mismatch or a terminal <paramref name="prev"/>.</summary>
    public static D SignTaskReceipt(byte[] secret, object? taskId, object? state, IReadOnlyList<string> chainIds, object? issuedAt, D? prev)
    {
        if (!(taskId is string tid && tid.Length > 0 && tid.Length <= 256) || !InSet(States, state) || !IntentJs.IsNonNeg(issuedAt) || chainIds.Count == 0)
            throw new ArgumentException("signTaskReceipt: malformed input");
        if (prev != null && (!JsX.StrictEq(prev.GetValueOrDefault("task_id"), taskId) || InSet(Terminal, prev.GetValueOrDefault("state"))))
            throw new ArgumentException("signTaskReceipt: prev is for another task or already terminal");
        if (prev != null && !IntentJs.IsNonNeg(prev.GetValueOrDefault("seq"))) throw new ArgumentException("signTaskReceipt: prev has no valid seq");
        using var key = EdKey.FromSeed(secret);
        var body = new D
        {
            ["v"] = new Num("1"),
            ["task_id"] = taskId,
            ["state"] = state,
            ["seq"] = prev != null ? IntentJs.OfLong(IntentJs.Lng(prev["seq"]) + 1) : new Num("0"),
            ["prev"] = prev != null ? A2a.ReceiptDigest(prev) : null,
            ["chain"] = PcaGrant.ChainDigest(chainIds),
            ["issued_at"] = issuedAt,
            ["signer"] = key.Id,
        };
        var msg = Encoding.UTF8.GetBytes(A2aReceiptDomain).Concat(Pca.Canon(body)).ToArray();
        var o = new D(body) { ["sig"] = Pca.B64u(key.Sign(msg)) };
        return o;
    }

    /// <summary>Well formed and signed by <paramref name="signer"/> (the key the receiver pinned) over exactly its content. Never throws.</summary>
    public static bool VerifyTaskReceipt(object? r, string signer) => A2a.VerifyReceipt(r, signer);

    /// <summary>Check an ordered list of receipts for one task: <c>{ok:true, last, terminal}</c> or <c>{ok:false, code, at?}</c>.</summary>
    public static D CheckReceiptChain(object? receipts, string signer, string taskId, IReadOnlyList<string> chainIds)
    {
        if (receipts is not L l || l.Count == 0) return new D { ["ok"] = false, ["code"] = "empty" };
        var c = A2a.CheckReceiptChain(l, signer, taskId, chainIds);
        if (c.Code != null) return new D { ["ok"] = false, ["code"] = c.Code, ["at"] = new Num(c.At.ToString()) };
        return new D { ["ok"] = true, ["last"] = l[^1], ["terminal"] = c.Terminal };
    }

    /// <summary>May a workflow start its next step because of this task? Only on a verified, unbroken receipt chain ending in COMPLETED.</summary>
    public static bool MayTriggerNext(object? receipts, string signer, string taskId, IReadOnlyList<string> chainIds) =>
        receipts is L l && l.Count > 0 && A2a.MayTriggerNext(l, signer, taskId, chainIds);

    /// <summary>Put a receipt on a status update or message metadata (a copy).</summary>
    public static D AttachReceipt(object? carrier, object? r)
    {
        var md = JsX.JsonOf(JsX.At(carrier, "metadata"));
        var o = JsX.Spread(carrier);
        var m = JsX.Spread(md ?? new D());
        m[ReceiptKey] = r;
        o["metadata"] = m;
        return o;
    }

    /// <summary>The receipt carried by a push / stream payload (<c>statusUpdate.metadata</c>, <c>task.metadata</c>, <c>message.metadata</c>), or null. Unverified.</summary>
    public static object? ReceiptOfPayload(object? payload)
    {
        if (payload is not D p) return null;
        foreach (var k in new[] { "statusUpdate", "task", "message" })
        {
            var md = p.GetValueOrDefault(k) is D c ? c.GetValueOrDefault("metadata") : null;
            if (md is D d && d.ContainsKey(ReceiptKey)) return d[ReceiptKey];
        }
        return null;
    }

    // ---- extended Agent Card ----

    static string PolicyKey(object? v) =>
        ReferenceEquals(v, JsX.Undef) ? "u" : v == null ? "z" : v is string s ? "s:" + s : v is bool b ? (b ? "b:1" : "b:0")
            : IntentJs.NumOf(v) is double d ? "n:" + JsX.JsNumString(d) : "o:" + Guid.NewGuid(); // an object is a distinct reference

    static object? DefaultVerbOf(object? s)
    {
        var tags = JsX.At(s, "tags");
        if (ReferenceEquals(tags, JsX.Undef) || tags == null) return JsX.Undef;
        if (tags is not L tl) throw JsX.TypeError("tags.find is not a function");
        foreach (var x in tl) if (x is string xs && xs.StartsWith("pca-verb:", StringComparison.Ordinal)) return xs["pca-verb:".Length..];
        return JsX.Undef;
    }

    /// <summary>The extended Agent Card from a residual policy (A2A 3.1.11, 13.3): lists the hidden skills a caller may attempt. <paramref name="o"/>: <c>authenticated</c>
    /// (must be true), <c>hiddenSkills</c>, <c>envelopes</c> (<c>verb, status, policyDigest</c>); <paramref name="verbOf"/> maps a skill to its PCA verb (null: the skill's
    /// <c>pca-verb:&lt;verb&gt;</c> tag). A verb with no envelope, or a denied one, reveals nothing. The result is unsigned.</summary>
    public static D ExtendedAgentCard(object? publicCard, D o, Func<object?, string?>? verbOf = null)
    {
        if (o.GetValueOrDefault("authenticated") is not true) throw new InvalidOperationException("extendedAgentCard: the caller must be authenticated (A2A 13.3)");
        var envelopes = (L)o["envelopes"]!;
        var hidden = (L)o["hiddenSkills"]!;
        var digests = new Dictionary<string, object?>();
        foreach (var e in envelopes) { var d = JsX.At(e, "policyDigest"); digests.TryAdd(PolicyKey(d), d); }
        if (digests.Count > 1) throw new ArgumentException("extendedAgentCard: envelopes were computed against different policies");
        var byVerb = new Dictionary<string, object?>();
        foreach (var e in envelopes) { if (JsX.At(e, "verb") is string vs) byVerb[vs] = e; }
        var revealed = new L();
        foreach (var s in hidden)
        {
            object? verb;
            if (verbOf != null) { var vv = verbOf(s); verb = vv == null ? JsX.Undef : vv; }
            else verb = DefaultVerbOf(s);
            object? env = verb is string vstr && byVerb.TryGetValue(vstr, out var ev) ? ev : null;
            if (env == null || JsX.At(env, "status") is string st && st == "denied") continue;
            var sk = JsX.Spread(s);
            var tags = JsX.At(s, "tags");
            var nt = ReferenceEquals(tags, JsX.Undef) || tags == null ? new L() : SpreadList(tags);
            nt.Add(JsX.At(env, "status") is string ast && ast == "autonomous" ? "pca:autonomous" : "pca:needs-approval");
            sk["tags"] = nt;
            revealed.Add(sk);
        }
        if (publicCard == null) throw JsX.TypeError("cannot destructure null");
        var rest = JsX.Spread(publicCard);
        rest.Remove("signatures");
        var caps = JsX.Spread(rest.GetValueOrDefault("capabilities") ?? new D());
        var exts = caps.GetValueOrDefault("extensions") as L ?? new L();
        var policyDigest = digests.Count == 0 ? JsX.Undef : digests.Values.First();
        var next = new L();
        foreach (var e in exts)
        {
            if (!ReferenceEquals(policyDigest, JsX.Undef) && JsX.At(e, "uri") is string u && u == PcaA2aExtensionUri)
            {
                var ne = JsX.Spread(e);
                var pm = JsX.At(e, "params");
                var np = JsX.Spread(ReferenceEquals(pm, JsX.Undef) || pm == null ? new D() : pm);
                np["policy_digest"] = policyDigest;
                ne["params"] = np;
                next.Add(ne);
            }
            else next.Add(e);
        }
        var skills = rest.GetValueOrDefault("skills") is L sl ? new L(sl) : new L();
        skills.AddRange(revealed);
        caps["extensions"] = next;
        rest["capabilities"] = caps;
        rest["skills"] = skills;
        return rest;
    }
}
