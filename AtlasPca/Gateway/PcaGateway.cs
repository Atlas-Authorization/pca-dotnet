using System.Globalization;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gateway;

/// <summary>Full-policy mode: the grant's limits and caveats are evaluated against the real params by <see cref="Pca.Authorize"/>, with revocation, the
/// replay counter and the trust budget. The agent signs the params plus the request binding (see <see cref="PcaGateway.BindParams"/>).</summary>
public sealed class FullPolicy
{
    /// <summary>True (default): the params are the request body (a strict JSON object).</summary>
    public bool ParamsFromBody { get; set; } = true;
    /// <summary>Used instead of the body when set; a null return denies.</summary>
    public Func<D, D?>? ParamsFn { get; set; }
    public IStateStore? State { get; set; }
    public Func<D, D, bool?>? IsRevoked { get; set; }
    /// <summary>Further <see cref="AuthorizeInput"/> settings (plan, intent policy, risk, ...) applied to each request's input first.</summary>
    public Action<AuthorizeInput>? Configure { get; set; }
    /// <summary>The zk verifier hook for a PCActn that carries <c>zk_compliance</c> (see <see cref="AuthorizeInput.ZkHook"/>); without it a carried proof is refused.</summary>
    public PcaCore.Hook? ZkHook { get; set; }
    /// <summary>The attestation verifier hook (see <see cref="AuthorizeInput.AttestationHook"/>).</summary>
    public PcaCore.Hook? AttestationHook { get; set; }
    /// <summary>The attestation gate (see <see cref="AuthorizeInput.EnforceAttestation"/>).</summary>
    public PcaCore.AttestationGate? EnforceAttestation { get; set; }
    /// <summary>Caveat-language input (pins, history, ...) merged over the presented discharges / narrow block; null: every K1 caveat refuses.</summary>
    public Func<D, D, K1Input?>? K1 { get; set; }
    /// <summary>The provenance gate's own options (mediator pins, action facts, observed content); the gateway's log is joined to its observed content.</summary>
    public ArgProvenanceOptions? Provenance { get; set; }
    /// <summary>The per-gateway log of relayed untrusted content; null: an in-memory one.</summary>
    public IProvenanceLog? ProvenanceLog { get; set; }
    /// <summary>True turns the log off.</summary>
    public bool ProvenanceLogOff { get; set; }
}

/// <summary>Gateway configuration. Routes are <c>{method?, path, capability: {verb, resource?}}</c>, the first match wins.</summary>
public sealed class GatewayOptions
{
    /// <summary>This gateway's audience (the RFC 8707 resource): a proof minted for another audience is denied.</summary>
    public string Audience { get; set; } = "";
    public List<D> Routes { get; set; } = new();
    /// <summary><c>(grant_ref, pcactn) -&gt; grant</c>; null: unknown grant.</summary>
    public Func<object?, D, D?>? ResolveGrant { get; set; }
    public List<string>? AuthorizedPlanRoots { get; set; }
    public bool InsecureSkipPlanRootCheck { get; set; }
    /// <summary>"deny" (default), "allow" or "require-proof".</summary>
    public string? UnmatchedRoute { get; set; }
    public IReplayGuard? ReplayGuard { get; set; }
    /// <summary>Request binding: null (bind method, path, query and a supplied body hash), <c>false</c> (off) or <c>{authority?, body?}</c>.</summary>
    public object? BindRequest { get; set; }
    /// <summary>The revocation hook: <c>{pcactn, grant, nowEpoch}</c> to <c>{enforced, ok?, reason?}</c>. A throw refuses the proof.</summary>
    public Func<D, D?>? Revocation { get; set; }
    /// <summary>Core checks that must report pass (null: <c>["revocation"]</c> in signature-only mode, none in full mode).</summary>
    public List<string>? RequireChecks { get; set; }
    /// <summary>Per-proof policy hook over <c>{pcactn, grant, verdict, request, required?}</c>: a bool, or <c>{allow, reason?}</c>; false or a throw denies.</summary>
    public Func<D, object?>? CheckProof { get; set; }
    /// <summary>"strict" (default) or "off".</summary>
    public string? PathPolicy { get; set; }
    public Func<long>? Now { get; set; }
    public string? Realm { get; set; }
    /// <summary>"full", "signature-only" or null (a misconfiguration that denies every request).</summary>
    public string? PolicyMode { get; set; }
    public FullPolicy? Full { get; set; }
    internal IProvenanceLog? DefaultLog;

    internal GatewayOptions Frozen()
    {
        var c = (GatewayOptions)MemberwiseClone();
        c.Routes = Routes.Select(r => (D)Pca.ParseStrict(JsJson.Stringify(r))!).ToList();
        if (AuthorizedPlanRoots != null) c.AuthorizedPlanRoots = new List<string>(AuthorizedPlanRoots);
        return c;
    }
}

/// <summary>The outcome of <see cref="PcaGateway.Authorize"/>: 200 allow, 400 invalid path, 401 unauthenticated, 403 forbidden, 503 replay guard unavailable.</summary>
public sealed class GatewayDecision
{
    public bool Allow { get; init; }
    public int Status { get; init; }
    public string Code { get; init; } = "";
    public string Reason { get; init; } = "";
    public Dictionary<string, string> Headers { get; init; } = new();
    /// <summary><c>{allow, checks, reason?}</c> when a PCActn was decoded and verified.</summary>
    public D? Verdict { get; init; }
    public D? Pcactn { get; init; }
    /// <summary>The route's required capability.</summary>
    public D? Matched { get; init; }
    /// <summary>Full-policy mode: the full verifier's <c>{allow, checks, reason?}</c>.</summary>
    public D? PolicyVerdict { get; init; }
}

public static partial class PcaGateway
{
    static readonly Dictionary<string, string> ErrorToken = new()
    {
        ["no-proof"] = "missing_proof", ["invalid-proof"] = "invalid_proof", ["unknown-grant"] = "invalid_proof", ["verify-failed"] = "invalid_proof",
        ["wrong-audience"] = "invalid_resource", ["insufficient-capability"] = "insufficient_capability", ["unmapped-route"] = "access_denied",
        ["invalid-path"] = "invalid_request", ["replayed-proof"] = "replayed_proof", ["replay-guard-unavailable"] = "temporarily_unavailable",
        ["request-mismatch"] = "proof_not_bound_to_request", ["proof-rejected"] = "access_denied",
    };

    static GatewayDecision Deny(string code, int status, string reason, string realm, D? verdict = null, D? pcactn = null, D? matched = null, D? policyVerdict = null) => new()
    {
        Allow = false, Status = status, Code = code, Reason = reason,
        Headers = new Dictionary<string, string> { ["www-authenticate"] = $"PCA realm=\"{realm}\", error=\"{ErrorToken[code]}\"" },
        Verdict = verdict, Pcactn = pcactn, Matched = matched, PolicyVerdict = policyVerdict,
    };

    static GatewayDecision Allowed(string reason, D? verdict = null, D? pcactn = null, D? matched = null, D? policyVerdict = null)
    {
        var headers = new Dictionary<string, string>();
        if (verdict != null) headers["x-pca-verdict"] = JsJson.Stringify(verdict);
        if (pcactn != null)
        {
            headers["x-pca-verb"] = (string)((D)pcactn["action"]!)["verb"]!;
            headers["x-pca-grant"] = (string)pcactn["grant_ref"]!;
        }
        return new GatewayDecision { Allow = true, Status = 200, Code = "allow", Reason = reason, Headers = headers, Verdict = verdict, Pcactn = pcactn, Matched = matched, PolicyVerdict = policyVerdict };
    }

    static bool MatchMethod(D rule, string method)
    {
        var m = rule.GetValueOrDefault("method");
        if (m == null) return true;
        var ms = (string)m;
        return ms == "*" || ms.ToUpperInvariant() == "ANY" || ms.ToUpperInvariant() == method.ToUpperInvariant();
    }

    static bool MatchPath(string pattern, string path)
    {
        if (pattern is "*" or "/*") return true;
        if (pattern.EndsWith("/*", StringComparison.Ordinal))
        {
            var prefix = pattern[..^2];
            return path == prefix || path.StartsWith(prefix + "/", StringComparison.Ordinal);
        }
        if (pattern.EndsWith('*')) return path.StartsWith(pattern[..^1], StringComparison.Ordinal);
        return path == pattern;
    }

    static D? MatchRoute(List<D> routes, string method, string path)
    {
        foreach (var r in routes) if (MatchMethod(r, method) && MatchPath((string)r["path"]!, path)) return r;
        return null;
    }

    static string Mode(GatewayOptions o) => o.PolicyMode ?? "";

    static string MissingText(GatewayOptions o, List<string> missing) =>
        (o.PolicyMode == null || o.PolicyMode == "signature-only" ? "the gateway" : "full policy mode") + " is missing " + string.Join(", ", missing);

    static List<string> MissingPolicy(GatewayOptions o)
    {
        if (o.PolicyMode == null) return new List<string> { "policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })" };
        if (o.PolicyMode == "signature-only")
        {
            var m = new List<string>();
            if (o.ReplayGuard == null) m.Add("replayGuard (signature-only mode needs a single-use guard)");
            var rc = o.RequireChecks ?? DefaultRequireChecks.ToList();
            if (rc.Contains("revocation") && o.Revocation == null) m.Add("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)");
            return m;
        }
        if (o.PolicyMode != "full") return new List<string> { $"a known policy mode (got '{o.PolicyMode}')" };
        var f = o.Full ?? new FullPolicy();
        var missing = new List<string>();
        if (o.Audience.Length == 0) missing.Add("audience");
        if (o.ResolveGrant == null) missing.Add("resolveGrant");
        if (f.State == null) missing.Add("state");
        if (f.IsRevoked == null) missing.Add("isRevoked");
        if (f.State != null && f.State is not IBudgetStore) missing.Add("state.claim_budget (the trust budget is decided and debited with the replay claim)");
        if (!f.ParamsFromBody && f.ParamsFn == null) missing.Add("params ('body' or a function)");
        return missing;
    }

    /// <summary>Full-policy mode: the params the agent must have signed for this request: <c>(params, null)</c> or <c>(null, error)</c>.</summary>
    static (D? Params, string? Error) SignedParams(D req, FullPolicy policy, object? bind)
    {
        D? parameters;
        if (policy.ParamsFn == null)
        {
            if (G(req, "body") is not string body) return (null, "full policy mode reads the params from the body, and the request carries none");
            try { parameters = Pca.ParseStrict(body) as D; }
            catch (Exception e) { return (null, "the body is not strict JSON: " + e.Message); }
        }
        else parameters = policy.ParamsFn(req);
        if (parameters == null) return (null, "the request params are not a JSON object");
        if (bind is false) return (parameters, null);
        var b = bind as D ?? new D();
        if (parameters.ContainsKey("binding")) return (null, "the request params carry a 'binding' member (reserved for the request binding)");
        if ((Jt(b.GetValueOrDefault("authority")) && !Jt(G(req, "authority"))) || (b.GetValueOrDefault("body") is true && !Jt(G(req, "bodySha256"))))
            return (null, "request lacks an attribute the proof must bind (authority / body hash)");
        try
        {
            // the params carry the body, so its hash is bound only when asked for explicitly (bindRequest body: true)
            var o = new D();
            if (Jt(b.GetValueOrDefault("authority"))) o["authority"] = true;
            o["body"] = b.GetValueOrDefault("body") is true;
            return (BindParams(parameters, RequestBinding(req, o)), null);
        }
        catch (Exception e) { return (null, "the request cannot be bound: " + e.Message); }
    }

    static bool Flag(object? v) => Jt(v);

    /// <summary>The core verdict in the reference vocabulary: <c>{allow, checks, reason?}</c> plus whether the wire and audience checks held.</summary>
    static (D Verdict, bool Wire, bool Audience) Verify(D pcactn, D grant, GatewayOptions opts, long now)
    {
        var v = Pca.VerifyPcactnCore(pcactn, grant, now, opts.Audience, null, null, null, null, new PlanRootPolicy(opts.AuthorizedPlanRoots, opts.InsecureSkipPlanRootCheck));
        var allow = v.Allow;
        string? reason = v.Reason.Length > 0 ? v.Reason : null;
        var revocation = "not-enforced";
        var wire = v.Checks.GetValueOrDefault("wire");
        if (opts.Revocation != null && wire)
        {
            try
            {
                var res = opts.Revocation(new D { ["pcactn"] = pcactn, ["grant"] = grant, ["nowEpoch"] = new Num(now.ToString(CultureInfo.InvariantCulture)) });
                var enforced = Flag(G(res, "enforced")); var ok = Flag(G(res, "ok"));
                if (!enforced) revocation = "not-enforced";
                else if (ok) revocation = "pass";
                else
                {
                    revocation = "fail";
                    if (allow || reason == null)
                    {
                        var rr = G(res, "reason");
                        reason = "revocation: " + (rr != null ? Str(rr) : "rejected");
                    }
                    allow = false;
                }
            }
            catch (Exception e)
            {
                revocation = "fail";
                if (allow || reason == null) reason = "malformed PCActn: " + e.Message;
                allow = false;
            }
        }
        var st = new D();
        foreach (var (k, passed) in v.Checks) st[k == "chain" ? "cap_chain" : k] = passed ? "pass" : "fail";
        if (v.PlanRootAuthorized == "not-enforced") st["plan_root_authorized"] = "not-enforced";
        st["attestation"] = "not-enforced";
        st["threshold"] = "not-enforced";
        st["revocation"] = revocation;
        if (!st.ContainsKey("taint_gate")) st["taint_gate"] = "not-enforced";
        var verdict = new D { ["allow"] = allow, ["checks"] = st };
        if (reason != null) verdict["reason"] = reason;
        return (verdict, wire, v.Checks.GetValueOrDefault("audience"));
    }

    /// <summary>The framework-agnostic core: extract the PCActn, map the request to the capability its route requires, verify (fail closed), enforce
    /// audience, capability, request binding, required checks, the proof hook, the policy and single use. DENY-BY-DEFAULT at every step.
    /// <paramref name="req"/> is <c>{method, path, query?, authority?, bodySha256?, body?, headers}</c>.</summary>
    public static GatewayDecision Authorize(D req, GatewayOptions opts)
    {
        var realm = opts.Realm ?? opts.Audience;
        var unmatched = opts.UnmatchedRoute ?? "deny";
        var path = (string)req["path"]!; var method = (string)req["method"]!;

        // 0. an ambiguous request target is never matched against the route map
        if ((opts.PathPolicy ?? "strict") == "strict" && AmbiguousPathReason(path) is { } bad) return Deny("invalid-path", 400, bad, realm);

        // 1. route -> required capability; an unmapped route follows UnmatchedRoute (default deny)
        var rule = MatchRoute(opts.Routes, method, path);
        if (rule == null)
        {
            if (unmatched == "allow") return Allowed($"route {method} {path} is unmapped (unmatchedRoute=allow)");
            if (unmatched == "deny") return Deny("unmapped-route", 403, $"no capability mapping for {method} {path} (deny-by-default)", realm);
        }
        var required = (D?)rule?["capability"];

        // 2. the proof (fail closed)
        var (pcactn, code, why) = ExtractPcactn(G(req, "headers"));
        if (pcactn == null) return Deny(code!, 401, why!, realm);

        // 3. the grant the chain must root in
        var grantRef = pcactn.TryGetValue("grant_ref", out var gr) ? gr : null;
        var grant = opts.ResolveGrant?.Invoke(grantRef, pcactn);
        if (grant == null) return Deny("unknown-grant", 401, "unknown grant_ref " + (pcactn.ContainsKey("grant_ref") ? Str(grantRef) : "undefined"), realm, pcactn: pcactn);

        // 3b. a configuration with a missing component denies every request (fail closed)
        var missingCfg = MissingPolicy(opts);
        if (missingCfg.Count > 0) return Deny("proof-rejected", 403, MissingText(opts, missingCfg) + " (fail closed)", realm, pcactn: pcactn);

        // 4. offline verification, the audience bound to THIS gateway
        var now = opts.Now != null ? opts.Now() : AtlasPca.ReplayClock.NowMs();
        var (verdict, wireOk, audOk) = Verify(pcactn, grant, opts, now);
        if (verdict["allow"] is not true)
        {
            var audienceFailed = wireOk && !audOk;
            var vr = verdict.GetValueOrDefault("reason") as string;
            return Deny(audienceFailed ? "wrong-audience" : "verify-failed", audienceFailed ? 403 : 401, string.IsNullOrEmpty(vr) ? "PCActn verification failed" : vr, realm, verdict, pcactn);
        }

        // 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
        var action = (D)pcactn["action"]!;
        if (required != null)
        {
            if (!StrictEq(action["verb"], required["verb"]))
                return Deny("insufficient-capability", 403, $"route requires capability '{Str(required["verb"])}' but the proof authorizes '{Str(action["verb"])}'", realm, verdict, pcactn, required);
            if (required.GetValueOrDefault("resource") is { } rres && !StrictEq(action["resource"], rres))
                return Deny("insufficient-capability", 403, $"route is bound to resource '{Str(rres)}' but the proof targets '{Str(action["resource"])}'", realm, verdict, pcactn, required);
        }

        var policy = Mode(opts) == "full" ? opts.Full ?? new FullPolicy() : null;
        var bind = opts.BindRequest;
        D? fullParams = null;
        if (policy != null)
        {
            // 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
            var (sp, spErr) = SignedParams(req, policy, bind);
            if (sp == null) return Deny("request-mismatch", 403, spErr!, realm, verdict, pcactn);
            if (!StrictEq(action["params_digest"], Pca.ParamsDigest(sp)))
                return Deny("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)", realm, verdict, pcactn);
            fullParams = sp;
        }
        else if (bind is not false)
        {
            // 5b. request binding: the signed params digest must be the digest of THIS request
            var b = bind as D ?? new D();
            if ((Jt(b.GetValueOrDefault("authority")) && !Jt(G(req, "authority"))) || (b.GetValueOrDefault("body") is true && !Jt(G(req, "bodySha256"))))
                return Deny("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)", realm, verdict, pcactn);
            string bound;
            try { bound = Pca.ParamsDigest(RequestBinding(req, b)); }
            catch (Exception e) { return Deny("request-mismatch", 403, "the request cannot be bound: " + e.Message, realm, verdict, pcactn); }
            if (!StrictEq(action["params_digest"], bound))
                return Deny("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)", realm, verdict, pcactn);
        }

        // 5c. required checks must have PASSED (not merely "not-enforced"); full mode takes revocation from IsRevoked
        var checks = (D)verdict["checks"]!;
        foreach (var c in opts.RequireChecks ?? (policy == null ? DefaultRequireChecks.ToList() : new List<string>()))
            if (!(checks.GetValueOrDefault(c) is string cs && cs == "pass"))
                return Deny("proof-rejected", 403, $"required check '{c}' is {(checks.TryGetValue(c, out var st) ? Str(st) : "absent")}", realm, verdict, pcactn);

        // 5d. per-proof policy hook (limits, budgets, revocation lists); a raise denies
        if (opts.CheckProof != null)
        {
            try
            {
                var ctx = new D { ["pcactn"] = pcactn, ["grant"] = grant, ["verdict"] = verdict, ["request"] = req };
                if (required != null) ctx["required"] = required;
                var r = opts.CheckProof(ctx);
                var ok = r is bool rb ? rb : Jt(G(r, "allow"));
                if (!ok)
                {
                    var rsn = r is D && Jt(G(r, "reason")) ? Str(G(r, "reason")) : "rejected by checkProof";
                    return Deny("proof-rejected", 403, rsn, realm, verdict, pcactn);
                }
            }
            catch (Exception e) { return Deny("proof-rejected", 403, "checkProof failed: " + e.Message, realm, verdict, pcactn); }
        }

        // 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
        D? policyVerdict = null;
        if (policy != null && fullParams != null)
        {
            var (decision, pv) = FullPolicyCheck(req, opts, policy, pcactn, grant, required, fullParams, verdict, realm, now);
            if (decision != null) return decision;
            policyVerdict = pv;
        }

        // 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
        if (opts.ReplayGuard != null)
        {
            bool first;
            try { first = opts.ReplayGuard.Claim(Str(pcactn["grant_ref"]) + ":" + Str(pcactn["sig"]), IntentJs.NumOf(pcactn["exp"]) ?? double.NaN, now); }
            catch (Exception e) { return Deny("replay-guard-unavailable", 503, "replay guard unavailable: " + e.Message, realm, verdict, pcactn); }
            if (!first) return Deny("replayed-proof", 403, "this proof has already been used", realm, verdict, pcactn);
        }
        return Allowed(policyVerdict != null ? "proof-carrying action authorized (full policy)" : "proof-carrying action verified", verdict, pcactn, required, policyVerdict);
    }

    /// <summary>Merge the presented discharges / narrow block under the policy's own K1 input (its members win).</summary>
    static K1Input MergeK1(D presented, K1Input? own)
    {
        var discharges = own?.Discharges ?? (presented.GetValueOrDefault("discharges") as L);
        var pins = own?.Pins; var revoked = own?.RevokedDischarges; var spiffe = own?.SpiffeId; var history = own?.History;
        if (own is { HasNarrow: true }) return new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = spiffe, History = history, Narrow = own.Narrow };
        if (presented.TryGetValue("narrow", out var narrow)) return new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = spiffe, History = history, Narrow = narrow };
        return new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = spiffe, History = history };
    }

    /// <summary>Full-policy mode: delegate to the core authorize pipeline with the gateway's own audience, grant and clock.</summary>
    static (GatewayDecision? Decision, D? PolicyVerdict) FullPolicyCheck(D req, GatewayOptions opts, FullPolicy policy, D pcactn, D grant, D? required, D fullParams, D verdict, string realm, long now)
    {
        K1Input? k1 = null;
        if (policy.K1 != null)
        {
            try { k1 = MergeK1(PresentedArtifacts(req, policy), policy.K1(req, pcactn)); }
            catch (Exception e) { return (Deny("proof-rejected", 403, $"k1 input failed: {e.Message} (fail closed)", realm, verdict, pcactn), null); }
        }
        var bundle = PresentedProvenance(req, policy);
        var log = policy.ProvenanceLogOff ? null : policy.ProvenanceLog ?? (opts.DefaultLog ??= new MemoryProvenanceLog());
        var chain = pcactn.GetValueOrDefault("cap_chain") as L;
        var leaf = chain != null && chain.Count > 0 && chain[^1] is D lastCap && lastCap.TryGetValue("holder", out var lh) ? lh : Undef;
        var receipts = ReferenceEquals(bundle, Absent) ? null : G(bundle, "receipts") as L;
        var session = receipts != null && receipts.Count > 0 ? G(receipts[0], "session") : null;
        var logKey = Str(pcactn.GetValueOrDefault("grant_ref")) + "\n" + (ReferenceEquals(leaf, Undef) ? "undefined" : Str(leaf)) + "\n" + (session is string ss ? ss : "-");
        var action = (D)pcactn["action"]!;
        AuthorizeResult d;
        try
        {
            var input = new AuthorizeInput();
            policy.Configure?.Invoke(input);
            var verb = required != null ? Str(required["verb"]) : (string)action["verb"]!;
            var resource = required != null && required.GetValueOrDefault("resource") != null ? Str(required["resource"]) : (string)action["resource"]!;
            input.Operation = new Operation(verb, resource, fullParams);
            input.Audience = opts.Audience;
            input.Now = now;
            input.StateStore = policy.State;
            input.IsRevoked = policy.IsRevoked;
            if (policy.ZkHook != null) input.ZkHook = policy.ZkHook;
            if (policy.AttestationHook != null) input.AttestationHook = policy.AttestationHook;
            if (policy.EnforceAttestation != null) input.EnforceAttestation = policy.EnforceAttestation;
            input.ResolveGrant = _ => grant;
            if (k1 != null) { var k = k1; input.K1 = _ => k; }
            if (!ReferenceEquals(bundle, Absent)) { input.Provenance = bundle; input.ProvenanceUnreadable = bundle == null; }
            if (policy.Provenance != null || log != null)
            {
                var user = policy.Provenance;
                var joinedLog = log;
                input.ProvenanceFlow = new ArgProvenanceOptions
                {
                    Mediators = user?.Mediators,
                    Actions = user?.Actions,
                    Observed = (p, op, sess) =>
                    {
                        var o = new List<ProvObservation>();
                        if (user?.Observed != null) o.AddRange(user.Observed(p, op, sess) ?? Array.Empty<ProvObservation>());
                        if (joinedLog != null)
                            foreach (var x in joinedLog.Seen(logKey))
                                if (x.GetValueOrDefault("origin") is string og && x.GetValueOrDefault("source") is string sc) o.Add(new ProvObservation(og, sc));
                        return o;
                    },
                };
            }
            d = Pca.Authorize(pcactn, input);
        }
        catch (Exception e) { return (Deny("proof-rejected", 403, $"full policy failed: {e.Message} (fail closed)", realm, verdict, pcactn), null); }
        // what this call returns flows back into the agent's context: the session has now seen untrusted content
        if (d.Allow && log != null) log.Add(logKey, new D { ["origin"] = "tool", ["source"] = action["verb"] });
        var dchecks = new D(); foreach (var (ck, cv) in d.Checks) dchecks[ck] = cv;
        if (!d.Allow)
        {
            var code = d.Checks.GetValueOrDefault("replay") == "fail" ? "replayed-proof"
                : d.Checks.GetValueOrDefault("operation") == "fail" ? "insufficient-capability"
                : d.Status == 401 ? "verify-failed" : "proof-rejected";
            var pv = new D { ["allow"] = false, ["checks"] = dchecks, ["reason"] = d.Reason };
            return (Deny(code, d.Status, string.IsNullOrEmpty(d.Reason) ? "rejected" : d.Reason, realm, verdict, pcactn, policyVerdict: pv), null);
        }
        return (null, new D { ["allow"] = true, ["checks"] = dchecks });
    }

    /// <summary>A reusable authorizer bound to one frozen configuration. Throws <see cref="ArgumentException"/> when a component is missing.</summary>
    public static Func<D, GatewayDecision> CreateGateway(GatewayOptions opts)
    {
        var missing = MissingPolicy(opts);
        if (missing.Count > 0) throw new ArgumentException("pca-gateway: " + MissingText(opts, missing));
        var frozen = opts.Frozen();
        return req => Authorize(req, frozen);
    }
}
