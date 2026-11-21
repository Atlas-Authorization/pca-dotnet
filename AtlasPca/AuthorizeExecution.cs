// `authorizeExecution` (packages/pca server/authorize-execution.ts): the full-policy check for ONE local execution (an agent framework tool call, a gateway request), for verifiers
// that have the PCActn in hand rather than an HTTP request. The core verifier alone checks that a proof is genuine; it does not read the grant's limits, so a validly signed $400
// payment under a $100 grant passes it. This runs, in order: (1) configuration: the audience, a grant source, the replay / budget store and the revocation check are REQUIRED, a
// missing one denies every call (fail closed, never a downgrade to signature-only); (2) operation binding: the PCActn's signed verb (and resource, when the caller names one) must
// be the operation about to execute; (3) the full server verifier, through Pca.Authorize (the one pipeline): the grant from the caller's store, the operation's params against the
// signed params digest, the grant's predicates, limits and caveats, revocation, the replay counter and the trust budget, with risk priced from server-side inputs.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The operation that is about to execute: what the PCActn must have been signed for.</summary>
/// <param name="Verb">The PCA verb of this operation (for example <c>stripe.refund</c>). Must equal the signed <c>action.verb</c>.</param>
/// <param name="Resource">The PCA resource. When given it must equal the signed <c>action.resource</c>.</param>
/// <param name="Params">The parameters the operation will execute with. They must hash to the signed <c>action.params_digest</c>.</param>
/// <param name="Provenance">The provenance bundle the agent presented with this call; null = unlabelled.</param>
public sealed record ExecutionOperation(string Verb, string? Resource, D Params, object? Provenance = null);

/// <summary>The configuration of <see cref="PcaExecution.AuthorizeExecution"/>. <see cref="Audience"/>, a grant source (<see cref="Grant"/> or <see cref="ResolveGrant"/>), <see cref="State"/>
/// and <see cref="IsRevoked"/> are required.</summary>
public sealed class AuthorizeExecutionOptions
{
    /// <summary>REQUIRED: this verifier's audience id. A PCActn whose signed <c>aud</c> differs is denied.</summary>
    public string Audience { get; set; } = "";
    /// <summary>The grant the PCActn must chain to. Give this or <see cref="ResolveGrant"/>.</summary>
    public D? Grant { get; set; }
    /// <summary>Look the grant up in YOUR store by the PCActn's signed <c>grant_ref</c>. Never return a grant taken from the call.</summary>
    public Func<string, D, D?>? ResolveGrant { get; set; }
    /// <summary>REQUIRED: replay counters and trust budgets per agent. Share one store across processes.</summary>
    public IStateStore? State { get; set; }
    /// <summary>REQUIRED: is this grant revoked, <c>(grant, pcactn) -&gt; revoked?</c>. Only <c>false</c> passes; a verifier that cannot answer this must not authorize.</summary>
    public Func<D, D, bool?>? IsRevoked { get; set; }
    /// <summary>Has the principal authorized this plan root for this grant, <c>(grantRef, planRoot)</c>? Default: a one-step plan is authorized when it is exactly the step that was signed.</summary>
    public Func<string, string, bool>? IsPlanAuthorized { get; set; }
    /// <summary>Server-side risk inputs for this operation, <c>(grant, params, pcactn)</c>. Default: <see cref="PcaServer.AmountRisk"/> (<c>blastRadius = amount / kappa</c>). Inputs not supplied are priced at the worst case.</summary>
    public Func<D, D, D, IReadOnlyDictionary<string, double>?>? Risk { get; set; }
    /// <summary>The threshold co-signature hook (revocation always comes from <see cref="IsRevoked"/>).</summary>
    public Func<D, D, ThresholdHookResult?>? ThresholdHook { get; set; }
    /// <summary>The zk verifier hook for a PCActn that carries <c>zk_compliance</c> (see <see cref="AuthorizeInput.ZkHook"/>); without it a carried proof is refused.</summary>
    public PcaCore.Hook? ZkHook { get; set; }
    /// <summary>The attestation verifier hook (see <see cref="AuthorizeInput.AttestationHook"/>).</summary>
    public PcaCore.Hook? AttestationHook { get; set; }
    /// <summary>The attestation gate (see <see cref="AuthorizeInput.EnforceAttestation"/>).</summary>
    public PcaCore.AttestationGate? EnforceAttestation { get; set; }
    /// <summary>Further checks that must report <c>pass</c>, on top of the full-mode defaults.</summary>
    public IEnumerable<string>? Require { get; set; }
    /// <summary>Caveat language v2 input (pins, presented discharges, revoked discharges, SPIFFE id, history). Null: every K1 caveat in the chain refuses (fail closed).</summary>
    public Func<D, K1Input?>? K1 { get; set; }
    /// <summary>Accepted signature suites. Default <c>ed25519</c> only.</summary>
    public IReadOnlyCollection<string>? AllowedSuites { get; set; }
    /// <summary>Server-side PQ pins <c>issuer -&gt; pq_pk</c>, needed only to accept a post-quantum suite.</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>Verifier clock (epoch ms). Default: the wall clock.</summary>
    public Func<long>? Now { get; set; }
    /// <summary>High-assurance policy: weaker, missing, failed, unlabelled, awaiting-audit or unsupported evidence denies.</summary>
    public AssuranceRequirement? RequireAssurance { get; set; }
    /// <summary>The information-flow taint gate. Null: not enforced.</summary>
    public TaintGate? EnforceTaint { get; set; }
    /// <summary>The freshness-anchor gate. Null: not enforced.</summary>
    public FreshnessGate? EnforceFreshness { get; set; }
    /// <summary>More than one process or node shares <see cref="State"/>: a process-scoped store is refused and every call is denied with the reason.</summary>
    public bool? MultiInstance { get; set; }
    /// <summary>The provenance gate's configuration (pinned mediators, the action facts, server observations). The gate is always on; null = no pins and unknown actions.</summary>
    public ArgProvenanceOptions? ProvenanceFlow { get; set; }
}

/// <summary>The outcome of <see cref="PcaExecution.AuthorizeExecution"/>. On a denial <see cref="Kind"/> is config, binding, authn, policy, replay or revoked.</summary>
public sealed record ExecutionDecision(bool Allow, string? Kind = null, int Status = 200, string? Reason = null, D? Pcactn = null, D? Grant = null, AuthorizeResult? Result = null);

public static class PcaExecution
{
    /// <summary>The required components that <paramref name="o"/> lacks (empty when the configuration is complete).</summary>
    public static IReadOnlyList<string> MissingExecutionComponents(AuthorizeExecutionOptions? o)
    {
        var missing = new List<string>();
        if (string.IsNullOrEmpty(o?.Audience)) missing.Add("audience");
        if (o?.Grant == null && o?.ResolveGrant == null) missing.Add("grant or resolveGrant");
        if (o?.State == null) missing.Add("state");
        if (o?.IsRevoked == null) missing.Add("isRevoked");
        return missing;
    }

    static ExecutionDecision Deny(string kind, int status, string reason, AuthorizeResult? r = null) => new(false, kind, status, reason, Result: r);

    const string RiskNoise = "risk input(s) missing";

    /// <summary>The reason of the first failing check (the verifier also lists context such as worst-case risk inputs). The verb and resource are bound before the verifier runs, so a
    /// failing <c>operation</c> check here is a params mismatch that <c>params_digest</c> already reports: it is ranked last so the reason stays the established <c>params_digest</c> one.</summary>
    static string DecisiveReason(AuthorizeResult r)
    {
        foreach (var name in r.Checks.Where(kv => kv.Key != "operation").Concat(r.Checks.Where(kv => kv.Key == "operation")).Where(kv => kv.Value == "fail").Select(kv => kv.Key))
        {
            var hit = r.Reasons.FirstOrDefault(x => x.StartsWith(name + ":", StringComparison.Ordinal) && !x.Contains(RiskNoise, StringComparison.Ordinal));
            if (hit != null) return hit;
        }
        return r.Reasons.FirstOrDefault(x => !x.Contains(RiskNoise, StringComparison.Ordinal)) ?? r.Reasons.FirstOrDefault() ?? "denied";
    }

    static string Show(object? v) => v == null ? "undefined" : IntentRevocation.JsText(v, true);

    /// <summary>The PCActn's one-step plan, rebuilt from the signed action.</summary>
    static List<D> PlanOf(D p)
    {
        var action = (D)p["action"]!;
        var node = new D { ["id"] = ((D)p["plan"]!)["node_id"], ["verb"] = action["verb"], ["resource"] = action["resource"] };
        if (action.TryGetValue("params_digest", out var pd)) node["params_digest"] = pd;
        if (action.TryGetValue("reversibility_class", out var rc)) node["reversibility_class"] = rc;
        return new List<D> { node };
    }

    /// <summary>Authorize one execution completely: configuration, binding to the operation, and the full verifier. Never throws: a failure is a denial.</summary>
    public static ExecutionDecision AuthorizeExecution(object? pcactn, ExecutionOperation operation, AuthorizeExecutionOptions options)
    {
        var missing = MissingExecutionComponents(options);
        if (missing.Count > 0) return Deny("config", 403, $"full policy mode is missing {string.Join(", ", missing)} (fail closed)");
        try
        {
            var p = pcactn as D;
            var signed = p?.GetValueOrDefault("action") as D;
            var verb = signed?.GetValueOrDefault("verb");
            var resource = signed?.GetValueOrDefault("resource");
            // binding: checked before any state is read or written, so a proof presented for another operation is not spent
            if (!Equals(verb, operation.Verb) || (operation.Resource != null && !Equals(resource, operation.Resource)))
            {
                var want = operation.Resource != null ? $"{operation.Verb} on {operation.Resource}" : operation.Verb;
                return Deny("binding", 403, $"the proof is for {Show(verb)} on {Show(resource)}, but this call is {want}");
            }
            var grantRef = p!.GetValueOrDefault("grant_ref") as string ?? "";
            var grant = options.Grant ?? options.ResolveGrant!(grantRef, p);
            if (grant == null) return Deny("authn", 401, "unknown grant_ref");
            var now = options.Now?.Invoke() ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var prms = operation.Params;

            // the one pipeline: Pca.Authorize with every component required and the proof bound to the operation. This wrapper only maps its option names, adds the principal's plan
            // gate and the amount-priced risk, and maps the result to an ExecutionDecision.
            var input = new AuthorizeInput
            {
                Operation = new Operation(operation.Verb, operation.Resource ?? (string)resource!, prms),
                Audience = options.Audience,
                ResolveGrant = _ => grant,
                StateStore = options.State,
                IsRevoked = (pc, g) => options.IsRevoked!(g, pc),
                AllowedSuites = options.AllowedSuites ?? new[] { "ed25519" },
                PqPins = options.PqPins,
                Now = now,
                RequireAssurance = options.RequireAssurance,
                EnforceTaint = options.EnforceTaint,
                EnforceFreshness = options.EnforceFreshness,
                MultiInstance = options.MultiInstance,
                ThresholdHook = options.ThresholdHook,
                ZkHook = options.ZkHook,
                AttestationHook = options.AttestationHook,
                EnforceAttestation = options.EnforceAttestation,
                K1 = options.K1,
                Provenance = operation.Provenance,
                ProvenanceFlow = options.ProvenanceFlow,
                Require = PcaServer.ExecutionRequiredChecks.Concat(options.Require ?? Enumerable.Empty<string>()).ToList(),
                ServerRiskFor = (_, g, pc) => options.Risk != null ? options.Risk(g, prms, pc) : PcaServer.AmountRisk(g, prms) is double br ? new Dictionary<string, double> { ["blastRadius"] = br } : null,
                Context = pc =>
                {
                    var plan = PlanOf(pc);
                    var root = (string)((D)pc["plan"]!)["root"]!;
                    var consistent = Pca.MerkleRoot(plan.Select(n => (object?)PcaHelpers.PlanNodeLeaf(n)).ToList()) == root;
                    var approved = options.IsPlanAuthorized == null || options.IsPlanAuthorized(pc.GetValueOrDefault("grant_ref") as string ?? "", root);
                    return new D { ["params"] = prms, ["plan"] = new L(plan), ["plan_authorized"] = consistent && approved };
                },
            };
            var r = Pca.Authorize(pcactn, input);
            if (r.Allow) return new ExecutionDecision(true, null, 200, null, r.Pcactn ?? p, grant, r);
            var kind = r.Status == 401 ? "authn" : r.Checks.GetValueOrDefault("revocation") == "fail" ? "revoked" : r.Checks.GetValueOrDefault("replay") == "fail" ? "replay" : "policy";
            return Deny(kind, r.Status, DecisiveReason(r), r);
        }
        catch (Exception e) { return Deny("policy", 403, "authorization error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
    }
}
