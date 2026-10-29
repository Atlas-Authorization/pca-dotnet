using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AtlasPca.AspNetCore;

/// <summary>
/// Configuration for <see cref="PcaMiddleware"/>.
/// A "capability" (the grant) is the already-parsed PCA tree form that the verifier consumes:
/// a <see cref="Dictionary{TKey,TValue}"/> of string -&gt; object? (as produced by
/// <see cref="Pca.ParseJson"/> / <see cref="Pca.ParseStrict"/>).
/// </summary>
public sealed class PcaOptions
{
    /// <summary>The audience (resource-server / instance id) this server accepts. Checked against the signed <c>aud</c>.</summary>
    public string Audience { get; set; } = "";

    /// <summary>
    /// Resolves a <c>grant_ref</c> (the 32-byte base64url cap hash carried by the PCActn) to the root grant capability,
    /// or <c>null</c> when no grant is known for that ref (an unknown grant -&gt; 401).
    /// </summary>
    public Func<string, Task<Dictionary<string, object?>?>> GrantResolver { get; set; }
        = _ => Task.FromResult<Dictionary<string, object?>?>(null);

    /// <summary>Supplies "now" in epoch milliseconds. Defaults to the system UTC clock; override it for tests or a trusted time source.</summary>
    public Func<long> Clock { get; set; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>Request header the base64url PCActn is read from. Defaults to <c>PCA-Action</c>.</summary>
    public string HeaderName { get; set; } = "PCA-Action";

    /// <summary>The realm advertised in the <c>WWW-Authenticate</c> challenge.</summary>
    public string Realm { get; set; } = "pca";

    /// <summary>
    /// Optional Intent Layer M2 policy (require a bound <c>intent</c>, fidelity floor, residual-risk ceiling). Null (the
    /// default) = no policy: the <c>intent</c> check runs only for a PCActn that carries <c>intent</c>.
    /// </summary>
    public IntentPolicy? IntentPolicy { get; set; }

    /// <summary>
    /// Goal binding v3: the root grant must open to exactly this approved goal and compiled policy (a v1 / v2 grant does not), and a
    /// PCActn without a bound <c>intent</c> is refused. Merged into <see cref="IntentPolicy"/> (the floors there still apply); both
    /// set with different digests is a configuration error. Malformed digests fail every request closed.
    /// </summary>
    public ApprovedGoalRef? ApprovedGoal { get; set; }

    /// <summary>The intent policy the verifier runs with: <see cref="IntentPolicy"/> with <see cref="ApprovedGoal"/> applied.</summary>
    internal IntentPolicy? EffectiveIntentPolicy => ApprovedGoal is null ? IntentPolicy : (IntentPolicy ?? new IntentPolicy()) with { ApprovedGoal = ApprovedGoal };

    /// <summary>
    /// Run the downstream pipeline at most once per authorization, with a durable operation record (T3). Needs the authorize path (not
    /// <see cref="SignatureOnly"/>). The response the downstream middleware produces (status, headers, body) is recorded as the operation's
    /// result: a retry of the same PCActn is answered from the record (header <c>PCA-Replayed: true</c>) without running it again, a
    /// throw is recorded <c>failed</c> (500 <c>operation_failed</c>), a record still in flight is 409 <c>operation_in_progress</c>, an unknown
    /// outcome 409 <c>operation_uncertain</c>, a refused re-check 403 <c>operation_aborted</c>. An irreversible operation needs
    /// <see cref="PcaExecutorOptions.Recheck"/> (fail closed). The downstream response is buffered in memory.
    /// </summary>
    public PcaExecutorOptions? Executor { get; set; }

    /// <summary>
    /// Optional Intent Layer v2 verifier state per request (rules 13-18: plaintext params, accepted schemas, the session root and
    /// grants, revocation evidence, layers, accumulator state, W-B artifacts and policy), given the request and the parsed
    /// PCActn. Null (the default) or a null result = no v2 state: the v2 checks run only for a PCActn carrying
    /// <c>intent_session</c> (and then fail closed). A resolver that throws denies the request (403 <c>intent_v2_context_error</c>).
    /// </summary>
    public Func<HttpContext, Dictionary<string, object?>, Task<IntentV2Context?>>? IntentV2 { get; set; }

    /// <summary>
    /// Optional consistency-token policy per request (the verifier's own state counters move), given the request and the parsed PCActn.
    /// Null or a null result = no policy (a PCActn carrying <c>fresh_at</c> is then refused). When the PCActn has no <c>fresh_at</c>
    /// member and the policy carries no side-carried token, the <c>pca-fresh-at</c> request header (JSON) is read; an unparseable
    /// header is a bad token (deny), never a missing one. A resolver that throws denies the request.
    /// </summary>
    public Func<HttpContext, Dictionary<string, object?>, Task<FreshAtPolicy?>>? FreshAt { get; set; }

    /// <summary>
    /// The components of the full <see cref="Pca.AuthorizeAsync"/> pipeline, which is what the middleware runs by default (0.5):
    /// the proof must be for exactly the operation this request executes, the grant's envelope predicates and caveats must hold,
    /// the grant must not be revoked, and the counter is consumed in the replay store. Left null (and not
    /// <see cref="SignatureOnly"/>) the middleware runs with an empty option set and refuses every request with 403
    /// <c>authorize_config</c> naming the missing components. Never both with <see cref="SignatureOnly"/>.
    /// </summary>
    public PcaAuthorizeOptions? Authorize { get; set; }

    /// <summary>
    /// Explicit opt-in to signature-only verification: only the core verifier runs (signature, chain, audience, validity,
    /// counter format). It does NOT check the operation, the envelope predicates and caveats, revocation or replay. Mutually
    /// exclusive with <see cref="Authorize"/> (the middleware constructor throws).
    /// </summary>
    public bool SignatureOnly { get; set; }

    public void Validate()
    {
        if (string.IsNullOrEmpty(Audience)) throw new InvalidOperationException("PcaOptions.Audience must be set.");
        if (GrantResolver is null) throw new InvalidOperationException("PcaOptions.GrantResolver must be set.");
        if (Clock is null) throw new InvalidOperationException("PcaOptions.Clock must be set.");
        if (string.IsNullOrEmpty(HeaderName)) throw new InvalidOperationException("PcaOptions.HeaderName must be set.");
        if (SignatureOnly && Authorize != null) throw new InvalidOperationException("PcaOptions: SignatureOnly and Authorize are mutually exclusive (signature-only skips every authorize check).");
        if (IntentPolicy?.ApprovedGoal is { } a && ApprovedGoal is { } b && a != b) throw new InvalidOperationException("PcaOptions: IntentPolicy.ApprovedGoal and ApprovedGoal name different goals.");
        if (Executor != null)
        {
            if (SignatureOnly) throw new InvalidOperationException("PcaOptions: Executor needs the authorize path (not SignatureOnly).");
            if (Executor.Operations is null) throw new InvalidOperationException("PcaOptions: Executor.Operations (an IOperationStore) is required.");
            if (Executor.RecheckFor is not (null or "irreversible" or "always")) throw new InvalidOperationException("PcaOptions: Executor.RecheckFor must be \"irreversible\" or \"always\".");
        }
        if (Authorize is { EscalationPrincipals.Count: > 0, StateStore: { } store } && store is not ILastStore)
            throw new InvalidOperationException("PcaOptions: Authorize.EscalationPrincipals needs a StateStore that implements ILastStore (an escalation answer is bound to the holder's history head).");
    }
}

/// <summary>What the middleware stores at <c>HttpContext.Items["pca"]</c> on success: the allowing verdict and the verified PCActn.</summary>
public sealed record PcaAuthResult(Verdict Verdict, Dictionary<string, object?> Pcactn)
{
    /// <summary>The full allowing decision (checks, bound operation). Null with <see cref="PcaOptions.SignatureOnly"/>.</summary>
    public AuthorizeResult? Authorization { get; init; }

    /// <summary>With <see cref="PcaOptions.Executor"/>: the operation id, to hand to the downstream call as its idempotency key.</summary>
    public string? IdempotencyKey { get; init; }

    /// <summary>The operation the proof was bound to and consumed for. Null with <see cref="PcaOptions.SignatureOnly"/>.</summary>
    public AuthorizedOperation? Operation => Authorization?.Operation;
}

/// <summary>
/// The <see cref="PcaOptions.Authorize"/> option: the components <see cref="Pca.AuthorizeAsync"/> needs on top of the
/// audience, grant resolver, clock and Intent Layer options of <see cref="PcaOptions"/>. A missing <see cref="StateStore"/>,
/// <see cref="IsRevoked"/> or <see cref="Operation"/> mapping denies every request (403, fail closed).
/// </summary>
public sealed class PcaAuthorizeOptions
{
    /// <summary>The replay store (atomic claim per counter stream). Required.</summary>
    public IStateStore? StateStore { get; set; }

    /// <summary><c>(pcactn, grant) -&gt; revoked?</c>; only <c>false</c> passes. Required.</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>, bool?>? IsRevoked { get; set; }

    /// <summary><c>"single-step"</c> (the default): accept a one-node plan whose node is exactly this operation. Set null to
    /// require a principal-authorized plan from <see cref="Context"/>.</summary>
    public string? Plan { get; set; } = "single-step";

    /// <summary>Optional per-request context (<c>plan</c>, <c>plan_authorized</c>, <c>subject</c>, <c>env</c>,
    /// <c>blast_radius</c>, <c>recent_action_times</c>, <c>reversibility_class</c>). A throwing callback denies.</summary>
    public Func<HttpContext, Dictionary<string, object?>, Dictionary<string, object?>?>? Context { get; set; }

    /// <summary>Caveat language v2 input per request (the verifier's discharge pins, revoked discharges, verified SPIFFE ID, history).
    /// Discharges and a narrow block are read from the <c>PCA-Discharges</c> and <c>PCA-Narrow</c> headers (strict base64url JSON) and
    /// merged under what this callback returns (its members win); unreadable headers present nothing. <c>max_uses</c> is spent in
    /// <see cref="StateStore"/>. Null: a chain with a K1 caveat is refused (the caveat language is not configured).</summary>
    public Func<HttpContext, Dictionary<string, object?>, K1Input?>? K1 { get; set; }

    /// <summary>Extra check names that must pass.</summary>
    public IReadOnlyList<string>? Require { get; set; }

    /// <summary>Pins the keys whose escalation answers count (header <c>PCA-Escalation-Answer</c>: strict base64url JSON, or the JSON
    /// body member <c>escalation_answer</c>). Empty: every escalate is refused (403, <c>decision</c> "escalate").</summary>
    public IReadOnlyList<PinnedSigner>? EscalationPrincipals { get; set; }

    /// <summary>K7: recompute the approval render digest from the executed params and your own definition (see <c>AuthorizeInput.EscalationRender</c>).</summary>
    public Func<Dictionary<string, object?>, string?>? EscalationRender { get; set; }

    /// <summary>The documented INSECURE opt-out of the default that an escalation answer needs a recomputed, matching approval render.</summary>
    public bool InsecureUnboundApproval { get; set; }

    /// <summary>K5 (C-308): the workflow admission gate (the keys this server pinned; see <see cref="AuthorizeInput.Workflow"/>). Null = off. With it set,
    /// a request without a <see cref="WorkflowCall"/> is refused when <c>Required</c>.</summary>
    public WorkflowGate? Workflow { get; set; }

    /// <summary>The workflow step this request is (commitment, receipts, step, units, goal digest), read from the request. A null result means the
    /// request carries no workflow step; a throwing callback denies (403, check <c>workflow</c>). Used only when <see cref="Workflow"/> is set. Unset: the JSON request body member <c>workflow</c> {commitment, receipts, step, units, goal_digest} is read when the PCActn came in the body (not in the header).</summary>
    public Func<HttpContext, Dictionary<string, object?>, WorkflowCall?>? WorkflowCall { get; set; }

    /// <summary>The operation this request will execute, from the route and the parsed request (never from the PCActn).
    /// Required. A null result or an exception denies (403).</summary>
    public Func<HttpContext, Task<Operation?>>? Operation { get; set; }

    /// <summary>Revocation staleness (T9): caps how old the revocation state may be, by the action's effective reversibility class. Needs
    /// <see cref="RevocationState"/> (and <see cref="GuardianPublic"/> for a signed epoch); a stale, missing or unverifiable state fails the
    /// <c>freshness</c> check. <see cref="IsRevoked"/> stays the revocation answer and works unchanged.</summary>
    public RevocationStalenessPolicy? RevocationStaleness { get; set; }

    /// <summary><c>(request, pcactn, grant) -&gt; state</c>: the guardian-signed epoch or bare root (with its issue time) the revocation answer rests on. A throw denies.</summary>
    public Func<HttpContext, Dictionary<string, object?>, Dictionary<string, object?>, RevocationState?>? RevocationState { get; set; }

    /// <summary>The pinned Ed25519 identity (base64url) of the epoch guardian.</summary>
    public string? GuardianPublic { get; set; }

    /// <summary>Which capability ids need a non-membership proof when <see cref="RevocationStaleness"/> is on. Default: every <c>id</c> in the
    /// PCActn's <c>cap_chain</c>; return an empty list for a freshness-only gate.</summary>
    public Func<HttpContext, Dictionary<string, object?>, IReadOnlyList<string>>? RevocationIds { get; set; }

    /// <summary><c>(request, pcactn, id) -&gt; proof</c>: the non-membership proof {size, lo?, hi?} for a capability id. Without it, or when it
    /// returns null, the request is denied (fail closed).</summary>
    public Func<HttpContext, Dictionary<string, object?>, string, Dictionary<string, object?>?>? RevocationProofFor { get; set; }

    /// <summary>PQ key pins of a post-quantum guardian ({Ed25519 identity: ML-DSA public key}).</summary>
    public IReadOnlyDictionary<string, string>? GuardianPins { get; set; }

    /// <summary>A high-assurance policy (T8): unmet evidence fails the <c>assurance</c> check before any replay state is written.</summary>
    public AssuranceRequirement? RequireAssurance { get; set; }

    /// <summary>The assurance labels of the verifier's hooks (the report never trusts presented evidence).</summary>
    public AssuranceHooks? AssuranceHooks { get; set; }

    /// <summary>The plan registry (T10): the registered plan and its executability feed <c>plan_root_authorized</c>; the <c>plan_state</c> check names the state on a denial. Set <see cref="Plan"/> to null to require a registered plan.</summary>
    public PlanRegistry? Plans { get; set; }

    /// <summary>Provenance by default (check <c>provenance_flow</c>, always on; see <see cref="AuthorizeInput.ProvenanceFlow"/>): the pinned
    /// mediator keys, the action facts and the server's own observations. The bundle is read from the <c>PCA-Provenance</c> header (strict
    /// base64url JSON; an undecodable header denies) or the JSON body member <c>pca_provenance</c>. Null: no pins, so every sensitive action
    /// escalates unless the grant envelope names the principal's mediator.</summary>
    public ArgProvenanceOptions? ProvenanceFlow { get; set; }

    /// <summary>Optional undo windows (see <see cref="AuthorizeInput.Undo"/>): <c>(ctx, pcactn, grant, operation) -&gt; admission</c>, called only for an
    /// unanswered, non-provenance escalation; return an admission only after your undo coordinator durably opened the window's record.</summary>
    public Func<HttpContext, Dictionary<string, object?>, Dictionary<string, object?>, Operation, UndoAdmission?>? Undo { get; set; }
}

/// <summary>The <see cref="PcaOptions.Executor"/> option: the operation records and the re-check policy.</summary>
public sealed class PcaExecutorOptions
{
    /// <summary>REQUIRED: the operation record store (shared and durable in production).</summary>
    public IOperationStore? Operations { get; set; }
    /// <summary>An extra re-check before an irreversible operation (for example a step-up approval still stands). The executor always re-runs
    /// <see cref="PcaAuthorizeOptions.IsRevoked"/>, checks the PCActn's expiry and a registered plan first.</summary>
    public Func<ExecutionHandle, RecheckResult>? Recheck { get; set; }
    /// <summary>"irreversible" (default) or "always".</summary>
    public string? RecheckFor { get; set; }
    /// <summary>The server's reversibility class for an operation (catalog); null: the signed class only.</summary>
    public Func<Operation, string?>? ReversibilityClassOf { get; set; }
    /// <summary>An open record older than this (ms) is settled; null: five minutes.</summary>
    public long? PendingTimeoutMs { get; set; }
}
