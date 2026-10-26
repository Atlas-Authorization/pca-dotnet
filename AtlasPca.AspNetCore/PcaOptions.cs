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
    /// Optional Intent Layer v2 verifier state per request (rules 13-18: plaintext params, accepted schemas, the session root and
    /// grants, revocation evidence, layers, accumulator state, W-B artifacts and policy), given the request and the parsed
    /// PCActn. Null (the default) or a null result = no v2 state: the v2 checks run only for a PCActn carrying
    /// <c>intent_session</c> (and then fail closed). A resolver that throws denies the request (403 <c>intent_v2_context_error</c>).
    /// </summary>
    public Func<HttpContext, Dictionary<string, object?>, Task<IntentV2Context?>>? IntentV2 { get; set; }

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
    }
}

/// <summary>What the middleware stores at <c>HttpContext.Items["pca"]</c> on success: the allowing verdict and the verified PCActn.</summary>
public sealed record PcaAuthResult(Verdict Verdict, Dictionary<string, object?> Pcactn)
{
    /// <summary>The full allowing decision (checks, bound operation). Null with <see cref="PcaOptions.SignatureOnly"/>.</summary>
    public AuthorizeResult? Authorization { get; init; }

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

    /// <summary>Extra check names that must pass.</summary>
    public IReadOnlyList<string>? Require { get; set; }

    /// <summary>The operation this request will execute, from the route and the parsed request (never from the PCActn).
    /// Required. A null result or an exception denies (403).</summary>
    public Func<HttpContext, Task<Operation?>>? Operation { get; set; }
}
