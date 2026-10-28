using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace AtlasPca.AspNetCore;

/// <summary>
/// ASP.NET Core middleware for Proof-Carrying Authority. It reads a PCActn from the <c>PCA-Action</c> header
/// (base64url -&gt; JSON -&gt; strict decode) or from a JSON body <c>{"pcactn": ...}</c>, resolves the root grant,
/// and by default runs the full <see cref="Pca.AuthorizeAsync"/> pipeline (operation binding, envelope predicates and caveats,
/// revocation, replay). <see cref="PcaOptions.SignatureOnly"/> opts into the offline verifier alone (<see cref="Pca.VerifyPcactnCore"/>).
///
/// On success it sets <c>HttpContext.Items["pca"]</c> to a <see cref="PcaAuthResult"/> and calls the next middleware.
/// On failure it writes 401 (absent / undecodable / unknown grant) or 403 (a denying verdict) with a
/// <c>WWW-Authenticate: PCA realm="pca", ...</c> header and a small JSON body. It does not re-implement any crypto.
/// </summary>
public sealed class PcaMiddleware
{
    readonly RequestDelegate _next;
    readonly PcaOptions _options;

    public PcaMiddleware(RequestDelegate next, PcaOptions options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var (tree, error) = await ReadPcactnAsync(ctx);
        if (error is { } e1)
        {
            await ChallengeAsync(ctx, StatusCodes.Status401Unauthorized, e1.Error, e1.Description);
            return;
        }

        if (tree is not Dictionary<string, object?> p)
        {
            await ChallengeAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_request", "PCActn must be a JSON object.");
            return;
        }

        FreshAtPolicy? freshAt = null;
        if (_options.FreshAt != null)
        {
            try { freshAt = WithSideCarried(ctx, p, await _options.FreshAt(ctx, p)); }
            catch (Exception)
            {
                await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", "fresh_at_policy_error: the consistency-token policy could not be resolved (fail closed).");
                return;
            }
        }

        if (!_options.SignatureOnly)
        {
            await AuthorizeAsync(ctx, p, _options.Authorize ?? new PcaAuthorizeOptions(), freshAt);
            return;
        }

        // The grant_ref binds the PCActn to a root grant; resolve it before the (grant-rooted) verify.
        if (!p.TryGetValue("grant_ref", out var gr) || gr is not string grantRef || grantRef.Length == 0)
        {
            await ChallengeAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_request", "PCActn is missing a string 'grant_ref'.");
            return;
        }

        Dictionary<string, object?>? grant;
        try { grant = await _options.GrantResolver(grantRef); }
        catch (Exception)
        {
            // The host's resolver failed: fail closed as TS requirePCA does (403, guard error), never an unhandled 500.
            await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", "grant resolution failed (fail closed).");
            return;
        }
        if (grant is null)
        {
            await ChallengeAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_grant", "No grant is known for this grant_ref.");
            return;
        }

        // The existing verifier: 8 offline checks, audience vs signed aud, chain rooted at the resolved grant.
        IntentV2Context? intentV2 = null;
        if (_options.IntentV2 != null)
        {
            try { intentV2 = await _options.IntentV2(ctx, p); }
            catch (Exception)
            {
                await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", "intent_v2_context_error: the Intent Layer v2 verifier state could not be resolved (fail closed).");
                return;
            }
        }
        Verdict verdict = Pca.VerifyPcactnCore(p, grant, _options.Clock(), _options.Audience, intentPolicy: _options.EffectiveIntentPolicy, intentV2: intentV2, freshAt: freshAt);
        if (!verdict.Allow)
        {
            await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", verdict.Reason);
            return;
        }

        ctx.Items["pca"] = new PcaAuthResult(verdict, p);
        await _next(ctx);
    }

    /// <summary>
    /// The full pipeline (the default; <see cref="PcaOptions.Authorize"/>): map the request to its operation, then
    /// <see cref="Pca.AuthorizeAsync"/>. Any denial (including a missing component or operation) stops the request here.
    /// </summary>
    async Task AuthorizeAsync(HttpContext ctx, Dictionary<string, object?> p, PcaAuthorizeOptions az, FreshAtPolicy? freshAt)
    {
        Operation? op = null;
        if (az.Operation != null)
        {
            try { op = await az.Operation(ctx); }
            catch (Exception) { op = null; } // the host's mapping failed: no operation, which denies
        }
        var context = az.Context;
        var v2 = _options.IntentV2;
        var state = az.RevocationState;
        WorkflowCall? wcall = null;
        if (az.Workflow != null)
        {
            if (az.WorkflowCall != null)
            {
                try { wcall = az.WorkflowCall(ctx, p); }
                catch (Exception) { wcall = new WorkflowCall(null, null, null); } // the host's reader failed: an empty call, which the gate denies
            }
            else wcall = await ExtractWorkflowCallAsync(ctx);
        }
        var input = new AuthorizeInput
        {
            Operation = op,
            Audience = _options.Audience,
            ResolveGrantAsync = r => _options.GrantResolver(r),
            StateStore = az.StateStore,
            IsRevoked = az.IsRevoked,
            Now = _options.Clock(),
            Plan = az.Plan,
            Context = context == null ? null : pc => context(ctx, pc),
            IntentPolicy = _options.EffectiveIntentPolicy,
            FreshAt = freshAt,
            IntentV2ProviderAsync = v2 == null ? null : pc => v2(ctx, pc),
            Require = az.Require,
            K1 = az.K1 == null ? null : pc => CaveatLang.MergePresented(PresentedFrom(ctx), az.K1(ctx, pc)),
            EscalationPrincipals = az.EscalationPrincipals,
            EscalationRender = az.EscalationRender,
            InsecureUnboundApproval = az.InsecureUnboundApproval,
            EscalationAnswer = az.EscalationPrincipals is { Count: > 0 } ? await ExtractEscalationAnswerAsync(ctx) : null,
            RevocationStaleness = az.RevocationStaleness,
            RevocationState = state == null ? null : (pc, g) => state(ctx, pc, g),
            GuardianPublic = az.GuardianPublic,
            GuardianPins = az.GuardianPins,
            RevocationIds = az.RevocationIds == null ? null : pc => az.RevocationIds(ctx, pc),
            RevocationProofFor = az.RevocationProofFor == null ? null : (pc, id) => az.RevocationProofFor(ctx, pc, id),
            RequireAssurance = az.RequireAssurance,
            AssuranceHooks = az.AssuranceHooks,
            Plans = az.Plans,
            Workflow = az.Workflow,
            WorkflowCall = wcall,
        };
        if (_options.Executor != null)
        {
            await ExecuteOnceAsync(ctx, p, input, op, _options.Executor);
            return;
        }
        var result = await Pca.AuthorizeAsync(p, input);
        if (!result.Allow)
        {
            await DeniedAsync(ctx, result);
            return;
        }
        ctx.Items["pca"] = new PcaAuthResult(result.Verdict!, p) { Authorization = result };
        await _next(ctx);
    }

    Task DeniedAsync(HttpContext ctx, AuthorizeResult result) =>
        ChallengeAsync(ctx, result.Status, result.Status == StatusCodes.Status401Unauthorized ? "invalid_request" : "access_denied", result.Reason ?? "denied", result);

    static readonly HashSet<string> NotRecorded = new(StringComparer.OrdinalIgnoreCase) { "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive" };

    /// <summary>
    /// The executor path (<see cref="PcaOptions.Executor"/>): authorize, then run the downstream pipeline inside
    /// <see cref="Pca.ExecuteAuthorizedAsync"/> with its response buffered, so a retry is answered from the operation record.
    /// </summary>
    async Task ExecuteOnceAsync(HttpContext ctx, Dictionary<string, object?> p, AuthorizeInput input, Operation? op, PcaExecutorOptions ex)
    {
        var executor = new PcaExecutor(new ExecutorOptions
        {
            Operations = ex.Operations, Authorize = input, Recheck = ex.Recheck, RecheckFor = ex.RecheckFor, ReversibilityClassOf = ex.ReversibilityClassOf,
            PendingTimeoutMs = ex.PendingTimeoutMs, Now = _options.Clock,
        });
        var original = ctx.Response.Body;
        var outcome = await executor.RunAsync(p, op, async h =>
        {
            var az = h.Authorization!;
            ctx.Items["pca"] = new PcaAuthResult(az.Verdict!, p) { Authorization = az, IdempotencyKey = h.IdempotencyKey };
            using var buffer = new MemoryStream();
            ctx.Response.Body = buffer;
            try { await _next(ctx); }
            finally { ctx.Response.Body = original; }
            var headers = new Dictionary<string, object?>();
            foreach (var kv in ctx.Response.Headers)
                if (!NotRecorded.Contains(kv.Key)) headers[kv.Key] = kv.Value.Select(v => (object?)(v ?? "")).ToList();
            // the app's response is the operation's result: a JSON tree a durable store can keep
            return new Dictionary<string, object?>
            {
                ["status"] = new Num(ctx.Response.StatusCode.ToString(CultureInfo.InvariantCulture)), ["headers"] = headers, ["body"] = Convert.ToBase64String(buffer.ToArray()),
            };
        });
        switch (outcome.Status)
        {
            case "committed": await WriteRecordedAsync(ctx, outcome); break;
            case "denied": await DeniedAsync(ctx, outcome.Authorization!); break;
            case "failed": await ChallengeAsync(ctx, StatusCodes.Status500InternalServerError, "operation_failed", "the operation failed"); break;
            case "aborted": await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "operation_aborted", outcome.Reason ?? "aborted"); break;
            case "pending": await ChallengeAsync(ctx, StatusCodes.Status409Conflict, "operation_in_progress", "another execution of this operation is in flight"); break;
            case "uncertain": await ChallengeAsync(ctx, StatusCodes.Status409Conflict, "operation_uncertain", outcome.Reason ?? "outcome unknown"); break;
            default: await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", outcome.Reason ?? "denied"); break;
        }
    }

    /// <summary>The app's recorded response, rebuilt from the operation record (an unreadable record is 409 <c>operation_uncertain</c>).</summary>
    async Task WriteRecordedAsync(HttpContext ctx, ExecuteOutcome outcome)
    {
        int status; byte[] body; Dictionary<string, object?> headers;
        try
        {
            var r = (Dictionary<string, object?>)outcome.Result!;
            if (r["status"] is not Num n || !int.TryParse(n.Raw, NumberStyles.None, CultureInfo.InvariantCulture, out status)) throw new FormatException("status");
            headers = (Dictionary<string, object?>)r["headers"]!;
            body = Convert.FromBase64String((string)r["body"]!);
        }
        catch (Exception)
        {
            await ChallengeAsync(ctx, StatusCodes.Status409Conflict, "operation_uncertain", "the recorded result is unreadable");
            return;
        }
        ctx.Response.StatusCode = status;
        foreach (var (name, values) in headers)
            if (values is List<object?> l && !NotRecorded.Contains(name)) ctx.Response.Headers[name] = new StringValues(l.Select(v => v as string ?? "").ToArray());
        if (outcome.Replayed) ctx.Response.Headers["PCA-Replayed"] = "true";
        await ctx.Response.Body.WriteAsync(body);
    }

    /// <summary>The side-carried <c>pca-fresh-at</c> header (the pre-member form), read only when the PCActn has no <c>fresh_at</c> member and
    /// the policy carries no token of its own. An unparseable header becomes a null token (bad_token), never an absent one.</summary>
    static FreshAtPolicy? WithSideCarried(HttpContext ctx, Dictionary<string, object?> p, FreshAtPolicy? policy)
    {
        if (policy == null || p.ContainsKey("fresh_at") || policy.HasSideCarried) return policy;
        var h = ctx.Request.Headers["pca-fresh-at"];
        if (h.Count == 0 || string.IsNullOrEmpty(h[0])) return policy;
        object? token;
        try { token = Pca.ParseStrict(h[0]!); } catch (Exception) { token = null; }
        return new FreshAtPolicy(policy.Signer, policy.Scope, policy.Local, policy.MaxTokenAgeMs, policy.Require, true, token);
    }

    /// <summary>
    /// Returns the parsed PCActn tree, or an (error, description) pair for a 401. Header mode takes precedence over body.
    /// Enables rewind on the body so downstream middleware can still read it.
    /// </summary>
    async Task<(object? Tree, (string Error, string Description)? Error)> ReadPcactnAsync(HttpContext ctx)
    {
        var header = ctx.Request.Headers[_options.HeaderName];
        if (header.Count > 0 && !string.IsNullOrEmpty(header[0]))
        {
            // 0.4.1: STRICT unpadded base64url of well-formed UTF-8 (Pca.DecodePcaHeader). Invalid UTF-8 used to be replaced with
            // U+FFFD and reach the JSON parser, so one PCActn had several header spellings.
            string? text = Pca.DecodePcaHeader(header[0]);
            if (text is null)
                return (null, ("invalid_request", $"The {_options.HeaderName} header is not canonical base64url."));
            if (Encoding.UTF8.GetByteCount(text) > Pca.MaxArtifactBytes)
                return (null, ("invalid_request", $"The {_options.HeaderName} header is not a decodable PCActn: " + Pca.ArtifactSizeReason));
            try
            {
                return (Pca.ParseStrict(text), null);
            }
            catch (Exception ex)
            {
                return (null, ("invalid_request", $"The {_options.HeaderName} header is not a decodable PCActn: " + ex.Message));
            }
        }

        // Body mode: {"pcactn": <PCActn>}. Buffer so downstream can re-read the body.
        ctx.Request.EnableBuffering();
        string body;
        try
        {
            // STRICT UTF-8 (throws on invalid bytes), as the header path: Encoding.UTF8 silently replaced malformed sequences
            // with U+FFFD, so byte-distinct bodies decoded to the same text. Invalid UTF-8 => 401.
            using var reader = new StreamReader(ctx.Request.Body, StrictUtf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            body = await reader.ReadToEndAsync();
        }
        catch (DecoderFallbackException)
        {
            if (ctx.Request.Body.CanSeek) ctx.Request.Body.Position = 0;
            return (null, ("invalid_request", "The request body is not valid UTF-8."));
        }
        if (ctx.Request.Body.CanSeek) ctx.Request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
            return (null, ("invalid_request", $"No PCActn: set the {_options.HeaderName} header or POST a JSON body {{\"pcactn\":...}}."));

        object? envelope;
        try
        {
            // R6-01: the SAME strict profile as header mode (duplicate keys refused at any depth, depth-bounded BEFORE recursion so a
            // hostile body cannot overflow the stack). A lenient parse collapsed duplicate keys last-wins before verification, while
            // the rewound body still carried the first value for a first-wins downstream parser.
            envelope = Pca.ParseStrictEnvelope(body);
        }
        catch (Exception ex)
        {
            return (null, ("invalid_request", "The request body is not valid JSON: " + ex.Message));
        }
        if (envelope is not Dictionary<string, object?> env || !env.TryGetValue("pcactn", out var inner))
            return (null, ("invalid_request", "The request body must be a JSON object {\"pcactn\":...}."));
        return (inner, null);
    }

    /// <summary>The principal's escalation answer: header <c>PCA-Escalation-Answer</c> (strict unpadded base64url of the JSON), else the body
    /// member <c>escalation_answer</c>. Null when absent or unreadable (an unreadable answer is no answer).</summary>
    async Task<object?> ExtractEscalationAnswerAsync(HttpContext ctx)
    {
        try
        {
            var h = ctx.Request.Headers["PCA-Escalation-Answer"];
            if (h.Count > 0 && !string.IsNullOrEmpty(h[0]))
            {
                var text = Pca.DecodePcaHeader(h[0]);
                return text is null || Encoding.UTF8.GetByteCount(text) > Pca.MaxArtifactBytes ? null : Pca.ParseStrict(text);
            }
            if (!ctx.Request.Body.CanSeek) return null;
            ctx.Request.Body.Position = 0;
            using var reader = new StreamReader(ctx.Request.Body, StrictUtf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            ctx.Request.Body.Position = 0;
            return string.IsNullOrWhiteSpace(body) || Pca.ParseStrictEnvelope(body) is not Dictionary<string, object?> env
                ? null : env.TryGetValue("escalation_answer", out var a) ? a : null;
        }
        catch (Exception) { return null; }
    }

    /// <summary>The default workflow step: the JSON body member <c>workflow</c> {commitment, receipts, step, units, goal_digest}, read only when the PCActn
    /// itself came in the body (header mode reads no body). Null when there is no such member; a present but unreadable member is an empty call,
    /// which the gate denies.</summary>
    async Task<WorkflowCall?> ExtractWorkflowCallAsync(HttpContext ctx)
    {
        try
        {
            var h = ctx.Request.Headers[_options.HeaderName];
            if ((h.Count > 0 && !string.IsNullOrEmpty(h[0])) || !ctx.Request.Body.CanSeek) return null;
            ctx.Request.Body.Position = 0;
            using var reader = new StreamReader(ctx.Request.Body, StrictUtf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            ctx.Request.Body.Position = 0;
            if (string.IsNullOrWhiteSpace(body) || Pca.ParseStrictEnvelope(body) is not Dictionary<string, object?> env || !env.TryGetValue("workflow", out var w)) return null;
            if (w is not Dictionary<string, object?> m) return new WorkflowCall(null, null, null);
            return new WorkflowCall(m.GetValueOrDefault("commitment"), m.GetValueOrDefault("receipts"), m.GetValueOrDefault("step") as string,
                m.GetValueOrDefault("units"), m.GetValueOrDefault("goal_digest") as string);
        }
        catch (Exception) { return new WorkflowCall(null, null, null); }
    }

    /// <summary>The discharges and narrow block the request presents (headers <c>PCA-Discharges</c>, <c>PCA-Narrow</c>); unreadable
    /// headers present nothing.</summary>
    public static PresentedK1 PresentedFrom(HttpContext ctx) =>
        CaveatLang.PresentedK1Of(ctx.Request.Headers.Where(h => h.Value.Count > 0).Select(h => KeyValuePair.Create(h.Key, h.Value[0] ?? "")));

    static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Writes the challenge. The header carries only the operator's realm and the static error code; the description is NOT
    /// emitted there because it can carry request-derived text (the verdict reason, a JSON parse error), and TS
    /// <c>requirePCA</c> puts no reason in its challenge either. The description stays in the JSON body.
    /// </summary>
    async Task ChallengeAsync(HttpContext ctx, int status, string error, string description, AuthorizeResult? decided = null)
    {
        ctx.Response.StatusCode = status;
        if (status is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
            ctx.Response.Headers["WWW-Authenticate"] = $"PCA realm=\"{Escape(_options.Realm)}\", error=\"{error}\"";
        ctx.Response.ContentType = "application/json; charset=utf-8";
        var body = new Dictionary<string, object?> { ["error"] = error, ["error_description"] = description };
        if (decided != null)
        {
            body["decision"] = decided.Decision;
            // the request is a canonical JSON tree (numbers are Num): embed it as parsed JSON, not as a CLR object graph
            if (decided.Escalation != null) body["escalation"] = JsonDocument.Parse(Pca.Canonicalize(decided.Escalation)).RootElement;
        }
        var payload = JsonSerializer.Serialize(body);
        await ctx.Response.WriteAsync(payload);
    }

    /// <summary>Escape a value for an HTTP auth-param quoted-string (and strip CR/LF to keep the header single-line).</summary>
    static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", " ").Replace("\n", " ");
}
