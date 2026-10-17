using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AtlasPca.AspNetCore;

/// <summary>
/// ASP.NET Core middleware for Proof-Carrying Authority. It reads a PCActn from the <c>PCA-Action</c> header
/// (base64url -&gt; JSON -&gt; strict decode) or from a JSON body <c>{"pcactn": ...}</c>, resolves the root grant,
/// and runs the existing offline verifier (<see cref="Pca.VerifyPcactnCore"/>: the eight checks, audience vs the
/// signed <c>aud</c>, and the capability chain rooted at the grant).
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
        Verdict verdict = Pca.VerifyPcactnCore(p, grant, _options.Clock(), _options.Audience, intentPolicy: _options.IntentPolicy, intentV2: intentV2);
        if (!verdict.Allow)
        {
            await ChallengeAsync(ctx, StatusCodes.Status403Forbidden, "access_denied", verdict.Reason);
            return;
        }

        ctx.Items["pca"] = new PcaAuthResult(verdict, p);
        await _next(ctx);
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

    static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Writes the challenge. The header carries only the operator's realm and the static error code; the description is NOT
    /// emitted there because it can carry request-derived text (the verdict reason, a JSON parse error), and TS
    /// <c>requirePCA</c> puts no reason in its challenge either. The description stays in the JSON body.
    /// </summary>
    async Task ChallengeAsync(HttpContext ctx, int status, string error, string description)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.Headers["WWW-Authenticate"] = $"PCA realm=\"{Escape(_options.Realm)}\", error=\"{error}\"";
        ctx.Response.ContentType = "application/json; charset=utf-8";
        var payload = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["error"] = error,
            ["error_description"] = description,
        });
        await ctx.Response.WriteAsync(payload);
    }

    /// <summary>Escape a value for an HTTP auth-param quoted-string (and strip CR/LF to keep the header single-line).</summary>
    static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", " ").Replace("\n", " ");
}
