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

        Dictionary<string, object?>? grant = await _options.GrantResolver(grantRef);
        if (grant is null)
        {
            await ChallengeAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_grant", "No grant is known for this grant_ref.");
            return;
        }

        // The existing verifier: 8 offline checks, audience vs signed aud, chain rooted at the resolved grant.
        Verdict verdict = Pca.VerifyPcactnCore(p, grant, _options.Clock(), _options.Audience);
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
            byte[]? bytes = Pca.B64uDecode(header[0]);
            if (bytes is null)
                return (null, ("invalid_request", $"The {_options.HeaderName} header is not canonical base64url."));
            try
            {
                return (Pca.ParseStrict(Encoding.UTF8.GetString(bytes)), null);
            }
            catch (Exception ex)
            {
                return (null, ("invalid_request", $"The {_options.HeaderName} header is not a decodable PCActn: " + ex.Message));
            }
        }

        // Body mode: {"pcactn": <PCActn>}. Buffer so downstream can re-read the body.
        ctx.Request.EnableBuffering();
        string body;
        using (var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
        {
            body = await reader.ReadToEndAsync();
        }
        if (ctx.Request.Body.CanSeek) ctx.Request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
            return (null, ("invalid_request", $"No PCActn: set the {_options.HeaderName} header or POST a JSON body {{\"pcactn\":...}}."));

        object? envelope;
        try
        {
            envelope = Pca.ParseJson(body); // transport envelope: lenient parse; the PCActn itself is strictly re-checked by the verifier.
        }
        catch (Exception ex)
        {
            return (null, ("invalid_request", "The request body is not valid JSON: " + ex.Message));
        }
        if (envelope is not Dictionary<string, object?> env || !env.TryGetValue("pcactn", out var inner))
            return (null, ("invalid_request", "The request body must be a JSON object {\"pcactn\":...}."));
        return (inner, null);
    }

    async Task ChallengeAsync(HttpContext ctx, int status, string error, string description)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.Headers["WWW-Authenticate"] =
            $"PCA realm=\"{Escape(_options.Realm)}\", error=\"{error}\", error_description=\"{Escape(description)}\"";
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
