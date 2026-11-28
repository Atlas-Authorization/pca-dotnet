using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AtlasPca.AspNetCore;

/// <summary>
/// The request/response form of the PCA guard: a <see cref="DelegatingHandler"/> that verifies the inbound PCActn on an
/// <see cref="HttpRequestMessage"/> before the inner handler runs (an in-process server pipeline, a Functions-style host, a test host).
/// It runs the same <see cref="PcaMiddleware"/> checks over a request context built from the message; on success the inner handler
/// runs and the verdict is on <c>request.Options</c> under <see cref="ResultKey"/>; otherwise a 401/403 response with a
/// <c>WWW-Authenticate</c> challenge and the body <c>{error, verdict, decision}</c> (plus <c>escalation</c>) is returned and the inner handler never runs.
/// Without <see cref="PcaAuthorizeOptions.Operation"/> the request is not bound to an operation, which must be opted into with
/// <see cref="PcaOptions.SignatureOnly"/> (construction throws otherwise).
/// </summary>
public sealed class PcaFetchHandler : DelegatingHandler
{
    /// <summary>Where the handler leaves the <see cref="PcaAuthResult"/> of a request it let through.</summary>
    public static readonly HttpRequestOptionsKey<PcaAuthResult> ResultKey = new("pca");

    readonly PcaOptions _options;

    public PcaFetchHandler(PcaOptions options, HttpMessageHandler inner) : base(inner ?? throw new ArgumentNullException(nameof(inner)))
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        if (!_options.SignatureOnly && _options.Authorize?.Operation == null)
            throw new InvalidOperationException("PcaFetchHandler: Authorize.Operation is required: map each request to the operation it will execute so the proof is bound to it, or set SignatureOnly only to migrate.");
        if (_options.Executor != null) throw new InvalidOperationException("PcaFetchHandler: Executor needs the response pipeline; use app.UsePca or the MVC [RequirePca] filter.");
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = request.Method.Method;
        var uri = request.RequestUri;
        if (uri is { IsAbsoluteUri: true })
        {
            ctx.Request.Scheme = uri.Scheme;
            ctx.Request.Host = new HostString(uri.Authority);
            ctx.Request.Path = new PathString(uri.AbsolutePath);
            ctx.Request.QueryString = new QueryString(uri.Query);
        }
        foreach (var h in request.Headers) ctx.Request.Headers[h.Key] = string.Join(",", h.Value);
        if (request.Content != null)
        {
            foreach (var h in request.Content.Headers) ctx.Request.Headers[h.Key] = string.Join(",", h.Value);
            ctx.Request.Body = new MemoryStream(await request.Content.ReadAsByteArrayAsync(cancellationToken));
        }
        else ctx.Request.Body = new MemoryStream();
        var written = new MemoryStream();
        ctx.Response.Body = written;
        ctx.RequestAborted = cancellationToken;

        var passed = false;
        await new PcaMiddleware(_ => { passed = true; return Task.CompletedTask; }, _options).InvokeAsync(ctx);
        if (passed)
        {
            if (ctx.Items.TryGetValue("pca", out var r) && r is PcaAuthResult pr) request.Options.Set(ResultKey, pr);
            return await base.SendAsync(request, cancellationToken);
        }
        return Deny(ctx, written, request);
    }

    // the challenge the gate wrote, in the reference body shape {error, verdict, decision, escalation?}
    static HttpResponseMessage Deny(HttpContext ctx, MemoryStream written, HttpRequestMessage request)
    {
        JsonObject? src = null;
        try { src = JsonNode.Parse(Encoding.UTF8.GetString(written.ToArray())) as JsonObject; } catch (System.Text.Json.JsonException) { }
        var code = src?["error"]?.GetValue<string>() ?? "forbidden";
        var reason = src?["error_description"]?.GetValue<string>() ?? code;
        var body = new JsonObject
        {
            ["error"] = reason,
            ["verdict"] = new JsonObject { ["allow"] = false, ["reason"] = reason, ["reasons"] = new JsonArray(JsonValue.Create(reason)), ["code"] = code },
            ["decision"] = src?["decision"]?.DeepClone() ?? JsonValue.Create("deny"),
        };
        if (src?["escalation"] is { } esc) body["escalation"] = esc.DeepClone();
        var status = ctx.Response.StatusCode is >= 400 and < 600 ? ctx.Response.StatusCode : 403;
        var res = new HttpResponseMessage((HttpStatusCode)status) { RequestMessage = request, Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body.ToJsonString())) };
        res.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        if (ctx.Response.Headers.TryGetValue("WWW-Authenticate", out var www) && www.Count > 0)
            res.Headers.TryAddWithoutValidation("WWW-Authenticate", (string?)www[0]);
        return res;
    }
}
