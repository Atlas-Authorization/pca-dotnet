using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace AtlasPca.AspNetCore;

/// <summary>
/// Per-endpoint PCA for minimal APIs: <c>app.MapPost("/pay", handler).RequirePca(options)</c> (or <c>.RequirePca()</c> with the options
/// registered by <c>services.AddPca</c>). It runs the same <see cref="PcaMiddleware"/> checks for that endpoint only: on success
/// <c>HttpContext.Items["pca"]</c> holds the <see cref="PcaAuthResult"/> and the handler runs; on failure the 401/403 challenge is written
/// and the handler never runs. <see cref="PcaOptions.Executor"/> is refused here: a minimal-API result is written after the filter returns,
/// so the executor could not record it; use <c>app.UsePca</c> or <see cref="RequirePcaAttribute"/> (MVC) for run-once execution.
/// </summary>
public sealed class PcaEndpointFilter : IEndpointFilter
{
    readonly PcaMiddleware _gate;
    readonly PcaOptions _options;

    public PcaEndpointFilter(PcaOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (options.Executor != null) throw new InvalidOperationException("PcaEndpointFilter: Executor needs the response pipeline; use app.UsePca or the MVC [RequirePca] filter.");
        // the gate's next only marks the pass: the handler runs after it, in the filter chain
        _gate = new PcaMiddleware(ctx => { ctx.Items[Passed] = true; return Task.CompletedTask; }, options);
    }

    internal static readonly object Passed = new();

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        http.Items.Remove(Passed);
        await _gate.InvokeAsync(http);
        if (!(http.Items.TryGetValue(Passed, out var ok) && ok is true)) return Results.Empty; // the challenge is already written
        http.Items.Remove(Passed);
        return await next(context);
    }
}

/// <summary>Registration of <see cref="PcaEndpointFilter"/> on a minimal-API endpoint or group.</summary>
public static class PcaEndpointConventionExtensions
{
    /// <summary>Require a verified PCActn on this endpoint (or every endpoint of a group), with these options.</summary>
    public static TBuilder RequirePca<TBuilder>(this TBuilder builder, PcaOptions options) where TBuilder : IEndpointConventionBuilder
    {
        var filter = new PcaEndpointFilter(options ?? throw new ArgumentNullException(nameof(options)));
        builder.Add(eb => eb.FilterFactories.Add((_, next) => ctx => filter.InvokeAsync(ctx, next)));
        return builder;
    }

    /// <summary>Require a verified PCActn, with the options registered by <c>services.AddPca</c>.</summary>
    public static TBuilder RequirePca<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
    {
        PcaEndpointFilter? filter = null;
        var gate = new object();
        builder.Add(eb => eb.FilterFactories.Add((fc, next) =>
        {
            lock (gate) filter ??= new PcaEndpointFilter(fc.ApplicationServices.GetRequiredService<PcaOptions>());
            var f = filter;
            return ctx => f.InvokeAsync(ctx, next);
        }));
        return builder;
    }
}

/// <summary>
/// PCA for MVC controllers and actions: <c>[RequirePca]</c> uses the options registered by <c>services.AddPca</c>. It runs as a resource
/// filter, before model binding reads the body, with the same checks as <see cref="PcaMiddleware"/>: on failure the challenge is written and
/// the action never runs; on success the rest of the pipeline (binding, action, result) runs inside the gate, so
/// <see cref="PcaOptions.Executor"/> records and replays the action's response exactly as the middleware does.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequirePcaAttribute : Attribute, IFilterFactory
{
    public bool IsReusable => true;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider) => new PcaResourceFilter(serviceProvider.GetRequiredService<PcaOptions>());
}

/// <summary>The MVC resource filter behind <see cref="RequirePcaAttribute"/>; add it directly (<c>options.Filters.Add(new PcaResourceFilter(o))</c>) for global use.</summary>
public sealed class PcaResourceFilter : IAsyncResourceFilter
{
    readonly PcaOptions _options;

    public PcaResourceFilter(PcaOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
    }

    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        var ran = false;
        var gate = new PcaMiddleware(async _ => { ran = true; await next(); }, _options);
        await gate.InvokeAsync(context.HttpContext);
        if (!ran) context.Result = new EmptyResult(); // denied: the challenge is already written; short-circuit the action
    }
}
