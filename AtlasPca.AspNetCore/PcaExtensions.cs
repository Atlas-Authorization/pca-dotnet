using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AtlasPca.AspNetCore;

/// <summary>DI registration for PCA: <c>services.AddPca(o =&gt; { ... })</c>.</summary>
public static class PcaServiceCollectionExtensions
{
    public static IServiceCollection AddPca(this IServiceCollection services, Action<PcaOptions> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var options = new PcaOptions();
        configure(options);
        options.Validate();
        services.AddSingleton(options);
        return services;
    }
}

/// <summary>Pipeline registration for PCA: <c>app.UsePca()</c> (uses the DI-registered options) or <c>app.UsePca(o =&gt; { ... })</c>.</summary>
public static class PcaApplicationBuilderExtensions
{
    /// <summary>Add the middleware using <see cref="PcaOptions"/> resolved from DI (register it first with <see cref="PcaServiceCollectionExtensions.AddPca"/>).</summary>
    public static IApplicationBuilder UsePca(this IApplicationBuilder app)
        => app.UseMiddleware<PcaMiddleware>();

    /// <summary>Add the middleware with inline options.</summary>
    public static IApplicationBuilder UsePca(this IApplicationBuilder app, Action<PcaOptions> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var options = new PcaOptions();
        configure(options);
        options.Validate();
        return app.UseMiddleware<PcaMiddleware>(options);
    }

    /// <summary>Add the middleware with a prebuilt <see cref="PcaOptions"/>.</summary>
    public static IApplicationBuilder UsePca(this IApplicationBuilder app, PcaOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        options.Validate();
        return app.UseMiddleware<PcaMiddleware>(options);
    }
}
