using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AtlasPca.AspNetCore;

/// <summary>
/// <c>PcaProtect.Create</c>: the secure defaults for a resource server, in one call.
/// <code>
/// var p = PcaProtect.Create("ins_acme", grants, ctx =&gt; MyOperation(ctx));
/// app.UsePcaProtect(p);          // or: app.UsePca(p.Options)
/// p.Revoke(grantId);             // later: every action under that grant is refused
/// </code>
/// It fills in the parts every server otherwise wires by hand: the grant lookup (your own list or function, never the request), an
/// in-memory replay store, a revocation source and <c>Plan = "single-step"</c> (the grant alone limits what runs). Everything is still the
/// full <see cref="Pca.AuthorizeAsync"/> pipeline, bound to the operation your route executes and default-deny. Whatever you set in
/// <c>configure</c> wins over a default. Not done here: server-side risk from a connector catalog (this SDK has none); supply risk
/// inputs through <see cref="PcaAuthorizeOptions.Context"/> if a grant prices risk.
/// </summary>
public static class PcaProtect
{
    /// <summary>Protect with a fixed set of grants, looked up by their <c>id</c> (the <c>grant_ref</c> of a proof).</summary>
    public static Protected Create(string audience, IEnumerable<Dictionary<string, object?>> grants, Func<HttpContext, Task<Operation?>> operation,
        Action<PcaOptions>? configure = null, Func<Dictionary<string, object?>, bool>? isRevoked = null)
    {
        if (grants is null) throw new ArgumentNullException(nameof(grants));
        var byId = new Dictionary<string, Dictionary<string, object?>>(StringComparer.Ordinal);
        foreach (var g in grants) if (g.TryGetValue("id", out var id) && id is string s) byId[s] = g;
        return Create(audience, r => Task.FromResult<Dictionary<string, object?>?>(byId.TryGetValue(r, out var g) ? g : null), operation, configure, isRevoked);
    }

    /// <summary>Protect with your own grant lookup (from a store you control; a null result is an unknown grant).</summary>
    public static Protected Create(string audience, Func<string, Task<Dictionary<string, object?>?>> resolveGrant, Func<HttpContext, Task<Operation?>> operation,
        Action<PcaOptions>? configure = null, Func<Dictionary<string, object?>, bool>? isRevoked = null)
    {
        if (resolveGrant is null) throw new ArgumentNullException(nameof(resolveGrant));
        if (operation is null) throw new ArgumentNullException(nameof(operation));
        var revoked = new ConcurrentDictionary<string, bool>(StringComparer.Ordinal);
        var options = new PcaOptions
        {
            Audience = audience,
            GrantResolver = resolveGrant,
            Authorize = new PcaAuthorizeOptions
            {
                StateStore = new MemoryStateStore(),
                Plan = "single-step",
                Operation = operation,
                // only false passes: a grant without a string id counts as revoked
                IsRevoked = (_, grant) => !(grant.TryGetValue("id", out var id) && id is string s) || revoked.ContainsKey(s) || (isRevoked?.Invoke(grant) ?? false),
            },
        };
        configure?.Invoke(options);
        options.Validate();
        return new Protected(options, id => revoked[id] = true);
    }

    /// <summary>Add the middleware with the options of <see cref="Protected"/>.</summary>
    public static IApplicationBuilder UsePcaProtect(this IApplicationBuilder app, Protected protectedOptions)
        => app.UsePca(protectedOptions?.Options ?? throw new ArgumentNullException(nameof(protectedOptions)));
}

/// <summary>The result of <c>PcaProtect.Create</c>: the middleware options and the revoke handle.</summary>
public sealed class Protected
{
    readonly Action<string> _revoke;
    internal Protected(PcaOptions options, Action<string> revoke) { Options = options; _revoke = revoke; }

    /// <summary>Pass to <c>app.UsePca(...)</c> (or use <c>app.UsePcaProtect(p)</c>).</summary>
    public PcaOptions Options { get; }

    /// <summary>Refuse every further action under this grant id.</summary>
    public void Revoke(string grantId) => _revoke(grantId);
}
