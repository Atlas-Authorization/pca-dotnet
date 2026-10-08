using System;
using System.Collections.Generic;
using System.Threading.Tasks;

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

    public void Validate()
    {
        if (string.IsNullOrEmpty(Audience)) throw new InvalidOperationException("PcaOptions.Audience must be set.");
        if (GrantResolver is null) throw new InvalidOperationException("PcaOptions.GrantResolver must be set.");
        if (Clock is null) throw new InvalidOperationException("PcaOptions.Clock must be set.");
        if (string.IsNullOrEmpty(HeaderName)) throw new InvalidOperationException("PcaOptions.HeaderName must be set.");
    }
}

/// <summary>What the middleware stores at <c>HttpContext.Items["pca"]</c> on success: the allowing verdict and the verified PCActn.</summary>
public sealed record PcaAuthResult(Verdict Verdict, Dictionary<string, object?> Pcactn);
