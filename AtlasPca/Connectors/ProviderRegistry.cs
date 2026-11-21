using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Connectors;

/// <summary>The registry of provider manifests, by id.</summary>
public sealed class ProviderRegistry
{
    readonly Dictionary<string, D> byId = new(StringComparer.Ordinal);

    /// <summary>Validate and register a manifest; <c>expectedDigest</c> pins it, a duplicate id needs <c>replace: true</c>.</summary>
    public D Register(object? manifest, D? opts = null)
    {
        var valid = PcaConnectors.AssertManifest(manifest);
        var id = (string)valid["id"]!;
        if (opts != null && opts.TryGetValue("expectedDigest", out var ed) && ed != null && !(ed is string eds && PcaConnectors.ManifestDigest(valid) == eds))
            throw new ConnectorError($"manifest '{id}' does not match the pinned digest");
        if (byId.ContainsKey(id) && !(opts != null && opts.TryGetValue("replace", out var rp) && rp is true))
            throw new ConnectorError($"provider '{id}' is already registered; pass {{ replace: true }} to replace it deliberately");
        byId[id] = valid;
        return valid;
    }

    public D? Get(string providerId) => byId.GetValueOrDefault(providerId);

    public D Require(string providerId) => byId.TryGetValue(providerId, out var m) ? m : throw new UnknownProviderError(providerId);

    public bool Has(string providerId) => byId.ContainsKey(providerId);

    /// <summary>Every manifest, in id order (UTF-16 code units).</summary>
    public List<D> List() => byId.Values.OrderBy(m => (string)m["id"]!, StringComparer.Ordinal).ToList();

    public List<string> Ids() => List().Select(m => (string)m["id"]!).ToList();
}
