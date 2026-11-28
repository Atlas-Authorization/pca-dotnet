using System.Text.RegularExpressions;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connectors;

/// <summary>A connector failure (the reference's <c>ConnectorError</c>).</summary>
public class ConnectorError : Exception
{
    public ConnectorError(string message) : base(message) { }
}

/// <summary>A provider manifest that failed validation; <see cref="Issues"/> lists every problem.</summary>
public sealed class ManifestValidationError : ConnectorError
{
    public IReadOnlyList<string> Issues { get; }
    public ManifestValidationError(IReadOnlyList<string> issues) : base("invalid provider manifest: " + string.Join("; ", issues)) { Issues = issues; }
}

/// <summary>No connector is registered for the provider id.</summary>
public sealed class UnknownProviderError : ConnectorError
{
    public string ProviderId { get; }
    public UnknownProviderError(string providerId) : base($"no connector registered for provider '{providerId}'") { ProviderId = providerId; }
}

/// <summary>A declarative catalog of outbound OAuth connectors for the token vault: manifest validation and digests, the provider
/// registry, the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and refresh into the
/// vault, and the manifest-to-vault-provider mapping. Manifests and option bags are parsed JSON trees with the reference's member names.</summary>
public static partial class PcaConnectors
{
    public static readonly IReadOnlySet<string> ReservedAuthorizeParams = new HashSet<string> { "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method" };
    public static readonly IReadOnlySet<string> ReservedTokenParams = new HashSet<string> { "grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token" };

    static readonly string[] TokenPlacements = { "bearer", "header", "query" };
    static readonly string[] RefreshModes = { "refresh_token", "none" };
    static readonly string[] ClientAuths = { "post", "basic" };
    static readonly HashSet<string> ForbiddenHeaders = new() { "host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie" };

    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static readonly Regex IdPattern = new(@"\A[a-z0-9][a-z0-9._-]*\z", Ro);
    static readonly Regex HeaderName = new(@"\A[A-Za-z0-9][A-Za-z0-9-]*\z", Ro);
    static readonly Regex QueryName = new(@"\A[A-Za-z_][A-Za-z0-9_.-]*\z", Ro);
    static readonly Regex Var = new(@"\{([A-Za-z0-9_]+)\}", Ro);
    static readonly Regex VarHost = new(@"\A\{[A-Za-z0-9_]+\}(:[0-9]+)?\z", Ro);

    static object? Own(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : Undef;
    static bool NonEmpty(object? v) => v is string s && s.Length > 0;
    static bool StrArray(object? v) => v is L l && l.All(x => x is string);
    static bool StrRecord(object? v) => v is D m && m.Values.All(x => x is string);
    static bool IsSep(char c) => JsJson.IsJsSpace(c) || c == ',';

    static bool IsHttpsUrl(object? v)
    {
        if (v is not string s || !s.StartsWith("https://", StringComparison.Ordinal)) return false;
        var x = Var.Replace(s, "x");
        var u = AtlasPca.Jose.WhatwgUrl.TryParse(x);
        if (u == null || u.Protocol != "https:" || AtlasPca.Connect.ConnectJs.HasCredentials(x) || AtlasPca.Connect.ConnectJs.HasFragment(x)) return false;
        var rest = s["https://".Length..];
        var cut = rest.IndexOfAny(new[] { '/', '?', '#' });
        return !VarHost.IsMatch(cut < 0 ? rest : rest[..cut]);
    }

    static List<string> UrlVars(string url) => Var.Matches(url).Select(m => m.Groups[1].Value).ToList();

    static string OneOf(IEnumerable<string> items) => string.Join(" | ", items);

    static D Fail(List<string> issues) => new() { ["ok"] = false, ["issues"] = issues.Cast<object?>().ToList() };

    /// <summary><c>{ok: true, manifest}</c> or <c>{ok: false, issues}</c>: every problem of a provider manifest, no partial acceptance.</summary>
    public static D ValidateManifest(object? inp)
    {
        var issues = new List<string>();
        if (inp is not D) return Fail(new List<string> { "manifest must be an object" });
        var mid = Own(inp, "id");
        if (!NonEmpty(mid)) issues.Add("id must be a non-empty string");
        else if (!IdPattern.IsMatch((string)mid!)) issues.Add($"id '{mid}' must be lowercase and match ^[a-z0-9][a-z0-9._-]*$");
        if (!NonEmpty(Own(inp, "displayName"))) issues.Add("displayName must be a non-empty string");
        var authorizeUrl = Own(inp, "authorizeUrl");
        if (!IsHttpsUrl(authorizeUrl)) issues.Add("authorizeUrl must be an https:// URL");
        var tokenUrl = Own(inp, "tokenUrl");
        if (!IsHttpsUrl(tokenUrl)) issues.Add("tokenUrl must be an https:// URL");
        var scopesAvailable = Own(inp, "scopesAvailable");
        if (!StrArray(scopesAvailable)) issues.Add("scopesAvailable must be an array of strings");
        var defaultScopes = Own(inp, "defaultScopes");
        if (!StrArray(defaultScopes)) issues.Add("defaultScopes must be an array of strings");
        foreach (var (name, lst) in new (string, object?)[] { ("scopesAvailable", scopesAvailable), ("defaultScopes", defaultScopes) })
        {
            if (!StrArray(lst)) continue;
            var l = ((L)lst!).Select(x => (string)x!).ToList();
            if (l.Any(s => s.Length == 0 || s.Any(IsSep)))
                issues.Add(name + " entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)");
            if (l.Distinct(StringComparer.Ordinal).Count() != l.Count) issues.Add(name + " must not contain duplicates");
        }
        if (StrArray(scopesAvailable) && StrArray(defaultScopes) && ((L)scopesAvailable!).Count > 0)
        {
            var avail = ((L)scopesAvailable).Select(x => (string)x!).ToHashSet(StringComparer.Ordinal);
            var missing = ((L)defaultScopes!).Select(x => (string)x!).Where(s => !avail.Contains(s)).ToList();
            if (missing.Count > 0) issues.Add("defaultScopes must be a subset of scopesAvailable (unknown: " + string.Join(", ", missing) + ")");
        }
        var refresh = Own(inp, "refresh");
        if (refresh is not D) issues.Add("refresh must be an object");
        else
        {
            if (!(Own(refresh, "mode") is string mode && RefreshModes.Contains(mode))) issues.Add("refresh.mode must be one of " + OneOf(RefreshModes));
            var te = Own(refresh, "tokenEndpoint");
            if (!ReferenceEquals(te, Undef) && !IsHttpsUrl(te)) issues.Add("refresh.tokenEndpoint, when present, must be an https:// URL");
            var sn = Own(refresh, "supportsScopeNarrowing");
            if (!ReferenceEquals(sn, Undef) && sn is not bool) issues.Add("refresh.supportsScopeNarrowing must be a boolean");
            var ep = Own(refresh, "extraParams");
            if (!ReferenceEquals(ep, Undef) && !StrRecord(ep)) issues.Add("refresh.extraParams must be a string→string map");
            else if (StrRecord(ep))
                foreach (var k in ((D)ep!).Keys)
                    if (ReservedTokenParams.Contains(k)) issues.Add($"refresh.extraParams may not set '{k}': the request builder owns it");
        }
        var placement = Own(inp, "tokenPlacement");
        if (!(placement is string pl && TokenPlacements.Contains(pl))) issues.Add("tokenPlacement must be one of " + OneOf(TokenPlacements));
        else if (pl == "header" && !NonEmpty(Own(inp, "headerName"))) issues.Add("tokenPlacement 'header' requires a non-empty headerName");
        else if (pl == "query" && !NonEmpty(Own(inp, "queryParam"))) issues.Add("tokenPlacement 'query' requires a non-empty queryParam");
        if (Own(inp, "headerName") is string hn && (!HeaderName.IsMatch(hn) || ForbiddenHeaders.Contains(hn.ToLowerInvariant())))
            issues.Add($"headerName '{hn}' must be an HTTP token and not a protocol header");
        if (Own(inp, "queryParam") is string qp && !QueryName.IsMatch(qp)) issues.Add($"queryParam '{qp}' must be a plain parameter name");
        if (Own(inp, "scopeSeparator") is string sepRaw && sepRaw.Length == 0) issues.Add("scopeSeparator must not be empty");
        var pkce = Own(inp, "pkce");
        if (!ReferenceEquals(pkce, Undef) && pkce is not bool) issues.Add("pkce must be a boolean");
        var scopeSep = Own(inp, "scopeSeparator");
        if (!ReferenceEquals(scopeSep, Undef) && scopeSep is not string) issues.Add("scopeSeparator must be a string");
        var authParams = Own(inp, "authParams");
        if (!ReferenceEquals(authParams, Undef) && !StrRecord(authParams)) issues.Add("authParams must be a string→string map");
        else if (StrRecord(authParams))
            foreach (var k in ((D)authParams!).Keys)
                if (ReservedAuthorizeParams.Contains(k)) issues.Add($"authParams may not set '{k}': the request builder owns it");
        var clientAuth = Own(inp, "clientAuth");
        if (!ReferenceEquals(clientAuth, Undef) && !(clientAuth is string ca && ClientAuths.Contains(ca))) issues.Add("clientAuth must be one of " + OneOf(ClientAuths));
        var requiredVars = Own(inp, "requiredVars");
        if (!ReferenceEquals(requiredVars, Undef) && !StrArray(requiredVars)) issues.Add("requiredVars must be an array of strings");
        if (IsHttpsUrl(authorizeUrl) && IsHttpsUrl(tokenUrl))
        {
            var declared = (StrArray(requiredVars) ? ((L)requiredVars!).Select(x => (string)x!) : Enumerable.Empty<string>()).Distinct(StringComparer.Ordinal).ToList();
            var used = UrlVars((string)authorizeUrl!).Concat(UrlVars((string)tokenUrl!)).Distinct(StringComparer.Ordinal).ToList();
            foreach (var v in used)
                if (!declared.Contains(v)) issues.Add("url uses '{" + v + "}' but requiredVars does not declare it");
            foreach (var v in declared)
                if (!used.Contains(v)) issues.Add("requiredVars declares '" + v + "' but no URL uses '{" + v + "}'");
        }
        var docsUrl = Own(inp, "docsUrl");
        if (!ReferenceEquals(docsUrl, Undef) && docsUrl is not string) issues.Add("docsUrl must be a string");
        if (issues.Count > 0) return Fail(issues);
        return new D { ["ok"] = true, ["manifest"] = FreezeManifest((D)inp) };
    }

    static List<object?> Strs(object? v) => StrArray(v) ? ((L)v!).ToList() : new L();

    static D FreezeManifest(D inp)
    {
        var rr = Own(inp, "refresh") as D ?? new D();
        var refresh = new D { ["mode"] = Own(rr, "mode") is string rm && rm == "none" ? "none" : "refresh_token" };
        if (Own(rr, "tokenEndpoint") is string te) refresh["tokenEndpoint"] = te;
        if (Own(rr, "supportsScopeNarrowing") is bool sn) refresh["supportsScopeNarrowing"] = sn;
        var ep = Own(rr, "extraParams");
        if (StrRecord(ep)) refresh["extraParams"] = new D((D)ep!);
        var tp = Own(inp, "tokenPlacement");
        var m = new D
        {
            ["id"] = Own(inp, "id") is string id ? id : "",
            ["displayName"] = Own(inp, "displayName") is string dn ? dn : "",
            ["authorizeUrl"] = Own(inp, "authorizeUrl") is string au ? au : "",
            ["tokenUrl"] = Own(inp, "tokenUrl") is string tu ? tu : "",
            ["scopesAvailable"] = Strs(Own(inp, "scopesAvailable")),
            ["defaultScopes"] = Strs(Own(inp, "defaultScopes")),
            ["refresh"] = refresh,
            ["tokenPlacement"] = tp is string t && t == "header" ? "header" : tp is string t2 && t2 == "query" ? "query" : "bearer",
        };
        if (Own(inp, "pkce") is bool pkce) m["pkce"] = pkce;
        if (Own(inp, "scopeSeparator") is string sep) m["scopeSeparator"] = sep;
        var ap = Own(inp, "authParams");
        if (StrRecord(ap)) m["authParams"] = new D((D)ap!);
        if (Own(inp, "clientAuth") is string ca && (ca == "post" || ca == "basic")) m["clientAuth"] = ca;
        if (Own(inp, "headerName") is string hn) m["headerName"] = hn;
        if (Own(inp, "queryParam") is string qp) m["queryParam"] = qp;
        var rv = Own(inp, "requiredVars");
        if (StrArray(rv)) m["requiredVars"] = ((L)rv!).ToList();
        if (Own(inp, "docsUrl") is string du) m["docsUrl"] = du;
        return m;
    }

    /// <summary>The validated manifest, or a <see cref="ManifestValidationError"/> listing every issue.</summary>
    public static D AssertManifest(object? inp)
    {
        var r = ValidateManifest(inp);
        if (r["ok"] is not true) throw new ManifestValidationError(((L)r["issues"]!).Select(x => (string)x!).ToList());
        return (D)r["manifest"]!;
    }

    /// <summary>The content address of a validated manifest: a pinned digest detects a swapped endpoint.</summary>
    public static string ManifestDigest(object? manifest) => Pca.HashCanonical(manifest);

    // ---- registry ----
    public static ProviderRegistry CreateDefaultRegistry()
    {
        var r = new ProviderRegistry();
        foreach (var m in ConnectorProviders.BuiltinManifests()) r.Register(m);
        return r;
    }

    /// <summary>The process-wide default registry (the built-in catalog plus whatever <see cref="RegisterProvider"/> adds).</summary>
    public static ProviderRegistry DefaultRegistry { get; } = CreateDefaultRegistry();

    public static D RegisterProvider(object? manifest, D? opts = null) => DefaultRegistry.Register(manifest, opts);

    /// <summary>One digest over the whole catalog (id and manifest digest, in id order).</summary>
    public static string CatalogDigest(ProviderRegistry? registry = null) =>
        Pca.HashCanonical((registry ?? DefaultRegistry).List().Select(m => (object?)new L { m["id"], ManifestDigest(m) }).ToList());

    public static D? GetProvider(string providerId) => DefaultRegistry.Get(providerId);

    public static List<D> ListProviders() => DefaultRegistry.List();
}
