using System.Globalization;
using System.Text;
using AtlasPca.Connect;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connectors;

/// <summary>Where an exchanged or refreshed connection is stored: the vault, the agent and (optionally) the connection id, bound to the
/// principal whose capability may later use it.</summary>
public sealed class ConnectBinding
{
    public required TokenVault Vault { get; init; }
    public required string AgentId { get; init; }
    public string? ConnectionId { get; init; }
    public required string Principal { get; init; }
    /// <summary>The scopes the authority covers; null: the requested scopes.</summary>
    public List<string>? Scopes { get; init; }
    public string? Audience { get; init; }
}

public static partial class PcaConnectors
{
    const double DefaultTokenLifetimeMs = 3_600_000;

    sealed class TokenResponse
    {
        public string AccessToken = "";
        public double? ExpiresInSecs;
        public string? RefreshToken;
        public List<string>? Scopes;
    }

    static void CheckExtraParams(object? extra, string what)
    {
        foreach (var (k, _) in Entries(extra))
            if (ReservedTokenParams.Contains(k)) throw new ConnectorError($"{what}: extraParams may not set '{k}'");
    }

    /// <summary><c>s.split(/[\s,]+/)</c>: leading and trailing separators leave empty pieces.</summary>
    static List<string> SplitSeparators(string s)
    {
        var o = new List<string>();
        int start = 0, i = 0;
        while (i < s.Length)
        {
            if (IsSep(s[i]))
            {
                int j = i;
                while (j < s.Length && IsSep(s[j])) j++;
                o.Add(s[start..i]);
                start = j; i = j;
            }
            else i++;
        }
        o.Add(s[start..]);
        return o;
    }

    static TokenResponse ParseTokenResponse(object? body, string provider)
    {
        if (body is not D m) throw new ConnectorError($"[{provider}] token endpoint returned a non-object body");
        if (!(m.GetValueOrDefault("access_token") is string at && at.Length > 0)) throw new ConnectorError($"[{provider}] token endpoint response has no access_token");
        var o = new TokenResponse { AccessToken = at };
        var ex = m.GetValueOrDefault("expires_in");
        if (ex is Num && IntentJs.NumOf(ex) is double e && double.IsFinite(e) && e > 0) o.ExpiresInSecs = e;
        if (m.GetValueOrDefault("refresh_token") is string rt && rt.Length > 0) o.RefreshToken = rt;
        if (m.GetValueOrDefault("scope") is string sc && JsTrim(sc).Length > 0) o.Scopes = SplitSeparators(JsTrim(sc));
        return o;
    }

    static TokenResponse PostToken(D manifest, string tokenEndpoint, D parameters, string? clientSecret, VaultFetch? fetch)
    {
        var id = (string)manifest["id"]!;
        var headers = new Dictionary<string, string> { ["content-type"] = "application/x-www-form-urlencoded", ["accept"] = "application/json" };
        var body = new D(parameters);
        if (manifest.GetValueOrDefault("clientAuth") is "basic")
        {
            if (clientSecret == null) throw new ConnectorError($"[{id}] clientAuth 'basic' requires a clientSecret");
            var cid = body.GetValueOrDefault("client_id");
            if (cid == null || ReferenceEquals(cid, Undef)) throw new ConnectorError($"[{id}] missing client_id for basic auth");
            headers["authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(Str(cid) + ":" + clientSecret));
            body.Remove("client_id");
            body.Remove("client_secret");
        }
        var secs = new List<string?>
        {
            clientSecret, parameters.GetValueOrDefault("code") as string, parameters.GetValueOrDefault("code_verifier") as string,
            parameters.GetValueOrDefault("refresh_token") as string, headers.GetValueOrDefault("authorization"),
        };
        IVaultHttpResponse res;
        try
        {
            if (fetch == null) throw new InvalidOperationException("fetchImpl is not a function");
            res = fetch(tokenEndpoint, new VaultHttpRequest("POST", headers, EncodeForm(body)));
        }
        catch (Exception e)
        {
            throw new ConnectorError($"[{id}] token transport error: " + ConnectJs.Redact(e.Message, secs));
        }
        if (!res.Ok)
        {
            string detail;
            try
            {
                var t = res.Text();
                detail = ConnectJs.Redact(t.Length > 256 ? t[..256] : t, secs);
            }
            catch (Exception) { detail = "<unreadable body>"; }
            throw new ConnectorError($"[{id}] token endpoint {res.Status.ToString(CultureInfo.InvariantCulture)}: {detail}");
        }
        object? json;
        try { json = res.Json(); }
        catch (Exception) { throw new ConnectorError($"[{id}] unparseable token JSON"); }
        return ParseTokenResponse(json, id);
    }

    static double NowOf(D args, Func<long>? clock)
    {
        var n = args.GetValueOrDefault("now");
        return n == null ? (clock != null ? clock() : AtlasPca.ReplayClock.NowMs()) : IntentJs.NumOf(n) ?? throw TypeError("now is not a number");
    }

    static StoredConnection StoreConnection(D manifest, TokenResponse parsed, List<string> requested, ConnectBinding bind, double now, string? priorRefreshToken = null)
    {
        var expiresAt = parsed.ExpiresInSecs is double s ? now + s * 1000 : now + DefaultTokenLifetimeMs;
        var granted = parsed.Scopes ?? requested;
        return bind.Vault.PutConnection(new PutConnectionArgs
        {
            AgentId = bind.AgentId,
            Provider = (string)manifest["id"]!,
            ConnectionId = bind.ConnectionId,
            AccessToken = parsed.AccessToken,
            ExpiresAt = expiresAt,
            Scopes = granted,
            Principal = bind.Principal,
            AuthorityScopes = bind.Scopes ?? requested,
            Audience = bind.Audience,
            RefreshToken = parsed.RefreshToken ?? priorRefreshToken,
        });
    }

    static List<string> Requested(D args, D manifest) =>
        ((L)(args.GetValueOrDefault("scopes") ?? manifest["defaultScopes"])!).Select(x => (string)x!).ToList();

    /// <summary>Exchange an authorization code for tokens at the provider's token endpoint and store the connection in the vault.
    /// <paramref name="args"/>: providerId, clientId, clientSecret?, code, redirectUri, codeVerifier?, scopes?, now?, vars?, extraParams?.</summary>
    public static StoredConnection ExchangeCode(D args, ConnectBinding bind, VaultFetch? fetch, ProviderRegistry? registry = null, Func<long>? clock = null)
    {
        var manifest = (registry ?? DefaultRegistry).Require((string)args["providerId"]!);
        var id = (string)manifest["id"]!;
        var now = NowOf(args, clock);
        var requested = Requested(args, manifest);
        if (!(args.GetValueOrDefault("code") is string code && code.Length > 0)) throw new ConnectorError($"[{id}] an authorization code is required");
        CheckExtraParams(args.GetValueOrDefault("extraParams"), $"[{id}] exchangeCode");
        if (manifest.GetValueOrDefault("pkce") is true && !args.ContainsKey("codeVerifier"))
            throw new ConnectorError($"[{id}] provider uses PKCE; a codeVerifier is required to exchange the code");
        var ps = new D
        {
            ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = args.TryGetValue("redirectUri", out var ru) ? ru : Undef,
            ["client_id"] = args.TryGetValue("clientId", out var ci) ? ci : Undef,
        };
        if (args.TryGetValue("clientSecret", out var cs)) ps["client_secret"] = cs;
        if (args.TryGetValue("codeVerifier", out var cv)) ps["code_verifier"] = cv;
        foreach (var (k, v) in Entries(args.GetValueOrDefault("extraParams"))) ps[k] = v;
        var endpoint = SubstituteVars((string)manifest["tokenUrl"]!, args.TryGetValue("vars", out var vr) ? vr : Undef);
        var parsed = PostToken(manifest, endpoint, ps, args.GetValueOrDefault("clientSecret") as string, fetch);
        return StoreConnection(manifest, parsed, requested, bind, now);
    }

    /// <summary>Refresh a connection's tokens at the provider and store the result in the vault (the refresh token is kept unless the provider
    /// rotates it). <paramref name="args"/> as for <see cref="ExchangeCode"/>, with refreshToken in place of code, redirectUri and codeVerifier.</summary>
    public static StoredConnection Refresh(D args, ConnectBinding bind, VaultFetch? fetch, ProviderRegistry? registry = null, Func<long>? clock = null)
    {
        var manifest = (registry ?? DefaultRegistry).Require((string)args["providerId"]!);
        var id = (string)manifest["id"]!;
        var refreshCfg = (D)manifest["refresh"]!;
        if ((string)refreshCfg["mode"]! == "none") throw new ConnectorError($"[{id}] provider does not support token refresh");
        var now = NowOf(args, clock);
        var requested = Requested(args, manifest);
        if (!(args.GetValueOrDefault("refreshToken") is string rt && rt.Length > 0)) throw new ConnectorError($"[{id}] a refresh token is required");
        CheckExtraParams(args.GetValueOrDefault("extraParams"), $"[{id}] refresh");
        var ps = new D { ["grant_type"] = "refresh_token", ["refresh_token"] = rt, ["client_id"] = args.TryGetValue("clientId", out var ci) ? ci : Undef };
        if (args.TryGetValue("clientSecret", out var cs)) ps["client_secret"] = cs;
        foreach (var (k, v) in Entries(refreshCfg.GetValueOrDefault("extraParams"))) ps[k] = v;
        foreach (var (k, v) in Entries(args.GetValueOrDefault("extraParams"))) ps[k] = v;
        if (refreshCfg.GetValueOrDefault("supportsScopeNarrowing") is true && requested.Count > 0) ps["scope"] = string.Join(Separator(manifest), requested);
        var endpoint = SubstituteVars((string)(refreshCfg.GetValueOrDefault("tokenEndpoint") ?? manifest["tokenUrl"])!, args.TryGetValue("vars", out var vr) ? vr : Undef);
        var parsed = PostToken(manifest, endpoint, ps, args.GetValueOrDefault("clientSecret") as string, fetch);
        return StoreConnection(manifest, parsed, requested, bind, now, rt);
    }

    /// <summary>The vault's token-endpoint configuration for a refreshable manifest (<paramref name="creds"/>: clientId, clientSecret?, vars?).</summary>
    public static ProviderConfig ManifestToProviderConfig(D manifest, D creds)
    {
        var id = (string)manifest["id"]!;
        var refresh = (D)manifest["refresh"]!;
        if ((string)refresh["mode"]! == "none") throw new ConnectorError($"[{id}] provider does not support token refresh; no ProviderConfig");
        var cfg = new ProviderConfig
        {
            TokenEndpoint = SubstituteVars((string)(refresh.GetValueOrDefault("tokenEndpoint") ?? manifest["tokenUrl"])!, creds.TryGetValue("vars", out var vr) ? vr : Undef),
            ClientId = (string)creds["clientId"]!,
        };
        if (creds.TryGetValue("clientSecret", out var cs)) cfg.ClientSecret = cs as string;
        if (refresh.TryGetValue("supportsScopeNarrowing", out var sn)) cfg.SupportsScopeNarrowing = (bool)sn!;
        if (refresh.TryGetValue("extraParams", out var ep)) cfg.ExtraParams = ((D)ep!).ToDictionary(e => e.Key, e => (string)e.Value!);
        return cfg;
    }

    /// <summary>The <c>providers</c> option of a TokenVault from per-provider credentials; non-refreshable providers are skipped.</summary>
    public static Dictionary<string, ProviderConfig> BuildVaultProviders(D credsById, ProviderRegistry? registry = null)
    {
        var reg = registry ?? DefaultRegistry;
        var o = new Dictionary<string, ProviderConfig>();
        foreach (var (pid, creds) in credsById)
        {
            var manifest = reg.Require(pid);
            if ((string)((D)manifest["refresh"]!)["mode"]! == "none") continue;
            o[pid] = ManifestToProviderConfig(manifest, (D)creds!);
        }
        return o;
    }
}
