// The token-refresh side of the outbound vault: one refresh-token grant against a provider's token endpoint.
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Connect;

/// <summary>Per-provider OAuth token-endpoint configuration used to refresh an access token.</summary>
public sealed class ProviderConfig
{
    public string TokenEndpoint { get; set; } = "";
    public string ClientId { get; set; } = "";
    /// <summary>Null for public clients / PKCE.</summary>
    public string? ClientSecret { get; set; }
    /// <summary>Null = unset. When true a narrowed <c>scope</c> is sent on refresh.</summary>
    public bool? SupportsScopeNarrowing { get; set; }
    /// <summary>Extra static form parameters (null = none).</summary>
    public Dictionary<string, string>? ExtraParams { get; set; }
}

/// <summary>A minimal structural view of an HTTP response.</summary>
public interface IVaultHttpResponse
{
    bool Ok { get; }
    int Status { get; }
    /// <summary>The parsed JSON body (D, List, string, bool, Num, null); throws when it does not parse.</summary>
    object? Json();
    string Text();
}

public sealed record VaultHttpRequest(string Method, Dictionary<string, string> Headers, string Body);

/// <summary>The injectable transport. In production wrap an HttpClient; in tests pass a scripted one.</summary>
public delegate IVaultHttpResponse VaultFetch(string url, VaultHttpRequest init);

/// <summary>The fields <see cref="ConnectRefresh.RefreshConnection"/> hands back for the vault to apply.</summary>
public sealed class Refreshed
{
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
    public double ExpiresAt { get; set; }
    public List<string> Scopes { get; set; } = new();
}

/// <summary>What <see cref="ConnectRefresh.RefreshConnection"/> needs.</summary>
public sealed class RefreshArgs
{
    public StoredConnection Connection { get; set; } = null!;
    /// <summary>Null when the provider has no configuration.</summary>
    public ProviderConfig? Config { get; set; }
    public string RefreshToken { get; set; } = "";
    public List<string> Requested { get; set; } = new();
    /// <summary>Null when no transport is configured.</summary>
    public VaultFetch? Fetch { get; set; }
    public double Now { get; set; }
    public double DefaultTokenLifetimeMs { get; set; }
}

public static class ConnectRefresh
{
    sealed class TokenResponse
    {
        public string AccessToken = "";
        public double? ExpiresInSecs;
        public string? RefreshToken;
        public List<string>? Scopes;
    }

    static TokenResponse ParseTokenResponse(object? body, string provider)
    {
        if (body is not D m) throw new RefreshFailedError(provider, "token endpoint returned a non-object body");
        if (!(m.GetValueOrDefault("access_token") is string at && at.Length > 0)) throw new RefreshFailedError(provider, "token endpoint response has no access_token");
        var o = new TokenResponse { AccessToken = at };
        if (m.GetValueOrDefault("expires_in") is Num && IntentJs.NumOf(m["expires_in"]) is double ei && double.IsFinite(ei) && ei > 0) o.ExpiresInSecs = ei;
        if (m.GetValueOrDefault("refresh_token") is string rt && rt.Length > 0) o.RefreshToken = rt;
        if (m.GetValueOrDefault("scope") is string sc && JsX.JsTrim(sc).Length > 0) o.Scopes = ConnectJs.SplitRuns(JsX.JsTrim(sc));
        return o;
    }

    /// <summary>Epoch-ms expiry claimed by a JWT access token (decodeJwt semantics: three dot-separated parts, a non-empty payload that is a JSON object); null for an
    /// opaque token or a non-finite / non-number <c>exp</c>.</summary>
    public static double? JwtExpiryMs(string accessToken)
    {
        try
        {
            var parts = accessToken.Split('.');
            if (parts.Length != 3 || parts[1].Length == 0) return null;
            var payload = Pca.ParseJson(Encoding.UTF8.GetString(ConnectJs.LenientB64uDecode(parts[1])));
            if (payload is not D pd || pd.GetValueOrDefault("exp") is not Num) return null;
            return IntentJs.NumOf(pd["exp"]) is double e && double.IsFinite(e) ? e * 1000 : null;
        }
        catch (Exception) { return null; }
    }

    /// <summary>Refresh the connection's access token at its provider's token endpoint with the stored refresh token. When the provider supports scope narrowing the
    /// requested scopes are sent so the new token is no wider. Returns the fields to apply; throws <see cref="RefreshFailedError"/> on any transport or parse failure.</summary>
    public static Refreshed RefreshConnection(RefreshArgs a)
    {
        var provider = a.Connection.Provider;
        var secrets = new List<string?> { a.RefreshToken, a.Connection.AccessToken };
        if (a.Config != null)
        {
            secrets.Add(a.Config.ClientSecret);
            if (a.Config.ExtraParams != null) secrets.AddRange(a.Config.ExtraParams.Values);
        }
        if (a.Config == null) throw new RefreshFailedError(provider, "no provider token-endpoint config");
        if (a.Fetch == null) throw new RefreshFailedError(provider, "no fetch transport configured");

        var ps = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = a.RefreshToken, ["client_id"] = a.Config.ClientId };
        if (a.Config.ClientSecret != null) ps["client_secret"] = a.Config.ClientSecret;
        if (a.Config.ExtraParams != null) foreach (var (k, v) in a.Config.ExtraParams) ps[k] = v; // an overriding key keeps its position, as an object spread does
        bool narrow = a.Config.SupportsScopeNarrowing == true && a.Requested.Count > 0;
        if (narrow) ps["scope"] = string.Join(" ", a.Requested);

        IVaultHttpResponse res;
        try
        {
            var headers = new Dictionary<string, string> { ["content-type"] = "application/x-www-form-urlencoded", ["accept"] = "application/json" };
            res = a.Fetch(a.Config.TokenEndpoint, new VaultHttpRequest("POST", headers, ConnectJs.FormEncode(ps)));
        }
        catch (Exception e)
        {
            throw new RefreshFailedError(provider, "transport error: " + ConnectJs.Redact(e.Message, secrets));
        }
        if (!res.Ok)
        {
            string detail;
            try
            {
                var t = res.Text();
                detail = ConnectJs.Redact(t.Length > 256 ? t[..256] : t, secrets);
            }
            catch (Exception) { detail = "<unreadable body>"; }
            throw new RefreshFailedError(provider, $"token endpoint {res.Status}: {detail}", res.Status);
        }
        object? json;
        try { json = res.Json(); }
        catch (Exception) { throw new RefreshFailedError(provider, "unparseable JSON body"); } // the parser's message quotes the start of the body, which may hold a token
        var parsed = ParseTokenResponse(json, provider);

        var o = new Refreshed { AccessToken = parsed.AccessToken };
        o.ExpiresAt = parsed.ExpiresInSecs is double s ? a.Now + s * 1000 : JwtExpiryMs(parsed.AccessToken) ?? a.Now + a.DefaultTokenLifetimeMs;
        o.Scopes = parsed.Scopes ?? (narrow ? new List<string>(a.Requested) : new List<string>(a.Connection.Scopes));
        o.RefreshToken = parsed.RefreshToken ?? a.RefreshToken;
        return o;
    }
}
