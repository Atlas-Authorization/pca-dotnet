using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connectors;

public static partial class PcaConnectors
{
    static readonly Regex PkceVerifier = new(@"\A[A-Za-z0-9._~-]{43,128}\z", Ro);
    static readonly Regex Label = new(@"\A[A-Za-z0-9][A-Za-z0-9-]{0,62}\z", Ro);
    static readonly Regex Scheme = new(@"\A([A-Za-z][A-Za-z0-9+.\-]*):", Ro);
    const int MinStateChars = 16;

    static string RandomToken(int n = 32) => Pca.B64u(RandomNumberGenerator.GetBytes(n));

    /// <summary>The PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain".</summary>
    public static string PkceChallenge(string verifier, string method = "S256") =>
        method == "plain" ? verifier : Pca.B64u(Pca.Sha(Encoding.UTF8.GetBytes(verifier)));

    /// <summary>Fill <c>{name}</c> placeholders from <paramref name="vars"/> (a parsed object; <see cref="InteropJs.JsX.Undef"/> when absent);
    /// each value must be a single DNS label so a value can never change the host.</summary>
    public static string SubstituteVars(string url, object? vars)
    {
        return Var.Replace(url, m =>
        {
            var name = m.Groups[1].Value;
            if (vars == null) throw TypeError("Cannot convert undefined or null to object");
            var v = Own(vars, name);
            if (ReferenceEquals(v, Undef)) throw new ConnectorError("missing URL variable '{" + name + "}'");
            if (!(v is string s && Label.IsMatch(s))) throw new ConnectorError("URL variable '{" + name + "}' must be a single DNS label (letters, digits and hyphens)");
            return s;
        });
    }

    static string Enc(object? v) => JsJson.EncodeUriComponent(v is string s ? s : Str(v));

    static string EncodeForm(IEnumerable<KeyValuePair<string, object?>> pairs) => string.Join("&", pairs.Select(p => Enc(p.Key) + "=" + Enc(p.Value)));

    static string Clean(string text)
    {
        int a = 0, b = text.Length;
        while (a < b && text[a] <= 0x20) a++;
        while (b > a && text[b - 1] <= 0x20) b--;
        return text[a..b].Replace("\t", "").Replace("\n", "").Replace("\r", "");
    }

    static bool IsSpecialScheme(string s) => s is "http" or "https" or "ftp" or "ws" or "wss";

    /// <summary>protocol, whether credentials / a fragment are present and the hostname of an absolute URL; null when it does not parse.</summary>
    static (string Protocol, bool Creds, string Hostname, bool Hash)? UrlInfo(string text)
    {
        var s = Clean(text);
        var m = Scheme.Match(s);
        if (!m.Success) return null;
        var scheme = m.Groups[1].Value.ToLowerInvariant();
        if (IsSpecialScheme(scheme))
        {
            var u = AtlasPca.Jose.WhatwgUrl.TryParse(s);
            if (u == null) return null;
            var h = u.Host;
            var host = h.StartsWith('[') ? h[..(h.IndexOf(']') + 1)] : h.Split(':')[0];
            return (scheme + ":", AtlasPca.Connect.ConnectJs.HasCredentials(s), host, AtlasPca.Connect.ConnectJs.HasFragment(s));
        }
        var rest = s[m.Length..];
        var hash = rest.IndexOf('#');
        var frag = hash >= 0 ? rest[(hash + 1)..] : "";
        string user = "", pw = "", hostname = "";
        if (rest.StartsWith("//", StringComparison.Ordinal))
        {
            var after = rest[2..];
            var cut = after.IndexOfAny(new[] { '/', '?', '#' });
            var auth = cut < 0 ? after : after[..cut];
            var at = auth.LastIndexOf('@');
            if (at >= 0)
            {
                var ui = auth[..at];
                auth = auth[(at + 1)..];
                var c = ui.IndexOf(':');
                user = c < 0 ? ui : ui[..c];
                pw = c < 0 ? "" : ui[(c + 1)..];
            }
            var colon = auth.IndexOf(':');
            hostname = colon < 0 ? auth : auth[..colon];
        }
        return (scheme + ":", user != "" || pw != "", hostname, frag != "");
    }

    static void CheckRedirectUri(object? uri)
    {
        var info = UrlInfo(Str(uri)) ?? throw new ConnectorError("buildAuthorizeUrl: redirectUri must be an absolute URL");
        if (info.Hash) throw new ConnectorError("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)");
        if (info.Creds) throw new ConnectorError("buildAuthorizeUrl: redirectUri must not carry credentials");
        var local = info.Hostname is "localhost" or "127.0.0.1" or "[::1]";
        if (info.Protocol != "https:" && !(info.Protocol == "http:" && local)) throw new ConnectorError("buildAuthorizeUrl: redirectUri must be https (http only for localhost)");
    }

    static string Separator(D manifest) => manifest.TryGetValue("scopeSeparator", out var s) && s is string ss ? ss : " ";

    static void CheckScopes(D manifest, object? scopes, bool allowUnlisted)
    {
        if (scopes is not L list) throw new ConnectorError("buildAuthorizeUrl: scopes must be a list");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var sep = Separator(manifest);
        var avail = (L)manifest["scopesAvailable"]!;
        foreach (var o in list)
        {
            if (!(o is string s) || s.Length == 0 || s.Any(IsSep) || s.Contains(sep, StringComparison.Ordinal))
                throw new ConnectorError("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator");
            if (!seen.Add(s)) throw new ConnectorError($"buildAuthorizeUrl: scope '{s}' is listed twice");
            if (!allowUnlisted && avail.Count > 0 && !avail.Contains(s))
                throw new ConnectorError($"buildAuthorizeUrl: scope '{s}' is not offered by provider '{manifest["id"]}'");
        }
    }

    /// <summary>The members of a parsed object, in order (a falsy or non-object value has none).</summary>
    /// <summary><c>Object.entries(v)</c>: a map's members, a list's or string's indexed elements (a string's are its UTF-16 units), nothing for any other value.</summary>
    static IEnumerable<KeyValuePair<string, object?>> Entries(object? v) => v switch
    {
        D m => m,
        L l => l.Select((x, i) => new KeyValuePair<string, object?>(i.ToString(System.Globalization.CultureInfo.InvariantCulture), x)),
        string s => s.Select((c, i) => new KeyValuePair<string, object?>(i.ToString(System.Globalization.CultureInfo.InvariantCulture), c.ToString())),
        _ => Enumerable.Empty<KeyValuePair<string, object?>>(),
    };

    /// <summary>The authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider: <c>{url, state, pkce?}</c>. <paramref name="options"/> carries
    /// clientId, redirectUri, scopes, state, pkce (false, true or <c>{verifier, method}</c>), vars, extraParams, allowUnlistedScopes and allowPlainPkce.
    /// A random state / PKCE verifier is generated when none is given.</summary>
    public static D BuildAuthorizeUrl(string providerId, D options, ProviderRegistry? registry = null)
    {
        var manifest = (registry ?? DefaultRegistry).Require(providerId);
        var scopes = options.GetValueOrDefault("scopes") ?? manifest["defaultScopes"];
        var separator = Separator(manifest);
        var state = options.GetValueOrDefault("state") ?? RandomToken();
        if (!(options.GetValueOrDefault("clientId") is string clientId && clientId.Length > 0)) throw new ConnectorError("buildAuthorizeUrl: clientId must be a non-empty string");
        var redirect = options.TryGetValue("redirectUri", out var ru) ? ru : Undef;
        CheckRedirectUri(redirect);
        if (!(state is string stateText && stateText.Length >= MinStateChars))
            throw new ConnectorError("buildAuthorizeUrl: state must be at least 16 characters (omit it to get a random one)");
        CheckScopes(manifest, scopes, options.GetValueOrDefault("allowUnlistedScopes") is true);
        var extra = options.GetValueOrDefault("extraParams");
        foreach (var (k, _) in Entries(extra))
            if (ReservedAuthorizeParams.Contains(k)) throw new ConnectorError($"buildAuthorizeUrl: extraParams may not set '{k}'");
        var scopeList = (L)scopes!;
        var ps = new List<KeyValuePair<string, object?>> { new("response_type", "code"), new("client_id", clientId), new("redirect_uri", redirect) };
        if (scopeList.Count > 0) ps.Add(new("scope", string.Join(separator, scopeList.Select(x => (string)x!))));
        ps.Add(new("state", stateText));
        var pk = options.TryGetValue("pkce", out var pkv) ? pkv : Undef;
        var want = pk is false ? false : !ReferenceEquals(pk, Undef) || manifest.GetValueOrDefault("pkce") is true;
        D? pkce = null;
        if (want)
        {
            object? verifier; object? method;
            if (pk is D pd)
            {
                verifier = pd.TryGetValue("verifier", out var vv) ? vv : Undef;
                method = pd.GetValueOrDefault("method") ?? "S256";
            }
            else if (pk == null) throw TypeError("Cannot read properties of null");
            else { verifier = RandomToken(); method = "S256"; }
            if (!PkceVerifier.IsMatch(Str(verifier))) throw new ConnectorError("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)");
            if (!(method is string ms && (ms == "S256" || (ms == "plain" && options.GetValueOrDefault("allowPlainPkce") is true))))
                throw new ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')");
            if (verifier is not string vs) throw TypeError("verifier.encode is not a function");
            var challenge = PkceChallenge(vs, ms);
            ps.Add(new("code_challenge", challenge));
            ps.Add(new("code_challenge_method", ms));
            pkce = new D { ["verifier"] = vs, ["challenge"] = challenge, ["method"] = ms };
        }
        if (manifest.GetValueOrDefault("authParams") is D auth) ps.AddRange(auth);
        ps.AddRange(Entries(extra));
        var vars = options.TryGetValue("vars", out var vr) ? vr : Undef;
        var b = SubstituteVars((string)manifest["authorizeUrl"]!, vars);
        var o = new D { ["url"] = b + (b.Contains('?') ? "&" : "?") + EncodeForm(ps), ["state"] = stateText };
        if (pkce != null) o["pkce"] = pkce;
        return o;
    }

    /// <summary>How to present an access token: <c>{kind: "header" | "query", name, value}</c>, or null for an unknown placement. The token must be
    /// printable ASCII without spaces. The manifest is used as given (not validated).</summary>
    public static D? ApplyAccessToken(D manifest, object? accessToken)
    {
        if (!(accessToken is string t && t.Length > 0 && t.All(c => c >= 0x21 && c <= 0x7e)))
            throw new ConnectorError("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces");
        var placement = manifest.GetValueOrDefault("tokenPlacement");
        if (placement is "bearer") return new D { ["kind"] = "header", ["name"] = "Authorization", ["value"] = "Bearer " + t };
        if (placement is "header")
        {
            if (!manifest.ContainsKey("headerName")) throw new ConnectorError($"manifest '{Str(Own(manifest, "id"))}' is header-placed but has no headerName");
            return new D { ["kind"] = "header", ["name"] = manifest["headerName"], ["value"] = t };
        }
        if (placement is "query")
        {
            if (!manifest.ContainsKey("queryParam")) throw new ConnectorError($"manifest '{Str(Own(manifest, "id"))}' is query-placed but has no queryParam");
            return new D { ["kind"] = "query", ["name"] = manifest["queryParam"], ["value"] = t };
        }
        return null;
    }
}
