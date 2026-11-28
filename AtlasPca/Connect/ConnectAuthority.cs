// The capability caveat that grants outbound OAuth authority. It is pure data inside the signed capability body, so it is attenuable: a
// delegation hop may add a narrower oauth_scope for the same provider, which can only shrink the effective grant (intersection).
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connect;

public static class ConnectAuthority
{
    public const string OAuthScopeCaveat = "oauth_scope";

    /// <summary>An oauth_scope caveat granting <paramref name="scopes"/> on <paramref name="provider"/>; duplicate scopes are collapsed (first occurrence kept).</summary>
    public static D OauthScopeCaveat(string provider, IEnumerable<string> scopes)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var l = new L();
        foreach (var s in scopes) if (seen.Add(s)) l.Add(s);
        return new D { ["type"] = OAuthScopeCaveat, ["provider"] = provider, ["scopes"] = l };
    }

    static bool IsStringArray(object? v) => v is L l && l.All(x => x is string);

    public static bool IsOAuthScopeCaveat(object? cv)
    {
        if (cv is not D m) return false;
        if (!m.ContainsKey("type") || !m.ContainsKey("provider") || !m.ContainsKey("scopes")) return false;
        return m["type"] is string t && t == OAuthScopeCaveat && m["provider"] is string && IsStringArray(m["scopes"]);
    }

    /// <summary>The effective OAuth scopes a verified capability chain grants for <paramref name="provider"/>: the intersection of every oauth_scope
    /// caveat naming it in the chain's leaf. Null when the chain grants nothing for the provider (so the vault can tell "not covered" from "covered but too
    /// narrow"). Run the chain verification first; this only reads the signed caveat lineage.</summary>
    public static HashSet<string>? GrantedOAuthScopes(object? chain, string provider)
    {
        if (chain is not L c || c.Count == 0) return null;
        var leaf = c[^1];
        if (leaf == null) throw JsX.TypeError("Cannot read properties of null (reading 'caveats')"); // the reference reads leaf.caveats
        if (leaf is not D ld || !ld.TryGetValue("caveats", out var cavs) || cavs is not L cl) return null;
        HashSet<string>? effective = null;
        foreach (var cv in cl)
        {
            if (!IsOAuthScopeCaveat(cv) || (string)((D)cv!)["provider"]! != provider) continue;
            var here = new HashSet<string>(((L)((D)cv)["scopes"]!).Select(x => (string)x!), StringComparer.Ordinal);
            if (effective == null) effective = here;
            else effective = new HashSet<string>(effective.Where(here.Contains), StringComparer.Ordinal);
        }
        return effective;
    }
}
