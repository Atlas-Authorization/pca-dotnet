// SCOPES DERIVED FROM THE ACTION, for MCP and OAuth (packages/pca action-scopes.ts): the scopes a request needs or a token may carry come from the reviewed
// ActionDef's `upstream` declaration, not from the caller and not from the grant alone: scopes = upstream.scopes_min, and every one of them must lie inside the
// grant's scopes. A definition without a valid signed confirmation, an action this server does not know, a provider mismatch or an empty scope list derives
// NOTHING: the answer is a refusal, never a guess and never a broader default.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ActionScopes
{
    /// <summary>RFC 6749 section 3.3 scope-token: printable ASCII without space, double quote or backslash.</summary>
    static bool ScopeToken(string s)
    {
        if (s.Length == 0) return false;
        foreach (var c in s) if (!(c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e))) return false;
        return true;
    }

    static D No(string code) => new() { ["ok"] = false, ["code"] = code };

    /// <summary>Derive the scopes for an action <c>{verb, def_digest, confirmed, upstream: {provider, scopes_min}}</c>. <paramref name="granted"/> is the scope set the grant (or
    /// the stored connection) allows: when given, every derived scope must be in it (the action can ask for less than the grant, never more). <paramref name="provider"/> pins the
    /// upstream. Returns <c>{ok: true, scopes, provider, def_digest}</c> or <c>{ok: false, code}</c> with code unknown_action, unconfirmed, provider_mismatch, no_scopes,
    /// bad_scope or exceeds_grant.</summary>
    public static D Derive(object? action, string? provider = null, IEnumerable<string>? granted = null)
    {
        if (action is not D a) return No("unknown_action");
        if (a.GetValueOrDefault("confirmed") is not true) return No("unconfirmed");
        var up = a.GetValueOrDefault("upstream") as D;
        if (provider != null && up?.GetValueOrDefault("provider") as string != provider) return No("provider_mismatch");
        if (up?.GetValueOrDefault("scopes_min") is not L min || min.Count == 0) return No("no_scopes");
        if (!min.All(s => s is string t && t.Length <= 256 && ScopeToken(t))) return No("bad_scope");
        var scopes = min.Cast<string>().Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
        if (granted != null)
        {
            var g = new HashSet<string>(granted, StringComparer.Ordinal);
            if (!scopes.All(g.Contains)) return No("exceeds_grant");
        }
        return new D { ["ok"] = true, ["scopes"] = scopes.Cast<object?>().ToList(), ["provider"] = up!.GetValueOrDefault("provider"), ["def_digest"] = a.GetValueOrDefault("def_digest") };
    }
}
