// Trait selectors and the registry-growth semantics, and the producer side of the signed human confirmation.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionSelectors
{
    /// <summary>Does the selector match an action whose trait closure is <paramref name="closure"/>? An unknown selector kind yields null (falsy), as the reference.</summary>
    public static bool? SelectorMatches(D s, ICollection<string> closure)
    {
        switch (Ak.S(s, "k"))
        {
            case "trait": return closure.Contains((string)s["id"]!);
            case "all_of": return ((L)s["ids"]!).All(i => closure.Contains((string)i!));
            case "any_of": return ((L)s["ids"]!).Any(i => closure.Contains((string)i!));
            case "not": return SelectorMatches((D)s["s"]!, closure) != true;
            case "and": return SelectorMatches((D)s["a"]!, closure) == true && SelectorMatches((D)s["b"]!, closure) == true;
            default: return null;
        }
    }

    /// <summary>Unconfirmed means maximally dangerous: every prohibit selector matches it, no allow selector ever does; the closure is not consulted.</summary>
    public static bool? SelectorMatchesFor(D s, string mode, ICollection<string> closure, bool confirmed) => !confirmed ? mode == "prohibit" : SelectorMatches(s, closure);

    public static bool SelectorHasNot(D s) => Ak.S(s, "k") switch
    {
        "not" => true,
        "and" => SelectorHasNot((D)s["a"]!) || SelectorHasNot((D)s["b"]!),
        _ => false,
    };

    static bool AnyOf(D x) => Ak.S(x, "k") switch
    {
        "any_of" => true,
        "and" => AnyOf((D)x["a"]!) || AnyOf((D)x["b"]!),
        _ => false,
    };

    /// <summary>T7 typing rule for an ALLOW selector: no negation, and any_of only in a pinned allow. Null = allowed.</summary>
    public static string? AllowSelectorError(D s, bool pinned)
    {
        if (SelectorHasNot(s)) return "an allow selector must not use negation: the absence of a trait is never a safety claim";
        if (!pinned && AnyOf(s)) return "any_of in an allow selector requires the grant to be pinned to a pack digest";
        return null;
    }

    /// <summary>A matching prohibit denies; a pinned verb with a matching allow is allowed; an unpinned verb is deny/escalate; else deny.</summary>
    public static string PolicyDecision(D p, string verb, ICollection<string> closure, bool confirmed)
    {
        if (((L)p["prohibit"]!).Any(s => SelectorMatchesFor((D)s!, "prohibit", closure, confirmed) == true)) return "deny";
        if (!((L)p["pinned"]!).Any(v => v is string vs && vs == verb)) return Ak.S(p, "on_new_action") == "escalate" ? "escalate" : "deny";
        return ((L)p["allow"]!).Any(s => SelectorMatchesFor((D)s!, "allow", closure, confirmed) == true) ? "allow" : "deny";
    }
}

public static class ActionConfirmation
{
    /// <summary>True iff the dismissal reason is nothing but whitespace and the C0 separators (JavaScript trim plus U+001C..U+001F).</summary>
    public static bool BlankReason(string s) => s.All(c => c is >= '\u001c' and <= '\u001f' || AtlasPca.Js.JsJson.IsJsSpace(c));

    /// <summary>The domain-separated message the reviewer signs.</summary>
    public static byte[] ReviewMessage(D b) => Actions.ReviewMessage(b, Ak.Strs(b["final_traits"]));

    /// <summary>The review reference for body <paramref name="b"/> (final_traits sorted and distinct, dismissed sorted by trait), signed with a 32-byte Ed25519 seed.</summary>
    public static D SignReview(D b, byte[] secret)
    {
        if (secret is not { Length: 32 }) throw new ArgumentException("the reviewer key must be a 32-byte Ed25519 secret");
        var norm = new D(b);
        norm["final_traits"] = Ak.ToL(Ak.SortUniq(Ak.Strs(b["final_traits"])));
        norm["dismissed"] = new L(((L)b["dismissed"]!).OrderBy(x => (string)((D)x!)["trait"]!, StringComparer.Ordinal));
        norm["sig"] = Pca.B64u(EdKey.FromSeed(secret).Sign(ReviewMessage(norm)));
        return norm;
    }
}
