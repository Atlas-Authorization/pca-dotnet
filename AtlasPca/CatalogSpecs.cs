using System.Globalization;
using AtlasPca.Js;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The JSON form of a catalog entry (the reference ActionSpec), shared by the digest, the untyped <see cref="Catalog.DefineActionJson"/> and the pinned catalog.</summary>
public static class CatalogSpecs
{
    /// <summary>The reference ActionSpec object: <c>aliases</c> is left out when empty, <c>traits</c> when empty unless <see cref="CatalogAction.TraitsListed"/>, <c>amountField</c> and <c>resource</c> when null.</summary>
    public static JD ToJson(CatalogAction a)
    {
        var m = new JD { ["connector"] = a.Connector, ["action"] = a.Action, ["verb"] = a.Verb, ["reversibility"] = a.Reversibility, ["blastRadius"] = Facade.JsNumber(a.BlastRadius) };
        if (a.AmountField != null) m["amountField"] = a.AmountField;
        if (a.Resource != null) m["resource"] = a.Resource;
        m["description"] = a.Description;
        if (a.Aliases.Count > 0) m["aliases"] = new JL(a.Aliases);
        if (a.Traits.Count > 0 || a.TraitsListed) m["traits"] = new JL(a.Traits);
        return m;
    }

    /// <summary>A catalog entry from its JSON form, as given (not validated: <see cref="Catalog.DefineActionJson"/> validates). A member of another type than the reference reads is a refusal.</summary>
    public static CatalogAction FromJson(JD m)
    {
        string S(string k) => m.GetValueOrDefault(k) as string ?? throw new ArgumentException("catalog entry: " + k + " must be a string");
        string? O(string k) => m.TryGetValue(k, out var v) ? v as string ?? throw new ArgumentException("catalog entry: " + k + " must be a string") : null;
        IReadOnlyList<string> Ls(string k) => !m.TryGetValue(k, out var v) ? Array.Empty<string>()
            : v is JL l && l.All(x => x is string) ? l.Cast<string>().ToList() : throw new ArgumentException("catalog entry: " + k + " must be a list of strings");
        return new CatalogAction(S("connector"), S("action"), S("verb"), S("reversibility"), BlastOf(m.GetValueOrDefault("blastRadius")) ?? throw new ArgumentException("catalog entry: blastRadius must be a number"),
            O("amountField"), S("description"), Ls("aliases"), Ls("traits"), O("resource"), m.ContainsKey("traits"));
    }

    internal static double? BlastOf(object? v) => v switch
    {
        double d => d,
        long l => l,
        int i => i,
        Num n => double.Parse(n.Raw, CultureInfo.InvariantCulture),
        _ => null,
    };
}

public sealed partial class Catalog
{
    /// <summary>The blast-radius presets by shape of action (conservative, overridable).</summary>
    public static IReadOnlyDictionary<string, double> Blast { get; } = new Dictionary<string, double>
    {
        ["read"] = 0.05, ["reversibleWrite"] = 0.2, ["rateLimitedWrite"] = 0.5, ["irreversibleWrite"] = 0.8, ["moneyMovement"] = 0.9,
    };

    static readonly string[] ReversibilityOrder = { "reversible", "rate_limited", "irreversible" };

    /// <summary>Validate an entry given as JSON (the reference <c>defineAction</c>): connector and action non-empty strings, no whitespace or dot in the connector, a present
    /// <c>amountField</c> a non-empty string, a known reversibility class, a blast radius in [0, 1]. The result keeps every member and adds <c>verb</c>
    /// (<c>connector.action</c>) when it is absent or null. Throws <see cref="ArgumentException"/>.</summary>
    public static JD DefineActionJson(object? spec)
    {
        if (spec == null) throw new ArgumentException("defineAction: spec must be an object");
        var m = spec as JD;
        object? Get(string k) => m != null && m.TryGetValue(k, out var v) ? v : null;
        if (Get("connector") is not string connector || Get("action") is not string action || connector.Length == 0 || action.Length == 0)
            throw new ArgumentException("defineAction: connector and action are required");
        if (connector.Any(JsJson.IsJsSpace) || connector.Contains('.')) throw new ArgumentException("defineAction: connector must not contain whitespace or a dot");
        if (m!.TryGetValue("amountField", out var af) && (af is not string s || s.Length == 0)) throw new ArgumentException("defineAction: amountField must be a non-empty string");
        if (Get("reversibility") is not string rev || Array.IndexOf(ReversibilityOrder, rev) < 0)
            throw new ArgumentException($"defineAction: bad reversibility '{(Get("reversibility") is string r ? r : "undefined")}'");
        if (CatalogSpecs.BlastOf(Get("blastRadius")) is not double b || !(b >= 0 && b <= 1)) throw new ArgumentException("defineAction: blastRadius must be in [0,1]");
        var o = new JD(m);
        if (m.GetValueOrDefault("verb") == null) o["verb"] = connector + "." + action;
        return o;
    }

    /// <summary>The entry with the given members; throws like <see cref="DefineActionJson"/> (a null amount field is no member).</summary>
    public static CatalogAction DefineAction(CatalogAction a) => CatalogSpecs.FromJson(DefineActionJson(CatalogSpecs.ToJson(a)));

    /// <summary>Every definition of a connector, in definition order.</summary>
    public IEnumerable<CatalogAction> ForConnector(string connector) => _byVerb.Values.Where(a => a.Connector == connector);

    /// <summary>What a verb the catalog does not know is treated as: irreversible, blast radius 1; the connector is the text before the first dot, the action the rest (the whole verb when that is empty).</summary>
    public static CatalogAction UncataloguedSpec(string verb)
    {
        var parts = verb.Split('.');
        var rest = string.Join(".", parts.Skip(1));
        return new CatalogAction(parts[0], rest.Length > 0 ? rest : verb, verb, "irreversible", 1, null, "(uncatalogued) " + verb, Array.Empty<string>(), Array.Empty<string>());
    }

    /// <summary>Resolve a verb, failing closed: an unknown verb comes back as <see cref="UncataloguedSpec"/> with <c>Catalogued</c> false (no alias is consulted).</summary>
    public (CatalogAction Spec, bool Catalogued) ResolveAction(string verb) => Get(verb) is { } s ? (s, true) : (UncataloguedSpec(verb), false);

    /// <summary>SHA-256 over the canonical JSON of every entry, sorted by verb (UTF-16 code unit order). A catalog a deployment reviewed can be pinned by it.
    /// Throws on an entry the canonical form refuses (a blast radius that is not a finite number).</summary>
    public string Digest() => Pca.HashCanonical(new JL(_byVerb.Values.OrderBy(a => a.Verb, StringComparer.Ordinal).Select(a => (object?)CatalogSpecs.ToJson(a))));

    /// <summary>Throws unless the catalog hashes to <paramref name="expected"/>.</summary>
    public void AssertPinned(string? expected)
    {
        if (Digest() != expected) throw new InvalidOperationException("catalog does not match the pinned digest");
    }

    /// <summary>The catalog with more entries. An extra entry may not replace an existing verb with a less cautious one (a lower reversibility class or a lower blast
    /// radius): that would let a plugin relabel <c>gmail.send</c> as reversible. Throws <see cref="InvalidOperationException"/>.</summary>
    public Catalog Extend(IEnumerable<CatalogAction> extra)
    {
        var list = extra.ToList();
        foreach (var e in list)
            if (Get(e.Verb) is { } old && (Array.IndexOf(ReversibilityOrder, e.Reversibility) < Array.IndexOf(ReversibilityOrder, old.Reversibility) || e.BlastRadius < old.BlastRadius))
                throw new InvalidOperationException($"extendCatalog: '{e.Verb}' would be less cautious than the existing entry");
        return new Catalog(All().Concat(list));
    }
}
