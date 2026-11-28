// The built-in connector defs, the domain vocabulary defs and bindings, how the built-ins become confirmed, and the starter templates.
// Without a release signing step the built-ins carry no attestation: unconfirmed, maximally dangerous.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionBuiltin
{
    static readonly Lazy<D> Data = new(() => (D)Pca.ParseJson(ActionData.BuiltinJson)!);

    /// <summary>The built-in connector defs (parsed afresh per call, so a caller may keep or change the tree).</summary>
    public static L BuiltinDefs() => (L)Ak.Copy(Data.Value["builtin"])!;
    public static L DomainDefs() => (L)Ak.Copy(Data.Value["domain"])!;
    public static L CorePackDefs() { var l = BuiltinDefs(); l.AddRange(DomainDefs()); return l; }
    public static D LegacyCatalog() => (D)Ak.Copy(Data.Value["legacyCatalog"])!;
    public static D LegacyOntologyEffect() => (D)Ak.Copy(Data.Value["legacyOntologyEffect"])!;
    public static L Resolutions() => (L)Ak.Copy(Data.Value["resolutions"])!;
    /// <summary>The domain bindings: domain to a list of {id, verb, resourceType, params, ccys?}.</summary>
    public static D DomainVerbBindings() => (D)Ak.Copy(Data.Value["domainVerbs"])!;

    /// <summary>The built-in defs with their release attestation attached where the package carries one (none yet: all stay unconfirmed).</summary>
    public static L ReleasedBuiltinDefs(L? defs = null) => defs ?? BuiltinDefs();

    /// <summary>The pinned release reviewer keys; null before the first release signing (then pass no pins: nothing is confirmed).</summary>
    public static D? BuiltinReviewerPins() => null;

    /// <summary>The release pins and registry the built-in attestations verify against (<c>{pins, registry}</c>); null before the first release signing.</summary>
    public static D? BuiltinReleaseCtx(Dictionary<string, D>? registry = null) =>
        BuiltinReviewerPins() is { } pins ? new D { ["pins"] = pins, ["registry"] = registry ?? Actions.CoreRegistry } : null;

    /// <summary>The review options under which the released built-ins count as confirmed: a signature by the pinned release key, nothing else. The attestation verifier to hand
    /// to the algebra's <c>attestationVerified</c> argument; null before the first release signing (no pinned key), where no built-in is confirmed.</summary>
    public static Func<D, bool>? BuiltinReviewOpts(Dictionary<string, D>? registry = null)
    {
        var pins = BuiltinReviewerPins();
        if (pins == null) return null;
        var reg = registry ?? Actions.CoreRegistry;
        return d => ImportReview.VerifyAttestation(d, pins, reg).GetValueOrDefault("ok") is true;
    }

    /// <summary>Release step: confirm (sign) every built-in def with the release reviewer key. The key is a parameter and is never stored.</summary>
    public static L SignBuiltins(string kid, byte[] secret, object? ts, Dictionary<string, D>? registry = null, L? defs = null)
    {
        var reg = registry ?? Actions.CoreRegistry;
        var o = new L();
        foreach (var x in defs ?? BuiltinDefs())
        {
            var d = (D)x!;
            var traits = d.GetValueOrDefault("traits") is L t ? Ak.SortUniq(t.Select(v => (string)v!)) : new List<string>();
            o.Add(ImportReview.ConfirmDef(d, reg, kid, secret, null, Ak.ToL(traits), null, ts));
        }
        return o;
    }

    static D DefOf(string verb) =>
        CorePackDefs().Select(x => (D)x!).FirstOrDefault(x => (string)x["verb"]! == verb) ?? throw new ArgumentException($"domain binding names unknown def '{verb}'");

    static L Bindings(string domain) => ((D)Data.Value["domainVerbs"]!).TryGetValue(domain, out var b) && b is L l ? l : throw new KeyNotFoundException($"unknown domain '{domain}'");

    /// <summary>The verbs and aliases of a domain ontology, derived from the defs (effect class derived, never assigned).</summary>
    public static D DomainVerbs(string domain, Dictionary<string, D>? reg = null)
    {
        reg ??= Actions.CoreRegistry;
        var bindings = Bindings(domain).Select(x => (D)x!).ToList();
        var onto = ActionDerive.ToOntology(bindings.Select(b => DefOf((string)b["verb"]!)), reg);
        var verbs = new L(); var aliases = new D();
        foreach (var b in bindings)
        {
            var d = DefOf((string)b["verb"]!);
            if (!Ak.Strs(Ak.G(d, "aliases")).Contains((string)b["id"]!)) throw new ArgumentException($"domain binding '{b["id"]}' is not an alias of '{b["verb"]}'");
            var ov = ((L)onto["verbs"]!).Select(x => (D)x!).First(v => (string)v["id"]! == (string)b["verb"]!);
            var ps = new D();
            foreach (var (nl, dpo) in (D)b["params"]!)
            {
                var dp = (string)dpo!;
                if (!((D)ov["params"]!).TryGetValue(dp, out var po) || po is not D p) throw new ArgumentException($"domain binding '{b["id"]}' surfaces unknown parameter '{dp}'");
                ps[nl] = Ak.S(p, "kind") == "money" && Ak.G(b, "ccys") is L cc ? new D { ["kind"] = "money", ["ccys"] = new L(cc) } : p;
            }
            verbs.Add(new D { ["id"] = b["id"], ["effect"] = ActionDerive.EffectClass(d), ["resource_type"] = b["resourceType"], ["params"] = ps });
            foreach (var a in Ak.Strs(Ak.G(d, "aliases"))) if (a != (string)b["id"]!) aliases[a] = b["id"];
        }
        return new D { ["verbs"] = verbs, ["aliases"] = aliases };
    }

    /// <summary>The role map of a domain verb for the selector layer: role to the natural-language parameter names carrying it.</summary>
    public static D DomainRoles(string domain)
    {
        var outp = new D();
        foreach (var bo in Bindings(domain))
        {
            var b = (D)bo!;
            var d = DefOf((string)b["verb"]!);
            var roles = new D();
            foreach (var (nl, dpo) in (D)b["params"]!)
            {
                var role = Ak.S(Ak.G(d["params"], (string)dpo!), "role");
                if (role == null) continue;
                if (!roles.TryGetValue(role, out var l)) roles[role] = l = new L();
                ((L)l!).Add(nl);
            }
            outp[(string)b["id"]!] = roles;
        }
        return outp;
    }
}

/// <summary>One starter pack a platform can begin from: typical actions of a business type in the authoring YAML form, with custom traits and business rules.</summary>
public sealed class StarterTemplate
{
    readonly D _raw;
    internal StarterTemplate(D raw) { _raw = raw; }
    public string Id => (string)_raw["id"]!;
    public string Title => (string)_raw["title"]!;
    public string Description => (string)_raw["description"]!;
    public string Ns => (string)_raw["ns"]!;
    public D Summary() => new() { ["id"] = Id, ["title"] = Title, ["description"] = Description, ["ns"] = Ns };

    /// <summary>The pack's custom traits under namespace <paramref name="ns"/> (ids "ns.name").</summary>
    public L Traits(object? ns) { var n = ActionTemplates.CheckNs(ns); return (L)Sub(Ak.Copy(_raw["traits"]), n)!; }
    /// <summary>The authoring YAML under namespace <paramref name="ns"/>, with rules blocks and their examples (text: parse it and pass the value to ActionAuthor.LoadActionsValue).</summary>
    public string Yaml(object? ns) => ((string)_raw["yaml"]!).Replace(ActionData.TemplateMarker, ActionTemplates.CheckNs(ns), StringComparison.Ordinal);

    static object? Sub(object? x, string ns) => x switch
    {
        string s => s.Replace(ActionData.TemplateMarker, ns, StringComparison.Ordinal),
        L l => new L(l.Select(v => Sub(v, ns))),
        D d => d.ToDictionary(kv => kv.Key, kv => Sub(kv.Value, ns)),
        _ => x,
    };
}

public static class ActionTemplates
{
    static readonly Lazy<List<StarterTemplate>> All = new(() => ((L)Pca.ParseJson(ActionData.TemplatesJson)!).Select(x => new StarterTemplate((D)x!)).ToList());

    /// <summary>The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved "pca".</summary>
    public static string CheckNs(object? ns)
    {
        if (ns is not string s || !Rx.Get(@"\A[a-z][a-z0-9_]{0,31}\z", RegexOptions.CultureInvariant).IsMatch(s)) throw new ActionKitError("bad_ns", "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)");
        if (s == "pca") throw new ActionKitError("bad_ns", "the namespace 'pca' is reserved for core traits");
        return s;
    }

    public static IReadOnlyList<StarterTemplate> StarterTemplates() => All.Value;
    public static StarterTemplate? StarterTemplateById(string id) => All.Value.FirstOrDefault(t => t.Id == id);
}
