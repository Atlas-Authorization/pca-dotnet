// Approval-render wrappers, the facade view of a def and the provenance-gate facts. The render itself is Approval.Render.
// attestationVerified is the caller's confirmation verifier (absent: nothing is confirmed).
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionApprovals
{
    /// <summary>The approval render, with the confirmation decided by the verifier (asked only after the render itself succeeded).</summary>
    public static D RenderApproval(D d, object? parameters, Func<D, bool>? attestationVerified = null)
    {
        var r = Approval.Render(d, parameters, false);
        r["unreviewed"] = !ActionEffective.IsConfirmed(d, attestationVerified);
        return r;
    }

    /// <summary>H(R) for an executed action; refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb.</summary>
    public static string RenderDigestForAction(D d, object? parameters, D pcactn, Func<D, bool>? attestationVerified = null)
    {
        var action = (D)pcactn["action"]!;
        if (!JsX.StrictEq(action["verb"], d["verb"])) throw new ActionKitError("render_verb_mismatch", $"the PCActn is for '{Ak.JsStr(action["verb"])}', the definition for '{d["verb"]}'");
        if (!JsX.StrictEq(Ak.G(action, "params_digest"), Pca.ParamsDigest(parameters))) throw new ActionKitError("render_params_mismatch", "the supplied params are not the params the PCActn signed");
        return Approval.RenderDigest(RenderApproval(d, parameters, attestationVerified));
    }

    /// <summary>The approver client's check before it signs: re-render from the pinned def and require the requested digest. Returns the digest to sign.</summary>
    public static string ApproverRenderCheck(D d, object? parameters, object? requestedRenderDigest, Func<D, bool>? attestationVerified = null)
    {
        var dg = Approval.RenderDigest(RenderApproval(d, parameters, attestationVerified));
        if (!JsX.StrictEq(dg, requestedRenderDigest)) throw new ActionKitError("render_mismatch", "the approval request commits to a render this definition and these params do not produce");
        return dg;
    }

    /// <summary>Single-tap (one-gesture) approval is allowed only for a confirmed definition.</summary>
    public static bool SingleTapAllowed(object? r) => !JsX.Truthy(Ak.G(r, "unreviewed"));

    /// <summary><see cref="RenderFromDefs"/> under the reference name.</summary>
    public static Func<string, string, D?, D> RenderersFromDefs(IEnumerable<D> defs, Func<D, bool>? attestationVerified = null) => RenderFromDefs(defs, attestationVerified);

    /// <summary>The step-up renderer derived from the pinned defs (found by verb or alias); an unknown verb throws, which makes the review a deny.</summary>
    public static Func<string, string, D?, D> RenderFromDefs(IEnumerable<D> defs, Func<D, bool>? attestationVerified = null)
    {
        var byVerb = new Dictionary<string, D>();
        foreach (var d in defs)
        {
            byVerb[(string)d["verb"]!] = d;
            foreach (var a in Ak.Strs(Ak.G(d, "aliases"))) byVerb.TryAdd(a, d);
        }
        return (verb, _, parameters) =>
        {
            if (!byVerb.TryGetValue(verb, out var d)) throw new ActionKitError("render_unknown_verb", $"no pinned action definition for '{verb}'");
            return RenderApproval(d, parameters ?? new D(), attestationVerified);
        };
    }
}

public static class ActionFacade
{
    /// <summary>One def to one facade row: reversibility and blast are the EFFECTIVE values; <paramref name="reviewed"/> prices the def as reviewed (release-attested catalog only).</summary>
    public static D SpecOfDef(D d, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null, bool reviewed = false)
    {
        reg ??= Actions.CoreRegistry;
        var full = ActionEffective.EffectiveWith(d, reg, attestationVerified);
        var e = reviewed ? (D)full["hint"]! : full;
        var verb = (string)d["verb"]!;
        var parts = verb.Split('.');
        string? amount;
        try { amount = ActionDerive.ParamByRole(d, "money.amount"); } catch (ActionKitError) { amount = null; }
        var eff = (D)e["eff"]!;
        var o = new D { ["connector"] = parts[0], ["action"] = string.Join(".", parts.Skip(1)), ["verb"] = verb, ["reversibility"] = eff["rev"], ["blastRadius"] = Ak.I(eff["blast_ppm"]) / 1_000_000.0 };
        if (amount != null) o["amountField"] = amount;
        o["description"] = Ak.G(d, "description") ?? d["title"];
        var aliases = Ak.Strs(Ak.G(d, "aliases"));
        if (aliases.Count > 0) o["aliases"] = Ak.ToL(aliases.OrderBy(x => x, StringComparer.Ordinal));
        o["traits"] = e["closure"];
        return o;
    }

    public static L FacadeSpecs(IEnumerable<D> defs, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null, bool reviewed = false) =>
        new(defs.Select(d => (object?)SpecOfDef(d, reg, attestationVerified, reviewed)));
}

public static class ActionProvenance
{
    /// <summary>The gate facts of one def. Unconfirmed means maximally dangerous: no effects, the top trait set, provenance relaxations ignored.</summary>
    public static D ProvenanceInfoOf(D d, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null)
    {
        reg ??= Actions.CoreRegistry;
        var traits = ActionEffective.TraitsOfWith(d, reg, attestationVerified);
        if (!ActionEffective.IsConfirmed(d, attestationVerified)) return new D { ["effects"] = new L(), ["traits"] = Ak.ToL(traits) };
        var n = Actions.Normalize(d);
        var ps = new D();
        foreach (var (name, po) in (D)n["params"]!) if (po is D p && p.ContainsKey("provenance_min")) ps[name] = p["provenance_min"];
        var o = new D { ["effects"] = new L((L)n["effects"]!), ["traits"] = Ak.ToL(traits) };
        if (ps.Count > 0) o["params"] = ps;
        return o;
    }

    /// <summary>The provenance.actions resolver: the facts of the def whose verb (or alias) is the operation's verb, null for an unknown verb. Two defs claiming one name throw.</summary>
    public static Func<D, D?> ProvenanceActions(IEnumerable<D> defs, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null)
    {
        reg ??= Actions.CoreRegistry;
        var byVerb = new Dictionary<string, D>();
        foreach (var d in defs)
        {
            var n = Actions.Normalize(d);
            var info = ProvenanceInfoOf(d, reg, attestationVerified);
            foreach (var v in new[] { (string)n["verb"]! }.Concat(Ak.Strs(n["aliases"])))
            {
                if (byVerb.ContainsKey(v)) throw new InvalidOperationException($"provenanceActions: two definitions claim the verb '{v}'");
                byVerb[v] = info;
            }
        }
        return op => Ak.G(op, "verb") is string v && byVerb.TryGetValue(v, out var i) ? i : null;
    }
}
