// From an ActionDef to T(d), decl(d) and eff(d) with a caller-supplied confirmation verifier, plus the structural param rules.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionEffective
{
    public static bool ProfileEq(D p, D q) => Actions.Leq(p, q) && Actions.Leq(q, p);

    public static List<string> ImpliedTraits(D n)
    {
        var ps = ((D)n["params"]!).Values.Select(v => (D)v!).ToList();
        return Actions.ImpliedFromFacts(Ak.Strs(n["effects"]), ps, (string)((D)n["resource"]!)["scope"]!, Actions.WorstReversibility(n["reversibility"], ((D)n["params"]!).ToDictionary(kv => kv.Key, kv => (D)kv.Value!)));
    }

    /// <summary>True iff the caller's verifier says the def carries a valid signed review. Absent: never.</summary>
    public static bool IsConfirmed(D d, Func<D, bool>? attestationVerified = null) => attestationVerified != null && attestationVerified(d);

    public static List<string> TraitsOfWith(D d, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null) =>
        IsConfirmed(d, attestationVerified) ? Actions.HintTraits(d) : Actions.TopTraits(reg);

    static D View(Dictionary<string, D> reg, D decl, List<string> traits)
    {
        var floor = Actions.FloorOf(reg, traits);
        return new D { ["traits"] = Ak.ToL(traits), ["closure"] = Ak.ToL(Actions.Closure(reg, traits)), ["floor"] = floor, ["eff"] = Actions.Join(decl, floor) };
    }

    /// <summary>{traits, closure, floor, eff, confirmed, decl, hint:{traits,closure,floor,eff}, clamps}.</summary>
    public static D EffectiveWith(D d, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null)
    {
        var decl = Actions.DeclProfile(d);
        var hint = View(reg, decl, Actions.HintTraits(d));
        var confirmed = IsConfirmed(d, attestationVerified);
        var main = confirmed ? hint : View(reg, decl, Actions.TopTraits(reg));
        var clamps = new L();
        var hf = (D)hint["floor"]!;
        if (d.ContainsKey("reversibility") && Ak.RevRank((string)decl["rev"]!) < Ak.RevRank((string)hf["rev"]!))
            clamps.Add(new D { ["field"] = "rev", ["declared"] = decl["rev"], ["floor"] = hf["rev"] });
        if (d.ContainsKey("blast") && Ak.I(decl["blast_ppm"]) < Ak.I(hf["blast_ppm"]))
            clamps.Add(new D { ["field"] = "blast_ppm", ["declared"] = decl["blast_ppm"], ["floor"] = hf["blast_ppm"] });
        var o = new D(main) { ["confirmed"] = confirmed, ["decl"] = decl, ["hint"] = hint, ["clamps"] = clamps };
        return o;
    }

    /// <summary>The hint profile after adding trait <paramref name="t"/> to the declared traits (never lower). Analysis only.</summary>
    public static D EffWithTrait(D d, string t, Dictionary<string, D> reg)
    {
        var d2 = new D(d);
        var tr = d.TryGetValue("traits", out var x) && x is L l ? new L(l) : new L();
        tr.Add(t);
        d2["traits"] = tr;
        return (D)((D)EffectiveWith(d2, reg)["hint"]!)["eff"]!;
    }

    /// <summary>Structural param rules (among <paramref name="ids"/>) the def violates.</summary>
    public static List<string> PrulesViolations(D d, IEnumerable<string>? ids = null)
    {
        var n = Actions.Normalize(d);
        var pm = (D)n["params"]!;
        var ps = pm.Values.Select(v => (D)v!).ToList();
        var res = (D)n["resource"]!;
        List<D> WithRole(Func<string, bool> pred) => ps.Where(p => p.TryGetValue("role", out var r) && r is string rs && pred(rs)).ToList();
        bool MoneyOk(D p)
        {
            if (Ak.G(p, "unit") is not D u || Ak.S(u, "kind") != "money") return false;
            var ccy = Ak.G(u, "ccy");
            if (ccy is string) return true;
            var c = ccy is D cd && Ak.G(cd, "from") is string f && pm.TryGetValue(f, out var cv) ? (D?)cv : null;
            return c != null && Ak.S(c, "role") == "money.currency" && Ak.S(c, "format") == "iso_currency";
        }
        var bad = new List<string>();
        foreach (var rid in ids ?? Ak.ParamRuleIds)
        {
            var ok = true;
            switch (rid)
            {
                case "money_has_currency": ok = WithRole(r => r is "money.amount" or "money.fee").All(MoneyOk); break;
                case "money_amount_bounded": ok = WithRole(r => r == "money.amount").All(p => Ak.S(p, "type") == "integer" && p.ContainsKey("min") && p.ContainsKey("max")); break;
                case "id_not_wildcard": ok = !(Ak.G(res, "id") is string rid0 && rid0 == "*" && Ak.S(res, "scope") == "one"); break;
                case "recipient_param_declared": ok = Ak.S(n, "audience") == "resource" || WithRole(r => r == "party.payee" || r.StartsWith("contact.", StringComparison.Ordinal)).Count > 0; break;
                case "array_bounded": ok = ps.Where(p => Ak.S(p, "type") == "array").All(p => Ak.G(p, "max_items") != null); break;
                case "export_bounded": ok = Ak.S(res, "scope") == "one" || WithRole(r => r == "count.limit").Any(p => p.ContainsKey("max")); break;
                case "secret_not_logged": ok = WithRole(r => r.StartsWith("credential.", StringComparison.Ordinal)).All(p => Ak.Strs(Ak.G(p, "tags")).Contains("secret")); break;
                case "pay_has_idempotency": ok = !Ak.Strs(n["effects"]).Contains("pay") || Ak.S(n["idempotency"], "mode") != "none"; break;
            }
            if (!ok) bad.Add(rid);
        }
        return bad;
    }

    public static List<string> RequiredPrulesViolated(D d, D eff) => PrulesViolations(d, Ak.Strs(eff["prules"]));
}
