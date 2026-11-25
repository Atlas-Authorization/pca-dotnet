using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Constitution invariants projected onto policy vetoes (the per-action ones); windowed and history ones are reported unmodeled.</summary>
public static class Constitution
{
    /// <summary>vetoesFromConstitution: {vetoes, unmodeled}. A null element of invariants throws (the reference TypeError).</summary>
    public static D VetoesFromConstitution(object? c)
    {
        var vetoes = new L(); var unmodeled = new L();
        var invs = Jx.Opt(c, "invariants");
        if (invs is L list)
        {
            foreach (var inv in list)
            {
                var kind = Jx.Prop(inv, "kind");
                var id = Jx.Prop(inv, "id");
                switch (kind as string)
                {
                    case "never":
                    {
                        var v = new D(); Jx.Set(v, "id", id); v["kind"] = "deny"; Jx.Set(v, "when", Jx.Prop(inv, "when"));
                        vetoes.Add(v); break;
                    }
                    case "never_unless":
                    {
                        var v = new D(); Jx.Set(v, "id", id); v["kind"] = "deny"; Jx.Set(v, "when", Jx.Prop(inv, "when")); Jx.Set(v, "unless", Jx.Prop(inv, "unless"));
                        vetoes.Add(v); break;
                    }
                    case "require_approval_over":
                    {
                        var over = new D(); Jx.Set(over, "path", Jx.Prop(inv, "amount")); Jx.Set(over, "threshold", Jx.Prop(inv, "threshold"));
                        var v = new D(); Jx.Set(v, "id", id); v["kind"] = "approval"; Jx.Set(v, "when", Jx.Prop(inv, "when")); v["over"] = over; Jx.Set(v, "unless", Jx.Prop(inv, "approved"));
                        vetoes.Add(v); break;
                    }
                    case "cap":
                    case "rate":
                    {
                        var u = new D(); Jx.Set(u, "id", id); u["kind"] = kind; u["reason"] = "windowed total: bounded by maxExposure, not by a per-action veto";
                        unmodeled.Add(u); break;
                    }
                    default:
                    {
                        var u = new D(); Jx.Set(u, "id", id); Jx.Set(u, "kind", kind); u["reason"] = "needs action history";
                        unmodeled.Add(u); break;
                    }
                }
            }
        }
        return new D { ["vetoes"] = vetoes, ["unmodeled"] = unmodeled };
    }
}
