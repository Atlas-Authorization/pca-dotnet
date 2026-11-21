// Undo windows over action definitions, the structural half: the reversibility class for concrete params, may-be-reversible and
// the compensation shape (can one action undo another without the agent's help).
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionUndo
{
    /// <summary>The class of a reversibility declaration for concrete params (an unmapped or absent value takes the default, else irreversible).</summary>
    public static string ReversibilityFor(D d, D parameters)
    {
        var r = Actions.Normalize(d)["reversibility"];
        if (r is string rs) return rs;
        var by = (string)Ak.G(r, "by")!;
        var v = parameters.TryGetValue(by, out var pv) ? pv : null;
        string? k = v switch
        {
            string s => s,
            bool b => b ? "true" : "false",
            _ when IntentJs.IsSafeInteger(v) && !IntentJs.IsNegZero(IntentJs.NumOf(v)!.Value) => ((long)IntentJs.NumOf(v)!.Value).ToString(CultureInfo.InvariantCulture),
            _ => null,
        };
        var map = (D)Ak.G(r, "map")!;
        if (k != null && map.TryGetValue(k, out var m)) return (string)m!;
        return Ak.G(r, "default") as string ?? "irreversible";
    }

    /// <summary>True when some value of the declaration is reversible (a fixed class, a map value or the default).</summary>
    public static bool MayBeReversible(D d)
    {
        if (!d.TryGetValue("reversibility", out var r) || r == null) return false;
        if (r is string s) return s == "reversible";
        return ((D)Ak.G(r, "map")!).Values.Any(v => v is string x && x == "reversible") || Ak.G(r, "default") is string dv && dv == "reversible";
    }

    static bool SameType(object? a, D b)
    {
        if (a is not D ad || Ak.S(ad, "type") != Ak.S(b, "type")) return false;
        var x = Ak.G(ad, "items"); var y = Ak.G(b, "items");
        return x == null ? y == null : x is string xs && y is string ys && xs == ys;
    }

    /// <summary>{ok:true, shape:{copied, target?}} or {ok:false, reason}. Structural only.</summary>
    public static D CompensationShape(D orig, D comp)
    {
        var compVerb = (string)comp["verb"]!;
        if (Ak.IsReadOnly(Ak.Strs(comp["effects"]))) return new D { ["ok"] = false, ["reason"] = $"the compensating action {compVerb} only reads" };
        var ct = (string)((D)comp["resource"]!)["type"]!;
        var ot = (string)((D)orig["resource"]!)["type"]!;
        if (ct != ot) return new D { ["ok"] = false, ["reason"] = $"the compensating action {compVerb} acts on {ct}, not {ot}" };
        var nc = Actions.Normalize(comp);
        var copied = new L();
        string? target = null;
        var idem = (D)nc["idempotency"]!;
        var idemParam = Ak.S(idem, "mode") == "key_param" ? Ak.S(idem, "param") : null;
        var origParams = (D)orig["params"]!;
        foreach (var name in ((D)nc["params"]!).Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var p = (D)((D)nc["params"]!)[name]!;
            if (name == idemParam) continue;
            if (SameType(origParams.GetValueOrDefault(name), p)) { copied.Add(name); continue; }
            if (!(p["required"] is bool rq && rq)) continue;
            if (Ak.S(p, "role") == "id." + ct && target == null) { target = name; continue; }
            return new D { ["ok"] = false, ["reason"] = $"the compensating action {compVerb} needs '{name}', which neither the original call nor its result supplies" };
        }
        var shape = new D { ["copied"] = copied };
        if (target != null) shape["target"] = target;
        return new D { ["ok"] = true, ["shape"] = shape };
    }
}
