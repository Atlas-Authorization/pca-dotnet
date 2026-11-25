// The undo-window engine over action definitions, gated by confirmation: reversibility counts only when it is CONFIRMED (a valid signed review
// by a pinned reviewer key), its effective class and the class for THESE params are reversible, and it names a compensating action that is itself
// confirmed and can be derived before the effect runs. Anything else is irreversible. The compensating call is derived, never authored by the agent.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionUndoEngine
{
    /// <summary>The callback the algebra takes: a confirmed def counts only if its attestation verifies under the pinned reviewer keys.</summary>
    public static Func<D, bool> AttestationVerifier(object? pins, Dictionary<string, D> reg) => d => Actions.AttestationError(d, reg, pins) == null;

    /// <summary>plan(op) answers {def_digest, compensation, render, render_digest} or null. Answers only from CONFIRMED definitions (no pins: nothing is undoable),
    /// exact verb match only. Never throws: anything undecidable is not undoable.</summary>
    public static Func<D, D?> UndoEngine(IEnumerable<D> defs, object? pins, Dictionary<string, D>? registry = null)
    {
        var reg = registry ?? Actions.CoreRegistry;
        var byVerb = new Dictionary<string, D>();
        foreach (var d in defs) byVerb.TryAdd((string)d["verb"]!, d);
        var review = pins == null ? null : AttestationVerifier(pins, reg);
        bool Confirmed(D d)
        {
            try { return ActionEffective.IsConfirmed(d, review); } catch (Exception) { return false; }
        }
        return op =>
        {
            try
            {
                if (!byVerb.TryGetValue((string)op["verb"]!, out var d)) return null;
                var parameters = op.GetValueOrDefault("params") is D pd ? pd : new D();
                if (!Confirmed(d) || Ak.IsReadOnly(Ak.Strs(d["effects"])) || Ak.G(d, "compensates") == null) return null;
                var eff = (D)ActionEffective.EffectiveWith(d, reg, review)["eff"]!;
                if ((string)eff["rev"]! != "reversible" || ActionUndo.ReversibilityFor(d, parameters) != "reversible") return null;
                if (!byVerb.TryGetValue((string)d["compensates"]!, out var c) || !Confirmed(c)) return null;
                var s = ActionUndo.CompensationShape(d, c);
                if (s["ok"] is not true) return null;
                var shape = (D)s["shape"]!;
                var cparams = new D();
                var nc = Actions.Normalize(c);
                foreach (var ko in (L)shape["copied"]!)
                {
                    var k = (string)ko!;
                    if (parameters.TryGetValue(k, out var pv)) cparams[k] = Ak.Copy(pv);
                    else if (((D)((D)nc["params"]!)[k]!)["required"] is true) return null; // the call left out what the undo needs
                }
                var render = ActionApprovals.RenderApproval(d, parameters, review);
                var comp = new D { ["verb"] = c["verb"], ["params"] = cparams, ["def_digest"] = Actions.DefDigest(c) };
                if (shape.ContainsKey("target")) comp["target_param"] = shape["target"];
                return new D { ["def_digest"] = Actions.DefDigest(d), ["compensation"] = comp, ["render"] = render, ["render_digest"] = Approval.RenderDigest(render) };
            }
            catch (Exception) { return null; }
        };
    }
}
