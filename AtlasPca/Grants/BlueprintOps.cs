// Blueprint operations beyond verification: the group kill, the attestation-gated admission registry and the admission decision over
// adapter evidence (packages/pca-grants blueprint.ts groupKill and blueprint-admission.ts). Hardware evidence verification is the Attest namespace.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary>Thrown by an evidence provider; <c>ErrorName</c> is the reference's error name that is reported as the <c>reason</c> of a verifier_error.</summary>
public sealed class EvidenceException : Exception
{
    public string ErrorName { get; }
    public EvidenceException(string errorName, string message) : base(message) { ErrorName = errorName; }
}

public static class Blueprints
{
    /// <summary>GROUP KILL: the operator signs the blueprint as <c>disabled</c> at the next epoch; the registry accepts it, the key is revoked as an issuer
    /// (<paramref name="revokeIssuer"/> gets <c>{kind, value, reason, revokedAt}</c>) and the consistency issuer's revocation_epoch is advanced
    /// (<paramref name="advanceFreshAt"/> gets the epoch and returns the token). Returns <c>{ok: true, record, freshAt?}</c> or <c>{ok: false, code}</c>.</summary>
    public static JD GroupKill(EdKey key, BlueprintRegistry registry, string blueprintKey, object? now, string? reason = null,
        Action<JD>? revokeIssuer = null, Func<long, JD>? advanceFreshAt = null)
    {
        var cur = registry.Get(blueprintKey);
        if (cur == null) return new JD { ["ok"] = false, ["code"] = "unknown_blueprint" };
        var next = G.Without(cur, "sig", "operator", "v");
        next["status"] = "disabled";
        next["epoch"] = G.N(G.L(cur["epoch"]) + 1);
        next["issued_at"] = now;
        var record = GrantSigning.SignBlueprint(key, next);
        var r = registry.Accept(record);
        if (!r.Ok) return new JD { ["ok"] = false, ["code"] = r.Code };
        revokeIssuer?.Invoke(new JD { ["kind"] = "issuer", ["value"] = blueprintKey, ["reason"] = reason ?? "blueprint disabled (group kill)", ["revokedAt"] = now });
        var res = new JD { ["ok"] = true, ["record"] = record };
        if (advanceFreshAt != null) res["freshAt"] = advanceFreshAt(G.L(record["epoch"]));
        return res;
    }

    /// <summary>ATTESTATION-GATED ADMISSION: a blueprint with <c>runtime_pins</c> admits an instance only after a hardware verifier verified the evidence for
    /// the expected binding and the MEASURED identity matched a pin. No pins, no evidence, a verifier answer that is not ok and bound, no measurement or no
    /// matching pin all deny; the identity compared is the verifier's measurement, never the document's own claims.</summary>
    public static JD AdmitBlueprintInstance(JD blueprint, JD? document, IVendorVerifier verifier, AttestationBinding expected, long nowMs)
    {
        if (G.Get(blueprint, "runtime_pins") is not JL pins || pins.Count == 0) return new JD { ["admitted"] = false, ["code"] = "no_pins" };
        if (document == null) return new JD { ["admitted"] = false, ["code"] = "not_ok", ["reason"] = "no evidence" };
        return AdmitWithEvidence(blueprint, () =>
        {
            var h = verifier.Verify(document, expected, nowMs);
            var r = new JD { ["ok"] = h.Ok, ["bound"] = h.Bound };
            if (h.Measured != null) r["identity"] = h.Measured;
            if (h.Reason != null) r["reason"] = h.Reason;
            return r;
        });
    }

    /// <summary>Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under, so a group kill or any new record invalidates them.</summary>
    public sealed class AdmissionRegistry
    {
        readonly Dictionary<string, (long Epoch, long Until)> m = new(StringComparer.Ordinal);
        static string K(string bpKey, string instance) => bpKey + "\0" + instance;

        /// <summary>Record an admission made under <paramref name="bp"/> (its epoch) valid until <paramref name="until"/> (epoch ms).</summary>
        public void Admit(string instanceKey, JD bp, long until) => m[K((string)bp["key"]!, instanceKey)] = (G.L(bp["epoch"]), until);

        public bool Revoke(string instanceKey, string bpKey) => m.Remove(K(bpKey, instanceKey));

        /// <summary>A function for <see cref="Blueprint.Check"/>'s <c>admitted</c>: true only for an unexpired admission made under the record's current epoch.</summary>
        public Func<string, JD, bool> Checker(long now) => (k, bp) => m.TryGetValue(K((string)bp["key"]!, k), out var a) && a.Epoch == G.L(bp["epoch"]) && now < a.Until;
    }

    static bool StrictEq(object? a, object? b) => a switch
    {
        string s => b is string t && s == t,
        bool x => b is bool y && x == y,
        Num n => b is Num p && IntentJs.NormNum(n.Raw).Raw == IntentJs.NormNum(p.Raw).Raw,
        _ => false,
    };

    static bool PinMatches(object? pin, object? id) =>
        pin is JD p && p.Count > 0 && p.All(kv => kv.Value != null && id is JD d && d.TryGetValue(kv.Key, out var v) && StrictEq(v, kv.Value));

    /// <summary>Admit from adapter evidence. <c>ok</c> and <c>bound</c> must both be exactly true, and the identity the adapter established must equal one pin
    /// in every member. A provider that throws, a malformed result, no identity or no matching pin all deny.</summary>
    public static JD AdmitWithEvidence(JD blueprint, Func<object?> getEvidence)
    {
        static JD No(string code, string? reason = null)
        {
            var o = new JD { ["admitted"] = false, ["code"] = code };
            if (reason != null) o["reason"] = reason;
            return o;
        }
        if (G.Get(blueprint, "runtime_pins") is not JL pins || pins.Count == 0) return No("no_pins");
        object? r;
        try { r = getEvidence(); }
        catch (Exception e) { return No("verifier_error", e is EvidenceException ee ? ee.ErrorName : "Error"); }
        if (G.Get(r, "ok") is not true) return No("not_ok", G.Get(r, "reason") as string);
        if (G.Get(r, "bound") is not true) return No("not_bound");
        var identity = G.Get(r, "identity");
        if (identity is not (JD or JL)) return No("no_identity");
        var pin = pins.FirstOrDefault(p => PinMatches(p, identity));
        return pin != null ? new JD { ["admitted"] = true, ["identity"] = identity, ["pin"] = pin } : No("no_matching_pin");
    }
}
