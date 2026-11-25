// The signing half of action pins and the registry's signed evolution records of the reference (action-pin.ts): the constants, signing a registry document under a domain, signing an evolution record, the registry
// key entry and the principal's re-approval of a widening step, with the verify side as the reference's verdict forms. The verification itself and the pin decision are Actions.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ActionPinOps
{
    public const int MaxEvolutionSteps = 32;
    public const int MaxEscTier = 3;

    static L Strs(params string[] xs) => xs.Cast<object?>().ToList();

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new()
    {
        ["ACTION_PIN_ON_NEW"] = Strs("deny", "escalate"), ["EVOLUTION_CLASSES"] = Strs("equal", "narrow", "widen", "incomparable", "added", "removed"), ["EVOLUTION_RECORD_KIND"] = Actions.EvolutionRecordKind,
        ["REAPPROVAL_KIND"] = Actions.ReapprovalKind, ["EVOLUTION_DOMAIN"] = Actions.EvolutionDomain, ["EVOLUTION_DIFF_DOMAIN"] = Actions.EvolutionDiffDomain, ["REAPPROVAL_DOMAIN"] = Actions.ReapprovalDomain,
        ["MAX_EVOLUTION_STEPS"] = IntentJs.OfLong(MaxEvolutionSteps), ["MAX_ESC_TIER"] = IntentJs.OfLong(MaxEscTier),
    };

    /// <summary>Sign <c>domain || strictCanonical(body)</c> as a registry key: <c>{alg, kid, value, pq_value?}</c> (<c>kid</c> names the pinned key entry). <paramref name="alg"/> null is ed25519, another suite needs its PQ key
    /// in <paramref name="keys"/>. Throws on a body the strict canonical form refuses and on an unknown alg.</summary>
    public static D SignRegistryDoc(string domain, object? body, string kid, byte[] registrySecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"signWithSuite: unknown signature alg '{alg}'");
        var parts = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(registrySecret, keys), IntentJs.Message(domain, body));
        var sig = new D { ["alg"] = resolved, ["kid"] = kid, ["value"] = parts.Sig };
        if (parts.PqSig != null) sig["pq_value"] = parts.PqSig;
        return sig;
    }

    /// <summary>Sign an evolution record as the registry: <c>{...record, sig}</c>. An invalid unsigned record is never signed (throws).</summary>
    public static D SignEvolutionRecord(D record, string kid, byte[] registrySecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var bad = Actions.EvolutionRecordError(record, signed: false);
        if (bad != null) throw new InvalidOperationException("signEvolutionRecord: " + bad);
        return new D(record) { ["sig"] = SignRegistryDoc(Actions.EvolutionDomain, record, kid, registrySecret, alg, keys) };
    }

    /// <summary>The registry key entry <c>{kid, alg, pk, pq_pk?}</c> of a signer.</summary>
    public static D RegistryKeyOf(string kid, byte[] registrySecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"registryKeyOf: unknown signature alg '{alg}'");
        using var k = EdKey.FromSeed(registrySecret);
        var o = new D { ["kid"] = kid, ["alg"] = resolved, ["pk"] = k.Id };
        if (PqSuites.SuitePqPublicKey(resolved, keys) is { } pq) o["pq_pk"] = pq;
        return o;
    }

    /// <summary>The principal approves one evolution step for one grant: <c>{v, kind, grant, verb, diff, sig: {alg: "ed25519", value}}</c>, bound to the grant id and the diff digest of the record (signed or not).</summary>
    public static D SignReapproval(string grantId, D record, byte[] principalSecret)
    {
        var body = new D { ["v"] = IntentJs.OfLong(1), ["kind"] = Actions.ReapprovalKind, ["grant"] = grantId, ["verb"] = record.GetValueOrDefault("verb"), ["diff"] = Actions.EvolutionDiffDigest(record) };
        var parts = PqSuites.SignSuiteArtifact(null, PqSuites.SuiteKeysOf(principalSecret, null), IntentJs.Message(Actions.ReapprovalDomain, body));
        return new D(body) { ["sig"] = new D { ["alg"] = "ed25519", ["value"] = parts.Sig } };
    }

    static D Verdict(string? reason) => reason == null ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = reason };

    /// <summary>The verdict form of <see cref="Actions.VerifyRegistrySig"/>: <c>{ok}</c> or <c>{ok: false, reason}</c>.</summary>
    public static D VerifyRegistrySig(string domain, D body, D sig, object? keys) => Verdict(Actions.VerifyRegistrySig(domain, body, sig, keys));

    /// <summary>The verdict form of <see cref="Actions.VerifyEvolutionRecord"/>.</summary>
    public static D VerifyEvolutionRecord(object? record, object? keys) => Verdict(Actions.VerifyEvolutionRecord(record, keys));
}
