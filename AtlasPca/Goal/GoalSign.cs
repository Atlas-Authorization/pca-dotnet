using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;

/// <summary>The one signer of the goal-to-decision flow: approvals, test sets, policy pins and precedents are artifacts signed with the
/// suite-agile artifact signer under a per-kind domain, over strict canonical bytes.</summary>
public static class GoalSign
{
    /// <summary>Domain separation: an artifact of one kind never verifies as another kind.</summary>
    public static string GoalDomain(string kind) => "atlas-pca/goal/" + kind + "/v1\0";

    /// <summary>The pinned public identity (b64u Ed25519) of a signing key.</summary>
    public static string SignerId(EdKey key) => key.Id;

    /// <summary>The pinned public identity of a 32-byte Ed25519 seed.</summary>
    public static string SignerId(byte[] seed) => EdKey.FromSeed(seed).Id;

    /// <summary>Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body.</summary>
    public static D SignGoalArtifact(string kind, D body, SuiteKey signer) => Issue.SignArtifact(GoalDomain(kind), body, signer);

    public static D SignGoalArtifact(string kind, D body, byte[] seed) => SignGoalArtifact(kind, body, SuiteKey.Ed25519(EdKey.FromSeed(seed)));

    /// <summary>Suite capability and shape of an artifact's suite members; null = usable.</summary>
    internal static string? ArtifactSuiteError(D a) => IntentArtifacts.ArtifactSuiteError(a);

    /// <summary>Verify a signed artifact against the caller's PINNED signers (each a b64u key string or a map {pk, pq_pk}): the pin whose
    /// pk equals the artifact's own signerField member must verify. Total: false on anything malformed.</summary>
    public static bool VerifyGoalArtifact(string kind, object? artifact, string signerField, IEnumerable<object?> pins)
    {
        try
        {
            if (artifact is not D a) return false;
            if (ArtifactSuiteError(a) != null) return false;
            if (a.get(signerField) is not string who) return false;
            object? pin = null;
            bool found = false;
            foreach (var p in pins)
            {
                object? pk = p is string ? p : G.get(p, "pk");
                if (pk is string ps && ps == who) { pin = p; found = true; break; }
            }
            if (!found) return false;
            return VerifyArtifactSig(GoalDomain(kind), a, pin);
        }
        catch (Exception) { return false; }
    }

    /// <summary>The artifact's signature under a PINNED signer (a b64u key string or a map {pk, pq_pk?}); the caller has checked the
    /// suite members. Ed25519 under pk; any other suite only when the artifact's pq_pk equals the pin's. Total.</summary>
    public static bool VerifyArtifactSig(string domain, D a, object? pin)
    {
        try
        {
            object? pk = pin is string ? pin : G.get(pin, "pk");
            if (a.get("sig") is not string || pk is not string) return false;
            object? pinPq = pin is D pd ? pd.get("pq_pk") : null;
            return IntentArtifacts.VerifyArtifactSig(domain, a, pk, pinPq is string ? pinPq : null);
        }
        catch (Exception) { return false; }
    }

    /// <summary>A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents.</summary>
    public static D SignPayload(string kind, object? payload, EdKey key, SuiteKey suite) =>
        SignGoalArtifact(kind, G.map("v", G.num(1), "kind", kind, "signer", key.Id, "payload", payload), suite);

    public static D SignPayload(string kind, object? payload, byte[] seed)
    {
        var key = EdKey.FromSeed(seed);
        return SignPayload(kind, payload, key, SuiteKey.Ed25519(key));
    }

    public static bool VerifyPayload(D? s, string kind, IEnumerable<object?> pins) =>
        s != null && G.safeInt(s.get("v")) == 1 && s.get("kind") is string k && k == kind && VerifyGoalArtifact(kind, s, "signer", pins);
}
