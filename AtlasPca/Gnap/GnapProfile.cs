using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gnap;

/// <summary>The Agent-GNAP profile as a machine-readable spec object.</summary>
static class GnapProfile
{
    static D O(params object?[] kv)
    {
        var d = new D();
        for (int i = 0; i < kv.Length; i += 2) d[(string)kv[i]!] = kv[i + 1];
        return d;
    }

    static L Ls(params object?[] xs) => new(xs);

    internal static D Profile() => O(
        "name", "agent-gnap",
        "version", "1.0",
        "rfc", "RFC 9635",
        "summary", "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
        "mapping", Ls(
            O("gnap", "access[].type", "pca", "predicate resource namespace gnap:<type>:<location>", "note", "the resource family the rights live in"),
            O("gnap", "access[].actions", "pca", "predicate.verb (list, or * for any)", "note", "the operations permitted"),
            O("gnap", "access[].locations", "pca", "predicate.resource (exact or trailing-* prefix)", "note", "the resource targets"),
            O("gnap", "access[].datatypes / identifier", "pca", "predicate.where on action.params.*", "note", "value-level constraints"),
            O("gnap", "client.key.jwk (OKP/Ed25519)", "pca", "capability.holder (cnf-bound key)", "note", "the proof-of-possession key"),
            O("gnap", "grant request (no prior grant)", "pca", "mintGrant → root capability", "note", "envelope predicates = requested access"),
            O("gnap", "grant request (delegated hop)", "pca", "delegate → child capability + gnap_access caveat", "note", "append-only attenuation"),
            O("gnap", "access_token (§3.2)", "pca", "a verifiable PCA capability chain (encodeBoundToken)", "note", "bound, self-verifying token"),
            O("gnap", "continue (§3.1) + interact (§3.3)", "pca", "PCA step-up: FROST/threshold co-signature folded into a PCActn", "note", "tier-2/3 escalation"),
            O("gnap", "jwsd detached JWS (§7.3.4)", "pca", "request proof binding the body to capability.holder", "note", "verified with jose")),
        "proofMethods", Ls("jwsd"),
        "multiHop", "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA caveats are conjunctive and append-only, so no hop can widen — \"never wider than the issuer\" holds across any depth.",
        "stepUp", "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or multi-signature) before the action is admitted.",
        "security", Ls(
            "Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
            "Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
            "All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
            "Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
            "Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant."));
}
