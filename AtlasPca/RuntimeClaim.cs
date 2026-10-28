// Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class. Valid
// only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
// verifiedEvidence), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is "none". Total.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public static class RuntimeClaim
{
    public const string Domain = "atlas-pca/runtime-class-claim/v1\0";
    static readonly string[] Classes = { "none", "os_confined", "egress_default_deny", "wasi_no_ambient" };
    static readonly string[] Keys = { "v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    public static string VerifiedClass(object? v, IReadOnlyList<string> pinnedAttestors, string passportDigest, IReadOnlyList<string> verifiedEvidence, object? now)
    {
        try
        {
            if (v is not JD c || c.Count != Keys.Length || !Keys.All(c.ContainsKey)) return "none";
            if (!Pca.SafeNat(c["v"], out var one) || one != 1) return "none";
            if (c["class"] is not string cls || !Classes.Contains(cls)) return "none";
            if (!Str(c["attestor"], 128) || !Str(c["passport_digest"], 128) || !Str(c["evidence_digest"], 128)) return "none";
            if (!Pca.SafeNat(c["iat"], out var iat) || !Pca.SafeNat(c["exp"], out var exp) || !Pca.SafeNat(now, out var t)) return "none";
            var attestor = (string)c["attestor"]!;
            if (!pinnedAttestors.Contains(attestor) || (string)c["passport_digest"]! != passportDigest || !verifiedEvidence.Contains((string)c["evidence_digest"]!)) return "none";
            if (!(iat <= t && t < exp)) return "none";
            var body = new JD();
            foreach (var kv in c) if (kv.Key != "sig") body[kv.Key] = kv.Value;
            return Pca.VerifyDomain(Domain, body, attestor, c["sig"]) ? cls : "none";
        }
        catch (Exception)
        {
            return "none";
        }
    }
}
