using System.Security.Cryptography;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.FheParts;

/// <summary>
/// Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to one action, the
/// gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the policy and a replay guard
/// BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate output it opened.
/// </summary>
public static class FheOrigin
{
    const string ClaimDomain = "atlas-pca-fhe/signed-claim/v1\0";
    const string VerdictDomain = "atlas-pca-fhe/verdict-attestation/v1\0";
    const int NonceBytes = 16;
    const int MaxContextLen = 512;

    static byte[] Prefixed(string domain, object? body) => Encoding.UTF8.GetBytes(domain + Pca.Canonicalize(body));
    static string BytesDigest(string s) => Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    static bool IsObject(object? o) => o is D or L;

    static byte[] ClaimStatement(D claim, string context, string nonce, string signer) => Prefixed(ClaimDomain, new D
    {
        ["v"] = IntentJs.OfLong(1), ["context"] = context, ["nonce"] = nonce, ["signer"] = signer, ["binding"] = claim.GetValueOrDefault("binding"),
        ["policy"] = Pca.HashCanonical(claim.GetValueOrDefault("policy")), ["enc_inputs"] = BytesDigest((string)claim["encInputs"]!),
    });

    /// <summary>The content digest of a signed claim (what the key holder's attestation commits to).</summary>
    public static string SignedClaimDigest(object? signed) => Pca.HashCanonical(signed);

    static EdKey Key(byte[] sk) => sk is { Length: 32 } ? EdKey.FromSeed(sk) : throw new ArgumentException("signing key must be a 32-byte Ed25519 secret key");

    /// <summary>Signs an encrypted risk claim; the nonce is fresh random unless supplied (tests, replay of recorded vectors). An all-zero nonce is refused as an RNG failure.</summary>
    public static D SignRiskClaim(D claim, byte[] signerSecretKey, string context, byte[]? nonce = null)
    {
        if (string.IsNullOrEmpty(context) || context.Length > MaxContextLen) throw new ArgumentException($"context must be a non-empty string of at most {MaxContextLen} characters");
        nonce ??= RandomNumberGenerator.GetBytes(NonceBytes);
        if (nonce.All(b => b == 0)) throw new InvalidOperationException("signRiskClaim: random source returned all zeros (RNG failure)");
        using var k = Key(signerSecretKey);
        var n = Pca.B64u(nonce); var signer = k.Id;
        return new D { ["claim"] = claim, ["context"] = context, ["nonce"] = n, ["signer"] = signer, ["sig"] = Pca.B64u(k.Sign(ClaimStatement(claim, context, n, signer))) };
    }

    /// <summary>A bounded set of nonces already seen; Claim(key) is false when the key was seen or the window is full.</summary>
    public static Func<string, bool> MemoryNonceGuard(int maxEntries = 100_000)
    {
        var seen = new HashSet<string>();
        return key => !seen.Contains(key) && seen.Count < maxEntries && seen.Add(key);
    }

    /// <summary>What the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate policy and the replay guard.</summary>
    public sealed record ClaimExpectations(IReadOnlyList<string> TrustedSigners, string Context, object? Binding, object? Policy, Func<string, bool> Nonces);

    /// <summary>ok with the claim and its digest, or not ok with a reason.</summary>
    public sealed record ClaimCheck(bool Ok, D? Claim, string? Digest, string? Reason);

    static ClaimCheck Fail(string reason) => new(false, null, null, reason);

    /// <summary>Verifies a signed claim; never throws (a malformed or hostile input is a not-ok result).</summary>
    public static ClaimCheck VerifySignedRiskClaim(object? s, ClaimExpectations exp)
    {
        try
        {
            if (s is not D c) return Fail("claim is not signed: malformed envelope");
            if (c.GetValueOrDefault("context") is not string context || c.GetValueOrDefault("nonce") is not string nonce || c.GetValueOrDefault("signer") is not string signer
                || c.GetValueOrDefault("sig") is not string sig || c.GetValueOrDefault("claim") is not D claim || claim.GetValueOrDefault("encInputs") is not string
                || !IsObject(claim.GetValueOrDefault("binding")) || !IsObject(claim.GetValueOrDefault("policy")))
                return Fail("claim is not signed: malformed envelope");
            if (Pca.B64uDecode(nonce, NonceBytes) == null) return Fail("malformed nonce");
            var signerBytes = Pca.B64uDecode(signer, 32); var sigBytes = Pca.B64uDecode(sig, 64);
            if (signerBytes == null || sigBytes == null) return Fail("malformed signer key or signature");
            if (!exp.TrustedSigners.Contains(signer)) return Fail("signer is not a trusted encryptor");
            if (!Pca.VerifyEd25519Strict(signerBytes, ClaimStatement(claim, context, nonce, signer), sigBytes))
                return Fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)");
            if (context != exp.Context) return Fail("context mismatch: claim was signed for a different grant/policy");
            if (Pca.HashCanonical(claim["binding"]) != Pca.HashCanonical(exp.Binding)) return Fail("binding mismatch: claim is bound to a different action");
            if (Pca.HashCanonical(claim["policy"]) != Pca.HashCanonical(exp.Policy)) return Fail("policy mismatch: claim was signed for a different gate policy");
            if (!exp.Nonces(signer + ":" + nonce)) return Fail("replay: nonce already used (or the replay window is full)");
            return new ClaimCheck(true, claim, SignedClaimDigest(s), null);
        }
        catch (Exception) { return Fail("claim could not be verified (malformed)"); }
    }

    static byte[] VerdictStatement(string claimDigest, object? gateDigest, bool admit, string holder) => Prefixed(VerdictDomain, new D
    {
        ["v"] = IntentJs.OfLong(1), ["claim"] = claimDigest, ["gate"] = gateDigest, ["admit"] = admit, ["holder"] = holder,
    });

    /// <summary>The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output.</summary>
    public static D AttestVerdict(byte[] holderSecretKey, D signed, D gate, bool admit)
    {
        var gateDigest = new D { ["encRiskRaw"] = BytesDigest((string)gate["encRiskRaw"]!), ["encSlack"] = BytesDigest((string)gate["encSlack"]!) };
        var claimDigest = SignedClaimDigest(signed);
        using var k = Key(holderSecretKey);
        var holder = k.Id;
        return new D
        {
            ["claimDigest"] = claimDigest, ["gateDigest"] = gateDigest, ["admit"] = admit, ["holder"] = holder,
            ["sig"] = Pca.B64u(k.Sign(VerdictStatement(claimDigest, gateDigest, admit, holder))),
        };
    }

    /// <summary>ok with the attested admit bit, or not ok with a reason.</summary>
    public sealed record AttestationCheck(bool Ok, bool Admit, string? Reason);

    static AttestationCheck AFail(string reason) => new(false, false, reason);

    /// <summary>Verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output.</summary>
    public static AttestationCheck VerifyVerdictAttestation(object? a, IReadOnlyList<string> trustedHolders, string claimDigest, D? gate)
    {
        try
        {
            if (a is not D x) return AFail("malformed attestation");
            if (x.GetValueOrDefault("claimDigest") is not string cd || x.GetValueOrDefault("holder") is not string holderS || x.GetValueOrDefault("sig") is not string sigS
                || x.GetValueOrDefault("admit") is not bool admit || x.GetValueOrDefault("gateDigest") is not D gd
                || gd.GetValueOrDefault("encRiskRaw") is not string gRaw || gd.GetValueOrDefault("encSlack") is not string gSlack)
                return AFail("malformed attestation");
            if (!trustedHolders.Contains(holderS)) return AFail("attestation holder is not trusted");
            var holder = Pca.B64uDecode(holderS, 32); var sig = Pca.B64uDecode(sigS, 64);
            if (holder == null || sig == null) return AFail("malformed holder key or signature");
            if (!Pca.VerifyEd25519Strict(holder, VerdictStatement(cd, gd, admit, holderS), sig)) return AFail("attestation signature does not verify");
            if (cd != claimDigest) return AFail("attestation is for a different claim");
            if (gate != null && (gRaw != BytesDigest((string)gate["encRiskRaw"]!) || gSlack != BytesDigest((string)gate["encSlack"]!)))
                return AFail("attestation is for a different gate output");
            return new AttestationCheck(true, admit, null);
        }
        catch (Exception) { return AFail("attestation could not be verified (malformed)"); }
    }
}
