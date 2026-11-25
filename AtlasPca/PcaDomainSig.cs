// Domain-separated Ed25519 signatures over strict canonical JSON, shared by every K3 operational-plane artifact
// (packages/pca-grants/src/sig.ts): signature over DOMAIN-PREFIX bytes || strict-canonical-JSON(body), verified with the
// SDK's strict Ed25519 verifier. Total: anything malformed is false.
using System.Text;

namespace AtlasPca;

public static partial class Pca
{
    /// <summary>A non-negative safe integer lexeme.</summary>
    internal static bool SafeNat(object? v, out long n) => TryInt(v, out n) && n >= 0;

    /// <summary>True iff <paramref name="sig"/> is a canonical 64-byte base64url signature by <paramref name="signer"/> over exactly
    /// <paramref name="domain"/> || canonical(<paramref name="body"/>). Never throws.</summary>
    internal static bool VerifyDomain(string domain, object? body, object? signer, object? sig)
    {
        try
        {
            if (B64uDecode(sig, 64) == null) return false;
            return VerifyB64u(signer, Cat(Encoding.UTF8.GetBytes(domain), Canon(body)), sig);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Strict Ed25519 over the UTF-8 bytes of a digest string (the K4 signing form). Never throws.</summary>
    internal static bool VerifyDigest(object? signer, string digest, object? sig)
    {
        try { return VerifyB64u(signer, Encoding.UTF8.GetBytes(digest), sig); }
        catch (Exception) { return false; }
    }

    /// <summary>A safe integer (any sign) lexeme.</summary>
    internal static bool SafeInt(object? v, out long n) => TryInt(v, out n);
}
