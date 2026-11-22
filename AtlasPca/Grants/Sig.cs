// Domain-separated Ed25519 signatures over strict canonical JSON (the signing side of the K3 operational plane): signature over
// DOMAIN-PREFIX bytes || strict-canonical-JSON(body). Verification is Pca.VerifyDomain.
using System.Text;

namespace AtlasPca.Grants;

public static class Sig
{
    /// <summary>The b64u public key of a signing key.</summary>
    public static string SignerOf(EdKey key) => key.Id;

    /// <summary>b64u Ed25519 signature over <paramref name="domain"/> || canonical(<paramref name="body"/>); throws when the body has no strict canonical form.</summary>
    public static string SignBody(string domain, object? body, EdKey key) =>
        Pca.B64u(key.Sign(Pca.Cat(Encoding.UTF8.GetBytes(domain), Pca.Canon(body))));

    /// <summary>True iff <paramref name="sig"/> is a canonical 64-byte b64u signature by <paramref name="signer"/> over exactly <paramref name="body"/>. Never throws.</summary>
    public static bool VerifyBody(string domain, object? body, object? signer, object? sig) => Pca.VerifyDomain(domain, body, signer, sig);
}
