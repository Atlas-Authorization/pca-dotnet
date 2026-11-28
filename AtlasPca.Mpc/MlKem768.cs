using Org.BouncyCastle.Crypto.Parameters;

namespace AtlasPca.Mpc;

/// <summary>
/// ML-KEM-768 (FIPS 203) on the audited BouncyCastle implementation with caller-supplied randomness: key generation from a
/// 64-byte seed (d || z) and encapsulation from a 32-byte message, so the OT transcripts are reproducible from a seeded stream.
/// </summary>
internal static class MlKem768
{
    internal const int MSG_BYTES = 32;
    internal const int KEYGEN_SEED_BYTES = 64;

    /// <summary>A key pair; PublicKey is the 1184-byte encapsulation key.</summary>
    internal sealed record KeyPair(byte[] PublicKey, MLKemPrivateKeyParameters SecretKey);

    /// <summary>Encapsulation result.</summary>
    internal sealed record Encapsulation(byte[] CipherText, byte[] SharedSecret);

    internal static KeyPair Keygen(byte[] seed64)
    {
        var sk = MlKemBc.Key(768, seed64);
        return new KeyPair(sk.GetPublicKeyEncoded(), sk);
    }

    internal static Encapsulation Encapsulate(byte[] publicKey, byte[] msg32)
    {
        var (ct, ss) = MlKemBc.Encapsulate(768, publicKey, msg32);
        return new Encapsulation(ct, ss);
    }

    internal static byte[] Decapsulate(byte[] cipherText, MLKemPrivateKeyParameters sk) => MlKemBc.Decapsulate(768, cipherText, sk);
}
