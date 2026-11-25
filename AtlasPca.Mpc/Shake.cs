using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace AtlasPca.Mpc;

/// <summary>SHAKE256 one-shot: the platform's OpenSSL-backed implementation where it exists, BouncyCastle otherwise.</summary>
internal static class Shake
{
    public static byte[] Shake256(byte[] data, int outLen)
    {
        if (System.Security.Cryptography.Shake256.IsSupported) return System.Security.Cryptography.Shake256.HashData(data, outLen);
        var d = new ShakeDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[outLen];
        d.OutputFinal(o, 0, outLen);
        return o;
    }
}
