using System.Security.Cryptography;

namespace AtlasPca.Aggsig;

/// <summary>
/// BLS12-381 signature aggregation for Proof-Carrying Authority (port of the TypeScript aggsig package), on blst.
/// Rogue-key safety by construction: the aggregate verifiers take <see cref="RegisteredKey"/>s only, and a RegisteredKey can only
/// come from <see cref="RegisterKey"/> / <see cref="KeyRegistry.Register"/>, which verify KeyValidate and a proof of possession first.
/// The raw verifiers live in the internal AggsigCore.
/// </summary>
public static class Aggsig
{
    public const string SigDst = AggsigCore.SigDst;
    public const string PopDst = AggsigCore.PopDst;
    public const int PublicKeyLength = AggsigCore.PublicKeyLength;
    public const int SignatureLength = AggsigCore.SignatureLength;

    /// <summary>32-byte big-endian scalar and its 48-byte compressed G1 public key.</summary>
    public sealed class KeyPair
    {
        public byte[] SecretKey { get; }
        public byte[] PublicKey { get; }
        internal KeyPair(byte[] secretKey, byte[] publicKey) { SecretKey = secretKey; PublicKey = publicKey; }
    }

    /// <summary>Either a registered key or the reason it was refused.</summary>
    public sealed class RegisterResult
    {
        public bool Ok { get; }
        public RegisteredKey? Key { get; }
        public string? Reason { get; }
        RegisterResult(bool ok, RegisteredKey? key, string? reason) { Ok = ok; Key = key; Reason = reason; }
        internal static RegisterResult Success(RegisteredKey k) => new(true, k, null);
        internal static RegisterResult Fail(string why) => new(false, null, why);
    }

    internal static string Hex(byte[] b) => Convert.ToHexString(b);

    public static KeyPair KeyGen() => AggsigCore.KeyGen(RandomNumberGenerator.GetBytes);

    public static byte[] PublicKeyOf(byte[] secretKey) => AggsigCore.PublicKeyOf(secretKey);

    public static bool KeyValidate(byte[]? publicKey) => AggsigCore.KeyValidate(publicKey);

    public static byte[] Sign(byte[] secretKey, byte[] msg) => AggsigCore.Sign(secretKey, msg);

    /// <summary>CoreVerify of one signature. Never throws.</summary>
    public static bool Verify(byte[]? publicKey, byte[]? msg, byte[]? sig) => AggsigCore.Verify(publicKey, msg, sig);

    /// <summary>Sum the G2 signature points into one 96-byte aggregate; throws on an empty list or a non-canonical signature.</summary>
    public static byte[] Aggregate(IReadOnlyList<byte[]> sigs) => AggsigCore.Aggregate(sigs);

    /// <summary>Sign one's OWN public key under the PoP DST.</summary>
    public static byte[] PopProve(byte[] secretKey) => AggsigCore.PopProve(secretKey);

    /// <summary>Admit a public key: KeyValidate plus a valid proof of possession. The only way to obtain a RegisteredKey. Never throws.</summary>
    public static RegisterResult RegisterKey(byte[]? publicKey, byte[]? pop)
    {
        if (publicKey == null || pop == null) return RegisterResult.Fail("public key and proof of possession must be Uint8Arrays");
        if (!AggsigCore.KeyValidate(publicKey)) return RegisterResult.Fail("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)");
        if (pop.Length != AggsigCore.SignatureLength) return RegisterResult.Fail("proof of possession is not a 96-byte compressed G2 signature");
        if (!AggsigCore.PopVerify(publicKey, pop)) return RegisterResult.Fail("proof of possession does not verify for this key");
        return RegisterResult.Success(new RegisteredKey(publicKey));
    }

    /// <summary>Why the keys cannot be used for aggregate verification, or null when every element is a genuine RegisteredKey.</summary>
    public static string? CheckRegistered(IReadOnlyList<RegisteredKey?>? keys)
    {
        if (keys == null) return "keys must be an array of RegisteredKey";
        if (keys.Count == 0) return "no keys";
        for (int i = 0; i < keys.Count; i++)
            if (keys[i] == null) return "key " + i + " is not a registered key: it was not admitted through registerKey (proof of possession)";
        return null;
    }

    static List<byte[]> RawOf(IReadOnlyList<RegisteredKey?> keys) => keys.Select(k => k!.Bytes()).ToList();

    /// <summary>AggregateVerify over distinct messages, registered keys only. Never throws.</summary>
    public static bool AggregateVerify(IReadOnlyList<RegisteredKey?>? keys, IReadOnlyList<byte[]> msgs, byte[]? aggSig)
    {
        if (CheckRegistered(keys) != null) return false;
        return AggsigCore.AggregateVerify(RawOf(keys!), msgs, aggSig);
    }

    /// <summary>FastAggregateVerify: one message, registered keys only; one signer may not be counted twice. Never throws.</summary>
    public static bool FastAggregateVerify(IReadOnlyList<RegisteredKey?>? keys, byte[]? msg, byte[]? aggSig)
    {
        if (CheckRegistered(keys) != null) return false;
        var seen = new HashSet<string>();
        foreach (var k in keys!) if (!seen.Add(Hex(k!.Bytes()))) return false;
        return AggsigCore.FastAggregateVerify(RawOf(keys!), msg, aggSig);
    }
}
