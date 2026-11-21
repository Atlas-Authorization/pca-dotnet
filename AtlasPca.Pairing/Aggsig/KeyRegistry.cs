namespace AtlasPca.Aggsig;

/// <summary>A verifier's pinned set of admitted keys, indexed by key bytes: each was admitted with a verified proof of possession.</summary>
public sealed class KeyRegistry
{
    readonly Dictionary<string, RegisteredKey> keys = new();
    readonly object gate = new();

    /// <summary>Verify the proof of possession and admit the key. Re-registering the same key is idempotent.</summary>
    public Aggsig.RegisterResult Register(byte[]? publicKey, byte[]? pop)
    {
        var r = Aggsig.RegisterKey(publicKey, pop);
        if (r.Ok) lock (gate) keys[Aggsig.Hex(publicKey!)] = r.Key!;
        return r;
    }

    /// <summary>The registered key for these bytes, or null if it was never admitted.</summary>
    public RegisteredKey? Get(byte[]? publicKey)
    {
        if (publicKey == null || publicKey.Length != AggsigCore.PublicKeyLength) return null;
        lock (gate) return keys.TryGetValue(Aggsig.Hex(publicKey), out var k) ? k : null;
    }

    public bool Has(byte[]? publicKey) => Get(publicKey) != null;

    public int Size { get { lock (gate) return keys.Count; } }
}
