// Persistence surface for the outbound token vault: a stored connection is an agent's third-party OAuth material bound to a PCA authority
// descriptor (the capability shape that is allowed to use it), the store contract, the in-memory test double and the envelope-encrypting wrapper.
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connect;

/// <summary>The PCA authority a connection is bound to: which capability may unlock this token.</summary>
public sealed class ConnectionAuthority
{
    public string Provider { get; set; } = "";
    /// <summary>The trust anchor: the b64u public key the capability chain must be rooted at.</summary>
    public string Principal { get; set; } = "";
    public List<string> Scopes { get; set; } = new();
    /// <summary>When set, the PCActn's signed aud must equal it (null = none).</summary>
    public string? Audience { get; set; }

    public ConnectionAuthority Copy() => new() { Provider = Provider, Principal = Principal, Scopes = new List<string>(Scopes), Audience = Audience };
}

/// <summary>A stored outbound connection, keyed by agent + provider + connectionId. Stores clone in and out.</summary>
public sealed class StoredConnection
{
    public string AgentId { get; set; } = "";
    public string Provider { get; set; } = "";
    public string ConnectionId { get; set; } = "";
    public string AccessToken { get; set; } = "";
    /// <summary>Null when there is none.</summary>
    public string? RefreshToken { get; set; }
    /// <summary>Access-token expiry, epoch milliseconds.</summary>
    public double ExpiresAt { get; set; }
    /// <summary>The scopes the stored access token actually carries.</summary>
    public List<string> Scopes { get; set; } = new();
    public ConnectionAuthority Authority { get; set; } = new();
    public double CreatedAt { get; set; }
    /// <summary>Null when never used.</summary>
    public double? LastUsedAt { get; set; }
    public long UseCount { get; set; }

    public StoredConnection Copy() => new()
    {
        AgentId = AgentId, Provider = Provider, ConnectionId = ConnectionId, AccessToken = AccessToken, RefreshToken = RefreshToken, ExpiresAt = ExpiresAt,
        Scopes = new List<string>(Scopes), Authority = Authority.Copy(), CreatedAt = CreatedAt, LastUsedAt = LastUsedAt, UseCount = UseCount,
    };

    /// <summary>The connection as the reference's plain object (members absent when unset).</summary>
    public D ToJson()
    {
        var a = new D { ["provider"] = Authority.Provider, ["principal"] = Authority.Principal, ["scopes"] = Authority.Scopes.Cast<object?>().ToList() };
        if (Authority.Audience != null) a["audience"] = Authority.Audience;
        var m = new D
        {
            ["agentId"] = AgentId, ["provider"] = Provider, ["connectionId"] = ConnectionId, ["accessToken"] = AccessToken, ["expiresAt"] = JsX.Number(ExpiresAt),
            ["scopes"] = Scopes.Cast<object?>().ToList(), ["authority"] = a, ["createdAt"] = JsX.Number(CreatedAt), ["useCount"] = new Num(UseCount.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        if (RefreshToken != null) m["refreshToken"] = RefreshToken;
        if (LastUsedAt != null) m["lastUsedAt"] = JsX.Number(LastUsedAt.Value);
        return m;
    }
}

/// <summary>The composite key identifying one stored connection.</summary>
public sealed record ConnectionKey(string AgentId, string Provider, string ConnectionId)
{
    /// <summary>NUL-joined: provider / connectionId / agentId are b64u or opaque tokens, none of which contain NUL.</summary>
    internal string Str() => AgentId + "\0" + Provider + "\0" + ConnectionId;
}

/// <summary>CRUD over stored connections. Implementations must round-trip a <see cref="StoredConnection"/> by its key; any exception means the store failed.</summary>
public interface IConnectionStore
{
    /// <summary>The connection, or null.</summary>
    StoredConnection? Get(ConnectionKey key);
    void Set(StoredConnection connection);
    void Delete(ConnectionKey key);
    /// <summary>Marks the store as encrypting at rest; <see cref="TokenVault"/> requires it in strict mode.</summary>
    bool Encrypted => false;
}

/// <summary>Process-local store (a test double: tokens sit in plaintext in process memory, so a vault accepts it only with strict off). Connections are cloned in and out.</summary>
public sealed class InMemoryConnectionStore : IConnectionStore
{
    readonly ConcurrentDictionary<string, StoredConnection> _map = new(StringComparer.Ordinal);

    public StoredConnection? Get(ConnectionKey key) => _map.TryGetValue(key.Str(), out var c) ? c.Copy() : null;

    public void Set(StoredConnection c) => _map[new ConnectionKey(c.AgentId, c.Provider, c.ConnectionId).Str()] = c.Copy();

    public void Delete(ConnectionKey key) => _map.TryRemove(key.Str(), out _);
}

/// <summary>Wraps and unwraps the per-secret data keys of <see cref="EncryptedConnectionStore"/>: a local key ring or your KMS behind the same two methods. The
/// <c>aad</c> binds the wrapped key to the exact connection and field, so a ciphertext copied to another connection or field fails to open.</summary>
public interface IKeyWrapper
{
    WrappedKey Wrap(byte[] dek, byte[] aad);
    byte[] Unwrap(string keyId, byte[] wrapped, byte[] aad);
}

public sealed record WrappedKey(string KeyId, byte[] Wrapped);

/// <summary>A key ring held in process memory. Rotation: add the new key under a new id and make it active; records written under old ids still open until the old key
/// is removed. For production keys implement <see cref="IKeyWrapper"/> over a KMS.</summary>
public sealed class LocalKeyWrapper : IKeyWrapper
{
    readonly Dictionary<string, byte[]> _keys = new(StringComparer.Ordinal);
    string _active;
    readonly object _lock = new();

    public LocalKeyWrapper(IReadOnlyDictionary<string, byte[]> ring, string activeId)
    {
        foreach (var (id, k) in ring) AddKey(id, k);
        if (!_keys.ContainsKey(activeId)) throw new ArgumentException("LocalKeyWrapper: the active key id is not in the key ring");
        _active = activeId;
    }

    public void AddKey(string id, byte[] key)
    {
        if (id.Length == 0) throw new ArgumentException("LocalKeyWrapper: key id must not be empty");
        if (key is not { Length: 32 }) throw new ArgumentException("LocalKeyWrapper: keys must be 32 bytes");
        lock (_lock) _keys[id] = (byte[])key.Clone();
    }

    public void SetActive(string id)
    {
        lock (_lock)
        {
            if (!_keys.ContainsKey(id)) throw new ArgumentException("LocalKeyWrapper: the active key id is not in the key ring");
            _active = id;
        }
    }

    public void RemoveKey(string id)
    {
        lock (_lock)
        {
            if (id == _active) throw new ArgumentException("LocalKeyWrapper: cannot remove the active key");
            if (_keys.Remove(id, out var k)) CryptographicOperations.ZeroMemory(k);
        }
    }

    /// <summary>Overwrites every key with zeros and empties the ring.</summary>
    public void Destroy()
    {
        lock (_lock)
        {
            foreach (var k in _keys.Values) CryptographicOperations.ZeroMemory(k);
            _keys.Clear();
        }
    }

    public WrappedKey Wrap(byte[] dek, byte[] aad)
    {
        lock (_lock)
        {
            if (!_keys.TryGetValue(_active, out var k)) throw new InvalidOperationException("no active key");
            return new WrappedKey(_active, Seal(k, aad, dek));
        }
    }

    public byte[] Unwrap(string keyId, byte[] wrapped, byte[] aad)
    {
        lock (_lock)
        {
            if (!_keys.TryGetValue(keyId, out var k)) throw new InvalidOperationException("unknown key id");
            return Open(k, aad, wrapped);
        }
    }

    /// <summary>AES-256-GCM: iv(12) || ciphertext || tag(16), the aad authenticated.</summary>
    internal static byte[] Seal(byte[] key, byte[] aad, byte[] plain)
    {
        var iv = RandomNumberGenerator.GetBytes(12);
        var o = new byte[12 + plain.Length + 16];
        iv.CopyTo(o, 0);
        using var g = new AesGcm(key, 16);
        g.Encrypt(iv, plain, o.AsSpan(12, plain.Length), o.AsSpan(12 + plain.Length, 16), aad);
        return o;
    }

    internal static byte[] Open(byte[] key, byte[] aad, byte[] sealedBytes)
    {
        if (sealedBytes.Length < 12 + 16) throw new ArgumentException("short ciphertext");
        int n = sealedBytes.Length - 28;
        var plain = new byte[n];
        using var g = new AesGcm(key, 16);
        g.Decrypt(sealedBytes.AsSpan(0, 12), sealedBytes.AsSpan(12, n), sealedBytes.AsSpan(12 + n, 16), plain, aad);
        return plain;
    }
}

/// <summary>Wraps any <see cref="IConnectionStore"/> so the access and refresh tokens are encrypted before they reach it (envelope encryption: a random data key per
/// secret, wrapped by a <see cref="IKeyWrapper"/>, the aad binding it to the exact connection and field). Everything else in a record stays readable so the inner store
/// can index and expire it. Fails closed: a stored token that is not an envelope, fails authentication, or was sealed under an unknown key makes <see cref="Get"/> throw a
/// <see cref="StoreError"/> that carries no detail.</summary>
public sealed class EncryptedConnectionStore : IConnectionStore
{
    const string Prefix = "pca1";
    readonly IConnectionStore _inner;
    readonly IKeyWrapper _wrapper;

    public EncryptedConnectionStore(IConnectionStore inner, IKeyWrapper wrapper)
    {
        _inner = inner;
        _wrapper = wrapper;
    }

    public bool Encrypted => true;

    static byte[] UnB64u(string s)
    {
        foreach (var c in s) if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-')) throw new ArgumentException("bad encoding");
        return ConnectJs.LenientB64uDecode(s);
    }

    /// <summary>The additional authenticated data: length-prefixed (version, field, agent, provider, connection).</summary>
    internal static byte[] AadFor(ConnectionKey key, string field)
    {
        var parts = new[] { "pca-connect/v1", field, key.AgentId, key.Provider, key.ConnectionId };
        return Encoding.UTF8.GetBytes(string.Join("|", parts.Select(p => Encoding.UTF8.GetByteCount(p) + ":" + p)));
    }

    string EncryptField(ConnectionKey key, string field, string plain)
    {
        var aad = AadFor(key, field);
        var dek = RandomNumberGenerator.GetBytes(32);
        try
        {
            var w = _wrapper.Wrap(dek, aad);
            var sealedBytes = LocalKeyWrapper.Seal(dek, aad, Encoding.UTF8.GetBytes(plain));
            return string.Join(".", Prefix, Pca.B64u(Encoding.UTF8.GetBytes(w.KeyId)), Pca.B64u(w.Wrapped), Pca.B64u(sealedBytes));
        }
        finally { CryptographicOperations.ZeroMemory(dek); }
    }

    string DecryptField(ConnectionKey key, string field, string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4 || parts[0] != Prefix) throw new ArgumentException("not an envelope");
        var aad = AadFor(key, field);
        var dek = _wrapper.Unwrap(Encoding.UTF8.GetString(UnB64u(parts[1])), UnB64u(parts[2]), aad);
        try { return Encoding.UTF8.GetString(LocalKeyWrapper.Open(dek, aad, UnB64u(parts[3]))); }
        finally { CryptographicOperations.ZeroMemory(dek); }
    }

    public StoredConnection? Get(ConnectionKey key)
    {
        var raw = _inner.Get(key);
        if (raw == null) return null;
        try
        {
            var o = raw.Copy();
            var k = new ConnectionKey(raw.AgentId, raw.Provider, raw.ConnectionId);
            if (k.AgentId != key.AgentId || k.Provider != key.Provider || k.ConnectionId != key.ConnectionId) throw new InvalidOperationException("record key mismatch");
            o.AccessToken = DecryptField(k, "access", raw.AccessToken);
            if (raw.RefreshToken != null) o.RefreshToken = DecryptField(k, "refresh", raw.RefreshToken);
            return o;
        }
        catch (Exception) { throw new StoreError("a stored token could not be decrypted"); }
    }

    public void Set(StoredConnection connection)
    {
        var k = new ConnectionKey(connection.AgentId, connection.Provider, connection.ConnectionId);
        var sealedConn = connection.Copy();
        try
        {
            sealedConn.AccessToken = EncryptField(k, "access", connection.AccessToken);
            if (connection.RefreshToken != null) sealedConn.RefreshToken = EncryptField(k, "refresh", connection.RefreshToken);
        }
        catch (Exception) { throw new StoreError("a token could not be encrypted; nothing was stored"); }
        _inner.Set(sealedConn);
    }

    public void Delete(ConnectionKey key) => _inner.Delete(key);

    /// <summary>Re-encrypt one record under the wrapper's active key (run after rotating the key ring).</summary>
    public bool Reencrypt(ConnectionKey key)
    {
        var c = Get(key);
        if (c == null) return false;
        Set(c);
        return true;
    }
}
