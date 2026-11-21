using System.Security.Cryptography;
using System.Text;
using AtlasPca.Gnap;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Ciba;

/// <summary>A durable string key-value store with compare-and-swap. <see cref="PutIfEquals"/> writes the new value only if the stored value is exactly
/// <c>expected</c> (null means "the key must be absent") and reports whether it wrote. It MUST be atomic across every process sharing the store, and a write
/// MUST be durable before it returns. Any failure must throw.</summary>
public interface IDurableKv
{
    /// <summary>The stored string, or null when absent.</summary>
    string? Get(string key);
    bool PutIfEquals(string key, string? expected, string next);
}

/// <summary>Thrown by the KV reference implementations; the broker treats any throw from the store as "no approval". <see cref="Code"/> is
/// <c>corrupt_record</c>, <c>lock_timeout</c> or <c>bad_key</c>.</summary>
public sealed class ApprovalStoreException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>Shared-store reference for the durable broker: a versioned <see cref="IApprovalStore"/> built on a tiny durable key-value interface that needs ONE
/// primitive, a compare-and-swap on a string (Redis, DynamoDB conditional put, SQL <c>UPDATE ... WHERE value = ?</c>, etcd).</summary>
public static class CibaKv
{
    static Versioned Decode(string raw)
    {
        object? parsed;
        try { parsed = Pca.ParseJson(raw); }
        catch (Exception) { throw new ApprovalStoreException("corrupt_record", "ciba: stored approval record is not valid JSON"); }
        var v = GnapJs.NumOf(GnapJs.Member(parsed, "version"));
        if (parsed is not D m || v is not double d || d != Math.Round(d) || double.IsInfinity(d) || d < 1 || !m.ContainsKey("value"))
            throw new ApprovalStoreException("corrupt_record", "ciba: stored approval record has no valid version");
        return new Versioned((long)d, m["value"]);
    }

    /// <summary>An <see cref="IApprovalStore"/> over a <see cref="IDurableKv"/>. Each key holds <c>{version, value}</c> as JSON; <c>Cas</c> re-reads the raw string,
    /// checks the version, and swaps only if the raw string is still the one it read, so two processes racing on the same expected version cannot both win. A stored
    /// value that is not a valid versioned record throws (<c>corrupt_record</c>).</summary>
    public static IApprovalStore CreateKvApprovalStore(IDurableKv kv)
    {
        if (kv == null) throw new ArgumentException("createKvApprovalStore: `kv` with get and putIfEquals is required");
        return new KvStore(kv);
    }

    sealed class KvStore(IDurableKv kv) : IApprovalStore
    {
        public Versioned? Get(string key)
        {
            var raw = kv.Get(key);
            return raw == null ? null : Decode(raw);
        }

        public bool Cas(string key, long expectedVersion, object? value)
        {
            var raw = kv.Get(key);
            long current = raw == null ? 0 : Decode(raw).Version;
            if (current != expectedVersion) return false;
            var next = GnapJs.Stringify(new D { ["version"] = expectedVersion + 1, ["value"] = value });
            return kv.PutIfEquals(key, raw, next);
        }
    }

    /// <summary>Single-process <see cref="IDurableKv"/> for tests of code that takes a KV. Not durable.</summary>
    public static IDurableKv CreateMemoryKv() => new MemoryKv();

    sealed class MemoryKv : IDurableKv
    {
        readonly Dictionary<string, string> m = new();

        public string? Get(string k) { lock (m) return m.GetValueOrDefault(k); }

        public bool PutIfEquals(string k, string? expected, string next)
        {
            lock (m)
            {
                if (m.GetValueOrDefault(k) != expected) return false;
                m[k] = next;
                return true;
            }
        }
    }

    /// <summary>An <see cref="IDurableKv"/> on a directory, safe for several processes on ONE host (and one filesystem with atomic exclusive-create and rename). One file per key;
    /// each swap takes a per-key lock file (exclusive create), compares, writes a temp file and renames it over the key. A process that dies while holding the lock leaves it
    /// behind: every later swap on that key then throws <c>lock_timeout</c> (fail closed) until an operator removes the <c>.lock</c> file.</summary>
    public static IDurableKv CreateDirectoryKv(string dir, long lockTimeoutMs = 5000)
    {
        if (lockTimeoutMs <= 0) throw new ArgumentException("createDirectoryKv: lockTimeoutMs must be a positive number");
        Directory.CreateDirectory(dir);
        OwnerOnly.Directory(dir);
        return new DirKv(dir, lockTimeoutMs);
    }

    sealed class DirKv(string dir, long lockTimeoutMs) : IDurableKv
    {
        // The key is hashed into the file name, so no key can escape the directory.
        string FileOf(string key)
        {
            if (string.IsNullOrEmpty(key)) throw new ApprovalStoreException("bad_key", "ciba: store key must be a non-empty string");
            return Path.Combine(dir, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant());
        }

        public string? Get(string key)
        {
            var f = FileOf(key);
            return File.Exists(f) ? File.ReadAllText(f, Encoding.UTF8) : null;
        }

        public bool PutIfEquals(string key, string? expected, string next)
        {
            var f = FileOf(key);
            var lockPath = f + ".lock";
            var deadline = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + lockTimeoutMs;
            bool locked = false;
            while (!locked)
            {
                try
                {
                    using (new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write)) { }
                    locked = true;
                }
                catch (IOException) when (File.Exists(lockPath))
                {
                    if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= deadline) throw new ApprovalStoreException("lock_timeout", "ciba: could not take the store lock in time");
                    Thread.Sleep(2);
                }
            }
            try
            {
                var current = File.Exists(f) ? File.ReadAllText(f, Encoding.UTF8) : null;
                if (current != expected) return false;
                var tmp = f + "." + Environment.ProcessId + ".tmp";
                using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write))
                {
                    var bytes = Encoding.UTF8.GetBytes(next);
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush(true); // durable before the rename publishes it
                }
                OwnerOnly.File(tmp);
                File.Move(tmp, f, true);
                return true;
            }
            finally
            {
                try { File.Delete(lockPath); } catch (IOException) { /* the lock stays: later swaps fail closed with lock_timeout */ }
            }
        }
    }
}
