// AtomicKv: the small durable key/value contract the operation records and the plan registry are built on. A value is the JSON text of
// one record. Update is the only mutation: it MUST be atomic across every thread, process and node that shares the store (a conditional
// UPDATE, a unique-key insert, a Redis script), and a call that cannot decide MUST throw (the callers then fail closed).
using System.Data.Common;
using System.Globalization;

namespace AtlasPca;

/// <summary>An atomic key/value store of string values.</summary>
public interface IAtomicKv
{
    /// <summary>The value under <paramref name="key"/>, or null when there is none.</summary>
    string? Get(string key);

    /// <summary>Atomically replaces the value under <paramref name="key"/> with <c>fn(prev)</c> (<c>prev</c> is null when there is none).
    /// <paramref name="fn"/> returning null leaves the key unchanged. <paramref name="fn"/> may be called more than once (an optimistic
    /// store retries) and must not call the store.</summary>
    void Update(string key, Func<string?, string?> fn);
}

/// <summary>The in-process <see cref="IAtomicKv"/> (tests and single-process tools). Its values die with the process.</summary>
public sealed class MemoryAtomicKv : IAtomicKv
{
    readonly Dictionary<string, string> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();

    public string? Get(string key)
    {
        lock (_lock) return _m.TryGetValue(key, out var v) ? v : null;
    }

    public void Update(string key, Func<string?, string?> fn)
    {
        lock (_lock)
        {
            var next = fn(_m.TryGetValue(key, out var v) ? v : null);
            if (next != null) _m[key] = next;
        }
    }
}

/// <summary>An <see cref="IAtomicKv"/> over ADO.NET (SQLite 3.24+ or PostgreSQL 9.5+). Every write is ONE conditional statement under the
/// row's version (compare-and-set), retried when another writer won, so concurrent threads, connections and processes sharing the
/// database never lose an update. <c>connectionFactory</c> must return a NEW connection per call; the store opens and disposes it.</summary>
public sealed class SqlAtomicKv : IAtomicKv
{
    public const string DefaultTable = "pca_kv";
    const int MaxAttempts = 1000;
    readonly Func<DbConnection> _connect;
    readonly string _table;

    public SqlAtomicKv(Func<DbConnection> connectionFactory, string table = DefaultTable)
    {
        _connect = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        if (string.IsNullOrEmpty(table) || table.Length > 63 || !(char.IsAsciiLetter(table[0]) || table[0] == '_')
            || !table.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            throw new ArgumentException("table must be a plain SQL identifier ([A-Za-z_][A-Za-z0-9_]*)", nameof(table));
        _table = table;
    }

    /// <summary>Create the table when it does not exist.</summary>
    public void EnsureSchema()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {_table} (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL, ver BIGINT NOT NULL)";
        cmd.ExecuteNonQuery();
    }

    public string? Get(string key)
    {
        using var c = Open();
        return Read(c, key).Value;
    }

    public void Update(string key, Func<string?, string?> fn)
    {
        using var c = Open();
        for (int i = 0; i < MaxAttempts; i++)
        {
            var (value, ver, found) = Read(c, key);
            var next = fn(value);
            if (next == null) return;
            using var cmd = c.CreateCommand();
            if (found)
            {
                cmd.CommandText = $"UPDATE {_table} SET v = @v, ver = ver + 1 WHERE k = @k AND ver = @ver";
                Param(cmd, "@v", next); Param(cmd, "@k", key); Param(cmd, "@ver", ver);
            }
            else
            {
                cmd.CommandText = $"INSERT INTO {_table} (k, v, ver) VALUES (@k, @v, 1) ON CONFLICT(k) DO NOTHING";
                Param(cmd, "@k", key); Param(cmd, "@v", next);
            }
            if (cmd.ExecuteNonQuery() == 1) return;
        }
        throw new InvalidOperationException($"SqlAtomicKv: update of '{key}' lost the race {MaxAttempts} times (fail closed)");
    }

    (string? Value, long Ver, bool Found) Read(DbConnection c, string key)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"SELECT v, ver FROM {_table} WHERE k = @k";
        Param(cmd, "@k", key);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return (null, 0, false);
        return (r.GetString(0), Convert.ToInt64(r.GetValue(1), CultureInfo.InvariantCulture), true);
    }

    DbConnection Open()
    {
        var c = _connect() ?? throw new InvalidOperationException("the connection factory returned null");
        if (c.State != System.Data.ConnectionState.Open) c.Open();
        return c;
    }

    static void Param(DbCommand cmd, string name, object value)
    {
        var p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        cmd.Parameters.Add(p);
    }
}
