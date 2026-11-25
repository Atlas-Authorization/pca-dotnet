// The persistence contract of the undo ledger (the reference undo.ts store section): UndoError, the IUndoStore contract with a memory reference and
// a kv reference (one document per record, every write ONE atomic read-modify-write), plus the guard. A record is the parsed JSON tree of an
// undo record (see UndoWindows). `shortcut:` KvUndoStore.ListAsync scans every key (fine for one host's backlog); a database store indexes (state, window_end).
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>An undo-ledger error. Code: not_durable | store_missing | store_corrupt | invalid | conflict_exhausted | signer_missing | config.</summary>
public sealed class UndoError : Exception
{
    public string Code { get; }
    public UndoError(string code, string message) : base($"{code}: {message}") { Code = code; }
}

/// <summary>A query over undo records: only records in <see cref="State"/>; optionally whose window ended at or before <see cref="WindowEndedBy"/> (the
/// finalize sweep), for a grant or a bond, at most <see cref="Limit"/>.</summary>
public sealed record UndoQuery(string State, long? WindowEndedBy = null, string? GrantRef = null, string? BondRef = null, int? Limit = null);

/// <summary>The persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and a version column:
/// <c>UPDATE ... WHERE id = $1 AND ver = $2</c>) or use <see cref="KvUndoStore"/>.</summary>
public interface IUndoStore
{
    /// <summary>True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so.</summary>
    bool Durable { get; }
    Task<JD?> GetAsync(string id);
    /// <summary>Atomically insert if no record with this id exists; otherwise return the stored one unchanged.</summary>
    Task<(bool Created, JD? Record)> CreateAsync(JD record);
    /// <summary>Atomically replace the record iff its stored <c>ver</c> is <paramref name="expectedVer"/>.</summary>
    Task<bool> ReplaceAsync(string id, long expectedVer, JD next);
    Task<List<JD>> ListAsync(UndoQuery query);
}

public static class UndoStores
{
    internal const string Prefix = "pca-undo/v1/";

    /// <summary>True for an object that implements the undo-store contract.</summary>
    public static bool IsUndoStore(object? s) => s is IUndoStore;

    internal static JD Clone(JD r) => Issue.NormJ(r);

    internal static bool Matches(JD r, UndoQuery q) =>
        r.GetValueOrDefault("state") as string == q.State
        && (q.WindowEndedBy == null || IntentJs.NumOf(r.GetValueOrDefault("window_end")) <= q.WindowEndedBy)
        && (q.GrantRef == null || r.GetValueOrDefault("grant_ref") as string == q.GrantRef)
        && (q.BondRef == null || r.GetValueOrDefault("bond_ref") as string == q.BondRef);

    internal static long Ver(JD r) => IntentJs.IsSafeInteger(r.GetValueOrDefault("ver")) ? IntentJs.Lng(r["ver"]) : throw new UndoError("store_corrupt", "an undo record has the wrong shape");

    internal static void NeedId(object? id)
    {
        if (!UndoWindows.IdOk(id)) throw new UndoError("invalid", "an undo record id is a non-empty string without control characters");
    }
}

/// <summary>A process-memory <see cref="IUndoStore"/>: <c>Durable</c> is false, so the coordinator refuses it unless the caller says, for a test, that it
/// accepts losing every open window on restart. Never use it in production.</summary>
public sealed class MemoryUndoStore : IUndoStore
{
    readonly Dictionary<string, JD> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();
    public bool Durable => false;

    public Task<JD?> GetAsync(string id) { lock (_lock) return Task.FromResult(_m.TryGetValue(id, out var r) ? UndoStores.Clone(r) : null); }

    public Task<(bool Created, JD? Record)> CreateAsync(JD record)
    {
        UndoStores.NeedId(record?.GetValueOrDefault("id"));
        var id = (string)record!["id"]!;
        lock (_lock)
        {
            if (_m.TryGetValue(id, out var cur)) return Task.FromResult((false, (JD?)UndoStores.Clone(cur)));
            _m[id] = UndoStores.Clone(record);
            return Task.FromResult((true, (JD?)null));
        }
    }

    public Task<bool> ReplaceAsync(string id, long expectedVer, JD next)
    {
        if (next.GetValueOrDefault("id") as string != id) throw new UndoError("invalid", "replace: the record id cannot change");
        lock (_lock)
        {
            if (!_m.TryGetValue(id, out var cur) || UndoStores.Ver(cur) != expectedVer) return Task.FromResult(false);
            _m[id] = UndoStores.Clone(next);
            return Task.FromResult(true);
        }
    }

    public Task<List<JD>> ListAsync(UndoQuery q)
    {
        lock (_lock)
        {
            var o = _m.Values.Where(r => UndoStores.Matches(r, q)).OrderBy(r => (string)r["id"]!, StringComparer.Ordinal).ToList();
            if (q.Limit is { } n) o = o.Take(n).ToList();
            return Task.FromResult(o.Select(UndoStores.Clone).ToList());
        }
    }
}

/// <summary>The reference <see cref="IUndoStore"/> over any <see cref="IKeyedAtomicKv"/> (one JSON document per record, every write one atomic
/// <c>Update</c>). <c>Durable</c> is declared by the caller because a kv cannot tell: true only over a persistent kv, false over an in-memory one.</summary>
public sealed class KvUndoStore : IUndoStore
{
    readonly IKeyedAtomicKv _kv;
    public bool Durable { get; }

    public KvUndoStore(IKeyedAtomicKv kv, bool durable)
    {
        _kv = kv ?? throw new UndoError("store_missing", "KvUndoStore needs a durable kv");
        Durable = durable;
    }

    static string K(string id) { UndoStores.NeedId(id); return UndoStores.Prefix + id; }

    static JD? Decode(string? text)
    {
        if (text == null) return null;
        if (Pca.ParseJson(text) is not JD r || !IntentJs.IsInt(r.GetValueOrDefault("v")) || IntentJs.NumOf(r["v"]) != 1.0 || !UndoWindows.IdOk(r.GetValueOrDefault("id"))
            || !UndoWindows.States.Contains(r.GetValueOrDefault("state") as string ?? "") || !IntentJs.IsSafeInteger(r.GetValueOrDefault("ver")) || r.GetValueOrDefault("receipts") is not List<object?>)
            throw new UndoError("store_corrupt", "an undo record has the wrong shape");
        return r;
    }

    public Task<JD?> GetAsync(string id) => Task.FromResult(Decode(_kv.Get(K(id))));

    public Task<(bool Created, JD? Record)> CreateAsync(JD record)
    {
        UndoStores.NeedId(record?.GetValueOrDefault("id"));
        var text = Pca.Canonicalize(record);
        JD? existing = null;
        _kv.Update(K((string)record!["id"]!), prev => { existing = Decode(prev); return existing != null ? null : text; });
        return Task.FromResult(existing != null ? (false, (JD?)existing) : (true, (JD?)null));
    }

    public Task<bool> ReplaceAsync(string id, long expectedVer, JD next)
    {
        if (next.GetValueOrDefault("id") as string != id) throw new UndoError("invalid", "replace: the record id cannot change");
        var text = Pca.Canonicalize(next);
        var done = false;
        _kv.Update(K(id), prev =>
        {
            var cur = Decode(prev);
            done = cur != null && UndoStores.Ver(cur) == expectedVer;
            return done ? text : null;
        });
        return Task.FromResult(done);
    }

    public Task<List<JD>> ListAsync(UndoQuery q)
    {
        var o = new List<JD>();
        foreach (var key in _kv.Keys().Where(x => x.StartsWith(UndoStores.Prefix, StringComparison.Ordinal)).OrderBy(x => x, StringComparer.Ordinal))
        {
            var r = Decode(_kv.Get(key));
            if (r != null && UndoStores.Matches(r, q)) o.Add(r);
            if (q.Limit is { } n && o.Count >= n) break;
        }
        return Task.FromResult(o);
    }
}
