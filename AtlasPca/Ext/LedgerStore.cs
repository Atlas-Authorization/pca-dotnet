using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The typed failure of every store-backed ledger operation. <see cref="Code"/> is stable (<c>store_missing</c>, <c>rollback</c>, ...); the message is for humans.</summary>
public sealed class LedgerStoreError : Exception
{
    public string Code { get; }

    public LedgerStoreError(string code, string message) : base(code + ": " + message) { Code = code; }

    public LedgerStoreError(string code, string message, Exception? cause) : base(code + ": " + message, cause) { Code = code; }
}

/// <summary>The result of <see cref="ILedgerStore.Append"/>: <c>appended</c>, <c>replayed</c> (the same batch was already there) or <c>conflict</c>; <see cref="Size"/> is the log length after.</summary>
public sealed record LedgerAppendOutcome(string Outcome, long Size)
{
    public D ToJson() => new() { ["outcome"] = Outcome, ["size"] = IntentJs.OfLong(Size) };
}

/// <summary>The result of <see cref="ILedgerStore.AppendCheckpoint"/>; <see cref="Reason"/> only on a conflict.</summary>
public sealed record LedgerCheckpointOutcome(string Outcome, long Count, string? Reason)
{
    public D ToJson()
    {
        var m = new D { ["outcome"] = Outcome, ["count"] = IntentJs.OfLong(Count) };
        if (Reason != null) m["reason"] = Reason;
        return m;
    }
}

/// <summary>The persistence contract of a transparency log (the durable side of <see cref="StoredLedger"/>). Implement it over a database (an append-only table with
/// a unique index on the position gives <c>Append</c> for free) or use <see cref="KvLedgerStore"/>.
///
/// <c>Append</c> and <c>AppendCheckpoint</c> are compare-and-swap on the current length: they succeed only at the exact position the caller saw, all entries of a
/// batch or none, so two writers can never assign one index twice and a log never has holes. Committing the same batch again at the same position is a replay
/// (idempotent, nothing written). Acknowledged writes survive a crash or restart; a write in flight at the crash is applied entirely or not at all.</summary>
public interface ILedgerStore
{
    /// <summary>Current number of entries.</summary>
    long Size();

    /// <summary>Commits <c>[from, to)</c>. Throws <see cref="ArgumentException"/> (the reference's RangeError) when the range is not inside the log.</summary>
    List<string> Read(long from, long to);

    /// <summary>Atomically append <paramref name="commits"/> iff the log has exactly <paramref name="expectedSize"/> entries (all or none). A batch that is already stored
    /// at <paramref name="expectedSize"/> is <c>replayed</c>. Every commit must be a non-empty string (<see cref="ArgumentException"/> otherwise).</summary>
    LedgerAppendOutcome Append(long expectedSize, IReadOnlyList<string?> commits);

    /// <summary>Number of checkpoints.</summary>
    long CheckpointCount();

    /// <summary>Checkpoints <c>[from, count)</c> in order (copies).</summary>
    List<D> Checkpoints(long from);

    /// <summary>Atomically append a checkpoint <c>{sth, proof?}</c> iff exactly <paramref name="expectedCount"/> exist. A store also enforces what needs no cryptography:
    /// the checkpoint's size is within the log and not below the previous checkpoint's (equal only with the same root). The same checkpoint at the same position is <c>replayed</c>.</summary>
    LedgerCheckpointOutcome AppendCheckpoint(long expectedCount, D? cp);
}

/// <summary>The pure transition functions of a ledger store: every reference store is these plus a lock. A document is the commits and the checkpoints;
/// <see cref="AppendToLedgerDoc"/> and <see cref="CheckpointToLedgerDoc"/> mutate it ONLY when they report <c>appended</c>.</summary>
public sealed class LedgerDoc
{
    public List<string> Commits { get; } = new();
    public List<D> Checkpoints { get; } = new();

    public static LedgerDoc Empty() => new();

    static bool IsCommit(object? c) => c is string s && s.Length > 0;

    /// <summary>The JSON form <c>{v:1, commits, checkpoints}</c>.</summary>
    public D ToJson() => new()
    {
        ["v"] = IntentJs.OfLong(1),
        ["commits"] = Commits.Cast<object?>().ToList(),
        ["checkpoints"] = Checkpoints.Select(c => StoreJs.DeepCopy(c)).ToList(),
    };

    /// <summary>Decode a stored document (null = empty). Fails closed with <c>store_corrupt</c>; the result shares nothing with <paramref name="raw"/>.</summary>
    public static LedgerDoc Decode(object? raw)
    {
        if (raw == null) return Empty();
        if (raw is not D m || !IntentJs.IsInt(m.GetValueOrDefault("v")) || IntentJs.Lng(m["v"]) != 1
            || m.GetValueOrDefault("commits") is not L commits || m.GetValueOrDefault("checkpoints") is not L cps)
            throw new LedgerStoreError("store_corrupt", "ledger document has the wrong shape");
        var d = new LedgerDoc();
        foreach (var c in commits)
        {
            if (!IsCommit(c)) throw new LedgerStoreError("store_corrupt", "ledger document has the wrong shape");
            d.Commits.Add((string)c!);
        }
        foreach (var c in cps)
        {
            if (c is not D cm || cm.GetValueOrDefault("sth") is not D) throw new LedgerStoreError("store_corrupt", "malformed checkpoint entry");
            d.Checkpoints.Add((D)StoreJs.DeepCopy(cm)!);
        }
        return d;
    }

    static void CheckSafe(long v, string what)
    {
        if (v < 0 || v > 9007199254740991L) throw new ArgumentException(what);
    }

    public static LedgerAppendOutcome AppendToLedgerDoc(LedgerDoc doc, long expectedSize, IReadOnlyList<string?>? commits)
    {
        CheckSafe(expectedSize, "append: expectedSize must be a non-negative safe integer");
        if (commits == null || commits.Count == 0 || commits.Any(c => !IsCommit(c))) throw new ArgumentException("append: commits must be a non-empty array of non-empty strings");
        long size = doc.Commits.Count;
        if (expectedSize < size)
        {
            bool same = true;
            for (int i = 0; i < commits.Count; i++)
            {
                long at = expectedSize + i;
                if (at >= size || doc.Commits[(int)at] != commits[i]) { same = false; break; }
            }
            return new LedgerAppendOutcome(same ? "replayed" : "conflict", size);
        }
        if (expectedSize > size) return new LedgerAppendOutcome("conflict", size);
        doc.Commits.AddRange(commits.Select(c => c!));
        return new LedgerAppendOutcome("appended", doc.Commits.Count);
    }

    public static LedgerCheckpointOutcome CheckpointToLedgerDoc(LedgerDoc doc, long expectedCount, D? cp)
    {
        CheckSafe(expectedCount, "appendCheckpoint: expectedCount must be a non-negative safe integer");
        long count = doc.Checkpoints.Count;
        if (expectedCount < count)
        {
            return JsCanon.Lenient(doc.Checkpoints[(int)expectedCount]) == JsCanon.Lenient(cp) ? new LedgerCheckpointOutcome("replayed", count, null)
                : new LedgerCheckpointOutcome("conflict", count, "another checkpoint holds that position");
        }
        if (expectedCount > count) return new LedgerCheckpointOutcome("conflict", count, "the checkpoint position is ahead of the log");
        var sth = cp?.GetValueOrDefault("sth") as D;
        if (sth == null || !IntentJs.IsInt(sth.GetValueOrDefault("size")) || IntentJs.Lng(sth["size"]) < 0 || sth.GetValueOrDefault("root") is not string root)
            return new LedgerCheckpointOutcome("conflict", count, "malformed checkpoint");
        long size = IntentJs.Lng(sth["size"]);
        if (size > doc.Commits.Count) return new LedgerCheckpointOutcome("conflict", count, "the checkpoint is beyond the end of the log");
        var last = count == 0 ? null : doc.Checkpoints[(int)count - 1].GetValueOrDefault("sth") as D;
        if (last != null)
        {
            // a stored size that is no number compares false both ways, as in the reference
            if (IntentJs.NumOf(last.GetValueOrDefault("size")) is double ls && (size < ls || (size == ls && !Equals(root, last.GetValueOrDefault("root")))))
                return new LedgerCheckpointOutcome("conflict", count, "the checkpoint does not extend the previous one");
        }
        doc.Checkpoints.Add((D)StoreJs.DeepCopy(cp)!);
        return new LedgerCheckpointOutcome("appended", doc.Checkpoints.Count, null);
    }
}

/// <summary>The reference <see cref="ILedgerStore"/>: the whole log is one document in an <see cref="IAtomicKv"/>, so every write is one atomic read-modify-write.
/// Over <see cref="SqlAtomicKv"/> it is durable and safe across processes; over <see cref="MemoryAtomicKv"/> it is the in-process variant (tests only).
/// LIMIT: the document is rewritten on every write; a production log lives in a database with a unique index on the position.</summary>
public sealed class KvLedgerStore : ILedgerStore
{
    public const string DocKey = "pca-ledger-store/v1";
    readonly IAtomicKv _kv;
    readonly string _key;

    public KvLedgerStore(IAtomicKv kv, string key = DocKey)
    {
        _kv = kv ?? throw new LedgerStoreError("store_missing", "KvLedgerStore needs an IAtomicKv");
        _key = key;
    }

    LedgerDoc Doc()
    {
        var text = _kv.Get(_key);
        if (text == null) return LedgerDoc.Empty();
        object? raw;
        try { raw = Pca.ParseJson(text); }
        catch (Exception) { throw new LedgerStoreError("store_corrupt", "ledger document is not JSON"); }
        return LedgerDoc.Decode(raw);
    }

    public long Size() => Doc().Commits.Count;

    public List<string> Read(long from, long to)
    {
        var d = Doc();
        if (from < 0 || from > to || to > d.Commits.Count) throw new ArgumentException("read: range is not inside the log");
        return d.Commits.GetRange((int)from, (int)(to - from));
    }

    public LedgerAppendOutcome Append(long expectedSize, IReadOnlyList<string?> commits)
    {
        LedgerAppendOutcome? output = null;
        _kv.Update(_key, prev =>
        {
            var d = LedgerDoc.Decode(prev == null ? null : Pca.ParseJson(prev));
            output = LedgerDoc.AppendToLedgerDoc(d, expectedSize, commits);
            return output.Outcome == "appended" ? Pca.Canonicalize(d.ToJson()) : null;
        });
        return output!;
    }

    public long CheckpointCount() => Doc().Checkpoints.Count;

    public List<D> Checkpoints(long from)
    {
        var d = Doc();
        if (from < 0 || from > d.Checkpoints.Count) throw new ArgumentException("checkpoints: from is not inside the list");
        return d.Checkpoints.Skip((int)from).Select(c => (D)StoreJs.DeepCopy(c)!).ToList();
    }

    public LedgerCheckpointOutcome AppendCheckpoint(long expectedCount, D? cp)
    {
        LedgerCheckpointOutcome? output = null;
        _kv.Update(_key, prev =>
        {
            var d = LedgerDoc.Decode(prev == null ? null : Pca.ParseJson(prev));
            output = LedgerDoc.CheckpointToLedgerDoc(d, expectedCount, cp);
            return output.Outcome == "appended" ? Pca.Canonicalize(d.ToJson()) : null;
        });
        return output!;
    }
}
