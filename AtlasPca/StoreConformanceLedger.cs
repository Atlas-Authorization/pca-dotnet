// Conformance for transparency-log stores (ILedgerStore). A ledger store is the durable side of a tamper-evident log: what it must get right is atomic
// compare-and-swap on the length (one winner per position, all of a batch or none, no holes), idempotent retries, the cryptography-free checkpoint rules,
// and durability of acknowledged writes. Each check is one such claim, driven against YOUR store through an adapter; a violation throws with the exact mismatch:
//
//     var report = LedgerStoreConformance.Run(new MyAdapter());
//     Assert.True(report.Ok, report.Format());
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One isolated ledger backend plus the means to reconnect to it.</summary>
public sealed class LedgerStoreHandle : ISuiteHandle
{
    public ILedgerStore Store { get; }
    readonly Func<ILedgerStore> _reopen;
    readonly Func<ILedgerStore>? _crash;
    readonly Action? _closer;

    public LedgerStoreHandle(ILedgerStore store, Func<ILedgerStore> reopen, Func<ILedgerStore>? crash, Action? closer)
    {
        Store = store;
        _reopen = reopen;
        _crash = crash;
        _closer = closer;
    }

    /// <summary>Another client on the SAME backend (the first stays usable).</summary>
    public ILedgerStore Reopen() => _reopen();

    /// <summary>Kill the backend abruptly (no flush), then return a client on whatever survived.</summary>
    public ILedgerStore Crash() => _crash!();

    public bool CanCrash => _crash != null;

    public void Close() => _closer?.Invoke();
}

/// <summary>The adapter a ledger store author implements.</summary>
public abstract class LedgerStoreAdapter
{
    public abstract string Name { get; }

    /// <summary>Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported.</summary>
    public virtual bool Durable => true;

    /// <summary>A fresh, empty, isolated backend. Called once per check.</summary>
    public abstract LedgerStoreHandle Create();
}

public static class LedgerStoreConformance
{
    // ---- fixtures ----

    static string Cm(int i) => "commit-" + i + "-" + new string('x', 30);

    static D Cp(long size) => Cp(size, "root-" + size, "");

    static D Cp(long size, string root, string prev) => new()
    {
        ["sth"] = new D
        {
            ["instance_id"] = "i",
            ["principal"] = "p",
            ["size"] = IntentJs.OfLong(size),
            ["root"] = root,
            ["prev_root"] = prev,
            ["timestamp"] = IntentJs.OfLong(1),
            ["guardian"] = "g",
            ["sig"] = "s",
        },
    };

    static List<string?> Range(int a, int b)
    {
        var o = new List<string?>();
        for (int i = a; i < b; i++) o.Add(Cm(i));
        return o;
    }

    static List<string> All(ILedgerStore s) => s.Read(0, s.Size());

    static D Outcome(string o, long size) => new LedgerAppendOutcome(o, size).ToJson();

    static D CpOutcome(string o, long count) => new LedgerCheckpointOutcome(o, count, null).ToJson();

    static L Sizes(List<D> cps) => cps.Select(c => ((D)c["sth"]!)["size"]).ToList();

    static L Strs(IEnumerable<string?> xs) => xs.Cast<object?>().ToList();

    /// <summary>A writer that retries until its commit is in, the way a real client does.</summary>
    static long AppendRetrying(ILedgerStore s, string commit)
    {
        for (; ; )
        {
            long size = s.Size();
            var r = s.Append(size, new[] { commit });
            if (r.Outcome is "appended" or "replayed") return size;
        }
    }

    // ---- the checks ----

    public static readonly IReadOnlyList<SuiteCheck<LedgerStoreHandle>> Checks = new List<SuiteCheck<LedgerStoreHandle>>
    {
        new("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed", h =>
        {
            var s = h.Store;
            StoreSuite.Eq(0, s.Size());
            StoreSuite.Eq(new L(), s.Read(0, 0));
            StoreSuite.Eq(0, s.CheckpointCount());
            StoreSuite.Eq(new L(), s.Checkpoints(0));
        }),
        new("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions", h =>
        {
            var s = h.Store;
            StoreSuite.Eq(Outcome("appended", 1), s.Append(0, new[] { Cm(0) }).ToJson());
            StoreSuite.Eq(Outcome("appended", 3), s.Append(1, new[] { Cm(1), Cm(2) }).ToJson());
            StoreSuite.Eq(Strs(Range(0, 3)), s.Read(0, 3));
            StoreSuite.Eq(Strs(Range(1, 3)), s.Read(1, 3));
            StoreSuite.Eq(new L(), s.Read(3, 3));
        }),
        new("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 3));
            StoreSuite.Eq(Outcome("conflict", 3), s.Append(5, new[] { Cm(9) }).ToJson());
            StoreSuite.Eq(Outcome("conflict", 3), s.Append(2, new[] { Cm(9) }).ToJson());
            StoreSuite.Eq(Strs(Range(0, 3)), All(s));
        }),
        new("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 3));
            StoreSuite.Eq(Outcome("replayed", 3), s.Append(0, Range(0, 3)).ToJson());
            StoreSuite.Eq(Outcome("replayed", 3), s.Append(1, Range(1, 3)).ToJson());
            StoreSuite.Eq(Outcome("conflict", 3), s.Append(0, new[] { Cm(0), "other" }).ToJson());
            StoreSuite.Eq(Outcome("conflict", 3), s.Append(2, new[] { Cm(2), Cm(3) }).ToJson());
            StoreSuite.Eq(Strs(Range(0, 3)), All(s));
        }),
        new("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing", h =>
        {
            var s = h.Store;
            s.Append(0, new[] { Cm(0) });
            var bads = new List<string?[]> { Array.Empty<string?>(), new string?[] { "" }, new string?[] { Cm(1), null }, new string?[] { null } };
            foreach (var bad in bads) StoreSuite.Rejects<ArgumentException>(() => s.Append(1, bad), "append of " + bad.Length + " commit(s)");
            foreach (long bad in new long[] { -1, long.MaxValue, 9007199254740992L }) StoreSuite.Rejects<ArgumentException>(() => s.Append(bad, new[] { Cm(1) }), "append at " + bad);
            StoreSuite.Eq(new L { Cm(0) }, All(s));
            foreach (var r in new (long, long)[] { (-1, 1), (1, 0), (0, 2) }) StoreSuite.Rejects<ArgumentException>(() => s.Read(r.Item1, r.Item2), $"read {r.Item1}..{r.Item2}");
        }),
        new("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte", h =>
        {
            var s = h.Store;
            var odd = new List<string?> { "a\"b\\c", "gränt-🔒-\t-\u0001", new string('x', 5000), "__proto__", " leading and trailing " };
            s.Append(0, odd);
            StoreSuite.Eq(Strs(odd), All(s));
        }),
        new("racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch", h =>
        {
            var clients = new List<ILedgerStore> { h.Store, h.Reopen(), h.Reopen(), h.Reopen() };
            var tasks = new List<Func<LedgerAppendOutcome>>();
            for (int i = 0; i < 8; i++) { int n = i; tasks.Add(() => clients[n % 4].Append(0, new[] { Cm(100 + n) })); }
            var r = StoreSuite.Parallel(tasks);
            StoreSuite.Eq(1, r.Count(x => x.Outcome == "appended"));
            StoreSuite.Eq(7, r.Count(x => x.Outcome == "conflict"));
            var log = All(h.Store);
            StoreSuite.Eq(1, log.Count);
            StoreSuite.Ok(Range(100, 108).Contains(log[0]), "the log holds a winner's commit");
        }),
        new("racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once", h =>
        {
            var clients = new List<ILedgerStore> { h.Store, h.Reopen(), h.Reopen() };
            var tasks = new List<Func<long>>();
            for (int i = 0; i < 16; i++) { int n = i; tasks.Add(() => AppendRetrying(clients[n % 3], Cm(200 + n))); }
            var idx = StoreSuite.Parallel(tasks);
            StoreSuite.Eq(16, idx.Distinct().Count());
            var sorted = idx.OrderBy(x => x).Cast<object?>().ToList();
            var want = new L();
            for (long i = 0; i < 16; i++) want.Add(i);
            StoreSuite.Eq(want, sorted);
            var log = All(h.Store);
            StoreSuite.Eq(Strs(Range(200, 216).OrderBy(x => x, StringComparer.Ordinal)), Strs(log.OrderBy(x => x, StringComparer.Ordinal)));
            StoreSuite.Eq(16, log.Count);
            for (int i = 0; i < 16; i++) StoreSuite.Eq(Cm(200 + i), log[(int)idx[i]]);
        }),
        new("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 2));
            StoreSuite.Eq("conflict", s.Append(5, Range(10, 14)).Outcome);
            StoreSuite.Eq(Strs(Range(0, 2)), All(s));
            StoreSuite.Eq(Outcome("appended", 6), s.Append(2, Range(10, 14)).ToJson());
            var want = Range(0, 2);
            want.AddRange(Range(10, 14));
            StoreSuite.Eq(Strs(want), All(s));
        }),
        new("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 6));
            StoreSuite.Eq(CpOutcome("appended", 1), s.AppendCheckpoint(0, Cp(2)).ToJson());
            StoreSuite.Eq(CpOutcome("replayed", 1), s.AppendCheckpoint(0, Cp(2)).ToJson());
            StoreSuite.Eq("conflict", s.AppendCheckpoint(0, Cp(3)).Outcome);
            StoreSuite.Eq("conflict", s.AppendCheckpoint(2, Cp(3)).Outcome);
            StoreSuite.Eq(CpOutcome("appended", 2), s.AppendCheckpoint(1, Cp(5, "root-5", "root-2")).ToJson());
            StoreSuite.Eq(new L { 2, 5 }, Sizes(s.Checkpoints(0)));
            StoreSuite.Eq(new L { 5 }, Sizes(s.Checkpoints(1)));
            StoreSuite.Eq(2, s.CheckpointCount());
        }),
        new("checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 4));
            StoreSuite.Eq("conflict", s.AppendCheckpoint(0, Cp(5)).Outcome);
            StoreSuite.Eq("appended", s.AppendCheckpoint(0, Cp(3)).Outcome);
            StoreSuite.Eq("conflict", s.AppendCheckpoint(1, Cp(2)).Outcome);
            StoreSuite.Eq("conflict", s.AppendCheckpoint(1, Cp(3, "other-root", "")).Outcome);
            StoreSuite.Eq("appended", s.AppendCheckpoint(1, Cp(3)).Outcome); // equal size, same root: allowed
            StoreSuite.Eq("conflict", s.AppendCheckpoint(2, null).Outcome);
            StoreSuite.Eq(2, s.CheckpointCount());
        }),
        new("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands", h =>
        {
            h.Store.Append(0, Range(0, 6));
            var other = h.Reopen();
            var who = new List<ILedgerStore> { h.Store, other, h.Store, other };
            var tasks = new List<Func<LedgerCheckpointOutcome>>();
            for (int i = 0; i < 4; i++) { int n = i; tasks.Add(() => who[n].AppendCheckpoint(0, Cp(2 + n))); }
            var r = StoreSuite.Parallel(tasks);
            StoreSuite.Eq(1, r.Count(x => x.Outcome == "appended"));
            StoreSuite.Eq(1, h.Store.CheckpointCount());
        }),
        new("reads-are-snapshots", "mutating what a read returned cannot change the store", h =>
        {
            var s = h.Store;
            s.Append(0, Range(0, 3));
            s.AppendCheckpoint(0, Cp(2));
            try { s.Read(0, 3)[0] = "mutated"; } catch (NotSupportedException) { /* an unmodifiable copy is as good */ }
            var c = s.Checkpoints(0);
            ((D)c[0]["sth"]!)["size"] = IntentJs.OfLong(99);
            StoreSuite.Eq(Strs(Range(0, 3)), All(s));
            StoreSuite.Eq(2, ((D)s.Checkpoints(0)[0]["sth"]!)["size"]);
        }),
        new("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", "durable", h =>
        {
            h.Store.Append(0, Range(0, 5));
            h.Store.AppendCheckpoint(0, Cp(3));
            h.Store.Append(5, Range(5, 7));
            var back = h.Reopen();
            StoreSuite.Eq(Strs(Range(0, 7)), All(back));
            StoreSuite.Eq(new L { Cp(3) }, back.Checkpoints(0));
            StoreSuite.Eq(Outcome("appended", 8), back.Append(7, new[] { Cm(7) }).ToJson());
        }),
        new("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", "crash", h =>
        {
            h.Store.Append(0, Range(0, 3));
            h.Store.AppendCheckpoint(0, Cp(2));
            var inflight = Task.Run(() => { try { h.Store.Append(3, Range(3, 7)); } catch (Exception) { /* killed in flight */ } });
            var back = h.Crash();
            inflight.Wait();
            var log = All(back);
            StoreSuite.Ok(log.Count == 3 || log.Count == 7, "log has " + log.Count + " entries"); // the batch of four is whole or absent
            StoreSuite.Eq(Strs(Range(0, log.Count)), Strs(log));
            StoreSuite.Eq(new L { Cp(2) }, back.Checkpoints(0));
            StoreSuite.Eq(Outcome(log.Count == 3 ? "appended" : "replayed", 7), back.Append(3, Range(3, 7)).ToJson());
            StoreSuite.Eq(Strs(Range(0, 7)), All(back));
        }),
    };

    /// <summary>Run the suite against <paramref name="adapter"/> (only the named checks when <paramref name="only"/> is non-null).</summary>
    public static SuiteReport Run(LedgerStoreAdapter adapter, ICollection<string>? only = null) =>
        StoreSuite.Run("ledger store", adapter.Name, adapter.Durable, adapter.Create, Checks, only);

    // ---- reference adapters: GOOD ones must pass, BAD ones are positive controls the suite MUST flag ----

    sealed class KvAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) : LedgerStoreAdapter
    {
        public override string Name => name;
        public override bool Durable => durable;

        public override LedgerStoreHandle Create()
        {
            var clients = backend();
            Func<ILedgerStore> open = () => new KvLedgerStore(clients());
            return new LedgerStoreHandle(open(), open, crashable ? open : null, null);
        }
    }

    /// <summary>An adapter over any <see cref="IAtomicKv"/>: <paramref name="backend"/> opens one isolated backend and returns a factory of clients on it.</summary>
    public static LedgerStoreAdapter KvStoreAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) => new KvAdapter(name, durable, backend, crashable);

    /// <summary>GOOD, in process: the reference store over a <see cref="MemoryAtomicKv"/>. Not durable (declared).</summary>
    public static LedgerStoreAdapter MemoryStoreAdapter() =>
        new KvAdapter("KvLedgerStore over MemoryAtomicKv", false, () => { var kv = new MemoryAtomicKv(); return () => kv; }, false);

    /// <summary>The mistakes a bad store makes.</summary>
    public enum Defect { NoCas, PartialBatch, LostUpdate, Amnesia, CheckpointRegress, NoReplay }

    static string Label(Defect d) => d switch
    {
        Defect.NoCas => "BAD no compare-and-swap (appends at the tail whatever the caller saw)",
        Defect.PartialBatch => "BAD partial batch (a conflicting batch leaves its first commit behind)",
        Defect.LostUpdate => "BAD lost update (read, pause, write)",
        Defect.Amnesia => "BAD amnesia (claims durability, forgets on reopen)",
        Defect.CheckpointRegress => "BAD checkpoint regression (accepts a checkpoint below the previous one)",
        _ => "BAD no idempotence (a retried batch conflicts)",
    };

    /// <summary>A store with one switchable defect, for the positive controls (each reproduces a real mistake).</summary>
    sealed class Defective(Defect defect) : ILedgerStore
    {
        readonly object _lock = new();
        volatile LedgerDoc _doc = LedgerDoc.Empty();

        public void Forget() => _doc = LedgerDoc.Empty();

        public long Size() => _doc.Commits.Count;

        public List<string> Read(long f, long t)
        {
            var d = _doc;
            if (f < 0 || f > t || t > d.Commits.Count) throw new ArgumentException("read");
            return d.Commits.GetRange((int)f, (int)(t - f));
        }

        public LedgerAppendOutcome Append(long expected, IReadOnlyList<string?> commits)
        {
            if (expected < 0 || commits == null || commits.Count == 0 || commits.Any(c => string.IsNullOrEmpty(c))) throw new ArgumentException("append");
            if (defect == Defect.LostUpdate)
            {
                var work = LedgerDoc.Decode(_doc.ToJson());
                StoreSuite.RaceWindow();
                var o = LedgerDoc.AppendToLedgerDoc(work, expected, commits);
                if (o.Outcome == "appended") _doc = work;
                return o;
            }
            lock (_lock)
            {
                var d = _doc;
                if (defect == Defect.NoCas)
                {
                    d.Commits.AddRange(commits.Select(c => c!));
                    return new LedgerAppendOutcome("appended", d.Commits.Count);
                }
                if (defect == Defect.PartialBatch && expected != d.Commits.Count)
                {
                    d.Commits.Add(commits[0]!);
                    return new LedgerAppendOutcome("conflict", d.Commits.Count);
                }
                var o = LedgerDoc.AppendToLedgerDoc(d, expected, commits);
                if (defect == Defect.NoReplay && o.Outcome == "replayed") return new LedgerAppendOutcome("conflict", o.Size);
                return o;
            }
        }

        public long CheckpointCount() => _doc.Checkpoints.Count;

        public List<D> Checkpoints(long from) => _doc.Checkpoints.Skip((int)from).Select(c => (D)StoreJs.DeepCopy(c)!).ToList();

        public LedgerCheckpointOutcome AppendCheckpoint(long expected, D? c)
        {
            lock (_lock)
            {
                var d = _doc;
                var sth = c?.GetValueOrDefault("sth") as D;
                if (defect == Defect.CheckpointRegress && expected == d.Checkpoints.Count && sth != null)
                {
                    d.Checkpoints.Add((D)StoreJs.DeepCopy(c)!);
                    return new LedgerCheckpointOutcome("appended", d.Checkpoints.Count, null);
                }
                return LedgerDoc.CheckpointToLedgerDoc(d, expected, c);
            }
        }
    }

    sealed class DefectiveAdapter(Defect defect) : LedgerStoreAdapter
    {
        public override string Name => Label(defect);

        public override LedgerStoreHandle Create()
        {
            var d = new Defective(defect);
            Func<ILedgerStore> again = () => { if (defect == Defect.Amnesia) d.Forget(); return d; };
            return new LedgerStoreHandle(d, again, again, null);
        }
    }

    /// <summary>A bad adapter: one store object shared by every client (a reopen on <see cref="Defect.Amnesia"/> clears it).</summary>
    public static LedgerStoreAdapter DefectiveStoreAdapter(Defect defect) => new DefectiveAdapter(defect);

    /// <summary>The reference adapters by name (the bad ones are positive controls).</summary>
    public static IReadOnlyDictionary<string, Func<LedgerStoreAdapter>> ReferenceAdapters()
    {
        var m = new Dictionary<string, Func<LedgerStoreAdapter>> { ["ledger-memory"] = MemoryStoreAdapter };
        foreach (var d in Enum.GetValues<Defect>())
        {
            var dd = d;
            var name = "bad-ledger-" + string.Concat(dd.ToString().Select((ch, i) => char.IsUpper(ch) && i > 0 ? "-" + char.ToLowerInvariant(ch) : char.ToLowerInvariant(ch).ToString()));
            m[name] = () => DefectiveStoreAdapter(dd);
        }
        return m;
    }
}
