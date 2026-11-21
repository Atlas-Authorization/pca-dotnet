using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>StoreConformance is a kit that tests a store: its mutants die against deliberately broken stores, each caught under the
/// exact check name with the exact note. Issue is the producer side: refusals with the reference's messages (envelope.ts, merkle.ts,
/// pcactn.ts, passport.ts) and the exact signed members.</summary>
public class StoreIssueKillTests
{
    // ================= StoreConformance: harness =================

    sealed class NullMessage : Exception { public override string Message => null!; }

    sealed class StateHandle : IStateStore, IDisposable
    {
        readonly Func<string, long, ClaimResult?> _f;
        readonly bool _throwOnDispose;
        public int Disposed;
        public StateHandle(Func<string, long, ClaimResult?> f, bool throwOnDispose = false) { _f = f; _throwOnDispose = throwOnDispose; }
        public ClaimResult? Claim(string key, long counter) => _f(key, counter);
        public void Dispose()
        {
            Disposed++;
            if (_throwOnDispose) throw new InvalidOperationException("close failed");
        }
    }

    sealed class StateBackend { public MemoryStateStore M = new(); public int Restarts; public readonly List<StateHandle> Handles = new(); }

    /// <summary>Every handle shares <c>b.M</c>; <c>f</c> breaks the behaviour it wants and passes the rest to the good store.</summary>
    static ConformanceReport RunS(Func<string, long, MemoryStateStore, ClaimResult?> f, StateBackend? backend = null, bool shared = true, bool durable = false, bool wipeOnRestart = false, int rounds = 2, int copies = 3, int handles = 2, bool throwOnDispose = false)
    {
        var b = backend ?? new StateBackend();
        return StoreConformance.RunStateStore(new StateStoreConformance
        {
            Name = "t",
            Open = () => { var h = new StateHandle((k, n) => f(k, n, b.M), throwOnDispose); b.Handles.Add(h); return h; },
            Restart = () => { b.Restarts++; if (wipeOnRestart) b.M = new MemoryStateStore(); },
            Shared = shared, Durable = durable, Rounds = rounds, Copies = copies, Handles = handles,
        });
    }

    static bool Is(string key, string suffix) => key.EndsWith(":" + suffix, StringComparison.Ordinal);
    static ClaimResult? Good(string k, long n, MemoryStateStore m) => m.Claim(k, n);

    static void Fails(ConformanceReport r, string check, string note) =>
        Assert.Equal(new ConformanceCheck(check, "fail", note), r.Checks.Single(c => c.Name == check));

    // ================= report =================

    [Fact]
    public void StatusOfNamesTheCheckOrAbsent()
    {
        var r = new ConformanceReport("n");
        Assert.Equal("absent", r.StatusOf("nope"));
        r.Add("a", null);
        r.Add("b", "bad");
        r.Skip("c", "why");
        Assert.Equal(("pass", "fail", "skip", "absent"), (r.StatusOf("a"), r.StatusOf("b"), r.StatusOf("c"), r.StatusOf("d")));
    }

    [Fact]
    public void ToStringIsOneExactLinePerCheck()
    {
        var pass = new ConformanceReport("n");
        pass.Add("claim-burst", null, "ok note");
        pass.Skip("x", "why");
        Assert.Equal($"store conformance: n -> PASS\n  [PASS] {"claim-burst".PadRight(20)} ok note\n  [SKIP] {"x".PadRight(20)} why\n", pass.ToString());
        var fail = new ConformanceReport("m");
        fail.Add("k", "bad");
        Assert.Equal($"store conformance: m -> FAIL\n  [FAIL] {"k".PadRight(20)} bad\n", fail.ToString());
    }

    [Fact]
    public void ConfigurationDefaults()
    {
        Assert.Equal("store", new StateStoreConformance().Name);
        Assert.Equal("store", new OperationStoreConformance().Name);
    }

    [Fact]
    public void AMissingOpenIsTheOnlyCheckAndAFailure()
    {
        var want = new ConformanceCheck("configuration", "fail", "Open is required");
        Assert.Equal(want, StoreConformance.RunStateStore(new StateStoreConformance()).Checks.Single());
        Assert.Equal(want, StoreConformance.RunOperationStore(new OperationStoreConformance()).Checks.Single());
    }

    // ================= Race =================

    static readonly MethodInfo RaceM = typeof(StoreConformance).GetMethod("Race", BindingFlags.NonPublic | BindingFlags.Static)!;
    static void Race(int n, Action<int> body) => RaceM.Invoke(null, new object[] { n, body });

    static int ThreadCount()
    {
        using var p = Process.GetCurrentProcess();
        return p.Threads.Count;
    }

    [Fact]
    public void RaceRunsEveryCopyOnABackgroundThread()
    {
        var seen = new ConcurrentBag<(int I, bool Background)>();
        Race(4, i => seen.Add((i, Thread.CurrentThread.IsBackground)));
        Assert.Equal(new[] { (0, true), (1, true), (2, true), (3, true) }, seen.OrderBy(x => x.I).ToArray());
    }

    [Fact]
    public void RaceReleasesNoCopyBeforeEveryThreadHasStarted()
    {
        // the gate: when the first body runs, every thread already exists. An open gate (or no wait) runs it while the rest are still being started.
        const int n = 256;
        int before = ThreadCount(), first = 0, atFirst = -1;
        using var release = new ManualResetEventSlim(false);
        Race(n, _ =>
        {
            if (Interlocked.Exchange(ref first, 1) == 0)
            {
                atFirst = ThreadCount();
                release.Set();
            }
            else release.Wait();
        });
        Assert.True(atFirst >= before + n / 2, $"{before} threads before the race, only {atFirst} when the first copy ran");
    }

    // ================= state store: handles =================

    [Fact]
    public void EveryHandleIsOpenedAsDeclaredAndClosedExactlyOnce()
    {
        // burst 1 + concurrent H + durability 2 + crash 2 + retry 2
        var all = new StateBackend();
        Assert.True(RunS(Good, all, durable: true, handles: 3).Ok);
        Assert.Equal(10, all.Handles.Count);
        Assert.All(all.Handles, h => Assert.Equal(1, h.Disposed));
        // shared false: one handle per check, whatever Handles says (the retry too: pca-state.ts:305)
        var one = new StateBackend();
        Assert.True(RunS(Good, one, shared: false, handles: 9).Ok);
        Assert.Equal(3, one.Handles.Count);
        Assert.All(one.Handles, h => Assert.Equal(1, h.Disposed));
        // Handles <= 0 is the default 4 (pca-state.ts:460)
        foreach (var bad in new[] { 0, -1 })
        {
            var d = new StateBackend();
            Assert.True(RunS(Good, d, handles: bad).Ok);
            Assert.Equal(7, d.Handles.Count);
        }
        var h1 = new StateBackend();
        Assert.True(RunS(Good, h1, handles: 1).Ok);
        Assert.Equal(4, h1.Handles.Count);
    }

    [Fact]
    public void ACloseFailureIsNotAConformanceFailure()
    {
        var b = new StateBackend();
        var r = RunS(Good, b, durable: true, throwOnDispose: true);
        Assert.True(r.Ok, r.ToString());
        Assert.All(b.Handles, h => Assert.Equal(1, h.Disposed));
    }

    [Fact]
    public void AFailedOpenClosesWhatWasOpenedAndIsReported()
    {
        var opened = new List<StateHandle>();
        int n = 0;
        var mem = new MemoryStateStore();
        var r = StoreConformance.RunStateStore(new StateStoreConformance
        {
            Shared = true, Rounds = 1, Copies = 1, Handles = 4,
            Open = () =>
            {
                if (++n >= 4) throw new InvalidOperationException("down");
                var h = new StateHandle(mem.Claim);
                opened.Add(h);
                return h;
            },
        });
        Assert.Equal("pass", r.StatusOf("claim-burst"));
        Fails(r, "claim-concurrent", "Open: down");
        Fails(r, "retry-after-timeout", "Open: down");
        Assert.Equal(3, opened.Count);
        Assert.All(opened, h => Assert.Equal(1, h.Disposed));
    }

    [Fact]
    public void AnOpenThatReturnsNullIsReported() =>
        Fails(StoreConformance.RunStateStore(new StateStoreConformance { Open = () => null! }), "claim-burst", "Open: Open returned null");

    [Fact]
    public void RaceSizesAreReportedWithTheirDefaults()
    {
        static string Note(int rounds, int copies, int handles, bool shared = true)
        {
            var r = RunS(Good, shared: shared, rounds: rounds, copies: copies, handles: handles);
            Assert.True(r.Ok, r.ToString());
            return r.Checks.Single(c => c.Name == "claim-concurrent").Note;
        }
        Assert.Equal("2 rounds x 3 copies over 2 handle(s)", Note(2, 3, 2));
        Assert.Equal("1 rounds x 1 copies over 1 handle(s)", Note(1, 1, 1));
        Assert.Equal("10 rounds x 16 copies over 4 handle(s)", Note(0, 0, 0));
        Assert.Equal("10 rounds x 16 copies over 4 handle(s)", Note(-1, -1, -1));
        Assert.Equal("2 rounds x 3 copies over 1 handle(s)", Note(2, 3, 5, shared: false));
    }

    [Fact]
    public void ADurabilityCheckTheStoreDeclinesIsSkippedNotPassed()
    {
        var r = RunS(Good);
        foreach (var name in new[] { "claim-durability", "crash-after-claim" })
            Assert.Equal(new ConformanceCheck(name, "skip", "Durable is false (state dies with the process)"), r.Checks.Single(c => c.Name == name));
    }

    [Fact]
    public void EveryStateCheckUsesItsOwnStream()
    {
        var keys = new ConcurrentBag<string>();
        Assert.True(RunS((k, n, m) => { keys.Add(k); return m.Claim(k, n); }, durable: true).Ok);
        Assert.All(keys, k => Assert.StartsWith("conf:", k));
        Assert.Equal(new[] { "burst", "burst-other", "concurrent", "concurrent-distinct", "crash", "durability", "retry" },
            keys.Select(k => k[(k.LastIndexOf(':') + 1)..]).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToArray());
    }

    // ================= state store: claim-burst =================

    [Fact]
    public void BurstCatchesAStoreThatRefusesOrThrowsOnFirstUse()
    {
        Fails(RunS((k, n, m) => Is(k, "burst") ? new ClaimResult(false) : m.Claim(k, n)), "claim-burst", "counter 1 was not admitted on first use (err refused)");
        Fails(RunS((k, n, m) => Is(k, "burst") ? null : m.Claim(k, n)), "claim-burst", "counter 1 was not admitted on first use (err refused)");
        Fails(RunS((k, n, m) => Is(k, "burst") ? throw new InvalidOperationException("boom") : m.Claim(k, n)), "claim-burst", "counter 1 was not admitted on first use (err boom)");
        Fails(RunS((k, n, m) => Is(k, "burst") && n == 7 ? new ClaimResult(false) : m.Claim(k, n)), "claim-burst", "counter 7 was not admitted on first use (err refused)");
    }

    [Fact]
    public void BurstWalksTheReplaysDownToCounterOne()
    {
        // admits only the replay of counter 1, the last one the descending walk reaches
        int ones = 0;
        Fails(RunS((k, n, m) => Is(k, "burst") && n == 1 && ++ones == 2 ? new ClaimResult(true) : m.Claim(k, n)), "claim-burst",
            "counter 1 was admitted twice (or an older counter was admitted after a newer one)");
        Fails(RunS((k, n, m) => Is(k, "burst") ? new ClaimResult(true) : m.Claim(k, n)), "claim-burst",
            "counter 25 was admitted twice (or an older counter was admitted after a newer one)");
    }

    [Fact]
    public void BurstCatchesAReplayThatErrors()
    {
        int calls = 0;
        Fails(RunS((k, n, m) => Is(k, "burst") && ++calls > 25 ? throw new InvalidOperationException("boom") : m.Claim(k, n)), "claim-burst", "replay of counter 25 errored: boom");
    }

    [Fact]
    public void BurstCatchesARefusedNextCounterAndAFreshKey()
    {
        Fails(RunS((k, n, m) => Is(k, "burst") && n == 26 ? new ClaimResult(false) : m.Claim(k, n)), "claim-burst", "the next counter after refusals was not admitted (err refused)");
        Fails(RunS((k, n, m) => Is(k, "burst-other") ? new ClaimResult(false) : m.Claim(k, n)), "claim-burst", "a fresh key refused counter 1 (err refused)");
    }

    // ================= state store: claim-concurrent =================

    [Fact]
    public void ConcurrentCatchesAStoreThatFailsOnlyTheLastRound() =>
        Fails(RunS((k, n, m) => Is(k, "concurrent") && n == 2 ? new ClaimResult(true) : m.Claim(k, n)), "claim-concurrent",
            "round 2: 3 of 3 copies of one counter were admitted (want exactly 1; 0 errors)");

    [Fact]
    public void ConcurrentCountsErrors() =>
        Fails(RunS((k, n, m) => Is(k, "concurrent") ? throw new InvalidOperationException("boom") : m.Claim(k, n)), "claim-concurrent",
            "round 1: 0 of 3 copies of one counter were admitted (want exactly 1; 3 errors)");

    [Fact]
    public void ConcurrentRequiresTheHighestRacingCounter() =>
        // rounds 2, copies 3: the distinct race claims 3, 4, 5
        Fails(RunS((k, n, m) => Is(k, "concurrent-distinct") && n == 5 ? new ClaimResult(false) : m.Claim(k, n)), "claim-concurrent", "the highest of 3 racing counters was not admitted");

    [Fact]
    public void ConcurrentReclaimsEveryCounterAfterTheRace()
    {
        // the top counter stays claimable: only the re-claim of base + copies shows it
        Fails(RunS((k, n, m) =>
        {
            if (!(Is(k, "concurrent-distinct") && n == 5)) return m.Claim(k, n);
            m.Claim(k, n);
            return new ClaimResult(true);
        }), "claim-concurrent", "counter 5 is admitted again after the race (err )");
        // a re-claim that errors is reported too
        int tops = 0;
        Fails(RunS((k, n, m) => Is(k, "concurrent-distinct") && n == 5 && Interlocked.Increment(ref tops) == 2 ? throw new InvalidOperationException("boom") : m.Claim(k, n)),
            "claim-concurrent", "counter 5 is admitted again after the race (err boom)");
    }

    // ================= state store: durability and crash =================

    [Fact]
    public void RestartRunsAndAWipedBackendIsCaught()
    {
        var b = new StateBackend();
        var r = RunS(Good, b, durable: true, wipeOnRestart: true);
        Assert.Equal(2, b.Restarts);
        Fails(r, "claim-durability", "counter 3 was admitted again after closing every handle (err )");
        Fails(r, "crash-after-claim", "counter 1 was admitted again after the instance died (err )");
    }

    [Fact]
    public void DurabilityReportsEachStep()
    {
        Fails(RunS((k, n, m) => Is(k, "durability") && n == 2 ? new ClaimResult(false) : m.Claim(k, n), durable: true), "claim-durability", "counter 2 was not admitted (err refused)");
        int threes = 0;
        Fails(RunS((k, n, m) => Is(k, "durability") && n == 3 && ++threes == 2 ? throw new InvalidOperationException("boom") : m.Claim(k, n), durable: true),
            "claim-durability", "counter 3 was admitted again after closing every handle (err boom)");
        Fails(RunS((k, n, m) => Is(k, "durability") && n == 4 ? new ClaimResult(false) : m.Claim(k, n), durable: true), "claim-durability", "counter 4 was not admitted after closing every handle (err refused)");
    }

    [Fact]
    public void CrashReportsEachStep()
    {
        Fails(RunS((k, n, m) => Is(k, "crash") && n == 1 ? new ClaimResult(false) : m.Claim(k, n), durable: true), "crash-after-claim", "counter 1 was not admitted (err refused)");
        Fails(RunS((k, n, m) => Is(k, "crash") && n == 2 ? new ClaimResult(false) : m.Claim(k, n), durable: true), "crash-after-claim", "counter 2 was not admitted after the instance died (err refused)");
    }

    // ================= state store: retry-after-timeout =================

    [Fact]
    public void RetryReportsEachStep()
    {
        Fails(RunS((k, n, m) => Is(k, "retry") ? new ClaimResult(true) : m.Claim(k, n)), "retry-after-timeout",
            "the retry of a claim whose answer was lost was admitted (err ): the commit had already landed");
        int calls = 0;
        Fails(RunS((k, n, m) => Is(k, "retry") && ++calls == 2 ? throw new InvalidOperationException("boom") : m.Claim(k, n)), "retry-after-timeout",
            "the retry of a claim whose answer was lost was admitted (err boom): the commit had already landed");
        Fails(RunS((k, n, m) => Is(k, "retry") && n == 2 ? new ClaimResult(false) : m.Claim(k, n)), "retry-after-timeout", "the next counter after the retry was not admitted (err refused)");
    }

    [Fact]
    public void AnExceptionWithoutAMessageIsAnAnswerTheLossyWrapperDidNotLose()
    {
        // the only way a claim comes back (false, null) through the wrapper: the store's exception reports a null Message
        int calls = 0;
        Fails(RunS((k, n, m) => Is(k, "retry") && ++calls == 1 ? throw new NullMessage() : m.Claim(k, n)), "retry-after-timeout", "the lossy wrapper must lose the first answer");
    }

    [Fact]
    public void AStoreThatCannotShareRetriesOnItsOnlyHandle()
    {
        // each Open is a fresh store: only the handle that took the lost claim knows about it
        var r = StoreConformance.RunStateStore(new StateStoreConformance { Open = () => new MemoryStateStore(), Shared = false });
        Assert.True(r.Ok, r.ToString());
    }

    [Fact]
    public void TheLossyWrapperCommitsThenLosesTheFirstAnswerOnly()
    {
        var t = typeof(StoreConformance).GetNestedType("LossyStore", BindingFlags.NonPublic)!;
        var mem = new MemoryStateStore();
        var lossy = (IStateStore)Activator.CreateInstance(t, new object[] { mem })!;
        var e = Assert.Throws<TimeoutException>(() => lossy.Claim("k", 1));
        Assert.Equal("timeout (answer lost after commit)", e.Message);
        Assert.Equal(1L, mem.Last("k"));
        Assert.Equal(new ClaimResult(true), lossy.Claim("k", 2));
    }

    // ================= operation store: harness =================

    sealed class OpBackend
    {
        public MemoryOperationStore M = new();
        public int Restarts;
        public readonly List<OpHandle> Handles = new();
        public Func<OperationRecord, (bool Created, OperationRecord? Existing)?>? OnCreate;
        public Func<string, OperationRecord?, OperationRecord?>? OnGet;
        public Func<string, string, OperationRecord, bool?>? OnTransition;
    }

    sealed class OpHandle : IOperationStore, IDisposable
    {
        readonly OpBackend _b;
        public readonly ConcurrentQueue<OperationRecord> Creates = new();
        public readonly ConcurrentQueue<string> Transitions = new();
        public int Disposed;
        public OpHandle(OpBackend b) => _b = b;

        public (bool Created, OperationRecord? Existing) Create(OperationRecord record)
        {
            Creates.Enqueue(record);
            return _b.OnCreate?.Invoke(record) ?? _b.M.Create(record);
        }

        public OperationRecord? Get(string id) => _b.OnGet != null ? _b.OnGet(id, _b.M.Get(id)) : _b.M.Get(id);

        public bool Transition(string id, string from, OperationRecord next)
        {
            Transitions.Enqueue(id);
            return _b.OnTransition?.Invoke(id, from, next) ?? _b.M.Transition(id, from, next);
        }

        public void Dispose() { Disposed++; throw new InvalidOperationException("close failed"); }
    }

    static ConformanceReport RunO(OpBackend b, bool shared = true, bool durable = true, int copies = 3, bool wipeOnRestart = false) =>
        StoreConformance.RunOperationStore(new OperationStoreConformance
        {
            Name = "t",
            Open = () => { var h = new OpHandle(b); b.Handles.Add(h); return h; },
            Restart = () => { b.Restarts++; if (wipeOnRestart) b.M = new MemoryOperationStore(); },
            Shared = shared, Durable = durable, Copies = copies,
        });

    static (bool Created, OperationRecord? Existing)? Res(bool created) => (created, null);

    static readonly string[] OpChecks = { "create-once", "transition-once", "wrong-state", "get-missing", "shared", "durability" };

    // ================= operation store: shape =================

    [Fact]
    public void EveryOperationCheckRunsInOrderOnItsOwnHandlesAndClosesThem()
    {
        var b = new OpBackend();
        var r = RunO(b);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(OpChecks, r.Checks.Select(c => c.Name).ToArray());
        Assert.All(r.Checks, c => Assert.Equal("pass", c.Status));
        // create 2, transition 2, wrong 1, get 1, shared 2, durability 2
        Assert.Equal(10, b.Handles.Count);
        Assert.All(b.Handles, h => Assert.Equal(1, h.Disposed));
        Assert.Equal(1, b.Restarts);
    }

    [Fact]
    public void AStoreThatCannotShareGetsOneHandlePerCheckClosedOnce()
    {
        var b = new OpBackend();
        var r = RunO(b, shared: false, durable: false);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(4, b.Handles.Count);
        Assert.All(b.Handles, h => Assert.Equal(1, h.Disposed));
        Assert.Equal(new ConformanceCheck("shared", "skip", "Shared is false"), r.Checks.Single(c => c.Name == "shared"));
        Assert.Equal(new ConformanceCheck("durability", "skip", "Durable is false"), r.Checks.Single(c => c.Name == "durability"));
    }

    [Fact]
    public void RacesSplitAcrossTheTwoHandlesByParity()
    {
        var b = new OpBackend();
        Assert.True(RunO(b, copies: 3).Ok);
        // copies 0 and 2 on the first handle, copy 1 on the second
        Assert.Equal((2, 1), (b.Handles[0].Creates.Count, b.Handles[1].Creates.Count));
        Assert.Equal((2, 1), (b.Handles[2].Transitions.Count, b.Handles[3].Transitions.Count));
    }

    [Fact]
    public void CopiesSizeTheRaceWithADefault()
    {
        static int Creates(int copies)
        {
            var b = new OpBackend();
            var r = RunO(b, copies: copies);
            Assert.True(r.Ok, r.ToString());
            return b.Handles[0].Creates.Count + b.Handles[1].Creates.Count;
        }
        Assert.Equal(3, Creates(3));
        Assert.Equal(1, Creates(1));
        Assert.Equal(16, Creates(0));
        Assert.Equal(16, Creates(-1));
    }

    [Fact]
    public void TheProbeRecordIsExact()
    {
        var b = new OpBackend();
        RunO(b);
        var rec = b.Handles[0].Creates.First();
        Assert.Equal(new OperationRecord(rec.Id, OperationStates.Pending, "v", "/r", "d", "reversible", 1), rec);
    }

    [Fact]
    public void EveryOperationCheckUsesItsOwnId()
    {
        var ids = new ConcurrentBag<string>();
        var b = new OpBackend
        {
            OnCreate = rec => { ids.Add(rec.Id); return null; },
            OnGet = (id, cur) => { ids.Add(id); return cur; },
            OnTransition = (id, _, _) => { ids.Add(id); return null; },
        };
        Assert.True(RunO(b).Ok);
        Assert.All(ids, k => Assert.StartsWith("conf:", k));
        Assert.Equal(new[] { "create", "durable", "missing", "never", "shared", "transition", "wrong" },
            ids.Select(k => k[(k.LastIndexOf(':') + 1)..]).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToArray());
    }

    // ================= operation store: each broken store, by check =================

    [Fact]
    public void CreateOnceCatchesALoserWithoutTheExistingRecord()
    {
        var b = new OpBackend();
        b.OnCreate = rec => Res(b.M.Create(rec).Created);
        Fails(RunO(b), "create-once", "201 concurrent creates of one id reported created (want exactly 1; >=100 means a loser got no existing record)");
    }

    [Fact]
    public void ACreateThatFailsIsReportedByEveryCheckThatNeedsOne()
    {
        foreach (var (suffix, check) in new[] { ("transition", "transition-once"), ("wrong", "wrong-state"), ("shared", "shared"), ("durable", "durability") })
        {
            var b = new OpBackend { OnCreate = rec => Is(rec.Id, suffix) ? Res(false) : null };
            Fails(RunO(b), check, "create failed");
        }
    }

    [Fact]
    public void TransitionOnceCatchesManyWinners()
    {
        var b = new OpBackend { OnTransition = (id, _, _) => Is(id, "transition") ? (bool?)true : null };
        Fails(RunO(b), "transition-once", "3 concurrent transitions out of pending won (want exactly 1)");
    }

    [Fact]
    public void WrongStateCatchesEachViolation()
    {
        var applied = new OpBackend { OnTransition = (id, _, _) => Is(id, "wrong") ? (bool?)true : null };
        Fails(RunO(applied), "wrong-state", "a transition from the wrong state applied");

        var changed = new OpBackend();
        changed.OnTransition = (id, _, next) =>
        {
            if (!Is(id, "wrong")) return null;
            changed.M.Transition(id, OperationStates.Pending, next);
            return false;
        };
        Fails(RunO(changed), "wrong-state", "the record changed after a refused transition: committed");

        var lost = new OpBackend { OnGet = (id, cur) => Is(id, "wrong") ? null : cur };
        Fails(RunO(lost), "wrong-state", "the record changed after a refused transition: missing");

        var unknown = new OpBackend { OnTransition = (id, _, _) => Is(id, "missing") ? (bool?)true : null };
        Fails(RunO(unknown), "wrong-state", "a transition of an unknown id applied");
    }

    [Fact]
    public void GetMissingCatchesAPhantomRecord()
    {
        var b = new OpBackend { OnGet = (id, cur) => Is(id, "never") ? new OperationRecord(id, OperationStates.Pending, "v", "/r", "d", "reversible", 1) : cur };
        Fails(RunO(b), "get-missing", "an unknown id returned a record (pending)");
    }

    [Fact]
    public void SharedCatchesAHandleThatSeesNothing()
    {
        var b = new OpBackend { OnGet = (id, cur) => Is(id, "shared") ? null : cur };
        Fails(RunO(b), "shared", "another handle does not see the record");
    }

    [Fact]
    public void DurabilityRestartsAndCatchesALostRecord()
    {
        var b = new OpBackend();
        Fails(RunO(b, wipeOnRestart: true), "durability", "the record did not survive closing every handle");
        Assert.Equal(1, b.Restarts);
    }

    // ================= Issue: harness =================

    const long Now = 1_800_000_000_000L;
    static SuiteKey K(byte b) => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray()));
    static SuiteKey P => K(0x61);
    static SuiteKey A => K(0x62);
    static SuiteKey B => K(0x63);

    static void Refuses(Action f, string message)
    {
        var e = Assert.Throws<ArgumentException>(f);
        Assert.Equal(message, e.Message);
    }

    static JD Envelope() => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static JD Env(string key, object? value) { var e = Envelope(); e[key] = value; return e; }
    static JD MintedEnvelope(JD env) => (JD)((JL)Issue.MintGrant(P, A.Id!, null, env, "g", "salt").Grant["caveats"]!)[0]!;

    // ================= Issue: values =================

    [Fact]
    public void DefaultRiskPolicyIsTheReferences() =>
        // risk.ts:41
        Assert.Equal("""{"bMax":1,"kappa":1,"lambda":0.0005,"rho":0.5,"theta1":0.25,"theta2":0.6,"weights":{"alpha":0.25,"beta":0.2,"delta":0.2,"epsilon":0.1,"gamma":0.2,"zeta":0.05}}""",
            Pca.Canonicalize(Issue.DefaultRiskPolicy()));

    [Fact]
    public void ActSpecDefaultsAreEmpty()
    {
        Assert.Equal("", new ActSpec().NodeId);
        Assert.Equal("", new ActSpec().Aud);
    }

    // ================= Issue: plans =================

    [Fact]
    public void CommitPlanRefusals()
    {
        Refuses(() => Issue.CommitPlan(Array.Empty<JD>()), "merkleRoot: empty leaf set"); // merkle.ts:95
        Refuses(() => Issue.CommitPlan(new[] { new JD { ["verb"] = "v" } }), "commitPlan: missing node id"); // stricter than merkle.ts:190
        Refuses(() => Issue.CommitPlan(new[] { new JD { ["id"] = 5L } }), "commitPlan: missing node id");
        Refuses(() => Issue.CommitPlan(new[] { new JD { ["id"] = "a" }, new JD { ["id"] = "b" }, new JD { ["id"] = "a" } }), "commitPlan: duplicate node id a"); // merkle.ts:191
    }

    [Fact]
    public void ProofForAnUnknownNodeIsRefused()
    {
        var p = Issue.CommitPlan(new[] { new JD { ["id"] = "a" }, new JD { ["id"] = "b" } });
        Refuses(() => p.ProofFor("nope"), "commitPlan: unknown node nope"); // merkle.ts:200
        Assert.Equal(1L, p.ProofFor("b")["index"]);
    }

    // ================= Issue: grants and chain =================

    [Fact]
    public void MintRootNeedsAnEd25519Identity() =>
        Refuses(() => Issue.MintRoot(SuiteKey.Create("ml-dsa-65", null, PqKey.Generate(Pq.Prim.MlDsa65)), A.Id!, null, new JL()), "a root issuer needs an Ed25519 identity");

    [Fact]
    public void MintGrantRefusals()
    {
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Envelope(), ""), "mintGrant: goal required"); // envelope.ts:166
        foreach (var k in new[] { "predicates", "caveats" })
        {
            var gone = Envelope();
            gone.Remove(k);
            Refuses(() => Issue.MintGrant(P, A.Id!, null, gone, "g"), $"mintGrant: envelope.{k} is required"); // stricter than envelope.ts:192
            Refuses(() => Issue.MintGrant(P, A.Id!, null, Env(k, null), "g"), $"mintGrant: envelope.{k} is required");
        }
    }

    [Fact]
    public void MintGrantValidatesTheEnvelopeLikeTheReference()
    {
        // envelope.ts:167-187
        var noRisk = Envelope();
        noRisk.Remove("risk_policy");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, noRisk, "g"), "mintGrant: risk_policy must be an object");
        var zeroKappa = Issue.DefaultRiskPolicy();
        zeroKappa["kappa"] = 0L;
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("risk_policy", zeroKappa), "g"), "mintGrant: risk_policy.kappa must be > 0");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("units", "x"), "g"), "mintGrant: units must be an object");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("tighten", "x"), "g"), "mintGrant: tighten must be an array");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("tighten", null), "g"), "mintGrant: tighten must be an array");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("template_ref", "x"), "g"), "mintGrant: template_ref must be an object");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("actions", "x"), "g"), "mintGrant: actions must be an object");
        Refuses(() => Issue.MintGrant(P, A.Id!, null, Env("model_polarity", "strict"), "g"), "mintGrant: model_polarity must be 'legacy' when present");
        Assert.Equal("legacy", MintedEnvelope(Env("model_polarity", "legacy"))["model_polarity"]);
    }

    [Fact]
    public void MintGrantReportsTheFirstBadMemberInTheReferenceOrder()
    {
        // envelope.ts:167-187
        var chain = new (string Key, string Bad, string Message)[]
        {
            ("risk_policy", "x", "risk_policy must be an object"), // risk.ts:53
            ("units", "x", "units must be an object"), // envelope-rules.ts:57
            ("tighten", "x", "tighten must be an array"),
            ("template_ref", "x", "template_ref must be an object"), // envelope-rules.ts:90
            ("actions", "x", "actions must be an object"), // action-pin.ts:111
            ("provenance", "x", "provenance must be an object"), // arg-provenance.ts:461
            ("model_polarity", "strict", "model_polarity must be 'legacy' when present"),
        };
        for (int i = 0; i + 1 < chain.Length; i++)
        {
            var both = Env(chain[i].Key, chain[i].Bad);
            both[chain[i + 1].Key] = chain[i + 1].Bad;
            Refuses(() => Issue.MintGrant(P, A.Id!, null, both, "g"), "mintGrant: " + chain[i].Message);
        }
    }

    [Fact]
    public void MintGrantKeepsOnlyTheEnvelopeMembers()
    {
        var env = Envelope();
        env["goal_commit"] = "forged";
        env["type"] = "forged";
        env["junk"] = true;
        env["objective_risk"] = "o";
        env["progress"] = "p";
        env["tighten"] = new JL();
        env["units"] = new JD { ["action.params.x"] = new JD { ["kind"] = "usd" } };
        env["template_ref"] = new JD { ["template_id"] = "t", ["version_digest"] = "v", ["slots"] = new JD() };
        env["actions"] = new JD { ["pack"] = new JD { ["ns"] = "acme", ["root"] = Digest }, ["on_new_action"] = "deny" };
        env["provenance"] = new JD { ["mode"] = "enforce" };
        var cv = MintedEnvelope(env);
        foreach (var k in new[] { "units", "template_ref", "actions", "provenance" }) Assert.Equal(Pca.Canonicalize(env[k]), Pca.Canonicalize(cv[k]));
        Assert.Equal(Issue.GoalCommit("g", "salt"), cv["goal_commit"]);
        Assert.Equal("envelope", cv["type"]);
        Assert.False(cv.ContainsKey("junk")); // envelope.ts:190 builds the member list itself
        Assert.Equal(("o", "p"), (cv["objective_risk"], cv["progress"]));
        Assert.Empty((JL)cv["tighten"]!);
        Assert.Equal("{}", Pca.Canonicalize(cv["agent_binding"]));
        // envelope.ts:194: a null binding is no binding, a real one is kept
        Assert.Equal("{}", Pca.Canonicalize(MintedEnvelope(Env("agent_binding", null))["agent_binding"]));
        Assert.Equal("""{"operator":"op"}""", Pca.Canonicalize(MintedEnvelope(Env("agent_binding", new JD { ["operator"] = "op" }))["agent_binding"]));
    }

    [Fact]
    public void DelegateCommitsTheHolderPqKey()
    {
        var parent = Issue.MintRoot(P, A.Id!, "parent-pk", new JL());
        var parentPq = Pca.HolderPqCommitment("parent-pk");
        Assert.Equal(parentPq, parent["holder_pq"]);
        // capability.ts:399: a new key wins; else kept only when the holder is unchanged
        Assert.Equal(Pca.HolderPqCommitment("child-pk"), Issue.Delegate(parent, B.Id!, null, A, "child-pk")["holder_pq"]);
        Assert.Equal(parentPq, Issue.Delegate(parent, A.Id!, null, A)["holder_pq"]);
        Assert.False(Issue.Delegate(parent, B.Id!, null, A).ContainsKey("holder_pq"));
    }

    [Fact]
    public void AttenuateKeepsTheHolderAndOnlyAddsCaveats()
    {
        var added = new JD { ["type"] = "ttl", ["ms"] = 5L };
        var parent = Issue.MintRoot(P, A.Id!, "parent-pk", new JL());
        var child = Issue.Attenuate(parent, new JL { added }, A);
        Assert.Equal((A.Id, A.Id, Pca.CapHash(parent), Pca.HolderPqCommitment("parent-pk")), (child["holder"], child["issuer"], child["parent"], child["holder_pq"]));
        Assert.Equal("""[{"ms":5,"type":"ttl"}]""", Pca.Canonicalize(child["caveats"]));
    }

    // ================= Issue: PCActn =================

    static ActSpec Spec(JD? node = null, JD? prms = null)
    {
        var g = Issue.MintGrant(P, A.Id!, null, Envelope(), "g");
        var n = node ?? new JD { ["id"] = "n1", ["verb"] = "pay", ["resource"] = "r" };
        return new ActSpec { Grant = g.Grant, Chain = new JL { g.Grant }, Plan = Issue.CommitPlan(new[] { n }), NodeId = "n1", Params = prms, Counter = 1, Signer = A, Aud = "aud", Iat = Now };
    }

    [Fact]
    public void BuildPCActnRefusals()
    {
        var noAud = Spec();
        noAud.Aud = "";
        Refuses(() => Issue.BuildPCActn(noAud), "buildPCActn: aud (audience) is required"); // pcactn.ts:365
        var unknown = Spec();
        unknown.NodeId = "nope";
        Refuses(() => Issue.BuildPCActn(unknown), "buildPCActn: unknown plan node nope"); // pcactn.ts:367
        var digest = Pca.ParamsDigest(new JD { ["a"] = 1L });
        Refuses(() => Issue.BuildPCActn(Spec(new JD { ["id"] = "n1", ["params_digest"] = digest }, new JD { ["a"] = 2L })), "buildPCActn: params do not match plan node n1's params_digest"); // pcactn.ts:370
        Assert.Equal(digest, ((JD)Issue.BuildPCActn(Spec(new JD { ["id"] = "n1", ["params_digest"] = digest }, new JD { ["a"] = 1L }))["action"]!)["params_digest"]);
    }

    [Fact]
    public void BuildPCActnRefusesANullParamsDigestLikeTheReference() =>
        // pcactn.ts:369: only an absent digest skips the comparison
        Refuses(() => Issue.BuildPCActn(Spec(new JD { ["id"] = "n1", ["params_digest"] = null })), "buildPCActn: params do not match plan node n1's params_digest");

    [Fact]
    public void BuildPCActnTimes()
    {
        var clock = Spec();
        clock.Iat = null;
        long before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var iat = Assert.IsType<long>(Issue.BuildPCActn(clock)["iat"]);
        Assert.InRange(iat, before, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        var dflt = Issue.BuildPCActn(Spec());
        Assert.Equal((Now, Now + 1_200_000L), (dflt["iat"], dflt["exp"])); // pcactn.ts:150
        var ttl = Spec();
        ttl.TtlMs = 5;
        Assert.Equal(Now + 5, Issue.BuildPCActn(ttl)["exp"]);
        var exp = Spec();
        exp.Exp = Now + 9;
        exp.TtlMs = 5;
        Assert.Equal(Now + 9, Issue.BuildPCActn(exp)["exp"]);
    }

    [Fact]
    public void BuildPCActnCarriesTheSuppliedBlocks()
    {
        JD Block(string v) => new() { ["x"] = v };
        var s = Spec();
        s.Attestation = Block("att");
        s.Provenance = Block("prov");
        s.Freshness = Block("fresh");
        s.RiskClaim = Block("risk");
        s.ProgressStep = Block("step");
        s.Intent = Block("intent");
        s.IntentSession = Block("session");
        var evidence = new JL { "e" };
        s.ProhibitionEvidence = evidence;
        var a = Issue.BuildPCActn(s);
        Assert.Same(s.Attestation, a["attestation"]);
        Assert.Same(s.Provenance, a["provenance"]);
        Assert.Same(s.Freshness, a["freshness"]);
        Assert.Same(s.RiskClaim, a["risk_claim"]);
        Assert.Same(s.ProgressStep, a["progress_step"]);
        Assert.Same(s.Intent, a["intent"]);
        Assert.Same(s.IntentSession, a["intent_session"]);
        Assert.Same(evidence, a["prohibition_evidence"]);
        var plain = Issue.BuildPCActn(Spec());
        foreach (var k in new[] { "progress_step", "prohibition_evidence", "intent", "intent_session" }) Assert.False(plain.ContainsKey(k));
        // pcactn.ts:393-397
        Assert.Equal("""{"epoch":0,"measurement":"","model_id":"unattested","operator":"unattested","quote_digest":""}""", Pca.Canonicalize(plain["attestation"]));
        Assert.Equal("""{"causal_hash":"","taint_level":0,"trusted_refs":[]}""", Pca.Canonicalize(plain["provenance"]));
        Assert.Equal("""{"accumulator_witness":"","beacon_ref":"","epoch":0}""", Pca.Canonicalize(plain["freshness"]));
        Assert.Equal("""{"inputs":{},"r":0}""", Pca.Canonicalize(plain["risk_claim"]));
    }

    // ================= Issue: signed artifacts =================

    static string Digest => Pca.HashCanonical("store-issue-kill");
    static JD Hop() => Issue.NormJ(Issue.MintGrant(P, A.Id!, null, Envelope(), "g").Grant);

    [Fact]
    public void DischargeBindsAndRefuses()
    {
        var d = Issue.Discharge(B, "kyc", "svc", Hop(), "action", Digest, null, Now, Now + 1);
        Assert.Equal(Digest, d["action_digest"]);
        Assert.False(Issue.Discharge(B, "kyc", "svc", Hop(), "chain_hop", Digest, null, Now, Now + 1).ContainsKey("action_digest"));
        Refuses(() => Issue.Discharge(B, "kyc", "svc", Hop(), "chain_hop", null, null, Now, Now), "signDischarge: not_after must be greater than iat");
        Refuses(() => Issue.Discharge(B, "kyc", "svc", Hop(), "action", null, null, Now, Now + 1), "signDischarge: action_digest is required for bind action and forbidden for chain_hop");
    }

    [Fact]
    public void NarrowBindsAndRefuses()
    {
        var cav = new JL { new JD { ["type"] = "max_uses", ["id"] = "u", ["n"] = 2L, ["until"] = Now + 5 } };
        Assert.Equal(Digest, Issue.Narrow(A, Hop(), cav, Digest, Now, Now + 1)["action_digest"]);
        Assert.False(Issue.Narrow(A, Hop(), cav, null, Now, Now + 1).ContainsKey("action_digest"));
        Refuses(() => Issue.Narrow(A, Hop(), cav, null, Now, Now), "signNarrow: not_after must be greater than iat");
    }

    [Fact]
    public void EscalationAnswerCarriesTheDecisionAndRender()
    {
        var g = Issue.MintGrant(P, A.Id!, null, Envelope(), "g");
        var grant = Issue.NormJ(g.Grant);
        var act = Issue.NormJ(new Agent(A, "aud", g.Grant) { Clock = () => Now }.Act("read", "x"));
        Assert.Equal("allow", Issue.EscalationAnswer(P, grant, act, null, true, Now, Now + 1)["decision"]);
        var deny = Issue.EscalationAnswer(P, grant, act, null, false, Now, Now + 1, Digest);
        Assert.Equal(("deny", Digest), (deny["decision"], deny["render_digest"]));
        Assert.False(Issue.EscalationAnswer(P, grant, act, null, true, Now, Now + 1).ContainsKey("render_digest"));
        Refuses(() => Issue.EscalationAnswer(P, grant, act, null, true, Now, Now), "signEscalationAnswer: expires_at must be greater than iat");
    }

    // ================= Issue: workflow =================

    static JD WfStep(string id, params string[] deps) => new()
    {
        ["id"] = id, ["verb"] = "call", ["resource"] = "res", ["params_digest"] = null, ["deps"] = deps.Select(x => (object?)x).ToList(),
        ["sink"] = null, ["deny_labels"] = new JL(), ["escalate_labels"] = new JL(), ["fresh_ms"] = null, ["cost"] = new JD(),
    };

    static JD WfBody(string principal, params JD[] steps) => new()
    {
        ["v"] = 1L, ["id"] = "wf1", ["principal"] = principal, ["goal_digest"] = null, ["plan_root"] = null, ["issued_at"] = 1L, ["expires_at"] = 2L,
        ["steps"] = steps.Select(x => (object?)x).ToList(), ["edges"] = new JL(), ["budget"] = new JD { ["max_steps"] = 10L, ["caps"] = new JD() },
    };

    [Fact]
    public void SignWorkflowRefusals()
    {
        var pk = P.Ed!;
        Assert.Equal(pk.Id, ((JD)Issue.SignWorkflow(pk, WfBody(pk.Id, WfStep("a")))["body"]!)["principal"]);
        Refuses(() => Issue.SignWorkflow(pk, WfBody(pk.Id, WfStep("a", "b"), WfStep("b", "a"))), "signWorkflow: malformed workflow"); // workflow.ts:219
        Refuses(() => Issue.SignWorkflow(pk, WfBody(pk.Id)), "signWorkflow: malformed workflow");
        Refuses(() => Issue.SignWorkflow(pk, WfBody(A.Id!, WfStep("a"))), "signWorkflow: principal is not the signer"); // workflow.ts:220
    }

    [Fact]
    public void ReceiptSequenceFollowsPrevWhateverItsNumberType()
    {
        var rs = B.Ed!;
        var wf = Issue.NormJ(WfBody(P.Id!, WfStep("a")));
        JD Receipt(JD? prev) => Issue.SignStepReceipt(rs, wf, "a", "ok", Digest, new JD(), 5, prev);
        var first = Receipt(null);
        Assert.Equal(new Num("0"), first["seq"]);
        Assert.Equal(new Num("1"), Receipt(first)["seq"]);
        Assert.Equal(new Num("5"), Receipt(new JD(first) { ["seq"] = 4L })["seq"]);
    }

    [Fact]
    public void WfOutputSortsLabelsAndCarriesOnlyNumbers()
    {
        // workflow.ts:231: num only when asked for and the value is a number
        var n = Issue.WfOutput(5L, new[] { "b", "a", "B" }, "usd", true);
        Assert.Equal(Workflow.ValueDigest(5L), n["digest"]);
        Assert.Equal("usd", n["unit"]);
        Assert.Equal(new JL { "B", "a", "b" }, (JL)n["labels"]!);
        Assert.Empty((JL)Issue.WfOutput(5L)["labels"]!);
        Assert.Equal(5L, n["num"]);
        Assert.Equal(7, Issue.WfOutput(7, null, null, true)["num"]);
        Assert.Equal(new Num("9"), Issue.WfOutput(new Num("9"), null, null, true)["num"]);
        Assert.Null(Issue.WfOutput("s", null, null, true)["num"]);
        Assert.Null(Issue.WfOutput(true, null, null, true)["num"]);
        Assert.Null(Issue.WfOutput(5L, null, null, false)["num"]);
        Assert.Null(Issue.WfOutput(5, null, null, false)["num"]);
    }

    // ================= Issue: read grants =================

    static JD ReadBody(string principal, bool valid = true) => new()
    {
        ["v"] = 1L, ["id"] = "g1", ["principal"] = principal, ["issued_at"] = 1L, ["expires_at"] = 2L, ["caps"] = new JD(), ["sinks"] = new JD(),
        ["reads"] = valid
            ? new JL { new JD { ["verb"] = "read", ["resource_prefix"] = "r/", ["purposes"] = new JL { "audit" }, ["modes"] = new JD(), ["default_mode"] = "hash" } }
            : new JL(),
    };

    static JD AggBody(string principal, bool valid = true) => new()
    {
        ["v"] = 1L, ["id"] = "g1", ["principal"] = principal, ["issued_at"] = 1L, ["expires_at"] = 2L, ["epsilon_budget_micro"] = 1L, ["max_queries"] = 1L,
        ["rules"] = valid
            ? new JL { new JD { ["verb"] = "read", ["resource_prefix"] = "r/", ["purposes"] = new JL { "audit" }, ["fns"] = new JL { "count" }, ["min_group"] = 1L, ["clamp"] = 1L, ["epsilon_micro"] = 1L, ["dp"] = true } }
            : new JL(),
    };

    [Fact]
    public void SignReadGrantRefusesEachSide()
    {
        var pk = P.Ed!;
        Assert.Equal("g1", ((JD)Issue.SignReadGrant(pk, ReadBody(pk.Id))["body"]!)["id"]);
        Refuses(() => Issue.SignReadGrant(pk, ReadBody(A.Id!)), "signReadGrant: malformed grant"); // readside.ts:95
        Refuses(() => Issue.SignReadGrant(pk, ReadBody(pk.Id, valid: false)), "signReadGrant: malformed grant");
    }

    [Fact]
    public void SignAggregateGrantRefusesEachSide()
    {
        var pk = P.Ed!;
        Assert.Equal("g1", ((JD)Issue.SignAggregateGrant(pk, AggBody(pk.Id))["body"]!)["id"]);
        Refuses(() => Issue.SignAggregateGrant(pk, AggBody(A.Id!)), "signAggregateGrant: malformed grant"); // read-vault.ts:95
        Refuses(() => Issue.SignAggregateGrant(pk, AggBody(pk.Id, valid: false)), "signAggregateGrant: malformed grant");
    }

    // ================= Issue: passports =================

    static JD Pass(object? hw) => Issue.IssuePassport(new JD { ["model_id"] = "m", ["operator"] = "o", ["hardware_rooted"] = hw });

    [Fact]
    public void FingerprintCoversEveryIdentityField()
    {
        // passport.ts:44
        var p = new JD { ["model_id"] = "m", ["weights_digest"] = "w", ["system_prompt_digest"] = "s", ["tool_manifest_digest"] = "t", ["runtime_measurement"] = "r", ["operator"] = "o", ["hardware_rooted"] = false };
        Assert.Equal(Pca.HashCanonical(new JD
        {
            ["d"] = "atlas-pca/passport/v1", ["model_id"] = "m", ["weights_digest"] = "w", ["system_prompt_digest"] = "s", ["tool_manifest_digest"] = "t",
            ["runtime_measurement"] = "r", ["operator"] = "o", ["hardware_rooted"] = false,
        }), Issue.PassportFingerprint(p));
    }

    [Fact]
    public void SignPassportRefusals()
    {
        var forged = Pass(false);
        forged["id"] = "forged";
        Refuses(() => Issue.SignPassport(forged, P, "sub", Now, Now + 1), "signPassport: passport.id is not the fingerprint of its identity (use issuePassport)"); // passport.ts:225
        const string NeedsEvidence = "signPassport: hardware_rooted requires attestation evidence (fail closed)"; // passport.ts:226
        Refuses(() => Issue.SignPassport(Pass(true), P, "sub", Now, Now + 1), NeedsEvidence);
        // truthy in the reference, not only true
        Refuses(() => Issue.SignPassport(Pass(1L), P, "sub", Now, Now + 1), NeedsEvidence);
        Refuses(() => Issue.SignPassport(Pass("yes"), P, "sub", Now, Now + 1), NeedsEvidence);
        Assert.True(Issue.SignPassport(Pass(false), P, "sub", Now, Now + 1).ContainsKey("sig"));
    }

    [Fact]
    public void SignPassportTimes()
    {
        const string Bad = "signPassport: iat/nbf/exp must be safe integers with exp > nbf"; // passport.ts:232
        var pp = Pass(false);
        Refuses(() => Issue.SignPassport(pp, P, "sub", Now, Now), Bad);
        Refuses(() => Issue.SignPassport(pp, P, "sub", Now, Now - 1), Bad);
        Assert.Equal(new Num((Now + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)), Issue.SignPassport(pp, P, "sub", Now, Now + 1)["exp"]);
        // nbf defaults to iat, and when set it is what exp is measured against
        Assert.Equal(new Num("100"), Issue.SignPassport(pp, P, "sub", 100, 200)["nbf"]);
        Assert.Equal(new Num("150"), Issue.SignPassport(pp, P, "sub", 100, 200, 150)["nbf"]);
        Refuses(() => Issue.SignPassport(pp, P, "sub", 100, 150, 150), Bad);
        // the safe-integer boundary on each side of each time
        Assert.True(Issue.SignPassport(pp, P, "sub", -Pca.MaxSafeInt, Pca.MaxSafeInt).ContainsKey("sig"));
        Refuses(() => Issue.SignPassport(pp, P, "sub", 100, Pca.MaxSafeInt + 1), Bad);
        Refuses(() => Issue.SignPassport(pp, P, "sub", -Pca.MaxSafeInt - 1, 200, 100), Bad);
        Refuses(() => Issue.SignPassport(pp, P, "sub", 100, 200, -Pca.MaxSafeInt - 1), Bad);
        Refuses(() => Issue.SignPassport(pp, P, "sub", long.MinValue, 200, 100), Bad);
    }

    [Fact]
    public void SignPassportEvidence()
    {
        var evidence = new JD { ["document"] = new JD { ["nonce"] = "n" } };
        var filled = (JD)Issue.SignPassport(Pass(true), P, "sub", 100, 200, null, evidence)["evidence"]!;
        Assert.Equal(new Num("100"), filled["at"]);
        Assert.Equal("""{"nonce":"n"}""", Pca.Canonicalize(filled["document"]));
        Assert.False(evidence.ContainsKey("at")); // the caller's object is not written to
        var kept = (JD)Issue.SignPassport(Pass(true), P, "sub", 100, 200, null, new JD(evidence) { ["at"] = 50L })["evidence"]!;
        Assert.Equal(new Num("50"), kept["at"]);
        Assert.False(Issue.SignPassport(Pass(false), P, "sub", 100, 200).ContainsKey("evidence"));
    }

    [Fact]
    public void SignPassportBindsTheSuite()
    {
        var pq = PqKey.Generate(Pq.Prim.MlDsa65);
        var hybrid = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", K(0x64).Ed, pq);
        var h = Issue.SignPassport(Pass(false), hybrid, "sub", 100, 200);
        Assert.Equal(("hybrid-ed25519-ml-dsa-65", pq.PkB64u), (h["alg"], h["pq_pk"]));
        Assert.IsType<string>(h["pq_sig"]);
        var e = Issue.SignPassport(Pass(false), P, "sub", 100, 200);
        foreach (var k in new[] { "alg", "pq_pk", "pq_sig" }) Assert.False(e.ContainsKey(k));
    }
}
