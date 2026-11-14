using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The key-value, budget and pin conformance kits: the exact names, order, sizes and failure messages of their reports, every handle opened is
// closed, the race loops run their rounds, and the restart runs between closing and reopening. Each defect is a single-fault store double.
public class StoreConformanceKvKillTests
{
    const string Durable = "Durable is false (state dies with the process)";

    static string Note(ConformanceReport r, string name) => r.Checks.First(c => c.Name == name).Note;
    static string Status(ConformanceReport r, string name) => r.Checks.First(c => c.Name == name).Status;
    static string[] Names(ConformanceReport r) => r.Checks.Select(c => c.Name).ToArray();

    sealed class Probe
    {
        public int Opened, Disposed, Calls, Restarts;
        public readonly List<string> Keys = new();
        public readonly List<string> Written = new();
        public readonly object Gate = new();
        public void Key(string k) { lock (Gate) Keys.Add(k); }
    }

    static void AssertKey(Probe p, string suffix) => Assert.Contains(p.Keys, k => k.EndsWith(":" + suffix, StringComparison.Ordinal));

    static (int R, int C, int H) Sizes(int rounds, int copies, int handles, bool shared) =>
        (rounds <= 0 ? 10 : rounds, copies <= 0 ? 16 : copies, !shared ? 1 : handles <= 0 ? 4 : handles);

    // ================= atomic key-value store =================

    public enum KvFault { None, GetGhost, PrevStale, NoStore, PrevNull, NullStoresEmpty, NullClears, SwallowThrow, ThrowWrites, Lossy, PrefixValue }

    sealed class KvBackend
    {
        public readonly Dictionary<string, string> M = new();
        public KvFault Fault;
        public readonly Probe P = new();
    }

    sealed class FaultyKv : IAtomicKv, IDisposable
    {
        readonly KvBackend b;
        public FaultyKv(KvBackend b) { this.b = b; Interlocked.Increment(ref b.P.Opened); }
        public void Dispose() => Interlocked.Increment(ref b.P.Disposed);

        public string? Get(string key)
        {
            b.P.Key(key);
            lock (b.M) return b.M.TryGetValue(key, out var v) ? v : b.Fault == KvFault.GetGhost ? "ghost" : null;
        }

        public void Update(string key, Func<string?, string?> fn)
        {
            Interlocked.Increment(ref b.P.Calls);
            b.P.Key(key);
            if (b.Fault == KvFault.Lossy)
            {
                string? p;
                lock (b.M) p = b.M.GetValueOrDefault(key);
                var n = fn(p);
                Thread.Sleep(2); // a read outside the lock, a write after a pause: a concurrent writer's update is lost
                if (n != null) lock (b.M) b.M[key] = n;
                return;
            }
            lock (b.M)
            {
                var exists = b.M.TryGetValue(key, out var cur);
                // the faults that would make a racing function throw or loop are scoped to the one check they target
                string? prev = b.Fault == KvFault.PrevStale && key.EndsWith(":kv-replace", StringComparison.Ordinal) ? cur ?? "stale" : b.Fault == KvFault.PrevNull ? null : cur;
                string? next;
                try { next = fn(prev); }
                catch when (b.Fault == KvFault.SwallowThrow) { return; }
                catch when (b.Fault == KvFault.ThrowWrites) { b.M[key] = "boom"; throw; }
                if (next == null)
                {
                    if (b.Fault == KvFault.NullStoresEmpty) b.M[key] = "";
                    else if (b.Fault == KvFault.NullClears && exists) b.M.Remove(key);
                    return;
                }
                if (b.Fault == KvFault.NoStore) return;
                b.M[key] = b.Fault == KvFault.PrefixValue && key.EndsWith(":kv-create", StringComparison.Ordinal) ? "z" + next : next;
                lock (b.P.Gate) b.P.Written.Add(next);
            }
        }
    }

    static (ConformanceReport R, KvBackend B) RunKv(KvFault fault, bool shared = true, bool durable = false, int rounds = 0, int copies = 0, int handles = 0, bool clearOnRestart = false)
    {
        var b = new KvBackend { Fault = fault };
        var r = StoreConformance.RunAtomicKv(new AtomicKvConformance
        {
            Name = "double", Open = () => new FaultyKv(b), Shared = shared, Durable = durable, Rounds = rounds, Copies = copies, Handles = handles,
            Restart = () => { Interlocked.Increment(ref b.P.Restarts); if (clearOnRestart) lock (b.M) b.M.Clear(); },
        });
        return (r, b);
    }

    [Fact]
    public void TheDefaultsOfTheKitsAreNamedAndSized()
    {
        var kv = new AtomicKvConformance();
        Assert.Equal(("kv", 10, 16, 4, false, false), (kv.Name, kv.Rounds, kv.Copies, kv.Handles, kv.Durable, kv.Shared));
        var bu = new BudgetStoreConformance();
        Assert.Equal(("budget", 10, 16, 4, false, false), (bu.Name, bu.Rounds, bu.Copies, bu.Handles, bu.Durable, bu.Shared));
        var pi = new PinStoreConformance();
        Assert.Equal(("pins", 10, 16, 4, false, false), (pi.Name, pi.Rounds, pi.Copies, pi.Handles, pi.Durable, pi.Shared));
        Assert.Null(kv.Open); Assert.Null(bu.Open); Assert.Null(pi.Open); Assert.Null(kv.Restart); Assert.Null(bu.Restart); Assert.Null(pi.Restart);
    }

    [Fact]
    public void AMissingOpenIsOneFailedConfigurationCheck()
    {
        foreach (var r in new[] { StoreConformance.RunAtomicKv(new AtomicKvConformance()), StoreConformance.RunBudgetStore(new BudgetStoreConformance()), StoreConformance.RunPinStore(new PinStoreConformance()) })
        {
            Assert.False(r.Ok);
            Assert.Equal(new[] { new ConformanceCheck("configuration", "fail", "Open is required") }, r.Checks);
        }
        Assert.Equal("kv", StoreConformance.RunAtomicKv(new AtomicKvConformance()).Name);
        Assert.Equal("budget", StoreConformance.RunBudgetStore(new BudgetStoreConformance()).Name);
        Assert.Equal("pins", StoreConformance.RunPinStore(new PinStoreConformance()).Name);
    }

    [Fact]
    public void AHandleThatIsNullIsAFailureOfEveryCheck()
    {
        var kv = StoreConformance.RunAtomicKv(new AtomicKvConformance { Open = () => null! });
        Assert.All(kv.Checks.Where(c => c.Name != "durability"), c => Assert.Equal(("fail", "Open returned null"), (c.Status, c.Note)));
        var bu = StoreConformance.RunBudgetStore(new BudgetStoreConformance { Open = () => null! });
        Assert.Equal("Open returned null", Note(bu, "budget-missing"));
        var pi = StoreConformance.RunPinStore(new PinStoreConformance { Open = () => null! });
        Assert.Equal("Open returned null", Note(pi, "pin-missing"));
    }

    [Fact]
    public void ThePassingKvReportListsEveryCheckInOrderAndSkipsDurabilityHonestly()
    {
        var (r, b) = RunKv(KvFault.None);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal("double", r.Name);
        Assert.Equal(new[] { "get-missing", "update-creates-and-replaces", "update-null-keeps", "update-concurrent", "create-once", "update-throw-keeps", "durability" }, Names(r));
        Assert.Equal(new[] { "pass", "pass", "pass", "pass", "pass", "pass", "skip" }, r.Checks.Select(c => c.Status));
        Assert.Equal(new[] { "", "", "", "10 rounds x 16 copies over 4 handle(s)", "", "", Durable }, r.Checks.Select(c => c.Note));
        Assert.Equal(0, b.P.Restarts);
        foreach (var s in new[] { "kv-get-missing", "kv-replace", "kv-null", "kv-throw", "kv-concurrent", "kv-create" }) AssertKey(b.P, s);
        Assert.DoesNotContain(b.P.Keys, k => k.EndsWith(":kv-durable", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0, 0, 0, true)]
    [InlineData(-1, -1, -1, true)]
    [InlineData(3, 5, 2, true)]
    [InlineData(3, 5, 2, false)]
    public void TheRaceSizesFallBackWhenNotPositiveAndOnlyASharedStoreGetsSeveralHandles(int rounds, int copies, int handles, bool shared)
    {
        var (R, C, H) = Sizes(rounds, copies, handles, shared);
        var (r, b) = RunKv(KvFault.None, shared, durable: true, rounds, copies, handles);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal($"{R} rounds x {C} copies over {H} handle(s)", Note(r, "update-concurrent"));
        Assert.Equal(7 + R * C * 3 + 1, b.P.Calls); // 7 updates in the basics, the concurrent and two create races per round, one durable write
        Assert.Equal(4 + 2 * H + 2, b.P.Opened); // four basics, the concurrent and create-once sets, two durability opens
        Assert.Equal(b.P.Opened, b.P.Disposed);
        Assert.Equal(1, b.P.Restarts);
        AssertKey(b.P, "kv-durable");
        Assert.Equal("pass", Status(r, "durability"));
    }

    [Theory]
    [InlineData(KvFault.GetGhost, "get-missing", "a key never written has a value")]
    [InlineData(KvFault.PrevStale, "update-creates-and-replaces", "the function saw a previous value for a new key")]
    [InlineData(KvFault.NoStore, "update-creates-and-replaces", "an update to a new key did not store its value")]
    [InlineData(KvFault.PrevNull, "update-creates-and-replaces", "an update did not see and replace the stored value")]
    [InlineData(KvFault.NullStoresEmpty, "update-null-keeps", "a function returning null created a value")]
    [InlineData(KvFault.NullClears, "update-null-keeps", "a function returning null changed the stored value")]
    [InlineData(KvFault.SwallowThrow, "update-throw-keeps", "a throwing function was swallowed")]
    [InlineData(KvFault.ThrowWrites, "update-throw-keeps", "a throwing function changed the stored value")]
    [InlineData(KvFault.NoStore, "update-concurrent", "after round 1 the counter is missing, expected 16 (an update was lost)")]
    [InlineData(KvFault.NoStore, "create-once", "round 1: no creator's value was stored")]
    [InlineData(KvFault.PrefixValue, "create-once", "round 1: no creator's value was stored")]
    [InlineData(KvFault.PrevNull, "create-once", "round 1: a later creator overwrote the stored value")]
    public void EachKvDefectFailsItsOwnCheckWithItsMessage(KvFault fault, string check, string message)
    {
        var (r, b) = RunKv(fault);
        Assert.False(r.Ok);
        Assert.Equal(("fail", message), (Status(r, check), Note(r, check)));
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    [Fact]
    public void ALaterCreatorsValueIsWrittenWhenTheStoreForgetsWhatIsThere()
    {
        var (r, b) = RunKv(KvFault.PrevNull);
        Assert.Equal("fail", Status(r, "create-once"));
        Assert.Contains(b.P.Written, w => w.StartsWith("late", StringComparison.Ordinal));
        Assert.Contains(b.P.Written, w => w.StartsWith("w", StringComparison.Ordinal));
    }

    [Fact]
    public void ALostUpdateNamesTheRoundTheCounterAndTheExpectedCount()
    {
        var (r, b) = RunKv(KvFault.Lossy);
        Assert.Equal("fail", Status(r, "update-concurrent"));
        Assert.Matches(new Regex(@"^after round \d+ the counter is \d+, expected \d+ \(an update was lost\)$"), Note(r, "update-concurrent"));
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    [Fact]
    public void ADurableKvIsReopenedAfterTheRestartAndAForgetfulOneFails()
    {
        var (lost, b) = RunKv(KvFault.None, durable: true, clearOnRestart: true);
        Assert.Equal(("fail", "a written value did not survive closing every handle and a restart"), (Status(lost, "durability"), Note(lost, "durability")));
        Assert.Equal(1, b.P.Restarts);
        Assert.Equal(b.P.Opened, b.P.Disposed);
        var (kept, kb) = RunKv(KvFault.None, durable: true);
        Assert.Equal(("pass", ""), (Status(kept, "durability"), Note(kept, "durability")));
        Assert.Equal(kb.P.Opened, kb.P.Disposed);
    }

    // ================= budget store =================

    public enum BFault { None, Ghost, CreateRefused, CreateNotStored, CreateOverwrites, RefusedCreateStores, OldOverMissing, AnyOldWhenPresent, RefusedSwapStores, RightSwapRefused, RightSwapNotStored, AlwaysWins }

    sealed class BBackend
    {
        public readonly Dictionary<string, TrustBudget> M = new();
        public BFault Fault;
        public readonly Probe P = new();
    }

    sealed class FaultyBudget : IBudgetStore, IDisposable
    {
        readonly BBackend b;
        public FaultyBudget(BBackend b) { this.b = b; Interlocked.Increment(ref b.P.Opened); }
        public void Dispose() => Interlocked.Increment(ref b.P.Disposed);

        public TrustBudget? Budget(string key)
        {
            b.P.Key(key);
            lock (b.M) return b.M.TryGetValue(key, out var v) ? v : b.Fault == BFault.Ghost ? new TrustBudget(0, 0, 0) : null;
        }

        public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new)
        {
            Interlocked.Increment(ref b.P.Calls);
            b.P.Key(key);
            lock (b.M)
            {
                b.M.TryGetValue(key, out var cur);
                var ok = Equals(cur, old);
                switch (b.Fault)
                {
                    case BFault.CreateRefused: if (old == null) return false; break;
                    case BFault.CreateNotStored: if (old == null) return true; break;
                    case BFault.CreateOverwrites: if (old == null) { b.M[key] = @new; return true; } break;
                    case BFault.RefusedCreateStores: if (!ok && old == null) { b.M[key] = @new; return false; } break;
                    case BFault.OldOverMissing: if (cur == null) ok = true; break;
                    case BFault.AnyOldWhenPresent: if (cur != null) ok = true; break;
                    case BFault.RefusedSwapStores: if (!ok && cur != null) { b.M[key] = @new; return false; } break;
                    case BFault.RightSwapRefused: if (cur != null) return false; break;
                    case BFault.RightSwapNotStored: if (ok && cur != null) return true; break;
                    case BFault.AlwaysWins: b.M[key] = @new; return true;
                }
                if (!ok) return false;
                b.M[key] = @new;
                return true;
            }
        }
    }

    static (ConformanceReport R, BBackend B) RunBudget(BFault fault, bool shared = true, bool durable = false, int rounds = 0, int copies = 0, int handles = 0, bool clearOnRestart = false)
    {
        var b = new BBackend { Fault = fault };
        var r = StoreConformance.RunBudgetStore(new BudgetStoreConformance
        {
            Name = "double", Open = () => new FaultyBudget(b), Shared = shared, Durable = durable, Rounds = rounds, Copies = copies, Handles = handles,
            Restart = () => { Interlocked.Increment(ref b.P.Restarts); if (clearOnRestart) lock (b.M) b.M.Clear(); },
        });
        return (r, b);
    }

    [Fact]
    public void ThePassingBudgetReportListsEveryCheckInOrder()
    {
        var (r, b) = RunBudget(BFault.None);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(new[] { "budget-missing", "cas-create", "cas-wrong-old", "cas-concurrent", "durability" }, Names(r));
        Assert.Equal(new[] { "pass", "pass", "pass", "pass", "skip" }, r.Checks.Select(c => c.Status));
        Assert.Equal(new[] { "", "", "", "10 rounds x 16 copies over 4 handle(s)", Durable }, r.Checks.Select(c => c.Note));
        foreach (var s in new[] { "budget-missing", "budget-create", "budget-wrong", "budget-concurrent" }) AssertKey(b.P, s);
        Assert.Equal(0, b.P.Restarts);
    }

    [Theory]
    [InlineData(0, 0, 0, true)]
    [InlineData(-1, -1, -1, true)]
    [InlineData(3, 5, 2, true)]
    [InlineData(3, 5, 2, false)]
    public void TheBudgetRaceSizesFallBackWhenNotPositive(int rounds, int copies, int handles, bool shared)
    {
        var (R, C, H) = Sizes(rounds, copies, handles, shared);
        var (r, b) = RunBudget(BFault.None, shared, durable: true, rounds, copies, handles);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal($"{R} rounds x {C} copies over {H} handle(s)", Note(r, "cas-concurrent"));
        Assert.Equal(6 + R * (1 + C) + 1, b.P.Calls);
        Assert.Equal(3 + H + 2, b.P.Opened);
        Assert.Equal(b.P.Opened, b.P.Disposed);
        Assert.Equal(1, b.P.Restarts);
        AssertKey(b.P, "budget-durable");
        Assert.Equal("pass", Status(r, "durability"));
    }

    [Theory]
    [InlineData(BFault.Ghost, "budget-missing", "a key never written has a budget")]
    [InlineData(BFault.CreateRefused, "cas-create", "creating a budget (old = none) was refused")]
    [InlineData(BFault.CreateNotStored, "cas-create", "the created budget is not what was stored")]
    [InlineData(BFault.CreateOverwrites, "cas-create", "a second create over an existing budget was accepted")]
    [InlineData(BFault.RefusedCreateStores, "cas-create", "a refused create changed the stored budget")]
    [InlineData(BFault.OldOverMissing, "cas-wrong-old", "a swap with an old value over a missing budget was accepted")]
    [InlineData(BFault.AnyOldWhenPresent, "cas-wrong-old", "a swap with the wrong old value was accepted")]
    [InlineData(BFault.RefusedSwapStores, "cas-wrong-old", "a refused swap changed the stored budget")]
    [InlineData(BFault.RightSwapRefused, "cas-wrong-old", "a swap with the right old value was refused or not stored")]
    [InlineData(BFault.RightSwapNotStored, "cas-wrong-old", "a swap with the right old value was refused or not stored")]
    [InlineData(BFault.CreateRefused, "cas-concurrent", "creating the budget was refused")]
    [InlineData(BFault.AlwaysWins, "cas-concurrent", "round 1: 16 swaps from the same value won (exactly one must)")]
    public void EachBudgetDefectFailsItsOwnCheckWithItsMessage(BFault fault, string check, string message)
    {
        var (r, b) = RunBudget(fault);
        Assert.False(r.Ok);
        Assert.Equal(("fail", message), (Status(r, check), Note(r, check)));
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    [Fact]
    public void ABudgetThatCannotBeCreatedOrDoesNotSurviveFailsDurability()
    {
        var (refused, rb) = RunBudget(BFault.CreateRefused, durable: true);
        Assert.Equal(("fail", "creating the budget was refused"), (Status(refused, "durability"), Note(refused, "durability")));
        Assert.Equal(rb.P.Opened, rb.P.Disposed);
        var (lost, b) = RunBudget(BFault.None, durable: true, clearOnRestart: true);
        Assert.Equal(("fail", "a stored budget did not survive closing every handle and a restart"), (Status(lost, "durability"), Note(lost, "durability")));
        Assert.Equal(1, b.P.Restarts);
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    // ================= pin store =================

    public enum PFault { None, Ghost, NoStore, ReturnsInput, LowerStores, NeverRaises, ReturnsStale, AcceptsNegative, AcceptsEmpty, RefusedCreates, Sets }

    sealed class PBackend
    {
        public readonly Dictionary<string, long> M = new();
        public PFault Fault;
        public readonly Probe P = new();
    }

    sealed class FaultyPin : IPinStore, IDisposable
    {
        readonly PBackend b;
        public FaultyPin(PBackend b) { this.b = b; Interlocked.Increment(ref b.P.Opened); }
        public void Dispose() => Interlocked.Increment(ref b.P.Disposed);

        public long? Pin(string key)
        {
            b.P.Key(key);
            lock (b.M)
            {
                if (b.M.TryGetValue(key, out var v)) return v;
                return b.Fault == PFault.Ghost ? (long?)0L : null;
            }
        }

        public long RaisePin(string key, long value)
        {
            Interlocked.Increment(ref b.P.Calls);
            b.P.Key(key);
            if (b.Fault != PFault.AcceptsNegative && value < 0)
            {
                if (b.Fault == PFault.RefusedCreates) lock (b.M) b.M[key] = 0;
                throw new ArgumentException("bad");
            }
            if (b.Fault != PFault.AcceptsEmpty && string.IsNullOrEmpty(key)) throw new ArgumentException("bad");
            lock (b.M)
            {
                var has = b.M.TryGetValue(key, out var cur);
                switch (b.Fault)
                {
                    case PFault.NoStore: return value;
                    case PFault.ReturnsInput: b.M[key] = has ? Math.Max(cur, value) : value; return value;
                    case PFault.LowerStores: { var r = has ? Math.Max(cur, value) : value; b.M[key] = value; return r; }
                    case PFault.NeverRaises: if (has) return cur; b.M[key] = value; return value;
                    case PFault.ReturnsStale: b.M[key] = has ? Math.Max(cur, value) : value; return has ? cur : value;
                    case PFault.Sets: b.M[key] = value; return value;
                    default: { var n = has && cur >= value ? cur : value; b.M[key] = n; return n; }
                }
            }
        }
    }

    static (ConformanceReport R, PBackend B) RunPin(PFault fault, bool shared = true, bool durable = false, int rounds = 0, int copies = 0, int handles = 0, bool clearOnRestart = false)
    {
        var b = new PBackend { Fault = fault };
        var r = StoreConformance.RunPinStore(new PinStoreConformance
        {
            Name = "double", Open = () => new FaultyPin(b), Shared = shared, Durable = durable, Rounds = rounds, Copies = copies, Handles = handles,
            Restart = () => { Interlocked.Increment(ref b.P.Restarts); if (clearOnRestart) lock (b.M) b.M.Clear(); },
        });
        return (r, b);
    }

    [Fact]
    public void ThePassingPinReportListsEveryCheckInOrder()
    {
        var (r, b) = RunPin(PFault.None);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal(new[] { "pin-missing", "raise-monotone", "raise-input", "raise-concurrent", "durability" }, Names(r));
        Assert.Equal(new[] { "pass", "pass", "pass", "pass", "skip" }, r.Checks.Select(c => c.Status));
        Assert.Equal(new[] { "", "", "", "10 rounds x 16 copies over 4 handle(s)", Durable }, r.Checks.Select(c => c.Note));
        foreach (var s in new[] { "pin-missing", "pin-monotone", "pin-input", "pin-concurrent" }) AssertKey(b.P, s);
        Assert.Equal(0, b.P.Restarts);
    }

    [Theory]
    [InlineData(0, 0, 0, true)]
    [InlineData(-1, -1, -1, true)]
    [InlineData(3, 5, 2, true)]
    [InlineData(3, 5, 2, false)]
    public void ThePinRaceSizesFallBackWhenNotPositive(int rounds, int copies, int handles, bool shared)
    {
        var (R, C, H) = Sizes(rounds, copies, handles, shared);
        var (r, b) = RunPin(PFault.None, shared, durable: true, rounds, copies, handles);
        Assert.True(r.Ok, r.ToString());
        Assert.Equal($"{R} rounds x {C} copies over {H} handle(s)", Note(r, "raise-concurrent"));
        Assert.Equal(6 + R * C + 1, b.P.Calls);
        Assert.Equal(3 + H + 2, b.P.Opened);
        Assert.Equal(b.P.Opened, b.P.Disposed);
        Assert.Equal(1, b.P.Restarts);
        AssertKey(b.P, "pin-durable");
        Assert.Equal("pass", Status(r, "durability"));
    }

    [Theory]
    [InlineData(PFault.Ghost, "pin-missing", "a key never raised has a pin")]
    [InlineData(PFault.NoStore, "raise-monotone", "the first raise did not store its value")]
    [InlineData(PFault.ReturnsInput, "raise-monotone", "a lower raise returned something other than the standing pin")]
    [InlineData(PFault.LowerStores, "raise-monotone", "a lower raise lowered the pin")]
    [InlineData(PFault.NeverRaises, "raise-monotone", "an equal or higher raise did not leave the highest value")]
    [InlineData(PFault.ReturnsStale, "raise-monotone", "an equal or higher raise did not leave the highest value")]
    [InlineData(PFault.AcceptsNegative, "raise-input", "a negative pin was accepted")]
    [InlineData(PFault.AcceptsEmpty, "raise-input", "an empty key was accepted")]
    [InlineData(PFault.RefusedCreates, "raise-input", "a refused raise created a pin")]
    [InlineData(PFault.NoStore, "raise-concurrent", "round 1: the pin is missing after racing raises of 1..16, expected 16")]
    public void EachPinDefectFailsItsOwnCheckWithItsMessage(PFault fault, string check, string message)
    {
        var (r, b) = RunPin(fault);
        Assert.False(r.Ok);
        Assert.Equal(("fail", message), (Status(r, check), Note(r, check)));
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    [Fact]
    public void ARaceThatSetsInsteadOfRaisingNamesTheRoundAndThePin()
    {
        var (r, b) = RunPin(PFault.Sets);
        Assert.Equal("fail", Status(r, "raise-concurrent"));
        Assert.Matches(new Regex(@"^round \d+: the pin is \d+ after racing raises of 1\.\.16, expected 16$"), Note(r, "raise-concurrent"));
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }

    [Fact]
    public void ADurablePinIsReopenedAfterTheRestartAndAForgetfulOneFails()
    {
        var (lost, b) = RunPin(PFault.None, durable: true, clearOnRestart: true);
        Assert.Equal(("fail", "a pin did not survive closing every handle and a restart"), (Status(lost, "durability"), Note(lost, "durability")));
        Assert.Equal(1, b.P.Restarts);
        Assert.Equal(b.P.Opened, b.P.Disposed);
    }
}
