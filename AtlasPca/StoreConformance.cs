// Store conformance: run your IStateStore (the replay store behind Authorize) and your IOperationStore through the invariants the
// guards rely on, from a test in your own repository:
//
//     var report = StoreConformance.RunStateStore(new StateStoreConformance { Name = "postgres", Open = OpenStore, Shared = true, Durable = true });
//     Assert.True(report.Ok, report.ToString());
//
// State store checks: claim-burst (strictly increasing counters admitted once each, repeats and older counters refused),
// claim-concurrent (N copies of one counter on several handles: exactly one admitted, every round; distinct counters in a race never
// admit the same one twice and always admit the highest), claim-durability (state survives closing every handle and a restart),
// crash-after-claim (admitted, then the instance dies without closing: the same counter stays refused), retry-after-timeout (the claim
// commits but its answer is lost: the retry is refused, the next counter admitted). Operation store checks: create-once,
// transition-once, wrong-state, get-missing, shared, durability. A check the store declares it cannot meet (not Durable, not Shared)
// is skipped, never passed.
using System.Text;

namespace AtlasPca;

/// <summary>The outcome of one check. <see cref="Status"/> is <c>pass</c>, <c>fail</c> or <c>skip</c>.</summary>
public sealed record ConformanceCheck(string Name, string Status, string Note);

/// <summary>The outcome of a conformance run.</summary>
public sealed class ConformanceReport
{
    public string Name { get; }
    public List<ConformanceCheck> Checks { get; } = new();

    public ConformanceReport(string name) => Name = name;

    /// <summary>Whether no check failed.</summary>
    public bool Ok => Checks.All(c => c.Status != "fail");

    internal void Add(string name, string? failure, string note = "") =>
        Checks.Add(failure != null ? new ConformanceCheck(name, "fail", failure) : new ConformanceCheck(name, "pass", note));

    internal void Skip(string name, string why) => Checks.Add(new ConformanceCheck(name, "skip", why));

    /// <summary>The status of the named check (<c>absent</c> when it did not run).</summary>
    public string StatusOf(string name) => Checks.FirstOrDefault(c => c.Name == name)?.Status ?? "absent";

    /// <summary>One line per check.</summary>
    public override string ToString()
    {
        var b = new StringBuilder($"store conformance: {Name} -> {(Ok ? "PASS" : "FAIL")}\n");
        foreach (var c in Checks) b.Append($"  [{c.Status.ToUpperInvariant()}] {c.Name,-20} {c.Note}\n");
        return b.ToString();
    }
}

/// <summary>Configures <see cref="StoreConformance.RunStateStore"/>.</summary>
public sealed class StateStoreConformance
{
    public string Name { get; set; } = "store";
    /// <summary>Returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection). A store that is <see cref="IDisposable"/> is disposed after use.</summary>
    public Func<IStateStore>? Open { get; set; }
    /// <summary>When set, crashes and restarts the backend; it runs between closing the handles and reopening.</summary>
    public Action? Restart { get; set; }
    /// <summary>State survives closing every handle (and <see cref="Restart"/>). False skips the durability checks.</summary>
    public bool Durable { get; set; }
    /// <summary>Several handles can share the backend. False runs the race checks on one handle.</summary>
    public bool Shared { get; set; }
    /// <summary>Sizes the race checks (defaults 10 rounds, 16 copies, 4 handles).</summary>
    public int Rounds { get; set; } = 10;
    public int Copies { get; set; } = 16;
    public int Handles { get; set; } = 4;
}

/// <summary>Configures <see cref="StoreConformance.RunOperationStore"/>.</summary>
public sealed class OperationStoreConformance
{
    public string Name { get; set; } = "store";
    /// <summary>Returns a NEW handle onto the SAME backend each call.</summary>
    public Func<IOperationStore>? Open { get; set; }
    public Action? Restart { get; set; }
    /// <summary>Records survive closing every handle (and <see cref="Restart"/>).</summary>
    public bool Durable { get; set; }
    /// <summary>Handles share the backend.</summary>
    public bool Shared { get; set; }
    /// <summary>Concurrent callers per race (default 16).</summary>
    public int Copies { get; set; } = 16;
}

public static class StoreConformance
{
    static long _seq;

    static string Key(string prefix) => $"conf:{DateTime.UtcNow.Ticks}:{Interlocked.Increment(ref _seq)}:{prefix}";

    static void Close(object? s)
    {
        try { (s as IDisposable)?.Dispose(); } catch (Exception) { /* a close failure is not a conformance failure */ }
    }

    /// <summary>Runs <paramref name="n"/> copies of <paramref name="body"/> on dedicated threads released together.</summary>
    static void Race(int n, Action<int> body)
    {
        using var gate = new ManualResetEventSlim(false);
        var threads = Enumerable.Range(0, n).Select(i => new Thread(() => { gate.Wait(); body(i); }) { IsBackground = true }).ToList();
        foreach (var t in threads) t.Start();
        gate.Set();
        foreach (var t in threads) t.Join();
    }

    /// <summary>The claim's answer: admitted, refused, or errored (a claim that cannot decide).</summary>
    static (bool Ok, string? Error) Claim(IStateStore s, string key, long n)
    {
        try
        {
            var r = s.Claim(key, n);
            return (r is { Ok: true }, null);
        }
        catch (Exception e) { return (false, e.Message); }
    }

    /// <summary>Null when the claim was admitted without error, else why not.</summary>
    static string? NotAdmitted(IStateStore s, string key, long n)
    {
        var (ok, err) = Claim(s, key, n);
        return ok && err == null ? null : err ?? "refused";
    }

    sealed class Handles : IDisposable
    {
        public readonly List<IStateStore> Stores = new();
        public void Dispose() { foreach (var s in Stores) Close(s); }
    }

    static Handles OpenN(StateStoreConformance c, int n)
    {
        var h = new Handles();
        try
        {
            for (int i = 0; i < n; i++) h.Stores.Add(c.Open!() ?? throw new InvalidOperationException("Open returned null"));
        }
        catch (Exception e)
        {
            h.Dispose();
            throw new InvalidOperationException("Open: " + e.Message, e);
        }
        return h;
    }

    /// <summary>Runs the replay-store checks. <see cref="StateStoreConformance.Open"/> is required (a missing one is a failed report).</summary>
    public static ConformanceReport RunStateStore(StateStoreConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int rounds = c.Rounds <= 0 ? 10 : c.Rounds, copies = c.Copies <= 0 ? 16 : c.Copies, handles = !c.Shared ? 1 : c.Handles <= 0 ? 4 : c.Handles;
        string? Run(Func<string?> f)
        {
            try { return f(); }
            catch (Exception e) { return e.Message; }
        }
        rep.Add("claim-burst", Run(() => ClaimBurst(c)));
        rep.Add("claim-concurrent", Run(() => ClaimConcurrent(c, rounds, copies, handles)), $"{rounds} rounds x {copies} copies over {handles} handle(s)");
        if (c.Durable)
        {
            rep.Add("claim-durability", Run(() => ClaimDurability(c)));
            rep.Add("crash-after-claim", Run(() => CrashAfterClaim(c)));
        }
        else
        {
            rep.Skip("claim-durability", "Durable is false (state dies with the process)");
            rep.Skip("crash-after-claim", "Durable is false (state dies with the process)");
        }
        rep.Add("retry-after-timeout", Run(() => RetryAfterTimeout(c)));
        return rep;
    }

    static string? ClaimBurst(StateStoreConformance c)
    {
        using var hs = OpenN(c, 1);
        var s = hs.Stores[0];
        var key = Key("burst");
        const int n = 25;
        for (long i = 1; i <= n; i++)
            if (NotAdmitted(s, key, i) is { } why1) return $"counter {i} was not admitted on first use (err {why1})";
        for (long i = n; i >= 1; i--)
        {
            var (ok, err) = Claim(s, key, i);
            if (err != null) return $"replay of counter {i} errored: {err}";
            if (ok) return $"counter {i} was admitted twice (or an older counter was admitted after a newer one)";
        }
        if (NotAdmitted(s, key, n + 1) is { } why2) return $"the next counter after refusals was not admitted (err {why2})";
        // keys are independent streams
        if (NotAdmitted(s, Key("burst-other"), 1) is { } why3) return $"a fresh key refused counter 1 (err {why3})";
        return null;
    }

    static string? ClaimConcurrent(StateStoreConformance c, int rounds, int copies, int handles)
    {
        using var hs = OpenN(c, handles);
        var key = Key("concurrent");
        for (long round = 1; round <= rounds; round++)
        {
            int wins = 0, errs = 0;
            long counter = round;
            Race(copies, i =>
            {
                var (ok, err) = Claim(hs.Stores[i % hs.Stores.Count], key, counter);
                if (err != null) Interlocked.Increment(ref errs);
                else if (ok) Interlocked.Increment(ref wins);
            });
            if (wins != 1) return $"round {round}: {wins} of {copies} copies of one counter were admitted (want exactly 1; {errs} errors)";
        }
        // distinct counters racing on one key: the highest is always admitted and nothing is admitted twice
        long baseCounter = rounds;
        var key2 = Key("concurrent-distinct");
        var admitted = new int[copies + 1];
        Race(copies, idx =>
        {
            int n = idx + 1;
            if (Claim(hs.Stores[n % hs.Stores.Count], key2, baseCounter + n).Ok) Volatile.Write(ref admitted[n], 1);
        });
        if (Volatile.Read(ref admitted[copies]) != 1) return $"the highest of {copies} racing counters was not admitted";
        for (long i = 1; i <= copies; i++)
        {
            var (ok, err) = Claim(hs.Stores[0], key2, baseCounter + i);
            if (ok || err != null) return $"counter {baseCounter + i} is admitted again after the race (err {err})";
        }
        return null;
    }

    static string? ClaimDurability(StateStoreConformance c)
    {
        var key = Key("durability");
        using (var hs = OpenN(c, 1))
            for (long i = 1; i <= 3; i++)
                if (NotAdmitted(hs.Stores[0], key, i) is { } why) return $"counter {i} was not admitted (err {why})";
        c.Restart?.Invoke();
        return AfterReopen(c, key, 3, 4, "closing every handle");
    }

    static string? AfterReopen(StateStoreConformance c, string key, long used, long next, string what)
    {
        using var hs = OpenN(c, 1);
        var (ok, err) = Claim(hs.Stores[0], key, used);
        if (err != null || ok) return $"counter {used} was admitted again after {what} (err {err})";
        if (NotAdmitted(hs.Stores[0], key, next) is { } why) return $"counter {next} was not admitted after {what} (err {why})";
        return null;
    }

    static string? CrashAfterClaim(StateStoreConformance c)
    {
        // the instance dies after the claim and before its handler ran: its handle is abandoned, never closed until the check ends
        using var hs = OpenN(c, 1);
        var key = Key("crash");
        if (NotAdmitted(hs.Stores[0], key, 1) is { } why) return $"counter 1 was not admitted (err {why})";
        c.Restart?.Invoke();
        return AfterReopen(c, key, 1, 2, "the instance died");
    }

    /// <summary>Commits the claim and then loses the answer once.</summary>
    sealed class LossyStore : IStateStore
    {
        readonly IStateStore _inner;
        int _lose = 1;
        public LossyStore(IStateStore inner) => _inner = inner;

        public ClaimResult? Claim(string key, long counter)
        {
            var r = _inner.Claim(key, counter);
            if (Interlocked.Exchange(ref _lose, 0) == 1) throw new TimeoutException("timeout (answer lost after commit)");
            return r;
        }
    }

    static string? RetryAfterTimeout(StateStoreConformance c)
    {
        using var hs = OpenN(c, 2);
        var first = hs.Stores[0];
        var other = c.Shared ? hs.Stores[^1] : first;
        var lossy = new LossyStore(first);
        var key = Key("retry");
        var (lostOk, lostErr) = Claim(lossy, key, 1);
        if (lostOk || lostErr == null) return "the lossy wrapper must lose the first answer";
        var (retryOk, retryErr) = Claim(other, key, 1);
        if (retryErr != null || retryOk) return $"the retry of a claim whose answer was lost was admitted (err {retryErr}): the commit had already landed";
        if (NotAdmitted(other, key, 2) is { } why) return $"the next counter after the retry was not admitted (err {why})";
        return null;
    }

    // ---------------------------------------------------------------- operation records

    static OperationRecord Rec(string id) => new(id, OperationStates.Pending, "v", "/r", "d", "reversible", 1);

    /// <summary>Runs the operation-record store checks.</summary>
    public static ConformanceReport RunOperationStore(OperationStoreConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int copies = c.Copies <= 0 ? 16 : c.Copies;
        string? Run(Func<string?> f)
        {
            try { return f(); }
            catch (Exception e) { return e.Message; }
        }
        (IOperationStore A, IOperationStore B) Open2()
        {
            var a = c.Open!();
            return c.Shared ? (a, c.Open!()) : (a, a);
        }
        void CloseBoth(IOperationStore a, IOperationStore b) { Close(a); if (!ReferenceEquals(a, b)) Close(b); }

        rep.Add("create-once", Run(() =>
        {
            var (a, b) = Open2();
            try
            {
                var id = Key("create");
                int created = 0;
                Race(copies, i =>
                {
                    try
                    {
                        var (ok, existing) = (i % 2 == 0 ? a : b).Create(Rec(id));
                        if (ok) Interlocked.Increment(ref created);
                        else if (existing?.Id != id) Interlocked.Add(ref created, 100);
                    }
                    catch (Exception) { /* a call that cannot decide is not a creation */ }
                });
                return created != 1 ? $"{created} concurrent creates of one id reported created (want exactly 1; >=100 means a loser got no existing record)" : null;
            }
            finally { CloseBoth(a, b); }
        }));
        rep.Add("transition-once", Run(() =>
        {
            var (a, b) = Open2();
            try
            {
                var id = Key("transition");
                if (!a.Create(Rec(id)).Created) return "create failed";
                int won = 0;
                Race(copies, i =>
                {
                    try { if ((i % 2 == 0 ? a : b).Transition(id, OperationStates.Pending, Rec(id) with { State = OperationStates.Executing })) Interlocked.Increment(ref won); }
                    catch (Exception) { /* a call that cannot decide did not win */ }
                });
                return won != 1 ? $"{won} concurrent transitions out of pending won (want exactly 1)" : null;
            }
            finally { CloseBoth(a, b); }
        }));
        rep.Add("wrong-state", Run(() =>
        {
            var s = c.Open!();
            try
            {
                var id = Key("wrong");
                if (!s.Create(Rec(id)).Created) return "create failed";
                var next = Rec(id) with { State = OperationStates.Committed };
                if (s.Transition(id, OperationStates.Executing, next)) return "a transition from the wrong state applied";
                var got = s.Get(id);
                if (got is not { State: OperationStates.Pending }) return $"the record changed after a refused transition: {got?.State ?? "missing"}";
                if (s.Transition(Key("missing"), OperationStates.Pending, next)) return "a transition of an unknown id applied";
                return null;
            }
            finally { Close(s); }
        }));
        rep.Add("get-missing", Run(() =>
        {
            var s = c.Open!();
            try { return s.Get(Key("never")) is { } got ? $"an unknown id returned a record ({got.State})" : null; }
            finally { Close(s); }
        }));
        if (c.Shared)
        {
            rep.Add("shared", Run(() =>
            {
                var (a, b) = Open2();
                try
                {
                    var id = Key("shared");
                    if (!a.Create(Rec(id)).Created) return "create failed";
                    return b.Get(id)?.Id == id ? null : "another handle does not see the record";
                }
                finally { CloseBoth(a, b); }
            }));
        }
        else rep.Skip("shared", "Shared is false");
        if (c.Durable)
        {
            rep.Add("durability", Run(() =>
            {
                var id = Key("durable");
                var a = c.Open!();
                try { if (!a.Create(Rec(id)).Created) return "create failed"; }
                finally { Close(a); }
                c.Restart?.Invoke();
                var b = c.Open!();
                try { return b.Get(id) is { State: OperationStates.Pending } ? null : "the record did not survive closing every handle"; }
                finally { Close(b); }
            }));
        }
        else rep.Skip("durability", "Durable is false");
        return rep;
    }
}
