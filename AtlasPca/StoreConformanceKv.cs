// Store conformance for the seams the durable registries, the trust budget and the revocation-epoch pin are built on (see StoreConformance.cs
// for the replay and operation store kits and the report type):
//
//     var report = StoreConformance.RunAtomicKv(new AtomicKvConformance { Name = "postgres", Open = OpenKv, Shared = true, Durable = true });
//     Assert.True(report.Ok, report.ToString());
//
// Atomic key-value store (the LeaseRegistry, BreakGlassRegistry, plan and operation records run on it): get-missing, update-creates-and-replaces,
// update-null-keeps, update-concurrent (N racing read-modify-writes lose no update), create-once (racing creators: exactly one value is written),
// update-throw-keeps (a throwing function leaves the value), durability. Budget store: budget-missing, cas-create, cas-wrong-old, cas-concurrent
// (racing swaps from one value: exactly one wins), durability. Pin store: pin-missing, raise-monotone, raise-concurrent (the pin ends at the highest
// raise), raise-input, durability. A check the store declares it cannot meet (not Durable, not Shared) is skipped, never passed.
namespace AtlasPca;

/// <summary>Configures <see cref="StoreConformance.RunAtomicKv"/>.</summary>
public sealed class AtomicKvConformance
{
    public string Name { get; set; } = "kv";
    /// <summary>Returns a NEW handle onto the SAME backend each call.</summary>
    public Func<IAtomicKv>? Open { get; set; }
    /// <summary>Crashes and restarts the backend between closing the handles and reopening.</summary>
    public Action? Restart { get; set; }
    public bool Durable { get; set; }
    public bool Shared { get; set; }
    public int Rounds { get; set; } = 10;
    public int Copies { get; set; } = 16;
    public int Handles { get; set; } = 4;
}

/// <summary>Configures <see cref="StoreConformance.RunBudgetStore"/>.</summary>
public sealed class BudgetStoreConformance
{
    public string Name { get; set; } = "budget";
    public Func<IBudgetStore>? Open { get; set; }
    public Action? Restart { get; set; }
    public bool Durable { get; set; }
    public bool Shared { get; set; }
    public int Rounds { get; set; } = 10;
    public int Copies { get; set; } = 16;
    public int Handles { get; set; } = 4;
}

/// <summary>Configures <see cref="StoreConformance.RunPinStore"/>.</summary>
public sealed class PinStoreConformance
{
    public string Name { get; set; } = "pins";
    public Func<IPinStore>? Open { get; set; }
    public Action? Restart { get; set; }
    public bool Durable { get; set; }
    public bool Shared { get; set; }
    public int Rounds { get; set; } = 10;
    public int Copies { get; set; } = 16;
    public int Handles { get; set; } = 4;
}

public static partial class StoreConformance
{
    static string? Guard(Func<string?> f)
    {
        try { return f(); }
        catch (Exception e) { return e.Message; }
    }

    static List<T> OpenAll<T>(Func<T>? open, int n) where T : class
    {
        var l = new List<T>();
        for (int i = 0; i < n; i++) l.Add(open!() ?? throw new InvalidOperationException("Open returned null"));
        return l;
    }

    static void CloseAll<T>(List<T> l) { foreach (var s in l) Close(s); }

    // ================= atomic key-value store =================

    /// <summary>Runs the atomic key-value store checks. <see cref="AtomicKvConformance.Open"/> is required (a missing one is a failed report).</summary>
    public static ConformanceReport RunAtomicKv(AtomicKvConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int rounds = c.Rounds <= 0 ? 10 : c.Rounds, copies = c.Copies <= 0 ? 16 : c.Copies, handles = !c.Shared ? 1 : c.Handles <= 0 ? 4 : c.Handles;
        rep.Add("get-missing", Guard(() => KvBasics(c, "get-missing")));
        rep.Add("update-creates-and-replaces", Guard(() => KvBasics(c, "replace")));
        rep.Add("update-null-keeps", Guard(() => KvBasics(c, "null")));
        rep.Add("update-concurrent", Guard(() => KvConcurrent(c, rounds, copies, handles)), $"{rounds} rounds x {copies} copies over {handles} handle(s)");
        rep.Add("create-once", Guard(() => KvCreateOnce(c, rounds, copies, handles)));
        rep.Add("update-throw-keeps", Guard(() => KvBasics(c, "throw")));
        if (c.Durable) rep.Add("durability", Guard(() => KvDurability(c)));
        else rep.Skip("durability", "Durable is false (state dies with the process)");
        return rep;
    }

    static string? KvBasics(AtomicKvConformance c, string which)
    {
        var hs = OpenAll(c.Open, 1);
        try
        {
            var kv = hs[0];
            var key = Key("kv-" + which);
            switch (which)
            {
                case "get-missing":
                    return kv.Get(key) == null ? null : "a key never written has a value";
                case "replace":
                    {
                        string? seen = "x";
                        kv.Update(key, prev => { seen = prev; return "a"; });
                        if (seen != null) return "the function saw a previous value for a new key";
                        if (kv.Get(key) != "a") return "an update to a new key did not store its value";
                        kv.Update(key, prev => prev + "b");
                        return kv.Get(key) == "ab" ? null : "an update did not see and replace the stored value";
                    }
                case "null":
                    {
                        kv.Update(key, _ => null);
                        if (kv.Get(key) != null) return "a function returning null created a value";
                        kv.Update(key, _ => "v");
                        kv.Update(key, _ => null);
                        return kv.Get(key) == "v" ? null : "a function returning null changed the stored value";
                    }
                default: // throw
                    {
                        kv.Update(key, _ => "v");
                        try { kv.Update(key, _ => throw new InvalidOperationException("boom")); return "a throwing function was swallowed"; }
                        catch (InvalidOperationException) { /* expected */ }
                        return kv.Get(key) == "v" ? null : "a throwing function changed the stored value";
                    }
            }
        }
        finally { CloseAll(hs); }
    }

    static string? KvConcurrent(AtomicKvConformance c, int rounds, int copies, int handles)
    {
        var hs = OpenAll(c.Open, handles);
        try
        {
            var key = Key("kv-concurrent");
            for (int round = 1; round <= rounds; round++)
            {
                Race(copies, i => hs[i % hs.Count].Update(key, prev => (long.Parse(prev ?? "0") + 1).ToString()));
                var want = (long)round * copies;
                var got = hs[0].Get(key);
                if (got != want.ToString()) return $"after round {round} the counter is {got ?? "missing"}, expected {want} (an update was lost)";
            }
            return null;
        }
        finally { CloseAll(hs); }
    }

    static string? KvCreateOnce(AtomicKvConformance c, int rounds, int copies, int handles)
    {
        var hs = OpenAll(c.Open, handles);
        try
        {
            for (int round = 1; round <= rounds; round++)
            {
                var key = Key("kv-create");
                Race(copies, i => hs[i % hs.Count].Update(key, prev =>
                {
                    if (prev != null) return null;
                    return "w" + i;
                }));
                // a retried function may run more than once, but the stored value must be one winner's and stay put
                var first = hs[0].Get(key);
                if (first == null || !first.StartsWith('w')) return $"round {round}: no creator's value was stored";
                Race(copies, i => hs[i % hs.Count].Update(key, prev => prev != null ? null : "late" + i));
                if (hs[0].Get(key) != first) return $"round {round}: a later creator overwrote the stored value";
            }
            return null;
        }
        finally { CloseAll(hs); }
    }

    static string? KvDurability(AtomicKvConformance c)
    {
        var key = Key("kv-durable");
        var a = OpenAll(c.Open, 1);
        try { a[0].Update(key, _ => "kept"); }
        finally { CloseAll(a); }
        c.Restart?.Invoke();
        var b = OpenAll(c.Open, 1);
        try { return b[0].Get(key) == "kept" ? null : "a written value did not survive closing every handle and a restart"; }
        finally { CloseAll(b); }
    }

    // ================= budget store =================

    /// <summary>Runs the trust-budget store checks (<see cref="IBudgetStore"/>).</summary>
    public static ConformanceReport RunBudgetStore(BudgetStoreConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int rounds = c.Rounds <= 0 ? 10 : c.Rounds, copies = c.Copies <= 0 ? 16 : c.Copies, handles = !c.Shared ? 1 : c.Handles <= 0 ? 4 : c.Handles;
        rep.Add("budget-missing", Guard(() => BudgetBasics(c, "missing")));
        rep.Add("cas-create", Guard(() => BudgetBasics(c, "create")));
        rep.Add("cas-wrong-old", Guard(() => BudgetBasics(c, "wrong")));
        rep.Add("cas-concurrent", Guard(() => BudgetConcurrent(c, rounds, copies, handles)), $"{rounds} rounds x {copies} copies over {handles} handle(s)");
        if (c.Durable) rep.Add("durability", Guard(() => BudgetDurability(c)));
        else rep.Skip("durability", "Durable is false (state dies with the process)");
        return rep;
    }

    static string? BudgetBasics(BudgetStoreConformance c, string which)
    {
        var hs = OpenAll(c.Open, 1);
        try
        {
            var s = hs[0];
            var key = Key("budget-" + which);
            var b1 = new TrustBudget(1, 10, 10);
            var b2 = new TrustBudget(0.5, 10, 20);
            switch (which)
            {
                case "missing": return s.Budget(key) == null ? null : "a key never written has a budget";
                case "create":
                    if (!s.BudgetCas(key, null, b1)) return "creating a budget (old = none) was refused";
                    if (s.Budget(key) != b1) return "the created budget is not what was stored";
                    return s.BudgetCas(key, null, b2) ? "a second create over an existing budget was accepted" : s.Budget(key) == b1 ? null : "a refused create changed the stored budget";
                default:
                    if (s.BudgetCas(key, b1, b2)) return "a swap with an old value over a missing budget was accepted";
                    s.BudgetCas(key, null, b1);
                    if (s.BudgetCas(key, b2, new TrustBudget(0, 1, 1))) return "a swap with the wrong old value was accepted";
                    if (s.Budget(key) != b1) return "a refused swap changed the stored budget";
                    return s.BudgetCas(key, b1, b2) && s.Budget(key) == b2 ? null : "a swap with the right old value was refused or not stored";
            }
        }
        finally { CloseAll(hs); }
    }

    static string? BudgetConcurrent(BudgetStoreConformance c, int rounds, int copies, int handles)
    {
        var hs = OpenAll(c.Open, handles);
        try
        {
            for (int round = 1; round <= rounds; round++)
            {
                var key = Key("budget-concurrent");
                var start = new TrustBudget(1, 1, 1);
                if (!hs[0].BudgetCas(key, null, start)) return "creating the budget was refused";
                int wins = 0;
                Race(copies, i => { if (hs[i % hs.Count].BudgetCas(key, start, new TrustBudget(0.5, 1, 100 + i))) Interlocked.Increment(ref wins); });
                if (wins != 1) return $"round {round}: {wins} swaps from the same value won (exactly one must)";
            }
            return null;
        }
        finally { CloseAll(hs); }
    }

    static string? BudgetDurability(BudgetStoreConformance c)
    {
        var key = Key("budget-durable");
        var b = new TrustBudget(0.25, 3, 4);
        var a = OpenAll(c.Open, 1);
        try { if (!a[0].BudgetCas(key, null, b)) return "creating the budget was refused"; }
        finally { CloseAll(a); }
        c.Restart?.Invoke();
        var d = OpenAll(c.Open, 1);
        try { return d[0].Budget(key) == b ? null : "a stored budget did not survive closing every handle and a restart"; }
        finally { CloseAll(d); }
    }

    // ================= pin store =================

    /// <summary>Runs the monotone-pin store checks (<see cref="IPinStore"/>).</summary>
    public static ConformanceReport RunPinStore(PinStoreConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int rounds = c.Rounds <= 0 ? 10 : c.Rounds, copies = c.Copies <= 0 ? 16 : c.Copies, handles = !c.Shared ? 1 : c.Handles <= 0 ? 4 : c.Handles;
        rep.Add("pin-missing", Guard(() => PinBasics(c, "missing")));
        rep.Add("raise-monotone", Guard(() => PinBasics(c, "monotone")));
        rep.Add("raise-input", Guard(() => PinBasics(c, "input")));
        rep.Add("raise-concurrent", Guard(() => PinConcurrent(c, rounds, copies, handles)), $"{rounds} rounds x {copies} copies over {handles} handle(s)");
        if (c.Durable) rep.Add("durability", Guard(() => PinDurability(c)));
        else rep.Skip("durability", "Durable is false (state dies with the process)");
        return rep;
    }

    static string? PinBasics(PinStoreConformance c, string which)
    {
        var hs = OpenAll(c.Open, 1);
        try
        {
            var s = hs[0];
            var key = Key("pin-" + which);
            switch (which)
            {
                case "missing": return s.Pin(key) == null ? null : "a key never raised has a pin";
                case "monotone":
                    if (s.RaisePin(key, 5) != 5 || s.Pin(key) != 5) return "the first raise did not store its value";
                    if (s.RaisePin(key, 3) != 5) return "a lower raise returned something other than the standing pin";
                    if (s.Pin(key) != 5) return "a lower raise lowered the pin";
                    return s.RaisePin(key, 5) == 5 && s.RaisePin(key, 6) == 6 && s.Pin(key) == 6 ? null : "an equal or higher raise did not leave the highest value";
                default:
                    try { s.RaisePin(key, -1); return "a negative pin was accepted"; } catch (ArgumentException) { }
                    try { s.RaisePin("", 1); return "an empty key was accepted"; } catch (ArgumentException) { }
                    return s.Pin(key) == null ? null : "a refused raise created a pin";
            }
        }
        finally { CloseAll(hs); }
    }

    static string? PinConcurrent(PinStoreConformance c, int rounds, int copies, int handles)
    {
        var hs = OpenAll(c.Open, handles);
        try
        {
            for (int round = 1; round <= rounds; round++)
            {
                var key = Key("pin-concurrent");
                Race(copies, i => hs[i % hs.Count].RaisePin(key, (i + copies / 2) % copies + 1)); // the highest value mid-sequence: a store that keeps the first or the last write ends below the top
                if (hs[0].Pin(key) != copies) return $"round {round}: the pin is {hs[0].Pin(key)?.ToString() ?? "missing"} after racing raises of 1..{copies}, expected {copies}";
            }
            return null;
        }
        finally { CloseAll(hs); }
    }

    static string? PinDurability(PinStoreConformance c)
    {
        var key = Key("pin-durable");
        var a = OpenAll(c.Open, 1);
        try { a[0].RaisePin(key, 9); }
        finally { CloseAll(a); }
        c.Restart?.Invoke();
        var d = OpenAll(c.Open, 1);
        try { return d[0].Pin(key) == 9 ? null : "a pin did not survive closing every handle and a restart"; }
        finally { CloseAll(d); }
    }
}
