// Conformance for bond-settlement stores (IBondStore). A bond store keeps INTERNAL ACCOUNTING for the optimistic path (escrow, depositors, challengers,
// treasury); no money moves. What it must get right is atomicity and idempotence: a transition (open, release, slash) applies in full or not at all, a retry of a
// committed transition returns the stored record and moves nothing, two racing transitions on one bond have exactly one winner, and an acknowledged commit survives
// a restart or a crash. Each check is one such claim, driven against YOUR store through an adapter:
//
//     var report = BondStoreConformance.Run(new MyAdapter());
//     Assert.True(report.Ok, report.Format());
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One isolated bond store backend plus the means to reconnect to it.</summary>
public sealed class BondStoreHandle : ISuiteHandle
{
    public IBondStore Store { get; }
    readonly Func<IBondStore> _reopen;
    readonly Func<IBondStore>? _crash;
    readonly Action? _closer;

    public BondStoreHandle(IBondStore store, Func<IBondStore> reopen, Func<IBondStore>? crash, Action? closer)
    {
        Store = store;
        _reopen = reopen;
        _crash = crash;
        _closer = closer;
    }

    /// <summary>Another client on the SAME backend. After a restart this is how state is read back.</summary>
    public IBondStore Reopen() => _reopen();

    /// <summary>Kill the backend abruptly, then return a client on whatever survived.</summary>
    public IBondStore Crash() => _crash!();

    public bool CanCrash => _crash != null;

    public void Close() => _closer?.Invoke();
}

/// <summary>The adapter a bond store author implements.</summary>
public abstract class BondStoreAdapter
{
    public abstract string Name { get; }

    /// <summary>Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported.</summary>
    public virtual bool Durable => true;

    /// <summary>A fresh, empty, isolated backend. Called once per check.</summary>
    public abstract BondStoreHandle Create();
}

public static class BondStoreConformance
{
    // ---- plan builders (the store never verifies signatures; records are opaque to it) ----

    static D Rec(string claimId, string action, double amount, string from, string to, string evidenceDigest, D? split)
    {
        var r = new D
        {
            ["claimId"] = claimId,
            ["action"] = action,
            ["amount"] = StoreJs.Number(amount),
            ["from"] = from,
            ["to"] = to,
            ["at"] = IntentJs.OfLong(1),
            ["evidenceDigest"] = evidenceDigest,
        };
        if (split != null) r["split"] = split;
        r["sig"] = "sig";
        return r;
    }

    static D Move(string account, string op, double amount) => new() { ["account"] = account, ["op"] = op, ["amount"] = StoreJs.Number(amount) };

    static D OpenPlan(string id, string dep, double amount, double maxOpenClaims = 100, double maxOpenAmount = 1e9)
    {
        var open = new D
        {
            ["amount"] = StoreJs.Number(amount),
            ["depositor"] = dep,
            ["maxOpenClaims"] = StoreJs.Number(maxOpenClaims),
            ["maxOpenAmount"] = StoreJs.Number(maxOpenAmount),
        };
        return new D
        {
            ["claimId"] = id,
            ["expect"] = "none",
            ["next"] = "open",
            ["open"] = open,
            ["moves"] = new L { Move(dep, "debit", amount), Move("escrow", "credit", amount) },
            ["record"] = Rec(id, "open", amount, dep, "escrow", "", null),
        };
    }

    static D ReleasePlan(string id, string dep, double amount) => new()
    {
        ["claimId"] = id,
        ["expect"] = "open",
        ["next"] = "released",
        ["moves"] = new L { Move("escrow", "debit", amount), Move(dep, "credit", amount) },
        ["record"] = Rec(id, "release", amount, "escrow", dep, "", null),
    };

    static D SlashPlan(string id, double amount, string evidence = "ev")
    {
        var split = new D
        {
            ["amount"] = StoreJs.Number(amount),
            ["challengerReward"] = StoreJs.Number(amount / 2),
            ["victimCompensation"] = IntentJs.OfLong(0),
            ["treasuryRemainder"] = StoreJs.Number(amount / 2),
            ["challengerAccount"] = "chal",
            ["victimAccount"] = "pool",
            ["treasuryAccount"] = "treasury",
        };
        return new D
        {
            ["claimId"] = id,
            ["expect"] = "open",
            ["next"] = "slashed",
            ["moves"] = new L { Move("escrow", "debit", amount), Move("chal", "credit", amount / 2), Move("treasury", "credit", amount / 2) },
            ["record"] = Rec(id, "slash", amount, "escrow", "treasury", evidence, split),
        };
    }

    static D RecordOf(D plan) => (D)plan["record"]!;

    static D Committed(D plan) => new BondCommitOutcome("committed", RecordOf(plan), null, null).ToJson();

    static D Replayed(D plan) => new BondCommitOutcome("replayed", RecordOf(plan), null, null).ToJson();

    static BondCommitOutcome Commit(IBondStore s, D plan, double at) => s.Commit(plan, at);

    static L Bal(IBondStore s, params string[] accounts) => accounts.Select(a => (object?)s.Read("", a).Balances[a]).ToList();

    static string Status(IBondStore s, string id)
    {
        var sn = s.Read(id, null);
        return sn.Bond == null ? "none" : (string)sn.Bond["status"]!;
    }

    static readonly string[] Accounts = { "alice", "bob", "escrow", "chal", "treasury" };

    static double Total(IBondStore s) => Accounts.Sum(a => s.Read("", a).Balances[a]);

    static L Outcomes(List<BondCommitOutcome> r) => r.Select(o => o.Outcome).OrderBy(x => x, StringComparer.Ordinal).Cast<object?>().ToList();

    static int Count(List<BondCommitOutcome> r, string outcome) => r.Count(o => o.Outcome == outcome);

    static L Records(IBondStore s, string id) => (L)s.Read(id, null).Bond!["records"]!;

    // ---- the checks ----

    public static readonly IReadOnlyList<SuiteCheck<BondStoreHandle>> Checks = new List<SuiteCheck<BondStoreHandle>>
    {
        new("empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0", h =>
        {
            var want = new D
            {
                ["balances"] = new L { new L { "alice", 0 } },
                ["openTotals"] = new D { ["count"] = 0, ["sum"] = 0 },
                ["highWater"] = 0,
            };
            StoreSuite.Eq(want, h.Store.Read("nope", "alice").ToJson());
        }),
        new("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit", h =>
        {
            var s = h.Store;
            StoreSuite.Eq(2.5, s.Deposit("alice", 2.5));
            StoreSuite.Eq(3.0, s.Deposit("alice", 0.5));
            foreach (var bad in new[] { 0, -1, double.NaN, double.PositiveInfinity }) StoreSuite.Rejects(() => s.Deposit("alice", bad), "deposit of " + bad);
            StoreSuite.Rejects(() => s.Deposit("", 1), "deposit to an unnamed account");
            StoreSuite.Eq(new L { 3 }, Bal(s, "alice"));
        }),
        new("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            var plan = OpenPlan("b1", "alice", 60);
            StoreSuite.Eq(Committed(plan), Commit(s, plan, 500).ToJson());
            var bond = new D { ["claimId"] = "b1", ["amount"] = 60, ["depositor"] = "alice", ["status"] = "open", ["records"] = new L { RecordOf(plan) } };
            var want = new D
            {
                ["bond"] = bond,
                ["balances"] = new L { new L { "alice", 40 } },
                ["openTotals"] = new D { ["count"] = 1, ["sum"] = 60 },
                ["highWater"] = 500,
            };
            StoreSuite.Eq(want, s.Read("b1", "alice").ToJson());
            StoreSuite.Eq(new L { 60 }, Bal(s, "escrow"));
        }),
        new("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 10);
            StoreSuite.Eq("conflict", Commit(s, OpenPlan("b1", "alice", 60), 900).Outcome);
            var want = new D
            {
                ["balances"] = new L { new L { "alice", 10 } },
                ["openTotals"] = new D { ["count"] = 0, ["sum"] = 0 },
                ["highWater"] = 0,
            };
            StoreSuite.Eq(want, s.Read("b1", "alice").ToJson());
            StoreSuite.Eq(new L { 0 }, Bal(s, "escrow"));
        }),
        new("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            var plan = OpenPlan("b1", "alice", 60);
            Commit(s, plan, 1);
            StoreSuite.Eq(Replayed(plan), Commit(s, plan, 2).ToJson());
            StoreSuite.Eq("conflict", Commit(s, OpenPlan("b1", "alice", 61), 3).Outcome);
            StoreSuite.Eq("conflict", Commit(s, OpenPlan("b1", "bob", 60), 3).Outcome);
            StoreSuite.Eq(new L { 40, 60 }, Bal(s, "alice", "escrow"));
            StoreSuite.Eq(1, Records(s, "b1").Count);
        }),
        new("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            StoreSuite.Eq("committed", Commit(s, OpenPlan("c1", "alice", 30, 2, 50), 1).Outcome);
            StoreSuite.Eq("conflict", Commit(s, OpenPlan("c2", "alice", 21, 2, 50), 1).Outcome); // 30 + 21 > 50
            StoreSuite.Eq("committed", Commit(s, OpenPlan("c3", "alice", 20, 2, 50), 1).Outcome);
            StoreSuite.Eq("conflict", Commit(s, OpenPlan("c4", "alice", 1, 2, 50), 1).Outcome); // third open claim
            StoreSuite.Eq(new L { 50, 50 }, Bal(s, "alice", "escrow"));
        }),
        new("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            Commit(s, OpenPlan("r", "alice", 20), 1);
            Commit(s, OpenPlan("s", "alice", 40), 1);
            D rel = ReleasePlan("r", "alice", 20), sl = SlashPlan("s", 40);
            StoreSuite.Eq(Committed(rel), Commit(s, rel, 2).ToJson());
            StoreSuite.Eq(Committed(sl), Commit(s, sl, 3).ToJson());
            StoreSuite.Eq(new L { 60, 0, 20, 20 }, Bal(s, "alice", "escrow", "chal", "treasury"));
            StoreSuite.Eq(100, Total(s));
            StoreSuite.Eq(new L { "released", "slashed" }, new L { Status(s, "r"), Status(s, "s") });
            StoreSuite.Eq(new L { RecordOf(OpenPlan("s", "alice", 40)), RecordOf(sl) }, Records(s, "s"));
        }),
        new("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            StoreSuite.Eq("conflict", Commit(s, ReleasePlan("ghost", "alice", 5), 9).Outcome);
            Commit(s, OpenPlan("b", "alice", 20), 10);
            Commit(s, ReleasePlan("b", "alice", 20), 11);
            var before = Bal(s, "alice", "escrow", "treasury", "chal");
            before.Add(s.Read("b", null).HighWater);
            StoreSuite.Eq("conflict", Commit(s, SlashPlan("b", 20), 99).Outcome);
            var after = Bal(s, "alice", "escrow", "treasury", "chal");
            after.Add(s.Read("b", null).HighWater);
            StoreSuite.Eq(before, after);
            StoreSuite.Eq("released", Status(s, "b"));
        }),
        new("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            Commit(s, OpenPlan("b", "alice", 20), 1);
            var greedy = SlashPlan("b", 20);
            greedy["moves"] = new L { Move("escrow", "debit", 21), Move("treasury", "credit", 21) };
            StoreSuite.Eq("conflict", Commit(s, greedy, 5).Outcome);
            StoreSuite.Eq(new L { 20, 0 }, Bal(s, "escrow", "treasury"));
            StoreSuite.Eq("open", Status(s, "b"));
        }),
        new("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            Commit(s, OpenPlan("b", "alice", 40), 1);
            var sl = SlashPlan("b", 40, "ev-1");
            Commit(s, sl, 2);
            var again = SlashPlan("b", 40, "ev-1");
            var other = new D(RecordOf(sl)) { ["at"] = IntentJs.OfLong(77), ["sig"] = "other" };
            again["record"] = other;
            StoreSuite.Eq(Replayed(sl), Commit(s, again, 3).ToJson());
            StoreSuite.Eq("conflict", Commit(s, SlashPlan("b", 40, "ev-2"), 3).Outcome);
            StoreSuite.Eq("conflict", Commit(s, ReleasePlan("b", "alice", 40), 3).Outcome);
            StoreSuite.Eq(new L { 60, 0, 20, 20 }, Bal(s, "alice", "escrow", "chal", "treasury"));
            StoreSuite.Eq(2, Records(s, "b").Count);
        }),
        new("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once", h =>
        {
            h.Store.Deposit("alice", 100);
            Commit(h.Store, OpenPlan("b", "alice", 40), 1);
            var clients = new List<IBondStore> { h.Store, h.Reopen(), h.Reopen(), h.Reopen() };
            var tasks = new List<Func<BondCommitOutcome>>();
            for (int i = 0; i < 8; i++) { int n = i; tasks.Add(() => clients[n % clients.Count].Commit(ReleasePlan("b", "alice", 40), 10 + n)); }
            var want = new L { "committed" };
            for (int i = 0; i < 7; i++) want.Add("replayed");
            StoreSuite.Eq(want, Outcomes(StoreSuite.Parallel(tasks)));
            StoreSuite.Eq(new L { 100, 0 }, Bal(h.Store, "alice", "escrow"));
            StoreSuite.Eq(2, Records(h.Store, "b").Count);
        }),
        new("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved", h =>
        {
            h.Store.Deposit("alice", 100);
            Commit(h.Store, OpenPlan("b", "alice", 40), 1);
            var other = h.Reopen();
            var tasks = new List<Func<BondCommitOutcome>>
            {
                () => h.Store.Commit(ReleasePlan("b", "alice", 40), 5), () => other.Commit(SlashPlan("b", 40), 5),
                () => h.Store.Commit(SlashPlan("b", 40), 5), () => other.Commit(ReleasePlan("b", "alice", 40), 5),
            };
            var r = StoreSuite.Parallel(tasks);
            StoreSuite.Eq(1, Count(r, "committed"));
            StoreSuite.Eq(3, Count(r, "conflict") + Count(r, "replayed"));
            var st = Status(h.Store, "b");
            StoreSuite.Eq(st == "released" ? new L { 100, 0, 0, 0 } : new L { 60, 0, 20, 20 }, Bal(h.Store, "alice", "escrow", "chal", "treasury"));
            StoreSuite.Eq(100, Total(h.Store));
        }),
        new("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses", h =>
        {
            h.Store.Deposit("alice", 100);
            var other = h.Reopen();
            var tasks = new List<Func<BondCommitOutcome>>
            {
                () => h.Store.Commit(OpenPlan("b", "alice", 60), 1), () => other.Commit(OpenPlan("b", "alice", 60), 1),
                () => h.Store.Commit(OpenPlan("b", "alice", 60), 1), () => other.Commit(OpenPlan("b", "alice", 50), 1),
            };
            var r = StoreSuite.Parallel(tasks);
            StoreSuite.Eq(1, Count(r, "committed"));
            StoreSuite.Eq(r[3].Outcome == "committed" ? new L { 50, 50 } : new L { 40, 60 }, Bal(h.Store, "alice", "escrow"));
            StoreSuite.Eq(100, Total(h.Store));
        }),
        new("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited", h =>
        {
            h.Store.Deposit("alice", 100);
            var other = h.Reopen();
            var tasks = new List<Func<BondCommitOutcome>>();
            for (int i = 0; i < 6; i++) { int n = i; tasks.Add(() => (n % 2 == 1 ? h.Store : other).Commit(OpenPlan("b" + n, "alice", 40), 1)); }
            StoreSuite.Eq(2, Count(StoreSuite.Parallel(tasks), "committed"));
            StoreSuite.Eq(new L { 20, 80 }, Bal(h.Store, "alice", "escrow"));
        }),
        new("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly", h =>
        {
            var other = h.Reopen();
            var tasks = new List<Func<double>>();
            for (int i = 0; i < 16; i++) { int n = i; tasks.Add(() => (n % 2 == 1 ? h.Store : other).Deposit("alice", 1)); }
            StoreSuite.Parallel(tasks);
            StoreSuite.Eq(new L { 16 }, Bal(h.Store, "alice"));
        }),
        new("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            Commit(s, OpenPlan("a", "alice", 10), 100);
            Commit(s, OpenPlan("b", "alice", 10), 40);
            StoreSuite.Eq(100, s.Read("", null).HighWater);
            Commit(s, OpenPlan("c", "alice", 10), double.NaN);
            StoreSuite.Eq(100, s.Read("", null).HighWater);
            Commit(s, OpenPlan("d", "alice", 10), 101);
            StoreSuite.Eq(101, s.Read("", null).HighWater);
        }),
        new("reads-are-snapshots", "mutating a returned snapshot cannot change the store", h =>
        {
            var s = h.Store;
            s.Deposit("alice", 100);
            Commit(s, OpenPlan("b", "alice", 10), 1);
            var snap = s.Read("b", "alice");
            snap.Bond!["amount"] = IntentJs.OfLong(999);
            ((L)snap.Bond["records"]!).Clear();
            snap.Balances["alice"] = 12345.0;
            var again = s.Read("b", "alice");
            StoreSuite.Eq(10, again.Bond!["amount"]);
            StoreSuite.Eq(1, ((L)again.Bond["records"]!).Count);
            StoreSuite.Eq(new L { new L { "alice", 90 } }, again.ToJson()["balances"]);
        }),
        new("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name", h =>
        {
            var s = h.Store;
            foreach (var n in new[] { "__proto__", "constructor", "toString", "hasOwnProperty" })
            {
                s.Deposit(n, 50);
                StoreSuite.Eq("committed", Commit(s, OpenPlan(n, n, 20), 1).Outcome, n);
                StoreSuite.Eq(new L { 30 }, Bal(s, n), n);
                StoreSuite.Eq("open", Status(s, n), n);
            }
            StoreSuite.Eq("none", Status(s, "valueOf"));
            StoreSuite.Eq(new L { 0 }, Bal(s, "valueOf"));
        }),
        new("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", "durable", h =>
        {
            h.Store.Deposit("alice", 100);
            Commit(h.Store, OpenPlan("a", "alice", 40), 7);
            Commit(h.Store, OpenPlan("b", "alice", 20), 8);
            var sl = SlashPlan("b", 20);
            Commit(h.Store, sl, 9);
            var back = h.Reopen();
            var bond = new D { ["claimId"] = "b", ["amount"] = 20, ["depositor"] = "alice", ["status"] = "slashed", ["records"] = new L { RecordOf(OpenPlan("b", "alice", 20)), RecordOf(sl) } };
            var want = new D
            {
                ["bond"] = bond,
                ["balances"] = new L { new L { "alice", 40 } },
                ["openTotals"] = new D { ["count"] = 1, ["sum"] = 40 },
                ["highWater"] = 9,
            };
            StoreSuite.Eq(want, back.Read("b", "alice").ToJson());
            StoreSuite.Eq(new L { 40, 10, 10 }, Bal(back, "escrow", "chal", "treasury"));
            StoreSuite.Eq("replayed", Commit(back, sl, 10).Outcome);
        }),
        new("acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", "crash", h =>
        {
            h.Store.Deposit("alice", 100);
            Commit(h.Store, OpenPlan("a", "alice", 40), 1);
            Commit(h.Store, OpenPlan("b", "alice", 30), 2);
            var inflight = Task.Run(() => { try { h.Store.Commit(SlashPlan("b", 30), 3); } catch (Exception) { /* killed in flight */ } });
            var back = h.Crash();
            inflight.Wait();
            StoreSuite.Eq("open", Status(back, "a"));
            var st = Status(back, "b");
            StoreSuite.Ok(st == "open" || st == "slashed", "bond b is " + st);
            StoreSuite.Eq(st == "slashed" ? new L { 30, 40, 15, 15 } : new L { 30, 70, 0, 0 }, Bal(back, "alice", "escrow", "chal", "treasury"));
            StoreSuite.Eq(100, Total(back));
            StoreSuite.Eq(st == "slashed" ? "replayed" : "committed", Commit(back, SlashPlan("b", 30), 4).Outcome);
            StoreSuite.Eq(new L { 30, 40, 15, 15 }, Bal(back, "alice", "escrow", "chal", "treasury"));
        }),
    };

    /// <summary>Run the suite against <paramref name="adapter"/> (only the named checks when <paramref name="only"/> is non-null).</summary>
    public static SuiteReport Run(BondStoreAdapter adapter, ICollection<string>? only = null) =>
        StoreSuite.Run("bond store", adapter.Name, adapter.Durable, adapter.Create, Checks, only);

    // ---- reference adapters ----

    sealed class KvAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) : BondStoreAdapter
    {
        public override string Name => name;
        public override bool Durable => durable;

        public override BondStoreHandle Create()
        {
            var clients = backend();
            Func<IBondStore> open = () => new KvBondStore(clients());
            return new BondStoreHandle(open(), open, crashable ? open : null, null);
        }
    }

    /// <summary>An adapter over any <see cref="IAtomicKv"/>: <paramref name="backend"/> opens one isolated backend and returns a factory of clients on it.</summary>
    public static BondStoreAdapter KvStoreAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) => new KvAdapter(name, durable, backend, crashable);

    /// <summary>GOOD, in process: the reference store over a <see cref="MemoryAtomicKv"/>. Not durable (declared).</summary>
    public static BondStoreAdapter MemoryStoreAdapter() =>
        new KvAdapter("KvBondStore over MemoryAtomicKv", false, () => { var kv = new MemoryAtomicKv(); return () => kv; }, false);

    /// <summary>The mistakes a bad store makes.</summary>
    public enum Defect { NonAtomic, NoReplay, LostUpdate, Amnesia, ClockRewind }

    static string Label(Defect d) => d switch
    {
        Defect.NonAtomic => "BAD non-atomic (moves land before the phase check)",
        Defect.NoReplay => "BAD no idempotence (a retried transition conflicts)",
        Defect.LostUpdate => "BAD lost update (read, pause, write)",
        Defect.Amnesia => "BAD amnesia (claims durability, forgets on reopen)",
        _ => "BAD clock rewind (high-water mark follows the last call)",
    };

    sealed class Defective(Defect defect) : IBondStore
    {
        readonly object _lock = new();
        volatile BondDoc _doc = BondDoc.Empty();

        public void Forget() => _doc = BondDoc.Empty();

        public BondSnapshot Read(string claimId, string? depositor)
        {
            lock (_lock) return _doc.Snapshot(claimId, depositor);
        }

        public double Deposit(string account, double amount)
        {
            if (!(amount > 0) || double.IsInfinity(amount) || string.IsNullOrEmpty(account)) throw new ArgumentException("deposit");
            if (defect == Defect.LostUpdate)
            {
                BondDoc baseDoc;
                lock (_lock) baseDoc = BondDoc.Decode(_doc.Encode());
                Thread.Sleep(2);
                double nv = baseDoc.Balances.GetValueOrDefault(account) + amount;
                baseDoc.Balances[account] = nv;
                _doc = baseDoc;
                return nv;
            }
            lock (_lock)
            {
                double v = _doc.Balances.GetValueOrDefault(account) + amount;
                _doc.Balances[account] = v;
                return v;
            }
        }

        public BondCommitOutcome Commit(D plan, double observedAt)
        {
            if (defect == Defect.LostUpdate)
            {
                BondDoc working;
                lock (_lock) working = BondDoc.Decode(_doc.Encode());
                Thread.Sleep(2);
                var o = BondDoc.CommitBondPlan(working, plan, observedAt);
                if (o.Outcome == "committed") _doc = working;
                return o;
            }
            lock (_lock)
            {
                var d = _doc;
                var claimId = (string)plan["claimId"]!;
                if (defect == Defect.NonAtomic)
                {
                    // applies the balance moves first, then checks the phase: a conflict leaves the money moved
                    foreach (var mo in (L)plan["moves"]!)
                    {
                        var m = (D)mo!;
                        double a = IntentJs.NumOf(m["amount"])!.Value;
                        var account = (string)m["account"]!;
                        d.Balances[account] = d.Balances.GetValueOrDefault(account) + (m["op"] as string == "credit" ? a : -a);
                    }
                    d.Bonds.TryGetValue(claimId, out var b);
                    bool bad = plan["expect"] as string == "none" ? b != null : b == null || plan["expect"] as string != b["status"] as string;
                    if (bad) return new BondCommitOutcome("conflict", null, "phase", b == null ? "none" : (string)b["status"]!);
                    var open = plan.GetValueOrDefault("open") as D;
                    if (open != null)
                    {
                        d.Bonds[claimId] = new D
                        {
                            ["claimId"] = claimId, ["amount"] = open["amount"], ["depositor"] = open["depositor"], ["status"] = "open",
                            ["records"] = new L { plan["record"] },
                        };
                    }
                    else
                    {
                        b!["status"] = plan["next"];
                        ((L)b["records"]!).Add(plan["record"]);
                    }
                    d.HighWater = Math.Max(d.HighWater, observedAt);
                    return new BondCommitOutcome("committed", (D)plan["record"]!, null, null);
                }
                var output = BondDoc.CommitBondPlan(d, plan, observedAt);
                if (defect == Defect.NoReplay && output.Outcome == "replayed") return new BondCommitOutcome("conflict", null, "already applied", "open");
                if (defect == Defect.ClockRewind && output.Outcome == "committed") d.HighWater = observedAt;
                return output;
            }
        }
    }

    sealed class DefectiveAdapter(Defect defect) : BondStoreAdapter
    {
        public override string Name => Label(defect);

        public override BondStoreHandle Create()
        {
            var d = new Defective(defect);
            Func<IBondStore> again = () => { if (defect == Defect.Amnesia) d.Forget(); return d; };
            return new BondStoreHandle(d, again, again, null);
        }
    }

    /// <summary>A bad adapter: one store object shared by every client (a reopen on <see cref="Defect.Amnesia"/> clears it).</summary>
    public static BondStoreAdapter DefectiveStoreAdapter(Defect defect) => new DefectiveAdapter(defect);

    /// <summary>The reference adapters by name (the bad ones are positive controls).</summary>
    public static IReadOnlyDictionary<string, Func<BondStoreAdapter>> ReferenceAdapters()
    {
        var m = new Dictionary<string, Func<BondStoreAdapter>> { ["bond-memory"] = MemoryStoreAdapter };
        foreach (var d in Enum.GetValues<Defect>())
        {
            var dd = d;
            var name = "bad-bond-" + string.Concat(dd.ToString().Select((ch, i) => char.IsUpper(ch) && i > 0 ? "-" + char.ToLowerInvariant(ch) : char.ToLowerInvariant(ch).ToString()));
            m[name] = () => DefectiveStoreAdapter(dd);
        }
        return m;
    }
}
