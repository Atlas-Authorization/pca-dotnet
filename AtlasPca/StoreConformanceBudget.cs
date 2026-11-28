// Conformance for aggregate budget ledgers (IBudgetLedger): no overspend at principal, org and fleet scope given a ledger that is linearizable per key and
// durable. Each check is one claim (the cap holds under racing reservations, a reservation counts at once, a release frees budget only for a real reservation,
// a committed event is never released, expiry frees only what never started, a crash can only over-restrict), driven against YOUR ledger through an adapter:
//
//     var report = BudgetLedgerConformance.Run(new MyAdapter());
//     Assert.True(report.Ok, report.Format());
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One isolated budget ledger backend plus the means to reconnect to it.</summary>
public sealed class BudgetLedgerHandle : ISuiteHandle
{
    public IBudgetLedger Ledger { get; }
    /// <summary>Set by the runner: the adapter's declared durability, so a check can compare it with the ledger's own claim.</summary>
    public bool AdapterDurable { get; set; } = true;
    readonly Func<IBudgetLedger> _reopen;
    readonly Func<IBudgetLedger>? _crash;
    readonly Action? _closer;

    public BudgetLedgerHandle(IBudgetLedger ledger, Func<IBudgetLedger> reopen, Func<IBudgetLedger>? crash, Action? closer)
    {
        Ledger = ledger;
        _reopen = reopen;
        _crash = crash;
        _closer = closer;
    }

    /// <summary>Another client on the SAME backend (the first stays usable).</summary>
    public IBudgetLedger Reopen() => _reopen();

    /// <summary>Kill the backend abruptly, then return a client on whatever survived.</summary>
    public IBudgetLedger Crash() => _crash!();

    public bool CanCrash => _crash != null;

    public void Close() => _closer?.Invoke();
}

/// <summary>The adapter a budget ledger author implements.</summary>
public abstract class BudgetLedgerAdapter
{
    public abstract string Name { get; }

    /// <summary>Default true. Declare false ONLY for an in-process ledger; its <c>Durable</c> must then be false too, and the durability checks are skipped.</summary>
    public virtual bool Durable => true;

    public abstract BudgetLedgerHandle Create();
}

public static class BudgetLedgerConformance
{
    // ---- fixtures ----

    const long Cap = 200;
    const string K = "principal/alice", K2 = "principal/bob";

    static D Spend(D? over = null)
    {
        var a = new D
        {
            ["id"] = "spend",
            ["agg"] = "sum",
            ["val"] = "action.params.amount",
            ["sel"] = new D { ["verbs"] = new L { "pay" } },
            ["win"] = new D { ["kind"] = "task" },
            ["key"] = null,
            ["domain_max"] = IntentJs.OfLong(Cap),
            ["holder"] = new D { ["kind"] = "site_local" },
            ["scope"] = "principal",
        };
        if (over != null) foreach (var e in over) a[e.Key] = e.Value;
        return a;
    }

    static D Ev(string id, object? amount, long t = 1000) => new()
    {
        ["id"] = id,
        ["verb"] = "pay",
        ["resource"] = "r",
        ["params"] = new D { ["amount"] = (amount is string or null or bool or Num or D or L) ? amount : StoreJs.Number(Convert.ToDouble(amount, System.Globalization.CultureInfo.InvariantCulture)) },
        ["t"] = IntentJs.OfLong(t),
    };

    static BudgetReserveRequest Req(D evt, List<D> accs) => new() { Event = evt, Accumulators = accs };

    static BudgetReserveRequest Req(string id, double amount, long? expectedVersion = null, long? expiresAt = null) =>
        new() { Event = Ev(id, amount), Accumulators = new List<D> { Spend() }, ExpectedVersion = expectedVersion, ExpiresAt = expiresAt };

    static double ReservedTotal(IBudgetLedger l, string key) =>
        l.Snapshot(key).Events.Where(e => e.GetValueOrDefault("status") as string != "released").Sum(e => IntentJs.NumOf(((D)e["params"]!)["amount"])!.Value);

    static L Statuses(IBudgetLedger l, string key) => l.Snapshot(key).Events.Select(e => e.GetValueOrDefault("status")).ToList();

    static D MkEvidence(string id) => new()
    {
        ["v"] = IntentJs.OfLong(1),
        ["key"] = K,
        ["id"] = id,
        ["reason"] = "effect_failed",
        ["at"] = IntentJs.OfLong(5),
        ["signer"] = "s",
        ["sig"] = "x",
    };

    static int Count(List<BudgetReserveOutcome> r, string outcome) => r.Count(o => o.Outcome == outcome);

    /// <summary>The outcome name, or the entry's status when the settlement was refused.</summary>
    static string? RefusedStatus(BudgetSettleOutcome o) => o.Outcome == "refused" ? o.Status : o.Outcome;

    static List<Func<BudgetReserveOutcome>> Reserves(List<IBudgetLedger> clients, int n, Func<int, BudgetReserveRequest> req)
    {
        var tasks = new List<Func<BudgetReserveOutcome>>();
        for (int i = 0; i < n; i++) { int k = i; tasks.Add(() => clients[k % clients.Count].Reserve(K, req(k))); }
        return tasks;
    }

    static D Empty() => new() { ["version"] = 0, ["events"] = new L() };

    // ---- the checks ----

    public static readonly IReadOnlyList<SuiteCheck<BudgetLedgerHandle>> Checks = new List<SuiteCheck<BudgetLedgerHandle>>
    {
        new("empty-key-is-empty", "a key nobody reserved on has version 0 and no events", h => StoreSuite.Eq(Empty(), h.Ledger.Snapshot(K).ToJson())),
        new("reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted", h =>
        {
            var l = h.Ledger;
            var a = l.Reserve(K, Req("a", 150));
            StoreSuite.Eq("reserved", a.Outcome);
            StoreSuite.Eq(new D { ["spend"] = 150 }, a.ToJson()["post"]);
            var b = l.Reserve(K, Req("b", 51));
            StoreSuite.Eq(new L { "over_cap", "spend", 201, Cap }, new L { b.Outcome, b.Acc ?? "null", b.PostValue, b.Cap });
            StoreSuite.Eq("reserved", l.Reserve(K, Req("c", 50)).Outcome);
            StoreSuite.Eq(Cap, ReservedTotal(l, K));
        }),
        new("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 150));
            var before = l.Snapshot(K).ToJson();
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("b", 60)).Outcome);
            StoreSuite.Eq(before, l.Snapshot(K).ToJson());
        }),
        new("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts", h =>
        {
            var l = h.Ledger;
            var first = l.Reserve(K, Req("a", 150));
            StoreSuite.Eq(new BudgetReserveOutcome("replayed", first.Version, null, "reserved", null, null, null).ToJson(), l.Reserve(K, Req("a", 150)).ToJson());
            StoreSuite.Eq("id_conflict", l.Reserve(K, Req("a", 10)).Outcome);
            StoreSuite.Eq(150, ReservedTotal(l, K));
            StoreSuite.Eq("reserved", l.Reserve(K, Req("b", 50)).Outcome);
        }),
        new("expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version", h =>
        {
            var l = h.Ledger;
            StoreSuite.Eq("reserved", l.Reserve(K, Req("a", 10, 0)).Outcome);
            StoreSuite.Eq(new BudgetReserveOutcome("conflict", 1, null, null, null, null, null).ToJson(), l.Reserve(K, Req("b", 10, 0)).ToJson());
            StoreSuite.Eq(1, l.Snapshot(K).Events.Count);
            StoreSuite.Eq("reserved", l.Reserve(K, Req("b", 10, 1)).Outcome);
            StoreSuite.Eq("replayed", l.Reserve(K, Req("a", 10, 0)).Outcome);
        }),
        new("racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice", h =>
        {
            var clients = new List<IBudgetLedger> { h.Ledger, h.Reopen(), h.Reopen(), h.Reopen() };
            var rs = StoreSuite.Parallel(Reserves(clients, 40, i => Req("r" + i, 30)));
            StoreSuite.Eq(6, Count(rs, "reserved"));
            StoreSuite.Eq(34, Count(rs, "over_cap"));
            StoreSuite.Eq(180, ReservedTotal(h.Ledger, K));
            StoreSuite.Eq(6, h.Ledger.Snapshot(K).Events.Select(e => e["id"]).Distinct().Count());
        }),
        new("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict", h =>
        {
            var clients = new List<IBudgetLedger> { h.Ledger, h.Reopen(), h.Reopen() };
            var rs = StoreSuite.Parallel(Reserves(clients, 9, i => Req("v" + i, 1, 0)));
            StoreSuite.Eq(1, Count(rs, "reserved"));
            StoreSuite.Eq(8, Count(rs, "conflict"));
            StoreSuite.Eq(1, h.Ledger.Snapshot(K).Events.Count);
        }),
        new("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused", h =>
        {
            var clients = new List<IBudgetLedger> { h.Ledger, h.Reopen(), h.Reopen() };
            var tasks = new List<Func<string>>();
            for (int i = 0; i < 20; i++)
            {
                int n = i;
                tasks.Add(() =>
                {
                    var c = clients[n % 3];
                    for (; ; )
                    {
                        long v = c.Snapshot(K).Version;
                        var r = c.Reserve(K, Req("w" + n, 10, v));
                        if (r.Outcome != "conflict") return r.Outcome;
                    }
                });
            }
            foreach (var o in StoreSuite.Parallel(tasks)) StoreSuite.Eq("reserved", o);
            StoreSuite.Eq(Cap, ReservedTotal(h.Ledger, K));
            StoreSuite.Eq("over_cap", h.Ledger.Reserve(K, Req("extra", 1)).Outcome);
        }),
        new("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 10));
            l.Reserve(K, Req("b", 10));
            StoreSuite.Eq("unknown", l.Commit(K, "ghost").Outcome);
            StoreSuite.Eq("unknown", l.Release(K, "ghost", null).Outcome);
            StoreSuite.Eq("settled", l.Commit(K, "a").Outcome);
            StoreSuite.Eq("replayed", l.Commit(K, "a").Outcome);
            StoreSuite.Eq("committed", RefusedStatus(l.Release(K, "a", null)));
            StoreSuite.Eq("settled", l.Release(K, "b", null).Outcome);
            StoreSuite.Eq("replayed", l.Release(K, "b", null).Outcome);
            StoreSuite.Eq("released", RefusedStatus(l.Commit(K, "b")));
            StoreSuite.Eq(new L { "committed", "released" }, Statuses(l, K));
        }),
        new("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 100));
            l.Reserve(K, Req("b", 100));
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("c", 1)).Outcome);
            l.Release(K, "a", null);
            l.Commit(K, "b");
            StoreSuite.Eq("reserved", l.Reserve(K, Req("d", 100)).Outcome);
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("e", 1)).Outcome);
        }),
        new("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later", h =>
        {
            var l = h.Ledger;
            StoreSuite.Eq("unknown", l.Release(K, "ghost", null).Outcome);
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("a", 201)).Outcome);
            StoreSuite.Eq("reserved", l.Reserve(K, Req("ghost", 200)).Outcome);
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("b", 1)).Outcome);
        }),
        new("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 200));
            l.Release(K, "a", null);
            l.Reserve(K, Req("b", 200));
            StoreSuite.Eq("refused", l.Commit(K, "a").Outcome);
            l.Commit(K, "b");
            StoreSuite.Eq(1, l.Snapshot(K).Events.Count(e => e.GetValueOrDefault("status") as string == "committed"));
        }),
        new("expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 40, null, 500));
            l.Reserve(K, Req("b", 40, null, 500));
            l.Reserve(K, Req("c", 40));
            l.Reserve(K, Req("d", 40, null, 500));
            l.Commit(K, "b");
            l.Start(K, "d");
            StoreSuite.Eq(new L(), l.Expire(K, 499).Released);
            StoreSuite.Eq(new L { "a" }, l.Expire(K, 500).Released);
            StoreSuite.Eq(new L(), l.Expire(K, 10_000).Released);
            StoreSuite.Eq(120, ReservedTotal(l, K));
            StoreSuite.Eq("refused", l.Commit(K, "a").Outcome);
            StoreSuite.Eq("refused", l.Start(K, "a").Outcome);
        }),
        new("start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 10, null, 5));
            l.Reserve(K, Req("b", 10));
            l.Reserve(K, Req("c", 10));
            long v = l.Snapshot(K).Version;
            StoreSuite.Eq("unknown", l.Start(K, "ghost").Outcome);
            StoreSuite.Eq(v, l.Snapshot(K).Version);
            StoreSuite.Eq("settled", l.Start(K, "a").Outcome);
            StoreSuite.Eq("replayed", l.Start(K, "a").Outcome);
            StoreSuite.Eq(new L(), l.Expire(K, 100).Released);
            StoreSuite.Eq("settled", l.Commit(K, "a").Outcome);
            StoreSuite.Eq("replayed", l.Start(K, "a").Outcome);
            l.Start(K, "b");
            StoreSuite.Eq("settled", l.Release(K, "b", null).Outcome);
            StoreSuite.Eq("released", RefusedStatus(l.Start(K, "b")));
            foreach (var e in l.Snapshot(K).Events) if (e["id"] as string == "c") StoreSuite.Ok(!e.ContainsKey("started"), "an unstarted reservation has no started flag");
        }),
        new("keys-are-independent", "two keys have their own caps, versions and events", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 200));
            StoreSuite.Eq("reserved", l.Reserve(K2, Req("a", 200)).Outcome);
            StoreSuite.Eq("over_cap", l.Reserve(K, Req("b", 1)).Outcome);
            StoreSuite.Eq(new L { "a" }, l.Snapshot(K2).Events.Select(e => e["id"]).ToList());
            StoreSuite.Eq(1, l.Snapshot(K2).Version);
        }),
        new("windows-reset-the-count", "a period window counts only the events of the period of the new event", h =>
        {
            var l = h.Ledger;
            var win = new D { ["kind"] = "period", ["ms"] = IntentJs.OfLong(1000), ["t0"] = IntentJs.OfLong(0) };
            var w = new List<D> { Spend(new D { ["win"] = win }) };
            StoreSuite.Eq("reserved", l.Reserve(K, Req(Ev("a", 200, 100), w)).Outcome);
            StoreSuite.Eq("over_cap", l.Reserve(K, Req(Ev("b", 1, 900), w)).Outcome);
            StoreSuite.Eq("reserved", l.Reserve(K, Req(Ev("c", 200, 1100), w)).Outcome);
        }),
        new("release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 10));
            StoreSuite.Rejects<ArgumentException>(() => l.Release(K, "a", MkEvidence("other")), "evidence for another reservation");
            StoreSuite.Eq("reserved", l.Snapshot(K).Events[0]["status"]);
            StoreSuite.Eq("settled", l.Release(K, "a", MkEvidence("a")).Outcome);
            StoreSuite.Eq(MkEvidence("a"), l.Snapshot(K).Events[0]["rel"]);
        }),
        new("invalid-input-is-refused", "a malformed event or request throws and writes nothing", h =>
        {
            var l = h.Ledger;
            var badT = Ev("x", 1);
            badT["t"] = new Num("0.5");
            var badVerb = Ev("x", 1);
            badVerb["verb"] = 7;
            foreach (var bad in new[] { Ev("", 1), badT, badVerb })
                StoreSuite.Rejects<ArgumentException>(() => l.Reserve(K, Req(bad, new List<D> { Spend() })), "reserve of " + bad["id"]);
            StoreSuite.Rejects<ArgumentException>(() => l.Reserve(K, Req("x", 1, -1)), "negative expected version");
            var noCap = Spend();
            noCap["domain_max"] = null;
            StoreSuite.Rejects<ArgumentException>(() => l.Reserve(K, Req(Ev("x", 1), new List<D> { noCap })), "accumulator without a cap");
            StoreSuite.Eq(Empty(), l.Snapshot(K).ToJson());
        }),
        new("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger", h =>
        {
            var l = h.Ledger;
            l.Reserve(K, Req("a", 10));
            l.Snapshot(K).Events[0]["status"] = "released";
            StoreSuite.Eq("reserved", l.Snapshot(K).Events[0]["status"]);
        }),
        new("durable-claim-matches-the-adapter", "a ledger says durable exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal", h =>
            StoreSuite.Ok(h.Ledger.Durable == h.AdapterDurable, $"ledger.Durable={h.Ledger.Durable} but the adapter declares durable={h.AdapterDurable}")),
        new("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", "durable", h =>
        {
            h.Ledger.Reserve(K, Req("a", 150));
            h.Ledger.Reserve(K, Req("b", 50));
            h.Ledger.Commit(K, "a");
            h.Ledger.Release(K, "b", null);
            var back = h.Reopen();
            var pairs = back.Snapshot(K).Events.Select(e => (object?)new L { e["id"], e["status"] }).ToList();
            StoreSuite.Eq(new L { new L { "a", "committed" }, new L { "b", "released" } }, pairs);
            StoreSuite.Eq("over_cap", back.Reserve(K, Req("c", 51)).Outcome);
            StoreSuite.Eq("reserved", back.Reserve(K, Req("c", 50)).Outcome);
        }),
        new("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", "crash", h =>
        {
            h.Ledger.Reserve(K, Req("a", 200));
            var inflight = Task.Run(() => { try { h.Ledger.Reserve(K, Req("b", 0)); } catch (Exception) { /* killed in flight */ } });
            var back = h.Crash();
            inflight.Wait();
            StoreSuite.Eq("over_cap", back.Reserve(K, Req("c", 1)).Outcome);
            StoreSuite.Eq("a", back.Snapshot(K).Events[0]["id"]);
        }),
    };

    /// <summary>Run the suite against <paramref name="adapter"/> (only the named checks when <paramref name="only"/> is non-null).</summary>
    public static SuiteReport Run(BudgetLedgerAdapter adapter, ICollection<string>? only = null) =>
        StoreSuite.Run("budget ledger", adapter.Name, adapter.Durable, () => { var h = adapter.Create(); h.AdapterDurable = adapter.Durable; return h; }, Checks, only);

    // ---- reference adapters ----

    sealed class KvAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) : BudgetLedgerAdapter
    {
        public override string Name => name;
        public override bool Durable => durable;

        public override BudgetLedgerHandle Create()
        {
            var clients = backend();
            Func<IBudgetLedger> open = () => new KvBudgetLedger(clients(), durable);
            return new BudgetLedgerHandle(open(), open, crashable ? open : null, null);
        }
    }

    /// <summary>An adapter over any <see cref="IAtomicKv"/>: <paramref name="backend"/> opens one isolated backend and returns a factory of clients on it.</summary>
    public static BudgetLedgerAdapter KvLedgerAdapter(string name, bool durable, Func<Func<IAtomicKv>> backend, bool crashable) => new KvAdapter(name, durable, backend, crashable);

    /// <summary>GOOD, in process: the reference ledger over a <see cref="MemoryAtomicKv"/>. Not durable (declared, and the ledger says so too).</summary>
    public static BudgetLedgerAdapter MemoryLedgerAdapter() =>
        new KvAdapter("KvBudgetLedger over MemoryAtomicKv", false, () => { var kv = new MemoryAtomicKv(); return () => kv; }, false);

    /// <summary>The mistakes a bad ledger makes.</summary>
    public enum Defect
    {
        NoCap, NoCas, LostUpdate, Amnesia, ReleaseUnreserved, ReleaseCommitted, LateCommit, NoReplay, SharedKeys, ExpireCommitted, ExpireStarted, VolatileClaimsDurable,
    }

    static string Label(Defect d) => d switch
    {
        Defect.NoCap => "BAD no cap check (records every reservation)",
        Defect.NoCas => "BAD no compare-and-swap (ignores expectedVersion)",
        Defect.LostUpdate => "BAD lost update (read, pause, write)",
        Defect.Amnesia => "BAD amnesia (claims durability, forgets on reopen)",
        Defect.ReleaseUnreserved => "BAD release without reserve (credits budget for an unknown id)",
        Defect.ReleaseCommitted => "BAD release of a committed event (frees spent budget)",
        Defect.LateCommit => "BAD late commit (a released reservation can be committed again)",
        Defect.NoReplay => "BAD no idempotence (a retried reservation counts twice)",
        Defect.SharedKeys => "BAD one state for every key (keys leak into each other)",
        Defect.ExpireCommitted => "BAD expiry releases committed events",
        Defect.ExpireStarted => "BAD expiry releases started reservations (an effect that ran stops counting)",
        _ => "BAD in-process ledger that claims durable: true",
    };

    sealed class Defective(Defect defect) : IBudgetLedger
    {
        readonly object _lock = new();
        Dictionary<string, BudgetDoc> _docs = new();

        public void Forget()
        {
            lock (_lock) _docs = new();
        }

        BudgetDoc Doc(string key)
        {
            lock (_lock)
            {
                var k = defect == Defect.SharedKeys ? "*" : key;
                if (!_docs.TryGetValue(k, out var d)) _docs[k] = d = BudgetDoc.Empty();
                return d;
            }
        }

        public bool Durable => true; // every defective ledger claims durability (VolatileClaimsDurable is the lie the check catches)

        public BudgetSnapshot Snapshot(string key)
        {
            lock (_lock)
            {
                var d = Doc(key);
                return new BudgetSnapshot(d.Ver, d.Events.Select(e => (D)StoreJs.DeepCopy(e)!).ToList());
            }
        }

        public BudgetReserveOutcome Reserve(string key, BudgetReserveRequest r)
        {
            var rr = r;
            if (defect == Defect.NoCas) { rr = Copy(r); rr.ExpectedVersion = null; }
            if (defect == Defect.NoCap)
            {
                rr = Copy(rr);
                rr.Accumulators = r.Accumulators!.Select(a => new D(a) { ["domain_max"] = IntentJs.OfLong(9007199254740991L) }).ToList();
            }
            if (defect == Defect.LostUpdate)
            {
                BudgetDoc work;
                lock (_lock) work = BudgetDoc.Decode(Doc(key).Encode());
                StoreSuite.RaceWindow();
                var o = work.ReserveInDoc(rr);
                if (o.Outcome == "reserved") lock (_lock) _docs[key] = work;
                return o;
            }
            lock (_lock)
            {
                var d = Doc(key);
                if (defect == Defect.NoReplay)
                {
                    foreach (var e in d.Events)
                    {
                        if (Equals(e["id"], r.Event!["id"]))
                        {
                            var dup = (D)StoreJs.DeepCopy(e)!;
                            dup["id"] = r.Event["id"] + "#dup";
                            d.Events.Add(dup);
                            d.Ver += 1;
                            return new BudgetReserveOutcome("reserved", d.Ver, new Dictionary<string, long>(), null, null, null, null);
                        }
                    }
                }
                return d.ReserveInDoc(rr);
            }
        }

        static BudgetReserveRequest Copy(BudgetReserveRequest r) => new()
        {
            Event = r.Event, Accumulators = r.Accumulators, Schema = r.Schema, ExpectedVersion = r.ExpectedVersion, ExpiresAt = r.ExpiresAt,
        };

        static D? Find(BudgetDoc d, string id) => d.Events.FirstOrDefault(e => id == e["id"] as string);

        public BudgetSettleOutcome Start(string key, string id)
        {
            lock (_lock) return Doc(key).StartInDoc(id);
        }

        public BudgetSettleOutcome Commit(string key, string id)
        {
            lock (_lock)
            {
                var d = Doc(key);
                if (defect == Defect.LateCommit)
                {
                    var e = Find(d, id);
                    if (e != null && e.GetValueOrDefault("status") as string == "released")
                    {
                        e["status"] = "committed";
                        d.Ver += 1;
                        return new BudgetSettleOutcome("settled", d.Ver, null);
                    }
                }
                return d.CommitInDoc(id);
            }
        }

        public BudgetSettleOutcome Release(string key, string id, D? evidence)
        {
            lock (_lock)
            {
                var d = Doc(key);
                var e = Find(d, id);
                if (defect == Defect.ReleaseUnreserved && e == null)
                {
                    var ghost = Ev(id, 0, 0);
                    ((D)ghost["params"]!)["amount"] = IntentJs.OfLong(-Cap);
                    ghost["status"] = "committed";
                    d.Events.Add(ghost);
                    d.Ver += 1;
                    return new BudgetSettleOutcome("settled", d.Ver, null);
                }
                if (defect == Defect.ReleaseCommitted && e != null && e.GetValueOrDefault("status") as string == "committed")
                {
                    e["status"] = "released";
                    d.Ver += 1;
                    return new BudgetSettleOutcome("settled", d.Ver, null);
                }
                return d.ReleaseInDoc(key, id, evidence);
            }
        }

        public BudgetExpired Expire(string key, long now)
        {
            lock (_lock)
            {
                var d = Doc(key);
                if (defect is Defect.ExpireCommitted or Defect.ExpireStarted)
                {
                    var released = new List<string>();
                    foreach (var e in d.Events)
                    {
                        double? exp = e.ContainsKey("exp") ? IntentJs.NumOf(e["exp"]) : null;
                        var status = e.GetValueOrDefault("status") as string;
                        bool hit = exp != null && exp <= now && (defect == Defect.ExpireCommitted ? status != "released" : status == "reserved");
                        if (hit) { e["status"] = "released"; released.Add((string)e["id"]!); }
                    }
                    if (released.Count > 0) d.Ver += 1;
                    return new BudgetExpired(released, d.Ver);
                }
                return d.ExpireInDoc(now);
            }
        }
    }

    sealed class DefectiveAdapter(Defect defect) : BudgetLedgerAdapter
    {
        public override string Name => Label(defect);
        public override bool Durable => defect != Defect.VolatileClaimsDurable;

        public override BudgetLedgerHandle Create()
        {
            var d = new Defective(defect);
            Func<IBudgetLedger> again = () => { if (defect == Defect.Amnesia) d.Forget(); return d; };
            return new BudgetLedgerHandle(d, again, again, null);
        }
    }

    /// <summary>A bad adapter: one ledger object shared by every client (a reopen on <see cref="Defect.Amnesia"/> clears it).</summary>
    public static BudgetLedgerAdapter DefectiveLedgerAdapter(Defect defect) => new DefectiveAdapter(defect);

    /// <summary>The reference adapters by name (the bad ones are positive controls).</summary>
    public static IReadOnlyDictionary<string, Func<BudgetLedgerAdapter>> ReferenceAdapters()
    {
        var m = new Dictionary<string, Func<BudgetLedgerAdapter>> { ["budget-memory"] = MemoryLedgerAdapter };
        foreach (var d in Enum.GetValues<Defect>())
        {
            var dd = d;
            var name = "bad-budget-" + string.Concat(dd.ToString().Select((ch, i) => char.IsUpper(ch) && i > 0 ? "-" + char.ToLowerInvariant(ch) : char.ToLowerInvariant(ch).ToString()));
            m[name] = () => DefectiveLedgerAdapter(dd);
        }
        return m;
    }
}
