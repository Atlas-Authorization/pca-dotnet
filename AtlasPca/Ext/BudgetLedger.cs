using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The typed failure of the aggregate budget ledger: <c>not_durable</c>, <c>scope_unbound</c>, <c>store_missing</c>, <c>store_corrupt</c>, <c>invalid</c>, <c>conflict_exhausted</c>.</summary>
public sealed class BudgetLedgerError(string code, string message) : Exception(code + ": " + message)
{
    public string Code { get; } = code;
}

/// <summary>A reservation request. <see cref="Accumulators"/> are the declarations of THIS key (each <c>domain_max</c> is the cap).</summary>
public sealed class BudgetReserveRequest
{
    /// <summary>{id, verb, resource, params, t}.</summary>
    public D? Event;
    public List<D>? Accumulators;
    /// <summary>An action schema (or null).</summary>
    public object? Schema;
    /// <summary>Refuse (<c>conflict</c>) unless the key is at this version.</summary>
    public long? ExpectedVersion;
    public long? ExpiresAt;
}

/// <summary><c>reserved</c> (+post), <c>replayed</c> (+status), <c>over_cap</c> (+acc, post, cap), <c>conflict</c>, <c>id_conflict</c>.</summary>
public sealed record BudgetReserveOutcome(string Outcome, long Version, Dictionary<string, long>? Post, string? Status, string? Acc, long? PostValue, double? Cap)
{
    public D ToJson()
    {
        var m = new D { ["outcome"] = Outcome, ["version"] = IntentJs.OfLong(Version) };
        if (Post != null)
        {
            var p = new D();
            foreach (var e in Post) p[e.Key] = IntentJs.OfLong(e.Value);
            m["post"] = p;
        }
        if (Status != null) m["status"] = Status;
        if (Acc != null)
        {
            m["acc"] = Acc;
            m["post"] = IntentJs.OfLong(PostValue!.Value);
            m["cap"] = StoreJs.Number(Cap!.Value);
        }
        return m;
    }
}

/// <summary><c>settled</c>, <c>replayed</c>, <c>unknown</c> or <c>refused</c> (+status of the entry).</summary>
public sealed record BudgetSettleOutcome(string Outcome, long Version, string? Status)
{
    public D ToJson()
    {
        var m = new D { ["outcome"] = Outcome, ["version"] = IntentJs.OfLong(Version) };
        if (Status != null) m["status"] = Status;
        return m;
    }
}

/// <summary>The result of <see cref="IBudgetLedger.Expire"/>: the released ids and the version afterwards.</summary>
public sealed record BudgetExpired(List<string> Released, long Version)
{
    public D ToJson() => new() { ["released"] = Released.Cast<object?>().ToList(), ["version"] = IntentJs.OfLong(Version) };
}

/// <summary>A copy of a key's events and its version.</summary>
public sealed record BudgetSnapshot(long Version, List<D> Events)
{
    public D ToJson() => new() { ["version"] = IntentJs.OfLong(Version), ["events"] = Events.Cast<object?>().ToList() };
}

/// <summary>The persistence contract of a durable aggregate budget (no overspend at principal, org and fleet scope), given a ledger that is linearizable per key
/// and durable. A reservation counts as soon as it is made; the ledger refuses a reservation whose post-value would pass the accumulator's <c>domain_max</c>
/// inside the same atomic step that records it.
///
/// Two phases: <c>Reserve</c> (counted at once), then <c>Start</c> (recorded BEFORE the effect runs), then <c>Commit</c> (the effect happened) or <c>Release</c>
/// (it did not). <c>Expire</c> frees only a reservation that was never started. A committed event is never released and a released one is never committed.
/// Each operation is atomic per key; the same reservation again is a replay that changes nothing; acknowledged writes survive a crash; <see cref="Durable"/> is
/// true only for a store that does. Events are the JSON objects <c>{id, verb, resource, params, t, status, exp?, started?, rel?}</c>.</summary>
public interface IBudgetLedger
{
    /// <summary>True ONLY when acknowledged writes survive a restart or crash. Non-session scopes refuse a ledger that does not say so.</summary>
    bool Durable { get; }

    BudgetSnapshot Snapshot(string key);

    BudgetReserveOutcome Reserve(string key, BudgetReserveRequest req);

    /// <summary>The effect is about to run: mark the reservation non-expirable. <c>refused</c> once released; <c>replayed</c> when already started or committed.</summary>
    BudgetSettleOutcome Start(string key, string id);

    BudgetSettleOutcome Commit(string key, string id);

    /// <summary><paramref name="evidence"/> (a signed release, see <see cref="Budgets.SignRelease"/>) may be null.</summary>
    BudgetSettleOutcome Release(string key, string id, D? evidence);

    /// <summary>Release every open, never-started reservation whose <c>exp</c> is at or before <paramref name="now"/>.</summary>
    BudgetExpired Expire(string key, long now);
}

/// <summary>One key's reservations and the pure transitions over them; every reference budget store is these plus a per-key lock.</summary>
public sealed class BudgetDoc
{
    public long Ver;
    public List<D> Events { get; } = new();

    public static BudgetDoc Empty() => new();

    const int IdMax = 256;

    /// <summary>A non-empty string of at most 256 characters without control characters.</summary>
    public static bool IdOk(object? s)
    {
        if (s is not string v) return false;
        if (v.Length == 0 || v.Length > IdMax) return false;
        foreach (var c in v) if (c <= 0x1f) return false;
        return true;
    }

    public D Encode() => new()
    {
        ["v"] = IntentJs.OfLong(1),
        ["ver"] = IntentJs.OfLong(Ver),
        ["events"] = Events.Select(e => StoreJs.DeepCopy(e)).ToList(),
    };

    /// <summary>Decode a stored document (null = empty); fails closed with <c>store_corrupt</c>. The result shares nothing with <paramref name="raw"/>.</summary>
    public static BudgetDoc Decode(object? raw)
    {
        if (raw == null) return Empty();
        if (raw is not D m || !IntentJs.IsInt(m.GetValueOrDefault("v")) || IntentJs.Lng(m["v"]) != 1 || !IntentJs.IsInt(m.GetValueOrDefault("ver"))
            || m.GetValueOrDefault("events") is not L events)
            throw new BudgetLedgerError("store_corrupt", "budget document has the wrong shape");
        var d = Empty();
        d.Ver = IntentJs.Lng(m["ver"]);
        foreach (var e in events)
        {
            if (e is not D em || em.GetValueOrDefault("id") is not string) throw new BudgetLedgerError("store_corrupt", "budget document has the wrong shape");
            d.Events.Add((D)StoreJs.DeepCopy(em)!);
        }
        return d;
    }

    D? Find(string id) => Events.FirstOrDefault(e => id == e.GetValueOrDefault("id") as string);

    static D Core(D e)
    {
        var m = new D();
        foreach (var k in new[] { "id", "verb", "resource", "params", "t" }) if (e.ContainsKey(k)) m[k] = e[k];
        return m;
    }

    static bool SameEvent(D a, D b) => Pca.HashCanonical(Core(a)) == Pca.HashCanonical(Core(b));

    public BudgetReserveOutcome ReserveInDoc(BudgetReserveRequest? req)
    {
        var e = req?.Event;
        if (e == null || !IdOk(e.GetValueOrDefault("id")) || e.GetValueOrDefault("verb") is not string verb || e.GetValueOrDefault("resource") is not string
            || !IntentJs.IsInt(e.GetValueOrDefault("t")) || e.GetValueOrDefault("params") is not (D or L))
            throw new ArgumentException("reserve: a malformed event");
        if (req!.Accumulators == null) throw new ArgumentException("reserve: accumulators must be an array");
        if (req.ExpectedVersion is < 0) throw new ArgumentException("reserve: expectedVersion must be a non-negative safe integer");
        var id = (string)e["id"]!;
        var prior = Find(id);
        if (prior != null)
        {
            return SameEvent(prior, e) ? new BudgetReserveOutcome("replayed", Ver, null, prior.GetValueOrDefault("status") as string, null, null, null)
                : new BudgetReserveOutcome("id_conflict", Ver, null, null, null, null, null);
        }
        if (req.ExpectedVersion != null && req.ExpectedVersion != Ver) return new BudgetReserveOutcome("conflict", Ver, null, null, null, null, null);
        var post = new Dictionary<string, long>();
        var history = Events.Cast<object?>().ToList();
        foreach (var a in req.Accumulators)
        {
            if (a.GetValueOrDefault("domain_max") == null) throw new ArgumentException("reserve: accumulator " + a.GetValueOrDefault("id") + " has no domain_max (the cap)");
            if (!IntentAcc.AccSelects(a, verb, req.Schema)) continue;
            var p = IntentHistory.AccPost(a, history, verb, e["params"] as D ?? new D(), e["t"], req.Schema);
            if (p == null) throw new BudgetLedgerError("store_corrupt", "unreadable history");
            double cap = IntentJs.NumOf(a["domain_max"]) ?? throw new ArgumentException("reserve: accumulator " + a.GetValueOrDefault("id") + " domain_max is not a number");
            if (p.Value > cap) return new BudgetReserveOutcome("over_cap", Ver, null, null, a.GetValueOrDefault("id") as string, p, cap);
            post[(string)a["id"]!] = p.Value;
        }
        var entry = new D
        {
            ["id"] = id,
            ["verb"] = e["verb"],
            ["resource"] = e["resource"],
            ["params"] = StoreJs.DeepCopy(e["params"]),
            ["t"] = e["t"],
            ["status"] = "reserved",
        };
        if (req.ExpiresAt != null) entry["exp"] = IntentJs.OfLong(req.ExpiresAt.Value);
        Events.Add(entry);
        Ver += 1;
        return new BudgetReserveOutcome("reserved", Ver, post, null, null, null, null);
    }

    public BudgetSettleOutcome StartInDoc(string id)
    {
        var e = Find(id);
        if (e == null) return new BudgetSettleOutcome("unknown", Ver, null);
        if (e.GetValueOrDefault("status") as string == "released") return new BudgetSettleOutcome("refused", Ver, "released");
        if (e.ContainsKey("started") || e.GetValueOrDefault("status") as string == "committed") return new BudgetSettleOutcome("replayed", Ver, null);
        e["started"] = true;
        Ver += 1;
        return new BudgetSettleOutcome("settled", Ver, null);
    }

    public BudgetSettleOutcome CommitInDoc(string id)
    {
        var e = Find(id);
        if (e == null) return new BudgetSettleOutcome("unknown", Ver, null);
        var status = e.GetValueOrDefault("status") as string;
        if (status == "committed") return new BudgetSettleOutcome("replayed", Ver, null);
        if (status != "reserved") return new BudgetSettleOutcome("refused", Ver, status);
        e["status"] = "committed";
        Ver += 1;
        return new BudgetSettleOutcome("settled", Ver, null);
    }

    public BudgetSettleOutcome ReleaseInDoc(string key, string id, D? evidence)
    {
        var e = Find(id);
        if (e == null) return new BudgetSettleOutcome("unknown", Ver, null);
        var status = e.GetValueOrDefault("status") as string;
        if (status == "released") return new BudgetSettleOutcome("replayed", Ver, null);
        if (status != "reserved") return new BudgetSettleOutcome("refused", Ver, status);
        if (evidence != null && (key != evidence.GetValueOrDefault("key") as string || id != evidence.GetValueOrDefault("id") as string))
            throw new ArgumentException("release: the evidence is for another reservation");
        e["status"] = "released";
        if (evidence != null) e["rel"] = StoreJs.DeepCopy(evidence);
        Ver += 1;
        return new BudgetSettleOutcome("settled", Ver, null);
    }

    public BudgetExpired ExpireInDoc(long now)
    {
        if (now < -9007199254740991L || now > 9007199254740991L) throw new ArgumentException("expire: now must be a safe integer");
        var released = new List<string>();
        foreach (var e in Events)
        {
            double? exp = e.ContainsKey("exp") ? IntentJs.NumOf(e["exp"]) : null;
            if (e.GetValueOrDefault("status") as string == "reserved" && !e.ContainsKey("started") && exp != null && exp <= now)
            {
                e["status"] = "released";
                e["rel"] = new D { ["reason"] = "expired", ["at"] = IntentJs.OfLong(now) };
                released.Add((string)e["id"]!);
            }
        }
        if (released.Count > 0) Ver += 1;
        return new BudgetExpired(released, Ver);
    }
}

/// <summary>The reference <see cref="IBudgetLedger"/>: one document per key in an <see cref="IAtomicKv"/>, so every operation is one atomic read-modify-write.
/// <c>durable</c> is declared by the caller because a kv cannot tell: pass true only for a persistent one (<see cref="SqlAtomicKv"/>); over <see cref="MemoryAtomicKv"/>
/// it must be false. LIMIT: one document per key, rewritten per write; a production ledger is a database row-per-event with a unique index on (key, id) and a
/// version column (reuse <see cref="BudgetDoc"/> inside its transaction).</summary>
public sealed class KvBudgetLedger : IBudgetLedger
{
    const string Prefix = "pca-budget-ledger/v1/";
    readonly IAtomicKv _kv;

    public KvBudgetLedger(IAtomicKv kv, bool durable)
    {
        _kv = kv ?? throw new BudgetLedgerError("store_missing", "KvBudgetLedger needs an IAtomicKv");
        Durable = durable;
    }

    public bool Durable { get; }

    static string K(string key)
    {
        if (!BudgetDoc.IdOk(key)) throw new ArgumentException("a ledger key is a non-empty string without control characters");
        return Prefix + key;
    }

    static BudgetDoc Decode(string? text) => BudgetDoc.Decode(text == null ? null : Pca.ParseJson(text));

    T Txn<T>(string key, Func<BudgetDoc, T> fn, Func<T, bool> writes)
    {
        T result = default!;
        _kv.Update(K(key), prev =>
        {
            var d = Decode(prev);
            result = fn(d);
            return writes(result) ? Pca.Canonicalize(d.Encode()) : null;
        });
        return result;
    }

    public BudgetSnapshot Snapshot(string key)
    {
        var d = Decode(_kv.Get(K(key)));
        return new BudgetSnapshot(d.Ver, d.Events.Select(e => (D)StoreJs.DeepCopy(e)!).ToList());
    }

    public BudgetReserveOutcome Reserve(string key, BudgetReserveRequest req) => Txn(key, d => d.ReserveInDoc(req), r => r.Outcome == "reserved");

    public BudgetSettleOutcome Start(string key, string id) => Txn(key, d => d.StartInDoc(id), r => r.Outcome == "settled");

    public BudgetSettleOutcome Commit(string key, string id) => Txn(key, d => d.CommitInDoc(id), r => r.Outcome == "settled");

    public BudgetSettleOutcome Release(string key, string id, D? evidence) => Txn(key, d => d.ReleaseInDoc(key, id, evidence), r => r.Outcome == "settled");

    public BudgetExpired Expire(string key, long now) => Txn(key, d => d.ExpireInDoc(now), r => r.Released.Count > 0);
}
