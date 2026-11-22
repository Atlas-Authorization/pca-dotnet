using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The typed failure of every store-backed bond operation. <see cref="Code"/> is stable; the message is for humans.</summary>
public sealed class BondStoreError : Exception
{
    public string Code { get; }

    public BondStoreError(string code, string message) : base(code + ": " + message) { Code = code; }

    public BondStoreError(string code, string message, Exception? cause) : base(code + ": " + message, cause) { Code = code; }
}

/// <summary>What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark.</summary>
public sealed record BondSnapshot(D? Bond, Dictionary<string, double> Balances, long OpenCount, double OpenSum, double HighWater)
{
    public D ToJson()
    {
        var m = new D();
        if (Bond != null) m["bond"] = Bond;
        m["balances"] = Balances.Select(e => (object?)new L { e.Key, StoreJs.Number(e.Value) }).ToList();
        m["openTotals"] = new D { ["count"] = IntentJs.OfLong(OpenCount), ["sum"] = StoreJs.Number(OpenSum) };
        m["highWater"] = StoreJs.Number(HighWater);
        return m;
    }
}

/// <summary><c>committed</c> / <c>replayed</c> (with <see cref="Record"/>) or <c>conflict</c> (with <see cref="Reason"/> and <see cref="Current"/>, the bond's phase).</summary>
public sealed record BondCommitOutcome(string Outcome, D? Record, string? Reason, string? Current)
{
    public D ToJson()
    {
        var m = new D { ["outcome"] = Outcome };
        if (Record != null) m["record"] = Record;
        if (Reason != null) m["reason"] = Reason;
        if (Current != null) m["current"] = Current;
        return m;
    }
}

/// <summary>The persistence contract for bond settlement. INTERNAL ACCOUNTING ONLY: nothing here moves money; balances are numbers a store keeps for the
/// deployment's own books. <see cref="Commit"/> applies a plan ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance movement, the new phase and
/// the signed record become visible together; committing the same transition twice is idempotent (the stored record, nothing moved).
///
/// A plan is the JSON object <c>{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}], record}</c>;
/// a bond row is <c>{claimId, amount, depositor, status, window?, records}</c>.</summary>
public interface IBondStore
{
    /// <summary>A consistent snapshot for planning (<paramref name="depositor"/> may be null). May be stale by commit time; commit re-checks everything.</summary>
    BondSnapshot Read(string claimId, string? depositor);

    /// <summary>Apply <paramref name="plan"/> atomically and record <paramref name="observedAt"/> in the time high-water mark. An open plan on an absent bond checks the caps and the
    /// balance and creates it; the same bond again is <c>replayed</c>, anything else <c>conflict</c>. Any other plan needs the bond in phase <c>expect</c>; if it is already in
    /// <c>next</c> via the same settlement it is <c>replayed</c>, else <c>conflict</c>; an overdraft is a <c>conflict</c>. Never throws for a refused plan, only when the store itself fails.</summary>
    BondCommitOutcome Commit(D plan, double observedAt);

    /// <summary>Atomically credit <paramref name="account"/> with <paramref name="amount"/> (a positive finite number). Returns the new balance.</summary>
    double Deposit(string account, double amount);
}

/// <summary>The state a reference bond store keeps, and the pure transition over it (<see cref="CommitBondPlan"/>); every reference store is this plus a lock.</summary>
public sealed class BondDoc
{
    public Dictionary<string, double> Balances { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, D> Bonds { get; } = new(StringComparer.Ordinal);
    public double HighWater;

    public static BondDoc Empty() => new();

    const double MaxSafeMicros = 1e15;

    /// <summary>Integer micro-units of <paramref name="x"/> when it is a micro-grid amount below 1e15 micros, else null.</summary>
    internal static long? ToMicros(double x)
    {
        if (double.IsNaN(x) || double.IsInfinity(x) || x < 0) return null;
        double scaled = x * 1_000_000;
        if (scaled > MaxSafeMicros) return null;
        double r = Math.Floor(scaled + 0.5); // JavaScript Math.round
        if (r / 1_000_000 != x && Math.Abs(scaled - r) > 1e-3) return null;
        return (long)r;
    }

    /// <summary>a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise.</summary>
    public static double ExactAdd(double a, double b, int sign)
    {
        var ma = ToMicros(a);
        var mb = ToMicros(b);
        if (ma == null || mb == null) return a + sign * b;
        return (double)(sign == 1 ? ma.Value + mb.Value : ma.Value - mb.Value) / 1_000_000;
    }

    /// <summary>Apply moves in order over a balance reader; throws <see cref="InvalidOperationException"/> (the reference's Error) on an invalid amount or an overdraft.</summary>
    public static Dictionary<string, double> ApplyBondMoves(Func<string, double> balanceOf, IEnumerable<object?> moves)
    {
        var output = new Dictionary<string, double>(StringComparer.Ordinal);
        double Bal(string a) => output.TryGetValue(a, out var v) ? v : balanceOf(a);
        foreach (var mo in moves)
        {
            var m = (D)mo!;
            var amount = IntentJs.NumOf(m.GetValueOrDefault("amount"));
            var op = m.GetValueOrDefault("op");
            if (amount == null || double.IsNaN(amount.Value) || double.IsInfinity(amount.Value) || amount.Value < 0) throw new InvalidOperationException($"{op}: invalid amount");
            var account = (string)m["account"]!;
            bool debit = op as string == "debit";
            if (!double.IsFinite(Bal(account))) throw new InvalidOperationException($"{op}: balance of {account} is not finite");
            if (debit && !(Bal(account) >= amount.Value)) throw new InvalidOperationException("debit: insufficient balance for " + account);
            output[account] = ExactAdd(Bal(account), amount.Value, debit ? -1 : 1);
        }
        return output;
    }

    /// <summary>Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored).</summary>
    public static bool SameSettlement(D a, D b) =>
        Equals(a.GetValueOrDefault("claimId"), b.GetValueOrDefault("claimId")) && Equals(a.GetValueOrDefault("action"), b.GetValueOrDefault("action"))
        && SameNum(a.GetValueOrDefault("amount"), b.GetValueOrDefault("amount")) && Equals(a.GetValueOrDefault("from"), b.GetValueOrDefault("from"))
        && Equals(a.GetValueOrDefault("to"), b.GetValueOrDefault("to")) && Equals(a.GetValueOrDefault("evidenceDigest"), b.GetValueOrDefault("evidenceDigest"))
        && JsCanon.Lenient(a.GetValueOrDefault("split")) == JsCanon.Lenient(b.GetValueOrDefault("split"));

    static bool SameNum(object? a, object? b)
    {
        var x = IntentJs.NumOf(a);
        var y = IntentJs.NumOf(b);
        return x == null || y == null ? a == null && b == null : x.Value == y.Value;
    }

    static bool SameWindow(D? a, D? b)
    {
        if (a == null || b == null) return a == null && b == null;
        return SameNum(a.GetValueOrDefault("windowMs"), b.GetValueOrDefault("windowMs")) && Equals(a.GetValueOrDefault("claimDigest"), b.GetValueOrDefault("claimDigest")); // registeredAt is the first call's
    }

    static string StatusOf(D? bond) => bond == null ? "none" : (string)bond["status"]!;

    static L Records(D bond) => (L)bond["records"]!;

    static double Cap(D open, string name) => IntentJs.NumOf(open.GetValueOrDefault(name)) ?? throw new ArgumentException($"commit: the open plan has no numeric {name}");

    /// <summary>Apply <paramref name="plan"/> to <paramref name="doc"/> following the <see cref="IBondStore.Commit"/> rules. Mutates <paramref name="doc"/> ONLY on <c>committed</c> (the moves are checked on an overlay first).</summary>
    public static BondCommitOutcome CommitBondPlan(BondDoc doc, D plan, double observedAt)
    {
        var claimId = (string)plan["claimId"]!;
        doc.Bonds.TryGetValue(claimId, out var bond);
        var open = plan.GetValueOrDefault("open") as D;
        var record = (plan.GetValueOrDefault("record") as D)!;
        if (plan.GetValueOrDefault("expect") as string == "none")
        {
            if (open == null || plan.GetValueOrDefault("next") as string != "open") return new BondCommitOutcome("conflict", null, "malformed open plan", StatusOf(bond));
            if (bond != null)
            {
                var recs = Records(bond);
                bool same = Equals(bond.GetValueOrDefault("depositor"), open.GetValueOrDefault("depositor")) && SameNum(bond.GetValueOrDefault("amount"), open.GetValueOrDefault("amount"))
                    && SameWindow(bond.GetValueOrDefault("window") as D, open.GetValueOrDefault("window") as D) && recs.Count > 0 && SameSettlement((D)recs[0]!, record);
                return same ? new BondCommitOutcome("replayed", (D)recs[0]!, null, null)
                    : new BondCommitOutcome("conflict", null, "bond " + claimId + " already exists", StatusOf(bond));
            }
            long count = 0;
            double sum = 0;
            foreach (var b in doc.Bonds.Values)
            {
                if (b.GetValueOrDefault("status") as string == "open" && Equals(b.GetValueOrDefault("depositor"), open.GetValueOrDefault("depositor")))
                {
                    count += 1;
                    sum += IntentJs.NumOf(b["amount"])!.Value;
                }
            }
            if (!(count + 1 <= Cap(open, "maxOpenClaims"))) return new BondCommitOutcome("conflict", null, "depositor open-claim cap reached", "none");
            if (!(double.IsFinite(sum + Cap(open, "amount")) && sum + Cap(open, "amount") <= Cap(open, "maxOpenAmount"))) return new BondCommitOutcome("conflict", null, "depositor aggregate open-bond cap exceeded", "none");
        }
        else if (bond == null)
        {
            return new BondCommitOutcome("conflict", null, "no bond for " + claimId, "none");
        }
        else if (!Equals(bond.GetValueOrDefault("status"), plan.GetValueOrDefault("expect")))
        {
            var recs = Records(bond);
            var last = recs.Count == 0 ? null : recs[^1] as D;
            return Equals(bond.GetValueOrDefault("status"), plan.GetValueOrDefault("next")) && last != null && SameSettlement(last, record)
                ? new BondCommitOutcome("replayed", last, null, null)
                : new BondCommitOutcome("conflict", null, "bond " + claimId + " is already " + bond.GetValueOrDefault("status"), StatusOf(bond));
        }
        Dictionary<string, double> next;
        try
        {
            var moves = plan.GetValueOrDefault("moves") as L ?? throw new ArgumentException("commit: moves must be an array");
            next = ApplyBondMoves(a => doc.Balances.TryGetValue(a, out var v) ? v : 0.0, moves);
        }
        catch (InvalidOperationException e)
        {
            return new BondCommitOutcome("conflict", null, e.Message, StatusOf(bond));
        }
        foreach (var e in next) doc.Balances[e.Key] = e.Value;
        if (open != null)
        {
            var row = new D { ["claimId"] = claimId, ["amount"] = open.GetValueOrDefault("amount"), ["depositor"] = open.GetValueOrDefault("depositor"), ["status"] = "open" };
            if (open.GetValueOrDefault("window") is D) row["window"] = StoreJs.DeepCopy(open["window"]);
            row["records"] = new L { StoreJs.DeepCopy(record) };
            doc.Bonds[claimId] = row;
        }
        else
        {
            bond!["status"] = plan.GetValueOrDefault("next");
            Records(bond).Add(StoreJs.DeepCopy(record));
        }
        double obs = double.IsNaN(observedAt) || double.IsInfinity(observedAt) ? 0 : observedAt;
        doc.HighWater = Math.Max(doc.HighWater, obs);
        return new BondCommitOutcome("committed", record, null, null);
    }

    /// <summary>The snapshot a scope reads from a document.</summary>
    public BondSnapshot Snapshot(string claimId, string? depositor)
    {
        Bonds.TryGetValue(claimId, out var bond);
        long count = 0;
        double sum = 0;
        var bal = new Dictionary<string, double>(StringComparer.Ordinal);
        if (depositor != null)
        {
            foreach (var b in Bonds.Values)
            {
                if (b.GetValueOrDefault("status") as string == "open" && depositor == b.GetValueOrDefault("depositor") as string)
                {
                    count += 1;
                    sum += IntentJs.NumOf(b["amount"])!.Value;
                }
            }
            bal[depositor] = Balances.TryGetValue(depositor, out var v) ? v : 0.0;
        }
        return new BondSnapshot(bond == null ? null : (D)StoreJs.DeepCopy(bond)!, bal, count, sum, HighWater);
    }

    /// <summary>The stored form <c>{v:1, balances:[[a,n]..], bonds:[..], highWater}</c>.</summary>
    public D Encode() => new()
    {
        ["v"] = IntentJs.OfLong(1),
        ["balances"] = Balances.Select(e => (object?)new L { e.Key, StoreJs.Number(e.Value) }).ToList(),
        ["bonds"] = Bonds.Values.Select(b => StoreJs.DeepCopy(b)).ToList(),
        ["highWater"] = StoreJs.Number(HighWater),
    };

    static BondStoreError Bad(string why) => new("store_corrupt", why);

    /// <summary>Decode a stored document (null = empty); fails closed with <c>store_corrupt</c>. The result shares nothing with <paramref name="raw"/>.</summary>
    public static BondDoc Decode(object? raw)
    {
        if (raw == null) return Empty();
        if (raw is not D m || !IntentJs.IsInt(m.GetValueOrDefault("v")) || IntentJs.Lng(m["v"]) != 1 || m.GetValueOrDefault("balances") is not L balances
            || m.GetValueOrDefault("bonds") is not L bonds || IntentJs.NumOf(m.GetValueOrDefault("highWater")) is not double hw)
            throw Bad("bond document has the wrong shape");
        var d = Empty();
        if (double.IsNaN(hw) || double.IsInfinity(hw) || hw < 0) throw Bad("highWater is not a non-negative number");
        d.HighWater = hw;
        foreach (var e in balances)
        {
            if (e is not L { Count: 2 } pair || pair[0] is not string account) throw Bad("malformed balance entry");
            var v = IntentJs.NumOf(pair[1]);
            if (v == null || double.IsNaN(v.Value) || double.IsInfinity(v.Value) || v.Value < 0) throw Bad("malformed balance entry");
            d.Balances[account] = v.Value;
        }
        foreach (var bo in bonds)
        {
            if (bo is not D b || b.GetValueOrDefault("claimId") is not string claimId || b.GetValueOrDefault("depositor") is not string
                || !IntentJs.IsFinite(b.GetValueOrDefault("amount")) || b.GetValueOrDefault("status") as string is not ("open" or "released" or "slashed")
                || b.GetValueOrDefault("records") is not L { Count: > 0 })
                throw Bad("malformed bond row");
            if (d.Bonds.ContainsKey(claimId)) throw Bad("duplicate bond row");
            d.Bonds[claimId] = (D)StoreJs.DeepCopy(b)!;
        }
        return d;
    }
}

/// <summary>The reference <see cref="IBondStore"/>: the whole book is one document in an <see cref="IAtomicKv"/>, so every transition is a single atomic read-modify-write.
/// Over <see cref="SqlAtomicKv"/> it is durable and multi-process safe; over <see cref="MemoryAtomicKv"/> it is the in-process variant (tests only). LIMIT: one document
/// rewritten on every commit; a production deployment implements <see cref="IBondStore"/> over a database transaction.</summary>
public sealed class KvBondStore : IBondStore
{
    public const string DocKey = "pca-bond-store/v1";
    readonly IAtomicKv _kv;
    readonly string _key;

    public KvBondStore(IAtomicKv kv, string key = DocKey)
    {
        _kv = kv ?? throw new BondStoreError("store_missing", "KvBondStore needs an IAtomicKv");
        _key = key;
    }

    static BondDoc Decode(string? text) => BondDoc.Decode(text == null ? null : Pca.ParseJson(text));

    public BondSnapshot Read(string claimId, string? depositor) => Decode(_kv.Get(_key)).Snapshot(claimId, depositor);

    public BondCommitOutcome Commit(D plan, double observedAt)
    {
        BondCommitOutcome? output = null;
        _kv.Update(_key, prev =>
        {
            var doc = Decode(prev);
            output = BondDoc.CommitBondPlan(doc, plan, observedAt);
            return output.Outcome == "committed" ? JsCanon.Lenient(doc.Encode()) : null; // null: leave the key untouched
        });
        return output!;
    }

    public double Deposit(string account, double amount)
    {
        if (string.IsNullOrEmpty(account)) throw new ArgumentException("deposit: account is required");
        if (double.IsNaN(amount) || double.IsInfinity(amount) || amount <= 0) throw new ArgumentException("deposit: amount must be a positive finite number");
        double balance = 0;
        _kv.Update(_key, prev =>
        {
            var doc = Decode(prev);
            var mv = new List<object?> { new D { ["account"] = account, ["op"] = "credit", ["amount"] = StoreJs.Number(amount) } };
            balance = BondDoc.ApplyBondMoves(a => doc.Balances.TryGetValue(a, out var v) ? v : 0.0, mv)[account];
            doc.Balances[account] = balance;
            return JsCanon.Lenient(doc.Encode());
        });
        return balance;
    }
}
