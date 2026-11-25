// The durable cumulative budget of a payment mandate with an atomic compare-and-set (the reference authorizeChargeAtomic / applyHumanCosignAtomic and
// memoryChargeBudgetStore). The debit of an `auto` charge is committed with a compare-and-set before it is returned, so two concurrent charges cannot both spend
// the same budget; losing the race re-reads and re-decides. A missing or malformed store throws; persistent contention denies a charge and throws for a co-sign
// (a co-sign is never silently dropped).
using AtlasPca.Authzen;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

/// <summary>A durable budget record: the budget <c>{B, tau, asOf}</c> and an opaque <c>Version</c> (a safe integer).</summary>
public sealed record ChargeBudgetRecord(JD Budget, long Version);

/// <summary>Durable cumulative-budget state with an atomic compare-and-set. <c>CompareAndSetAsync</c> succeeds only when the stored version still equals
/// <c>expected</c> (null = no record yet) and returns false otherwise. Back it with ONE conditional write (SQL <c>UPDATE .. WHERE version = $n</c>, Redis CAS,
/// a DynamoDB condition).</summary>
public interface IChargeBudgetStore
{
    Task<ChargeBudgetRecord?> GetAsync(string key);
    Task<bool> CompareAndSetAsync(string key, long? expected, JD budget);
}

/// <summary>The store is missing, returned a malformed record, or kept changing.</summary>
public sealed class ChargeStoreException(string message) : Exception(message);

/// <summary>A single-process reference store for tests; production needs a durable store with a conditional write.</summary>
public sealed class MemoryChargeBudgetStore : IChargeBudgetStore
{
    readonly Dictionary<string, ChargeBudgetRecord> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();
    public Task<ChargeBudgetRecord?> GetAsync(string key) { lock (_lock) return Task.FromResult(_m.GetValueOrDefault(key)); }

    public Task<bool> CompareAndSetAsync(string key, long? expected, JD budget)
    {
        lock (_lock)
        {
            if ((_m.TryGetValue(key, out var cur) ? cur.Version : (long?)null) != expected) return Task.FromResult(false);
            _m[key] = new ChargeBudgetRecord(budget, (expected ?? 0) + 1);
            return Task.FromResult(true);
        }
    }
}

public static partial class Payments
{
    const int MaxCasAttempts = 8;

    

    static void CheckRecord(ChargeBudgetRecord? r)
    {
        if (r == null) return;
        if (r.Version < 0 || r.Version > Pca.MaxSafeInt || r.Budget == null || !Finite(r.Budget.GetValueOrDefault("B")) || !Finite(r.Budget.GetValueOrDefault("tau")) || !Finite(r.Budget.GetValueOrDefault("asOf")))
            throw new ChargeStoreException("the store returned a malformed budget record");
    }

    static JD WithBudget(JD mandate, ChargeBudgetRecord? rec)
    {
        if (rec == null) return mandate;
        var o = new JD(mandate) { ["budget"] = rec.Budget };
        return o;
    }

    /// <summary>Run a charge through the PCA policy decision of the core engine against the grant you VERIFIED (the reference <c>authorizeCharge</c>; the four-argument
    /// form takes another decider).</summary>
    public static JD AuthorizeCharge(object? mandate, object? charge, object? verifiedGrant) => AuthorizeCharge(mandate, charge, verifiedGrant, PolicyVmDecide.Decide);

    /// <summary><see cref="AuthorizeCharge"/> against the DURABLE cumulative budget in <paramref name="store"/> (the mandate's own <c>budget</c> is only the initial
    /// value), with the PCA policy decision. <paramref name="key"/> defaults to the canonical hash of the verified grant.</summary>
    public static async Task<JD> AuthorizeChargeAtomicAsync(JD mandate, JD charge, JD verifiedGrant, IChargeBudgetStore store, string? key = null, DecideFn? decide = null)
    {
        if (store == null) throw new ChargeStoreException("a ChargeBudgetStore with get and compareAndSet is required");
        decide ??= PolicyVmDecide.Decide;
        key ??= Pca.HashCanonical(verifiedGrant);
        for (var i = 0; i < MaxCasAttempts; i++)
        {
            var rec = await store.GetAsync(key).ConfigureAwait(false);
            CheckRecord(rec);
            var d = AuthorizeCharge(WithBudget(mandate, rec), charge, verifiedGrant, decide);
            if (Prop(d, "outcome") as string != "auto") return d;
            if (await store.CompareAndSetAsync(key, rec?.Version, (JD)Prop(d, "budgetAfter")!).ConfigureAwait(false)) return d;
        }
        var last = AuthorizeCharge(mandate, charge, verifiedGrant, decide);
        var reasons = new JL { "budget_store_conflict" };
        if (Prop(last, "reasons") is JL rr) reasons.AddRange(rr);
        return new JD(last) { ["outcome"] = "deny", ["t"] = new Num("3"), ["cost"] = new Num("0"), ["budgetAfter"] = Prop(last, "budgetBefore"), ["reasons"] = reasons };
    }

    /// <summary><see cref="ApplyHumanCosign"/> against the DURABLE budget in <paramref name="store"/>: the restored budget is committed with a compare-and-set, so a
    /// co-sign racing a charge cannot be lost or applied twice. Call it only after you have verified the human co-sign.</summary>
    public static async Task<JD> ApplyHumanCosignAtomicAsync(JD mandate, JD verifiedGrant, IChargeBudgetStore store, long now, bool full = false, string? key = null)
    {
        if (store == null) throw new ChargeStoreException("a ChargeBudgetStore with get and compareAndSet is required");
        key ??= Pca.HashCanonical(verifiedGrant);
        for (var i = 0; i < MaxCasAttempts; i++)
        {
            var rec = await store.GetAsync(key).ConfigureAwait(false);
            CheckRecord(rec);
            var bound = Bind(WithBudget(mandate, rec), verifiedGrant);
            var next = (JD)ApplyHumanCosign(bound, new Num(now.ToString()), null, full)["budget"]!;
            if (await store.CompareAndSetAsync(key, rec?.Version, next).ConfigureAwait(false)) return next;
        }
        throw new ChargeStoreException("could not commit the co-sign: the budget record kept changing");
    }
}
