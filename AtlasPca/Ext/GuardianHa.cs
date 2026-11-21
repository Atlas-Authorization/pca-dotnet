// Guardian high-availability control logic: the pure decisions over the health of a guardian set (which guardians are live, whether a co-sign quorum is available, the
// degrade mode when it is lost, which guardians to ask, the failover order) and a durable, FENCED leader lease (at most one holder at a time, a strictly monotone fencing epoch
// a stale ex-leader cannot get around, store-side expiry, and "no leader" whenever the store errs). Process deployment and health probing stay the operator's job.
//
// What is guaranteed: lease safety holds IF the store's compare-and-swap is linearizable (run a conformance suite against your store) and the holder's clock error stays under
// the skew. Not guaranteed: availability, and protection of a downstream that never checks the fencing epoch (check it with a FenceGuard). Nothing here fails OPEN: losing the
// quorum or the lease restricts authority, never widens it.
//
// Values are JSON trees like the rest of the core (Dictionary<string, object?>, List<object?>, string, bool, Num). A guardian is {id, healthy, lastSeen, weight?}, a guardian set
// {guardians, quorum}, a lease record {holder, epoch, expiresAt}; a store reads and compare-and-swaps those records and reads its own clock (every expiry decision uses the
// store's clock, never the caller's). Lease results are {ok: true, lease} or {ok: false, reason, detail?}.
using System.Globalization;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The persistence contract of the leader lease. <see cref="Cas"/> replaces the record iff the stored one equals <c>expected</c> (null = none) in holder, epoch and expiry,
/// atomically and linearizably, and says whether it did; a next epoch below the stored one never replaces it. <see cref="Now"/> is the STORE's clock in epoch ms. Any member may throw:
/// the lease functions answer <c>store-error</c> and never grant.</summary>
public interface ILeaseStore
{
    /// <summary>The stored record, or null when there is none. Throws on a corrupt one.</summary>
    D? Read();
    bool Cas(object? expected, object? next);
    double Now();
}

/// <summary>A fenced operation lost the lease (<c>stale</c>, <c>expired</c>, <c>store-error</c>) or never had one (<c>no-lease</c>).</summary>
public sealed class FenceError : Exception
{
    public string Reason { get; }
    public FenceError(string reason) : base("fenced: " + reason) { Reason = reason; }
}

/// <summary>Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write).</summary>
public sealed class FenceGuard
{
    double hi;
    readonly object gate = new();

    /// <param name="initial">The highest epoch already seen; anything that is not a positive safe integer starts at 0.</param>
    public FenceGuard(object? initial = null) { hi = IntentJs.IsSafeInteger(initial) && IntentJs.NumOf(initial)!.Value > 0 ? IntentJs.NumOf(initial)!.Value : 0; }

    /// <summary>True (and the epoch becomes the highest) for a safe integer epoch of at least 1 that is not below the highest seen; false otherwise.</summary>
    public bool Admit(object? epoch)
    {
        lock (gate)
        {
            if (!IntentJs.IsSafeInteger(epoch) || IntentJs.NumOf(epoch)! < 1 || IntentJs.NumOf(epoch)! < hi) return false;
            hi = IntentJs.NumOf(epoch)!.Value;
            return true;
        }
    }

    public double Highest() { lock (gate) return hi; }
}

/// <summary>The reference lease store over an <see cref="IAtomicKv"/> (its <c>Update</c> is the compare-and-swap); with a durable key/value store it survives restarts.</summary>
public sealed class KvLeaseStore : ILeaseStore
{
    readonly IAtomicKv kv;
    readonly string key;
    readonly Func<double> clock;

    public KvLeaseStore(IAtomicKv kv, string? key = null, Func<double>? now = null)
    {
        this.kv = kv;
        this.key = key ?? "ha/lease";
        clock = now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public D? Read()
    {
        var raw = kv.Get(key);
        if (raw == null) return null;
        var v = Pca.ParseJson(raw);
        if (!GuardianHa.ValidRecord(v)) throw new InvalidOperationException("corrupt lease state");
        return (D)v!;
    }

    public bool Cas(object? expected, object? next)
    {
        if (!GuardianHa.ValidRecord(next)) throw new InvalidOperationException("invalid lease record");
        var nextD = (D)next!;
        var matched = false;
        kv.Update(key, prevText =>
        {
            matched = false;
            object? prev = prevText == null ? null : Pca.ParseJson(prevText);
            if (prevText != null && !GuardianHa.ValidRecord(prev)) return null;
            var prevD = prev as D;
            if (!GuardianHa.SameLease(prevD, expected) || IntentJs.NumOf(nextD["epoch"])! < (prevD == null ? 0 : IntentJs.NumOf(prevD["epoch"])!.Value)) return null;
            matched = true;
            return JsJson.Stringify(nextD);
        });
        return matched;
    }

    public double Now() => clock();
}

public static class GuardianHa
{
    /// <summary>The longest lease lifetime accepted, in ms (the agent-native module has a different limit of its own).</summary>
    public const double MaxLeaseTtlMs = 3_600_000;
    /// <summary>The default clock-error allowance, in ms.</summary>
    public const double DefaultLeaseSkewMs = 1_000;
    const int MaxHolderLen = 256;

    // ---- JavaScript value rules ----

    static bool IsFinite(object? x) => Jx.Fin(x) != null;
    static bool IsInteger(object? x) => Jx.Fin(x) is double d && d == Math.Floor(d);

    static bool Truthy(object? o) => o switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        double d => !(d == 0.0 || double.IsNaN(d)),
        long l => l != 0,
        int i => i != 0,
        Num n => IntentJs.NumOf(n) is double d && !(d == 0.0 || double.IsNaN(d)),
        _ => !Jx.IsUndef(o),
    };

    static object? Member(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : Jx.Undef;

    // `x ?? y`
    static object? Or(object? x, object? y) => x == null || Jx.IsUndef(x) ? y : x;

    // ---- liveness and quorum ----

    static bool IsObject(object? g) => g is D || g is L;

    /// <summary>The guardians that are flagged healthy AND have a fresh heartbeat at <paramref name="now"/> (<c>opts.staleMs</c>, default 30000), in the set's order. Fails closed: a
    /// malformed set, a non-finite clock or stale window, a non-finite or FUTURE-dated heartbeat, or a non-boolean <c>healthy</c> counts as down.</summary>
    public static L LiveGuardians(object? set, double now, object? opts = null)
    {
        var staleMs = Or(Member(opts, "staleMs"), 30_000L);
        var gs = Member(set, "guardians");
        if (!double.IsFinite(now) || !IsFinite(staleMs) || Jx.Fin(staleMs)! < 0 || gs is not L list || !list.All(g => g != null && IsObject(g))) return new L();
        var stale = Jx.Fin(staleMs)!.Value;
        return new L(list.Where(g => Member(g, "healthy") is true && Jx.Fin(Member(g, "lastSeen")) is double ls && ls <= now && now - ls <= stale));
    }

    static double WeightOf(object? g) => Jx.Fin(Member(g, "weight")) ?? 0;

    /// <summary><c>{total, live, quorum, available, degraded}</c>: <c>available</c> iff the quorum is an integer of at least 1 that the live count reaches, <c>degraded</c> iff some
    /// but fewer guardians are live. <c>quorum</c> is the set's own value (absent when the set has none).</summary>
    public static D QuorumStatus(object? set, double now, object? opts = null)
    {
        var live = LiveGuardians(set, now, opts).Count;
        var q = set == null || Jx.IsUndef(set) ? Jx.Undef : Member(set, "quorum");
        var o = new D { ["total"] = IntentJs.OfLong(Member(set, "guardians") is L g ? g.Count : 0), ["live"] = IntentJs.OfLong(live) };
        Jx.Set(o, "quorum", q);
        o["available"] = IsInteger(q) && Jx.Fin(q)! >= 1 && live >= Jx.Fin(q)!;
        // `live < set.quorum` compares as numbers (a text quorum is converted); only reached with live guardians, so a missing set never throws here
        o["degraded"] = live > 0 && live < Jx.ToNumber(Jx.Prop(set, "quorum"));
        return o;
    }

    /// <summary>The degradation mode of a quorum status: <c>normal</c> when the quorum is available, <c>read-only</c> when some guardians are live (unless
    /// <c>policy.allowReadOnly</c> is the boolean false), else <c>halt</c>. Never fails open.</summary>
    public static string DegradeMode(object? status, object? policy = null)
    {
        if (Truthy(Jx.Prop(status, "available"))) return "normal";
        if (Jx.ToNumber(Jx.Prop(status, "live")) > 0 && Member(policy, "allowReadOnly") is not false) return "read-only";
        return "halt";
    }

    // the order of preference: heavier first, then the fresher heartbeat, then the id in the platform's culture-invariant (ICU root) collation, as localeCompare does
    static int Preference(object? a, object? b)
    {
        var w = WeightOf(b) - WeightOf(a);
        if (w != 0) return w < 0 ? -1 : 1;
        var s = Jx.Fin(Member(b, "lastSeen"))!.Value - Jx.Fin(Member(a, "lastSeen"))!.Value;
        if (s != 0) return s < 0 ? -1 : 1;
        if (Member(a, "id") is not string x) throw JsX.TypeError("a.id.localeCompare is not a function");
        var y = Member(b, "id") is string ys ? ys : JsX.Str(Member(b, "id"));
        return Math.Sign(CultureInfo.InvariantCulture.CompareInfo.Compare(x, y, CompareOptions.None));
    }

    static List<object?> Ordered(L live) => live.OrderBy(g => g, Comparer<object?>.Create(Preference)).ToList();

    static object? IdOf(object? g) { var v = Member(g, "id"); return Jx.IsUndef(v) ? null : v; }

    /// <summary>The ids of the <c>quorum</c> freshest, highest-weight live guardians; empty when the quorum is not available (never attempt a co-sign below quorum).</summary>
    public static L SelectSigners(object? set, double now, object? opts = null)
    {
        var live = LiveGuardians(set, now, opts);
        var q = Jx.Prop(set, "quorum");
        if (!IsInteger(q) || Jx.Fin(q)! < 1 || live.Count < Jx.Fin(q)!) return new L();
        return new L(Ordered(live).Take((int)Jx.Fin(q)!.Value).Select(IdOf));
    }

    /// <summary><c>{primary, standbys}</c>: the preferred live guardian (null when none is live) and the others in preference order.</summary>
    public static D FailoverPlan(object? set, double now, object? opts = null)
    {
        var live = Ordered(LiveGuardians(set, now, opts));
        return new D { ["primary"] = live.Count > 0 ? IdOf(live[0]) : null, ["standbys"] = new L(live.Skip(1).Select(IdOf)) };
    }

    /// <summary>Why a guardian set is malformed (quorum out of range, an id that is not a non-empty string, duplicate ids), or null.</summary>
    public static string? ValidateGuardianSet(object? set)
    {
        if (set == null || Jx.IsUndef(set) || !IsObject(set)) return "guardian set is not an object";
        var gs = Member(set, "guardians");
        if (gs is not L list || list.Count == 0) return "guardian set is empty";
        var q = Member(set, "quorum");
        if (!IsInteger(q) || Jx.Fin(q)! < 1) return "quorum must be an integer ≥ 1";
        if (Jx.Fin(q)! > list.Count) return "quorum exceeds guardian count";
        if (!list.All(g => g is D && Member(g, "id") is string { Length: > 0 })) return "guardian id must be a non-empty string";
        if (list.Select(g => (string)Member(g, "id")!).Distinct(StringComparer.Ordinal).Count() != list.Count) return "duplicate guardian ids";
        return null;
    }

    // ---- the fenced leader lease ----

    /// <summary>Whether a value is a well-formed lease record: a holder text, an epoch that is a safe integer of at least 1, and a finite expiry of at least 0.</summary>
    public static bool ValidRecord(object? r) =>
        r is D m && Member(m, "holder") is string && IntentJs.IsSafeInteger(Member(m, "epoch")) && IntentJs.NumOf(m["epoch"])! >= 1
        && IsFinite(Member(m, "expiresAt")) && Jx.Fin(m["expiresAt"])! >= 0;

    internal static bool SameLease(object? a, object? b) =>
        a == null || b == null ? a == null && b == null
        : JsX.StrictEq(Member(a, "holder"), Member(b, "holder")) && JsX.StrictEq(Member(a, "epoch"), Member(b, "epoch")) && JsX.StrictEq(Member(a, "expiresAt"), Member(b, "expiresAt"));

    static D Ok(D lease) => new() { ["ok"] = true, ["lease"] = lease };
    static D Fail(string reason, string? detail = null)
    {
        var o = new D { ["ok"] = false, ["reason"] = reason };
        if (detail != null) o["detail"] = detail;
        return o;
    }

    // the lifetime and skew of a lease request, or null when they (or the holder) are not acceptable
    static (double Ttl, double Skew)? LeaseOpts(object? holder, object? o)
    {
        if (holder is not string { Length: > 0 and <= MaxHolderLen }) return null;
        var skew = Or(Member(o, "skewMs"), DefaultLeaseSkewMs);
        var ttl = Member(o, "ttlMs");
        if (!IsInteger(ttl) || Jx.Fin(ttl)! < 2 || Jx.Fin(ttl)! > MaxLeaseTtlMs) return null;
        if (!IsFinite(skew) || Jx.Fin(skew)! < 0 || Jx.Fin(skew)! >= Jx.Fin(ttl)!) return null;
        return (Jx.Fin(ttl)!.Value, Jx.Fin(skew)!.Value);
    }

    // the record and the store clock; a corrupt record or clock is a store error (never "free")
    static (D? Cur, double Now) Snapshot(ILeaseStore store)
    {
        var cur = store.Read();
        var now = store.Now();
        if (!double.IsFinite(now) || (cur != null && !ValidRecord(cur))) throw new InvalidOperationException("corrupt lease state");
        return (cur, now);
    }

    static double Num(D r, string k) => Jx.Fin(r[k])!.Value;

    static D Record(string holder, object epoch, double expiresAt) => new() { ["holder"] = holder, ["epoch"] = epoch, ["expiresAt"] = Jx.N(expiresAt) };

    /// <summary>Take the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover. <paramref name="opts"/> is
    /// <c>{ttlMs, skewMs?}</c>: <c>ttlMs</c> an integer in [2, <see cref="MaxLeaseTtlMs"/>], <c>skewMs</c> (default 1000) a finite number in [0, ttlMs): a holder stops acting
    /// <c>skewMs</c> before expiry, a challenger waits <c>skewMs</c> after it. Reasons: invalid, held, lost-race, store-error.</summary>
    public static D AcquireLease(ILeaseStore store, object? holder, object? opts)
    {
        var p = LeaseOpts(holder, opts);
        if (p == null) return Fail("invalid");
        try
        {
            var (cur, now) = Snapshot(store);
            if (cur != null && Num(cur, "expiresAt") + p.Value.Skew > now && Num(cur, "expiresAt") != 0) return Fail("held");
            var next = Record((string)holder!, IntentJs.OfLong((cur == null ? 0 : (long)Num(cur, "epoch")) + 1), now + p.Value.Ttl);
            return store.Cas(cur, next) ? Ok(next) : Fail("lost-race");
        }
        catch (Exception e) { return Fail("store-error", e.Message); }
    }

    /// <summary>Extend a lease the caller still holds. Refused once the holder's own safe window (expiry minus skew) has passed (<c>expired</c>) or after any takeover (<c>stale</c>).</summary>
    public static D RenewLease(ILeaseStore store, object? lease, object? opts)
    {
        var p = ValidRecord(lease) ? LeaseOpts(Member(lease, "holder"), opts) : null;
        if (p == null) return Fail("invalid");
        var l = (D)lease!;
        try
        {
            var (cur, now) = Snapshot(store);
            if (cur == null || !JsX.StrictEq(cur["holder"], l["holder"]) || !JsX.StrictEq(cur["epoch"], l["epoch"])) return Fail("stale");
            if (Num(cur, "expiresAt") - p.Value.Skew <= now) return Fail("expired");
            var next = Record((string)cur["holder"]!, cur["epoch"]!, now + p.Value.Ttl);
            return store.Cas(cur, next) ? Ok(next) : Fail("lost-race");
        }
        catch (Exception e) { return Fail("store-error", e.Message); }
    }

    /// <summary>Give the lease up early (expiry 0, epoch kept). Only the current holder at the current epoch can; a lease already released is <c>stale</c>.</summary>
    public static D ReleaseLease(ILeaseStore store, object? lease)
    {
        if (!ValidRecord(lease)) return Fail("invalid");
        var l = (D)lease!;
        try
        {
            var (cur, _) = Snapshot(store);
            if (cur == null || !JsX.StrictEq(cur["holder"], l["holder"]) || !JsX.StrictEq(cur["epoch"], l["epoch"]) || Num(cur, "expiresAt") == 0) return Fail("stale");
            var next = Record((string)cur["holder"]!, cur["epoch"]!, 0);
            return store.Cas(cur, next) ? Ok(next) : Fail("lost-race");
        }
        catch (Exception e) { return Fail("store-error", e.Message); }
    }

    /// <summary>Is this exact (holder, epoch) still the leader, with its safe window open, per the store? <c>{ok: true}</c>, or <c>{ok: false, reason: stale | expired | store-error}</c>: any
    /// error answers no. <paramref name="skewMs"/> must be a finite number of at least 0 (a different value is <c>stale</c>).</summary>
    public static D AssertFence(ILeaseStore store, object? token, object? skewMs)
    {
        try
        {
            if (!Truthy(token) || !IsFinite(skewMs) || Jx.Fin(skewMs)! < 0) return Fail("stale");
            var (cur, now) = Snapshot(store);
            if (cur == null || !JsX.StrictEq(cur["holder"], Member(token, "holder")) || !JsX.StrictEq(cur["epoch"], Member(token, "epoch"))) return Fail("stale");
            return Num(cur, "expiresAt") - Jx.Fin(skewMs)!.Value > now ? new D { ["ok"] = true } : Fail("expired");
        }
        catch (Exception) { return Fail("store-error"); }
    }

    /// <summary><see cref="AssertFence(ILeaseStore, object?, object?)"/> with the default skew.</summary>
    public static D AssertFence(ILeaseStore store, object? token) => AssertFence(store, token, DefaultLeaseSkewMs);

    /// <summary>Run <paramref name="sign"/> only while the caller is the fenced leader: the fence is checked before AND after the signature, and a leader that lost the lease in the middle
    /// gets a <see cref="FenceError"/> and the signature is discarded. Returns the signature and the epoch it was made under. Check-then-sign is inherently racy: the downstream must also
    /// <see cref="FenceGuard.Admit"/> the epoch.</summary>
    public static (T Result, object? Epoch) FencedSign<T>(ILeaseStore store, Func<D?> getLease, Func<T> sign, object? skewMs)
    {
        var lease = getLease();
        if (lease == null) throw new FenceError("no-lease");
        var pre = AssertFence(store, lease, skewMs);
        if (pre["ok"] is not true) throw new FenceError((string)pre["reason"]!);
        var result = sign();
        var post = AssertFence(store, lease, skewMs);
        if (post["ok"] is not true) throw new FenceError((string)post["reason"]!);
        return (result, Jx.IsUndef(Member(lease, "epoch")) ? null : lease["epoch"]);
    }

    public static (T Result, object? Epoch) FencedSign<T>(ILeaseStore store, Func<D?> getLease, Func<T> sign) => FencedSign(store, getLease, sign, DefaultLeaseSkewMs);
}
