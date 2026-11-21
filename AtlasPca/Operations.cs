// Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
//
// Authorize decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect the process can
// crash, the client can time out and retry, or two workers can pick up the same authorization. A record per operation id
// (AuthorizedOperation.Id, the digest of the presented PCActn) closes that gap:
//
//  1. ExecuteAuthorized creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N concurrent
//     executions of one authorization exactly one gets to run fn);
//  2. for an irreversible operation it re-checks revocation, expiry and approval immediately before fn (a recheck is required, fail
//     closed); a failed re-check records `aborted` and fn never runs;
//  3. it moves the record to `executing` and only then calls fn, with the operation id as the idempotency key;
//  4. the record becomes `committed` (with fn's result) or `failed` (with its error) afterwards.
//
// A second execution of the same id never runs fn again: it answers from the record. Once the pending timeout has passed, a record
// still `pending` is settled `aborted` (the side effect never started) and one still `executing` `uncertain` (it may or may not have
// happened: reconcile it with ResolveOperation using the idempotency key). Mirrors the reference operation-record module; the shared
// operation-vectors.json corpus pins the state machine and every message.
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Where an operation is in its execution.</summary>
public static class OperationStates
{
    /// <summary>Claimed for execution, fn not started yet (re-check running), or the process crashed before starting it.</summary>
    public const string Pending = "pending";
    /// <summary>fn has been started: the side effect is running, or the process crashed during or after it.</summary>
    public const string Executing = "executing";
    /// <summary>The side effect completed; <see cref="OperationRecord.Result"/> is what fn returned.</summary>
    public const string Committed = "committed";
    /// <summary>fn threw; not re-run (the downstream may have applied part of it: use the idempotency key).</summary>
    public const string Failed = "failed";
    /// <summary>The pre-execution re-check refused (revoked, expired, approval withdrawn); fn never ran.</summary>
    public const string Aborted = "aborted";
    /// <summary>Found executing after the pending timeout: the outcome is unknown and must be reconciled, never silently re-run.</summary>
    public const string Uncertain = "uncertain";
}

/// <summary>The durable record of one operation. Times are epoch milliseconds.</summary>
public sealed record OperationRecord(string Id, string State, string Verb, string Resource, string ParamsDigest, string Reversibility, long StartedAt)
{
    public long? ExecutingAt { get; init; }
    public long? FinishedAt { get; init; }
    /// <summary>What fn returned when committed (keep it JSON-serialisable for a durable store).</summary>
    public object? Result { get; init; }
    /// <summary>Why a record is failed, aborted or uncertain.</summary>
    public string? Error { get; init; }

    /// <summary>The wire shape (the reference's record): optional members are omitted when unset; <c>result</c> is always present on a committed record.</summary>
    public Dictionary<string, object?> ToJson()
    {
        var o = new D
        {
            ["id"] = Id, ["state"] = State, ["verb"] = Verb, ["resource"] = Resource, ["params_digest"] = ParamsDigest,
            ["reversibility"] = Reversibility, ["startedAt"] = IntentJs.OfLong(StartedAt),
        };
        if (ExecutingAt is long e) o["executingAt"] = IntentJs.OfLong(e);
        if (FinishedAt is long f) o["finishedAt"] = IntentJs.OfLong(f);
        if (Result != null || State == OperationStates.Committed) o["result"] = Result;
        if (Error != null) o["error"] = Error;
        return o;
    }

    /// <summary>Reads a record from parsed JSON; null when it is not one (no string id or state).</summary>
    public static OperationRecord? FromJson(object? v)
    {
        if (v is not D m || m.GetValueOrDefault("id") is not string id || m.GetValueOrDefault("state") is not string st) return null;
        static long L(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) ? (long)d : 0;
        static long? OptL(D obj, string k) => obj.TryGetValue(k, out var x) && IntentJs.NumOf(x) is double d && double.IsFinite(d) ? (long)d : null;
        return new OperationRecord(id, st, m.GetValueOrDefault("verb") as string ?? "", m.GetValueOrDefault("resource") as string ?? "",
            m.GetValueOrDefault("params_digest") as string ?? "", m.GetValueOrDefault("reversibility") as string ?? "irreversible", L(m.GetValueOrDefault("startedAt")))
        {
            ExecutingAt = OptL(m, "executingAt"), FinishedAt = OptL(m, "finishedAt"), Result = m.GetValueOrDefault("result"), Error = m.GetValueOrDefault("error") as string,
        };
    }
}

/// <summary>Durable, shared storage of operation records. <see cref="Create"/> and <see cref="Transition"/> MUST be atomic across every
/// process and node that shares the store (a unique-key insert and a conditional UPDATE ... WHERE state = from, a Redis script, an
/// <see cref="IAtomicKv"/>). A call that cannot decide MUST throw: the executor then refuses or reports the outcome as unknown.</summary>
public interface IOperationStore
{
    /// <summary>Atomically inserts <paramref name="record"/> if no record with its id exists (Created true); otherwise returns the existing record unchanged.</summary>
    (bool Created, OperationRecord? Existing) Create(OperationRecord record);
    OperationRecord? Get(string id);
    /// <summary>Atomically replaces the record with <paramref name="next"/> only if its current state is <paramref name="from"/>. Returns whether it did.</summary>
    bool Transition(string id, string from, OperationRecord next);
}

/// <summary>The optional <see cref="IOperationStore"/> capability <see cref="Pca.RecoverOperations"/> needs: the records still pending or executing.</summary>
public interface IOpenOperationLister
{
    IReadOnlyList<OperationRecord> ListOpen();
}

/// <summary>The in-process <see cref="IOperationStore"/> (tests, one worker). Its records die with the process.</summary>
public sealed class MemoryOperationStore : IOperationStore, IOpenOperationLister
{
    readonly Dictionary<string, OperationRecord> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();

    public (bool Created, OperationRecord? Existing) Create(OperationRecord record)
    {
        lock (_lock)
        {
            if (_m.TryGetValue(record.Id, out var cur)) return (false, cur);
            _m[record.Id] = record;
            return (true, null);
        }
    }

    public OperationRecord? Get(string id)
    {
        lock (_lock) return _m.GetValueOrDefault(id);
    }

    public bool Transition(string id, string from, OperationRecord next)
    {
        lock (_lock)
        {
            if (!_m.TryGetValue(id, out var cur) || cur.State != from) return false;
            _m[id] = next with { Id = id };
            return true;
        }
    }

    /// <summary>Ordered by id.</summary>
    public IReadOnlyList<OperationRecord> ListOpen()
    {
        lock (_lock)
            return _m.Values.Where(r => r.State is OperationStates.Pending or OperationStates.Executing).OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
    }
}

/// <summary>An <see cref="IOperationStore"/> over any <see cref="IAtomicKv"/> (use <see cref="SqlAtomicKv"/> for a database). It has no
/// ListOpen: recover a known id with <see cref="Pca.RecoverOperation"/>.</summary>
public sealed class KvOperationStore : IOperationStore
{
    public const string DefaultPrefix = "pca-op:";
    readonly IAtomicKv _kv;
    readonly string _prefix;

    public KvOperationStore(IAtomicKv kv, string? prefix = null)
    {
        _kv = kv ?? throw new ArgumentNullException(nameof(kv));
        _prefix = string.IsNullOrEmpty(prefix) ? DefaultPrefix : prefix;
    }

    static OperationRecord? Decode(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        try { return OperationRecord.FromJson(Pca.ParseJson(text)); }
        catch (Exception) { return null; }
    }

    public (bool Created, OperationRecord? Existing) Create(OperationRecord record)
    {
        var enc = Pca.Canonicalize(record.ToJson());
        OperationRecord? existing = null;
        _kv.Update(_prefix + record.Id, prev =>
        {
            existing = Decode(prev);
            return existing != null ? null : enc;
        });
        return (existing == null, existing);
    }

    public OperationRecord? Get(string id) => Decode(_kv.Get(_prefix + id));

    public bool Transition(string id, string from, OperationRecord next)
    {
        var enc = Pca.Canonicalize((next with { Id = id }).ToJson());
        bool done = false;
        _kv.Update(_prefix + id, prev =>
        {
            var cur = Decode(prev);
            done = cur != null && cur.State == from;
            return done ? enc : null;
        });
        return done;
    }
}

/// <summary>What a pre-execution re-check answered.</summary>
public sealed record RecheckResult(bool Ok, string? Reason = null)
{
    public static RecheckResult Pass { get; } = new(true);
}

/// <summary>What the executed function receives. <see cref="IdempotencyKey"/> is the operation id: pass it as the idempotency key of the downstream call.</summary>
public sealed record ExecutionHandle(string IdempotencyKey, AuthorizedOperation Operation, Dictionary<string, object?> Pcactn)
{
    /// <summary>The allowing authorization this execution rests on (its checks, verdict and assurance report).</summary>
    public AuthorizeResult? Authorization { get; init; }
}

/// <summary>Options of <see cref="Pca.ExecuteAuthorized"/>.</summary>
public sealed class ExecuteOptions
{
    /// <summary>REQUIRED (shared and durable in production).</summary>
    public IOperationStore? Store { get; set; }
    /// <summary>When set, the operation about to execute: the authorization must be for exactly it.</summary>
    public Operation? Operation { get; set; }
    /// <summary>Re-checks, immediately before fn, that the authorization still stands (grant not revoked, approval not expired or withdrawn).
    /// REQUIRED for an irreversible operation (fail closed), and for the others with <see cref="RecheckFor"/> "always". The PCActn's own
    /// expiry (<c>exp</c>) is always checked with it. A throw is a refusal.</summary>
    public Func<ExecutionHandle, RecheckResult>? Recheck { get; set; }
    /// <summary>Asynchronous <see cref="Recheck"/> (wins when both are set).</summary>
    public Func<ExecutionHandle, Task<RecheckResult>>? RecheckAsync { get; set; }
    /// <summary>"irreversible" (default) or "always".</summary>
    public string? RecheckFor { get; set; }
    /// <summary>The server's authoritative class; the stricter of it and the signed class applies (missing or unknown = irreversible).</summary>
    public string? ReversibilityClass { get; set; }
    /// <summary>An open record older than this (ms) is settled; null: five minutes.</summary>
    public long? PendingTimeoutMs { get; set; }
    /// <summary>The clock in epoch ms (null: the wall clock).</summary>
    public Func<long>? Now { get; set; }
}

/// <summary>The outcome of an execution attempt. <see cref="Replayed"/> means it was answered from an existing record.
/// <see cref="Status"/>: <c>committed</c> (<see cref="Result"/>; <see cref="Recorded"/> false: fn ran but the record could not be written, it stays executing and becomes uncertain),
/// <c>failed</c> (<see cref="Error"/>), <c>aborted</c> (<see cref="Reason"/>), <c>pending</c> (another execution of this id is in flight; fn did not run here),
/// <c>uncertain</c> (<see cref="Reason"/>: the earlier outcome is unknown; fn did not run here), <c>refused</c> (<see cref="Reason"/>: nothing ran and nothing was recorded)
/// or, from <see cref="PcaExecutor"/>, <c>denied</c> (<see cref="Authorization"/>: the authorization was refused, nothing ran).</summary>
public sealed class ExecuteOutcome
{
    public string Status { get; init; } = "refused";
    public string? OperationId { get; init; }
    public object? Result { get; init; }
    public string? Error { get; init; }
    public string? Reason { get; init; }
    public bool Replayed { get; init; }
    public bool Recorded { get; init; }
    /// <summary>The denial of a <c>denied</c> outcome.</summary>
    public AuthorizeResult? Authorization { get; init; }

    internal static ExecuteOutcome Refused(string reason) => new() { Status = "refused", Reason = reason };

    /// <summary>The reference's JSON shape of the outcome.</summary>
    public Dictionary<string, object?> ToJson()
    {
        var o = new D { ["status"] = Status };
        switch (Status)
        {
            case "committed": o["operationId"] = OperationId; o["result"] = Result; o["replayed"] = Replayed; o["recorded"] = Recorded; break;
            case "failed": o["operationId"] = OperationId; o["error"] = Error; o["replayed"] = Replayed; break;
            case "aborted": o["operationId"] = OperationId; o["reason"] = Reason; o["replayed"] = Replayed; break;
            case "pending": o["operationId"] = OperationId; o["replayed"] = true; break;
            case "uncertain": o["operationId"] = OperationId; o["reason"] = Reason; o["replayed"] = true; break;
            default: o["reason"] = Reason; break;
        }
        return o;
    }
}

public static partial class Pca
{
    /// <summary>The default age after which an open operation record is settled.</summary>
    public const long OperationPendingTimeoutMs = 5 * 60_000;

    sealed class OperationStoreFailure : Exception
    {
        public OperationStoreFailure(string message) : base(message) { }
    }

    static T StoreCall<T>(Func<T> f)
    {
        try { return f(); }
        catch (Exception e) { throw new OperationStoreFailure(e.Message); }
    }

    static ExecuteOutcome StoreFailed(Exception e) =>
        ExecuteOutcome.Refused("executeAuthorized: the operation store failed (fail closed): " + e.Message);

    static string JsNum(double d) => JsCanon.NumberString(d);

    /// <summary>Settles an open record older than the timeout: pending to aborted, executing to uncertain. Returns the record as stored now.</summary>
    static OperationRecord SettleStale(IOperationStore store, OperationRecord rec, long now, long timeoutMs)
    {
        if (rec.State != OperationStates.Pending && rec.State != OperationStates.Executing) return rec;
        // executing is aged from the moment fn was started (a slow re-check does not count against it)
        long start = rec.State == OperationStates.Executing ? rec.ExecutingAt ?? rec.StartedAt : rec.StartedAt;
        if (!(now - start > timeoutMs)) return rec;
        var next = rec.State == OperationStates.Pending
            ? rec with { State = OperationStates.Aborted, Error = $"not started within {timeoutMs} ms of the claim: the side effect never ran", FinishedAt = now }
            : rec with { State = OperationStates.Uncertain, Error = $"no outcome recorded within {timeoutMs} ms of the start: the side effect may or may not have happened", FinishedAt = now };
        StoreCall(() => store.Transition(rec.Id, rec.State, next));
        // whatever is stored now (the original execution may have finished in between)
        return StoreCall(() => store.Get(rec.Id)) ?? next;
    }

    /// <summary>Answers an execution attempt from an existing record (never runs anything).</summary>
    static ExecuteOutcome FromRecord(IOperationStore store, OperationRecord rec0, long now, long timeoutMs)
    {
        var rec = SettleStale(store, rec0, now, timeoutMs);
        var id = rec.Id;
        switch (rec.State)
        {
            case OperationStates.Committed: return new ExecuteOutcome { Status = "committed", OperationId = id, Result = rec.Result, Replayed = true, Recorded = true };
            case OperationStates.Failed: return new ExecuteOutcome { Status = "failed", OperationId = id, Error = rec.Error ?? "failed", Replayed = true };
            case OperationStates.Aborted: return new ExecuteOutcome { Status = "aborted", OperationId = id, Reason = rec.Error ?? "aborted", Replayed = true };
            case OperationStates.Uncertain: return new ExecuteOutcome { Status = "uncertain", OperationId = id, Reason = rec.Error ?? "outcome unknown", Replayed = true };
            case OperationStates.Pending:
            case OperationStates.Executing: return new ExecuteOutcome { Status = "pending", OperationId = id, Replayed = true };
            default: return new ExecuteOutcome { Status = "uncertain", OperationId = id, Reason = $"unknown record state '{rec.State}'", Replayed = true };
        }
    }

    internal static ExecuteOutcome AnswerFromRecord(IOperationStore store, OperationRecord rec, long now, long timeoutMs)
    {
        try { return FromRecord(store, rec, now, timeoutMs); }
        catch (OperationStoreFailure e) { return StoreFailed(e); }
    }

    /// <summary>Leaves executing (or uncertain, when recovery settled a slow execution) for the final state.</summary>
    static bool FinishRecord(IOperationStore store, OperationRecord rec, OperationRecord next)
    {
        if (StoreCall(() => store.Transition(rec.Id, rec.State, next))) return true;
        return rec.State == OperationStates.Executing && StoreCall(() => store.Transition(rec.Id, OperationStates.Uncertain, next));
    }

    /// <summary>Answers from the record as it is stored now (a concurrent recovery or execution changed it).</summary>
    static ExecuteOutcome AnswerCurrent(IOperationStore store, string id, long now, long timeoutMs)
    {
        var cur = StoreCall(() => store.Get(id));
        return cur == null
            ? new ExecuteOutcome { Status = "uncertain", OperationId = id, Reason = "the operation record disappeared", Replayed = true }
            : FromRecord(store, cur, now, timeoutMs);
    }

    /// <summary>Executes an allowed <see cref="Authorize"/> result at most once, with a durable record (see the file comment). fn runs only if
    /// this call created the pending record and the re-check (when required) passed; every other outcome is answered from the record. A
    /// throw from fn is recorded as failed and returned in the outcome, not re-thrown. Never throws.</summary>
    public static ExecuteOutcome ExecuteAuthorized(AuthorizeResult authorization, Func<ExecutionHandle, object?> fn, ExecuteOptions options) =>
        ExecuteAuthorizedAsync(authorization, h => Task.FromResult(fn(h)), options).GetAwaiter().GetResult();

    /// <summary><see cref="ExecuteAuthorized"/> with an asynchronous fn.</summary>
    public static async Task<ExecuteOutcome> ExecuteAuthorizedAsync(AuthorizeResult authorization, Func<ExecutionHandle, Task<object?>> fn, ExecuteOptions options)
    {
        try { return await ExecuteCore(authorization, fn, options).ConfigureAwait(false); }
        catch (OperationStoreFailure e) { return StoreFailed(e); }
        catch (Exception e) { return ExecuteOutcome.Refused("executeAuthorized: error (fail closed): " + e.Message); }
    }

    static async Task<ExecuteOutcome> ExecuteCore(AuthorizeResult? az, Func<ExecutionHandle, Task<object?>> fn, ExecuteOptions? opts)
    {
        var store = opts?.Store;
        if (store is null) return ExecuteOutcome.Refused("executeAuthorized: missing required component: store (fail closed)");
        if (az is not { Allow: true, Operation: { Id.Length: > 0 } operation, Pcactn: { } pcactn })
            return ExecuteOutcome.Refused("executeAuthorized: the authorization did not allow an operation");
        if (opts!.Operation is not null && !IsAuthorizedFor(az, opts.Operation))
            return ExecuteOutcome.Refused("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)");
        var clock = opts.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        long timeoutMs = opts.PendingTimeoutMs ?? OperationPendingTimeoutMs;
        var signed = IntentJs.Get(IntentJs.Get(pcactn, "action"), "reversibility_class");
        var reversibility = RevocationFreshness.EffectiveReversibility(opts.ReversibilityClass, signed);
        bool hasRecheck = opts.RecheckAsync is not null || opts.Recheck is not null;
        bool mustRecheck = reversibility == "irreversible" || opts.RecheckFor == "always";
        if (mustRecheck && !hasRecheck)
            return ExecuteOutcome.Refused($"executeAuthorized: a {reversibility} operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)");

        var handle = new ExecutionHandle(operation.Id, operation, pcactn) { Authorization = az };
        var rec = new OperationRecord(operation.Id, OperationStates.Pending, operation.Verb, operation.Resource, operation.ParamsDigest, reversibility, clock());
        var (created, existing) = StoreCall(() => store.Create(rec));
        if (!created) return FromRecord(store, existing!, clock(), timeoutMs);

        if (mustRecheck)
        {
            RecheckResult? rc;
            try
            {
                var t = clock();
                if (IntentJs.NumOf(IntentJs.Get(pcactn, "exp")) is double exp && t > exp)
                    rc = new RecheckResult(false, "the PCActn expired at " + JsNum(exp));
                else rc = opts.RecheckAsync is not null ? await opts.RecheckAsync(handle).ConfigureAwait(false) : opts.Recheck!(handle);
            }
            catch (Exception e) { rc = new RecheckResult(false, "recheck error (fail closed): " + e.Message); }
            if (rc is not { Ok: true })
            {
                var reason = "recheck: " + (string.IsNullOrEmpty(rc?.Reason) ? "refused" : rc!.Reason);
                var aborted = rec with { State = OperationStates.Aborted, Error = reason, FinishedAt = clock() };
                if (FinishRecord(store, rec, aborted)) return new ExecuteOutcome { Status = "aborted", OperationId = rec.Id, Reason = reason };
                return AnswerCurrent(store, rec.Id, clock(), timeoutMs);
            }
        }

        // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
        var running = rec with { State = OperationStates.Executing, ExecutingAt = clock() };
        if (!StoreCall(() => store.Transition(rec.Id, OperationStates.Pending, running))) return AnswerCurrent(store, rec.Id, clock(), timeoutMs);

        object? result;
        try { result = await fn(handle).ConfigureAwait(false); }
        catch (Exception e)
        {
            var error = e.Message;
            try { FinishRecord(store, running, running with { State = OperationStates.Failed, Error = error, FinishedAt = clock() }); } catch (Exception) { /* stays executing, then uncertain */ }
            return new ExecuteOutcome { Status = "failed", OperationId = rec.Id, Error = error };
        }
        bool recorded;
        try { recorded = FinishRecord(store, running, running with { State = OperationStates.Committed, Result = result, FinishedAt = clock() }); }
        catch (Exception) { recorded = false; }
        return new ExecuteOutcome { Status = "committed", OperationId = rec.Id, Result = result, Recorded = recorded };
    }

    /// <summary>Settles every open record older than <paramref name="olderThanMs"/> (run it at startup and periodically): pending to aborted (the
    /// side effect never started), executing to uncertain. Returns the records it settled. The store must implement
    /// <see cref="IOpenOperationLister"/>. Nothing is re-run: reconcile each uncertain one with <see cref="ResolveOperation"/>.</summary>
    public static IReadOnlyList<OperationRecord> RecoverOperations(IOperationStore store, long? olderThanMs = null, Func<long>? now = null)
    {
        if (store is not IOpenOperationLister lister) throw new InvalidOperationException("RecoverOperations: the store has no ListOpen (recover by id with RecoverOperation)");
        var settled = new List<OperationRecord>();
        foreach (var r in lister.ListOpen())
        {
            var u = RecoverOperation(store, r.Id, olderThanMs, now);
            if (u != null && u.State != r.State) settled.Add(u);
        }
        return settled;
    }

    /// <summary><see cref="RecoverOperations"/> for one id. Returns the record as it now stands (null: no record, the operation never started).</summary>
    public static OperationRecord? RecoverOperation(IOperationStore store, string id, long? olderThanMs = null, Func<long>? now = null)
    {
        var r = store.Get(id);
        return r == null ? null : SettleStale(store, r, (now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))(), olderThanMs ?? OperationPendingTimeoutMs);
    }

    /// <summary>Settles an uncertain record after reconciling with the downstream system (look the idempotency key up there): committed with the
    /// result it reports (<paramref name="committed"/> true), or failed (with <paramref name="error"/>) when it never applied. Returns false
    /// when the record is not uncertain (or unknown).</summary>
    public static bool ResolveOperation(IOperationStore store, string id, bool committed, object? result = null, string? error = null, Func<long>? now = null)
    {
        var r = store.Get(id);
        if (r is not { State: OperationStates.Uncertain }) return false;
        long at = (now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))();
        var next = committed
            ? r with { State = OperationStates.Committed, Result = result, FinishedAt = at }
            : r with { State = OperationStates.Failed, Error = error, FinishedAt = at };
        return store.Transition(id, OperationStates.Uncertain, next);
    }
}
