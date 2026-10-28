// Executor: Authorize + ExecuteAuthorized in one call, with retries answered from the record. A second presentation of the same PCActn is
// refused by Authorize as a replay; if that replay is the ONLY failing check (the proof, binding, policy and revocation all still pass
// now) and a record exists for its operation id and this operation, the record's outcome is returned (Replayed true) instead of the bare
// denial. No record means the first attempt never reached execution: the denial stands (the authorization was consumed; the agent signs
// a fresh PCActn).
namespace AtlasPca;

/// <summary>Options of <see cref="PcaExecutor"/>.</summary>
public sealed class ExecutorOptions
{
    /// <summary>REQUIRED: the operation record store.</summary>
    public IOperationStore? Operations { get; set; }
    /// <summary>The <see cref="AuthorizeInput"/> configuration (Audience, ResolveGrant, StateStore, IsRevoked, Plans, ...). Its Operation is set per call.
    /// Before an irreversible operation the executor re-runs <see cref="AuthorizeInput.IsRevoked"/> against the grant, checks the PCActn's
    /// expiry, and with <see cref="AuthorizeInput.Plans"/> that the registered plan is still executable for the node.</summary>
    public AuthorizeInput Authorize { get; set; } = new();
    /// <summary>An extra re-check before an irreversible operation (for example a step-up approval still stands).</summary>
    public Func<ExecutionHandle, RecheckResult>? Recheck { get; set; }
    /// <summary>"irreversible" (default) or "always".</summary>
    public string? RecheckFor { get; set; }
    /// <summary>The server's reversibility class for an operation (catalog); null: the signed class only.</summary>
    public Func<Operation, string?>? ReversibilityClassOf { get; set; }
    /// <summary>An open record older than this (ms) is settled; null: five minutes.</summary>
    public long? PendingTimeoutMs { get; set; }
    /// <summary>The clock in epoch ms (null: the wall clock; <see cref="AuthorizeInput.Now"/>, when set, wins for the authorization).</summary>
    public Func<long>? Now { get; set; }
}

/// <summary>Runs authorized operations at most once (the reference's <c>createExecutor</c>). Safe for concurrent use.</summary>
public sealed class PcaExecutor
{
    readonly ExecutorOptions _o;

    public PcaExecutor(ExecutorOptions options) => _o = options ?? throw new ArgumentNullException(nameof(options));

    long Clock() => (_o.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))();

    /// <summary>The executor's own re-check: the grant is still known and not revoked, a registered plan is still executable, then the caller's extra re-check.</summary>
    Func<ExecutionHandle, Task<RecheckResult>> Recheck() => async h =>
    {
        var input = _o.Authorize;
        var grantRef = h.Pcactn.GetValueOrDefault("grant_ref") as string ?? "";
        Dictionary<string, object?>? grant;
        try
        {
            grant = input.ResolveGrantAsync != null ? await input.ResolveGrantAsync(grantRef).ConfigureAwait(false) : input.ResolveGrant?.Invoke(grantRef);
        }
        catch (Exception) { return new RecheckResult(false, "the grant is no longer known"); }
        if (grant == null) return new RecheckResult(false, "the grant is no longer known");
        bool? revoked;
        try { revoked = input.IsRevoked?.Invoke(h.Pcactn, grant); }
        catch (Exception) { revoked = null; }
        if (revoked == null) return new RecheckResult(false, "revocation could not be checked");
        if (revoked == true) return new RecheckResult(false, "the grant has been revoked");
        // a registered plan must still be executable: not revoked, the principal's approval not expired
        if (input.Plans != null && h.Pcactn.GetValueOrDefault("plan") is Dictionary<string, object?> pl && pl.GetValueOrDefault("root") is string root
            && input.Plans.Get(grantRef, root) != null)
        {
            var ps = input.Plans.Check(grantRef, root, new PlanCheckOptions { NodeId = pl.GetValueOrDefault("node_id") as string, Now = Clock() });
            if (!ps.Executable) return new RecheckResult(false, string.IsNullOrEmpty(ps.Reason) ? "plan is " + ps.State : ps.Reason);
        }
        return _o.Recheck != null ? _o.Recheck(h) : RecheckResult.Pass;
    };

    /// <summary>Authorizes <paramref name="pcactn"/> for <paramref name="operation"/> and, when allowed, executes <paramref name="fn"/> at most once.
    /// A missing record store is a refusal. Never throws.</summary>
    public ExecuteOutcome Run(object? pcactn, Operation? operation, Func<ExecutionHandle, object?> fn) =>
        RunAsync(pcactn, operation, h => Task.FromResult(fn(h))).GetAwaiter().GetResult();

    /// <summary><see cref="Run"/> with an asynchronous fn.</summary>
    public async Task<ExecuteOutcome> RunAsync(object? pcactn, Operation? operation, Func<ExecutionHandle, Task<object?>> fn)
    {
        try
        {
            if (_o.Operations == null) return ExecuteOutcome.Refused("createExecutor: missing required component: Operations (fail closed)");
            var input = _o.Authorize.CloneForCall();
            input.Operation = operation;
            input.Now ??= Clock();
            var r = await Pca.AuthorizeAsync(pcactn, input).ConfigureAwait(false);
            string? cls = null;
            if (operation != null && _o.ReversibilityClassOf != null) cls = _o.ReversibilityClassOf(operation);
            long timeoutMs = _o.PendingTimeoutMs ?? Pca.OperationPendingTimeoutMs;
            if (r.Allow)
            {
                return await Pca.ExecuteAuthorizedAsync(r, fn, new ExecuteOptions
                {
                    Store = _o.Operations, Operation = operation, RecheckAsync = Recheck(), RecheckFor = _o.RecheckFor, ReversibilityClass = cls,
                    PendingTimeoutMs = timeoutMs, Now = Clock,
                }).ConfigureAwait(false);
            }
            var denied = new ExecuteOutcome { Status = "denied", Authorization = r };
            var failed = r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).ToList();
            if (r.Status != 403 || failed.Count != 1 || failed[0] != "replay" || operation == null || r.Pcactn == null) return denied;
            // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
            var rec = _o.Operations.Get(Pca.HashCanonical(r.Pcactn));
            if (rec == null || rec.Verb != operation.Verb || rec.Resource != operation.Resource) return denied;
            string want;
            try { want = Pca.ParamsDigest(operation.Params); }
            catch (Exception) { return denied; }
            if (rec.ParamsDigest != want) return denied;
            return Pca.AnswerFromRecord(_o.Operations, rec, Clock(), timeoutMs);
        }
        catch (Exception e) { return ExecuteOutcome.Refused("createExecutor: error (fail closed): " + e.Message); }
    }
}
