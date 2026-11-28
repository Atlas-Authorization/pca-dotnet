using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The compensation half of the undo coordinator: when it waits, how the target is found, the at-most-once operation record in every state it can be
// found in, the re-read under the record, the failure alerts and the retry.
public partial class UndoCoordinatorKillTests
{
    // a record vetoed before its effect was reported: the compensation waits for the report (or the timeout)
    const long Due = T0 + 1_000 + 300_000;

    static async Task<(Rig Rig, UndoAdmitted Adm)> Waiting(Func<JD, string?>? target = null, IOperationStore? ops = null, long? timeout = null, IUndoStore? store = null)
    {
        var rig = Make(resolveTarget: target ?? (_ => "tgt"), ops: ops, effectTimeout: timeout, store: store);
        var (adm, _) = await OpenOne(rig, false);
        rig.T = T0 + 1_000;
        var v = await VetoBy(rig, adm.Id);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("vetoed", State(v.Record));
        return (rig, adm);
    }

    static async Task<(Rig Rig, JD Rec, UndoAdmitted Adm)> VetoThenEffect(object? result, bool hasResult, IUndoEngine? engine = null, Func<JD, string?>? target = null)
    {
        var rig = Make(engine: engine, resolveTarget: target);
        var (adm, _) = await OpenOne(rig, false);
        rig.T = T0 + 1_000;
        Assert.Equal("vetoed", State((await VetoBy(rig, adm.Id)).Record));
        Assert.Empty(rig.Calls);
        var rec = await rig.C.RecordEffectAsync(adm.Id, result, hasResult);
        return (rig, rec, adm);
    }

    static OperationRecord Seed(string id, string state, long started) => new(id, state, "pay.refund", "invoice:1", "pd", "irreversible", started);

    static async Task<(Rig Rig, UndoAdmitted Adm, MemoryOperationStore Ops, string OpKey)> SeedWaiting(Func<string, OperationRecord> seed)
    {
        var ops = new MemoryOperationStore();
        var (rig, adm) = await Waiting(ops: ops);
        var key = OpId((await rig.C.GetAsync(adm.Id))!);
        ops.Create(seed(key));
        rig.T = Due;
        return (rig, adm, ops, key);
    }

    [Fact]
    public async Task TheCompensationWaitsForTheEffectReportUntilTheDefaultTimeout()
    {
        var seen = new List<JD>();
        var (rig, adm) = await Waiting(r => { seen.Add(r); return "tgt"; });
        rig.T = Due - 1;
        Assert.Equal("vetoed", State(await rig.C.CompensateAsync(adm.Id)));
        Assert.Empty(rig.Calls);
        Assert.Empty(seen);
        rig.T = Due;
        var done = await rig.C.CompensateAsync(adm.Id);
        Assert.Equal("compensated", State(done));
        var call = Assert.Single(rig.Calls);
        Assert.Equal("tgt", Sub(call.Operation, "params")["payment"]);
        var sr = Assert.Single(seen);
        Assert.Equal("vetoed", State(sr));
        Assert.Equal(adm.Id, sr["id"]);
        Assert.False(call.HasOriginalResult);
        Assert.Null(call.OriginalResult);
    }

    [Fact]
    public async Task TheEffectTimeoutOptionIsHonoured()
    {
        var (rig, adm) = await Waiting(timeout: 10_000);
        rig.T = T0 + 1_000 + 9_999;
        Assert.Equal("vetoed", State(await rig.C.CompensateAsync(adm.Id)));
        rig.T = T0 + 1_000 + 10_000;
        Assert.Equal("compensated", State(await rig.C.CompensateAsync(adm.Id)));
    }

    [Fact]
    public async Task ACompensationOnlyRunsForAVetoedRecord()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        Assert.Equal("open", State(await rig.C.CompensateAsync(adm.Id)));
        Assert.Empty(rig.Calls);
    }

    [Fact]
    public async Task TheTargetComesFromTheEffectResultWhenItNamesOne()
    {
        var (rig, rec, adm) = await VetoThenEffect(new JD { ["id"] = "pay_1" }, true);
        Assert.Equal("compensated", State(rec));
        var call = Assert.Single(rig.Calls);
        Assert.Equal("pay.refund", call.Operation["verb"]);
        Assert.Equal("invoice:1", call.Operation["resource"]);
        Assert.Equal(new[] { "memo", "payment" }, Sub(call.Operation, "params").Keys.ToArray());
        Assert.Equal("m", Sub(call.Operation, "params")["memo"]);
        Assert.Equal("pay_1", Sub(call.Operation, "params")["payment"]);
        Assert.True(call.HasOriginalResult);
        Assert.Equal("pay_1", ((JD)call.OriginalResult!)["id"]);
        Assert.Equal(adm.Id, call.UndoOf);
        Assert.Equal(OpId(rec), call.IdempotencyKey);
        Assert.False(call.Record.ContainsKey("pcactn"));
        Assert.Equal("vetoed", State(call.Record));
        Assert.True(call.Record.ContainsKey("receipts"));
        Assert.Equal(adm.Id, call.Record["id"]);
    }

    [Fact]
    public async Task AnEffectResultThatNamesNoTargetFailsTheCompensationLoudly()
    {
        const string why = "the target 'payment' of the compensation is unknown (no effect result names it)";
        var cases = new (object? Result, bool Has)[]
        {
            (new JD { ["id"] = "" }, true), (new JD { ["x"] = 1L }, true), ("a string", true), (null, true), (null, false),
        };
        foreach (var (result, has) in cases)
        {
            var (rig, rec, adm) = await VetoThenEffect(result, has);
            Assert.Equal("compensation_failed", State(rec));
            Assert.Equal(why, Sub(rec, "outcome")["reason"]);
            Assert.Empty(rig.Calls);
            Assert.Equal(new UndoAlert("critical", "compensation_failed", adm.Id, why), Assert.Single(rig.Alerts));
            var last = rig.N.Notices[^1];
            Assert.Equal("compensation_failed", last.Kind);
            Assert.Equal("compensation_failed", State(last.Record));
            Assert.False(last.Record.ContainsKey("pcactn"));
            Assert.False(last.Record.ContainsKey("receipts"));
        }
    }

    [Fact]
    public async Task ACustomTargetResolverWinsAndNullFailsTheCompensation()
    {
        var (rig, rec, _) = await VetoThenEffect(new JD { ["id"] = "pay_1" }, true, target: _ => "custom");
        Assert.Equal("compensated", State(rec));
        Assert.Equal("custom", Sub(rig.Calls[0].Operation, "params")["payment"]);
        var (rig2, rec2, _) = await VetoThenEffect(new JD { ["id"] = "pay_1" }, true, target: _ => null);
        Assert.Equal("compensation_failed", State(rec2));
        Assert.Empty(rig2.Calls);
    }

    [Fact]
    public async Task ACompensationWithoutATargetParamRunsWithItsOwnParamsAndNoOriginalResult()
    {
        var (rig, rec, _) = await VetoThenEffect(null, false, engine: new PlanEngine((_, _) => MakePlan(target: false)));
        Assert.Equal("compensated", State(rec));
        var call = Assert.Single(rig.Calls);
        Assert.Equal(new[] { "memo" }, Sub(call.Operation, "params").Keys.ToArray());
        Assert.False(call.HasOriginalResult);
        Assert.Null(call.OriginalResult);
        var (rig2, _, _) = await VetoThenEffect(new JD { ["id"] = "z" }, true, engine: new PlanEngine((_, _) => MakePlan(target: false)));
        Assert.True(rig2.Calls[0].HasOriginalResult);
    }

    [Fact]
    public async Task TheOperationRecordAndTheOutcomeShowTheExactRun()
    {
        var rig = Make();
        rig.Comp = _ => { rig.T += 7; return Task.FromResult<object?>(new JD { ["refund"] = "r1" }); };
        var (adm, _) = await OpenOne(rig);
        rig.T = T0 + 500;
        var v = await VetoBy(rig, adm.Id);
        Assert.True(v.Ok, v.Reason);
        var call = Assert.Single(rig.Calls);
        var op = rig.Ops.Get(call.IdempotencyKey)!;
        Assert.Equal(OperationStates.Committed, op.State);
        Assert.Equal("pay.refund", op.Verb);
        Assert.Equal("invoice:1", op.Resource);
        Assert.Equal(Pca.HashCanonical(call.Operation["params"]), op.ParamsDigest);
        Assert.Equal("irreversible", op.Reversibility);
        Assert.Equal(T0 + 500, op.StartedAt);
        Assert.Equal(T0 + 500, op.ExecutingAt);
        Assert.Equal(T0 + 507, op.FinishedAt);
        Assert.Equal("r1", ((JD)op.Result!)["refund"]);
        var outcome = Sub(v.Record, "outcome");
        Assert.Equal("compensated", outcome["status"]);
        Assert.Equal(T0 + 507, Lg(outcome["at"]));
        Assert.Equal("r1", Sub(outcome, "result")["refund"]);
        Assert.Equal(new[] { "opened", "effect", "vetoed", "compensated" }, Events(v.Record!));
    }

    [Fact]
    public async Task ACompensatorThatReturnsNothingLeavesNoResult()
    {
        var rig = Make();
        rig.Comp = _ => Task.FromResult<object?>(null);
        var (adm, _) = await OpenOne(rig);
        var v = await VetoBy(rig, adm.Id);
        Assert.Equal("compensated", State(v.Record));
        Assert.False(Sub(v.Record, "outcome").ContainsKey("result"));
        Assert.Null(rig.Ops.Get(Assert.Single(rig.Calls).IdempotencyKey)!.Result);
    }

    [Fact]
    public async Task AFailingCompensatorIsRecordedAlertedAndRetryable()
    {
        var rig = Make();
        rig.Comp = _ => { rig.T += 3; throw new InvalidOperationException("downstream 500"); };
        var (adm, _) = await OpenOne(rig);
        var v = await VetoBy(rig, adm.Id);
        Assert.True(v.Ok);
        Assert.Equal("compensation_failed", State(v.Record));
        Assert.Equal("the compensating action failed: downstream 500", Sub(v.Record, "outcome")["reason"]);
        var key = Assert.Single(rig.Calls).IdempotencyKey;
        var op = rig.Ops.Get(key)!;
        Assert.Equal(OperationStates.Failed, op.State);
        Assert.Equal("downstream 500", op.Error);
        Assert.Equal(T0 + 3, op.FinishedAt);
        Assert.Equal(new UndoAlert("critical", "compensation_failed", adm.Id, "the compensating action failed: downstream 500"), Assert.Single(rig.Alerts));
        Assert.Equal("compensation_failed", rig.N.Notices[^1].Kind);
        Assert.Equal("compensation_failed", State(rig.N.Notices[^1].Record));

        rig.Comp = _ => Task.FromResult<object?>(new JD { ["refund"] = "r2" });
        var again = await rig.C.RetryAsync(adm.Id);
        Assert.Equal("compensated", State(again));
        Assert.Equal(1L, Lg(again["attempt"]));
        Assert.Equal(2, rig.Calls.Count);
        Assert.NotEqual(key, rig.Calls[1].IdempotencyKey);
        Assert.Equal(OpId(again), rig.Calls[1].IdempotencyKey);
        Assert.Equal(new[] { "opened", "effect", "vetoed", "compensation_failed", "retried", "compensated" }, Events(again));
        Assert.Single(rig.Alerts);
        Assert.Equal("compensated", rig.N.Notices[^1].Kind);
    }

    [Fact]
    public async Task AnOperationStoreThatCannotBeUpdatedNeverHidesTheOutcome()
    {
        var ops = new HookOps(new MemoryOperationStore());
        ops.Transitioning = (_, _, next) => next.State == OperationStates.Committed ? throw new InvalidOperationException("store down") : (bool?)null;
        var rig = Make(ops: ops);
        var (adm, _) = await OpenOne(rig);
        Assert.Equal("compensated", State((await VetoBy(rig, adm.Id)).Record));

        var ops2 = new HookOps(new MemoryOperationStore());
        ops2.Transitioning = (_, _, next) => next.State == OperationStates.Failed ? throw new InvalidOperationException("store down") : (bool?)null;
        var rig2 = Make(ops: ops2);
        rig2.Comp = _ => throw new InvalidOperationException("downstream");
        var (adm2, _) = await OpenOne(rig2);
        var v = await VetoBy(rig2, adm2.Id);
        Assert.Equal("compensation_failed", State(v.Record));
        Assert.Equal("the compensating action failed: downstream", Sub(v.Record, "outcome")["reason"]);
    }

    [Fact]
    public async Task ACompensationNobodyCanClaimNeverRuns()
    {
        var ops = new HookOps(new MemoryOperationStore());
        ops.Transitioning = (_, _, next) => next.State == OperationStates.Executing ? false : (bool?)null;
        var (rig, adm) = await Waiting(ops: ops);
        rig.T = Due;
        var res = await rig.C.CompensateAsync(adm.Id);
        Assert.Equal("vetoed", State(res));
        Assert.Empty(rig.Calls);
        Assert.Equal(OperationStates.Pending, ops.Get(OpId(res))!.State);
    }

    [Fact]
    public async Task ARecordThatMovedOnAbortsTheClaimedOperation()
    {
        var alternatives = new Func<JD?, JD?>[]
        {
            _ => null,
            r => new JD(r!) { ["state"] = "compensated" },
            r => new JD(r!) { ["attempt"] = IntentJs.OfLong(5) },
        };
        foreach (var alt in alternatives)
        {
            var hook = new HookStore(new MemoryUndoStore());
            var (rig, adm) = await Waiting(store: hook);
            var key = OpId((await rig.C.GetAsync(adm.Id))!);
            rig.T = Due;
            hook.Gets = 0;
            hook.OnGet = (n, r) => n == 2 ? alt(r) : r;
            var res = await rig.C.CompensateAsync(adm.Id);
            Assert.Empty(rig.Calls);
            var op = rig.Ops.Get(key)!;
            Assert.Equal(OperationStates.Aborted, op.State);
            Assert.Equal("the undo record moved on", op.Error);
            Assert.Equal(Due, op.FinishedAt);
            var expected = alt(new JD { ["state"] = "vetoed", ["attempt"] = IntentJs.OfLong(0) });
            if (expected == null) Assert.Equal("vetoed", State(res));
            else if (State(expected) == "compensated") Assert.Equal("compensated", State(res));
            else Assert.Equal(5L, Lg(res["attempt"]));
        }
    }

    [Fact]
    public async Task AnAlreadyCommittedCompensationIsAdoptedNotRunTwice()
    {
        var (rig, adm, ops, key) = await SeedWaiting(id => Seed(id, OperationStates.Committed, T0) with { Result = new JD { ["x"] = 1L } });
        var res = await rig.C.CompensateAsync(adm.Id);
        Assert.Equal("compensated", State(res));
        Assert.Empty(rig.Calls);
        Assert.Equal(1L, Lg(Sub(Sub(res, "outcome"), "result")["x"]));
        Assert.Equal("compensated", rig.N.Notices[^1].Kind);
        Assert.Equal(OperationStates.Committed, ops.Get(key)!.State);

        var (rig2, adm2, _, _) = await SeedWaiting(id => Seed(id, OperationStates.Committed, T0));
        var res2 = await rig2.C.CompensateAsync(adm2.Id);
        Assert.Equal("compensated", State(res2));
        Assert.False(Sub(res2, "outcome").ContainsKey("result"));
    }

    [Fact]
    public async Task AFailedOrUncertainAttemptFailsTheRecordWithItsError()
    {
        var cases = new (string State, string? Error, string Reason)[]
        {
            (OperationStates.Failed, "kaput", "compensation attempt 0 failed: kaput"),
            (OperationStates.Failed, null, "compensation attempt 0 failed: "),
            (OperationStates.Uncertain, "lost", "compensation attempt 0 uncertain: lost"),
        };
        foreach (var (state, error, reason) in cases)
        {
            var (rig, adm, _, _) = await SeedWaiting(id => Seed(id, state, T0) with { Error = error });
            var res = await rig.C.CompensateAsync(adm.Id);
            Assert.Equal("compensation_failed", State(res));
            Assert.Equal(reason, Sub(res, "outcome")["reason"]);
            Assert.Empty(rig.Calls);
            Assert.Equal(new UndoAlert("critical", "compensation_failed", adm.Id, reason), Assert.Single(rig.Alerts));
        }
    }

    [Fact]
    public async Task AnAbortedAttemptIsRetriedAsANewAttempt()
    {
        var (rig, adm, ops, key) = await SeedWaiting(id => Seed(id, OperationStates.Aborted, T0));
        var res = await rig.C.CompensateAsync(adm.Id);
        Assert.Equal("compensated", State(res));
        Assert.Equal(1L, Lg(res["attempt"]));
        Assert.Equal(new[] { "opened", "vetoed", "compensation_failed", "retried", "compensated" }, Events(res));
        Assert.Equal("attempt never started", ((JD)((JL)res["receipts"]!)[2]!)["note"]);
        var call = Assert.Single(rig.Calls);
        Assert.NotEqual(key, call.IdempotencyKey);
        Assert.Equal(OperationStates.Aborted, ops.Get(key)!.State);
        Assert.Empty(rig.Alerts);
    }

    [Fact]
    public async Task APendingAttemptIsWaitedForUntilItIsStale()
    {
        var (rig, adm, ops, key) = await SeedWaiting(id => Seed(id, OperationStates.Pending, Due - 300_000));
        Assert.Equal("vetoed", State(await rig.C.CompensateAsync(adm.Id)));
        Assert.Empty(rig.Calls);
        Assert.Equal(OperationStates.Pending, ops.Get(key)!.State);

        var (rig2, adm2, ops2, key2) = await SeedWaiting(id => Seed(id, OperationStates.Pending, Due - 300_001));
        var res = await rig2.C.CompensateAsync(adm2.Id);
        var op = ops2.Get(key2)!;
        Assert.Equal(OperationStates.Aborted, op.State);
        Assert.Equal("never started", op.Error);
        Assert.Equal(Due, op.FinishedAt);
        Assert.Equal("compensated", State(res));
        Assert.Equal(1L, Lg(res["attempt"]));
        Assert.Single(rig2.Calls);
    }

    [Fact]
    public async Task AnExecutingAttemptIsJudgedByWhenItStartedExecuting()
    {
        var (rig, adm, ops, key) = await SeedWaiting(id => Seed(id, OperationStates.Executing, Due - 9_999_999) with { ExecutingAt = Due - 300_000 });
        Assert.Equal("vetoed", State(await rig.C.CompensateAsync(adm.Id)));
        Assert.Equal(OperationStates.Executing, ops.Get(key)!.State);
        Assert.Empty(rig.Calls);

        const string lost = "no outcome recorded: the compensation may or may not have run";
        var (rig2, adm2, ops2, key2) = await SeedWaiting(id => Seed(id, OperationStates.Executing, Due) with { ExecutingAt = Due - 300_001 });
        var res = await rig2.C.CompensateAsync(adm2.Id);
        var op = ops2.Get(key2)!;
        Assert.Equal(OperationStates.Uncertain, op.State);
        Assert.Equal(lost, op.Error);
        Assert.Equal(Due, op.FinishedAt);
        Assert.Equal("compensation_failed", State(res));
        Assert.Equal("compensation attempt 0 uncertain: " + lost, Sub(res, "outcome")["reason"]);
        Assert.Empty(rig2.Calls);

        var (rig3, adm3, ops3, key3) = await SeedWaiting(id => Seed(id, OperationStates.Executing, Due - 300_001));
        var res3 = await rig3.C.CompensateAsync(adm3.Id);
        Assert.Equal(OperationStates.Uncertain, ops3.Get(key3)!.State);
        Assert.Equal("compensation_failed", State(res3));
    }

    [Fact]
    public async Task ADeniedOrUnknownGrantAtCompensationTimeFailsTheRecordAsDenied()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        var args = new List<(string, JD)>();
        rig.Resolve = (r, pc) => { args.Add((r, pc)); return Task.FromResult<JD?>(null); };
        var v = await VetoBy(rig, adm.Id);
        Assert.Equal("compensation_failed", State(v.Record));
        var (gref, pc0) = Assert.Single(args);
        Assert.Equal((string)adm.Pcactn["grant_ref"]!, gref);
        Assert.Equal(Pca.Canonicalize(adm.Pcactn), Pca.Canonicalize(pc0));
        const string why = "the grant is no longer known: the compensation cannot be authorized";
        Assert.Equal(why, Sub(v.Record, "outcome")["reason"]);
        Assert.Equal(new UndoAlert("critical", "compensation_denied", adm.Id, why), Assert.Single(rig.Alerts));
        Assert.Equal("compensation_failed", rig.N.Notices[^1].Kind);
        Assert.Empty(rig.Calls);

        var narrow = Make();
        var (adm2, _) = await OpenOne(narrow);
        narrow.Resolve = (_, _) => Task.FromResult<JD?>(PayOnlyGrant);
        var v2 = await VetoBy(narrow, adm2.Id);
        Assert.Equal("compensation_failed", State(v2.Record));
        const string pre = "the compensating action is not authorized under the grant: ";
        var reason = (string)Sub(v2.Record, "outcome")["reason"]!;
        Assert.StartsWith(pre, reason);
        Assert.NotEqual(pre, reason);
        var alert = Assert.Single(narrow.Alerts);
        Assert.Equal("compensation_denied", alert.Code);
        Assert.Equal("critical", alert.Level);
        Assert.Equal(adm2.Id, alert.Record);
        Assert.Equal(reason, alert.Reason);
        Assert.Empty(narrow.Calls);
        Assert.Empty(((MemoryOperationStore)narrow.Ops).ListOpen());
    }

    [Fact]
    public async Task ATamperedStoredPcactnIsRefusedBeforeAnythingRuns()
    {
        async Task<(Rig, UndoAdmitted)> Tampered(string text)
        {
            var store = new MemoryUndoStore();
            var (rig, adm) = await Waiting(store: store);
            var rec = (await store.GetAsync(adm.Id))!;
            Assert.True(await store.ReplaceAsync(adm.Id, Lg(rec["ver"]), new JD(rec) { ["pcactn"] = text }));
            rig.T = Due;
            return (rig, adm);
        }
        var (r1, a1) = await Tampered("[]");
        var notObject = await Assert.ThrowsAsync<ArgumentException>(() => r1.C.CompensateAsync(a1.Id));
        Assert.Equal("decodePCActn: not an object", notObject.Message);

        var (r2, a2) = await Tampered(new string('a', Pca.MaxArtifactBytes + 1));
        var big = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => r2.C.CompensateAsync(a2.Id));
        Assert.Equal("text", big.ParamName);
        Assert.Contains(Pca.ArtifactSizeReason, big.Message);

        var (r3, a3) = await Tampered(new string('é', 262_145));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => r3.C.CompensateAsync(a3.Id));

        var (r4, a4) = await Tampered(new string('a', Pca.MaxArtifactBytes));
        var edge = await Record.ExceptionAsync(() => r4.C.CompensateAsync(a4.Id));
        Assert.NotNull(edge);
        Assert.IsNotType<ArgumentOutOfRangeException>(edge);
        Assert.Empty(r4.Calls);
    }
}
