using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AtlasPca;
using Microsoft.Data.Sqlite;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// The executor (Authorize + ExecuteAuthorized, retries answered from the record), the plan registry feeding Authorize, and the durable
// SQL stores, over the signed shared authorize fixtures.
public class ExecutorTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    // the signed class of this PCActn is irreversible: the executor re-checks before it runs
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);

    static AuthorizeInput Input(IStateStore store, Func<JD, JD, bool?>? revoked = null) => new()
    {
        Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = store, IsRevoked = revoked ?? ((_, _) => false), Now = Now, Plan = "single-step",
    };

    static AuthorizeInput Direct(IStateStore store) { var i = Input(store); i.Operation = Op; return i; }

    static PcaExecutor Exec(IOperationStore ops, IStateStore store, Func<JD, JD, bool?>? revoked = null, Func<ExecutionHandle, RecheckResult>? recheck = null) =>
        new(new ExecutorOptions { Operations = ops, Authorize = Input(store, revoked), Recheck = recheck, Now = () => Now });

    [Fact]
    public void ARetryOfTheSamePcactnIsAnsweredFromTheRecordAndFnRunsOnce()
    {
        int calls = 0;
        var ex = Exec(new MemoryOperationStore(), new MemoryStateStore());
        var first = ex.Run(Pcactn, Op, h => { calls++; return "paid:" + h.IdempotencyKey[..6]; });
        Assert.Equal("committed", first.Status);
        Assert.False(first.Replayed);
        var again = ex.Run(Pcactn, Op, h => { calls++; return "twice"; });
        Assert.Equal(("committed", true, first.Result), (again.Status, again.Replayed, again.Result));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void AReplayWithoutARecordOrForAnotherOperationStaysDenied()
    {
        var store = new MemoryStateStore();
        // the authorization was consumed outside the executor: no record exists
        Assert.True(Pca.Authorize(Pcactn, Direct(store)).Allow);
        Assert.False(Pca.Authorize(Pcactn, Direct(store)).Allow);
        var ex = Exec(new MemoryOperationStore(), store);
        var denied = ex.Run(Pcactn, Op, _ => 1);
        Assert.Equal("denied", denied.Status);
        Assert.Equal("fail", denied.Authorization!.Checks["replay"]);
        // a record for another operation does not answer it
        var ops = new MemoryOperationStore();
        ops.Create(new OperationRecord(Pca.HashCanonical(Pcactn), OperationStates.Committed, Op.Verb, Op.Resource, "not-the-digest", "reversible", 1) { Result = "x" });
        Assert.Equal("denied", Exec(ops, store).Run(Pcactn, Op, _ => 1).Status);
    }

    [Fact]
    public void ARevocationBetweenAuthorizeAndExecuteAbortsAnIrreversibleOperation()
    {
        int seen = 0, calls = 0;
        // the authorization pass sees "not revoked"; the re-check immediately before fn sees "revoked"
        var ex = Exec(new MemoryOperationStore(), new MemoryStateStore(), (_, _) => Interlocked.Increment(ref seen) > 1);
        var r = ex.Run(Pcactn, Op, _ => { calls++; return 1; });
        Assert.Equal(("aborted", "recheck: the grant has been revoked"), (r.Status, r.Reason));
        Assert.Equal(0, calls);
    }

    [Fact]
    public void AnExtraRecheckAndAMissingStoreAreHonoured()
    {
        var r = Exec(new MemoryOperationStore(), new MemoryStateStore(), null, _ => new RecheckResult(false, "step-up withdrawn")).Run(Pcactn, Op, _ => 1);
        Assert.Equal(("aborted", "recheck: step-up withdrawn"), (r.Status, r.Reason));
        var none = new PcaExecutor(new ExecutorOptions { Authorize = Input(new MemoryStateStore()) }).Run(Pcactn, Op, _ => 1);
        Assert.Equal(("refused", "createExecutor: missing required component: Operations (fail closed)"), (none.Status, none.Reason));
    }

    // ---- the plan registry feeding Authorize

    static JD PlanNodeOf(JD p)
    {
        var action = (JD)p["action"]!; var pl = (JD)p["plan"]!;
        return new JD { ["id"] = pl["node_id"], ["verb"] = action["verb"], ["resource"] = action["resource"], ["params_digest"] = action["params_digest"], ["reversibility_class"] = action["reversibility_class"] };
    }

    [Fact]
    public void AuthorizeFeedsFromThePlanRegistry()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => Now });
        AuthorizeInput In() { var i = Input(new MemoryStateStore()); i.Plan = null; i.Plans = reg; i.Operation = Op; return i; }
        var grantRef = (string)Pcactn["grant_ref"]!;
        // unknown root: denied, naming the registry
        var unknown = Pca.Authorize(Pcactn, In());
        Assert.False(unknown.Allow);
        Assert.Equal(("fail", "fail"), (unknown.Checks["plan_state"], unknown.Checks["plan_root_authorized"]));
        Assert.Contains("plan_state: plan ", unknown.Reasons.Single(r => r.StartsWith("plan_state:")));
        var d = reg.Draft(grantRef, new List<JD> { PlanNodeOf(Pcactn) });
        Assert.True(d.Ok, d.Reason);
        var root = d.Record!.Root;
        Assert.Equal(((JD)Pcactn["plan"]!)["root"], root); // the registry's root equals the PCActn's plan root
        reg.Validate(grantRef, root); reg.Commit(grantRef, root);
        var committed = Pca.Authorize(Pcactn, In());
        Assert.False(committed.Allow);
        Assert.Equal("fail", committed.Checks["plan_state"]);
        reg.Authorize(grantRef, root, new PlanApproval("principal"));
        var ok = Pca.Authorize(Pcactn, In());
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["plan_state"]);
        reg.Revoke(grantRef, root, "changed my mind");
        var revoked = Pca.Authorize(Pcactn, In());
        Assert.False(revoked.Allow);
        Assert.Contains("revoked (changed my mind)", revoked.Reason);
    }

    [Fact]
    public void TheExecutorRechecksTheRegisteredPlan()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => Now });
        var grantRef = (string)Pcactn["grant_ref"]!;
        var root = reg.Draft(grantRef, new List<JD> { PlanNodeOf(Pcactn) }).Record!.Root;
        reg.Validate(grantRef, root); reg.Commit(grantRef, root);
        reg.Authorize(grantRef, root, new PlanApproval("principal", Now + 1)); // the approval lapses right after the authorization
        PcaExecutor At(long clock)
        {
            var input = Input(new MemoryStateStore()); input.Plan = null; input.Plans = reg;
            return new PcaExecutor(new ExecutorOptions { Operations = new MemoryOperationStore(), Authorize = input, Now = () => clock });
        }
        // the same clock: the plan is executable at the re-check
        Assert.Equal("committed", At(Now).Run(Pcactn, Op, _ => "ran").Status);
        // authorize reads the fixed AuthorizeInput.Now (before the expiry); the re-check runs later, after the approval expired
        int calls = 0;
        var aborted = At(Now + 10).Run(Pcactn, Op, _ => { calls++; return 1; });
        Assert.Equal("aborted", aborted.Status);
        Assert.Contains("the principal's approval expired", aborted.Reason);
        Assert.Equal(0, calls);
    }

    // ---- durable SQL stores: several connections to one database file

    sealed class TempDb : IDisposable
    {
        public readonly string Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "pca-" + Guid.NewGuid().ToString("N") + ".db");
        public SqliteConnection Connect() => new("Data Source=" + Path + ";Pooling=False");
        public void Dispose() { try { File.Delete(Path); } catch (IOException) { /* best effort */ } }
    }

    [Fact]
    public async Task SqlBackedOperationStoreRunsFnExactlyOnceAcrossConnections()
    {
        using var db = new TempDb();
        var kv = new SqlAtomicKv(() => db.Connect());
        kv.EnsureSchema();
        var store = new KvOperationStore(kv);
        int calls = 0;
        var az = new AuthorizeResult
        {
            Allow = true, Status = 200, Pcactn = new JD { ["action"] = new JD { ["reversibility_class"] = "reversible" } },
            Operation = new AuthorizedOperation("v", "/r", Pca.ParamsDigest(null), "sql-op"),
        };
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            Pca.ExecuteAuthorized(az, h => { Interlocked.Increment(ref calls); Thread.Sleep(20); return "ok"; }, new ExecuteOptions { Store = store }))));
        Assert.Equal(1, calls);
        Assert.Equal(1, outcomes.Count(o => o.Status == "committed" && !o.Replayed));
        // the record survives a new store over the same database
        var reopened = new KvOperationStore(new SqlAtomicKv(() => db.Connect()));
        Assert.Equal(("committed", "ok"), (reopened.Get("sql-op")!.State, reopened.Get("sql-op")!.Result));
        Assert.Equal("committed", Pca.ExecuteAuthorized(az, _ => 2, new ExecuteOptions { Store = reopened }).Status);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task SqlBackedPlanRegistryHasOneWinnerPerTransition()
    {
        using var db = new TempDb();
        var kv = new SqlAtomicKv(() => db.Connect());
        kv.EnsureSchema();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => 7 });
        var d = reg.Draft("g", new List<JD> { new() { ["id"] = "n1", ["verb"] = "orders.read", ["resource"] = "/orders/1" } });
        Assert.True(d.Ok, d.Reason);
        var root = d.Record!.Root;
        Assert.True(reg.Validate("g", root).Ok);
        Assert.True(reg.Commit("g", root).Ok);
        var wins = (await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => reg.Authorize("g", root, new PlanApproval("p")))))).Count(t => t.Ok);
        Assert.Equal(1, wins);
        Assert.True(new PlanRegistry(new PlanRegistryOptions { Kv = new SqlAtomicKv(() => db.Connect()), Now = () => 7 }).IsPlanAuthorized("g", root));
    }
}
