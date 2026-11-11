using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Operation records (T3): replays operation-vectors.json scenario by scenario against ONE fresh in-memory store each (the harness is
// scripts/gen-conformance-native-parity.ts: `execute` runs a pre-authorized operation under a fixed clock, `seed` / `get` / `recover` /
// `recover_one` / `resolve` drive the store directly), then the concurrency and durable-store properties. A missing vector file FAILS.
public class OperationVectorTests
{
    static string S(object? o) => (string)o!;
    static long? OptL(D s, string k) => s.TryGetValue(k, out var v) ? N(v) : null;
    static string C(object? v) => Pca.Canonicalize(v);

    static AuthorizeResult Authorization(D s)
    {
        if (s.GetValueOrDefault("not_allowed") is true) return new AuthorizeResult { Allow = false, Status = 403 };
        var action = new D();
        if (s.TryGetValue("signed_class", out var sc)) action["reversibility_class"] = sc;
        var p = new D { ["action"] = action };
        if (s.TryGetValue("exp", out var exp)) p["exp"] = exp;
        return new AuthorizeResult
        {
            Allow = true, Status = 200, Pcactn = p,
            Operation = new AuthorizedOperation(s.GetValueOrDefault("verb") as string ?? "payments.refund", s.GetValueOrDefault("resource") as string ?? "/orders/1",
                s.GetValueOrDefault("params_digest") as string ?? Pca.ParamsDigest(null), S(s["id"])),
        };
    }

    static D Execute(D s, MemoryOperationStore store)
    {
        int calls = 0;
        long at = N(s["at"]);
        var az = Authorization(s);
        bool noStore = s.GetValueOrDefault("no_store") is true;
        var opts = new ExecuteOptions { Store = noStore ? null : store, Now = () => at };
        if (s.TryGetValue("recheck", out var rc))
        {
            if (rc is string) opts.Recheck = _ => RecheckResult.Pass;
            else
            {
                var m = D(rc);
                if (m.TryGetValue("refuse", out var why)) opts.Recheck = _ => new RecheckResult(false, S(why));
                else { var msg = S(m["throw"]); opts.Recheck = _ => throw new InvalidOperationException(msg); }
            }
        }
        if (s.TryGetValue("recheck_for", out var rf)) opts.RecheckFor = S(rf);
        if (s.TryGetValue("server_class", out var srv)) opts.ReversibilityClass = S(srv);
        if (s.TryGetValue("timeout_ms", out var to)) opts.PendingTimeoutMs = N(to);
        var f = D(s["fn"]);
        Func<ExecutionHandle, object?> fn = h =>
        {
            calls++;
            switch (S(f["kind"]))
            {
                case "throw": throw new InvalidOperationException(S(f["message"]));
                case "reenter": return Pca.ExecuteAuthorized(az, _ => throw new InvalidOperationException("inner must not run"), opts).Status;
                default: return f.TryGetValue("result", out var r) ? r : h.IdempotencyKey;
            }
        };
        var outcome = Pca.ExecuteAuthorized(az, fn, opts);
        bool none = noStore || s.GetValueOrDefault("not_allowed") is true;
        return new D { ["outcome"] = outcome.ToJson(), ["fn_calls"] = calls, ["record"] = none ? null : store.Get(S(s["id"]))?.ToJson() };
    }

    [Fact]
    public void ScenariosReplay()
    {
        var doc = Load("operation-vectors.json");
        var scs = L(doc["scenarios"]);
        Assert.True(scs.Count == 19, $"{scs.Count} scenarios, this runner pins 19");
        foreach (var sc in scs.Cast<D>())
        {
            var store = new MemoryOperationStore();
            var steps = L(sc["steps"]); var expect = L(sc["expect"]);
            Assert.Equal(steps.Count, expect.Count);
            for (int i = 0; i < steps.Count; i++)
            {
                var s = D(steps[i]);
                object? got;
                switch (S(s["op"]))
                {
                    case "seed": store.Create(OperationRecord.FromJson(s["record"])!); got = null; break;
                    case "get": got = store.Get(S(s["id"]))?.ToJson(); break;
                    case "recover":
                        got = Pca.RecoverOperations(store, OptL(s, "older_than_ms"), () => N(s["at"]))
                            .OrderBy(r => r.Id, StringComparer.Ordinal).Select(r => (object?)new D { ["id"] = r.Id, ["state"] = r.State }).ToList();
                        break;
                    case "recover_one": got = Pca.RecoverOperation(store, S(s["id"]), OptL(s, "older_than_ms"), () => N(s["at"]))?.ToJson(); break;
                    case "resolve":
                        {
                            var o = D(s["outcome"]);
                            got = Pca.ResolveOperation(store, S(s["id"]), S(o["state"]) == "committed", o.GetValueOrDefault("result"), o.GetValueOrDefault("error") as string, () => N(s["at"]));
                            break;
                        }
                    case "execute": got = Execute(s, store); break;
                    default: throw new InvalidOperationException("op " + s["op"]);
                }
                Assert.True(C(got) == C(expect[i]), $"{sc["name"]} step {i} ({s["op"]}):\n got  {C(got)}\n want {C(expect[i])}");
            }
        }
    }

    static AuthorizeResult Allowed(string id = "op-1", string cls = "reversible") => new()
    {
        Allow = true, Status = 200, Pcactn = new D { ["action"] = new D { ["reversibility_class"] = cls } },
        Operation = new AuthorizedOperation("payments.refund", "/orders/1", Pca.ParamsDigest(null), id),
    };

    // Of N concurrent executions of one authorization exactly one runs fn, over every store kind.
    [Fact]
    public async Task ParallelExecutionsRunFnExactlyOnce()
    {
        var stores = new Dictionary<string, IOperationStore> { ["memory"] = new MemoryOperationStore(), ["kv"] = new KvOperationStore(new MemoryAtomicKv()) };
        foreach (var (name, store) in stores)
        {
            int calls = 0;
            var az = Allowed();
            var tasks = Enumerable.Range(0, 64).Select(_ => Task.Run(() => Pca.ExecuteAuthorized(az, h => { Interlocked.Increment(ref calls); Thread.Sleep(5); return "done"; }, new ExecuteOptions { Store = store }))).ToArray();
            var outcomes = await Task.WhenAll(tasks);
            Assert.True(calls == 1, $"{name}: fn ran {calls} times");
            Assert.Equal(1, outcomes.Count(o => o.Status == "committed" && !o.Replayed));
            Assert.All(outcomes.Where(o => o.Replayed), o => Assert.Contains(o.Status, new[] { "pending", "committed" }));
            Assert.Equal("committed", store.Get("op-1")!.State);
        }
    }

    [Fact]
    public void KvStoreRoundTripsTransitionsAndRefusesALostRace()
    {
        var store = new KvOperationStore(new MemoryAtomicKv());
        var rec = new OperationRecord("o", OperationStates.Pending, "v", "/r", "d", "reversible", 10);
        Assert.True(store.Create(rec).Created);
        var again = store.Create(rec with { Verb = "other" });
        Assert.False(again.Created);
        Assert.Equal("v", again.Existing!.Verb);
        Assert.False(store.Transition("o", OperationStates.Executing, rec with { State = OperationStates.Committed }));
        Assert.True(store.Transition("o", OperationStates.Pending, rec with { State = OperationStates.Executing, ExecutingAt = 11 }));
        Assert.Equal(11L, store.Get("o")!.ExecutingAt);
        Assert.False(store.Transition("o", OperationStates.Pending, rec));
        Assert.Null(store.Get("missing"));
        Assert.False(store.Transition("missing", OperationStates.Pending, rec));
    }

    [Fact]
    public void AStoreThatThrowsIsARefusalAndNothingRuns()
    {
        int calls = 0;
        var r = Pca.ExecuteAuthorized(Allowed(), _ => { calls++; return 1; }, new ExecuteOptions { Store = new ThrowingStore() });
        Assert.Equal("refused", r.Status);
        Assert.StartsWith("executeAuthorized: the operation store failed (fail closed): ", r.Reason);
        Assert.Equal(0, calls);
    }

    sealed class ThrowingStore : IOperationStore
    {
        public (bool Created, OperationRecord? Existing) Create(OperationRecord record) => throw new InvalidOperationException("down");
        public OperationRecord? Get(string id) => throw new InvalidOperationException("down");
        public bool Transition(string id, string from, OperationRecord next) => throw new InvalidOperationException("down");
    }

    [Fact]
    public async Task AsyncFnAndAsyncRecheckAreAwaited()
    {
        var store = new MemoryOperationStore();
        var r = await Pca.ExecuteAuthorizedAsync(Allowed("a1", "irreversible"), async h => { await Task.Delay(5); return h.IdempotencyKey; },
            new ExecuteOptions { Store = store, RecheckAsync = async _ => { await Task.Delay(1); return RecheckResult.Pass; } });
        Assert.Equal(("committed", "a1"), (r.Status, r.Result));
        var no = await Pca.ExecuteAuthorizedAsync(Allowed("a2", "irreversible"), _ => Task.FromResult<object?>(1),
            new ExecuteOptions { Store = store, RecheckAsync = _ => Task.FromResult(new RecheckResult(false, "stop")) });
        Assert.Equal(("aborted", "recheck: stop"), (no.Status, no.Reason));
    }

    [Fact]
    public void RecoverNeedsAListingStoreAndWrongOperationIsRefused()
    {
        Assert.Throws<InvalidOperationException>(() => Pca.RecoverOperations(new KvOperationStore(new MemoryAtomicKv())));
        var r = Pca.ExecuteAuthorized(Allowed(), _ => 1, new ExecuteOptions { Store = new MemoryOperationStore(), Operation = new Operation("payments.refund", "/orders/2", null) });
        Assert.Equal(("refused", "executeAuthorized: the authorization is not for this operation (verb, resource or params differ)"), (r.Status, r.Reason));
    }
}
