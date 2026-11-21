using System.Reflection;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 round 3 Stryker survivors of Executor.cs: the constructor guard, the executor's own re-check (driven through its private
/// factory: grant resolution, revocation and plan outcomes with their reason texts, which match server/operations.ts createExecutor), the
/// reversibility-class hook, the pending timeout used to settle a replayed record, the replay-denial conditions, the fail-closed catch-all
/// and the callers' synchronization context never being captured.</summary>
public class K05R3BExecutorTests
{
    // ================= helpers =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_k05r3b_exec";
    static SuiteKey Principal => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray()));
    static SuiteKey Holder => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)8, 32).ToArray()));
    static Operation Op => new("payments.send", "payments/acme", new D { ["amount"] = 5L });

    static D Env() => (D)Pca.ParseJson("""
        {"predicates":[{"resource":"*","verb":"*","where":[]}],"caveats":[],
         "risk_policy":{"bMax":1000,"kappa":1,"lambda":0,"rho":0,"theta1":0.5,"theta2":0.8,"weights":{"alpha":0,"beta":0,"delta":0,"epsilon":0,"gamma":0,"zeta":0}},
         "provenance":{"mode":"insecure_off"}}
        """)!;

    // a PCActn minted by this SDK (principal opt-out of the provenance gate, so only the rules under test decide)
    static (D P, D G) Minted()
    {
        var g = Issue.MintGrant(Principal, Holder.Id!, null, Env(), "k05r3b exec");
        var grant = (D)Pca.ParseStrict(Pca.Canonicalize(g.Grant))!;
        var act = new Agent(Holder, Aud, g.Grant) { Clock = () => Now }.Act(Op.Verb, Op.Resource, new D { ["amount"] = 5L });
        return ((D)Pca.ParseStrict(Issue.Encode(act))!, grant);
    }

    static D WithSigned(D p, string member, object? value)
    {
        p[member] = value;
        p.Remove("sig");
        p["sig"] = Holder.Sign(Pca.ThresholdMessage(p)).Sig;
        return p;
    }

    static AuthorizeInput AzIn(D grant, IStateStore st) => new()
    {
        Audience = Aud, ResolveGrant = _ => grant, StateStore = st, IsRevoked = (_, _) => false, Now = Now, Plan = "single-step",
    };

    static PcaExecutor Exec(AuthorizeInput az, IOperationStore ops, Action<ExecutorOptions>? cfg = null)
    {
        var o = new ExecutorOptions { Operations = ops, Authorize = az, Now = () => Now };
        cfg?.Invoke(o);
        return new PcaExecutor(o);
    }

    static OperationRecord Seed(D p, string state, long startedAt) =>
        new(Pca.HashCanonical(p), state, Op.Verb, Op.Resource, Pca.ParamsDigest(Op.Params), "reversible", startedAt) { Result = "x" };

    // ---- the executor's private re-check
    static Func<ExecutionHandle, Task<RecheckResult>> RecheckOf(ExecutorOptions o) =>
        (Func<ExecutionHandle, Task<RecheckResult>>)typeof(PcaExecutor).GetMethod("Recheck", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(new PcaExecutor(o), null)!;

    static ExecutionHandle Handle(D p) => new("op", new AuthorizedOperation("v", "r", "d", "op"), p);

    static D GrantDoc() => new() { ["id"] = "g1" };

    static ExecutorOptions Opts(Action<AuthorizeInput> cfg, Func<ExecutionHandle, RecheckResult>? extra = null)
    {
        var i = new AuthorizeInput { ResolveGrant = _ => GrantDoc(), IsRevoked = (_, _) => false };
        cfg(i);
        return new ExecutorOptions { Authorize = i, Recheck = extra, Now = () => Now };
    }

    sealed class CountingContext : SynchronizationContext
    {
        public int Posts;
        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref Posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }
    }

    // run's synchronous part sees the context; only an await that captured it posts back
    static async Task<int> PostsDuring(Func<Task> run)
    {
        var ctx = new CountingContext();
        var saved = SynchronizationContext.Current;
        Task t;
        SynchronizationContext.SetSynchronizationContext(ctx);
        try { t = run(); }
        finally { SynchronizationContext.SetSynchronizationContext(saved); }
        await t;
        return ctx.Posts;
    }

    // ================= L34 =================

    [Fact]
    public void ANullOptionsObjectIsRefused()
    {
        var e = Assert.Throws<ArgumentNullException>(() => new PcaExecutor(null!));
        Assert.Equal("options", e.ParamName);
    }

    // ================= L42: a PCActn without a string grant_ref resolves the empty reference =================

    [Fact]
    public async Task ANonStringGrantRefIsResolvedAsTheEmptyString()
    {
        var seen = new List<string>();
        var f = RecheckOf(Opts(i => i.ResolveGrant = r => { seen.Add(r); return GrantDoc(); }));
        Assert.True((await f(Handle(new D()))).Ok);
        Assert.True((await f(Handle(new D { ["grant_ref"] = 5L }))).Ok);
        Assert.True((await f(Handle(new D { ["grant_ref"] = "g1" }))).Ok);
        Assert.Equal(new[] { "", "", "g1" }, seen.ToArray());
    }

    // ================= L46 / L48 / L49: grant resolution =================

    [Fact]
    public async Task AnUnresolvableGrantRefusesTheRecheck()
    {
        var gone = new RecheckResult(false, "the grant is no longer known");
        var cfgs = new Action<AuthorizeInput>[]
        {
            i => i.ResolveGrant = _ => throw new InvalidOperationException("db down"),
            i => i.ResolveGrant = _ => null,
            i => i.ResolveGrant = null,
            i => i.ResolveGrantAsync = _ => throw new InvalidOperationException("db down"),
            i => i.ResolveGrantAsync = _ => Task.FromResult<D?>(null),
            i => i.ResolveGrantAsync = async _ => { await Task.Yield(); throw new InvalidOperationException("late"); },
        };
        foreach (var cfg in cfgs)
            Assert.Equal(gone, await RecheckOf(Opts(cfg))(Handle(new D { ["grant_ref"] = "g" })));
    }

    [Fact]
    public async Task TheGrantResolutionAwaitDoesNotCaptureTheCallersContext()
    {
        var f = RecheckOf(Opts(i =>
        {
            i.ResolveGrant = null;
            i.ResolveGrantAsync = async _ => { await Task.Delay(20).ConfigureAwait(false); return GrantDoc(); };
        }));
        Task<RecheckResult>? t = null;
        Assert.Equal(0, await PostsDuring(() => t = f(Handle(new D { ["grant_ref"] = "g" }))));
        Assert.Equal(RecheckResult.Pass, await t!);
    }

    // ================= L53: revocation =================

    [Fact]
    public async Task ARevocationThatCannotBeCheckedRefusesTheRecheck()
    {
        async Task<RecheckResult> Run(Func<D, D, bool?>? rev) =>
            await RecheckOf(Opts(i => i.IsRevoked = rev))(Handle(new D { ["grant_ref"] = "g" }));
        var unchecked_ = new RecheckResult(false, "revocation could not be checked");
        Assert.Equal(unchecked_, await Run(null));
        Assert.Equal(unchecked_, await Run((_, _) => null));
        Assert.Equal(unchecked_, await Run((_, _) => throw new InvalidOperationException("down")));
        Assert.Equal(new RecheckResult(false, "the grant has been revoked"), await Run((_, _) => true));
        Assert.Equal(RecheckResult.Pass, await Run((_, _) => false));
    }

    // ================= L59 / L60: the registered plan =================

    [Fact]
    public async Task ARegisteredPlanMustStillBeExecutableForItsNode()
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => Now });
        string Draft(string id)
        {
            var t = reg.Draft("g", new List<D> { new() { ["id"] = id, ["verb"] = "v", ["resource"] = "r", ["reversibility_class"] = "reversible" } });
            Assert.True(t.Ok, t.Reason);
            var root = t.Record!.Root;
            var v = reg.Validate("g", root);
            Assert.True(v.Ok, v.Reason);
            var c = reg.Commit("g", root);
            Assert.True(c.Ok, c.Reason);
            return root;
        }
        var committed = Draft("n1");
        var authorized = Draft("n2");
        var a = reg.Authorize("g", authorized, new PlanApproval("principal"));
        Assert.True(a.Ok, a.Reason);

        async Task<RecheckResult> At(string root, string? node)
        {
            var plan = new D { ["root"] = root };
            if (node != null) plan["node_id"] = node;
            return await RecheckOf(Opts(i => i.Plans = reg))(Handle(new D { ["grant_ref"] = "g", ["plan"] = plan }));
        }

        // the reason is the registry's own (server/plan-lifecycle.ts), not a generic "plan is <state>"
        Assert.Equal(new RecheckResult(false, $"plan {committed} is committed but not authorized by the principal"), await At(committed, "n1"));
        // the PCActn's node id is passed to the check: a node the plan does not hold is refused
        Assert.Equal(new RecheckResult(false, $"plan {authorized} has no node 'ghost'"), await At(authorized, "ghost"));
        Assert.Equal(RecheckResult.Pass, await At(authorized, "n2"));
        Assert.Equal(RecheckResult.Pass, await At(authorized, null));
    }

    // ================= L83 / L105: the reversibility-class hook and the catch-all =================

    [Fact]
    public async Task TheServersReversibilityClassOfTheOperationDrivesTheRecheck()
    {
        var (p, g) = Minted();
        Operation? seen = null;
        var op = Op;
        int calls = 0;
        var ex = Exec(AzIn(g, new MemoryStateStore()), new MemoryOperationStore(), o =>
        {
            o.ReversibilityClassOf = op => { seen = op; return "irreversible"; };
            o.Recheck = _ => new RecheckResult(false, "step-up withdrawn");
        });
        var r = await ex.RunAsync(p, op, _ => { calls++; return Task.FromResult<object?>(1); });
        Assert.Equal(("aborted", "recheck: step-up withdrawn"), (r.Status, r.Reason));
        Assert.Equal(0, calls);
        Assert.Same(op, seen);
    }

    [Fact]
    public void TheClassHookIsNotAskedWithoutAnOperation()
    {
        var (p, g) = Minted();
        int asked = 0;
        var ex = Exec(AzIn(g, new MemoryStateStore()), new MemoryOperationStore(), o => o.ReversibilityClassOf = _ => { asked++; return null; });
        var r = ex.Run(p, null, _ => 1);
        Assert.Equal("denied", r.Status);
        Assert.Equal("fail", r.Authorization!.Checks["operation"]);
        Assert.Equal(0, asked);
    }

    [Fact]
    public void AThrowFromTheClassHookRefusesFailClosed()
    {
        var (p, g) = Minted();
        var ex = Exec(AzIn(g, new MemoryStateStore()), new MemoryOperationStore(), o => o.ReversibilityClassOf = _ => throw new InvalidOperationException("boom"));
        var r = ex.Run(p, Op, _ => 1);
        Assert.Equal(("refused", "createExecutor: error (fail closed): boom"), (r.Status, r.Reason));
    }

    // ================= L84: the pending timeout settles the record a replay finds =================

    static ExecuteOutcome Replay(long? timeoutMs, long ageMs)
    {
        var (p, g) = Minted();
        var st = new MemoryStateStore();
        var direct = AzIn(g, st);
        var op = Op;
        direct.Operation = op;
        Assert.True(Pca.Authorize(p, direct).Allow); // the authorization was consumed
        var ops = new MemoryOperationStore();
        ops.Create(Seed(p, OperationStates.Pending, Now - ageMs));
        return Exec(AzIn(g, st), ops, o => o.PendingTimeoutMs = timeoutMs).Run(p, op, _ => 1);
    }

    [Fact]
    public void TheConfiguredPendingTimeoutSettlesAStaleRecord()
    {
        var short1 = Replay(1000, 2000);
        Assert.Equal(("aborted", true, "not started within 1000 ms of the claim: the side effect never ran"), (short1.Status, short1.Replayed, short1.Reason));
        var within = Replay(1000, 500);
        Assert.Equal(("pending", true), (within.Status, within.Replayed));
    }

    [Fact]
    public void TheDefaultPendingTimeoutIsFiveMinutes()
    {
        var young = Replay(null, 2000);
        Assert.Equal(("pending", true), (young.Status, young.Replayed));
        var old = Replay(null, 400_000);
        Assert.Equal(("aborted", true, "not started within 300000 ms of the claim: the side effect never ran"), (old.Status, old.Replayed, old.Reason));
    }

    // ================= L95: only a lone, otherwise-valid replay is answered from the record =================

    [Fact]
    public void ALoneNonReplayFailureIsDeniedEvenWithAMatchingRecord()
    {
        var (p, g) = Minted();
        var ops = new MemoryOperationStore();
        ops.Create(Seed(p, OperationStates.Committed, Now - 1));
        var az = AzIn(g, new MemoryStateStore());
        az.IsRevoked = (_, _) => true;
        int calls = 0;
        var r = Exec(az, ops).Run(p, Op, _ => { calls++; return 1; });
        Assert.Equal("denied", r.Status);
        Assert.False(r.Replayed);
        Assert.Equal("fail", r.Authorization!.Checks["revocation"]);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void ADenialWithNoFailingCheckIsDeniedNotAnError()
    {
        var (p, g) = Minted();
        WithSigned(p, "bond_ref", "bond-1"); // an unsupported feature: denied (403) with no check marked fail
        var r = Exec(AzIn(g, new MemoryStateStore()), new MemoryOperationStore()).Run(p, Op, _ => 1);
        Assert.Equal("denied", r.Status);
        Assert.Equal("unsupported", r.Authorization!.Checks["bond"]);
        Assert.DoesNotContain("fail", r.Authorization.Checks.Values);
    }

    // ================= L81 / L91: neither await captures the caller's synchronization context =================

    [Fact]
    public async Task TheAuthorizationAwaitDoesNotCaptureTheCallersContext()
    {
        var (p, g) = Minted();
        var az = AzIn(g, new MemoryStateStore());
        az.ResolveGrant = null;
        az.ResolveGrantAsync = async _ => { await Task.Delay(20).ConfigureAwait(false); return g; };
        var ex = Exec(az, new MemoryOperationStore());
        Task<ExecuteOutcome>? t = null;
        Assert.Equal(0, await PostsDuring(() => t = ex.RunAsync(p, Op, _ => Task.FromResult<object?>(1))));
        Assert.Equal("committed", (await t!).Status);
    }

    [Fact]
    public async Task TheExecutionAwaitDoesNotCaptureTheCallersContext()
    {
        var (p, g) = Minted();
        var ex = Exec(AzIn(g, new MemoryStateStore()), new MemoryOperationStore());
        Task<ExecuteOutcome>? t = null;
        Assert.Equal(0, await PostsDuring(() => t = ex.RunAsync(p, Op, async _ => { await Task.Delay(20).ConfigureAwait(false); return (object?)"done"; })));
        var o = await t!;
        Assert.Equal(("committed", (object?)"done"), (o.Status, o.Result));
    }
}
