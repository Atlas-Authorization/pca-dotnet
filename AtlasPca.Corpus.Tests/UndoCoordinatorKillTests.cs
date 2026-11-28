using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Behaviour tests of the undo-window coordinator that pin every exact refusal text, record member, notice, alert and boundary of AtlasPca.UndoCoordinator.
// The rig and the helpers live here; the other files of this class (same prefix) hold the compensation, veto/finalize and notifier tests.
public partial class UndoCoordinatorKillTests
{
    const long T0 = 1_800_000_000_000L;
    const string Aud = "rs";
    const string D43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static readonly byte[] Secret = Enumerable.Repeat((byte)0x09, 32).ToArray();
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x01, 32).ToArray()));
    static SuiteKey H => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x02, 32).ToArray()));

    static JD MintGrantOf(params string[] verbs) => Issue.NormJ(Issue.MintGrant(P, H.Id!, null, new JD
    {
        ["predicates"] = new JL(verbs.Select(v => (object?)new JD { ["verb"] = v, ["resource"] = "invoice:*" })),
        ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "pay invoices", "s").Grant);

    static readonly JD Grant = MintGrantOf("pay", "pay.refund");
    static readonly JD PayOnlyGrant = MintGrantOf("pay");

    static JD Op(long amount = 5L) => new() { ["verb"] = "pay", ["resource"] = "invoice:1", ["params"] = new JD { ["amount"] = amount } };

    static JD Action(string? cls = null, long amount = 5L)
    {
        var a = new Agent(H, Aud, Grant, null, 0) { Clock = () => T0 };
        var prms = new JD { ["amount"] = amount };
        if (cls == null) return a.Act("pay", "invoice:1", prms);
        a.CommitPlan(new[] { new JD { ["id"] = "s1", ["verb"] = "pay", ["resource"] = "invoice:1", ["params_digest"] = Pca.ParamsDigest(prms), ["reversibility_class"] = cls } });
        return a.ActNode("s1", prms);
    }

    static JD MakePlan(string verb = "pay.refund", bool target = true, bool targetNull = false, JD? render = null, string? renderDigest = null)
    {
        var comp = new JD { ["verb"] = verb, ["params"] = new JD { ["memo"] = "m" }, ["def_digest"] = D43 };
        if (target) comp["target_param"] = "payment";
        if (targetNull) comp["target_param"] = null;
        var p = new JD { ["def_digest"] = D43, ["compensation"] = comp };
        if (render != null) p["render"] = render;
        if (renderDigest != null) p["render_digest"] = renderDigest;
        return p;
    }

    sealed class PlanEngine(Func<JD, string, JD?> f) : IUndoEngine
    {
        public Task<JD?> PlanAsync(JD operation, string operationId) => Task.FromResult(f(operation, operationId));
    }

    sealed class Notif(Func<UndoNotice, UndoNotifyResult?>? answer = null) : IUndoNotifier
    {
        public readonly List<UndoNotice> Notices = new();
        public Task<UndoNotifyResult> NotifyAsync(UndoNotice n)
        {
            Notices.Add(n);
            return Task.FromResult(answer == null ? new UndoNotifyResult(true) : answer(n)!);
        }
    }

    sealed class RelayOf(Func<IReadOnlyList<UndoRelayedVeto>?> f) : IUndoVetoRelay
    {
        public Task<IReadOnlyList<UndoRelayedVeto>> PendingAsync() => Task.FromResult(f()!);
    }

    sealed class FlakyStore(IUndoStore inner) : IUndoStore
    {
        public int FailNext;
        public int Replaces;
        public bool Durable => inner.Durable;
        public Task<JD?> GetAsync(string id) => inner.GetAsync(id);
        public Task<(bool Created, JD? Record)> CreateAsync(JD record) => inner.CreateAsync(record);
        public Task<List<JD>> ListAsync(UndoQuery query) => inner.ListAsync(query);
        public Task<bool> ReplaceAsync(string id, long expectedVer, JD next)
        {
            if (FailNext > 0) { FailNext--; Replaces++; return Task.FromResult(false); }
            return inner.ReplaceAsync(id, expectedVer, next);
        }
    }

    sealed class HookStore(IUndoStore inner) : IUndoStore
    {
        public int Gets;
        public Func<int, JD?, JD?>? OnGet;
        public bool Durable => inner.Durable;
        public async Task<JD?> GetAsync(string id)
        {
            var r = await inner.GetAsync(id);
            Gets++;
            return OnGet != null ? OnGet(Gets, r) : r;
        }
        public Task<(bool Created, JD? Record)> CreateAsync(JD record) => inner.CreateAsync(record);
        public Task<List<JD>> ListAsync(UndoQuery query) => inner.ListAsync(query);
        public Task<bool> ReplaceAsync(string id, long expectedVer, JD next) => inner.ReplaceAsync(id, expectedVer, next);
    }

    sealed class HookOps(IOperationStore inner) : IOperationStore
    {
        public Func<string, string, OperationRecord, bool?>? Transitioning;
        public (bool Created, OperationRecord? Existing) Create(OperationRecord record) => inner.Create(record);
        public OperationRecord? Get(string id) => inner.Get(id);
        public bool Transition(string id, string from, OperationRecord next) => Transitioning?.Invoke(id, from, next) ?? inner.Transition(id, from, next);
    }

    sealed class Ledger : IBudgetLedger
    {
        public readonly List<(string Key, string Id)> Commits = new();
        public readonly List<(string Key, string Id, JD? Evidence)> Releases = new();
        public Func<string, string, BudgetSettleOutcome>? OnCommit;
        public Func<string, string, BudgetSettleOutcome>? OnRelease;
        public bool Durable => true;
        public BudgetSnapshot Snapshot(string key) => throw new NotSupportedException();
        public BudgetReserveOutcome Reserve(string key, BudgetReserveRequest req) => throw new NotSupportedException();
        public BudgetSettleOutcome Start(string key, string id) => throw new NotSupportedException();
        public BudgetSettleOutcome Commit(string key, string id)
        {
            Commits.Add((key, id));
            return OnCommit != null ? OnCommit(key, id) : new BudgetSettleOutcome("settled", 1, null);
        }
        public BudgetSettleOutcome Release(string key, string id, JD? evidence)
        {
            Releases.Add((key, id, evidence));
            return OnRelease != null ? OnRelease(key, id) : new BudgetSettleOutcome("settled", 1, null);
        }
        public BudgetExpired Expire(string key, long now) => throw new NotSupportedException();
    }

    sealed class Rig
    {
        public long T = T0;
        public readonly List<UndoCompensationCall> Calls = new();
        public readonly List<UndoAlert> Alerts = new();
        public Notif N = null!;
        public IUndoStore Store = null!;
        public IOperationStore Ops = null!;
        public Func<string, JD, Task<JD?>> Resolve = (_, _) => Task.FromResult<JD?>(Grant);
        public Func<UndoCompensationCall, Task<object?>> Comp = _ => Task.FromResult<object?>(new JD { ["refund"] = "r1" });
        public UndoCoordinator C = null!;
        public IUndoNotifier? Notifier;
    }

    static Rig Make(Func<UndoNotice, UndoNotifyResult?>? notify = null, IUndoStore? store = null, IOperationStore? ops = null, IUndoEngine? engine = null,
        Func<JD, JD, Task<UndoPolicy?>>? policy = null, IUndoVetoRelay? relay = null, UndoBudget? budget = null, Func<JD, string?>? resolveTarget = null,
        UndoWindowBounds? window = null, long? effectTimeout = null, Func<UndoAlert, Task>? alert = null, IReadOnlyDictionary<string, string>? pqPins = null)
    {
        var rig = new Rig();
        rig.N = new Notif(notify);
        rig.Store = store ?? new MemoryUndoStore();
        rig.Ops = ops ?? new MemoryOperationStore();
        var o = new UndoCoordinatorOptions
        {
            Store = rig.Store, Engine = engine ?? new PlanEngine((_, _) => MakePlan()), SignerSecret = Secret, Audience = Aud,
            ResolveGrant = (r, pc) => rig.Resolve(r, pc),
            Compensate = call => { rig.Calls.Add(call); return rig.Comp(call); },
            Operations = rig.Ops, Notifier = rig.N,
            Alert = alert ?? (a => { rig.Alerts.Add(a); return Task.CompletedTask; }),
            Now = () => rig.T, InsecureVolatileStore = true, Policy = policy, Relay = relay, Budget = budget, ResolveTarget = resolveTarget, Window = window, PqPins = pqPins,
        };
        if (effectTimeout != null) o.EffectTimeoutMs = effectTimeout.Value;
        rig.C = Pca.CreateUndoCoordinator(o);
        return rig;
    }

    static async Task<(UndoAdmitted Adm, UndoWindowInfo Info)> OpenOne(Rig rig, bool effect = true, bool converted = false, long amount = 5L)
    {
        var adm = await rig.C.AdmitAsync(Action(null, amount), Op(amount), converted, Grant);
        Assert.Null(adm.Refused);
        var info = await rig.C.OpenAsync(adm.Admission!);
        if (effect) await rig.C.RecordEffectAsync(adm.Admission!.Id, new JD { ["id"] = "pay_1" }, true);
        return (adm.Admission!, info);
    }

    static string State(JD? r) => (string)r!["state"]!;
    static JD Sub(JD? r, string k) => (JD)r![k]!;
    static long Lg(object? v) => IntentJs.Lng(v);
    static Task<VetoResult> VetoBy(Rig rig, string id, string by = "ops") => rig.C.VetoAsync(id, UndoVetoBy.OperatorId(by));
    static string OpId(JD rec) => Pca.HashCanonical(new JD { ["d"] = "atlas-pca/undo-compensation-op/v1", ["record"] = rec["id"], ["attempt"] = rec["attempt"] });
    static List<string> Events(JD rec) => ((JL)rec["receipts"]!).Select(r => (string)((JD)r!)["event"]!).ToList();

    // ---------------------------------------------------------------------------------------------------------------- defaults and clock

    [Fact]
    public void TheOptionAndAdmissionDefaults()
    {
        Assert.Equal(300_000L, new UndoCoordinatorOptions().EffectTimeoutMs);
        Assert.Equal("", new UndoAdmitted().Id);
        Assert.Empty(new UndoAdmitted().Plan);
        Assert.Equal(60_000L, UndoCoordinator.RelayGraceMs);
    }

    [Fact]
    public async Task AClockOutsideTheSafeRangeFailsAdmissionClosed()
    {
        var rig = Make();
        const string msg = "undo admission error (fail closed): invalid: the clock returned a non-finite time";
        rig.T = Pca.MaxSafeInt + 1;
        Assert.Equal(msg, (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        rig.T = -Pca.MaxSafeInt - 1;
        Assert.Equal(msg, (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        rig.T = Pca.MaxSafeInt;
        Assert.DoesNotContain("non-finite", (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Refused ?? "");
        rig.T = -Pca.MaxSafeInt;
        Assert.DoesNotContain("non-finite", (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Refused ?? "");
    }

    // ---------------------------------------------------------------------------------------------------------------- admission

    [Fact]
    public async Task AnAdmissionCarriesEveryTermOfTheWindow()
    {
        var seen = new List<(JD Op, string Id)>();
        var rig = Make(engine: new PlanEngine((o, id) => { seen.Add((o, id)); return MakePlan(); }));
        var pc = Action();
        var op = Op();
        var res = await rig.C.AdmitAsync(pc, op, true, Grant);
        Assert.Null(res.Refused);
        var a = res.Admission!;
        var id = Pca.HashCanonical(pc);
        Assert.Equal(id, a.Id);
        var (sop, sid) = Assert.Single(seen);
        Assert.Same(op, sop);
        Assert.Equal(id, sid);
        Assert.Equal(T0, a.OpenedAt);
        Assert.Equal(T0 + 900_000, a.WindowEnd);
        Assert.True(a.Converted);
        Assert.Same(pc, a.Pcactn);
        Assert.Same(Grant, a.Grant);
        Assert.Equal(D43, a.Plan["def_digest"]);
        Assert.Equal(new[] { "verb", "resource", "params", "undo_of", "def_digest", "target_param" }, a.Compensation.Keys.ToArray());
        Assert.Equal("pay.refund", a.Compensation["verb"]);
        Assert.Equal("invoice:1", a.Compensation["resource"]);
        Assert.Equal("m", Sub(a.Compensation, "params")["memo"]);
        Assert.Equal(id, a.Compensation["undo_of"]);
        Assert.Equal(D43, a.Compensation["def_digest"]);
        Assert.Equal("payment", a.Compensation["target_param"]);
        Assert.Equal("pay", a.Operation["verb"]);
        Assert.Equal("invoice:1", a.Operation["resource"]);
        Assert.Equal(5L, Lg(Sub(a.Operation, "params")["amount"]));
        Assert.Equal(new UndoAdmission(id, a.WindowEnd, new UndoCompensationRef("pay.refund", "invoice:1")), a.ToAdmission());
        var plain = await rig.C.AdmitAsync(pc, new JD { ["verb"] = "pay", ["resource"] = "invoice:1" }, false, Grant);
        Assert.False(plain.Admission!.Converted);
        Assert.Empty(Sub(plain.Admission!.Operation, "params"));
    }

    [Fact]
    public async Task AnAbsentOrNullTargetParamIsNotCopiedIntoTheCompensation()
    {
        foreach (var plan in new[] { MakePlan(target: false), MakePlan(targetNull: true) })
        {
            var rig = Make(engine: new PlanEngine((_, _) => plan));
            var a = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
            Assert.False(a.Compensation.ContainsKey("target_param"));
        }
    }

    [Fact]
    public async Task EveryAdmissionRefusalHasItsExactText()
    {
        var rig = Make();
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), new JD { ["resource"] = "invoice:1" }, false, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), new JD { ["verb"] = "pay" }, false, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), new JD { ["verb"] = 5L, ["resource"] = "invoice:1" }, false, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), new JD { ["verb"] = "pay", ["resource"] = 5L }, false, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(null!, Op(), false, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), null!, false, Grant)).Refused);
        Assert.Equal("the signed class is irreversible", (await rig.C.AdmitAsync(Action("irreversible"), Op(), false, Grant)).Refused);
        Assert.Equal("not confirmed reversible, or no confirmed compensating action", (await Make(engine: new PlanEngine((_, _) => null)).C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        var off = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy("off")));
        Assert.Equal("policy: undo windows are off", (await off.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        var esc = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy("escalations")));
        Assert.Equal("policy: windows only replace approvals", (await esc.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        Assert.Null((await esc.C.AdmitAsync(Action(), Op(), true, Grant)).Refused);
        var odd = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy("anything else")));
        Assert.Null((await odd.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
    }

    [Fact]
    public async Task ADeniedCompensationNamesTheRealReasonNotTheFallback()
    {
        var rig = Make(engine: new PlanEngine((_, _) => MakePlan("admin.delete")));
        var refused = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Refused!;
        const string pre = "the compensating action is not authorized under the grant: ";
        Assert.StartsWith(pre, refused);
        var why = refused[pre.Length..];
        Assert.NotEmpty(why);
        Assert.False(why.StartsWith("risk input", StringComparison.Ordinal));
        Assert.NotEqual("the grant does not authorize the compensating action", why);
    }

    [Fact]
    public async Task AnAdmissionErrorFailsClosedWithTheMessageOrUnknown()
    {
        var boom = Make(engine: new PlanEngine((_, _) => throw new InvalidOperationException("engine down")));
        Assert.Equal("undo admission error (fail closed): engine down", (await boom.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        var mute = Make(engine: new PlanEngine((_, _) => throw new InvalidOperationException("")));
        Assert.Equal("undo admission error (fail closed): unknown", (await mute.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
    }

    [Fact]
    public async Task TheGrantIsResolvedByReferenceOnlyWhenNoneIsGiven()
    {
        var rig = Make();
        var refs = new List<(string, JD)>();
        rig.Resolve = (r, pc) => { refs.Add((r, pc)); return Task.FromResult<JD?>(Grant); };
        var pc = Action();
        var ok = await rig.C.AdmitAsync(pc, Op(), false);
        Assert.Null(ok.Refused);
        Assert.Same(Grant, ok.Admission!.Grant);
        var (r0, p0) = Assert.Single(refs);
        Assert.Equal((string)pc["grant_ref"]!, r0);
        Assert.Same(pc, p0);
        rig.Resolve = (_, _) => Task.FromResult<JD?>(null);
        Assert.Equal("unknown grant", (await rig.C.AdmitAsync(pc, Op(), false)).Refused);
        rig.Resolve = (_, _) => throw new InvalidOperationException("never called");
        Assert.Null((await rig.C.AdmitAsync(pc, Op(), false, Grant)).Refused);
    }

    [Fact]
    public async Task ThePolicySeesTheOperationAndTheGrantAndTheWindowIsClamped()
    {
        var seen = new List<(JD, JD)>();
        var rig = Make(policy: (o, g) => { seen.Add((o, g)); return Task.FromResult<UndoPolicy?>(new UndoPolicy("always", 120_000L)); });
        var op = Op();
        var res = await rig.C.AdmitAsync(Action(), op, false, Grant);
        var (so, sg) = Assert.Single(seen);
        Assert.Same(op, so);
        Assert.Same(Grant, sg);
        Assert.Equal(T0 + 120_000, res.Admission!.WindowEnd);

        var nul = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(null));
        Assert.Equal(T0 + 900_000, (await nul.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!.WindowEnd);

        var bounds = new UndoWindowBounds(MinMs: 60_000, MaxMs: 600_000, DefaultMs: 100_000);
        Assert.Equal(T0 + 100_000, (await Make(window: bounds).C.AdmitAsync(Action(), Op(), false, Grant)).Admission!.WindowEnd);
        var low = Make(window: bounds, policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy(null, 10_000L)));
        Assert.Equal(T0 + 60_000, (await low.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!.WindowEnd);
        var high = Make(window: bounds, policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy(null, 9_999_999L)));
        Assert.Equal(T0 + 600_000, (await high.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!.WindowEnd);
    }

    // ---------------------------------------------------------------------------------------------------------------- open

    [Fact]
    public async Task OpeningWritesTheFullDurableRecord()
    {
        var render = new JD { ["lines"] = "x" };
        var rig = Make(engine: new PlanEngine((_, _) => MakePlan(render: render, renderDigest: "RD")));
        var adm = (await rig.C.AdmitAsync(Action(), Op(), true, Grant)).Admission!;
        var info = await rig.C.OpenAsync(adm);
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.Equal(1L, Lg(rec["v"]));
        Assert.Equal(adm.Id, rec["id"]);
        Assert.Equal(Aud, rec["aud"]);
        Assert.Equal(adm.Pcactn["grant_ref"], rec["grant_ref"]);
        Assert.Equal(H.Id, rec["holder"]);
        Assert.Equal(Grant["issuer"], rec["principal"]);
        var act = Sub(rec, "action");
        Assert.Equal("pay", act["verb"]);
        Assert.Equal("invoice:1", act["resource"]);
        Assert.Equal(Sub(adm.Pcactn, "action")["params_digest"], act["params_digest"]);
        Assert.Equal(D43, act["def_digest"]);
        Assert.Equal(UndoWindows.CompensationDigest(adm.Compensation), rec["compensation_digest"]);
        Assert.Equal("pay.refund", Sub(rec, "compensation")["verb"]);
        Assert.Equal("RD", rec["render_digest"]);
        Assert.Equal(T0, Lg(rec["opened_at"]));
        Assert.Equal(adm.WindowEnd, Lg(rec["window_end"]));
        Assert.Equal(true, rec["converted"]);
        Assert.Equal("open", rec["state"]);
        Assert.Equal(0L, Lg(rec["ver"]));
        Assert.Equal(0L, Lg(rec["attempt"]));
        Assert.Equal(Pca.Canonicalize(adm.Pcactn), rec["pcactn"]);
        Assert.False(rec.ContainsKey("bond_ref"));
        var receipt = Assert.Single((JL)rec["receipts"]!);
        var r0 = (JD)receipt!;
        Assert.Equal("opened", r0["event"]);
        Assert.Equal("open", r0["state"]);
        Assert.Equal("converted", r0["note"]);
        Assert.Equal(T0, Lg(r0["at"]));
        Assert.Equal("", r0["prev"]);
        var n = Assert.Single(rig.N.Notices);
        Assert.Equal("opened", n.Kind);
        Assert.Equal(info.Token, n.Token);
        Assert.Same(render, n.Render);
        Assert.Equal(info.Token, UndoWindows.EncodeToken(UndoWindows.SignToken(rec, Secret)));
    }

    [Fact]
    public async Task APlainWindowHasNoRenderBondOrConvertedNote()
    {
        var rig = Make(engine: new PlanEngine((_, _) => MakePlan(render: new JD { ["lines"] = "x" })));
        var (adm, _) = await OpenOne(rig, false);
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.False(rec.ContainsKey("render_digest"));
        Assert.False(rec.ContainsKey("bond_ref"));
        Assert.Equal(false, rec["converted"]);
        Assert.Equal("", ((JD)((JL)rec["receipts"]!)[0]!)["note"]);
        Assert.NotNull(rig.N.Notices[0].Render);
        var none = Make();
        await OpenOne(none, false);
        Assert.Null(none.N.Notices[0].Render);
    }

    [Fact]
    public async Task ABondExtendsTheWindowOnlyWhenBothBondTermsAreGiven()
    {
        async Task<(UndoAdmitted, JD, UndoWindowInfo)> Run(string? bond, double? ends)
        {
            var rig = Make();
            var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
            var info = await rig.C.OpenAsync(adm, bond, ends);
            return (adm, (await rig.C.GetAsync(adm.Id))!, info);
        }
        var (a1, r1, i1) = await Run("claim1", a0End() + 5000.7);
        Assert.Equal(a1.WindowEnd + 5000, Lg(r1["window_end"]));
        Assert.Equal(a1.WindowEnd + 5000, i1.WindowEnd);
        Assert.Equal("claim1", r1["bond_ref"]);
        var (a2, r2, _) = await Run("claim1", T0 + 1000);
        Assert.Equal(a2.WindowEnd, Lg(r2["window_end"]));
        Assert.Equal("claim1", r2["bond_ref"]);
        var (a3, r3, _) = await Run("claim1", null);
        Assert.Equal(a3.WindowEnd, Lg(r3["window_end"]));
        Assert.Equal("claim1", r3["bond_ref"]);
        var (a4, r4, _) = await Run(null, a0End() + 5000);
        Assert.Equal(a4.WindowEnd, Lg(r4["window_end"]));
        Assert.False(r4.ContainsKey("bond_ref"));
    }

    static double a0End() => T0 + 900_000;

    [Fact]
    public async Task ReopeningTheSameAdmissionReturnsTheSameWindowWithoutANewNotice()
    {
        var rig = Make();
        var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
        var first = await rig.C.OpenAsync(adm);
        var again = await rig.C.OpenAsync(adm);
        Assert.Equal(first.Token, again.Token);
        Assert.Equal(first.WindowEnd, again.WindowEnd);
        Assert.Single(rig.N.Notices);
        Assert.Equal(new[] { "opened" }, Events((await rig.C.GetAsync(adm.Id))!));
    }

    [Fact]
    public async Task ReopeningWithOtherTermsOrAfterTheWindowMovedOnIsRefused()
    {
        var rig = Make();
        var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
        await rig.C.OpenAsync(adm);
        var other = new UndoAdmitted
        {
            Id = adm.Id, OpenedAt = adm.OpenedAt, WindowEnd = adm.WindowEnd, Converted = false, Plan = adm.Plan, Pcactn = adm.Pcactn, Grant = adm.Grant, Operation = adm.Operation,
            Compensation = new JD(adm.Compensation) { ["verb"] = "pay.other" },
        };
        var e = await Assert.ThrowsAsync<UndoError>(() => rig.C.OpenAsync(other));
        Assert.Equal("invalid: undo record " + adm.Id + " already exists with other terms or state open", e.Message);
        await rig.C.RecordEffectAsync(adm.Id, new JD { ["id"] = "p" }, true);
        await VetoBy(rig, adm.Id);
        var moved = await Assert.ThrowsAsync<UndoError>(() => rig.C.OpenAsync(adm));
        Assert.Equal("invalid: undo record " + adm.Id + " already exists with other terms or state compensated", moved.Message);
    }

    [Fact]
    public async Task TheWindowInfoMatchesTheRecordAndTheObligation()
    {
        var rig = Make();
        var adm = (await rig.C.AdmitAsync(Action(), Op(), true, Grant)).Admission!;
        var info = await rig.C.OpenAsync(adm);
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.Equal(adm.Id, info.Id);
        Assert.Equal(adm.WindowEnd, info.WindowEnd);
        Assert.True(info.Converted);
        Assert.Equal("pay.refund", info.CompensationVerb);
        Assert.Equal("invoice:1", info.CompensationResource);
        Assert.Equal("ok", UndoWindows.TokenCheck(UndoWindows.DecodeToken(info.Token), rig.C.SignerPublic, rec, IntentJs.OfLong(T0)));
        Assert.Equal(Pca.Canonicalize(UndoWindows.Obligation(adm.ToAdmission())), Pca.Canonicalize(info.Obligation));
        var plain = Make();
        var (_, pinfo) = await OpenOne(plain, false);
        Assert.False(pinfo.Converted);
    }

    [Fact]
    public async Task AWindowNobodyWasToldAboutIsAbortedWithTheExactReason()
    {
        var cases = new (Func<UndoNotice, UndoNotifyResult?> Answer, string Why)[]
        {
            (_ => null, "no channel delivered the notice"),
            (_ => new UndoNotifyResult(false), "no channel delivered the notice"),
            (_ => new UndoNotifyResult(false, "no channel"), "no channel"),
            (_ => throw new InvalidOperationException("boom"), "boom"),
            (_ => throw new InvalidOperationException(""), "notifier error"),
        };
        foreach (var (answer, why) in cases)
        {
            var rig = Make(answer);
            var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
            var e = await Assert.ThrowsAsync<UndoError>(() => rig.C.OpenAsync(adm));
            Assert.Equal("invalid: notify_failed: the undo window could not be announced (" + why + ")", e.Message);
            var a = Assert.Single(rig.Alerts);
            Assert.Equal(new UndoAlert("critical", "notify_failed", adm.Id, "the principal could not be told about the undo window: " + why), a);
            var rec = (await rig.C.GetAsync(adm.Id))!;
            Assert.Equal("finalized", State(rec));
            Assert.Equal("aborted", Sub(rec, "outcome")["status"]);
            Assert.Equal("notify_failed", Sub(rec, "outcome")["reason"]);
            Assert.Equal(new[] { "opened", "aborted" }, Events(rec));
        }
    }

    [Fact]
    public async Task AnAlertSinkThatThrowsIsWrittenToStandardErrorNotRaised()
    {
        var rig = Make(_ => new UndoNotifyResult(false, "no channel"), alert: _ => throw new InvalidOperationException("sink down"));
        var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
        var prev = Console.Error;
        var sw = new StringWriter();
        Console.SetError(sw);
        try
        {
            var e = await Assert.ThrowsAsync<UndoError>(() => rig.C.OpenAsync(adm));
            Assert.StartsWith("invalid: notify_failed", e.Message);
        }
        finally { Console.SetError(prev); }
        Assert.Contains("pca undo alert (notify_failed) for " + adm.Id + ": the principal could not be told about the undo window: no channel", sw.ToString());
    }

    [Fact]
    public async Task NoticesCarryTheStrippedRecordInOrder()
    {
        var rig = Make();
        var (adm, info) = await OpenOne(rig);
        rig.T = T0 + 1_000;
        Assert.True((await VetoBy(rig, adm.Id)).Ok);
        Assert.Equal(new[] { "opened", "vetoed", "compensated" }, rig.N.Notices.Select(n => n.Kind).ToArray());
        Assert.Equal(info.Token, rig.N.Notices[0].Token);
        Assert.Null(rig.N.Notices[1].Token);
        Assert.Null(rig.N.Notices[2].Token);
        Assert.Equal(new[] { "open", "vetoed", "compensated" }, rig.N.Notices.Select(n => State(n.Record)).ToArray());
        foreach (var n in rig.N.Notices)
        {
            Assert.False(n.Record.ContainsKey("pcactn"));
            Assert.False(n.Record.ContainsKey("receipts"));
            Assert.Equal(adm.Id, n.Record["id"]);
            Assert.True(n.Record.ContainsKey("action"));
            Assert.True(n.Record.ContainsKey("compensation"));
            Assert.True(n.Record.ContainsKey("grant_ref"));
        }
    }

    [Fact]
    public async Task TheSignerKeyIsCopiedAndPublished()
    {
        var seed = (byte[])Secret.Clone();
        var rig = new Rig();
        rig.C = Pca.CreateUndoCoordinator(new UndoCoordinatorOptions
        {
            Store = new MemoryUndoStore(), Engine = new PlanEngine((_, _) => MakePlan()), SignerSecret = seed, Audience = Aud, ResolveGrant = (_, _) => Task.FromResult<JD?>(Grant),
            Compensate = _ => Task.FromResult<object?>(null), Operations = new MemoryOperationStore(), Notifier = new Notif(), Alert = _ => Task.CompletedTask,
            Now = () => rig.T, InsecureVolatileStore = true,
        });
        Array.Clear(seed);
        Assert.Equal(UndoNotifiers.SignerPublic(Secret), rig.C.SignerPublic);
        var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
        var info = await rig.C.OpenAsync(adm);
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.Equal("ok", UndoWindows.TokenCheck(UndoWindows.DecodeToken(info.Token), rig.C.SignerPublic, rec, IntentJs.OfLong(T0)));
        Assert.Null(UndoWindows.ReceiptChainError(rec, rig.C.SignerPublic));
    }

    // ---------------------------------------------------------------------------------------------------------------- apply, effect, abort, hold

    [Fact]
    public async Task AnUnknownRecordAndARefusedTransitionRaiseTheirExactErrors()
    {
        var rig = Make();
        var e = await Assert.ThrowsAsync<UndoError>(() => rig.C.RecordEffectAsync("nope"));
        Assert.Equal("invalid: unknown: no undo record nope", e.Message);
        var (adm, _) = await OpenOne(rig);
        var r = await Assert.ThrowsAsync<UndoError>(() => rig.C.AbortAsync(adm.Id, "late"));
        Assert.Equal("invalid: effect_recorded: the effect ran: it can only be compensated or finalized", r.Message);
        var c = await Assert.ThrowsAsync<UndoError>(() => rig.C.CompensateAsync("nope"));
        Assert.Equal("invalid: no undo record nope", c.Message);
        var t = await Assert.ThrowsAsync<UndoError>(() => rig.C.RetryAsync(adm.Id));
        Assert.Equal("invalid: not_failed: a open record is not retried", t.Message);
        Assert.Equal("open", State(await rig.C.CompensateAsync(adm.Id)));
        Assert.Empty(rig.Calls);
    }

    [Fact]
    public async Task TheEffectReportRecordsTheResultOnlyWhenOneWasGiven()
    {
        async Task<JD> Effect(Func<UndoCoordinator, string, Task> report)
        {
            var rig = Make();
            var (adm, _) = await OpenOne(rig, false);
            await report(rig.C, adm.Id);
            return Sub((await rig.C.GetAsync(adm.Id))!, "effect");
        }
        var none = await Effect((c, id) => c.RecordEffectAsync(id));
        Assert.False(none.ContainsKey("result"));
        Assert.Equal(T0, Lg(none["at"]));
        var nullFlag = await Effect((c, id) => c.RecordEffectAsync(id, null, true));
        Assert.True(nullFlag.ContainsKey("result"));
        Assert.Null(nullFlag["result"]);
        var implicitResult = await Effect((c, id) => c.RecordEffectAsync(id, new JD { ["id"] = "x" }));
        Assert.Equal("x", Sub(implicitResult, "result")["id"]);
    }

    [Fact]
    public async Task AbortingFinalizesOnceAndReleasesTheHeldBudgetWithTheRightReason()
    {
        var ledger = new Ledger();
        var seen = new List<(string Key, string How)>();
        var rig = Make(budget: new UndoBudget(ledger, (r, how) => { seen.Add(((string)r["key"]!, how)); return null; }));
        var (adm, _) = await OpenOne(rig, false);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("principal/p", "res1") });
        var rec = await rig.C.AbortAsync(adm.Id, "effect_failed");
        Assert.Equal("finalized", State(rec));
        Assert.Equal("aborted", Sub(rec, "outcome")["status"]);
        Assert.Equal("effect_failed", Sub(rec, "outcome")["reason"]);
        var rel = Assert.Single(ledger.Releases);
        Assert.Equal("principal/p", rel.Key);
        Assert.Equal("res1", rel.Id);
        Assert.Null(rel.Evidence);
        var evSeen = Assert.Single(seen);
        Assert.Equal("principal/p", evSeen.Key);
        Assert.Equal("effect_not_run", evSeen.How);
        var again = await rig.C.AbortAsync(adm.Id, "effect_failed");
        Assert.Equal("finalized", State(again));
        Assert.Single(ledger.Releases);
        Assert.Empty(ledger.Commits);
    }

    [Fact]
    public async Task HeldBudgetIsAddedVersionedAndOnlyForLiveRecords()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig, false);
        var h1 = await rig.C.HoldBudgetAsync(adm.Id, new[] { ("k1", "a") });
        Assert.Equal(1L, Lg(h1["ver"]));
        var h2 = await rig.C.HoldBudgetAsync(adm.Id, new[] { ("k2", "b"), ("k3", "c") });
        Assert.Equal(2L, Lg(h2["ver"]));
        var list = ((JL)h2["budget"]!).Cast<JD>().Select(d => (string)d["key"]! + "/" + (string)d["id"]!).ToArray();
        Assert.Equal(new[] { "k1/a", "k2/b", "k3/c" }, list);
        Assert.Equal(2L, Lg((await rig.C.GetAsync(adm.Id))!["ver"]));
        var missing = await Assert.ThrowsAsync<UndoError>(() => rig.C.HoldBudgetAsync("nope", new[] { ("k", "i") }));
        Assert.Equal("invalid: no undo record nope", missing.Message);
        await rig.C.AbortAsync(adm.Id, "x");
        var closed = await Assert.ThrowsAsync<UndoError>(() => rig.C.HoldBudgetAsync(adm.Id, new[] { ("k", "i") }));
        Assert.Equal("invalid: a finalized record holds no budget", closed.Message);
        var v = Make();
        var (vadm, _) = await OpenOne(v, false);
        await VetoBy(v, vadm.Id);
        Assert.Equal("vetoed", State(await v.C.GetAsync(vadm.Id)));
        var before = Lg((await v.C.GetAsync(vadm.Id))!["ver"]);
        Assert.Equal(before + 1, Lg((await v.C.HoldBudgetAsync(vadm.Id, new[] { ("k", "i") }))["ver"]));
    }

    [Fact]
    public async Task AConflictingWriterIsRetriedExactlySixtyFourTimes()
    {
        var flaky = new FlakyStore(new MemoryUndoStore());
        var rig = Make(store: flaky);
        var (adm, _) = await OpenOne(rig, false);
        flaky.FailNext = 63;
        await rig.C.RecordEffectAsync(adm.Id);
        Assert.Equal(63, flaky.Replaces);
        Assert.Equal(1L, Lg((await rig.C.GetAsync(adm.Id))!["ver"]));

        var (adm2, _) = await OpenOne(rig, false, amount: 6);
        flaky.FailNext = 64;
        var e = await Assert.ThrowsAsync<UndoError>(() => rig.C.RecordEffectAsync(adm2.Id));
        Assert.Equal("conflict_exhausted: undo record " + adm2.Id + " kept changing", e.Message);
        Assert.Equal(0, flaky.FailNext);
        Assert.Equal(0L, Lg((await rig.C.GetAsync(adm2.Id))!["ver"]));

        flaky.FailNext = 63;
        await rig.C.HoldBudgetAsync(adm2.Id, new[] { ("k", "i") });
        Assert.Equal(1L, Lg((await rig.C.GetAsync(adm2.Id))!["ver"]));
        flaky.FailNext = 64;
        var h = await Assert.ThrowsAsync<UndoError>(() => rig.C.HoldBudgetAsync(adm2.Id, new[] { ("k", "j") }));
        Assert.Equal("conflict_exhausted: undo record " + adm2.Id + " kept changing", h.Message);
        Assert.Equal(1L, Lg((await rig.C.GetAsync(adm2.Id))!["ver"]));
    }

    // ---------------------------------------------------------------------------------------------------------------- budget settlement

    [Fact]
    public async Task FinalizingCommitsEveryReservationAndAlertsOnlyOnFailures()
    {
        var ledger = new Ledger { OnCommit = (k, i) => i == "bad" ? new BudgetSettleOutcome("refused", 1, null) : i == "again" ? new BudgetSettleOutcome("replayed", 1, null) : new BudgetSettleOutcome("settled", 1, null) };
        var rig = Make(budget: new UndoBudget(ledger));
        var (adm, _) = await OpenOne(rig);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("kA", "bad"), ("kB", "again"), ("kC", "fine") });
        rig.T = adm.WindowEnd + 1;
        Assert.Equal(new[] { adm.Id }, await rig.C.FinalizeDueAsync());
        Assert.Equal(new[] { "kA/bad", "kB/again", "kC/fine" }, ledger.Commits.Select(c => c.Key + "/" + c.Id).ToArray());
        Assert.Empty(ledger.Releases);
        Assert.Equal(new UndoAlert("warning", "budget_settle_failed", adm.Id, "commit of kA/bad: refused"), Assert.Single(rig.Alerts));
    }

    [Fact]
    public async Task ALedgerThatThrowsRaisesAnAlertAndTheRestStillSettle()
    {
        var ledger = new Ledger { OnCommit = (k, i) => i == "x" ? throw new InvalidOperationException("ledger down") : i == "y" ? throw new InvalidOperationException("") : new BudgetSettleOutcome("settled", 1, null) };
        var rig = Make(budget: new UndoBudget(ledger));
        var (adm, _) = await OpenOne(rig);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("k", "x"), ("k", "y"), ("k", "z") });
        rig.T = adm.WindowEnd + 1;
        await rig.C.FinalizeDueAsync();
        Assert.Equal(3, ledger.Commits.Count);
        Assert.Equal(new[] { "commit of k/x: ledger down", "commit of k/y: error" }, rig.Alerts.Select(a => a.Reason).ToArray());
        Assert.All(rig.Alerts, a => { Assert.Equal("warning", a.Level); Assert.Equal("budget_settle_failed", a.Code); Assert.Equal(adm.Id, a.Record); });
    }

    [Fact]
    public async Task ARollbackReleaseFailureIsAlertedWithTheRollbackWording()
    {
        var ledger = new Ledger { OnRelease = (_, _) => new BudgetSettleOutcome("refused", 1, null) };
        var rig = Make(budget: new UndoBudget(ledger));
        var (adm, _) = await OpenOne(rig);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("k", "i") });
        Assert.True((await VetoBy(rig, adm.Id)).Ok);
        Assert.Equal("rollback of k/i: refused", Assert.Single(rig.Alerts).Reason);
        var thrown = new Ledger { OnRelease = (_, _) => throw new InvalidOperationException("boom") };
        var rig2 = Make(budget: new UndoBudget(thrown));
        var (adm2, _) = await OpenOne(rig2);
        await rig2.C.HoldBudgetAsync(adm2.Id, new[] { ("k", "i") });
        Assert.True((await VetoBy(rig2, adm2.Id)).Ok);
        Assert.Equal("rollback of k/i: boom", Assert.Single(rig2.Alerts).Reason);
    }

    [Fact]
    public async Task WithoutALedgerOrAHeldReservationNothingIsSettled()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("k", "i") });
        var v = await VetoBy(rig, adm.Id);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("compensated", State(v.Record));
        var ledger = new Ledger();
        var held = Make(budget: new UndoBudget(ledger));
        var (a2, _) = await OpenOne(held);
        Assert.True((await VetoBy(held, a2.Id)).Ok);
        Assert.Empty(ledger.Releases);
        Assert.Empty(ledger.Commits);
    }
}
