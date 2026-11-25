using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The undo-window coordinator (AtlasPca.UndoCoordinator): admission, the durable record, the one-click veto, the compensation at most once,
// finalization, the veto relay and every fail-closed refusal. Hand-written: no shared corpus exists for the coordinator in any language.
public class UndoCoordinatorTests
{
    const long T0 = 1_800_000_000_000L;
    const string Aud = "rs";
    const string D43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static readonly byte[] Secret = Enumerable.Repeat((byte)0x09, 32).ToArray();
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x01, 32).ToArray()));
    static SuiteKey H => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x02, 32).ToArray()));

    static readonly JD Grant = Issue.NormJ(Issue.MintGrant(P, H.Id!, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "pay", ["resource"] = "invoice:*" }, new JD { ["verb"] = "pay.refund", ["resource"] = "invoice:*" } },
        ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "pay invoices", "s").Grant);

    static JD Op() => new() { ["verb"] = "pay", ["resource"] = "invoice:1", ["params"] = new JD { ["amount"] = 5L } };

    static JD Action(string? cls = null)
    {
        var a = new Agent(H, Aud, Grant, null, 0) { Clock = () => T0 };
        var prms = new JD { ["amount"] = 5L };
        if (cls == null) return a.Act("pay", "invoice:1", prms);
        a.CommitPlan(new[] { new JD { ["id"] = "s1", ["verb"] = "pay", ["resource"] = "invoice:1", ["params_digest"] = Pca.ParamsDigest(prms), ["reversibility_class"] = cls } });
        return a.ActNode("s1", prms);
    }

    sealed class Engine(string verb = "pay.refund") : IUndoEngine
    {
        public Task<JD?> PlanAsync(JD operation, string operationId) => Task.FromResult<JD?>(new JD
        {
            ["def_digest"] = D43,
            ["compensation"] = new JD { ["verb"] = verb, ["params"] = new JD(), ["def_digest"] = D43, ["target_param"] = "payment" },
        });
    }

    sealed class NoPlan : IUndoEngine
    {
        public Task<JD?> PlanAsync(JD operation, string operationId) => Task.FromResult<JD?>(null);
    }

    sealed class Notifier(bool deliver = true) : IUndoNotifier
    {
        public readonly List<UndoNotice> Notices = new();
        public Task<UndoNotifyResult> NotifyAsync(UndoNotice n)
        {
            Notices.Add(n);
            return Task.FromResult(deliver ? new UndoNotifyResult(true) : new UndoNotifyResult(false, "no channel"));
        }
    }

    sealed class Relay(List<UndoRelayedVeto> pending, bool fail = false) : IUndoVetoRelay
    {
        public Task<IReadOnlyList<UndoRelayedVeto>> PendingAsync() =>
            fail ? throw new InvalidOperationException("relay down") : Task.FromResult<IReadOnlyList<UndoRelayedVeto>>(pending.ToList());
    }

    sealed class Rig
    {
        public long[] Clock = { T0 };
        public readonly List<UndoCompensationCall> Calls = new();
        public readonly List<UndoAlert> Alerts = new();
        public UndoCoordinator C = null!;
    }

    static Rig Build(Notifier? notifier = null, IUndoStore? store = null, IUndoEngine? engine = null, Func<JD, JD, Task<UndoPolicy?>>? policy = null, IUndoVetoRelay? relay = null, UndoBudget? budget = null)
    {
        var rig = new Rig();
        rig.C = Pca.CreateUndoCoordinator(new UndoCoordinatorOptions
        {
            Store = store ?? new MemoryUndoStore(), Engine = engine ?? new Engine(), SignerSecret = Secret, Audience = Aud,
            ResolveGrant = (_, _) => Task.FromResult<JD?>(Grant),
            Compensate = call => { rig.Calls.Add(call); return Task.FromResult<object?>(new JD { ["refund"] = "r1" }); },
            Operations = new MemoryOperationStore(), Notifier = notifier ?? new Notifier(),
            Alert = a => { rig.Alerts.Add(a); return Task.CompletedTask; },
            Now = () => rig.Clock[0], InsecureVolatileStore = true, Policy = policy, Relay = relay, Budget = budget,
        });
        return rig;
    }


    static async Task<(UndoAdmitted Adm, UndoWindowInfo Info)> OpenOne(Rig rig, bool effect = true)
    {
        var adm = await rig.C.AdmitAsync(Action(), Op(), false, Grant);
        Assert.Null(adm.Refused);
        var info = await rig.C.OpenAsync(adm.Admission!);
        if (effect) await rig.C.RecordEffectAsync(adm.Admission!.Id, new JD { ["id"] = "pay_1" }, true);
        return (adm.Admission!, info);
    }

    static string State(JD? r) => (string)r!["state"]!;

    [Fact]
    public async Task VetoWithTheTokenCompensatesOnce()
    {
        var rig = Build();
        var (adm, info) = await OpenOne(rig);
        Assert.Equal("undo_window", info.Obligation["kind"]);
        rig.Clock[0] = T0 + 1_000;
        var v = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token));
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("compensated", State(v.Record));
        Assert.False(v.Replayed);
        Assert.Single(rig.Calls);
        Assert.Equal("pay_1", ((JD)rig.Calls[0].Operation["params"]!)["payment"]);
        var again = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token)); // the same veto is a replay: the compensation never runs twice
        Assert.True(again.Ok);
        Assert.True(again.Replayed);
        Assert.Single(rig.Calls);
        Assert.Empty(rig.Alerts);
    }

    [Fact]
    public async Task ABadTokenOrALateOneIsRefused()
    {
        var rig = Build();
        var (adm, info) = await OpenOne(rig, false);
        Assert.False((await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token("not a token"))).Ok);
        rig.Clock[0] = adm.WindowEnd + 1;
        var late = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token));
        Assert.False(late.Ok);
        Assert.Empty(rig.Calls);
        Assert.False((await rig.C.VetoAsync("missing", UndoVetoBy.OperatorId("ops"))).Ok);
        Assert.False((await rig.C.VetoAsync(adm.Id, UndoVetoBy.OperatorId(""))).Ok);
    }

    [Fact]
    public async Task FinalizeClosesTheWindowAndAlertsAnUnreportedEffect()
    {
        var rig = Build();
        var (adm, _) = await OpenOne(rig, false);
        Assert.Empty(await rig.C.FinalizeDueAsync()); // the window is still open
        rig.Clock[0] = adm.WindowEnd + 5;
        Assert.Equal(new[] { adm.Id }, await rig.C.FinalizeDueAsync());
        Assert.Equal("finalized", State(await rig.C.GetAsync(adm.Id)));
        Assert.Equal(new[] { "effect_unknown" }, rig.Alerts.Select(a => a.Code).ToArray());
        Assert.Empty(rig.Calls);
    }

    [Fact]
    public async Task AWindowNobodyWasToldAboutIsAborted()
    {
        var rig = Build(new Notifier(false));
        var adm = await rig.C.AdmitAsync(Action(), Op(), false, Grant);
        await Assert.ThrowsAsync<UndoError>(() => rig.C.OpenAsync(adm.Admission!));
        Assert.Equal("finalized", State(await rig.C.GetAsync(adm.Admission!.Id)));
        Assert.Equal("notify_failed", rig.Alerts[0].Code);
        Assert.Equal("critical", rig.Alerts[0].Level);
    }

    [Fact]
    public async Task AdmissionRefusesWhatIsNotConfirmedReversible()
    {
        var rig = Build();
        Assert.StartsWith("the signed class is irreversible", (await rig.C.AdmitAsync(Action("irreversible"), Op(), false, Grant)).Refused);
        Assert.Contains("not confirmed reversible", (await Build(engine: new NoPlan()).C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        var off = Build(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy("off")));
        Assert.Equal("policy: undo windows are off", (await off.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        var esc = Build(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy("escalations")));
        Assert.Contains("windows only replace approvals", (await esc.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
        Assert.Null((await esc.C.AdmitAsync(Action(), Op(), true, Grant)).Refused);
        Assert.Equal("no operation", (await rig.C.AdmitAsync(Action(), new JD(), false, Grant)).Refused);
    }

    [Fact]
    public async Task ACompensationTheGrantDoesNotAllowIsRefused()
    {
        var wide = Build(engine: new Engine("admin.delete"));
        Assert.Contains("not authorized under the grant", (await wide.C.AdmitAsync(Action(), Op(), false, Grant)).Refused);
    }

    [Fact]
    public void AVolatileStoreAndMissingComponentsFailClosed()
    {
        UndoCoordinatorOptions Base() => new()
        {
            Store = new MemoryUndoStore(), Engine = new Engine(), SignerSecret = Secret, Audience = Aud, ResolveGrant = (_, _) => Task.FromResult<JD?>(Grant),
            Compensate = _ => Task.FromResult<object?>(null), Operations = new MemoryOperationStore(), Notifier = new Notifier(), Alert = _ => Task.CompletedTask,
        };
        Assert.Equal("not_durable", Assert.Throws<UndoError>(() => Pca.CreateUndoCoordinator(Base())).Code);
        var o = Base();
        o.Audience = "";
        Assert.Equal("config", Assert.Throws<UndoError>(() => Pca.CreateUndoCoordinator(o)).Code);
        Assert.Equal(new[] { "store", "engine", "signerSecret", "audience", "resolveGrant", "compensate", "operations", "notifier", "alert" }, UndoNotifiers.Missing(null).ToArray());
    }

    [Fact]
    public async Task TheKvStoreAndEffectReporting()
    {
        var rig = Build(store: new KvUndoStore(new MemoryAtomicKv(), false));
        var adm = await rig.C.AdmitAsync(Action(), Op(), false, Grant);
        await rig.C.OpenAsync(adm.Admission!);
        Assert.Equal(0L, IntentJs.Lng((await rig.C.GetAsync(adm.Admission!.Id))!["ver"]));
        var rec = await Pca.ReportUndoEffect(rig.C, adm.Admission!.Id, "committed", new JD { ["id"] = "p9" }, true);
        Assert.Equal("p9", ((JD)((JD)rec["effect"]!)["result"]!)["id"]);
        var v = await rig.C.VetoAsync(adm.Admission!.Id, UndoVetoBy.OperatorId("ops"));
        Assert.Equal("compensated", State(v.Record));
        Assert.Equal("p9", ((JD)rig.Calls[0].Operation["params"]!)["payment"]);
    }

    [Fact]
    public async Task ARelayedVetoIsAppliedAsOfWhenTheRelayTookIt()
    {
        var pending = new List<UndoRelayedVeto>();
        var rig = Build(relay: new Relay(pending));
        var (adm, info) = await OpenOne(rig);
        pending.Add(new UndoRelayedVeto(adm.Id, info.Token, T0 + 500));
        rig.Clock[0] = adm.WindowEnd + 10; // the relay is read after the window closed: the veto still counts
        Assert.Empty(await rig.C.FinalizeDueAsync());
        Assert.Equal("compensated", State(await rig.C.GetAsync(adm.Id)));
        // a relayed time in the future (or before the opening) is refused
        var bad = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token, T0 - 1));
        Assert.False(bad.Ok);
        Assert.Equal("malformed", bad.Code);
    }

    [Fact]
    public async Task AnUnreadableRelayFinalizesNothing()
    {
        var rig = Build(relay: new Relay(new List<UndoRelayedVeto>(), fail: true));
        var (adm, _) = await OpenOne(rig, false);
        rig.Clock[0] = adm.WindowEnd + UndoCoordinator.RelayGraceMs + 5;
        Assert.Empty(await rig.C.FinalizeDueAsync());
        Assert.Equal("open", State(await rig.C.GetAsync(adm.Id)));
        Assert.Equal("veto_relay_failed", rig.Alerts[^1].Code);
    }

    [Fact]
    public async Task ARevokedGrantVetoesWhenThePolicySaysSo()
    {
        var rig = Build(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy(OnRevocation: "veto")));
        var (adm, _) = await OpenOne(rig);
        Assert.Equal(new[] { adm.Id }, await rig.C.OnRevocationAsync((string)adm.Pcactn["grant_ref"]!));
        Assert.Equal("compensated", State(await rig.C.GetAsync(adm.Id)));
        var keep = Build();
        var (a2, _) = await OpenOne(keep);
        Assert.Empty(await keep.C.OnRevocationAsync((string)a2.Pcactn["grant_ref"]!));
        Assert.Equal("revoked_open_window", keep.Alerts[^1].Code);
    }

    [Fact]
    public async Task AFailedCompensationIsAlertedAndNeverSilent()
    {
        var rig = new Rig();
        rig.C = Pca.CreateUndoCoordinator(new UndoCoordinatorOptions
        {
            Store = new MemoryUndoStore(), Engine = new Engine(), SignerSecret = Secret, Audience = Aud, ResolveGrant = (_, _) => Task.FromResult<JD?>(Grant),
            Compensate = _ => throw new InvalidOperationException("downstream 500"), Operations = new MemoryOperationStore(), Notifier = new Notifier(),
            Alert = a => { rig.Alerts.Add(a); return Task.CompletedTask; }, Now = () => rig.Clock[0], InsecureVolatileStore = true,
        });
        var (adm, _) = await OpenOne(rig);
        var v = await rig.C.VetoAsync(adm.Id, UndoVetoBy.OperatorId("ops"));
        Assert.True(v.Ok);
        Assert.Equal("compensation_failed", State(v.Record));
        Assert.Equal("compensation_failed", rig.Alerts[0].Code);
        Assert.Contains("downstream 500", rig.Alerts[0].Reason);
    }

    [Fact]
    public async Task TheHostedRelayReadsTheVetoList()
    {
        string? seen = null;
        var relay = UndoNotifiers.HostedVetoRelay("https://u.example/", "sk_test", (url, headers) =>
        {
            seen = url + "|" + headers["authorization"];
            return Task.FromResult(new UndoNotifiers.UndoRelayResponse(true, 200, () => Task.FromResult<object?>(Pca.ParseJson("{\"data\":[{\"record_id\":\"r1\",\"veto\":{\"token\":\"tok\",\"at\":5}}]}"))));
        }, 500);
        var list = await relay.PendingAsync();
        Assert.Equal("https://u.example/v1/pca/undo/vetoes?limit=200|Bearer sk_test", seen);
        Assert.Equal(new UndoRelayedVeto("r1", "tok", 5), list.Single());
        var bad = UndoNotifiers.HostedVetoRelay("https://u.example", "k", (_, _) => Task.FromResult(new UndoNotifiers.UndoRelayResponse(false, 503, () => Task.FromResult<object?>(null))));
        await Assert.ThrowsAsync<UndoError>(() => bad.PendingAsync());
    }

    [Fact]
    public void TheSmallHelpers()
    {
        Assert.Equal(UndoNotifiers.SignerPublic(Secret), UndoNotifiers.SignerPublic(Secret));
        Assert.Equal(60_000, Pca.UndoRelayGraceMs);
        var h = Pca.DefaultProvenanceBundle(_ => null, new JD { ["pca_provenance"] = "x" });
        Assert.Equal("x", h);
        Assert.Null(Pca.DefaultProvenanceBundle(_ => null, "not json"));
        Assert.Throws<FormatException>(() => Pca.DefaultProvenanceBundle(k => "***", null));
    }

    sealed class RecordingLedger : IBudgetLedger
    {
        public readonly List<(string Key, string Id, JD? Evidence)> Releases = new();
        public bool Durable => true;
        public BudgetSnapshot Snapshot(string key) => throw new NotSupportedException();
        public BudgetReserveOutcome Reserve(string key, BudgetReserveRequest req) => throw new NotSupportedException();
        public BudgetSettleOutcome Start(string key, string id) => throw new NotSupportedException();
        public BudgetSettleOutcome Commit(string key, string id) => throw new NotSupportedException();
        public BudgetSettleOutcome Release(string key, string id, JD? evidence)
        {
            Releases.Add((key, id, evidence));
            return new BudgetSettleOutcome("settled", 1, null);
        }
        public BudgetExpired Expire(string key, long now) => throw new NotSupportedException();
    }

    static async Task<(RecordingLedger Ledger, Rig Rig)> RollBack(Func<RecordingLedger, UndoBudget> budget)
    {
        var ledger = new RecordingLedger();
        var rig = Build(budget: budget(ledger));
        var (adm, _) = await OpenOne(rig);
        await rig.C.HoldBudgetAsync(adm.Id, new[] { ("principal/p", adm.Id) });
        var v = await rig.C.VetoAsync(adm.Id, UndoVetoBy.OperatorId("ops"));
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("compensated", State(v.Record));
        return (ledger, rig);
    }

    [Fact]
    public async Task AReleaseCarriesNoEvidenceUnlessTheCallerSuppliesIt()
    {
        var (ledger, rig) = await RollBack(l => new UndoBudget(l));
        Assert.Empty(rig.Alerts);
        var r = Assert.Single(ledger.Releases);
        Assert.Equal("principal/p", r.Key);
        Assert.Null(r.Evidence);
    }

    [Fact]
    public async Task TheCallersReleaseEvidenceIsWhatTheLedgerReceives()
    {
        var seen = new List<string>();
        var evidence = new JD { ["marker"] = "caller" };
        var (ledger, _) = await RollBack(l => new UndoBudget(l, (r, how) => { seen.Add(how); return evidence; }));
        Assert.Equal(new[] { "rollback" }, seen);
        Assert.Same(evidence, Assert.Single(ledger.Releases).Evidence);
    }
}
