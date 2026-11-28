using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The veto, relay, finalize, recover, revocation and bond-slash surfaces of the undo coordinator, with every refusal code and alert text exact.
public partial class UndoCoordinatorKillTests
{
    sealed class Bonds(Func<JD, object?> f) : IUndoBonds
    {
        public readonly List<JD> Seen = new();
        public Task<object?> SlashBondAsync(JD parameters)
        {
            Seen.Add(parameters);
            return Task.FromResult(f(parameters));
        }
    }

    [Fact]
    public async Task ARelayedVetoTimeMustLieBetweenTheOpeningAndNow()
    {
        async Task<VetoResult> Try(double at)
        {
            var rig = Make();
            var (adm, info) = await OpenOne(rig);
            rig.T = T0 + 10_000;
            return await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token, at));
        }
        const string why = "a relayed veto time must lie between the opening of the window and now";
        foreach (var bad in new double[] { T0 + 10_001, T0 - 1, double.NaN, double.PositiveInfinity, double.NegativeInfinity, T0 + 5.5 })
        {
            var r = await Try(bad);
            Assert.False(r.Ok);
            Assert.Equal("malformed", r.Code);
            Assert.Equal(why, r.Reason);
        }
        var atNow = await Try(T0 + 10_000);
        Assert.True(atNow.Ok, atNow.Reason);
        Assert.Equal(T0 + 10_000, Lg(Sub(atNow.Record, "veto")["at"]));
        var atOpen = await Try(T0);
        Assert.True(atOpen.Ok, atOpen.Reason);
        Assert.Equal(T0, Lg(Sub(atOpen.Record, "veto")["at"]));
    }

    [Fact]
    public async Task ATokenVetoRecordsTheTokenDigestAndIsReplayedOnce()
    {
        var rig = Make();
        var (adm, info) = await OpenOne(rig);
        rig.T = T0 + 2_000;
        var tok = UndoWindows.DecodeToken(info.Token)!;
        var v = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(tok));
        Assert.True(v.Ok, v.Reason);
        Assert.False(v.Replayed);
        var veto = Sub(v.Record, "veto");
        Assert.Equal("token", veto["via"]);
        Assert.Equal(Grant["issuer"], veto["by"]);
        Assert.Equal(UndoWindows.TokenDigest(tok), veto["evidence"]);
        Assert.Equal(T0 + 2_000, Lg(veto["at"]));
        Assert.Equal("token", ((JD)((JL)v.Record!["receipts"]!)[2]!)["note"]);
        var again = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token(info.Token));
        Assert.True(again.Ok);
        Assert.True(again.Replayed);
        Assert.Single(rig.N.Notices.Where(n => n.Kind == "vetoed"));
        Assert.Single(rig.Calls);
    }

    [Fact]
    public async Task EveryVetoRefusalHasItsExactCodeAndReason()
    {
        var rig = Make();
        var (adm, info) = await OpenOne(rig, false);
        var none = await rig.C.VetoAsync("nope", UndoVetoBy.OperatorId("ops"));
        Assert.Equal(new VetoResult(false, Code: "unknown", Reason: "no undo record nope"), none);
        var bad = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Token("not a token"));
        Assert.False(bad.Ok);
        Assert.Equal("malformed", bad.Code);
        Assert.Equal("the undo token was refused (malformed)", bad.Reason);
        foreach (var op in new[] { "", null })
        {
            var r = await rig.C.VetoAsync(adm.Id, UndoVetoBy.OperatorId(op!));
            Assert.Equal(new VetoResult(false, Code: "malformed", Reason: "an operator veto names the operator"), r);
        }
        var blank = await rig.C.VetoAsync(adm.Id, new UndoVetoBy());
        Assert.Equal(new VetoResult(false, Code: "invalid", Reason: "malformed veto"), blank);
        Assert.Equal("open", State(await rig.C.GetAsync(adm.Id)));
        rig.T = adm.WindowEnd;
        var edge = await VetoBy(rig, adm.Id);
        Assert.True(edge.Ok, edge.Reason);

        var late = Make();
        var (ladm, linfo) = await OpenOne(late, false);
        late.T = ladm.WindowEnd + 1;
        var closed = await VetoBy(late, ladm.Id);
        Assert.Equal(new VetoResult(false, Code: "window_closed", Reason: "the veto window closed at " + ladm.WindowEnd), closed);
        var expired = await late.C.VetoAsync(ladm.Id, UndoVetoBy.Token(linfo.Token));
        Assert.Equal("expired", expired.Code);
        Assert.Equal("the undo token was refused (expired)", expired.Reason);
        Assert.Equal(new[] { ladm.Id }, await late.C.FinalizeDueAsync());
        var fin = await VetoBy(late, ladm.Id);
        Assert.Equal(new VetoResult(false, Code: "finalized", Reason: "the window is closed and the action is final"), fin);
    }

    [Fact]
    public async Task OperatorAndPreparedVetoesRecordTheirOwnTerms()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig, false);
        rig.T = T0 + 700;
        var prepared = new JD { ["via"] = "revocation", ["by"] = "g1", ["at"] = IntentJs.OfLong(0) };
        var v = await rig.C.VetoAsync(adm.Id, UndoVetoBy.Prepared(prepared));
        Assert.True(v.Ok, v.Reason);
        var veto = Sub(v.Record, "veto");
        Assert.Equal("revocation", veto["via"]);
        Assert.Equal("g1", veto["by"]);
        Assert.Equal(T0 + 700, Lg(veto["at"]));
        Assert.Equal(0L, Lg(prepared["at"]));

        var op = Make();
        var (oadm, _) = await OpenOne(op, false);
        op.T = T0 + 800;
        var ov = await VetoBy(op, oadm.Id, "ops-1");
        var oveto = Sub(ov.Record, "veto");
        Assert.Equal("operator", oveto["via"]);
        Assert.Equal("ops-1", oveto["by"]);
        Assert.Equal(T0 + 800, Lg(oveto["at"]));
        Assert.False(oveto.ContainsKey("evidence"));
        Assert.Equal("operator", ((JD)((JL)ov.Record!["receipts"]!)[1]!)["note"]);
    }

    [Fact]
    public async Task AStoreFailureDuringAVetoFailsClosed()
    {
        foreach (var (message, expected) in new[] { ("store down", "store down"), ("", "unknown") })
        {
            var hook = new HookStore(new MemoryUndoStore());
            var rig = Make(store: hook);
            var (adm, _) = await OpenOne(rig, false);
            hook.OnGet = (_, _) => throw new InvalidOperationException(message);
            var v = await VetoBy(rig, adm.Id);
            Assert.Equal(new VetoResult(false, Code: "malformed", Reason: "veto error (fail closed): " + expected), v);
        }
    }

    [Fact]
    public async Task TheRelayIsSyncedEntryByEntry()
    {
        Assert.Empty(await Make().C.SyncRelayAsync());
        var nullList = Make(relay: new RelayOf(() => null));
        var e = await Assert.ThrowsAsync<UndoError>(() => nullList.C.SyncRelayAsync());
        Assert.Equal("invalid: the veto relay returned no list", e.Message);

        var pending = new List<UndoRelayedVeto>();
        var rig = Make(relay: new RelayOf(() => pending.ToList()));
        var (adm, info) = await OpenOne(rig);
        rig.T = T0 + 3_000;
        pending.Add(null!);
        pending.Add(new UndoRelayedVeto(null!, info.Token, T0 + 1_000));
        pending.Add(new UndoRelayedVeto("nope", info.Token, T0 + 1_000));
        pending.Add(new UndoRelayedVeto(adm.Id, info.Token, T0 + 1_000));
        var res = await rig.C.SyncRelayAsync();
        Assert.Equal(2, res.Count);
        Assert.Equal("unknown", res[0].Code);
        Assert.True(res[1].Ok, res[1].Reason);
        Assert.Equal("compensated", State(res[1].Record));
        Assert.Equal(T0 + 1_000, Lg(Sub(res[1].Record, "veto")["at"]));
    }

    [Fact]
    public async Task FinalizingClosesExactlyAfterTheWindowAndAlertsAnUnreportedEffect()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        rig.T = adm.WindowEnd;
        Assert.Empty(await rig.C.FinalizeDueAsync());
        rig.T = adm.WindowEnd + 1;
        Assert.Equal(new[] { adm.Id }, await rig.C.FinalizeDueAsync());
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.Equal("finalized", State(rec));
        Assert.Equal("finalized", Sub(rec, "outcome")["status"]);
        Assert.Equal(adm.WindowEnd + 1, Lg(Sub(rec, "outcome")["at"]));
        Assert.Empty(rig.Alerts);
        Assert.Equal("finalized", rig.N.Notices[^1].Kind);
        Assert.Equal("finalized", State(rig.N.Notices[^1].Record));
        Assert.False(rig.N.Notices[^1].Record.ContainsKey("pcactn"));
        Assert.Empty(await rig.C.FinalizeDueAsync());

        var quiet = Make();
        var (qadm, _) = await OpenOne(quiet, false);
        quiet.T = qadm.WindowEnd + 1;
        await quiet.C.FinalizeDueAsync();
        Assert.Equal(new UndoAlert("warning", "effect_unknown", qadm.Id, "the window closed without an effect report: reconcile the original operation"), Assert.Single(quiet.Alerts));
    }

    [Fact]
    public async Task WithARelayAWindowIsFinalizedOnlyAfterTheGracePeriod()
    {
        var rig = Make(relay: new RelayOf(() => new List<UndoRelayedVeto>()));
        var (adm, _) = await OpenOne(rig);
        rig.T = adm.WindowEnd + 60_000;
        Assert.Empty(await rig.C.FinalizeDueAsync());
        rig.T = adm.WindowEnd + 60_001;
        Assert.Equal(new[] { adm.Id }, await rig.C.FinalizeDueAsync());
    }

    [Fact]
    public async Task AnUnreadableRelayAlertsWithTheMessageOrError()
    {
        foreach (var (message, expected) in new[] { ("relay down", "relay down"), ("", "error") })
        {
            var rig = Make(relay: new RelayOf(() => throw new InvalidOperationException(message)));
            var (adm, _) = await OpenOne(rig);
            rig.T = adm.WindowEnd + 120_000;
            Assert.Empty(await rig.C.FinalizeDueAsync());
            Assert.Equal("open", State(await rig.C.GetAsync(adm.Id)));
            Assert.Equal(new UndoAlert("critical", "veto_relay_failed", "*", "the veto relay could not be read; no window was finalized: " + expected), Assert.Single(rig.Alerts));
        }
    }

    [Fact]
    public async Task RecoveryResumesWaitingCompensationsThenFinalizes()
    {
        var rig = Make(resolveTarget: _ => "tgt");
        var (waiting, _) = await OpenOne(rig, false);
        rig.T = T0 + 1_000;
        Assert.Equal("vetoed", State((await VetoBy(rig, waiting.Id)).Record));
        var (open, _) = await OpenOne(rig, true, amount: 6);
        rig.T = T0 + 2_000;
        Assert.Empty(await rig.C.RecoverAsync());
        Assert.Equal("vetoed", State(await rig.C.GetAsync(waiting.Id)));
        Assert.Empty(rig.Calls);
        rig.T = open.WindowEnd + 1;
        Assert.Equal(new[] { waiting.Id, open.Id }, await rig.C.RecoverAsync());
        Assert.Equal("compensated", State(await rig.C.GetAsync(waiting.Id)));
        Assert.Equal("finalized", State(await rig.C.GetAsync(open.Id)));
        Assert.Single(rig.Calls);
    }

    [Fact]
    public async Task ARevocationVetoesOnlyTheNamedGrantAndOnlyWhenThePolicySaysSo()
    {
        var seen = new List<(JD, JD)>();
        var rig = Make(policy: (o, g) => { seen.Add((o, g)); return Task.FromResult<UndoPolicy?>(new UndoPolicy(OnRevocation: "veto")); });
        var (adm, _) = await OpenOne(rig);
        var gref = (string)adm.Pcactn["grant_ref"]!;
        seen.Clear();
        Assert.Empty(await rig.C.OnRevocationAsync("another-grant"));
        Assert.Equal("open", State(await rig.C.GetAsync(adm.Id)));
        Assert.Empty(seen);
        Assert.Equal(new[] { adm.Id }, await rig.C.OnRevocationAsync(gref));
        var (so, sg) = Assert.Single(seen);
        Assert.Equal(new[] { "verb", "resource" }, so.Keys.ToArray());
        Assert.Equal("pay", so["verb"]);
        Assert.Equal("invoice:1", so["resource"]);
        Assert.Same(Grant, sg);
        var rec = (await rig.C.GetAsync(adm.Id))!;
        Assert.Equal("compensated", State(rec));
        Assert.Equal("revocation", Sub(rec, "veto")["via"]);
        Assert.Equal(gref, Sub(rec, "veto")["by"]);
        Assert.Empty(rig.Alerts);

        var late = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy(OnRevocation: "veto")));
        var (ladm, _) = await OpenOne(late);
        late.T = ladm.WindowEnd + 1;
        Assert.Empty(await late.C.OnRevocationAsync((string)ladm.Pcactn["grant_ref"]!));
        Assert.Equal("open", State(await late.C.GetAsync(ladm.Id)));
        Assert.Empty(late.Alerts);
    }

    [Fact]
    public async Task AKeptWindowAlertsAndTellsThePrincipal()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        var gref = (string)adm.Pcactn["grant_ref"]!;
        var args = new List<(string, JD)>();
        rig.Resolve = (r, pc) => { args.Add((r, pc)); return Task.FromResult<JD?>(Grant); };
        Assert.Empty(await rig.C.OnRevocationAsync(gref));
        var (aref, apc) = Assert.Single(args);
        Assert.Equal(gref, aref);
        Assert.Equal(Pca.Canonicalize(adm.Pcactn), Pca.Canonicalize(apc));
        Assert.Equal(new UndoAlert("warning", "revoked_open_window", adm.Id, "grant " + gref + " was revoked while this window is open; the principal can still undo it"), Assert.Single(rig.Alerts));
        var n = rig.N.Notices[^1];
        Assert.Equal("revoked", n.Kind);
        Assert.Equal("open", State(n.Record));
        Assert.False(n.Record.ContainsKey("pcactn"));
        Assert.Equal("open", State(await rig.C.GetAsync(adm.Id)));

        var vetoing = Make(policy: (_, _) => Task.FromResult<UndoPolicy?>(new UndoPolicy(OnRevocation: "veto")));
        var (vadm, _) = await OpenOne(vetoing);
        vetoing.Resolve = (_, _) => Task.FromResult<JD?>(null);
        Assert.Empty(await vetoing.C.OnRevocationAsync((string)vadm.Pcactn["grant_ref"]!));
        Assert.Equal("revoked_open_window", Assert.Single(vetoing.Alerts).Code);
        Assert.Equal("open", State(await vetoing.C.GetAsync(vadm.Id)));
    }

    [Fact]
    public async Task ASlashedBondRollsTheRecordBackWithTheSettlementAsEvidence()
    {
        var settlement = new JD { ["slashed"] = true };
        var bonds = new Bonds(_ => settlement);
        var rig = Make();
        var adm = (await rig.C.AdmitAsync(Action(), Op(), false, Grant)).Admission!;
        await rig.C.OpenAsync(adm, "claim1", null);
        await rig.C.RecordEffectAsync(adm.Id, new JD { ["id"] = "pay_1" }, true);
        var parameters = new JD { ["claimId"] = "claim1" };
        var (s, v) = await rig.C.RollbackOnSlashAsync(bonds, parameters);
        Assert.Same(settlement, s);
        Assert.Same(parameters, Assert.Single(bonds.Seen));
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("compensated", State(v.Record));
        var veto = Sub(v.Record, "veto");
        Assert.Equal("fraud_proof", veto["via"]);
        Assert.Equal("claim1", veto["by"]);
        Assert.Equal(Pca.HashCanonical(new JD { ["d"] = "atlas-pca/undo-slash-ref/v1", ["settlement"] = settlement }), veto["evidence"]);
        Assert.Empty(rig.Alerts);

        var byId = Make();
        var (iadm, _) = await OpenOne(byId);
        var (_, iv) = await byId.C.RollbackOnSlashAsync(bonds, new JD { ["claimId"] = iadm.Id });
        Assert.True(iv.Ok, iv.Reason);
        Assert.Equal("compensated", State(iv.Record));

        var unknown = Make();
        var (_, uv) = await unknown.C.RollbackOnSlashAsync(bonds, new JD { ["claimId"] = "zzz" });
        Assert.Equal(new VetoResult(false, Code: "unknown", Reason: "no undo record for bond zzz"), uv);
        Assert.Empty(unknown.Alerts);
    }

    [Fact]
    public async Task ASlashAfterTheWindowAlertsThatTheEffectCouldNotBeRolledBack()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig);
        rig.T = adm.WindowEnd + 1;
        await rig.C.FinalizeDueAsync();
        var (_, v) = await rig.C.RollbackOnSlashAsync(new Bonds(_ => "s"), new JD { ["claimId"] = adm.Id });
        Assert.False(v.Ok);
        Assert.Equal("finalized", v.Code);
        Assert.Equal(new UndoAlert("critical", "slash_after_window", adm.Id, "the bond was slashed but the effect could not be rolled back: the window is closed and the action is final"), rig.Alerts[^1]);
    }

    [Fact]
    public async Task ReportingAnEffectMapsEveryStatus()
    {
        var rig = Make();
        var (adm, _) = await OpenOne(rig, false);
        var pending = await Pca.ReportUndoEffect(rig.C, adm.Id, "pending");
        Assert.Equal("open", State(pending));
        Assert.False(pending.ContainsKey("effect"));
        Assert.Equal("open", State(await Pca.ReportUndoEffect(rig.C, adm.Id, "uncertain")));
        var missing = await Assert.ThrowsAsync<UndoError>(() => Pca.ReportUndoEffect(rig.C, "nope", "pending"));
        Assert.Equal("invalid: no undo record nope", missing.Message);
        var committed = await Pca.ReportUndoEffect(rig.C, adm.Id, "committed", new JD { ["id"] = "p9" }, true);
        Assert.Equal("p9", Sub(Sub(committed, "effect"), "result")["id"]);
        foreach (var status in new[] { "failed", "aborted", "refused" })
        {
            var r = Make();
            var (a, _) = await OpenOne(r, false);
            var rec = await Pca.ReportUndoEffect(r.C, a.Id, status);
            Assert.Equal("finalized", State(rec));
            Assert.Equal("aborted", Sub(rec, "outcome")["status"]);
            Assert.Equal("effect_" + status, Sub(rec, "outcome")["reason"]);
        }
    }

    [Fact]
    public void TheProvenanceBundleComesFromTheHeaderThenTheBody()
    {
        var keys = new List<string>();
        var enc = Pca.B64u(Encoding.UTF8.GetBytes("{\"a\":\"x\"}"));
        var fromHeader = Pca.DefaultProvenanceBundle(k => { keys.Add(k); return enc; }, "ignored");
        Assert.Equal("pca-provenance", Assert.Single(keys));
        Assert.Equal("x", ((JD)fromHeader!)["a"]);
        Assert.Equal("x", Pca.DefaultProvenanceBundle(_ => "", new JD { ["pca_provenance"] = "x" }));
        Assert.Equal("y", Pca.DefaultProvenanceBundle(_ => null, "{\"pca_provenance\":\"y\"}"));
        Assert.Null(Pca.DefaultProvenanceBundle(_ => null, new JD { ["other"] = "x" }));
        Assert.Null(Pca.DefaultProvenanceBundle(_ => null, 5L));
        Assert.Null(Pca.DefaultProvenanceBundle(_ => null, null));
        Assert.Null(Pca.DefaultProvenanceBundle(_ => null, "{not json"));
        var bad = Assert.Throws<FormatException>(() => Pca.DefaultProvenanceBundle(_ => "***", null));
        Assert.Equal("the PCA-Provenance header is not strict base64url", bad.Message);
    }

    [Fact]
    public void EveryMissingComponentIsNamedAndTheFailuresHaveTheirExactMessages()
    {
        UndoCoordinatorOptions Full() => new()
        {
            Store = new MemoryUndoStore(), Engine = new PlanEngine((_, _) => MakePlan()), SignerSecret = Secret, Audience = Aud, ResolveGrant = (_, _) => Task.FromResult<JD?>(Grant),
            Compensate = _ => Task.FromResult<object?>(null), Operations = new MemoryOperationStore(), Notifier = new Notif(), Alert = _ => Task.CompletedTask,
        };
        Assert.Empty(UndoNotifiers.Missing(Full()));
        var cases = new (string Name, Action<UndoCoordinatorOptions> Break)[]
        {
            ("store", o => o.Store = null), ("engine", o => o.Engine = null), ("signerSecret", o => o.SignerSecret = null), ("signerSecret", o => o.SignerSecret = new byte[31]),
            ("signerSecret", o => o.SignerSecret = new byte[33]), ("audience", o => o.Audience = null), ("audience", o => o.Audience = ""), ("resolveGrant", o => o.ResolveGrant = null),
            ("compensate", o => o.Compensate = null), ("operations", o => o.Operations = null), ("notifier", o => o.Notifier = null), ("alert", o => o.Alert = null),
        };
        foreach (var (name, brk) in cases)
        {
            var o = Full();
            brk(o);
            Assert.Equal(new[] { name }, UndoNotifiers.Missing(o).ToArray());
            var e = Assert.Throws<UndoError>(() => Pca.CreateUndoCoordinator(o));
            Assert.Equal("config", e.Code);
            Assert.Equal("config: undo coordinator: missing required component(s): " + name, e.Message);
        }
        var two = Full();
        two.Store = null;
        two.Alert = null;
        Assert.Equal("config: undo coordinator: missing required component(s): store, alert", Assert.Throws<UndoError>(() => Pca.CreateUndoCoordinator(two)).Message);
        var volatileStore = Assert.Throws<UndoError>(() => Pca.CreateUndoCoordinator(Full()));
        Assert.Equal("not_durable: an undo ledger must be durable: a restart would lose every open window and its compensation", volatileStore.Message);
        var durable = Full();
        durable.Store = new KvUndoStore(new MemoryAtomicKv(), true);
        Assert.NotNull(Pca.CreateUndoCoordinator(durable));
        var tests = Full();
        tests.InsecureVolatileStore = true;
        Assert.NotNull(Pca.CreateUndoCoordinator(tests));
    }
}
