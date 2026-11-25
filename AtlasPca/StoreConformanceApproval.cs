// Conformance cases for an approval store (packages/pca-ciba store-conformance.ts), plus broker-level cases run over it. Run them against YOUR store:
//
//   foreach (var c in StoreConformance.ApprovalStoreCases(() => new MyStore(), previous => new MyStore())) c.Run();
//   var report = StoreConformance.RunApprovalStore(() => new MyStore());      // or the whole set as a report
//
// Each case throws when the store breaks the contract: absent means version 0, Cas writes only at the expected version and bumps it by one, exactly one of many concurrent
// Cas calls wins, returned values are snapshots, and (with a reopen) written records survive a restart. The broker cases check what the contract is for: exactly one
// concurrent decision wins and an approval redeems once.
using AtlasPca.Ciba;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One conformance case: a name and a body that throws when the store breaks the contract.</summary>
public sealed record ApprovalStoreCase(string Name, Action Run);

public static partial class StoreConformance
{
    static string J(object? v) => JsJson.Stringify(v);

    static void Eq(object? expected, object? actual)
    {
        if (J(expected) != J(actual)) throw new InvalidOperationException($"expected {J(expected)}, got {J(actual)}");
    }

    static void EqVersioned(long version, object? value, Versioned? got)
    {
        if (got == null || got.Version != version || J(got.Value) != J(value)) throw new InvalidOperationException($"expected {{version {version}, value {J(value)}}}, got {(got == null ? "absent" : $"{{version {got.Version}, value {J(got.Value)}}}")}");
    }

    /// <summary>The store contract as cases. <paramref name="make"/> opens a store over a fresh, empty backing location each call; <paramref name="reopen"/>, for a persistent
    /// store, returns a NEW store object over the same backing location as the previous one, as after a restart (omit it to skip the durability case).</summary>
    public static IReadOnlyList<ApprovalStoreCase> ApprovalStoreCases(Func<IApprovalStore> make, Func<IApprovalStore, IApprovalStore>? reopen = null)
    {
        var cases = new List<ApprovalStoreCase>
        {
            new("an absent key reads null", () => { if (make().Get("nope") != null) throw new InvalidOperationException("an absent key was not null"); }),
            new("cas at version 0 creates the key at version 1 with the whole value", () =>
            {
                var s = make();
                var v = new D { ["a"] = 1L, ["nested"] = new D { ["b"] = new L { "x", 2L, null } } };
                if (!s.Cas("k", 0, v)) throw new InvalidOperationException("the create was refused");
                EqVersioned(1, v, s.Get("k"));
            }),
            new("cas at version 0 on an existing key is refused and changes nothing", () =>
            {
                var s = make();
                s.Cas("k", 0, "first");
                if (s.Cas("k", 0, "second")) throw new InvalidOperationException("a create over an existing key was accepted");
                EqVersioned(1, "first", s.Get("k"));
            }),
            new("cas succeeds only at the current version and bumps it by exactly one", () =>
            {
                var s = make();
                s.Cas("k", 0, 1L);
                if (!s.Cas("k", 1, 2L)) throw new InvalidOperationException("the update at the current version was refused");
                if (s.Cas("k", 1, 3L)) throw new InvalidOperationException("a stale update was accepted");
                if (s.Cas("k", 5, 4L)) throw new InvalidOperationException("an update from the future was accepted");
                if (!s.Cas("k", 2, 5L)) throw new InvalidOperationException("the update at the new version was refused");
                EqVersioned(3, 5L, s.Get("k"));
            }),
            new("cas on a key that does not exist at a non-zero version is refused and creates nothing", () =>
            {
                var s = make();
                if (s.Cas("k", 1, "x")) throw new InvalidOperationException("an update of an absent key was accepted");
                if (s.Get("k") != null) throw new InvalidOperationException("a refused update created the key");
            }),
            new("keys are independent", () =>
            {
                var s = make();
                s.Cas("a", 0, "A");
                s.Cas("b", 0, "B");
                s.Cas("a", 1, "A2");
                EqVersioned(2, "A2", s.Get("a"));
                EqVersioned(1, "B", s.Get("b"));
            }),
            new("a read is a snapshot: changing the returned value does not change the store", () =>
            {
                var s = make();
                s.Cas("k", 0, new D { ["list"] = new L { 1L } });
                ((L)((D)s.Get("k")!.Value!)["list"]!).Add(2L);
                EqVersioned(1, new D { ["list"] = new L { 1L } }, s.Get("k"));
            }),
            new("a written value is a snapshot: changing it after cas does not change the store", () =>
            {
                var s = make();
                var list = new L { 1L };
                s.Cas("k", 0, new D { ["list"] = list });
                list.Add(2L);
                EqVersioned(1, new D { ["list"] = new L { 1L } }, s.Get("k"));
            }),
            new("exactly one of many concurrent creates wins", () =>
            {
                var s = make();
                var results = new bool[32];
                Race(32, i => results[i] = s.Cas("k", 0, (long)i));
                if (results.Count(r => r) != 1) throw new InvalidOperationException($"{results.Count(r => r)} concurrent creates won (want exactly 1)");
                EqVersioned(1, (long)Array.IndexOf(results, true), s.Get("k"));
            }),
            new("exactly one of many concurrent updates at the same version wins", () =>
            {
                var s = make();
                s.Cas("k", 0, "base");
                var results = new bool[32];
                Race(32, i => results[i] = s.Cas("k", 1, (long)i));
                if (results.Count(r => r) != 1) throw new InvalidOperationException($"{results.Count(r => r)} concurrent updates won (want exactly 1)");
                EqVersioned(2, (long)Array.IndexOf(results, true), s.Get("k"));
            }),
            new("a retry loop over concurrent writers loses no increment", () =>
            {
                var s = make();
                s.Cas("n", 0, 0L);
                Race(24, _ =>
                {
                    while (true)
                    {
                        var cur = s.Get("n");
                        if (cur != null && s.Cas("n", cur.Version, (long)JsJson.ToJsNumber(cur.Value) + 1)) return;
                    }
                });
                EqVersioned(25, 24L, s.Get("n"));
            }),
        };
        if (reopen != null)
            cases.Add(new("records and their versions survive reopening the store", () =>
            {
                var s = make();
                s.Cas("k", 0, new D { ["v"] = 1L });
                s.Cas("k", 1, new D { ["v"] = 2L });
                var again = reopen(s);
                EqVersioned(2, new D { ["v"] = 2L }, again.Get("k"));
                if (again.Cas("k", 1, new D { ["v"] = "stale" })) throw new InvalidOperationException("a stale update was accepted after the reopen");
                if (!again.Cas("k", 2, new D { ["v"] = 3L })) throw new InvalidOperationException("the update at the current version was refused after the reopen");
            }));
        return cases;
    }

    static D StepUp() => (D)Pca.ParseStrict(
        "{\"id\":\"su_" + Guid.NewGuid().ToString("N") + "\",\"verb\":\"stripe.payout\",\"resource\":\"acct:1\",\"params\":{\"amount\":80,\"currency\":\"USD\",\"payee\":\"bob\"},"
        + "\"tier\":3,\"reason\":\"conformance\",\"goalCommit\":\"" + new string('A', 43) + "\",\"goal\":\"pay suppliers\",\"lineage\":{},\"r\":0.5,\"requestedAt\":1}")!;

    /// <summary>Broker-level cases over a store: what the compare-and-set contract is for.</summary>
    public static IReadOnlyList<ApprovalStoreCase> ApprovalBrokerCases(Func<IApprovalStore> make)
    {
        IApprovalBroker[] Brokers(int n)
        {
            var store = make();
            return Enumerable.Range(0, n).Select(_ => CibaApproval.CreateDurableCibaBroker(new DurableBrokerOptions { Store = store })).ToArray();
        }
        return new List<ApprovalStoreCase>
        {
            new("concurrent resolves through separate brokers: exactly one wins and its decision stands", () =>
            {
                var bs = Brokers(8);
                var id = (string)bs[0].Start(StepUp(), null)["auth_req_id"]!;
                var won = new bool[8];
                Race(8, i =>
                {
                    try { bs[i].Resolve(id, i % 2 == 0 ? "approve" : "deny", "user-" + i); won[i] = true; }
                    catch (Exception) { won[i] = false; }
                });
                if (won.Count(w => w) != 1) throw new InvalidOperationException($"{won.Count(w => w)} resolves won (want exactly 1)");
                var w1 = Array.IndexOf(won, true);
                var final = bs[0].Get(id);
                if (final?.GetValueOrDefault("decidedBy") as string != "user-" + w1) throw new InvalidOperationException("the stored decision is not the winner's");
                if (final?.GetValueOrDefault("status") as string != (w1 % 2 == 0 ? "approved" : "denied")) throw new InvalidOperationException("the stored status is not the winner's decision");
            }),
            new("an approval redeems once even when many brokers redeem at the same time", () =>
            {
                var bs = Brokers(8);
                var id = (string)bs[0].Start(StepUp(), null)["auth_req_id"]!;
                bs[0].Resolve(id, "approve", "owner");
                var outs = new D[8];
                Race(8, i => outs[i] = bs[i].Token(id));
                var ok = outs.Count(o => o["ok"] is true);
                if (ok != 1) throw new InvalidOperationException($"{ok} redemptions succeeded (want exactly 1)");
            }),
            new("a second broker over the same store sees the decision of the first", () =>
            {
                var bs = Brokers(2);
                var id = (string)bs[0].Start(StepUp(), null)["auth_req_id"]!;
                if (bs[1].Poll(id)["status"] as string != "pending") throw new InvalidOperationException("the second broker did not see the pending session");
                bs[0].Resolve(id, "approve", "owner");
                if (bs[1].Poll(id)["status"] as string != "approved") throw new InvalidOperationException("the second broker did not see the first broker's decision");
                try { bs[1].Resolve(id, "deny", "late"); }
                catch (Exception) { return; }
                throw new InvalidOperationException("a late resolve was not refused");
            }),
        };
    }

    /// <summary>Runs the store cases and the broker cases; the report passes when every case does.</summary>
    public static ConformanceReport RunApprovalStore(Func<IApprovalStore> make, Func<IApprovalStore, IApprovalStore>? reopen = null)
    {
        var report = new ConformanceReport("approval-store");
        foreach (var c in ApprovalStoreCases(make, reopen).Concat(ApprovalBrokerCases(make)))
        {
            string? failure = null;
            try { c.Run(); }
            catch (Exception e) { failure = e.GetType().Name + ": " + e.Message; }
            report.Add(c.Name, failure);
        }
        return report;
    }
}
