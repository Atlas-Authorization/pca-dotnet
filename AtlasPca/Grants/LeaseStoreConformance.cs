// Conformance kit for lease storage (packages/pca-grants lease-store-conformance.ts). Run it against any IAtomicKv (the in-memory one, an
// opened durable state, or your own database adapter) before trusting that store with leases:
//   LeaseStoreConformance.Run(new LeaseStoreKit(() => MyFreshEmptyKv(), kv => SameStoreOpenedAgain(kv)));
// It throws InvalidOperationException("lease store conformance: <check>: <detail>") on the first failure and returns the checks passed.
// What it proves: leases spread over the shards; an update is atomic (of many concurrent renewals of one lease exactly one wins and the
// rest are forks); different leases do not interfere; a prefix revocation lands in every shard and a lease revocation only in its own; a
// store opened with another shard count is refused rather than silently empty; state survives a reopen; a later-issued lease under a
// revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every shard and a longer max_ttl is refused.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary><paramref name="Open"/> returns a fresh empty store; <paramref name="Reopen"/> (optional) opens the same store again as a restarted process would.</summary>
public sealed record LeaseStoreKit(Func<IAtomicKv> Open, Func<IAtomicKv, IAtomicKv>? Reopen = null, int Shards = 16);

public static class LeaseStoreConformance
{
    const long T0 = 1_800_000_000_000L, Day = 86_400_000L;
    static readonly EdKey Sk = EdKey.FromSeed(Enumerable.Repeat((byte)61, 32).ToArray());

    static Num N(long v) => new(v.ToString(System.Globalization.CultureInfo.InvariantCulture));

    static JD Mk(string id, JD? over = null)
    {
        var m = new JD
        {
            ["lease_id"] = id, ["path"] = $"svc/{id.Length % 3}/{id}", ["grant_ref"] = "g-" + id, ["holder"] = "agent", ["requester"] = "alice",
            ["approvers"] = new JL { "bob" }, ["justification_digest"] = "j1", ["seq"] = N(1), ["issued_at"] = N(T0), ["renewed_at"] = N(T0),
            ["expires_at"] = N(T0 + 600_000), ["max_ttl"] = N(3_600_000),
        };
        if (over != null) foreach (var kv in over) m[kv.Key] = kv.Value;
        return m;
    }

    static JD Lease(string id, JD? over = null) => GrantSigning.SignLease(Sk, Mk(id, over));
    static JD Revocation(string target, string value, long at) => GrantSigning.SignLeaseRevocation(Sk, new JD { ["target"] = target, ["value"] = value, ["revoked_at"] = N(at) });
    static InvalidOperationException Fail(string check, string detail) => new($"lease store conformance: {check}: {detail}");
    static void Expect(string check, object? got, object? want) { if (!Equals(got, want)) throw Fail(check, $"got {got}, want {want}"); }
    static void ExpectSeq(string check, IReadOnlyList<LeaseHistoryEntry> h, params long[] want) => Expect(check, string.Join(",", h.Select(x => x.Seq)), string.Join(",", want));

    public static IReadOnlyList<string> Run(LeaseStoreKit kit)
    {
        var passed = new List<string>();
        var shards = kit.Shards;
        var policy = new LeasePolicy(new[] { Sk.Id });

        // 1. spread
        {
            var reg = new LeaseRegistry(policy, kit.Open(), new LeaseRegistryOptions(shards));
            var ids = Enumerable.Range(0, 256).Select(i => $"lease-{i}").ToList();
            foreach (var id in ids) Expect($"spread: issue {id}", reg.Accept(Lease(id)).Ok, true);
            var per = new int[shards];
            foreach (var id in ids) per[LeaseRegistry.ShardOf(id, shards)]++;
            if (per.Max() > ids.Count / 4 || per.Count(n => n > 0) < shards / 2) throw Fail("spread", $"256 leases landed {string.Join(",", per)}");
            foreach (var id in ids) if (reg.Get(id)?["lease_id"] as string != id) throw Fail("spread", $"{id} not found after issue");
            passed.Add("spread");
        }

        // 2. atomic update
        {
            var reg = new LeaseRegistry(policy, kit.Open(), new LeaseRegistryOptions(shards));
            reg.Accept(Lease("hot"));
            var rivals = Enumerable.Range(0, 8).Select(i => Lease("hot", new JD { ["seq"] = N(2), ["renewed_at"] = N(T0 + 1000), ["expires_at"] = N(T0 + 700_000 + i), ["justification_digest"] = $"r{i}" })).ToList();
            var results = Task.WhenAll(rivals.Select(r => Task.Run(() => reg.Accept(r)))).GetAwaiter().GetResult();
            Expect("atomic: one winner", results.Count(r => r.Ok), 1);
            Expect("atomic: the rest are forks", results.Count(r => !r.Ok && r.Code == "lease_fork"), 7);
            ExpectSeq("atomic: ledger length", reg.History("hot"), 1, 2);
            passed.Add("atomic update");
        }

        // 3. independence
        {
            var reg = new LeaseRegistry(policy, kit.Open(), new LeaseRegistryOptions(shards));
            var ids = Enumerable.Range(0, 32).Select(i => $"ind-{i}").ToList();
            Task.WhenAll(ids.Select(id => Task.Run(() => reg.Accept(Lease(id))))).GetAwaiter().GetResult();
            var renewed = Task.WhenAll(ids.Select(id => Task.Run(() => reg.Accept(Lease(id, new JD { ["seq"] = N(2), ["renewed_at"] = N(T0 + 10), ["expires_at"] = N(T0 + 900_000), ["justification_digest"] = "j2" }))))).GetAwaiter().GetResult();
            Expect("independence", renewed.All(r => r.Ok), true);
            passed.Add("independent leases");
        }

        // 4 + 5. revocation placement
        {
            var reg = new LeaseRegistry(policy, kit.Open(), new LeaseRegistryOptions(shards));
            var ids = Enumerable.Range(0, 64).Select(i => $"rv-{i}").ToList();
            foreach (var id in ids) reg.Accept(Lease(id, new JD { ["path"] = "db/prod/ro" }));
            var lone = Lease("lone", new JD { ["path"] = "other/x" });
            reg.Accept(lone);
            Expect("revoke by lease", reg.Revoke(Revocation("lease", "lone", T0 + 5)), new LeaseRevoke(true, null, 1));
            var holders = Enumerable.Range(0, shards).Count(i => reg.ShardRevocations(i).Count > 0);
            Expect("lease revocation lands in exactly one shard", holders, 1);
            Expect("revoked lease is dead", Grants_Check(lone, reg, T0 + 6), "deny");
            var byPrefix = Revocation("prefix", "db/prod", T0 + 10);
            Expect("revoke by prefix covers every lease in every shard", reg.Revoke(byPrefix), new LeaseRevoke(true, null, 64));
            Expect("revoke twice is idempotent", reg.Revoke(byPrefix), new LeaseRevoke(true, null, 64));
            var sig = (string)byPrefix["sig"]!;
            for (var i = 0; i < shards; i++)
            {
                var list = reg.ShardRevocations(i);
                if (!list.Any(r => (string?)r["sig"] == sig)) throw Fail("prefix revocation in every shard", $"shard {i} lacks it");
                Expect($"no duplicate in shard {i}", list.Count(r => (string?)r["sig"] == sig), 1);
            }
            foreach (var id in ids)
            {
                Expect($"check {id}", Grants_Check(reg.Get(id), reg, T0 + 11), "deny");
                var renewal = Lease(id, new JD { ["path"] = "db/prod/ro", ["seq"] = N(2), ["renewed_at"] = N(T0 + 20), ["expires_at"] = N(T0 + 700_000), ["justification_digest"] = "x" });
                Expect($"renewal of {id} refused", reg.Accept(renewal).Ok, false);
            }
            var fresh = Lease("after", new JD { ["path"] = "db/prod/ro", ["issued_at"] = N(T0 + 100), ["renewed_at"] = N(T0 + 100), ["expires_at"] = N(T0 + 900_000) });
            Expect("a lease issued after the revocation is new", reg.Accept(fresh).Ok, true);
            passed.Add("revocation placement");
        }

        // 6. shard-count mismatch
        {
            var kv = kit.Open();
            new LeaseRegistry(policy, kv, new LeaseRegistryOptions(shards)).Accept(Lease("m1"));
            var other = new LeaseRegistry(policy, kv, new LeaseRegistryOptions(shards * 2));
            Expect("shard mismatch accept", other.Accept(Lease("m2")), new LeaseAccept(false, "store_unreachable"));
            Expect("shard mismatch check", Grants_Check(Lease("m1"), other, T0 + 1), "deny");
            passed.Add("shard count is pinned");
        }

        // 7. restart
        if (kit.Reopen != null)
        {
            var kv = kit.Open();
            var reg = new LeaseRegistry(policy, kv, new LeaseRegistryOptions(shards));
            var l = Lease("persist");
            reg.Accept(l);
            reg.Accept(Lease("persist", new JD { ["seq"] = N(2), ["renewed_at"] = N(T0 + 5), ["expires_at"] = N(T0 + 800_000), ["justification_digest"] = "j2" }));
            reg.Revoke(Revocation("prefix", "gone", T0 + 50));
            var again = new LeaseRegistry(policy, kit.Reopen(kv), new LeaseRegistryOptions(shards));
            ExpectSeq("restart: renewal ledger", again.History("persist"), 1, 2);
            Expect("restart: revocation kept", again.ShardRevocations(0).Count, 1);
            Expect("restart: old record still superseded", Grants_Check(l, again, T0 + 6), "deny");
            passed.Add("state survives a restart");
        }

        // 8. ceiling and pruning
        {
            var now = T0;
            var reg = new LeaseRegistry(new LeasePolicy(new[] { Sk.Id }, MaxTtlCeiling: Day), kit.Open(), new LeaseRegistryOptions(shards, () => now));
            Expect("ceiling refuses a longer max_ttl", reg.Accept(Lease("big", new JD { ["max_ttl"] = N(Day + 1), ["expires_at"] = N(T0 + 1000) })), new LeaseAccept(false, "ttl_ceiling"));
            reg.Accept(Lease("small", new JD { ["max_ttl"] = N(Day) }));
            reg.Revoke(Revocation("prefix", "svc", T0));
            for (var i = 0; i < shards; i++) Expect($"kept before the ceiling passes (shard {i})", reg.ShardRevocations(i).Count, 1);
            now = T0 + Day + 1;
            reg.Accept(Lease("trigger", new JD { ["issued_at"] = N(now), ["renewed_at"] = N(now), ["expires_at"] = N(now + 1000), ["max_ttl"] = N(5000) }));
            reg.Revoke(Revocation("prefix", "zzz", now));
            for (var i = 0; i < shards; i++)
            {
                var left = reg.ShardRevocations(i).Select(r => (string?)r["value"]).ToList();
                if (left.Contains("svc")) throw Fail("pruning", $"shard {i} still holds the expired revocation");
                if (!left.Contains("zzz")) throw Fail("pruning", $"shard {i} lost the fresh revocation");
            }
            passed.Add("pruning bounds revocations");
        }
        return passed;
    }

    static string Grants_Check(object? presented, LeaseRegistry reg, long now) => AtlasPca.Lease.Check(presented, reg, new Num(now.ToString(System.Globalization.CultureInfo.InvariantCulture))).Decision;
}
