using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the durable stores (ledger, stored ledger, bond, budget ledger and its signed releases, mesh witness) against the
/// TypeScript reference (test-data/ref-core-stores-java.json.gz). Every case is one scripted op sequence over a fresh store; each op's result, or its
/// typed error code, must equal the reference's.</summary>
public class RefCoreStoresTests
{
    const string M = "ref-core-stores-java";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    /// <summary>The reference's Number.isSafeInteger argument check: anything else is a RangeError.</summary>
    static long Safe(object? o) => IntentJs.IsSafeInteger(o) ? IntentJs.Lng(o) : throw new ArgumentException("not a safe integer");

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");

    static D Map(object? o) => (D)o!;
    static L List(object? o) => (L)o!;
    static D? MapOrNull(object? o) => o == null ? null : (D)o;

    static string CodeOf(Exception t) => t switch
    {
        LedgerStoreError e => e.Code,
        BondStoreError e => e.Code,
        BudgetLedgerError e => e.Code,
        ArgumentException => "RangeError",
        _ => "Error",
    };

    static L Script(L args, Func<L, object?> f, bool byMessage = false)
    {
        var outp = new L();
        foreach (var o in List(args[0]))
        {
            try { outp.Add(f(List(o))); }
            catch (Exception t) { outp.Add(new D { ["$err"] = byMessage ? t.Message : CodeOf(t) }); }
        }
        return outp;
    }

    static List<string?> Strings(object? o)
    {
        if (o is not L l) throw new ArgumentException("not an array");
        return l.Select(x => x as string ?? throw new ArgumentException("not a string")).Cast<string?>().ToList();
    }

    static void KvSet(MemoryAtomicKv kv, string key, object? raw) => kv.Update(key, _ => JsCanon.Lenient(raw));

    static object? KvGet(MemoryAtomicKv kv, string key) => kv.Get(key) is { } s ? Pca.ParseJson(s) : null;

    [Fact]
    public void LedgerStore() => Base.Check(M, "ledgerStore", a =>
    {
        var kv = new MemoryAtomicKv();
        var s = new KvLedgerStore(kv);
        return Script(a, op => (string)op[0]! switch
        {
            "size" => s.Size(),
            "read" => s.Read(Safe(op[1]), Safe(op[2])),
            "append" => s.Append(Safe(op[1]), Strings(op[2])).ToJson(),
            "cpCount" => s.CheckpointCount(),
            "cps" => s.Checkpoints(Safe(op[1])),
            "appendCp" => s.AppendCheckpoint(Safe(op[1]), MapOrNull(op[2])).ToJson(),
            "kvSet" => Do(() => KvSet(kv, KvLedgerStore.DocKey, op[1])),
            _ => throw new InvalidOperationException("op"),
        });
    });

    static object? Do(Action f) { f(); return null; }

    [Fact]
    public void StoredLedgerOps() => Base.Check(M, "storedLedger", a =>
    {
        var kv = new MemoryAtomicKv();
        var store = new KvLedgerStore(kv);
        var handles = new Dictionary<string, StoredLedger>();
        long calls = 0;
        var gkey = EdKey.FromSeed(Seed("stored-ledger-guardian"));
        return Script(a, op =>
        {
            var head = (string)op[0]!;
            if (head == "open")
            {
                var o = new StoredLedger.Options
                {
                    Store = store,
                    GuardianKey = op.Count > 2 && "other-key".Equals(op[2]) ? EdKey.FromSeed(Seed("other")) : gkey,
                    InstanceId = op.Count > 3 && op[3] != null ? (string)op[3]! : "inst",
                    Principal = "pr",
                    Clock = () => 1_800_000_000_000.0 + 1000.0 * calls++,
                };
                var h = StoredLedger.Open(o);
                handles[(string)op[1]!] = h;
                return new D { ["size"] = h.Size(), ["guardian"] = h.Guardian };
            }
            if (head == "kvSet") return Do(() => KvSet(kv, KvLedgerStore.DocKey, op[1]));
            if (head == "kvGet") return KvGet(kv, KvLedgerStore.DocKey);
            var l = handles[head];
            switch ((string)op[1]!)
            {
                case "append": { var c = (string)op[2]!; return new D { ["index"] = l.Append(c), ["commit"] = c }; }
                case "checkpoint": return l.Checkpoint();
                case "catchUp": l.CatchUp(); return null;
                case "head": return l.Head();
                case "size": return l.Size();
                case "incl": return l.InclusionProof(Safe(op[2]));
                case "consFrom": return l.ConsistencyProofFrom(Safe(op[2]));
                case "commits": return l.Commits();
                case "latest": return l.LatestCheckpoint();
                case "chain": return l.CheckpointChain();
                case "guardian": return l.Guardian;
                default: throw new InvalidOperationException("op");
            }
        });
    });

    [Fact]
    public void BondStore() => Base.Check(M, "bondStore", a =>
    {
        var kv = new MemoryAtomicKv();
        var s = new KvBondStore(kv);
        return Script(a, op => (string)op[0]! switch
        {
            "read" => s.Read((string)op[1]!, (string?)op[2]).ToJson(),
            "commit" => s.Commit(Map(op[1]), Dbl(op[2])).ToJson(),
            "deposit" => StoreJs.Number(s.Deposit((string)op[1]!, Dbl(op[2]))),
            "kvSet" => Do(() => KvSet(kv, KvBondStore.DocKey, op[1])),
            "kvGet" => KvGet(kv, KvBondStore.DocKey),
            _ => throw new InvalidOperationException("op"),
        });
    });

    static BudgetReserveRequest Request(object? o)
    {
        var m = Map(o);
        var r = new BudgetReserveRequest
        {
            Event = Map(m["event"]),
            Accumulators = m.GetValueOrDefault("accumulators") is L accs ? accs.Select(x => Map(x)).ToList() : null,
            Schema = m.GetValueOrDefault("schema"),
        };
        if (m.ContainsKey("expectedVersion")) r.ExpectedVersion = Safe(m["expectedVersion"]);
        if (m.ContainsKey("expiresAt")) r.ExpiresAt = Safe(m["expiresAt"]);
        return r;
    }

    static List<BudgetReservation> Reservations(object? o) => List(o).Select(x => new BudgetReservation((string)Map(x)["key"]!, (string)Map(x)["id"]!)).ToList();

    [Fact]
    public void BudgetLedger() => Base.Check(M, "budgetLedger", a =>
    {
        var rkey = EdKey.FromSeed(Seed("release-signer"));
        var kv = new MemoryAtomicKv();
        KvBudgetLedger? ledger = null;
        var log = new KvLedgerStore(new MemoryAtomicKv());
        return Script(a, op =>
        {
            switch ((string)op[0]!)
            {
                case "new": ledger = new KvBudgetLedger(kv, (bool)op[1]!); return ledger.Durable;
                case "snapshot": return ledger!.Snapshot((string)op[1]!).ToJson();
                case "reserve": return ledger!.Reserve((string)op[1]!, Request(op[2])).ToJson();
                case "start": return ledger!.Start((string)op[1]!, (string)op[2]!).ToJson();
                case "commit": return ledger!.Commit((string)op[1]!, (string)op[2]!).ToJson();
                case "release": return ledger!.Release((string)op[1]!, (string)op[2]!, MapOrNull(op[3])).ToJson();
                case "expire": return ledger!.Expire((string)op[1]!, Safe(op[2])).ToJson();
                case "signRelease": return Budgets.SignRelease((string)op[1]!, (string)op[2]!, (string)op[3]!, Safe(op[4]), rkey);
                case "verifyRelease": return Budgets.VerifyRelease(op[1], "signer".Equals(op[2]) ? rkey.Id : (string)op[2]!);
                case "releaseCommit": return new L { Budgets.ReleaseDigest(Map(op[1])), Budgets.ReleaseCommit(Map(op[1])) };
                case "anchor": return new L { Budgets.AnchorRelease(log, Map(op[1])), log.Size() };
                case "scopeKey": return Budgets.ScopeKey((string)op[1]!, (string)op[2]!);
                case "kvSet": KvSet(kv, (string)op[1]!, op[2]); return null;
                case "admit":
                {
                    var ad = Map(op[1]);
                    var ids = Map(ad["ids"]).ToDictionary(e => e.Key, e => (string)e.Value!);
                    var accs = List(ad["accumulators"]).Select(x => Map(x)).ToList();
                    var allow = (bool)ad["allow"]!;
                    var r = Budgets.AdmitAggregateAction(ledger, ids, accs, null, Map(ad["event"]), state => new D { ["allow"] = allow, ["state"] = state },
                        ad.ContainsKey("expiresAt") ? Safe(ad["expiresAt"]) : null, ad.ContainsKey("maxAttempts") ? (int)Safe(ad["maxAttempts"]) : null);
                    var o = new D { ["admitted"] = r.Admitted };
                    if (r.Reason != null) o["reason"] = r.Reason;
                    if (r.Verdict != null) o["verdict"] = r.Verdict;
                    if (r.Reservations != null) o["reservations"] = r.Reservations.Select(x => (object?)new D { ["key"] = x.Key, ["id"] = x.Id }).ToList();
                    if (r.State != null) o["state"] = r.State;
                    return o;
                }
                case "startAgg": return Budgets.StartAggregate(ledger!, Reservations(op[1]));
                case "settleAgg": return Budgets.SettleAggregate(ledger!, Reservations(op[1]), (string)op[2]!, null).Select(x => (object?)x.ToJson()).ToList();
                default: throw new InvalidOperationException("op");
            }
        });
    });

    [Fact]
    public void MeshWitnessOps() => Base.Check(M, "meshWitness", a =>
    {
        var stores = new Dictionary<string, MemoryMeshWitnessStore>();
        var witnesses = new Dictionary<string, MeshWitness>();
        var domains = new Dictionary<string, MeshDomain>();
        return Script(a, op =>
        {
            switch ((string)op[0]!)
            {
                case "store": stores[(string)op[1]!] = new MemoryMeshWitnessStore(); return true;
                case "witness":
                {
                    var o = new MeshWitness.Options();
                    if (op[2] != null) o.Store = stores[(string)op[2]!];
                    var w = new MeshWitness(EdKey.FromSeed(Seed((string)op[3]!)), o);
                    witnesses[(string)op[1]!] = w;
                    return w.Id;
                }
                case "witnessClock":
                {
                    double now = Dbl(op[3]);
                    var o = new MeshWitness.Options { Clock = () => now };
                    if (op[4] != null) o.MaxClockSkewMs = Dbl(op[4]);
                    witnesses[(string)op[1]!] = new MeshWitness(EdKey.FromSeed(Seed((string)op[2]!)), o);
                    return true;
                }
                case "restart":
                {
                    var w = new MeshWitness(EdKey.FromSeed(Seed((string)op[3]!)), new MeshWitness.Options { Store = stores[(string)op[2]!] });
                    witnesses[(string)op[1]!] = w;
                    return w.ExportState();
                }
                case "domain": { var d = new MeshDomain((string)op[1]!, EdKey.FromSeed(Seed((string)op[2]!))); domains[(string)op[1]!] = d; return d.Id; }
                case "record":
                {
                    var label = (string)op[2]!;
                    var cap = new D { ["id"] = label, ["caveats"] = new L { new D { ["type"] = "scope", ["actions"] = new L { label } } } };
                    return domains[(string)op[1]!].Record(cap);
                }
                case "revoke": domains[(string)op[1]!].Revoke((string)op[2]!); return null;
                case "publish":
                    return domains[(string)op[1]!].PublishHead(List(op[3]).Select(w => witnesses[(string)w!]).ToList(), Dbl(op[2]), op[4] == null ? null : (int)Safe(op[4]));
                case "lastSeen": return witnesses[(string)op[1]!].LastSeen((string)op[2]!);
                case "export": return witnesses[(string)op[1]!].ExportState();
                case "import": witnesses[(string)op[1]!].ImportState(Map(op[2])); return null;
                case "load": return stores[(string)op[1]!].Load();
                case "save": stores[(string)op[1]!].Save(Map(op[2])); return null;
                case "domainId": return domains[(string)op[1]!].Id;
                default: throw new InvalidOperationException("op");
            }
        }, byMessage: true);
    });

    [Fact] public void EveryFnIsCovered() { Base.Covers(M, new[] { "ledgerStore", "storedLedger", "bondStore", "budgetLedger", "meshWitness" }); Assert.Equal(227, Base.Total(M)); }
}
