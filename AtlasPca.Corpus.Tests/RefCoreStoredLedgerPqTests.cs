using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The stored ledger under post-quantum and hybrid checkpoint suites (test-data/ref-core-stored-ledger-pq-java.json.gz): reopening documents the
/// reference signed, under each pin and suite setting, must give the reference's outcome, op by op. A refused op is recorded by its store error code,
/// any other failure as <c>Error</c>.</summary>
public class RefCoreStoredLedgerPqTests
{
    const string M = "ref-core-stored-ledger-pq-java";

    static readonly Lazy<PqKey> Ml = new(() => PqKey.FromSeed(Pq.Prim.MlDsa65, Enumerable.Repeat((byte)7, 32).ToArray()));

    [Fact]
    public void StoredLedgerPq() => Base.Check(M, "storedLedgerPq", a =>
    {
        var pins = (D)a[0]!;
        var kv = new MemoryAtomicKv();
        var store = new KvLedgerStore(kv);
        var g = EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/stored-ledger-guardian")));
        var hs = new Dictionary<string, StoredLedger>();
        long calls = 0;
        var outp = new L();
        foreach (var oo in (L)a[1]!)
        {
            var op = (L)oo!;
            try
            {
                var head = (string)op[0]!;
                if (head == "kvSet") { kv.Update(KvLedgerStore.DocKey, _ => JsCanon.Lenient(op[1])); outp.Add(null); continue; }
                if (head == "open")
                {
                    var c = op[2] as D ?? new D();
                    var h = StoredLedger.Open(new StoredLedger.Options
                    {
                        Store = store, GuardianKey = g, InstanceId = "inst", Principal = "pr",
                        Clock = () => Base.OracleT0 + 1000.0 * calls++,
                        Suite = c.GetValueOrDefault("suite") switch
                        {
                            "hybrid" => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", g, Ml.Value),
                            "ml" => SuiteKey.Create("ml-dsa-65", null, Ml.Value),
                            _ => null,
                        },
                        Pin = c.GetValueOrDefault("pin") is string pin ? ((D)pins[pin]!).ToDictionary(e => e.Key, e => (string)e.Value!) : null,
                    });
                    hs[(string)op[1]!] = h;
                    outp.Add(new D { ["size"] = h.Size(), ["guardian"] = h.Guardian });
                    continue;
                }
                var l = hs[head];
                switch ((string)op[1]!)
                {
                    case "append": { var commit = (string)op[2]!; outp.Add(new D { ["index"] = l.Append(commit), ["commit"] = commit }); break; }
                    case "checkpoint":
                    {
                        var s = l.Checkpoint();
                        outp.Add(new D
                        {
                            ["size"] = s.GetValueOrDefault("size"), ["alg"] = s.GetValueOrDefault("alg"), ["pq"] = s.ContainsKey("pq_sig"),
                            ["root"] = s.GetValueOrDefault("root"), ["prev_root"] = s.GetValueOrDefault("prev_root"),
                        });
                        break;
                    }
                    case "latest": outp.Add(l.LatestCheckpoint()); break;
                    case "chain": outp.Add(l.CheckpointChain()); break;
                    case "head": outp.Add(l.Head()); break;
                    case "size": outp.Add(l.Size()); break;
                    default: throw new InvalidOperationException("op");
                }
            }
            catch (Exception t) { outp.Add(new D { ["$err"] = t is LedgerStoreError e ? e.Code : "Error" }); }
        }
        return outp;
    }, min: 64);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "storedLedgerPq" });
        Assert.Equal(64, Base.Cases(M).Count);
    }
}
