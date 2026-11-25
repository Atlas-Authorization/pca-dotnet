using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class StoreConformanceLedgerTests
{
    [Fact]
    public void TheMemoryStorePassesAndSkipsWhatItDeclaresItCannotDo()
    {
        var r = LedgerStoreConformance.Run(LedgerStoreConformance.MemoryStoreAdapter());
        Assert.True(r.Ok, r.Format());
        Assert.Equal("skip", r.Check("state-survives-reopen").Status);
        Assert.Equal("skip", r.Check("acknowledged-writes-survive-a-crash").Status);
        Assert.Equal(13, r.Count("pass"));
    }

    [Fact]
    public void ADurableKvStorePassesEveryCheck()
    {
        var a = LedgerStoreConformance.KvStoreAdapter("kv", true, () => { var kv = new MemoryAtomicKv(); return () => kv; }, true);
        var r = LedgerStoreConformance.Run(a);
        Assert.True(r.Ok, r.Format());
        Assert.Equal(15, r.Count("pass"));
    }

    [Fact]
    public void EveryDefectiveStoreIsCaught()
    {
        foreach (var (name, make) in LedgerStoreConformance.ReferenceAdapters())
        {
            var r = LedgerStoreConformance.Run(make());
            Assert.Equal(!name.StartsWith("bad-"), r.Ok);
        }
    }

    [Fact]
    public void SpecificDefectsFailTheirOwnChecks()
    {
        var noCas = LedgerStoreConformance.Run(LedgerStoreConformance.DefectiveStoreAdapter(LedgerStoreConformance.Defect.NoCas));
        Assert.Equal("fail", noCas.Check("append-at-another-position-conflicts-without-trace").Status);
        var regress = LedgerStoreConformance.Run(LedgerStoreConformance.DefectiveStoreAdapter(LedgerStoreConformance.Defect.CheckpointRegress));
        Assert.Equal("fail", regress.Check("checkpoints-stay-inside-the-log-and-never-go-back").Status);
        var amnesia = LedgerStoreConformance.Run(LedgerStoreConformance.DefectiveStoreAdapter(LedgerStoreConformance.Defect.Amnesia));
        Assert.Equal("fail", amnesia.Check("state-survives-reopen").Status);
        var noReplay = LedgerStoreConformance.Run(LedgerStoreConformance.DefectiveStoreAdapter(LedgerStoreConformance.Defect.NoReplay));
        Assert.Equal("fail", noReplay.Check("append-retry-is-a-replay").Status);
    }

    [Fact]
    public void ADamagedDocumentFailsClosed()
    {
        var kv = new MemoryAtomicKv();
        kv.Update(KvLedgerStore.DocKey, _ => "{\"v\":2,\"commits\":[],\"checkpoints\":[]}");
        var e = Assert.Throws<LedgerStoreError>(() => new KvLedgerStore(kv).Size());
        Assert.Equal("store_corrupt", e.Code);
    }

    static StoredLedger.Options Opts(IAtomicKv kv, EdKey key) => new()
    {
        Store = new KvLedgerStore(kv),
        GuardianKey = key,
        InstanceId = "inst",
        Principal = "prin",
        Clock = () => 1_700_000_000_000,
    };

    static EdKey Guardian() => EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray());

    [Fact]
    public void AStoredLedgerAppendsCheckpointsAndReopens()
    {
        var kv = new MemoryAtomicKv();
        var key = Guardian();
        var led = StoredLedger.Open(Opts(kv, key));
        Assert.Equal(0, led.Append("c0"));
        Assert.Equal(1, led.Append("c1"));
        var sth1 = led.Checkpoint();
        Assert.True(Ledger.VerifyTreeHead(sth1, key.Id, null));
        Assert.Same(sth1, led.Checkpoint()); // an unchanged head returns the existing one
        Assert.Equal(2, led.Append("c2"));
        led.Checkpoint();
        Assert.True(Ledger.VerifyCheckpointChain(led.CheckpointChain().Cast<object?>().ToList(), key.Id, null).Ok);
        var again = StoredLedger.Open(Opts(kv, key));
        Assert.Equal(3, again.Size());
        Assert.Equal(led.Head()["root"], again.Head()["root"]);
        // a second handle that appended behind this one's back is picked up on the next append
        Assert.Equal(3, again.Append("c3"));
        Assert.Equal(4, led.Append("c4"));
        Assert.Equal(5, led.Size());
    }

    [Fact]
    public void ARolledBackOrTamperedStoreFailsClosedOnOpen()
    {
        var kv = new MemoryAtomicKv();
        var key = Guardian();
        var led = StoredLedger.Open(Opts(kv, key));
        led.Append("c0"); led.Append("c1"); led.Append("c2");
        led.Checkpoint();
        var doc = (D)Pca.ParseJson(kv.Get(KvLedgerStore.DocKey)!)!;

        var shrunk = (D)StoreJsCopy(doc);
        ((L)shrunk["commits"]!).RemoveAt(2);
        var kv2 = new MemoryAtomicKv();
        kv2.Update(KvLedgerStore.DocKey, _ => Pca.Canonicalize(shrunk));
        Assert.Equal("rollback", Assert.Throws<LedgerStoreError>(() => StoredLedger.Open(Opts(kv2, key))).Code);

        var edited = (D)StoreJsCopy(doc);
        ((L)edited["commits"]!)[1] = "edited";
        var kv3 = new MemoryAtomicKv();
        kv3.Update(KvLedgerStore.DocKey, _ => Pca.Canonicalize(edited));
        Assert.Equal("tamper", Assert.Throws<LedgerStoreError>(() => StoredLedger.Open(Opts(kv3, key))).Code);

        // a checkpoint of another log is refused
        var other = Opts(kv, key);
        other.InstanceId = "elsewhere";
        Assert.Equal("forged_checkpoint", Assert.Throws<LedgerStoreError>(() => StoredLedger.Open(other)).Code);
    }

    static object StoreJsCopy(object o) => Pca.ParseJson(Pca.Canonicalize(o))!;

    [Fact]
    public void OpenRefusesMissingStoreAndKey()
    {
        Assert.Equal("store_missing", Assert.Throws<LedgerStoreError>(() => StoredLedger.Open(new StoredLedger.Options { GuardianKey = Guardian() })).Code);
        Assert.Equal("guardian_key_missing", Assert.Throws<LedgerStoreError>(() => StoredLedger.Open(new StoredLedger.Options { Store = new KvLedgerStore(new MemoryAtomicKv()) })).Code);
    }
}
