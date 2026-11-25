using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

public class StoreConformanceMeshWitnessTests
{
    /// <summary>The durable store over an atomic key-value store: reopen shares the kv, damage overwrites the stored document.</summary>
    sealed class KvAdapter : MeshWitnessStoreAdapter
    {
        MemoryAtomicKv _kv = new();
        public override string Name => "KvMeshWitnessStore";
        public override IMeshWitnessStore Make() => new KvMeshWitnessStore(_kv = new()); // every case starts on its own empty storage (reopen and damage then act on that case's storage)
        public override bool CanReopen => true;
        public override IMeshWitnessStore Reopen(IMeshWitnessStore previous) => new KvMeshWitnessStore(_kv);
        public override bool CanDamage => true;
        public override void Damage(IMeshWitnessStore store) => _kv.Update(KvMeshWitnessStore.DocKey, prev => prev!.Replace("\"digest\":\"", "\"digest\":\"x"));
    }

    [Fact]
    public void TheMemoryStorePasses()
    {
        var r = MeshWitnessStoreConformance.Run(MeshWitnessStoreConformance.MemoryAdapter());
        Assert.True(r.Ok, r.Format());
        Assert.Equal(7, r.Count("pass"));
    }

    [Fact]
    public void TheKvStorePassesEveryCase()
    {
        var r = MeshWitnessStoreConformance.Run(new KvAdapter());
        Assert.True(r.Ok, r.Format());
        Assert.Equal(10, r.Count("pass"));
        Assert.Equal(0, r.Count("skip"));
    }

    [Fact]
    public void AForgetfulStoreIsCaught()
    {
        var r = MeshWitnessStoreConformance.Run(MeshWitnessStoreConformance.ForgetfulAdapter());
        Assert.False(r.Ok);
        Assert.Equal("fail", r.Check("save then load returns the same state").Status);
        Assert.Equal("fail", r.Check("a restarted witness remembers what it cosigned: it refuses a fork and a rollback").Status);
    }

    [Fact]
    public void AStaleStoreIsCaught()
    {
        var r = MeshWitnessStoreConformance.Run(MeshWitnessStoreConformance.StaleAdapter());
        Assert.False(r.Ok);
        Assert.Equal("fail", r.Check("a later save replaces the earlier one").Status);
    }

    [Fact]
    public void EveryReferenceAdapterIsNamed()
    {
        foreach (var (name, make) in MeshWitnessStoreConformance.ReferenceAdapters())
        {
            var ok = MeshWitnessStoreConformance.Run(make()).Ok;
            Assert.Equal(!name.StartsWith("bad-"), ok);
        }
    }

    [Fact]
    public void ADamagedKvStoreIsRefusedNotReadAsEmpty()
    {
        var kv = new MemoryAtomicKv();
        var store = new KvMeshWitnessStore(kv);
        Assert.Null(store.Load());
        kv.Update(KvMeshWitnessStore.DocKey, _ => "{not json");
        Assert.Throws<InvalidOperationException>(() => store.Load());
        kv.Update(KvMeshWitnessStore.DocKey, _ => "{\"v\":2,\"state\":{},\"digest\":\"\"}");
        Assert.Throws<InvalidOperationException>(() => store.Load());
    }

    static EdKey Key(byte b) => EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray());

    static Dictionary<string, object?> Cap(string id) => new() { ["id"] = id, ["issuer"] = "i" };

    [Fact]
    public void AWitnessRefusesAClockAheadHeadAndARegressingTimestamp()
    {
        var w = new MeshWitness(Key(1), new MeshWitness.Options { Clock = () => 1_000 });
        var d = new MeshDomain("d", Key(2));
        d.Record(Cap("a"));
        var ex = Assert.Throws<InvalidOperationException>(() => d.PublishHead(new[] { w }, 1_000 + MeshWitness.DefaultMaxClockSkewMs + 1));
        Assert.Equal("witness: head timestamp is in the future", ex.Message);
        d.PublishHead(new[] { w }, 900);
        d.Record(Cap("b"));
        ex = Assert.Throws<InvalidOperationException>(() => d.PublishHead(new[] { w }, 800));
        Assert.Equal("witness: timestamp regresses", ex.Message);
    }

    [Fact]
    public void AWitnessRefusesToDropARevocationAndStateRoundTrips()
    {
        var w = new MeshWitness(Key(1));
        var d = new MeshDomain("d", Key(2));
        d.Record(Cap("a"));
        d.Revoke("r1");
        d.PublishHead(new[] { w }, 1);
        var w2 = new MeshWitness(Key(1));
        w2.ImportState(w.ExportState());
        Assert.Equal(w.ExportState().Count, w2.ExportState().Count);
        Assert.Equal(Pca.Canonicalize(w.ExportState()), Pca.Canonicalize(w2.ExportState()));
        var fresh = new MeshDomain("d", Key(2));
        fresh.Record(Cap("a"));
        var ex = Assert.Throws<InvalidOperationException>(() => fresh.PublishHead(new[] { w2 }, 2));
        Assert.StartsWith("witness: ", ex.Message);
        var bad = new Dictionary<string, object?> { ["seen"] = new List<object?> { new Dictionary<string, object?> { ["head"] = 1 } } };
        Assert.Throws<InvalidOperationException>(() => new MeshWitness(Key(1)).ImportState(bad));
    }
}
