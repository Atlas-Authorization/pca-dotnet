using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class StoreConformanceBondTests
{
    [Fact]
    public void TheMemoryStorePassesAndSkipsWhatItDeclaresItCannotDo()
    {
        var r = BondStoreConformance.Run(BondStoreConformance.MemoryStoreAdapter());
        Assert.True(r.Ok, r.Format());
        Assert.Equal("skip", r.Check("state-survives-reopen").Status);
        Assert.Equal("skip", r.Check("acknowledged-commits-survive-a-crash").Status);
        Assert.Equal(18, r.Count("pass"));
    }

    [Fact]
    public void ADurableKvStorePassesEveryCheck()
    {
        var a = BondStoreConformance.KvStoreAdapter("kv", true, () => { var kv = new MemoryAtomicKv(); return () => kv; }, true);
        var r = BondStoreConformance.Run(a);
        Assert.True(r.Ok, r.Format());
        Assert.Equal(20, r.Count("pass"));
    }

    [Fact]
    public void EveryDefectiveStoreIsCaught()
    {
        foreach (var (name, make) in BondStoreConformance.ReferenceAdapters())
        {
            var r = BondStoreConformance.Run(make());
            Assert.Equal(!name.StartsWith("bad-"), r.Ok);
        }
    }

    // the lost-update reference adapters pause in StoreSuite.RaceWindow: inside a Parallel batch nobody leaves it before every racer
    // has entered (a racer that starts 300 ms late still meets the others), a racer's second window passes at once, and outside a
    // batch it does not wait at all
    [Fact]
    public void RacersAllMeetInTheRaceWindow()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var tasks = new List<Func<(long In, long Out, long Again)>>();
        for (int i = 0; i < 3; i++)
        {
            int n = i;
            tasks.Add(() =>
            {
                if (n == 0) Thread.Sleep(300);
                var a = sw.ElapsedMilliseconds;
                StoreSuite.RaceWindow();
                var o = sw.ElapsedMilliseconds;
                StoreSuite.RaceWindow();
                return (a, o, sw.ElapsedMilliseconds - o);
            });
        }
        var r = StoreSuite.Parallel(tasks);
        var lastIn = r.Max(x => x.In);
        Assert.True(lastIn >= 300, "the late racer entered late");
        Assert.All(r, x => Assert.True(x.Out >= lastIn, "a racer left the window before the last one entered"));
        Assert.All(r, x => Assert.True(x.Again < StoreSuite.RaceTimeout.TotalMilliseconds / 2, "a second window waited"));
        Assert.True(sw.ElapsedMilliseconds < StoreSuite.RaceTimeout.TotalMilliseconds / 2, "the racers waited for the timeout");
        var t = System.Diagnostics.Stopwatch.StartNew();
        StoreSuite.RaceWindow();
        Assert.True(t.ElapsedMilliseconds < StoreSuite.RaceTimeout.TotalMilliseconds / 2, "a window outside a batch waited");
    }

    [Fact]
    public void SpecificDefectsFailTheirOwnChecks()
    {
        Assert.Equal("fail", BondStoreConformance.Run(BondStoreConformance.DefectiveStoreAdapter(BondStoreConformance.Defect.NonAtomic)).Check("settle-needs-the-expected-phase").Status);
        Assert.Equal("fail", BondStoreConformance.Run(BondStoreConformance.DefectiveStoreAdapter(BondStoreConformance.Defect.NoReplay)).Check("settle-retry-returns-the-stored-record").Status);
        Assert.Equal("fail", BondStoreConformance.Run(BondStoreConformance.DefectiveStoreAdapter(BondStoreConformance.Defect.Amnesia)).Check("state-survives-reopen").Status);
        Assert.Equal("fail", BondStoreConformance.Run(BondStoreConformance.DefectiveStoreAdapter(BondStoreConformance.Defect.ClockRewind)).Check("time-high-water-only-moves-forward").Status);
        Assert.Equal("fail", BondStoreConformance.Run(BondStoreConformance.DefectiveStoreAdapter(BondStoreConformance.Defect.LostUpdate)).Check("concurrent-deposits-lose-nothing").Status);
    }

    [Fact]
    public void MicroUnitArithmeticIsExactAndOverdraftsAreRefused()
    {
        Assert.Equal(0.3, BondDoc.ExactAdd(0.1, 0.2, 1));
        Assert.Equal(0.1, BondDoc.ExactAdd(0.3, 0.2, -1));
        var moves = new List<object?> { new D { ["account"] = "a", ["op"] = "debit", ["amount"] = new Num("1") } };
        var ex = Assert.Throws<InvalidOperationException>(() => BondDoc.ApplyBondMoves(_ => 0.0, moves));
        Assert.Equal("debit: insufficient balance for a", ex.Message);
        var bad = new List<object?> { new D { ["account"] = "a", ["op"] = "credit", ["amount"] = new Num("-1") } };
        Assert.Equal("credit: invalid amount", Assert.Throws<InvalidOperationException>(() => BondDoc.ApplyBondMoves(_ => 0.0, bad)).Message);
    }

    [Fact]
    public void ADamagedDocumentFailsClosed()
    {
        var kv = new MemoryAtomicKv();
        var store = new KvBondStore(kv);
        kv.Update(KvBondStore.DocKey, _ => "{\"v\":1,\"balances\":[[\"a\",-1]],\"bonds\":[],\"highWater\":0}");
        Assert.Equal("store_corrupt", Assert.Throws<BondStoreError>(() => store.Read("x", null)).Code);
        Assert.Equal("store_missing", Assert.Throws<BondStoreError>(() => new KvBondStore(null!)).Code);
    }
}
