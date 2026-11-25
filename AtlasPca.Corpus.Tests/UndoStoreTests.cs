using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The undo-store contract run against both reference stores.</summary>
public class UndoStoreTests
{
    static D Rec(string id, string state = "open", long ver = 1, long windowEnd = 100, string grant = "g1") => new()
    {
        ["v"] = new Num("1"), ["id"] = id, ["state"] = state, ["ver"] = new Num(ver.ToString()), ["receipts"] = new L(), ["window_end"] = new Num(windowEnd.ToString()), ["grant_ref"] = grant,
    };

    public static IEnumerable<object[]> Stores() => new[]
    {
        new object[] { new MemoryUndoStore() },
        new object[] { new KvUndoStore(new MemoryAtomicKv(), false) },
    };

    [Theory, MemberData(nameof(Stores))]
    public async Task Contract(IUndoStore s)
    {
        Assert.False(s.Durable);
        Assert.Null(await s.GetAsync("a"));
        Assert.True((await s.CreateAsync(Rec("a"))).Created);
        var again = await s.CreateAsync(Rec("a", ver: 9));
        Assert.False(again.Created);
        Assert.Equal(1L, (long)IntentJs.NumOf(again.Record!["ver"])!.Value); // the stored one, unchanged
        Assert.False(await s.ReplaceAsync("a", 7, Rec("a", ver: 8)));        // wrong expected version
        Assert.True(await s.ReplaceAsync("a", 1, Rec("a", "vetoed", 2)));
        Assert.Equal("vetoed", (await s.GetAsync("a"))!["state"]);
        await s.CreateAsync(Rec("c", windowEnd: 50)); await s.CreateAsync(Rec("b", windowEnd: 200, grant: "g2"));
        Assert.Equal(new[] { "b", "c" }, (await s.ListAsync(new UndoQuery("open"))).Select(r => (string)r["id"]!));
        Assert.Equal(new[] { "c" }, (await s.ListAsync(new UndoQuery("open", WindowEndedBy: 100))).Select(r => (string)r["id"]!));
        Assert.Equal(new[] { "b" }, (await s.ListAsync(new UndoQuery("open", GrantRef: "g2"))).Select(r => (string)r["id"]!));
        Assert.Single(await s.ListAsync(new UndoQuery("open", Limit: 1)));
        await Assert.ThrowsAsync<UndoError>(() => s.CreateAsync(Rec("")));
        await Assert.ThrowsAnyAsync<UndoError>(() => s.ReplaceAsync("a", 2, Rec("zz", ver: 3)));
        Assert.True(UndoStores.IsUndoStore(s));
    }

    [Fact]
    public async Task KvStoreRefusesACorruptRecord()
    {
        var kv = new MemoryAtomicKv();
        kv.Update("pca-undo/v1/x", _ => "{\"v\":1,\"id\":\"x\"}");
        var e = await Assert.ThrowsAsync<UndoError>(() => new KvUndoStore(kv, true).GetAsync("x"));
        Assert.Equal("store_corrupt", e.Code);
        Assert.True(new KvUndoStore(kv, true).Durable);
    }
}
