using AtlasPca;
using AtlasPca.Revoke;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class FileRevocationStoreTests
{
    static D Entry(string kind, string value) => new() { ["kind"] = kind, ["value"] = value, ["reason"] = "r", ["revokedAt"] = new Num("1700000000000") };

    static string Temp() => Path.Combine(Path.GetTempPath(), "pca-rev-" + Guid.NewGuid().ToString("N") + ".json");

    [Fact]
    public async Task EntriesSurviveAReopen()
    {
        var p = Temp();
        try
        {
            var a = new FileRevocationStore(p);
            await a.Add(Entry("cap", "c1"));
            await a.Add(Entry("holder", "h1"));
            Assert.True(await a.Remove("cap", "c1"));
            Assert.False(await a.Remove("cap", "c1"));
            var b = new FileRevocationStore(p);
            Assert.Null(await b.Get("cap", "c1"));
            Assert.NotNull(await b.Get("holder", "h1"));
            Assert.Single(await b.All());
            await b.Clear();
            Assert.Empty(await new FileRevocationStore(p).All());
            Assert.False(File.Exists(p + ".tmp"));
        }
        finally { File.Delete(p); }
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("{\"entries\":[{\"kind\":\"bogus\",\"value\":\"x\",\"reason\":\"r\",\"revokedAt\":1}]}")]
    [InlineData("{\"entries\":[{\"kind\":\"cap\",\"value\":\"\",\"reason\":\"r\",\"revokedAt\":1}]}")]
    [InlineData("{\"entries\":[{\"kind\":\"prefix\",\"value\":\"a,b\",\"prefix\":[\"a\"],\"reason\":\"r\",\"revokedAt\":1}]}")]
    public void ACorruptFileRefusesToStartEmpty(string content)
    {
        var p = Temp();
        File.WriteAllText(p, content);
        try { Assert.Throws<InvalidOperationException>(() => new FileRevocationStore(p)); }
        finally { File.Delete(p); }
    }

    [Fact]
    public async Task AFailedFlushRollsMemoryBack()
    {
        var p = Temp();
        var a = new FileRevocationStore(p);
        await a.Add(Entry("cap", "c1"));
        try
        {
            Directory.CreateDirectory(p + ".tmp"); // the temp path is a directory: the flush fails
            await Assert.ThrowsAnyAsync<Exception>(() => a.Add(Entry("cap", "c2")));
            Assert.Null(await a.Get("cap", "c2"));
            Assert.NotNull(await a.Get("cap", "c1"));
        }
        finally { Directory.Delete(p + ".tmp"); File.Delete(p); }
    }
}
