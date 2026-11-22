using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

public class FileMeshWitnessStoreTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "pca-fmw-" + Guid.NewGuid().ToString("N"));
    string F => Path.Combine(_dir, "witness.json");
    public FileMeshWitnessStoreTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public void SavesAtomicallyAndLoadsWhatWasSaved()
    {
        var s = new FileMeshWitnessStore(F);
        Assert.Null(s.Load());                         // a missing file is a first run
        var state = new D { ["heads"] = new D { ["a"] = new Num("1") }, ["n"] = new Num("7") };
        s.Save(state);
        Assert.False(File.Exists(F + ".tmp"));
        Assert.Equal(Pca.Canonicalize(state), Pca.Canonicalize(new FileMeshWitnessStore(F).Load()));
        s.Save(new D { ["n"] = new Num("8") });
        Assert.Equal("8", ((Num)new FileMeshWitnessStore(F).Load()!["n"]!).Raw);
    }

    [Fact]
    public void ADamagedFileIsNeverReadAsEmpty()
    {
        var s = new FileMeshWitnessStore(F);
        s.Save(new D { ["n"] = new Num("1") });
        File.WriteAllText(F, File.ReadAllText(F).Replace("\"n\":1", "\"n\":2"));   // edited state, stale digest
        Assert.Contains("digest", Assert.Throws<InvalidOperationException>(() => s.Load()).Message);
        File.WriteAllText(F, "{ not json");
        Assert.Contains("not valid JSON", Assert.Throws<InvalidOperationException>(() => s.Load()).Message);
        File.WriteAllText(F, "{\"v\":2}");
        Assert.Contains("unexpected shape", Assert.Throws<InvalidOperationException>(() => s.Load()).Message);
    }
}
