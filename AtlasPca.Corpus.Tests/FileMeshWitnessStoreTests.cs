using System.Runtime.InteropServices;
using AtlasPca.Js;
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

    const string Shape = "FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty";

    // each shape condition alone: a saved file with exactly one field broken
    [Fact]
    public void EveryShapeConditionIsCheckedOnItsOwn()
    {
        var s = new FileMeshWitnessStore(F);
        s.Save(new D { ["n"] = new Num("1") });
        var good = (D)Pca.ParseJson(File.ReadAllText(F))!;
        void Expect(string text, string message)
        {
            File.WriteAllText(F, text);
            Assert.Equal(message, Assert.Throws<InvalidOperationException>(() => s.Load()).Message);
        }
        D With(string k, object? v) { var d = new D(good); if (v == null) d.Remove(k); else d[k] = v; return d; }
        Expect("[" + File.ReadAllText(F) + "]", Shape);
        Expect(JsJson.Stringify(With("v", new Num("2"))), Shape);
        Expect(JsJson.Stringify(With("digest", null)), Shape);
        Expect(JsJson.Stringify(With("digest", new Num("1"))), Shape);
        Expect(JsJson.Stringify(With("state", null)), Shape);
        Expect(JsJson.Stringify(With("state", new List<object?>())), Shape);
        Expect("{ not json", "FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty");
        Expect(JsJson.Stringify(With("digest", "x")), "FileMeshWitnessStore: the state file fails its digest; refusing to start empty");
        File.WriteAllText(F, JsJson.Stringify(good));
        Assert.Equal("1", ((Num)s.Load()!["n"]!).Raw);
    }

    [Fact]
    public void ANullPathIsRefused() => Assert.Throws<ArgumentNullException>(() => new FileMeshWitnessStore(null!));

    // the state is written to a separate temporary file and renamed over the real one: when the temporary cannot be created the save
    // fails and the last saved state is untouched
    [Fact]
    public void ASaveThatCannotWriteItsTemporaryLeavesTheOldState()
    {
        var s = new FileMeshWitnessStore(F);
        s.Save(new D { ["n"] = new Num("1") });
        Directory.CreateDirectory(F + ".tmp");
        Assert.ThrowsAny<Exception>(() => s.Save(new D { ["n"] = new Num("2") }));
        Assert.Equal("1", ((Num)new FileMeshWitnessStore(F).Load()!["n"]!).Raw);
    }

    [DllImport("libc", EntryPoint = "close")] static extern int CloseFd(int fd);

    // POSIX: every save fsyncs the directory through a descriptor it then closes (Windows journals the rename: no directory sync)
    [Fact]
    public void EverySaveFsyncsTheDirectoryAndClosesIt()
    {
        if (OperatingSystem.IsWindows()) return;
        var synced = new List<int>();
        var closed = new List<int>();
        var s = new FileMeshWitnessStore(F, fd => { synced.Add(fd); return 0; }, fd => { closed.Add(fd); return CloseFd(fd); });
        s.Save(new D { ["n"] = new Num("1") });
        s.Save(new D { ["n"] = new Num("2") });
        Assert.Equal(2, synced.Count);
        Assert.All(synced, fd => Assert.True(fd > 2, "a real descriptor"));
        Assert.Equal(synced, closed);
    }

    [Fact]
    public void AFailedDirectoryFsyncFailsTheSaveAndStillClosesTheDescriptor()
    {
        if (OperatingSystem.IsWindows()) return;
        var closed = new List<int>();
        var s = new FileMeshWitnessStore(F, _ => -1, fd => { closed.Add(fd); return CloseFd(fd); });
        var e = Assert.Throws<IOException>(() => s.Save(new D { ["n"] = new Num("1") }));
        Assert.StartsWith("FileMeshWitnessStore: directory fsync failed (errno ", e.Message);
        Assert.Single(closed);
    }

    // a directory the process may write into but not read: the rename succeeds, opening the directory for its fsync does not
    [Fact]
    public void ADirectoryThatCannotBeOpenedFailsTheSave()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root") return; // root opens it anyway
        var sub = Path.Combine(_dir, "wx");
        Directory.CreateDirectory(sub);
        File.SetUnixFileMode(sub, UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var calls = 0;
            var s = new FileMeshWitnessStore(Path.Combine(sub, "w.json"), _ => { calls++; return 0; }, fd => { calls++; return CloseFd(fd); });
            var e = Assert.Throws<IOException>(() => s.Save(new D { ["n"] = new Num("1") }));
            Assert.StartsWith("FileMeshWitnessStore: cannot open the directory for fsync (errno ", e.Message);
            Assert.Equal(0, calls);
        }
        finally { File.SetUnixFileMode(sub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    }
}
