using AtlasPca;
using AtlasPca.Ciba;
using AtlasPca.Revoke;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Every writer that keeps a file or directory private reads back as owner-only: mode 0600 / 0700 on Unix, a protected DACL with one entry for the current user on Windows.</summary>
public class OwnerOnlyTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "pca-owner-" + Guid.NewGuid().ToString("N"));

    public OwnerOnlyTests() => Directory.CreateDirectory(_dir);

    public void Dispose() { try { Directory.Delete(_dir, true); } catch (Exception) { } }

    string P(string name) => Path.Combine(_dir, name);

    [Fact]
    public void TheHelperRestrictsAFileAndADirectory()
    {
        var f = P("f"); File.WriteAllText(f, "x");
        OwnerOnly.File(f);
        Assert.True(OwnerOnly.IsOwnerOnly(f));
        var d = P("d"); Directory.CreateDirectory(d);
        OwnerOnly.Directory(d);
        Assert.True(OwnerOnly.IsOwnerOnly(d, true));
    }

    [Fact]
    public async Task TheFileRevocationStoreWritesOwnerOnly()
    {
        var p = P("rev.json");
        await new FileRevocationStore(p).Add(new D { ["kind"] = "cap", ["value"] = "c1", ["reason"] = "r", ["revokedAt"] = new Num("1700000000000") });
        Assert.True(OwnerOnly.IsOwnerOnly(p));
    }

    [Fact]
    public void TheMeshWitnessStoreWritesOwnerOnly()
    {
        var p = P("witness.json");
        new FileMeshWitnessStore(p).Save(new D { ["n"] = new Num("1") });
        Assert.True(OwnerOnly.IsOwnerOnly(p));
    }

    [Fact]
    public void TheCibaDirectoryKvAndFileStoreWriteOwnerOnly()
    {
        var dir = P("kv");
        var kv = CibaKv.CreateDirectoryKv(dir);
        Assert.True(OwnerOnly.IsOwnerOnly(dir, true));
        var store = CibaApproval.CreateFileApprovalStore(P("approvals.json"));
        Assert.True(store.Cas("k", 0, new D { ["a"] = new Num("1") }));
        Assert.True(OwnerOnly.IsOwnerOnly(P("approvals.json")));
        Assert.NotNull(kv);
    }

    [Fact]
    public void TheDurableStateWritesOwnerOnly()
    {
        var dir = P("ds");
        Assert.NotNull(DurableState.OpenDurableState(new DurableStateOptions { Dir = dir }));
        Assert.True(OwnerOnly.IsOwnerOnly(dir, true));
        var f = P("ds-new");
        Ds.WriteNew(f, "data");
        Assert.True(OwnerOnly.IsOwnerOnly(f));
    }
}
