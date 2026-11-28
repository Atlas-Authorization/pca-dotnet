using System.Diagnostics;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The platform layer of the durable store (hard link, process liveness, directory fsync, errno names) directly, so each branch (libc on
/// Unix, CreateHardLinkW / the process table on Windows) is pinned by the runner that executes it; the Windows mutation shard runs this class.</summary>
public class DsNativeTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "pca-dsn-" + Guid.NewGuid().ToString("N"));
    public DsNativeTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public void LinkCreatesTheNameOnceAndReportsAnExistingNameAsEexist()
    {
        var a = Path.Combine(_dir, "a"); File.WriteAllText(a, "x");
        var b = Path.Combine(_dir, "b");
        Assert.Equal(0, DsNative.Link(a, b));
        Assert.Equal("x", File.ReadAllText(b));
        Assert.Equal(DsNative.Eexist, DsNative.Link(a, b));
        Assert.Equal(17, DsNative.Eexist);
        var rc = DsNative.Link(Path.Combine(_dir, "missing"), Path.Combine(_dir, "c"));
        Assert.NotEqual(0, rc);
        Assert.NotEqual(DsNative.Eexist, rc);
        Assert.False(File.Exists(Path.Combine(_dir, "c")));
    }

    [Fact]
    public void PidAliveIsTrueForThisProcessAndFalseForNonPidsAndExitedProcesses()
    {
        Assert.True(DsNative.PidAlive(Environment.ProcessId));
        Assert.False(DsNative.PidAlive(double.NaN));
        Assert.False(DsNative.PidAlive(double.PositiveInfinity));
        Assert.False(DsNative.PidAlive(1.5));
        Assert.False(DsNative.PidAlive((double)int.MaxValue + 1));
        Assert.False(DsNative.PidAlive((double)int.MinValue - 1));
        var psi = new ProcessStartInfo(Environment.ProcessPath!, "--version") { RedirectStandardOutput = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var pid = p.Id;
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Assert.False(DsNative.PidAlive(pid));
    }

    [Fact]
    public void FsyncDirSucceedsOnADirectoryAndFailsOnAMissingOneWhereTheDirectoryIsSynced()
    {
        DsNative.FsyncDir(_dir);
        if (!OperatingSystem.IsWindows())
        {
            var e = Assert.Throws<IOException>(() => DsNative.FsyncDir(Path.Combine(_dir, "missing")));
            Assert.Contains("ENOENT", e.Message);
        }
        else DsNative.FsyncDir(Path.Combine(_dir, "missing")); // NTFS journals the rename: there is no directory fsync to fail
    }

    [Theory]
    [InlineData(1, "EPERM")] [InlineData(2, "ENOENT")] [InlineData(13, "EACCES")] [InlineData(17, "EEXIST")] [InlineData(18, "EXDEV")]
    [InlineData(31, "EMLINK")] [InlineData(95, "ENOTSUP")] [InlineData(45, "ENOTSUP")] [InlineData(38, "ENOSYS")] [InlineData(999, "errno 999")]
    public void ErrNameNamesTheErrno(int e, string name) => Assert.Equal(name, DsNative.ErrName(e));
}
