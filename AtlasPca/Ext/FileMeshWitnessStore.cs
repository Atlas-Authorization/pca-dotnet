// A file-backed IMeshWitnessStore (the reference FileMeshWitnessStore). Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the
// directory, so a crash leaves the old state or the new one, never a torn file. The file carries a digest of its state; a file that does not parse, has the wrong shape
// or fails the digest makes Load throw: a witness never starts empty over a damaged file. A missing file is a first run. Single process: two witnesses must not share one file.
// shortcut: the directory fsync is a POSIX call (libc); on Windows the rename is journaled by the file system and no directory sync is issued.
using System.Runtime.InteropServices;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed class FileMeshWitnessStore : IMeshWitnessStore
{
    readonly string _path;
    readonly Func<int, int> _fsync, _close;

    public FileMeshWitnessStore(string path) : this(path, fsync, close) { }

    // the directory fsync's libc fsync(2) and close(2), replaceable by a test (a failing fsync, a recorded close)
    internal FileMeshWitnessStore(string path, Func<int, int> dirFsync, Func<int, int> dirClose)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
        _fsync = dirFsync;
        _close = dirClose;
    }

    public D? Load()
    {
        if (!File.Exists(_path)) return null;
        object? doc = null;
        try { doc = Pca.ParseJson(File.ReadAllText(_path, Encoding.UTF8)); }
        catch (Exception) { throw new InvalidOperationException("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty"); }
        // `as`, not pattern variables read after the check: a mutant that drops the throw must still compile (CS0165), or Stryker drops every mutant of the method
        var d = doc as D;
        var digest = d?.GetValueOrDefault("digest") as string;
        var state = d?.GetValueOrDefault("state") as D;
        if (d == null || !(IntentJs.NumOf(d.GetValueOrDefault("v")) == 1.0) || digest == null || state == null)
            throw new InvalidOperationException("FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty");
        if (Pca.HashCanonical(state) != digest) throw new InvalidOperationException("FileMeshWitnessStore: the state file fails its digest; refusing to start empty");
        return state;
    }

    public void Save(D state)
    {
        var body = AtlasPca.Js.JsJson.Stringify(new D { ["v"] = new Num("1"), ["state"] = state, ["digest"] = Pca.HashCanonical(state) });
        var tmp = _path + ".tmp";
        using (var fs = OwnerOnly.CreateFile(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
        }
        File.Move(tmp, _path, overwrite: true);
        FsyncDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
    }

    [DllImport("libc", SetLastError = true)] static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", SetLastError = true)] static extern int fsync(int fd);
    [DllImport("libc", SetLastError = true)] static extern int close(int fd);

    void FsyncDirectory(string dir)
    {
        if (OperatingSystem.IsWindows()) return;
        var fd = open(dir, 0); // O_RDONLY
        if (fd == -1) throw new IOException($"FileMeshWitnessStore: cannot open the directory for fsync (errno {Marshal.GetLastWin32Error()})");
        try { if (_fsync(fd) != 0) throw new IOException($"FileMeshWitnessStore: directory fsync failed (errno {Marshal.GetLastWin32Error()})"); }
        finally { _close(fd); }
    }
}
