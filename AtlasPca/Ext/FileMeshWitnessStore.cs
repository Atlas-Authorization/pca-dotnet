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

    public FileMeshWitnessStore(string path) => _path = path ?? throw new ArgumentNullException(nameof(path));

    public D? Load()
    {
        if (!File.Exists(_path)) return null;
        object? doc;
        try { doc = Pca.ParseJson(File.ReadAllText(_path, Encoding.UTF8)); }
        catch (Exception) { throw new InvalidOperationException("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty"); }
        if (doc is not D d || !(IntentJs.NumOf(d.GetValueOrDefault("v")) == 1.0) || d.GetValueOrDefault("digest") is not string digest || d.GetValueOrDefault("state") is not D state)
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

    static void FsyncDirectory(string dir)
    {
        if (OperatingSystem.IsWindows()) return;
        var fd = open(dir, 0); // O_RDONLY
        if (fd < 0) throw new IOException($"FileMeshWitnessStore: cannot open the directory for fsync (errno {Marshal.GetLastWin32Error()})");
        try { if (fsync(fd) != 0) throw new IOException($"FileMeshWitnessStore: directory fsync failed (errno {Marshal.GetLastWin32Error()})"); }
        finally { close(fd); }
    }
}
