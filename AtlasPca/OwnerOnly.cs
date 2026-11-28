using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AtlasPca;

/// <summary>Restricts a file or directory to its owner: mode 0600 (0700 for a directory) on Unix, and on Windows a protected DACL (inheritance cut,
/// inherited entries not kept) with a single allow entry for the current user.</summary>
public static class OwnerOnly
{
    /// <summary>Restrict an EXISTING file in place (it was not created owner-only: prefer <see cref="CreateFile"/>).</summary>
    public static void File(string path) => Apply(path, false);

    /// <summary>Restrict an EXISTING directory in place (prefer <see cref="CreateDirectory"/>).</summary>
    public static void Directory(string path) => Apply(path, true);

    /// <summary>Open a new file that is owner-only from the first instant it exists: the Unix create mode, or on Windows a creation that carries the protected
    /// one-entry DACL, so no other process can hold a handle opened under a looser one. <see cref="FileMode.Create"/> replaces an existing file by deleting it first
    /// (creation security does not apply to a file that is already there).</summary>
    public static FileStream CreateFile(string path, FileMode mode, FileAccess access = FileAccess.Write, FileShare share = FileShare.None, int bufferSize = 4096, FileOptions options = FileOptions.None)
    {
        if (!OperatingSystem.IsWindows())
        {
            if (mode == FileMode.Create) { System.IO.File.Delete(path); mode = FileMode.CreateNew; } // an existing file would keep its old mode
            return new FileStream(path, new FileStreamOptions
            {
                Mode = mode, Access = access, Share = share, BufferSize = bufferSize, Options = options,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
        }
        return CreateFileWindows(path, mode, access, share, bufferSize, options);
    }

    [SupportedOSPlatform("windows")]
    static FileStream CreateFileWindows(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, FileOptions options)
    {
        if (mode == FileMode.Create) { System.IO.File.Delete(path); mode = FileMode.CreateNew; }
        var rights = access == FileAccess.Read ? FileSystemRights.Read : access == FileAccess.ReadWrite ? FileSystemRights.Read | FileSystemRights.Write : FileSystemRights.Write;
        // FileSystemAclExtensions.Create derives the stream's FileAccess from the rights mask and reports any write mask as ReadWrite,
        // so the handle (which carries only the rights asked for) is re-wrapped in a stream with exactly the access asked for; unbuffered,
        // so the first stream holds no data, and it never closes the handle on finalization
        var created = new FileInfo(path).Create(mode, rights, share, 1, options, OwnerOnlyFileSecurity()); // 1: no buffer (Create refuses 0)
        var handle = created.SafeFileHandle;
        GC.SuppressFinalize(created);
        return new FileStream(handle, access, bufferSize, (options & FileOptions.Asynchronous) != 0);
    }

    /// <summary>Write a new owner-only file with the given content (an existing file is replaced).</summary>
    public static void WriteAllBytes(string path, byte[] bytes)
    {
        using var fs = CreateFile(path, FileMode.Create);
        fs.Write(bytes, 0, bytes.Length);
        fs.Flush(true);
    }

    /// <summary>Create a directory that is owner-only from the first instant it exists (mode 0700, or on Windows a creation that carries the protected DACL). A directory that
    /// already exists is restricted in place.</summary>
    public static DirectoryInfo CreateDirectory(string path)
    {
        if (System.IO.Directory.Exists(path)) { Apply(path, true); return new DirectoryInfo(path); }
        if (!OperatingSystem.IsWindows())
            return System.IO.Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return CreateDirectoryWindows(path);
    }

    [SupportedOSPlatform("windows")]
    static DirectoryInfo CreateDirectoryWindows(string path)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(path));
        if (parent != null) System.IO.Directory.CreateDirectory(parent);
        var di = new DirectoryInfo(path);
        di.Create(OwnerOnlyDirectorySecurity());
        return di;
    }

    [SupportedOSPlatform("windows")]
    static FileSecurity OwnerOnlyFileSecurity()
    {
        var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current user has no SID");
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return sec;
    }

    [SupportedOSPlatform("windows")]
    static DirectorySecurity OwnerOnlyDirectorySecurity()
    {
        var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current user has no SID");
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    static void Apply(string path, bool directory)
    {
        if (!OperatingSystem.IsWindows())
        {
            System.IO.File.SetUnixFileMode(path, directory
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                : UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return;
        }
        ApplyWindows(path, directory);
    }

    [SupportedOSPlatform("windows")]
    static void ApplyWindows(string path, bool directory)
    {
        if (directory) new DirectoryInfo(path).SetAccessControl(OwnerOnlyDirectorySecurity());
        else new FileInfo(path).SetAccessControl(OwnerOnlyFileSecurity());
    }

    /// <summary>True when the path's DACL is protected and holds exactly one allow entry, for the current user (Windows); the mode is owner-only elsewhere.</summary>
    public static bool IsOwnerOnly(string path, bool directory = false)
    {
        if (!OperatingSystem.IsWindows())
        {
            var want = directory ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute : UnixFileMode.UserRead | UnixFileMode.UserWrite;
            return System.IO.File.GetUnixFileMode(path) == want;
        }
        return IsOwnerOnlyWindows(path, directory);
    }

    [SupportedOSPlatform("windows")]
    static bool IsOwnerOnlyWindows(string path, bool directory)
    {
        var me = WindowsIdentity.GetCurrent().User;
        FileSystemSecurity sec = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
        return sec.AreAccessRulesProtected && rules.Count == 1 && rules[0].AccessControlType == AccessControlType.Allow && rules[0].IdentityReference.Equals(me);
    }
}
