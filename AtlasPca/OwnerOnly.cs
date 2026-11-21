using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AtlasPca;

/// <summary>Restricts a file or directory to its owner: mode 0600 (0700 for a directory) on Unix, and on Windows a protected DACL (inheritance cut,
/// inherited entries not kept) with a single allow entry for the current user.</summary>
public static class OwnerOnly
{
    public static void File(string path) => Apply(path, false);

    public static void Directory(string path) => Apply(path, true);

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
        var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current user has no SID");
        if (directory)
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(sec);
        }
        else
        {
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(sec);
        }
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
