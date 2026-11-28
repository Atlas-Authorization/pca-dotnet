using System.Security.AccessControl;
using System.Security.Principal;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Windows: the exact DACL each OwnerOnly writer leaves (protected, one explicit allow entry for the current user with full control, inheritable
/// to children only on a directory), the access a created file's stream gets, and IsOwnerOnly refusing each way a DACL can fall short. (POSIX modes:
/// OwnerOnlyTests.)</summary>
public class OwnerOnlyTestsWindows : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "pca-owner-win-" + Guid.NewGuid().ToString("N"));

    public OwnerOnlyTestsWindows() => Directory.CreateDirectory(_dir);

    public void Dispose() { try { Directory.Delete(_dir, true); } catch (Exception) { } }

    string P(params string[] names) => Path.Combine(new[] { _dir }.Concat(names).ToArray());

    static void AssertOwnerOnlyAcl(string path, bool directory)
    {
        if (!OperatingSystem.IsWindows()) return;
        FileSystemSecurity sec = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        Assert.True(sec.AreAccessRulesProtected, "inheritance is cut");
        var r = Assert.Single(sec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>());
        Assert.Equal(AccessControlType.Allow, r.AccessControlType);
        Assert.Equal(WindowsIdentity.GetCurrent().User, r.IdentityReference);
        Assert.Equal(FileSystemRights.FullControl, r.FileSystemRights & FileSystemRights.FullControl);
        Assert.False(r.IsInherited);
        Assert.Equal(directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, r.InheritanceFlags);
        Assert.Equal(PropagationFlags.None, r.PropagationFlags);
    }

    [Fact]
    public void EveryWriterLeavesTheExactOwnerOnlyAcl()
    {
        if (!OperatingSystem.IsWindows()) return;
        var f = P("f"); File.WriteAllText(f, "x");
        OwnerOnly.File(f);
        AssertOwnerOnlyAcl(f, false);
        var d = P("d"); Directory.CreateDirectory(d);
        OwnerOnly.Directory(d);
        AssertOwnerOnlyAcl(d, true);
        var c = P("created");
        using (OwnerOnly.CreateFile(c, FileMode.CreateNew)) { }
        AssertOwnerOnlyAcl(c, false);
        var g = P("replaced"); File.WriteAllText(g, "old");
        OwnerOnly.WriteAllBytes(g, new byte[] { 7 });
        AssertOwnerOnlyAcl(g, false);
        Assert.Equal(new byte[] { 7 }, File.ReadAllBytes(g));
        var nd = P("new-dir");
        OwnerOnly.CreateDirectory(nd);
        AssertOwnerOnlyAcl(nd, true);
    }

    // an existing directory is restricted in place; a missing parent is created first
    [Fact]
    public void CreateDirectoryRestrictsAnExistingOneAndCreatesMissingParents()
    {
        if (!OperatingSystem.IsWindows()) return;
        var e = P("existing"); Directory.CreateDirectory(e);
        Assert.False(OwnerOnly.IsOwnerOnly(e, true));
        Assert.Equal(Path.GetFullPath(e), OwnerOnly.CreateDirectory(e).FullName);
        AssertOwnerOnlyAcl(e, true);
        var nested = P("a", "b", "c");
        Assert.Equal(Path.GetFullPath(nested), OwnerOnly.CreateDirectory(nested).FullName);
        Assert.True(Directory.Exists(nested));
        AssertOwnerOnlyAcl(nested, true);
    }

    [Fact]
    public void ACreatedFileStreamHasTheAccessAskedFor()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var w = OwnerOnly.CreateFile(P("w"), FileMode.CreateNew, FileAccess.Write)) { Assert.True(w.CanWrite); Assert.False(w.CanRead); w.WriteByte(1); }
        // (a read-only creation needs a mode that does not truncate: CreateNew / Create with read access alone are refused)
        using (var r = OwnerOnly.CreateFile(P("r"), FileMode.OpenOrCreate, FileAccess.Read)) { Assert.True(r.CanRead); Assert.False(r.CanWrite); }
        using (var rw = OwnerOnly.CreateFile(P("rw"), FileMode.CreateNew, FileAccess.ReadWrite))
        {
            Assert.True(rw.CanRead); Assert.True(rw.CanWrite);
            rw.WriteByte(9); rw.Position = 0;
            Assert.Equal(9, rw.ReadByte());
        }
        // FileMode.Create replaces an existing file with a new owner-only one
        File.WriteAllText(P("w"), "loose");
        using (var again = OwnerOnly.CreateFile(P("w"), FileMode.Create)) { again.WriteByte(2); }
        AssertOwnerOnlyAcl(P("w"), false);
        Assert.Equal(new byte[] { 2 }, File.ReadAllBytes(P("w")));
    }

    static FileSystemAccessRule Rule(IdentityReference who, FileSystemRights rights, AccessControlType type) => new(who, rights, type);

    string FileWithAcl(string name, bool protect, params FileSystemAccessRule[] rules)
    {
        var p = P(name);
        File.WriteAllText(p, "x");
        if (!OperatingSystem.IsWindows()) return p;
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(protect, false);
        foreach (var r in rules) sec.AddAccessRule(r);
        new FileInfo(p).SetAccessControl(sec);
        return p;
    }

    // each condition of IsOwnerOnly alone: protected, exactly one entry, an allow entry, for the current user
    [Fact]
    public void IsOwnerOnlyRefusesEachWayADaclFallsShort()
    {
        if (!OperatingSystem.IsWindows()) return;
        var me = WindowsIdentity.GetCurrent().User!;
        var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var ok = FileWithAcl("ok", true, Rule(me, FileSystemRights.FullControl, AccessControlType.Allow));
        Assert.True(OwnerOnly.IsOwnerOnly(ok));
        // not protected: a file created normally inside an owner-only directory inherits exactly its one entry (me, allow)
        var sub = P("inherit");
        OwnerOnly.CreateDirectory(sub);
        var inherited = Path.Combine(sub, "f");
        File.WriteAllText(inherited, "x");
        var isec = new FileInfo(inherited).GetAccessControl();
        Assert.False(isec.AreAccessRulesProtected);
        var only = Assert.Single(isec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>());
        Assert.True(only.IsInherited);
        Assert.Equal(me, only.IdentityReference);
        Assert.False(OwnerOnly.IsOwnerOnly(inherited));
        // two entries, the first one mine
        Assert.False(OwnerOnly.IsOwnerOnly(FileWithAcl("two", true, Rule(me, FileSystemRights.FullControl, AccessControlType.Allow), Rule(world, FileSystemRights.Read, AccessControlType.Allow))));
        // one entry, but a deny
        Assert.False(OwnerOnly.IsOwnerOnly(FileWithAcl("deny", true, Rule(me, FileSystemRights.WriteData, AccessControlType.Deny))));
        // one allow entry, for someone else
        Assert.False(OwnerOnly.IsOwnerOnly(FileWithAcl("world", true, Rule(world, FileSystemRights.FullControl, AccessControlType.Allow))));
        // a directory is judged the same way
        var d = P("loose-dir"); Directory.CreateDirectory(d);
        Assert.False(OwnerOnly.IsOwnerOnly(d, true));
    }
}
