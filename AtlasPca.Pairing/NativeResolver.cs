using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace AtlasPca.Pairing;

/// <summary>Native lookup for blst plus the GT shim (imported as "blst.dll"): ATLAS_PCA_LIBBLST wins,
/// then the default probing, which finds the copy this package carries under runtimes/&lt;rid&gt;/native, then the system.</summary>
internal static class NativeResolver
{
    [ModuleInitializer]
    internal static void Init()
    {
        try { NativeLibrary.SetDllImportResolver(typeof(NativeResolver).Assembly, Resolve); }
        catch (InvalidOperationException) { } // a resolver is already set for this assembly
    }

    internal static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
    {
        if (name != "blst.dll") return IntPtr.Zero;
        var p = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBBLST");
        return !string.IsNullOrEmpty(p) && NativeLibrary.TryLoad(p, out var h) ? h : IntPtr.Zero;
    }
}
