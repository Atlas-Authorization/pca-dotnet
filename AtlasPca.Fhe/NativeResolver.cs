using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace AtlasPca.Fhe;

/// <summary>Native lookup for SEAL's C library (sealc): ATLAS_PCA_LIBSEALC wins, then the default
/// probing, which finds the copy this package carries under runtimes/&lt;rid&gt;/native, then the system.</summary>
internal static class NativeResolver
{
    [ModuleInitializer]
    internal static void Init()
    {
        try
        {
            NativeLibrary.SetDllImportResolver(typeof(Microsoft.Research.SEAL.Evaluator).Assembly, Resolve);
        }
        catch (InvalidOperationException) { } // a resolver is already set for that assembly
    }

    internal static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
    {
        if (name != "sealc") return IntPtr.Zero;
        var p = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBSEALC");
        return !string.IsNullOrEmpty(p) && NativeLibrary.TryLoad(p, out var h) ? h : IntPtr.Zero;
    }
}
