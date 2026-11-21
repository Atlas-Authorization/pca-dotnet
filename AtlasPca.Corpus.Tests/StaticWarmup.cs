using System.Reflection;
using System.Runtime.CompilerServices;
using AtlasPca;

namespace AtlasPca.TestHost;

/// <summary>Stryker reuses one test host across mutants and sets the active mutant per test case. A static field of the library that is built by a
/// call into library code stays as it was when its type initializer first ran: had a mutant of that code been active then, every later mutant in
/// the host would run against the broken value (and be falsely killed). The library fields of that kind were turned into per-access members; the one
/// left, <c>LessNative.Fn</c> (it loads a native library once), is initialised here, before any test, with NO mutant active. Its loader's own mutants
/// are still tested: R9KillTests.LoadRefusesALibraryWithOtherSizesOrNoVerifyExport calls Load directly, outside any initializer. In a build
/// without Stryker's injected Stryker.MutantControl the field lookup finds nothing and only the initialisation runs.</summary>
static class StaticWarmup
{
    [ModuleInitializer]
    internal static void Run()
    {
        var field = typeof(LessNative).Assembly.GetType("Stryker.MutantControl")?.GetField("ActiveMutant", BindingFlags.Public | BindingFlags.Static);
        var before = field?.GetValue(null);
        try
        {
            field?.SetValue(null, -1); // no mutant active (Stryker's own "not initialised" value is -2)
            RuntimeHelpers.RunClassConstructor(typeof(LessNative).TypeHandle);
        }
        finally { field?.SetValue(null, before); }
    }
}
