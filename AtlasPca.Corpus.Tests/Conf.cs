using System.Globalization;
using AtlasPca;

namespace AtlasPca.Corpus.Tests;

/// <summary>Locates the shared conformance files by walking up from the test binary: the flagship layout
/// (packages/pca/conformance, packages/pca-conformance/vectors/goal) the CI source layout rebuilds. A missing file FAILS the
/// test (a vector file is never silently skipped).</summary>
internal static class Conf
{
    // The flagship layout (packages/pca/conformance, packages/pca-conformance/vectors/goal) or the mirror layout (conformance/, conformance/goal).
    static (string Conformance, string Goal) Locate()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var fc = Path.Combine(d, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(fc, "vectors.json"))) return (fc, Path.Combine(d, "packages", "pca-conformance", "vectors", "goal"));
            var mc = Path.Combine(d, "conformance");
            if (File.Exists(Path.Combine(mc, "vectors.json"))) return (mc, Path.Combine(mc, "goal"));
        }
        throw new FileNotFoundException("conformance/vectors.json not found above " + AppContext.BaseDirectory);
    }

    internal static string Dir() => Locate().Conformance;
    internal static string GoalDir()
    {
        var g = Locate().Goal;
        if (!File.Exists(Path.Combine(g, "index.json"))) throw new FileNotFoundException("the goal vectors are missing (a vector directory is never skipped)", g);
        return g;
    }

    internal static string Path_(string name)
    {
        var p = Path.Combine(Dir(), name);
        if (!File.Exists(p)) throw new FileNotFoundException($"conformance/{name} is missing (a vector file is never skipped)", p);
        return p;
    }

    internal static Dictionary<string, object?> Load(string name) => (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path_(name)))!;

    internal static Dictionary<string, object?> D(object? o) => (Dictionary<string, object?>)o!;
    internal static List<object?> L(object? o) => (List<object?>)o!;
    internal static long N(object? o) => long.Parse(((Num)o!).Raw, CultureInfo.InvariantCulture);
}
