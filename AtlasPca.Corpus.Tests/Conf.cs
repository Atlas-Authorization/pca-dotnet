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

    /// <summary>The action-kit vectors: flagship packages/pca-conformance/vectors/actions, or the mirror conformance/actions. Never skipped.</summary>
    internal static string ActionsDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
            foreach (var rel in new[] { Path.Combine("packages", "pca-conformance", "vectors", "actions"), Path.Combine("conformance", "actions") })
            {
                var c = Path.Combine(d, rel);
                if (Directory.Exists(c) && Directory.EnumerateFiles(c, "*.json").Any()) return c;
            }
        throw new FileNotFoundException("the action-kit vectors are missing (a vector directory is never skipped)", AppContext.BaseDirectory);
    }

    /// <summary>The approval profile vectors (PSD2 linking, batch; K7): flagship packages/pca-conformance/vectors/approval-profiles, or the mirror conformance/approval-profiles. Never skipped.</summary>
    internal static string ApprovalProfilesDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
            foreach (var rel in new[] { Path.Combine("packages", "pca-conformance", "vectors", "approval-profiles"), Path.Combine("conformance", "approval-profiles") })
            {
                var c = Path.Combine(d, rel);
                if (Directory.Exists(c) && Directory.EnumerateFiles(c, "*.json").Any()) return c;
            }
        throw new FileNotFoundException("the approval profile vectors are missing (a vector directory is never skipped)", AppContext.BaseDirectory);
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
