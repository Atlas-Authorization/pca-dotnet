using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace AtlasPca;

/// <summary>The library's regular expressions, built once per distinct (pattern, options) and handed out per access. The tables of the library are
/// per-access members rather than static fields: a static field keeps whatever its initializer produced when its type was first touched, and the
/// mutation tester Stryker.NET reuses one test host for many mutants (the active mutant is switched per test case), so a field built while a
/// mutant of its literal was active would keep that mutant for every later one. Keyed by the exact pattern text, a mutated pattern gets an entry
/// of its own and cannot replace the correct one.</summary>
static class Rx
{
    static readonly ConcurrentDictionary<(string Pattern, RegexOptions Options), Regex> Cache = new();

    internal static Regex Get(string pattern, RegexOptions options = RegexOptions.None) => Cache.GetOrAdd((pattern, options), static k => new Regex(k.Pattern, k.Options));
}
