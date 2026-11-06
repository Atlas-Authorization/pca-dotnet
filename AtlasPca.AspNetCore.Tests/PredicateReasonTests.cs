using System.Collections.Generic;
using System.IO;
using System.Linq;
using AtlasPca;
using Xunit;

namespace AtlasPca.AspNetCore.Tests;

// The limit-naming denial reasons (0.5): every case's expected reason was produced by the TypeScript evaluatePredicates
// (test-data/predicate-reasons.json), so the text must match byte for byte.
public class PredicateReasonTests
{
    static readonly List<Dictionary<string, object?>> Cases = ((List<object?>)((Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(
        System.AppContext.BaseDirectory, "test-data", "predicate-reasons.json")))!)["cases"]!).Cast<Dictionary<string, object?>>().ToList();

    static string Reason(Dictionary<string, object?> c)
    {
        var ctx = (Dictionary<string, object?>)c["ctx"]!;
        var why = Pca.EnvelopePredicates(c["predicates"], ctx);
        Assert.NotNull(why);
        return why!;
    }

    [Fact] public void ReasonsMatchTypeScript()
    {
        Assert.Equal(70, Cases.Count);
        var bad = Cases.Where(c => Reason(c) != (string)c["reason"]!).Select(c => $"{c["name"]}: {Reason(c)} != {c["reason"]}").ToList();
        Assert.Empty(bad);
    }
}
