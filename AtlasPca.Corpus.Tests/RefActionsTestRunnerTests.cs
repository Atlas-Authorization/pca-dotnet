using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the example and property runner against the TypeScript reference.</summary>
public class RefActionsTestRunnerTests
{
    const string M = "ref-actions-test-runner";

    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);

    [Fact] public void DecideExample() => Base.Check(M, "decideExample", a => ActionTestRunner.DecideExample((D)a[0]!, (D)a[1]!, Actions.CoreRegistry, Defs(a[2])));
    [Fact] public void RunDefTests() => Base.Check(M, "runDefTests", a => ActionTestRunner.RunDefTests(Defs(a[0]), Actions.CoreRegistry, a.Count > 1 && a[1] != null ? Base.Long(a[1]) : null));
    [Fact] public void TestText() => Base.Check(M, "testText", a => ActionTestRunner.TestText((D)a[0]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "decideExample", "runDefTests", "testText" }); Assert.Equal(47, Base.Total(M)); }
}
