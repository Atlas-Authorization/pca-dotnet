using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of intent statements (sign, verify, content address, goal strings) against the TypeScript reference
/// (test-data/ref-intent-statement.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentStatementTests
{
    const string M = "ref-intent-statement";

    [Fact] public void SignIntentFn() => Base.Check(M, "signIntent", a => IntentStatement.SignIntent((D)a[0]!, Pca.B64uDecode(a[1])!));

    [Fact]
    public void VerifyIntentFn() => Base.Check(M, "verifyIntent", a =>
    {
        var opts = (D)a[1]!;
        return IntentStatement.VerifyIntent(a[0], opts.GetValueOrDefault("expectedSigner") as string, opts.GetValueOrDefault("pqPins") as D);
    });

    [Fact] public void IntentRefFn() => Base.Check(M, "intentRef", a => IntentStatement.IntentRef(a[0]));
    [Fact] public void IntentGoalFn() => Base.Check(M, "intentGoal", a => IntentStatement.IntentGoal((string)a[0]!, a.Count > 1 ? a[1] as string : null));
    [Fact] public void ParseIntentGoalFn() => Base.Check(M, "parseIntentGoal", a => IntentStatement.ParseIntentGoal(a[0]));

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "signIntent", "verifyIntent", "intentRef", "intentGoal", "parseIntentGoal" }); Assert.Equal(215, Base.Total(M)); }
}
