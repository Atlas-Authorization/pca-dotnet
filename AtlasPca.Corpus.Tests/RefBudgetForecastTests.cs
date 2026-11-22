using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the budget planning helpers: <c>forecast</c>, <c>recommendPolicy</c> and <c>autonomyBoundOf</c> of the budget-forecast corpus and <c>recommendPolicy</c> of the sweep corpus. A non-finite result is
/// {"$num": text}. The <c>forecast</c> cases replay a plan through the policy simulator (a catalog of defineAction entries replaces the built-in one).</summary>
public class RefBudgetForecastTests
{
    const string M = "ref-budget-forecast", Sweep = "ref-core-sweep-java";

    static object? Out(object? v) => v switch
    {
        double d when double.IsNaN(d) => new D { ["$num"] = "NaN" },
        double d when double.IsPositiveInfinity(d) => new D { ["$num"] = "Infinity" },
        double d when double.IsNegativeInfinity(d) => new D { ["$num"] = "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Out(e.Value)),
        _ => v,
    };

    static object? KappaOpts(object? k) => k == null ? null : new D { ["kappa"] = k };

    // the plan's catalog: null is the built-in one, else defineAction entries that form the whole catalog (a verb unknown to it fails closed)
    static Catalog? CatalogOf(object? actions) => actions == null ? null : new Catalog(((L)actions).Select(x => CatalogSpecs.FromJson(Catalog.DefineActionJson(x))));

    [Fact]
    public void Forecast() => Base.Check(M, "forecast", a => BudgetForecast.Forecast(RefResearchConsoleTests.Compile(a[0]), (L)a[1]!, CatalogOf(a[3]), a[2] == null ? 0.0 : AtlasPca.Analyzer.Jx.ToNumber(a[2])), min: 150);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "forecast", "recommendPolicy", "autonomyBoundOf" });
        Assert.Equal(326, Base.Total(M));
    }

    [Fact] public void RecommendPolicy() => Base.Check(M, "recommendPolicy", a => Out(BudgetForecast.RecommendPolicy(a[0], a[1], KappaOpts(a.Count > 2 ? a[2] : null))), min: 166);
    [Fact] public void AutonomyBoundOf() => Base.Check(M, "autonomyBoundOf", a => Out(BudgetForecast.AutonomyBoundOf(a[0])), min: 10);
    [Fact] public void RecommendPolicySweep() => Base.Check(Sweep, "recommendPolicy", a => Out(BudgetForecast.RecommendPolicy(a[0], a[1], KappaOpts(a.Count > 2 ? a[2] : null))), min: 110);
}
