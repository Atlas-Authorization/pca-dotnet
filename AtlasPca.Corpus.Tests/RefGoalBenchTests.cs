using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the benchmark: seeded cases, simulated model fixtures, the four-level evaluation and the calibration report.</summary>
public class RefGoalBenchTests
{
    const string M = "ref-goal-bench";
    static D O(object? o) => (D)o!;
    static List<D> Cases(object? o) { var r = new List<D>(); foreach (var c in (L)o!) r.Add(O(c)); return r; }
    static long Lng(object? o) => (long)double.Parse(((Num)o!).Raw, NumberStyles.Float, CultureInfo.InvariantCulture);

    [Fact]
    public void RngSeq() => Base.Check(M, "rngSeq", a =>
    {
        var r = GoalBench.MakeRng(Lng(a[0]));
        var outp = new L();
        for (long i = 0, n = Lng(a[1]); i < n; i++) outp.Add(r.Next());
        return outp;
    });

    [Fact]
    public void GenerateCases() => Base.Check(M, "generateCases", a =>
        GoalBench.GenerateCases((string)a[0]!, (int)Lng(a[1]), Lng(a[2]), a[3] == null ? null : (int)Lng(a[3]), a[4] is true));

    [Fact] public void TruthGoalOf() => Base.Check(M, "truthGoalOf", a => GoalBench.TruthGoal(O(a[0])));

    [Fact]
    public void SimulateOutputOf() => Base.Check(M, "simulateOutputOf", a =>
    {
        object?[]? spec = null;
        foreach (var s in GoalBench.SIM_SPECS) if (Equals(s[0], a[1])) spec = s;
        return GoalBench.SimulateOutput(O(a[0]), (string)spec![0]!, (double)spec[1]!, (double)spec[2]!);
    });

    [Fact] public void RecordFixturesOf() => Base.Check(M, "recordFixturesOf", a => GoalBench.RecordFixtures(Cases(a[0])));
    [Fact] public void CaseSetDigest() => Base.Check(M, "caseSetDigest", a => GoalBench.CaseSetDigest(Cases(a[0])));

    [Fact]
    public void EvalCaseOf() => Base.Check(M, "evalCaseOf", a =>
    {
        var c = O(a[0]);
        return GoalBench.EvalCase(c, GoalBench.CompletionsFrom(GoalBench.RecordFixtures(new List<D> { c })), null, false, null);
    });

    [Fact]
    public void CompileWideningOf() => Base.Check(M, "compileWideningOf", a =>
    {
        var items = new List<D[]>();
        foreach (var c in Cases(a[0]))
        {
            var goal = GoalBench.TruthGoal(c);
            items.Add(new[] { goal, GoalBench.TruthOnt(c, goal) });
        }
        return GoalBench.CompileWideningCount(items, null);
    });

    [Fact] public void SummarizeOf() => Base.Check(M, "summarizeOf", a => GoalBench.Summarize((string)a[0]!, Cases(a[1]), (string)a[2]!, a[3] as D));

    [Fact]
    public void RunDomainOf() => Base.Check(M, "runDomainOf", a =>
    {
        var cs = Cases(a[1]);
        return GoalBench.RunDomain((string)a[0]!, cs, GoalBench.RecordFixtures(cs), null, false);
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "rngSeq", "generateCases", "truthGoalOf", "simulateOutputOf", "recordFixturesOf", "caseSetDigest", "evalCaseOf", "compileWideningOf", "summarizeOf", "runDomainOf" }); Assert.Equal(461, Base.Total(M)); }
}
