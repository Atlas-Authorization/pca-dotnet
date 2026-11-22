using AtlasPca.PolicyCi;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the policy-safety CI gate (normalization, lint rules, summary, pinned rule digest, authoring commands and the
/// command line) against the TypeScript reference, plus the schema, test and coverage runs that drive the analyzer.</summary>
public class RefPolicyCiTests
{
    const string M = "ref-policy-ci";
    const string X = "ref-policy-ci-java-extra";

    static object? Opt(L a, int i) => a.Count > i ? a[i] : null;
    static IReadOnlyList<object?> Chain(object? x) => (L)x!;
    static List<string> Strings(object? x) => ((L)x!).Select(s => (string)s!).ToList();

    [Fact] public void NormalizePolicyInput() => Base.Check(M, "normalizePolicyInput", a => CiNormalize.NormalizePolicyInput(a[0]));
    [Fact] public void NormalizeChain() => Base.Check(M, "normalizeChain", a => CiNormalize.NormalizeChain(Chain(a[0])));
    [Fact] public void IsCapability() => Base.Check(M, "isCapability", a => CiNormalize.IsCapability(a[0]));
    [Fact] public void IsEnvelope() => Base.Check(M, "isEnvelope", a => CiNormalize.IsEnvelope(a[0]));
    [Fact] public void LintPolicy() => Base.Check(M, "lintPolicy", a => PcaPolicyCi.LintPolicy(a[0], Opt(a, 1)));
    [Fact] public void LintChain() => Base.Check(M, "lintChain", a => PcaPolicyCi.LintChain(Chain(a[0]), Opt(a, 1)));
    [Fact] public void Lint() => Base.Check(M, "lint", a => PcaPolicyCi.Lint(a[0], Opt(a, 1)));
    [Fact] public void LintPolicies() => Base.Check(M, "lintPolicies", a => PcaPolicyCi.LintPolicies(Chain(a[0]), Opt(a, 1)));
    [Fact] public void Summarize() => Base.Check(M, "summarize", a => PcaPolicyCi.Summarize(a[0], Opt(a, 1)));
    [Fact] public void CheckLintRulesPin() => Base.Check(M, "checkLintRulesPin", a => PcaPolicyCi.CheckLintRulesPin((string)a[0]!, a.Count > 1 ? (string)a[1]! : null));
    [Fact] public void ToAnalyzerPolicy() => Base.Check(M, "toAnalyzerPolicy", a => CiAuthoring.ToAnalyzerPolicy(a[0]));
    [Fact] public void DiffCommand() => Base.Check(M, "diffCommand", a => CiAuthoring.DiffCommand(a[0], a[1], Opt(a, 2)));
    // only the input refusals are in this corpus: they never reach the analyzer's test runner or coverage engine
    [Fact] public void TestCommand() => Base.Check(M, "testCommand", a => CiAuthoring.TestCommand(a[0], a[1], Opt(a, 2)));
    [Fact] public void CoverageCommand() => Base.Check(M, "coverageCommand", a => CiAuthoring.CoverageCommand(a[0], a[1], Opt(a, 2)));
    [Fact] public void ParseArgs() => Base.Check(M, "parseArgs", a => CiCli.ParseArgs(Strings(a[0])));

    [Fact]
    public void Run() => Base.Check(M, "run", a =>
    {
        var input = (D)a[0]!;
        var files = (D)input["files"]!;
        var dir = Directory.CreateTempSubdirectory("pcaci");
        var prefix = dir.FullName + Path.DirectorySeparatorChar;
        // a workflow annotation escapes the path it names (a drive letter's colon becomes %3A): the reference prints the relative name either way
        var escaped = prefix.Replace("%", "%25").Replace(":", "%3A").Replace(",", "%2C");
        try
        {
            foreach (var (name, text) in files) File.WriteAllText(Path.Combine(dir.FullName, name), (string)text!, new System.Text.UTF8Encoding(false));
            var argv = Strings(input["argv"]).Select(t => files.ContainsKey(t) ? prefix + t : t).ToList();
            var lines = new L();
            var code = CiCli.Run(argv, s => lines.Add(s.Replace(prefix, "").Replace(escaped, "")));
            return new D { ["code"] = code, ["lines"] = lines };
        }
        finally { dir.Delete(true); }
    });

    // the schema, test and coverage runs over the analyzer
    [Fact] public void ExtraLintPolicy() => Base.Check(X, "lintPolicy", a => PcaPolicyCi.LintPolicy(a[0], Opt(a, 1)));
    [Fact] public void ExtraTestCommand() => Base.Check(X, "testCommand", a => CiAuthoring.TestCommand(a[0], a[1], Opt(a, 2)));
    [Fact] public void ExtraCoverageCommand() => Base.Check(X, "coverageCommand", a => CiAuthoring.CoverageCommand(a[0], a[1], Opt(a, 2)));

    [Fact]
    public void DigestOfTheRuleList()
    {
        Assert.Equal(24, ActionLintRules.LintRules.Count);
        Assert.Equal(43, ActionLintRules.LintRulesDigest().Length);
        Assert.True((bool)PcaPolicyCi.CheckLintRulesPin(" " + ActionLintRules.LintRulesDigest() + "\n")["ok"]!);
    }

    [Fact]
    public void CoversEveryFn()
    {
        Base.Covers(M, new[]
        {
            "normalizePolicyInput", "normalizeChain", "isCapability", "isEnvelope", "lintPolicy", "lintChain", "lint", "lintPolicies", "summarize",
            "checkLintRulesPin", "toAnalyzerPolicy", "diffCommand", "testCommand", "coverageCommand", "parseArgs", "run",
        }); Assert.Equal(2060, Base.Total(M));
        Base.Covers(X, new[] { "lintPolicy", "testCommand", "coverageCommand" }); Assert.Equal(162, Base.Total(X));
    }
}
