using System.IO.Compression;
using System.Reflection;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential kill tests of SafeRegex.cs against the TS reference (safe-regex.ts, predicates.ts isSafeRegexSource,
/// regex-budget.ts). test-data/killRegex.json.gz is the shared, language-neutral oracle (tools/pca-audit/kotlin-mutate/
/// killRegex-oracle-gen.mjs): full-match results (true / false / refused) of a pattern corpus crossed with boundary subjects,
/// compiled sizes, the step boundary, the safe-source guard and per-document budget sequences. Engine-only probes nested
/// deeper than any protocol entry point admits (each caps a regex at 200 units, so at most 100 groups) are skipped: they
/// refuse on stack exhaustion at a language-specific depth, which is not a protocol behaviour.</summary>
public class RegexDifferentialKillTests
{
    const int Reachable = 100;

    static readonly Lazy<D> Data = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "killRegex.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "test-data", "killRegex.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            return (D)Pca.ParseJson(sr.ReadToEnd())!;
        }
        throw new FileNotFoundException("test-data/killRegex.json.gz");
    });

    static L Sec(string k) => (L)Data.Value[k]!;
    static long N(object? o) => o is Num n ? long.Parse(n.Raw) : Convert.ToInt64(o);
    static bool? Want(long r) => r < 0 ? null : r == 1;

    static int Depth(string p)
    {
        int d = 0, m = 0;
        foreach (var ch in p) { if (ch == '(') d++; else if (ch == ')') d--; if (d > m) m = d; }
        return m;
    }

    [Fact]
    public void FullMatchAgreesWithTheReference() => BigStack.Run(() =>
    {
        int n = 0;
        foreach (L e in Sec("fm"))
        {
            var p = (string)e[0]!;
            var subs = (L)e[1]!;
            var rs = (string)e[2]!;
            Assert.Equal(subs.Count, rs.Length);
            if (Depth(p) > Reachable) continue;
            for (int k = 0; k < subs.Count; k++)
            {
                bool? want = rs[k] == 'n' ? null : rs[k] == '1';
                var got = SafeRegex.FullMatch(p, (string)subs[k]!);
                if (got != want) Assert.Fail($"/{p}/ on {subs[k]}: want {want}, got {got}");
                n++;
            }
        }
        Assert.True(n > 100_000);
    });

    [Fact]
    public void CompiledSizesAgree() => BigStack.Run(() =>
    {
        foreach (L e in Sec("size"))
        {
            var p = (string)e[0]!;
            if (Depth(p) > Reachable) continue;
            long want = N(e[1]);
            var c = SafeRegex.Compile(p);
            if (want < 0) Assert.True(c == null, $"/{p}/");
            else { Assert.True(c != null, $"/{p}/"); Assert.Equal(want, c!.Size); }
        }
    });

    [Fact]
    public void StepBoundaryAgrees() => BigStack.Run(() =>
    {
        Assert.Equal(4096, SafeRegex.MaxNfaInstructions);
        Assert.Equal(64, SafeRegex.MaxRepeat);
        Assert.Equal(2_000_000L, SafeRegex.MaxMatchSteps);
        foreach (L e in Sec("steps"))
        {
            var p = (string)e[0]!;
            if (Depth(p) > Reachable) continue;
            int n = (int)N(e[1]);
            Assert.True(Want(N(e[2])) == SafeRegex.FullMatch(p, new string('a', n)), $"/{p[..Math.Min(20, p.Length)]}/ n={n}");
        }
    });

    [Fact]
    public void SafeSourceGuardAgrees() => BigStack.Run(() =>
    {
        var safe = Sec("safe");
        Assert.True(safe.Count > 500);
        foreach (L e in safe)
        {
            var p = (string)e[0]!;
            if (Depth(p) > Reachable) continue;
            var want = (bool)e[1]!;
            if (SafeRegex.IsSafeSource(p) != want) Assert.Fail($"/{p}/: want {want}");
        }
    });

    /// <summary>The budget is private to SafeRegex (one per document, opened by WithBudget); reached by reflection. The .NET
    /// budget keeps no refusal counter (the TS one counts refusals for diagnostics only), so that column is not compared.</summary>
    [Fact]
    public void BudgetSequencesAgree()
    {
        var t = typeof(SafeRegex).GetNestedType("Budget", BindingFlags.NonPublic)!;
        var charge = t.GetMethod("Charge", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var fEv = t.GetField("evaluations", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var fCh = t.GetField("chars", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var fSt = t.GetField("steps", BindingFlags.NonPublic | BindingFlags.Instance)!;
        int k = 0;
        foreach (D b in Sec("budgets"))
        {
            var budget = Activator.CreateInstance(t, nonPublic: true)!;
            var ops = (L)b["ops"]!;
            var res = (L)b["res"]!;
            for (int i = 0; i < ops.Count; i++)
            {
                var op = (L)ops[i]!;
                var got = (bool)charge.Invoke(budget, new object?[] { (string)op[0]!, (int)N(op[1]) })!;
                Assert.True((bool)res[i]! == got, $"budget #{k} op {i}");
            }
            var fin = (L)b["fin"]!;
            Assert.Equal(N(fin[0]), (long)(int)fEv.GetValue(budget)!);
            Assert.Equal(N(fin[1]), (long)(int)fCh.GetValue(budget)!);
            Assert.Equal(N(fin[2]), (long)fSt.GetValue(budget)!);
            k++;
        }
    }
}
