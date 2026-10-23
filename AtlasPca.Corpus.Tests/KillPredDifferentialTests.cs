using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential kill tests of Predicates.cs against the TS reference (predicates.ts): path resolution over many contexts, every
/// leaf operator over fields x operands (value and ref forms), `like` globs, `matches`, `member_of` closures (incl. the 10,000-node bound
/// and own `__proto__` members), groupings, the per-document regex budget, predicates and predicate lists. Golden data:
/// test-data/killPred.json.gz, written by tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs (shared with the Kotlin suite).</summary>
public class KillPredDifferentialTests
{
    static readonly Lazy<D> Data = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "killPred.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "killPred.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            return (D)Pca.ParseBounded(sr.ReadToEnd(), int.MaxValue)!; // the oracle carries very deep vectors: no lenient depth cap (callers run on BigStack)
        }
        throw new FileNotFoundException("test-data/killPred.json.gz");
    });

    static L Sec(string k) => (L)Data.Value[k]!;
    static D? Ctx(object? i) => ((L)Data.Value["ctxs"]!)[int.Parse(((Num)i!).Raw)] as D;
    static Predicates.Tri Tri(object? s) => (string)s! switch { "T" => Predicates.Tri.True, "F" => Predicates.Tri.False, _ => Predicates.Tri.Unknown };
    static string Label(L e) { string c; try { c = Pca.Canonicalize(e[0]); if (c.Length > 160) c = c[..160]; } catch (Exception) { c = "<deep>"; } return c + " @ctx" + ((Num)e[1]!).Raw; }
    static void Check<T>(L e, T want, T got) { if (!EqualityComparer<T>.Default.Equals(want, got)) Assert.Fail($"{Label(e)}: want {want} got {got}"); }

    [Fact]
    public void ResolvePathMatchesTheReference() => BigStack.Run(() =>
    {
        foreach (L e in Sec("rp"))
        {
            var r = Predicates.ResolvePath(Ctx(e[1]), e[0]);
            Check(e, (bool)e[2]!, r.Found);
            if (r.Found) Check(e, true, IntentJs.JsonEquals(e[3], r.Value)); // lenient canonical-text equality (the oracle carries unsafe integers)
            else if (r.Value != null) Assert.Fail(Label(e) + ": a miss carries a value");
        }
    });

    [Fact]
    public void ConditionsMatchTheReference() => BigStack.Run(() =>
    {
        int n = 0;
        foreach (L e in Sec("cond"))
        {
            var got = Predicates.EvaluateConditionTri(e[0], Ctx(e[1]));
            Check(e, Tri(e[2]), got);
            Check(e, Tri(e[2]) == Predicates.Tri.True, Predicates.EvaluateCondition(e[0], Ctx(e[1])));
            n++;
        }
        Assert.True(n > 100000);
    });

    [Fact]
    public void PredicatesMatchTheReference() => BigStack.Run(() =>
    {
        foreach (L e in Sec("pred")) Check(e, (bool)e[2]!, Predicates.PredicateMatches(e[0], Ctx(e[1])));
    });

    [Fact]
    public void PredicateListsMatchTheReference() => BigStack.Run(() =>
    {
        foreach (L e in Sec("preds")) Check(e, (bool)e[2]!, Predicates.EvaluatePredicates(e[0], Ctx(e[1])));
    });

    [Fact]
    public void GlobMatchTokens()
    {
        Assert.True(Predicates.GlobMatch("a*c", "abc"));
        Assert.True(Predicates.GlobMatch("a**c", "ac"));
        Assert.False(Predicates.GlobMatch("a*c", "ab"));
        Assert.True(Predicates.GlobMatch("a?c", "abc"));
        Assert.False(Predicates.GlobMatch("a?c", "ac"));
        Assert.True(Predicates.GlobMatch("a\\*c", "a*c"));
        Assert.False(Predicates.GlobMatch("a\\*c", "abc"));
        Assert.True(Predicates.GlobMatch("a\\\\c", "a\\c"));
        Assert.Null(Predicates.GlobMatch("abc\\", "abc"));
        Assert.Null(Predicates.GlobMatch("\\", ""));
        Assert.True(Predicates.GlobMatch("", ""));
        Assert.False(Predicates.GlobMatch("", "a"));
        Assert.True(Predicates.GlobMatch("*", ""));
        Assert.False(Predicates.GlobMatch("?", ""));
        Assert.True(Predicates.GlobMatch("*a*b*c*", "xxaxxbxxcxx"));
        Assert.False(Predicates.GlobMatch("*a*b*c*", "xxaxxcxxbxx"));
        Assert.False(Predicates.GlobMatch("a*a*a*b", new string('a', 400)));
        Assert.True(Predicates.GlobMatch("a*a*a*b", new string('a', 400) + "b"));
    }

    [Fact]
    public void Constants()
    {
        Assert.Equal(512, Predicates.MaxPatternSubjectLen);
        Assert.Equal(512, Predicates.MaxLikePatternLen);
        Assert.Equal(200, Predicates.MaxMatchesPatternLen);
        Assert.Equal(10_000, Predicates.MaxMemberClosureNodes);
        Assert.Equal(512, Predicates.MaxReResourceLen);
        Assert.False(Predicates.EvaluateCondition(null, null));
    }
}
