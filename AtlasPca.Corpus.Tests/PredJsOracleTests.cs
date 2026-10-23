using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential kill tests of Predicates.cs / IntentJs.cs against the TS reference (predicates.ts, hash.ts and JavaScript
/// number semantics). test-data/k042-predjs.json is written by tools/pca-audit/java-mutate/k042-predjs-oracle.mjs; every input is
/// carried as JSON text so both sides parse identical lexemes (1e400, -0, lone surrogates).</summary>
public class PredJsOracleTests
{
    static readonly Lazy<D> G = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-predjs.json");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-predjs.json");
            if (File.Exists(f)) return (D)Pca.ParseJson(File.ReadAllText(f))!;
        }
        throw new FileNotFoundException("test-data/k042-predjs.json");
    });

    static L Cases(string k) => (L)G.Value[k]!;
    static Predicates.Tri Tri(string s) => s switch { "true" => Predicates.Tri.True, "false" => Predicates.Tri.False, _ => Predicates.Tri.Unknown };
    static D? Ctx(string name) => Pca.ParseJson((string)((D)G.Value["ctx"]!)[name]!) as D;
    static bool B(object? o) => (bool)o!;

    [Fact]
    public void ConditionsMatchTheReference()
    {
        var bad = new List<string>(); int n = 0;
        foreach (D c in Cases("tri"))
        {
            var cond = Pca.ParseJson((string)c["cond"]!);
            var want = Tri((string)c["tri"]!);
            var got = Predicates.EvaluateConditionTri(cond, Ctx((string)c["ctx"]!));
            var gotB = Predicates.EvaluateCondition(cond, Ctx((string)c["ctx"]!));
            if (got != want || gotB != (want == Predicates.Tri.True)) bad.Add($"{c["name"]}: want {want} got {got}/{gotB}");
            n++;
        }
        Assert.True(n > 400, "golden too small: " + n);
        Assert.Empty(bad);
    }

    [Fact]
    public void PredicatesMatchTheReference()
    {
        var bad = new List<string>();
        foreach (D c in Cases("preds"))
        {
            var preds = Pca.ParseJson((string)c["preds"]!);
            var want = B(c["allowed"]);
            var got = Predicates.EvaluatePredicates(preds, Ctx((string)c["ctx"]!));
            if (got != want) bad.Add($"{c["name"]}: allowed want {want} got {got}");
            var each = (L)c["each"]!;
            if (preds is L ps)
            {
                Assert.Equal(each.Count, ps.Count);
                for (int i = 0; i < ps.Count; i++)
                {
                    var m = Predicates.PredicateMatches(ps[i], Ctx((string)c["ctx"]!));
                    if (m != B(each[i])) bad.Add($"{c["name"]}[{i}]: want {each[i]} got {m}");
                }
            }
        }
        Assert.Empty(bad);
    }

    [Fact]
    public void JsonEqualsIsTheLenientCanonicalTextEquality()
    {
        var bad = new List<string>();
        foreach (D c in Cases("eq"))
            if (IntentJs.JsonEquals(Pca.ParseJson((string)c["a"]!), Pca.ParseJson((string)c["b"]!)) != B(c["eq"])) bad.Add($"{c["a"]} == {c["b"]}: want {c["eq"]}");
        Assert.Empty(bad);
    }

    /// <summary>The binary64 value, Number.isSafeInteger / isFinite and the normalized spelling (JavaScript's String(n) inside the
    /// strict profile; outside it, integral values below 1e21 print as exact binary64 digits, anything else as JavaScript's shortest
    /// digits in plain decimal).</summary>
    [Fact]
    public void NumbersMatchJavaScript()
    {
        var bad = new List<string>();
        foreach (D c in Cases("nums"))
        {
            string raw = (string)c["raw"]!, js = (string)c["js"]!;
            var n = new Num(raw);
            double d = double.Parse(raw, System.Globalization.CultureInfo.InvariantCulture);
            if (IntentJs.IsSafeInteger(n) != B(c["safe"])) bad.Add(raw + ": isSafeInteger");
            if (IntentJs.IsFinite(n) != B(c["finite"])) bad.Add(raw + ": isFinite");
            if (!IntentJs.NumOf(n)!.Value.Equals(d)) bad.Add(raw + ": num");
            string want;
            if (!B(c["finite"])) want = raw;
            else if (js == "-0") want = "-0";
            else if (d == Math.Round(d) && Math.Abs(d) < 1e21) want = new System.Numerics.BigInteger(d).ToString();
            else want = PlainOf(js);
            if (B(c["plain"]) && B(c["finite"]) && B(c["safe"]) && want != js) bad.Add(raw + ": safe spelling differs from JS");
            if (B(c["plain"]) && B(c["finite"]) && d != Math.Round(d) && want != js) bad.Add(raw + ": decimal spelling differs from JS");
            var got = IntentJs.NormNum(raw).Raw;
            if (got != want) bad.Add($"{raw}: normNum {got} want {want}");
            if (IntentJs.Normalize(n) is not Num nn || nn.Raw != want) bad.Add(raw + ": normalize");
            if (B(c["finite"]) && (IntentJs.Normalize(d) is not Num nd || nd.Raw != want)) bad.Add(raw + ": normalize(double)");
        }
        Assert.Empty(bad);
    }

    /// <summary>A JavaScript number text (maybe with an exponent) in plain decimal.</summary>
    static string PlainOf(string js)
    {
        int e = js.IndexOfAny(new[] { 'e', 'E' });
        if (e < 0) return js;
        bool neg = js.StartsWith('-');
        var mant = js[(neg ? 1 : 0)..e]; int exp = int.Parse(js[(e + 1)..], System.Globalization.CultureInfo.InvariantCulture);
        int dot = mant.IndexOf('.');
        var digits = dot < 0 ? mant : mant.Remove(dot, 1); int intLen = (dot < 0 ? mant.Length : dot) + exp;
        var plain = intLen <= 0 ? "0." + new string('0', -intLen) + digits : intLen >= digits.Length ? digits + new string('0', intLen - digits.Length) : digits[..intLen] + "." + digits[intLen..];
        return (neg ? "-" : "") + plain;
    }

    [Fact]
    public void Utf8LengthsAndSurrogates()
    {
        foreach (D c in Cases("u8"))
        {
            var s = (string)c["s"]!;
            Assert.Equal(((Num)c["n"]!).Raw, IntentJs.U8Len(s).ToString());
            Assert.Equal(B(c["lone"]), IntentJs.HasLoneSurrogate(s));
        }
        foreach (D c in Cases("cmp"))
            Assert.Equal(int.Parse(((Num)c["sign"]!).Raw), Math.Sign(IntentJs.CompareUtf8((string)c["a"]!, (string)c["b"]!)));
    }

    static D Mo(string v) => new() { ["field"] = "subject.id", ["op"] = "member_of", ["collection"] = "subject.g", ["value"] = v };
    static D Base(string id, D g) => new() { ["action"] = new D { ["verb"] = "v", ["resource"] = "r" }, ["subject"] = new D { ["id"] = id, ["g"] = g } };
    static D ChainCtx(int n) { var g = new D(); for (int i = 0; i < n; i++) g["n" + i] = "n" + (i + 1); return Base("n0", g); }
    static D FanCtx()
    {
        var g = new D(); var s = new L(); var cs = new L();
        for (int j = 0; j < 100; j++) cs.Add("c" + j);
        g["s"] = s;
        for (int i = 0; i < 100; i++) { s.Add("a" + i); g["a" + i] = cs; }
        g["c0"] = "e"; g["e"] = "t";
        return Base("s", g);
    }

    [Fact]
    public void MemberClosureIsCappedLikeTheReference() => BigStack.Run(() =>
    {
        var chain = (D)G.Value["chain"]!; var fan = (D)G.Value["fan"]!;
        var cc = ChainCtx(10005);
        foreach (var (k, v) in chain) Assert.Equal(Tri((string)v!), Predicates.EvaluateConditionTri(Mo(k), cc));
        var fc = FanCtx();
        foreach (var (k, v) in fan) Assert.Equal(Tri((string)v!), Predicates.EvaluateConditionTri(Mo(k), fc));
        Assert.Equal(Predicates.Tri.True, Tri((string)chain["n10000"]!));
        Assert.Equal(Predicates.Tri.False, Tri((string)chain["n10001"]!));
    });
}
