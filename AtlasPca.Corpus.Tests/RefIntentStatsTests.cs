using System.Numerics;
using AtlasPca;
using AtlasPca.InteropJs;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the intent numerics (Clopper-Pearson, binomial CDF, Hoeffding, Wilson) against the TypeScript reference
/// (test-data/ref-intent-stats.json.gz). A bigint travels as {"$bigint": decimal}; a non-finite double as {"$num": text}.</summary>
public class RefIntentStatsTests
{
    const string M = "ref-intent-stats";

    static double Dd(object? o) => IntentOmega.Dbl(o);
    static BigInteger Big(object? o) => BigInteger.Parse((string)((D)o!)["$bigint"]!, System.Globalization.CultureInfo.InvariantCulture);
    static D B(BigInteger x) => new() { ["$bigint"] = x.ToString(System.Globalization.CultureInfo.InvariantCulture) };
    static object? Fl(double d) => double.IsFinite(d) ? JsX.Number(d) : new D { ["$num"] = JsX.JsNumString(d) };
    static IntentStats.Dyadic Dy(object? o) => new(Big(((D)o!)["num"]), (int)Dd(((D)o)["exp"]));

    [Fact] public void ClopperPearsonUpperFn() => Base.Check(M, "clopperPearsonUpper", a => Fl(IntentStats.ClopperPearsonUpper(Dd(a[0]), Dd(a[1]), Dd(a[2]))));

    [Fact]
    public void ClopperPearsonCertifiedFn() => Base.Check(M, "clopperPearsonCertified", a =>
    {
        var c = IntentStats.ClopperPearsonCertified(Dd(a[0]), Dd(a[1]), Dd(a[2]));
        return new D { ["upper"] = Fl(c.Upper), ["upperUnits"] = B(c.UpperUnits), ["lowerUnits"] = B(c.LowerUnits) };
    });

    [Fact] public void BinomialCdfFn() => Base.Check(M, "binomialCdf", a => Fl(IntentStats.BinomialCdf(Dd(a[0]), Dd(a[1]), Dd(a[2]))));

    [Fact]
    public void DoubleToDyadicFn() => Base.Check(M, "doubleToDyadic", a =>
    {
        var d = IntentStats.DoubleToDyadic(Dd(a[0]));
        return new D { ["num"] = B(d.Num), ["exp"] = JsX.Number(d.Exp) };
    });

    [Fact] public void CdfRecNumeratorFn() => Base.Check(M, "cdfRecNumerator", a => B(IntentStats.CdfRecNumerator((int)Dd(a[0]), (int)Dd(a[1]), Big(a[2]))));
    [Fact] public void CdfExceedsFn() => Base.Check(M, "cdfExceeds", a => IntentStats.CdfExceeds((int)Dd(a[0]), (int)Dd(a[1]), Big(a[2]), Dy(a[3])));

    [Fact]
    public void HoeffdingHalfWidthFn() => Base.Check(M, "hoeffdingHalfWidth", a =>
        Fl(a.Count > 2 ? IntentStats.HoeffdingHalfWidth(Dd(a[0]), Dd(a[1]), Dd(a[2])) : IntentStats.HoeffdingHalfWidth(Dd(a[0]), Dd(a[1]))));

    [Fact]
    public void WilsonIntervalFn() => Base.Check(M, "wilsonInterval", a =>
    {
        var w = a.Count > 2 ? IntentStats.WilsonInterval(Dd(a[0]), Dd(a[1]), Dd(a[2])) : IntentStats.WilsonInterval(Dd(a[0]), Dd(a[1]));
        return new D { ["p"] = Fl(w.P), ["lo"] = Fl(w.Lo), ["hi"] = Fl(w.Hi) };
    });

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "clopperPearsonUpper", "clopperPearsonCertified", "binomialCdf", "doubleToDyadic", "cdfRecNumerator", "cdfExceeds", "hoeffdingHalfWidth", "wilsonInterval",
    }); Assert.Equal(995, Base.Total(M)); }
}
