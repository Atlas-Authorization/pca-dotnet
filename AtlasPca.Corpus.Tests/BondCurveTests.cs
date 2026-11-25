using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The bond power curve is computed from exactly rounded operations only (multiplication and square roots), so every platform gets the same bits; a gamma that is not a multiple of 1/8 is refused.</summary>
public class BondCurveTests
{
    [Fact]
    public void PowersAreBuiltFromMultiplicationsAndSquareRoots()
    {
        const double e = 12345.678;
        Assert.Equal(e, BondSettlement.PowEighths(e, 1));
        Assert.Equal(e * e, BondSettlement.PowEighths(e, 2));
        Assert.Equal(e * Math.Sqrt(e), BondSettlement.PowEighths(e, 1.5));
        Assert.Equal(e * e * Math.Sqrt(Math.Sqrt(e)), BondSettlement.PowEighths(e, 2.25));
        Assert.Equal(e * Math.Sqrt(Math.Sqrt(Math.Sqrt(e))), BondSettlement.PowEighths(e, 1.125));
        Assert.Equal(e * Math.Sqrt(e) * Math.Sqrt(Math.Sqrt(e)) * Math.Sqrt(Math.Sqrt(Math.Sqrt(e))), BondSettlement.PowEighths(e, 1.875));
        Assert.Equal(1.0, BondSettlement.PowEighths(1, 64));
    }

    [Fact]
    public void AGammaThatIsNotAnExactMultipleOfAnEighthOrAbove64IsRefused()
    {
        foreach (var gamma in new[] { 1.3, 1.1, 2.0001, 64.125, 65, 1000, double.NaN, double.PositiveInfinity })
        {
            var ex = Assert.Throws<InvalidOperationException>(() => BondSettlement.PowEighths(10, gamma));
            Assert.Equal("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64", ex.Message);
        }
    }
}
