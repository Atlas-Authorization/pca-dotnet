using System.Numerics;
using AtlasPca.IntentPkg;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The deterministic math (integer fixed point, one final round-to-nearest-even conversion) and the exact entropy cutoff.</summary>
public class DetMathTests
{
    [Fact]
    public void ExactPowersOfTwoAndFixedPoints()
    {
        Assert.Equal(0.0, DetMath.DetLn(1));
        Assert.Equal(0.0, DetMath.DetLog2(1));
        Assert.Equal(1.0, DetMath.DetExp(0));
        foreach (var k in new[] { -1074, -1022, -52, -10, -1, 1, 3, 10, 52, 100, 1023 })
            Assert.Equal((double)k, DetMath.DetLog2(Math.ScaleB(1.0, k)));
        Assert.Equal(double.PositiveInfinity, DetMath.DetLn(double.PositiveInfinity));
        Assert.Equal(double.PositiveInfinity, DetMath.DetExp(710));
        Assert.Equal(0.0, DetMath.DetExp(-746));
        Assert.True(double.IsNaN(DetMath.DetLn(-1)));
        Assert.Equal(double.NegativeInfinity, DetMath.DetLn(0));
        Assert.Equal(double.NegativeInfinity, DetMath.DetLn(-0.0));
        Assert.Equal(double.NegativeInfinity, DetMath.DetLog2(0));
        Assert.Equal(double.NegativeInfinity, DetMath.DetLog2(-0.0));
        Assert.True(double.IsNaN(DetMath.DetLog2(-1)));
        Assert.Equal(0.0, DetMath.DetExp(double.NegativeInfinity));
        Assert.Equal(0.0, DetMath.DetExp(DetMath.DetLn(0))); // a prior-mix cell with q = 0 or 1 weighs 0, not NaN
        Assert.True(double.IsNaN(DetMath.DetLog2(double.NaN)));
        Assert.True(double.IsNaN(DetMath.DetExp(double.NaN)));
        Assert.Equal(1.0, DetMath.DetPowInt(7, 0));
        Assert.Equal(0.5 * 0.5 * 0.5, DetMath.DetPowInt(0.5, 3));
    }

    [Fact]
    public void TheValuesAreWithinOneUlpOfTheLibrary()
    {
        // the integer method is correctly rounded up to 2^-96; the library is within an ulp or two of the true value: a loose sanity bound, not the contract
        foreach (var x in new[] { 0.001, 0.1, 0.5, 2, 3, 10, 100, 12345.678, 1e-300, 1e300 })
        {
            Assert.InRange(Math.Abs(DetMath.DetLn(x) - Math.Log(x)), 0, 4 * Math.Abs(Math.Log(x)) * 2.3e-16 + 1e-300);
            Assert.InRange(Math.Abs(DetMath.DetLog2(x) - Math.Log2(x)), 0, 4 * Math.Abs(Math.Log2(x)) * 2.3e-16 + 1e-300);
        }
        foreach (var x in new[] { -700.0, -10, -1, -0.1, 0.1, 1, 5, 30, 700 })
            Assert.InRange(Math.Abs(DetMath.DetExp(x) / Math.Exp(x) - 1), 0, 8 * 2.3e-16);
    }

    [Fact]
    public void ToDoubleRoundsToNearestEven()
    {
        var two53 = BigInteger.One << 53;
        Assert.Equal(9007199254740992.0, DetMath.ToDouble(two53 + 1)); // a tie goes to the even neighbour
        Assert.Equal(9007199254740996.0, DetMath.ToDouble(two53 + 3)); // a tie goes to the even neighbour
        Assert.Equal(9007199254740994.0, DetMath.ToDouble(two53 + 2));
        Assert.Equal(-9007199254740994.0, DetMath.ToDouble(-(two53 + 2)));
        Assert.Equal(9007199254740994.0, DetMath.ToDouble((two53 << 40) + (BigInteger.One << 40) * 2 + 1) / Math.ScaleB(1.0, 40)); // below a tie: rounds down
        Assert.Equal(double.PositiveInfinity, DetMath.ToDouble(BigInteger.One << 1100));
    }

    [Fact]
    public void TheProportionCutoffIsExact()
    {
        Assert.Equal(1107.0, Entropy.ProportionCutoff(1, 2000)); // the float recurrence underflowed to W + 1 and disabled the test
        Assert.Equal(13.0, Entropy.ProportionCutoff(8, 512));
        Assert.Equal(410.0, Entropy.ProportionCutoff(0.5, 512));
    }

    [Fact]
    public void ADomainViolationIsRefusedNeverRounded()
    {
        foreach (var h in new[] { 0.0, 0.1, 0.124, 1.0 / 3, 64.125, 65, -1, double.NaN, double.PositiveInfinity })
            Assert.Throws<ArgumentOutOfRangeException>(() => Entropy.ProportionCutoff(h, 512));
        foreach (var w in new[] { 0.0, 1, 1.5, 65537, -2, double.NaN, double.PositiveInfinity })
            Assert.Throws<ArgumentOutOfRangeException>(() => Entropy.ProportionCutoff(8, w));
        Assert.Equal(false, Entropy.HealthTestBytes(new byte[64], new HealthTestOptions(H: 4.1)).Ok); // not a multiple of 1/8: the repetition verdict
        Assert.Equal("repetition-count", Entropy.HealthTestBytes(new byte[64], new HealthTestOptions(H: 4.1)).Test);
    }
}
