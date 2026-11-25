using System.Reflection;
using AtlasPca;
using AtlasPca.TxnTokens;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Kill tests for the fixes of the sixteenth round that no corpus case pins on its own.</summary>
public class Round16KillTests
{
    [Theory]
    [InlineData(31.25, "31.3")] // an exact tie goes up, as Number.prototype.toFixed does (.NET formats it to even)
    [InlineData(0.25, "0.3")]
    [InlineData(100.0, "100.0")]
    [InlineData(31.249999999999996, "31.2")]
    public void ThePercentageOfAnEvaluationRoundsLikeToFixed(double value, string want)
    {
        var m = typeof(AtlasPca.ActionsKit.ImportEval).GetMethod("ToFixed1", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.Equal(want, (string)m.Invoke(null, new object[] { value })!);
    }

    [Theory]
    [InlineData(-1.0)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void ATransactionTokenToleranceThatIsNegativeOrNotFiniteIsRefusedUpFront(double tolerance)
    {
        var e = Assert.Throws<ArgumentException>(() => AtlasPca.TxnTokens.TxnTokens.FromTransactionToken("x.y.z", new byte[32],
            new FromTransactionTokenOptions { Audience = "td", ReplayCheck = "unchecked", ClockToleranceSec = tolerance }));
        Assert.Equal("fromTransactionToken: clockToleranceSec must be a finite number >= 0", e.Message);
    }

    [Fact]
    public void AJwkMemberWithALoneSurrogateReadsLikeTheEngineSkippingIt()
    {
        var x = Pca.B64u(new byte[32]);
        var plain = AtlasPca.Jose.Jose.ImportJwk(new Dictionary<string, object?> { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = x });
        var withSurrogate = AtlasPca.Jose.Jose.ImportJwk(new Dictionary<string, object?> { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = x + "\udc00" });
        Assert.NotNull(plain);
        Assert.NotNull(withSurrogate);
    }
}
