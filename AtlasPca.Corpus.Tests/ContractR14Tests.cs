using AtlasPca.Research;
using Xunit;
using SD = AtlasPca.Sdjwt.Sdjwt;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The immune decay is defined by exactly reproducible operations; a non-number kappa or theta is a violation; an unrepresentable time is refused.</summary>
public class ContractR14Tests
{
    const double Hour = 3_600_000;

    [Fact]
    public void DecayHalvesAndStepsWithoutPow()
    {
        Assert.Equal(0.5, Immune.Decay(1, Hour, Hour));
        Assert.Equal(0.25, Immune.Decay(1, 2 * Hour, Hour));
        Assert.Equal(0.9993233275026507, Immune.Decay(1, Hour / 1024, Hour));
        Assert.Equal(0.5 * 0.9993233275026507, Immune.Decay(1, Hour + Hour / 1024, Hour));
        Assert.Equal(1.0, Immune.Decay(1, Hour / 2048, Hour)); // less than one step: no decay
        Assert.Equal(0.0, Immune.Decay(1, 2000 * Hour, Hour)); // 0.5^1100 underflows
        Assert.Equal(5.0, Immune.Decay(5, 0, Hour));
        Assert.True(double.IsNaN(Immune.Decay(1, double.PositiveInfinity, double.PositiveInfinity)));
    }

    static D Policy(object? kappa, object? theta1, object? theta2) => new()
    {
        ["kappa"] = kappa, ["theta1"] = theta1, ["theta2"] = theta2, ["lambda"] = new Num("0"), ["rho"] = new Num("0"), ["bMax"] = new Num("1"),
        ["weights"] = new D(),
    };

    [Fact]
    public void ANonNumberKappaOrThetaIsAViolation()
    {
        var bs = Policy(new Num("1"), new Num("0.3"), new Num("0.6"));
        foreach (var bad in new object?[] { null, true, false, "3", new D() })
        {
            Assert.Equal("kappa and theta must be numbers", Immune.NoWidenViolation(bs, Policy(bad, new Num("0.3"), new Num("0.6"))));
            Assert.Equal("kappa and theta must be numbers", Immune.NoWidenViolation(bs, Policy(new Num("2"), bad, new Num("0.6"))));
            Assert.Equal("kappa and theta must be numbers", Immune.NoWidenViolation(bs, Policy(new Num("2"), new Num("0.3"), bad)));
        }
        Assert.Null(Immune.NoWidenViolation(bs, Policy(new Num("2"), new Num("0.3"), new Num("0.6"))));
    }

    [Fact]
    public void AnUnrepresentableNowIsRefusedBySdJwtVerification()
    {
        foreach (var now in new[] { "9e15", "-9e15", "8.64000000000001e15" })
        {
            var r = SD.VerifyPcaSdJwt("a.b.c~", new D { ["now"] = new Num(now), ["issuerKey"] = new D() });
            Assert.Equal(false, r["ok"]);
            Assert.Equal("now is not a representable time", r["reason"]);
        }
    }
}
