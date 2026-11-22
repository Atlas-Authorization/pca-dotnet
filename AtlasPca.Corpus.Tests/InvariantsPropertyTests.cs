using AtlasPca.Invariants;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The invariant property harness: the seeded stream, the generators, every property over the real native core, the runner's refusals. The
/// reference drives its properties through a property-testing library whose byte stream cannot be reproduced, so there is no per-case corpus: the
/// deterministic exports are replayed in <see cref="RefInvariantsTests"/>, and these check the properties and that they can fail.</summary>
public class InvariantsPropertyTests
{
    [Fact]
    public void TheMulberry32StreamIsFixed()
    {
        var g = new InvariantsRng(42);
        Assert.Equal(0.60110375192016363, g.Next(), 15);
        Assert.Equal(0.44829055899754167, g.Next(), 15);
        Assert.Equal(0.85246579349040985, g.Next(), 15);
    }

    [Fact]
    public void StreamsAreSeedAndIndexDependent()
    {
        Assert.NotEqual(InvariantsRng.ForProperty(1, 0).Next(), InvariantsRng.ForProperty(1, 1).Next());
        Assert.NotEqual(InvariantsRng.ForProperty(1, 0).Next(), InvariantsRng.ForProperty(1 + (1L << 32), 0).Next());
        Assert.Equal(InvariantsRng.ForProperty(7, 3).Next(), InvariantsRng.ForProperty(7, 3).Next());
    }

    [Fact]
    public void DrawsStayInRange()
    {
        var g = new InvariantsRng(5);
        for (var i = 0; i < 2000; i++)
        {
            Assert.InRange(g.Int(3, 9), 3, 9);
            Assert.InRange(g.IntB(-2, 2), -2, 2);
            Assert.InRange(g.Dbl(0.25, 0.75), 0.25, 0.75);
            Assert.InRange(g.Next(), 0.0, 0.9999999999);
            Assert.All(g.String(0, 6), c => Assert.InRange(c, ' ', '~'));
        }
        Assert.Equal(32, g.Bytes(32).Length);
    }

    [Fact]
    public void GeneratorsEmitLegalChainsAndWellFormedPolicies()
    {
        var g = new InvariantsRng(11);
        for (var i = 0; i < 5; i++)
        {
            var chain = InvariantArbitraries.ArbChain(g);
            Assert.True(Pca.VerifyChain(new List<object?>(chain.Caps), chain.RootIssuer, true).Ok);
            Assert.Equal(chain.Caps.Count, chain.Holders.Count);
            var p = InvariantArbitraries.ArbRiskPolicy(g);
            Assert.True(p.Kappa > 0 && p.Theta1 >= 0 && p.Theta2 >= p.Theta1 && p.BMax >= 0);
            var pt = InvariantArbitraries.ArbEvalPoint(g);
            Assert.True(pt.Action.ContainsKey("action") && pt.CavCtx.ContainsKey("now"));
        }
        Assert.Equal(32, InvariantArbitraries.ArbKeyPair(g).SecretKey.Length);
    }

    [Fact]
    public void EveryInvariantHoldsOnAFixedSeedSample()
    {
        var res = InvariantProperties.CheckInvariants(new CheckInvariantsOptions(NumRuns: 25, Seed: 3));
        Assert.Equal(PcaInvariants.InvariantNames.ToList(), res.Select(r => r.Name).ToList());
        Assert.All(res, r => Assert.True(r.Ok, r.Name + ": " + r.Error));
    }

    [Fact]
    public void ARunIsReproducibleFromItsSeed()
    {
        var p = InvariantProperties.All();
        var a = InvariantProperties.CheckInvariants(new CheckInvariantsOptions(NumRuns: 3, Seed: 9));
        var b = InvariantProperties.CheckInvariants(new CheckInvariantsOptions(NumRuns: 3, Seed: 9));
        Assert.Equal(a, b);
        Assert.Equal(p.Count, a.Count);
        var g1 = InvariantsRng.ForProperty(9, 0);
        var g2 = InvariantsRng.ForProperty(9, 0);
        Assert.Equal(((ChainModel)p[0].Generate(g1)[0]).PrincipalSeed, ((ChainModel)p[0].Generate(g2)[0]).PrincipalSeed);
    }

    [Fact]
    public void ThePropertiesCanFail()
    {
        var alwaysFalse = new InvariantProperty("x", _ => new object[] { 0 }, _ => false);
        Assert.Contains("failed at case 0", InvariantProperties.Run(alwaysFalse, 0, 5, 1));
        var throws = new InvariantProperty("t", _ => new object[] { 0 }, _ => throw new InvalidOperationException("boom"));
        Assert.Contains("InvalidOperationException: boom", InvariantProperties.Run(throws, 0, 5, 1));
        Assert.Null(InvariantProperties.Run(new InvariantProperty("ok", _ => new object[] { 0 }, _ => true), 0, 5, 1));
    }

    [Fact]
    public void ARiskInputAboveItsWorseningIsDetected()
    {
        // a policy that scored a worse input LOWER would break monotonicity: the property's check is the inequality itself
        var prop = InvariantProperties.RiskMonotoneProperty();
        var pol = new RiskPolicy(1, 1, 1, 1, 1, 1, 0.3, 0.6, 1, 0, 0, 5);
        Assert.True(prop.Check(new object[] { pol, new RiskInputs(0.2, 0.5, 0.2, 0.2, 0.5, 0.2), new RiskDeltas(0.5, 0.5, 0.5, 0.5, 0.5, 0.5) }));
    }

    [Fact]
    public void ForgedMutationsAreEachRejected()
    {
        var p = InvariantProperties.ForgedChainRejectedProperty();
        var g = InvariantsRng.ForProperty(1, 8);
        for (var i = 0; i < 20; i++) Assert.True(p.Check(p.Generate(g)));
    }

    [Fact]
    public void RefusesAVacuousRun()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => InvariantProperties.CheckInvariants(new CheckInvariantsOptions(NumRuns: 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => InvariantProperties.CheckInvariants(new CheckInvariantsOptions(NumRuns: -1)));
    }
}
