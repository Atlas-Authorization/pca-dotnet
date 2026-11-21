using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact-value checks of the risk functional, the threshold map, the trust budget and the plan geodesic (Risk.cs): every operand, boundary and message.
public class RiskKillTests2
{
    static readonly RiskPolicy Pol = new(0.25, 0.2, 0.2, 0.2, 0.1, 0.05, 0.25, 0.6, 1, 0.0005, 0.5, 1);
    // one distinct weight per input, so a swapped or dropped term changes the sum
    static readonly RiskPolicy Distinct = new(0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.25, 0.6, 1, 0.0005, 0.5, 1);
    static RiskInputs In(double sd = 0, double rev = 1, double bl = 0, double taint = 0, double conf = 1, double age = 0) => new(sd, rev, bl, taint, conf, age);
    static long Bits(double d) => BitConverter.DoubleToInt64Bits(d);
    const double Inf = double.PositiveInfinity;
    const double NInf = double.NegativeInfinity;

    [Fact]
    public void TheInputKeysAndTheWorstCaseAreFixed()
    {
        Assert.Equal(new[] { "semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age" }, Risk.InputKeys);
        Assert.Equal(new RiskInputs(1, 0, 1, 1, 0, 1), Risk.Worst);
    }

    [Fact]
    public void PolicyOfReadsAValidRiskPolicyAndRefusesTheRest()
    {
        Assert.Equal(new RiskPolicy(0.25, 0.2, 0.2, 0.2, 0.1, 0.05, 0.25, 0.6, 1, 0.0005, 0.5, 1), Risk.PolicyOf(Issue.NormJ(Issue.DefaultRiskPolicy())));
        Assert.Null(Risk.PolicyOf(null));
        Assert.Null(Risk.PolicyOf("x"));
        Assert.Null(Risk.PolicyOf(new JD()));
        var bad = Issue.NormJ(Issue.DefaultRiskPolicy());
        bad["kappa"] = 0L;
        Assert.Null(Risk.PolicyOf(bad));
    }

    // ================= score =================

    [Fact]
    public void EachInputCarriesItsOwnWeight()
    {
        Assert.Equal(0, Risk.Score(In(), Distinct), 12);
        Assert.Equal(0.01, Risk.Score(In(sd: 1), Distinct), 12);
        Assert.Equal(0.02, Risk.Score(In(rev: 0), Distinct), 12);
        Assert.Equal(0.04, Risk.Score(In(bl: 1), Distinct), 12);
        Assert.Equal(0.08, Risk.Score(In(taint: 1), Distinct), 12);
        Assert.Equal(0.16, Risk.Score(In(conf: 0), Distinct), 12);
        Assert.Equal(0.32, Risk.Score(In(age: 1), Distinct), 12);
        Assert.Equal(0.63, Risk.Score(Risk.Worst, Distinct), 12);
        Assert.Equal(0.005, Risk.Score(In(sd: 0.5), Distinct), 12);
        Assert.Equal(0.01, Risk.Score(In(rev: 0.5), Distinct), 12);
        Assert.Equal(0.02, Risk.Score(In(bl: 0.5), Distinct), 12);
        Assert.Equal(0.04, Risk.Score(In(taint: 0.5), Distinct), 12);
        Assert.Equal(0.08, Risk.Score(In(conf: 0.5), Distinct), 12);
        Assert.Equal(0.16, Risk.Score(In(age: 0.5), Distinct), 12);
    }

    [Fact]
    public void AnInputIsClampedAndANonFiniteOneIsItsWorstCase()
    {
        Assert.Equal(0.01, Risk.Score(In(sd: 1.5), Distinct), 12);
        Assert.Equal(0, Risk.Score(In(sd: -0.5), Distinct), 12);
        Assert.Equal(0.02, Risk.Score(In(rev: -2), Distinct), 12);
        Assert.Equal(0, Risk.Score(In(rev: 2), Distinct), 12);
        foreach (var bad in new[] { double.NaN, Inf, NInf })
        {
            Assert.Equal(0.01, Risk.Score(In(sd: bad), Distinct), 12);
            Assert.Equal(0.02, Risk.Score(In(rev: bad), Distinct), 12);
            Assert.Equal(0.04, Risk.Score(In(bl: bad), Distinct), 12);
            Assert.Equal(0.08, Risk.Score(In(taint: bad), Distinct), 12);
            Assert.Equal(0.16, Risk.Score(In(conf: bad), Distinct), 12);
            Assert.Equal(0.32, Risk.Score(In(age: bad), Distinct), 12);
        }
    }

    [Fact]
    public void AWeightBelowZeroOrNonFiniteContributesNothing()
    {
        var onlyBeta = Pol with { Beta = 0.2 };
        // a negative weight cannot cancel another term
        Assert.Equal(0.2, Risk.Score(In(sd: 1, rev: 0), onlyBeta with { Alpha = -5 }), 12);
        foreach (var bad in new[] { double.NaN, Inf, NInf, -0.0 })
            Assert.Equal(0.2, Risk.Score(In(sd: 1, rev: 0), onlyBeta with { Alpha = bad }), 12);
        // a zero weight is exactly +0, never -0
        var negZero = new RiskPolicy(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0, 0.25, 0.6, 1, 0.0005, 0.5, 1);
        Assert.Equal(0L, Bits(Risk.Score(Risk.Worst, negZero)));
        Assert.Equal(0L, Bits(Risk.Score(In(), Pol with { Alpha = 0, Beta = 0, Gamma = 0, Delta = 0, Epsilon = 0, Zeta = 0 })));
        // each weight slot is clamped on its own
        Assert.Equal(0.01, Risk.Score(Risk.Worst, new RiskPolicy(0.01, -1, -1, -1, -1, -1, 0.25, 0.6, 1, 0, 0, 1)), 12);
        Assert.Equal(0.32, Risk.Score(Risk.Worst, new RiskPolicy(-1, -1, -1, -1, -1, 0.32, 0.25, 0.6, 1, 0, 0, 1)), 12);
    }

    // ================= cost =================

    [Fact]
    public void CostIsKappaTimesAClampedRisk()
    {
        Assert.Equal(0.6, Risk.Cost(0.3, 2), 12);
        Assert.Equal(2, Risk.Cost(1, 2), 12);
        Assert.Equal(2, Risk.Cost(7, 2), 12);
        Assert.Equal(0, Risk.Cost(-7, 2));
        Assert.Equal(2, Risk.Cost(double.NaN, 2), 12);
        Assert.Equal(2, Risk.Cost(Inf, 2), 12);
        Assert.Equal(2, Risk.Cost(NInf, 2), 12);
        foreach (var k in new[] { -3.0, double.NaN, Inf, NInf, 0.0 })
            Assert.Equal(0, Risk.Cost(0.5, k));
        // signed zeros: the clamp keeps -0 and a non-positive kappa is +0
        Assert.Equal(Bits(-0.0), Bits(Risk.Cost(-0.0, 1)));
        Assert.Equal(0L, Bits(Risk.Cost(0.5, -0.0)));
    }

    // ================= threshold =================

    [Fact]
    public void TheThresholdMapSplitsAtTheClosedBounds()
    {
        Assert.Equal(new RequiredThreshold(1, "claim", true), Risk.Required(0, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(1, "claim", true), Risk.Required(0.25, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(1, "claim", false), Risk.Required(0.25, 0.25, 0.6, true));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(0.26, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(0.6, 0.25, 0.6, true));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Required(0.6000001, 0.25, 0.6));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Required(1, 0.25, 0.6, true));
    }

    [Fact]
    public void ANonFiniteRiskIsTheWorstCaseOfOne()
    {
        // theta2 = 1 makes r = 1 a t=2 action while NaN-as-is would be t=3
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(double.NaN, 0.25, 1));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(Inf, 0.25, 1));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Required(NInf, 0.25, 1));
        Assert.Equal(new RequiredThreshold(1, "claim", true), Risk.Required(double.NaN, 1, 1));
        Assert.Equal(new RequiredThreshold(1, "claim", false), Risk.Required(double.NaN, 1, 1, true));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Required(double.NaN, 0.25, 0.6));
    }

    [Fact]
    public void EscalateRaisesCoherentlyAndNeverLowers()
    {
        var claim = new RequiredThreshold(1, "claim", true);
        Assert.Equal(claim, Risk.Escalate(claim, 0));
        Assert.Equal(claim, Risk.Escalate(claim, 1));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Escalate(claim, 2));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(claim, 3));
        Assert.Equal(new RequiredThreshold(9, "strong", false), Risk.Escalate(claim, 9)); // never capped
        // a stronger proof than the floor is kept, optimistic acceptance only at t=1
        Assert.Equal(new RequiredThreshold(1, "strong", true), Risk.Escalate(new RequiredThreshold(1, "strong", true), 1));
        Assert.Equal(new RequiredThreshold(2, "strong", false), Risk.Escalate(new RequiredThreshold(2, "strong", true), 1));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Escalate(new RequiredThreshold(2, "claim", true), 2));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(new RequiredThreshold(3, "standard", false), 3));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(new RequiredThreshold(3, "claim", false), 1));
        Assert.Equal(new RequiredThreshold(2, "standard", false), Risk.Escalate(new RequiredThreshold(2, "standard", false), 2));
        Assert.Equal(new RequiredThreshold(3, "strong", false), Risk.Escalate(new RequiredThreshold(2, "standard", false), 3));
        // an unknown proof name ranks as the strongest and is kept when the ranks tie
        Assert.Equal(new RequiredThreshold(3, "bogus", false), Risk.Escalate(new RequiredThreshold(3, "bogus", false), 3));
        Assert.Equal(new RequiredThreshold(2, "", false), Risk.Escalate(new RequiredThreshold(2, "", false), 2));
    }

    // ================= budget =================

    [Fact]
    public void LeakDrainsLambdaPerSecondFromTheLastUpdate()
    {
        var l = Risk.Leak(new TrustBudget(1, 0), 4000, 0.1);
        Assert.Equal(0.6, l.B, 12);
        Assert.Equal(0, l.Tau);
        Assert.Equal(4000.0, l.AsOf!.Value);
        var m = Risk.Leak(new TrustBudget(1, 0, 2000), 4000, 0.1);
        Assert.Equal(0.8, m.B, 12);
        Assert.Equal(0, m.Tau);
        Assert.Equal(4000.0, m.AsOf!.Value);
        Assert.Equal(0, Risk.Leak(new TrustBudget(1, 0), 20_000, 0.1).B);
        Assert.Equal(1, Risk.Leak(new TrustBudget(1, 0), 4000, 0).B);
    }

    [Fact]
    public void LeakNeverRechargesAndNeverMovesTheClockBackwards()
    {
        var back = Risk.Leak(new TrustBudget(1, 1000, 5000), 3000, 1);
        Assert.Equal(1, back.B);
        Assert.Equal(5000.0, back.AsOf!.Value);
        Assert.Equal(1000, back.Tau);
        foreach (var lam in new[] { -1.0, double.NaN, Inf, NInf })
            Assert.Equal(1, Risk.Leak(new TrustBudget(1, 0), 4000, lam).B);
    }

    [Fact]
    public void LeakTreatsAnUnreadableClockAsNoElapsedTime()
    {
        foreach (var now in new[] { double.NaN, Inf, NInf })
        {
            var l = Risk.Leak(new TrustBudget(1, 0, 10), now, 1);
            Assert.Equal(1, l.B);
            Assert.Equal(10.0, l.AsOf!.Value);
        }
        // an unreadable last-update time: no leak either
        Assert.Equal(1, Risk.Leak(new TrustBudget(1, double.NaN), 5000, 1).B);
        Assert.Equal(1, Risk.Leak(new TrustBudget(1, Inf), 5000, 1).B);
        Assert.Equal(1, Risk.Leak(new TrustBudget(1, 0, double.NaN), 5000, 1).B);
        Assert.Equal(1, Risk.Leak(new TrustBudget(1, 0, NInf), 5000, 1).B);
    }

    [Fact]
    public void DebitRechargeAndRechargeFullKeepTheBudgetInRange()
    {
        Assert.Equal(new TrustBudget(0.75, 3, 4), Risk.Debit(new TrustBudget(1, 3, 4), 0.25));
        foreach (var c in new[] { double.NaN, Inf, NInf, -1.0 })
            Assert.Equal(new TrustBudget(1, 3, 4), Risk.Debit(new TrustBudget(1, 3, 4), c));
        Assert.Equal(0, Risk.Debit(new TrustBudget(1, 3, 4), 1).B);
        Assert.Equal(new TrustBudget(0.75, 99, 99), Risk.Recharge(new TrustBudget(0.25, 1, 2), 0.5, 1, 99));
        Assert.Equal(new TrustBudget(1, 99, 99), Risk.Recharge(new TrustBudget(0.75, 1), 0.25, 1, 99));
        Assert.Equal(1, Risk.Recharge(new TrustBudget(0.75, 1), 0.5, 1, 99).B);
        Assert.Equal(1, Risk.Recharge(new TrustBudget(2, 1), 0, 1, 99).B);
        foreach (var rho in new[] { -1.0, double.NaN, Inf, NInf })
            Assert.Equal(0.25, Risk.Recharge(new TrustBudget(0.25, 1), rho, 1, 99).B);
        foreach (var bMax in new[] { -1.0, double.NaN, Inf, NInf })
            Assert.Equal(0, Risk.Recharge(new TrustBudget(0.25, 1), 0.5, bMax, 99).B);
        Assert.Equal(new TrustBudget(0.75, 5, 5), Risk.RechargeFull(0.75, 5));
        foreach (var bMax in new[] { -1.0, double.NaN, Inf, NInf })
            Assert.Equal(new TrustBudget(0, 5, 5), Risk.RechargeFull(bMax, 5));
    }

    [Fact]
    public void AgeSinceTouchIsTheClampedFractionOfTheHorizon()
    {
        var b = new TrustBudget(1, 100);
        Assert.Equal(0, Risk.AgeSinceTouch(b, 100));
        Assert.Equal(0, Risk.AgeSinceTouch(b, 50));
        Assert.Equal(0.5, Risk.AgeSinceTouch(b, 1_800_100), 12);
        Assert.Equal(1, Risk.AgeSinceTouch(b, 3_600_100));
        Assert.Equal(1, Risk.AgeSinceTouch(b, 9_000_000));
        Assert.Equal(0.5, Risk.AgeSinceTouch(b, 600, 1000), 12);
        Assert.Equal(1, Risk.AgeSinceTouch(b, 1100, 1000));
        Assert.Equal(Bits(-0.0), Bits(Risk.AgeSinceTouch(new TrustBudget(1, 0.0), -0.0)));
        Assert.Equal(1, Risk.AgeSinceTouch(b, double.NaN));
        Assert.Equal(1, Risk.AgeSinceTouch(b, Inf));
        Assert.Equal(1, Risk.AgeSinceTouch(b, NInf));
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, double.NaN), 100));
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, Inf), 100));
        Assert.Equal(1, Risk.AgeSinceTouch(new TrustBudget(1, NInf), 100));
    }

    [Fact]
    public void AnUnusableHorizonIsTheWorstAgeWhateverTheClock()
    {
        var b = new TrustBudget(1, 100);
        foreach (var horizon in new[] { 0.0, -1.0, double.NaN, Inf, NInf })
        {
            Assert.Equal(1, Risk.AgeSinceTouch(b, 100, horizon)); // now == tau: 0/0 would be NaN
            Assert.Equal(1, Risk.AgeSinceTouch(b, 50, horizon));
            Assert.Equal(1, Risk.AgeSinceTouch(b, 500, horizon));
        }
    }

    // ================= admission =================

    [Fact]
    public void AdmissionFollowsTheBandAndTheBudget()
    {
        foreach (var t in new[] { 0, 1, 2 })
            Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(t, false));
        Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(0, true));
        Assert.Equal(new Admission(true, false, 1, true), Risk.AdmitOf(1, true));
        Assert.Equal(new Admission(false, true, 2, true), Risk.AdmitOf(2, true));
        foreach (var t in new[] { 3, 4, 9 })
        {
            Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(t, true));
            Assert.Equal(new Admission(false, true, 3, false), Risk.AdmitOf(t, false));
        }
    }

    [Fact]
    public void AdmitComparesTheBudgetToTheCostInclusively()
    {
        Assert.Equal(new Admission(false, true, 2, true), Risk.Admit(0.4, new TrustBudget(0.4, 0), Pol));
        Assert.Equal(new Admission(false, true, 3, false), Risk.Admit(0.4, new TrustBudget(0.39, 0), Pol));
        Assert.Equal(new Admission(false, true, 3, false), Risk.Admit(0.9, new TrustBudget(1, 0), Pol));
        Assert.Equal(new Admission(true, false, 1, true), Risk.Admit(0.25, new TrustBudget(0.25, 0), Pol with { Kappa = 1 }));
        Assert.Equal(new Admission(false, true, 3, false), Risk.Admit(0.25, new TrustBudget(0.25, 0), Pol with { Kappa = 2 }));
    }

    [Fact]
    public void TheCoreDecisionNeedsEveryPredicateAndDebitsOnlyAReleasedMeteredAction()
    {
        var rt = new RequiredThreshold(1, "claim", true);
        var machine = Risk.AdmitOf(1, true);
        Assert.Equal(new CoreDecision(true, true, false, rt, true), Risk.DecideCore(true, true, true, true, rt, machine));
        for (int off = 0; off < 4; off++)
        {
            var f = new[] { true, true, true, true };
            f[off] = false;
            var d = Risk.DecideCore(f[0], f[1], f[2], f[3], rt, machine);
            Assert.Equal(new CoreDecision(false, false, true, rt, false), d);
        }
        Assert.Equal(new CoreDecision(true, false, true, new RequiredThreshold(2, "standard", false), true), Risk.DecideCore(true, true, true, true, rt, Risk.AdmitOf(2, true)));
        Assert.Equal(new CoreDecision(true, false, true, new RequiredThreshold(3, "strong", false), false), Risk.DecideCore(true, true, true, true, rt, Risk.AdmitOf(1, false)));
        Assert.Equal(new CoreDecision(false, false, true, new RequiredThreshold(2, "standard", false), false), Risk.DecideCore(false, true, true, true, rt, new Admission(true, false, 2, true)));
    }

    [Fact]
    public void TheSafetyBoundIsBMaxOverKappa()
    {
        Assert.Equal(2.5, Risk.SafetyBound(10, 4), 12);
        Assert.Equal(0, Risk.SafetyBound(-3, 2));
        Assert.Equal(0, Risk.SafetyBound(3, 0));
        Assert.Equal(0, Risk.SafetyBound(3, -2));
        Assert.Equal(0, Risk.SafetyBound(0, 2));
    }

    // ================= budget algebra =================

    [Fact]
    public void ASubBudgetIsAllocatedWithinTheParent()
    {
        var parent = new TrustBudget(1, 3, 4);
        var ok = Risk.SubBudget(parent, 0.5);
        Assert.True(ok.Ok);
        Assert.Null(ok.Reason);
        Assert.Equal(new TrustBudget(0.5, 3, 4), Assert.Single(ok.Nodes!));
        var whole = Risk.SubBudget(parent, 1);
        Assert.True(whole.Ok);
        Assert.Equal(1, whole.Nodes![0].B);
        var none = Risk.SubBudget(parent, 0);
        Assert.True(none.Ok);
        Assert.Equal(0, none.Nodes![0].B);
        Assert.Equal(new TrustBudget(0.5, 3, 3), Risk.SubBudget(new TrustBudget(1, 3), 0.5).Nodes![0]); // no AsOf: the sub-budget starts at tau
    }

    [Fact]
    public void ASubBudgetOutsideTheParentIsRefusedWithoutNodes()
    {
        var parent = new TrustBudget(1, 3, 4);
        foreach (var bad in new[] { -0.5, double.NaN, Inf, NInf })
        {
            var r = Risk.SubBudget(parent, bad);
            Assert.False(r.Ok);
            Assert.Null(r.Nodes);
            Assert.Equal("allocation must be finite and >= 0", r.Reason);
        }
        var over = Risk.SubBudget(parent, 1.0000001);
        Assert.False(over.Ok);
        Assert.Null(over.Nodes);
        Assert.Equal("allocation exceeds parent remaining budget", over.Reason);
    }

    [Fact]
    public void ADebitCoversBothBudgetsOrChangesNothing()
    {
        var parent = new TrustBudget(1, 3, 4);
        var ok = Risk.DebitConsolidated(parent, new TrustBudget(0.5, 0), 0.25);
        Assert.True(ok.Ok);
        Assert.Null(ok.Reason);
        Assert.Equal(new TrustBudget(0.75, 3, 4), ok.Nodes![0]);
        Assert.Equal(new TrustBudget(0.25, 0), ok.Nodes![1]);
        var exact = Risk.DebitConsolidated(new TrustBudget(0.5, 0), new TrustBudget(0.5, 0), 0.5);
        Assert.True(exact.Ok);
        Assert.Equal(new[] { 0.0, 0.0 }, exact.Nodes!.Select(n => n.B).ToArray());
        var free = Risk.DebitConsolidated(parent, new TrustBudget(0.5, 0), -1);
        Assert.True(free.Ok);
        Assert.Equal(new[] { 1.0, 0.5 }, free.Nodes!.Select(n => n.B).ToArray());
        var sub = Risk.DebitConsolidated(parent, new TrustBudget(0.1, 0), 0.2);
        Assert.False(sub.Ok);
        Assert.Null(sub.Nodes);
        Assert.Equal("sub-agent budget insufficient", sub.Reason);
        var par = Risk.DebitConsolidated(new TrustBudget(0.1, 0), new TrustBudget(1, 0), 0.2);
        Assert.False(par.Ok);
        Assert.Null(par.Nodes);
        Assert.Equal("parent budget insufficient", par.Reason);
        Assert.Equal("sub-agent budget insufficient", Risk.DebitConsolidated(new TrustBudget(0.1, 0), new TrustBudget(0.1, 0), 0.2).Reason);
    }

    [Fact]
    public void ADebitAlongAPathNamesTheFirstNodeThatCannotCover()
    {
        var ok = Risk.DebitConsolidatedPath(new[] { new TrustBudget(1, 1), new TrustBudget(0.5, 2, 3) }, 0.5);
        Assert.True(ok.Ok);
        Assert.Null(ok.Reason);
        Assert.Equal(new[] { new TrustBudget(0.5, 1), new TrustBudget(0, 2, 3) }, ok.Nodes!.ToArray());
        var bad = Risk.DebitConsolidatedPath(new[] { new TrustBudget(1, 0), new TrustBudget(0.5, 0), new TrustBudget(0.1, 0) }, 0.6);
        Assert.False(bad.Ok);
        Assert.Null(bad.Nodes);
        Assert.Equal("budget node at depth 1 insufficient (need 0.6, have 0.5)", bad.Reason);
        Assert.Equal("budget node at depth 0 insufficient (need 2, have 1)", Risk.DebitConsolidatedPath(new[] { new TrustBudget(1, 0) }, 2).Reason);
        var empty = Risk.DebitConsolidatedPath(Array.Empty<TrustBudget>(), 1);
        Assert.True(empty.Ok);
        Assert.Empty(empty.Nodes!);
        Assert.True(Risk.DebitConsolidatedPath(new[] { new TrustBudget(0.25, 0) }, double.NaN).Ok);
        Assert.False(Risk.DebitConsolidatedPath(new[] { new TrustBudget(double.NaN, 0) }, 0.5).Ok);
        Assert.False(Risk.DebitConsolidatedPath(new[] { new TrustBudget(double.NaN, 0) }, 0).Ok); // NaN covers nothing, not even zero
    }

    // ================= ToFixed3 =================

    [Theory]
    [InlineData(0.0, "0.000")]
    [InlineData(0.0625, "0.063")]
    [InlineData(0.1875, "0.188")]
    [InlineData(0.0005, "0.001")]
    [InlineData(0.0015, "0.002")]
    [InlineData(0.0004999999, "0.000")]
    [InlineData(0.1, "0.100")]
    [InlineData(0.5, "0.500")]
    [InlineData(0.7000000000000001, "0.700")]
    [InlineData(0.9995, "1.000")]
    [InlineData(1.0, "1.000")]
    [InlineData(1.0005, "1.000")]
    [InlineData(123456789.125, "123456789.125")]
    [InlineData(1e15, "1000000000000000.000")]
    [InlineData(4503599627370496.0, "4503599627370496.000")]
    [InlineData(9007199254740992.0, "9007199254740992.000")]
    [InlineData(1152921504606846976.0, "1152921504606846976.000")]
    [InlineData(double.Epsilon, "0.000")]
    [InlineData(2.2250738585072014E-308, "0.000")]
    [InlineData(-1.0, "-1.000")]
    [InlineData(-1.5, "-1.500")]
    [InlineData(double.NaN, "NaN")]
    [InlineData(double.PositiveInfinity, "Infinity")]
    [InlineData(double.NegativeInfinity, "-Infinity")]
    public void ToFixed3RoundsLikeJavaScript(double r, string expected) => Assert.Equal(expected, Risk.ToFixed3(r));

    [Fact]
    public void ToFixed3PrintsANegativeZeroWithoutASign() => Assert.Equal("0.000", Risk.ToFixed3(-0.0));

    // ================= plan geodesic =================

    static JD N(string id, object? pre = null, object? post = null) => new() { ["id"] = id, ["pre"] = pre, ["post"] = post };
    static JL Plan(params object?[] nodes) => nodes.ToList();

    [Fact]
    public void AnEdgeFromAPreReferenceShortensTheDistance()
    {
        // with no edge the index distance a..d would be 3/3 = 1
        var p = Plan(N("a"), N("b"), N("c"), N("d", "a"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "a", "d"), 12);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "d", "a"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(p, "a", "c")); // unreachable
        Assert.Equal(1, Risk.PlanGeodesic(p, "b", "c"));
    }

    [Fact]
    public void AnEdgeFromAPostReferenceShortensTheDistance()
    {
        var p = Plan(N("a", null, "d"), N("b"), N("c"), N("d"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "a", "d"), 12);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "d", "a"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(p, "a", "b"));
        var viaList = Plan(N("a"), N("b"), N("c"), N("d", null, new JL { "b", 7L, null, "a" }));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(viaList, "d", "a"), 12);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(viaList, "d", "b"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(viaList, "a", "b"), 12);
    }

    [Fact]
    public void ListsKeepOnlyTheirStringsAndEveryReferenceKeyCounts()
    {
        var p = Plan(N("a"), N("b"), N("c"), N("d", new JL { "a", 5L, null, new JL { "c" }, "b" }));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "a", "d"), 12);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "b", "d"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(p, "a", "b"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(p, "a", "c")); // the nested list is not a reference
        foreach (var key in new[] { "after", "depends_on", "requires", "nodes" })
        {
            var asString = Plan(N("a"), N("b"), N("c"), N("d", new JD { [key] = "a" }));
            Assert.Equal(1.0 / 3, Risk.PlanGeodesic(asString, "a", "d"), 12);
            var asList = Plan(N("a"), N("b"), N("c"), N("d", new JD { [key] = new JL { "a" } }));
            Assert.Equal(1.0 / 3, Risk.PlanGeodesic(asList, "a", "d"), 12);
        }
        foreach (var key in new[] { "before", "enables", "then", "next" })
        {
            var asString = Plan(N("a", null, new JD { [key] = "d" }), N("b"), N("c"), N("d"));
            Assert.Equal(1.0 / 3, Risk.PlanGeodesic(asString, "a", "d"), 12);
            var asList = Plan(N("a", null, new JD { [key] = new JL { "d" } }), N("b"), N("c"), N("d"));
            Assert.Equal(1.0 / 3, Risk.PlanGeodesic(asList, "a", "d"), 12);
        }
        // a pre key under post (and the other way) and an unknown key add nothing
        var swapped = Plan(N("a", null, new JD { ["after"] = "d" }), N("b"), N("c"), N("d", new JD { ["before"] = "a", ["foo"] = "b" }));
        Assert.Equal(1, Risk.PlanGeodesic(swapped, "a", "d")); // index distance 3/3
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(swapped, "a", "b"), 12);
        var nested = Plan(N("a"), N("b"), N("c"), N("d", new JD { ["after"] = new JD { ["x"] = "a" } }));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(nested, "a", "b"), 12);
    }

    [Fact]
    public void ASelfReferenceOrAnUnknownIdAddsNoEdge()
    {
        var self = Plan(N("a"), N("b", "b", "b"), N("c"), N("d"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(self, "a", "b"), 12); // still the index distance
        Assert.Equal(1, Risk.PlanGeodesic(self, "a", "d"));
        var unknownPre = Plan(N("a"), N("b", "zzz"), N("c"), N("d"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(unknownPre, "b", "c"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(unknownPre, "a", "d"));
        var unknownPost = Plan(N("a"), N("b", null, "zzz"), N("c"), N("d"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(unknownPost, "b", "c"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(unknownPost, "a", "c"), 12);
    }

    [Fact]
    public void WithoutEdgesTheDistanceIsTheIndexGap()
    {
        var p = Plan(N("w"), N("a"), N("b"), N("c"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "a", "b"), 12);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(p, "b", "a"), 12);
        Assert.Equal(2.0 / 3, Risk.PlanGeodesic(p, "w", "b"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(p, "w", "c"));
        Assert.Equal(1, Risk.PlanGeodesic(Plan(N("a"), N("b")), "a", "b"));
    }

    [Fact]
    public void AShortestPathWinsOverALongerOne()
    {
        var chain = Plan(N("a"), N("b", "a"), N("c", "b"), N("d", "c"), N("e", new JL { "d", "a" }));
        Assert.Equal(0.25, Risk.PlanGeodesic(chain, "a", "e"), 12);
        Assert.Equal(0.25, Risk.PlanGeodesic(chain, "a", "b"), 12);
        Assert.Equal(0.5, Risk.PlanGeodesic(chain, "b", "e"), 12);
        Assert.Equal(0.5, Risk.PlanGeodesic(chain, "a", "d"), 12);
        Assert.Equal(0.5, Risk.PlanGeodesic(chain, "c", "e"), 12);
        var line = Plan(N("a"), N("b", "a"), N("c", "b"), N("d", "c"), N("e", "d"));
        Assert.Equal(1, Risk.PlanGeodesic(line, "a", "e"));
        Assert.Equal(0.5, Risk.PlanGeodesic(line, "a", "c"), 12);
        Assert.Equal(0.5, Risk.PlanGeodesic(line, "e", "c"), 12);
        Assert.Equal(0.75, Risk.PlanGeodesic(line, "e", "b"), 12);
    }

    [Fact]
    public void ADuplicateOrTwoWayEdgeCountsOnceAndAnIslandIsUnreachable()
    {
        var both = Plan(N("a", null, "b"), N("b", "a"), N("c"), N("d"));
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(both, "a", "b"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(both, "a", "c"));
        var islands = Plan(N("a"), N("b", "a"), N("c"), N("d", "c"), N("e"));
        Assert.Equal(0.25, Risk.PlanGeodesic(islands, "c", "d"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(islands, "a", "d"));
        Assert.Equal(1, Risk.PlanGeodesic(islands, "e", "a"));
    }

    [Fact]
    public void ThePlanShapeAndTheIdsAreCheckedBeforeAnyEdge()
    {
        var p = Plan(N("a"), N("b", "a"));
        Assert.Equal(0, Risk.PlanGeodesic(p, "a", "a"));
        Assert.Equal(1, Risk.PlanGeodesic(p, "zzz", "zzz"));
        Assert.Equal(1, Risk.PlanGeodesic(p, "a", null));
        Assert.Equal(1, Risk.PlanGeodesic(p, null, "a"));
        Assert.Equal(1, Risk.PlanGeodesic(p, "a", "zzz"));
        Assert.Equal(1, Risk.PlanGeodesic(p, "zzz", "a"));
        Assert.Equal(1, Risk.PlanGeodesic(null, "a", "b"));
        Assert.Equal(1, Risk.PlanGeodesic(new JD(), "a", "b"));
        Assert.Equal(1, Risk.PlanGeodesic(Plan(), "a", "b"));
        Assert.Equal(0, Risk.PlanGeodesic(Plan(N("a")), "a", "a"));
        Assert.Equal(1, Risk.PlanGeodesic(Plan(N("a"), N("b")), "a", "b"));
    }

    [Fact]
    public void OnlyObjectsWithAStringIdAreNodesButAllOfThemCountInTheSize()
    {
        var p = Plan("x", N("a"), new JD { ["id"] = 5L }, N("b"), 7L);
        Assert.Equal(2.0 / 4, Risk.PlanGeodesic(p, "a", "b"), 12);
        Assert.Equal(1, Risk.PlanGeodesic(p, "x", "a"));
        var later = Plan(N("a"), N("a"), N("b"));
        Assert.Equal(0.5, Risk.PlanGeodesic(later, "a", "b"), 12); // the last node with an id wins
        var skipped = Plan("x", N("a"), N("b", "a"), 7L);
        Assert.Equal(1.0 / 3, Risk.PlanGeodesic(skipped, "a", "b"), 12);
    }
}
