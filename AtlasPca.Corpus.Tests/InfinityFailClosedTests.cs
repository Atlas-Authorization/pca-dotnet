using AtlasPca;
using AtlasPca.Payments;
using AtlasPca.Signals;
using DpopApi = AtlasPca.Dpop.Dpop;
using SignalsApi = AtlasPca.Signals.Signals;
using SdjwtApi = AtlasPca.Sdjwt.Sdjwt;
using WbaApi = AtlasPca.WebBotAuth.WebBotAuth;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>A non-finite clock, budget, window or amount never admits, whichever side of the comparison the infinity lands on (NaN compares false on both sides,
/// -Infinity is below every deadline, +Infinity is above every cap). A legitimate +Infinity cap stays allowed on the cap side only.</summary>
public class InfinityFailClosedTests
{
    static readonly double[] NonFinite = { double.NaN, double.PositiveInfinity, double.NegativeInfinity };

    // ---- risk budgets: the balance is never infinite

    [Fact]
    public void InfiniteBudgetBalanceNeverCovers()
    {
        // the old `parent.B < x` / `b.B >= cost` read +Infinity as covered
        var inf = new TrustBudget(double.PositiveInfinity, 0, 0);
        var fin = new TrustBudget(10, 0, 0);
        Assert.False(Risk.SubBudget(inf, 5).Ok);
        Assert.False(Risk.DebitConsolidated(inf, fin, 1).Ok);
        Assert.False(Risk.DebitConsolidated(fin, inf, 1).Ok);
        Assert.False(Risk.DebitConsolidatedPath(new[] { fin, inf }, 1).Ok);
        Assert.False(Risk.DebitConsolidatedPath(new[] { new TrustBudget(double.NaN, 0, 0) }, 1).Ok);
        Assert.True(Risk.DebitConsolidatedPath(new[] { fin, fin }, 1).Ok);
    }

    // ---- class approvals

    [Fact]
    public void NonFiniteClassApprovalFieldsNeverCover()
    {
        foreach (var v in NonFinite)
        {
            // an infinite ttl (now < grantedAt + Inf) or an infinite grantedAt used to cover
            Assert.False(Approvals.ClassApprovalCovers(Approval(1_000, v), "stripe.refund", "r", 2_000));
            Assert.False(Approvals.ClassApprovalCovers(Approval(v, 10_000), "stripe.refund", "r", 2_000));
            Assert.False(Approvals.ClassApprovalCovers(Approval(1_000, 10_000), "stripe.refund", "r", v));
        }
        Assert.True(Approvals.ClassApprovalCovers(Approval(1_000, 10_000), "stripe.refund", "r", 2_000));
    }

    static D Approval(double grantedAt, double ttlMs) => new() { ["grantedAt"] = grantedAt, ["ttlMs"] = ttlMs, ["verbs"] = new L { "stripe.refund" }, ["resource"] = "r" };

    // ---- revocation freshness

    [Fact]
    public void NonFiniteClockNeverAgesRevocationState()
    {
        foreach (var v in NonFinite)
            // +Infinity now with an unbounded max age used to pass both comparisons
            Assert.False(RevocationFreshness.CheckAge(1_000, v, double.PositiveInfinity).Ok);
        Assert.True(RevocationFreshness.CheckAge(1_000, 2_000, 10_000).Ok);
    }

    // ---- replay stores

    [Fact]
    public void ReplayStoresRefuseANonFiniteClock()
    {
        var dpop = DpopApi.CreateInMemoryDpopReplayStore();
        var set = SignalsApi.CreateInMemorySetReplayStore();
        foreach (var v in NonFinite)
        {
            // a non-finite clock admits nothing (the old stores recorded the key and returned true)
            Assert.False(dpop.AddIfAbsent("k" + v, 100, v));
            Assert.False(set.AddIfAbsent("j" + v, 100, v));
        }
        Assert.False(set.AddIfAbsent("expiry", double.PositiveInfinity, 50));
        Assert.True(dpop.AddIfAbsent("fine", 100, 50));
        Assert.True(set.AddIfAbsent("fine", 100, 50));
    }

    // ---- SSF stream health

    [Fact]
    public void StreamHealthRefusesANonFiniteClock()
    {
        foreach (var v in NonFinite)
        {
            var s = new SsfStream.StreamHealth(new D());
            Assert.Null(s.RequestVerification(v));
            var t = new SsfStream.StreamHealth(new D());
            var state = t.RequestVerification(1_000)!;
            Assert.NotNull(state);
            Assert.False(t.AckVerification(state, v)); // the old ack matched the pending state at any clock
            Assert.False(t.RevocationFreshWithin(300, v));
        }
        var ok = new SsfStream.StreamHealth(new D());
        Assert.True(ok.AckVerification(ok.RequestVerification(1_000), 1_010));
        Assert.True(ok.RevocationFreshWithin(300, 1_100));
    }

    // ---- stripe webhook tolerance

    [Fact]
    public void StripeSignatureNeedsAFiniteClockAndTolerance()
    {
        var header = StripeRails.SignStripePayload("{}", "whsec", "1700000000");
        // the verifier reads its clock and tolerance as JSON numbers (a boxed double is not one: it reads as NaN)
        Assert.True(StripeRails.VerifyStripeSignature("{}", header, "whsec", new Num("1700000100")));
        // NaN now made |now - t| > tol false; an infinite tolerance made every age fresh
        Assert.False(StripeRails.VerifyStripeSignature("{}", header, "whsec", new Num("NaN")));
        Assert.False(StripeRails.VerifyStripeSignature("{}", header, "whsec", new Num("1900000000"), new Num("Infinity")));
        Assert.False(StripeRails.VerifyStripeSignature("{}", header, "whsec", new Num("1700000100"), new Num("NaN")));
    }

    // ---- bond moves and the insurance pool

    [Fact]
    public void InfiniteBalanceNeverFundsABondMove()
    {
        var mv = new L { new D { ["account"] = "a", ["op"] = "debit", ["amount"] = 5.0 } };
        // the old `balance < amount` was false for +Infinity: an unbounded balance paid any debit
        Assert.Throws<InvalidOperationException>(() => BondDoc.ApplyBondMoves(_ => double.PositiveInfinity, mv));
        Assert.Throws<InvalidOperationException>(() => BondDoc.ApplyBondMoves(_ => double.NaN, mv));
        Assert.Equal(5.0, BondDoc.ApplyBondMoves(_ => 10.0, mv)["a"]);
    }

    [Fact]
    public void SdJwtRefusesANonFiniteClockOrWindow()
    {
        foreach (var key in new[] { "now", "clockToleranceSec", "kbMaxAgeSec" })
            foreach (var v in NonFinite)
            {
                // the date checks compare with NaN (always false) and -Infinity (before every expiry): the options are refused up front
                var r = SdjwtApi.VerifyPcaSdJwt("x", new D { [key] = v });
                Assert.Equal(false, r["ok"]);
                Assert.Equal("now, clockToleranceSec and kbMaxAgeSec must be finite", r["reason"]);
            }
    }

    [Fact]
    public void WebBotAuthReplayCacheRefusesNonFiniteTimes()
    {
        var cache = WbaApi.MemoryReplayCache();
        foreach (var v in NonFinite)
        {
            Assert.False(cache("a" + v, 100, v));
            Assert.False(cache("b" + v, v, 50));
        }
        Assert.True(cache("fine", 100, 50));
    }

    // ---- beacons

    [Fact]
    public void NonFiniteClockNeverVerifiesABeacon()
    {
        using var issuer = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)9, 32).ToArray()));
        var beacon = Beacons.Mint(issuer, "inst", 1, 600_000);
        BeaconCheck Check(double now) => new() { Issuers = new[] { issuer.Id }, Now = now, Instance = "inst" };
        Assert.True(Beacons.Verify(beacon, Check(630_000)).Ok);
        // NaN compared false against issued_at and not_after, so the beacon verified at no time at all
        foreach (var v in NonFinite) Assert.False(Beacons.Verify(beacon, Check(v)).Ok);
    }

    // ---- shared payment token limits, spend cap, recurrence frequency, challenge status

    [Fact]
    public void SharedPaymentTokenLimitsRefuseANonFinitePeriodEnd()
    {
        D Mandate(object? end) => new() { ["terms"] = new D { ["currency"] = "USD", ["autoApproveThreshold"] = new Num("50"), ["periodEnd"] = end }, ["budget"] = new D { ["B"] = new Num("100") } };
        // an infinite period end was emitted as a null expiry, read as no expiry
        foreach (var raw in new[] { "NaN", "Infinity", "-Infinity" })
            Assert.Throws<InvalidOperationException>(() => Payments.Payments.SharedPaymentTokenLimits(Mandate(new Num(raw)), new Num("1000")));
        Assert.NotNull(Payments.Payments.SharedPaymentTokenLimits(Mandate(new Num("5000")), new Num("1000")));
    }

    [Fact]
    public void AcpSpendCapMustBeANonNegativeIntegerWhenPresent()
    {
        D Auth(object? cap) => new() { ["maxAmount"] = cap };
        var req = new D { ["amount"] = new Num("5"), ["currency"] = "usd", ["merchant"] = "m" };
        foreach (var raw in new[] { "NaN", "Infinity", "-Infinity", "-1", "-0", "1.5" })
        {
            var r = Acp.Acp.CheckPaymentAuthority(Auth(new Num(raw)), req);
            Assert.Equal(false, r["ok"]);
            Assert.Equal("authorized spend cap is not a non-negative integer (fail closed)", r["reason"]);
        }
        var nullCap = Acp.Acp.CheckPaymentAuthority(Auth(null), req); // a present null cap is refused, not unbounded
        Assert.Equal(false, nullCap["ok"]);
        Assert.Equal("authorized spend cap is not a non-negative integer (fail closed)", nullCap["reason"]);
        Assert.Equal(true, Acp.Acp.CheckPaymentAuthority(new D(), req)["ok"]); // an absent cap is unbounded
        Assert.Equal(true, Acp.Acp.CheckPaymentAuthority(Auth(new Num("5")), req)["ok"]);
    }

    [Fact]
    public void UnknownRecurrenceFrequencyIsAViolationWithoutALastUsedDate()
    {
        var amountRange = new D { ["type"] = "payment.amount_range", ["currency"] = "USD", ["max"] = new Num("10") };
        var budget = new D { ["type"] = "payment.budget", ["currency"] = "USD", ["max"] = new Num("10") };
        var closed = new D { ["payment_amount"] = new D { ["currency"] = "USD", ["amount"] = new Num("1") } };
        // no context and no last-used date: the old code only failed on a missing context, never on the frequency itself
        var rec = new D { ["type"] = "payment.agent_recurrence", ["frequency"] = "FORTNIGHTLY" };
        var open = new D { ["constraints"] = new L { amountRange, budget, rec } };
        var v = Ap2.Ap2.CheckPaymentConstraints(open, closed, new D { ["now"] = new Num("1700000000") });
        Assert.Contains("unknown recurrence frequency", v);
        // (the budget constraint without a context still reports its own "mandate context is required to evaluate a budget")
        Assert.DoesNotContain(v, m => m.StartsWith("mandate context is required to evaluate recurrence"));
    }

    [Fact]
    public void ChallengeStatusRefusesANonFiniteClock()
    {
        foreach (var v in NonFinite)
        {
            var o = new StoreBondLedgerOptions { Store = new KvBondStore(new MemoryAtomicKv()), GuardianKey = EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray()), Clock = () => v };
            // never reports finalized (which opens settlement) on a clock that is not a finite time
            Assert.Equal("clock_invalid", Assert.Throws<BondStoreError>(() => new StoreBondLedger(o).ChallengeStatus("c")).Code);
        }
    }

    [Fact]
    public void DlpNonFiniteTaintNeverBeatsAnInfiniteCeiling()
    {
        var policy = new D { ["classes"] = new L(), ["defaultMaxTaintForAuto"] = new Num("Infinity") };
        foreach (var raw in new[] { "NaN", "Infinity", "-Infinity" })
        {
            // the taint is read as +Infinity, which an unbounded ceiling used to admit
            var r = AtlasPca.Research.Dlp.EvaluateDlp(policy, new D { ["verb"] = "v", ["resource"] = "r", ["taint"] = new Num(raw) });
            Assert.Equal("step_up", r["outcome"]);
        }
    }

    [Fact]
    public void ClaimStatusRefusesANonFiniteClockOrWindow()
    {
        foreach (var x in NonFinite)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Optimistic.ClaimStatus(100, 50, x));
            Assert.Throws<ArgumentOutOfRangeException>(() => Optimistic.ClaimStatus(100, x, 120));
            Assert.Throws<ArgumentOutOfRangeException>(() => Optimistic.ClaimStatus(x, 50, 120));
            Assert.False(Optimistic.WithinChallengeWindow(100, 50, x));
        }
        Assert.Equal("open", Optimistic.ClaimStatus(100, 50, 120));
    }
}
