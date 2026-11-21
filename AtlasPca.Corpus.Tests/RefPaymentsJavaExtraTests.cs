using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the payments parts that sit on the core decision and the optimistic path: a charge authorized with the core engine's own decision
/// (no injected decider) and the bonded claim over a charge PCActn (Ed25519, compared in full).</summary>
public class RefPaymentsJavaExtraTests
{
    const string M = "ref-payments-java-extra";

    static double? N(D o, string k) => IntentJs.NumOf(o.GetValueOrDefault(k));

    [Fact] public void AuthorizeChargeCore() => Base.Check(M, "authorizeChargeCore", a => Payments.Payments.AuthorizeCharge(a[0], a[1], a[2]), min: 82);

    [Fact]
    public void OpenChargeBond() => Base.Check(M, "openChargeBond", a =>
    {
        var o = (D)a[1]!;
        var opts = new OpenOptimisticOptions
        {
            BondRef = (string)o["bondRef"]!, ClaimedR = N(o, "claimedR") ?? double.NaN, ChallengeWindowMs = N(o, "challengeWindowMs"), IssuedAt = N(o, "issuedAt"), ServerNow = N(o, "serverNow"),
        };
        return Optimistic.OpenChargeBond((D)a[0]!, opts, Pca.B64uDecode(a[2], 32) ?? throw new InvalidDataException("seed"));
    }, min: 55);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "authorizeChargeCore", "openChargeBond" });
        Assert.Equal(137, Base.Cases(M).Count);
    }
}
