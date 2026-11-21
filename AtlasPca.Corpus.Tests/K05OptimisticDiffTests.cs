using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the optimistic path (test-data/k05-optimistic.json.gz, TS reference packages/pca/src/optimistic.ts):
/// bonded claims, fraud proofs (wire level) and guardian-signed settlement records. Every result is the first failing check's name.</summary>
public class K05OptimisticDiffTests
{
    const string M = "optimistic";

    static double Num(object? v) => IntentJs.NumOf(v) ?? double.NaN;

    static ChallengeWindowPolicy Policy(object? po)
    {
        var p = (D)po!;
        return new ChallengeWindowPolicy(Num(p["minWindowMs"]), Num(p["maxWindowMs"]), Num(p["maxSkewMs"]));
    }

    [Fact] public void ClaimCheck() => K05.Check(M, "claimCheck", a => Optimistic.ClaimCheck(a[0], (string)a[1]!, (string)a[2]!, Num(a[3]), Policy(a[4])), min: 430);
    [Fact] public void FraudProofWireCheck() => K05.Check(M, "fraudProofWireCheck", a => Optimistic.FraudProofWireCheck(a[0], a[1]), min: 680);
    [Fact] public void SettlementWireCheck() => K05.Check(M, "settlementWireCheck", a => Optimistic.SettlementWireCheck(a[0], (string)a[1]!), min: 2520);

    [Fact] public void EveryFn() => K05.Covers(M, new[] { "claimCheck", "fraudProofWireCheck", "settlementWireCheck" });
}
