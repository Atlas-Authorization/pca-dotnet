using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of reputation and underwriting: the validator and the fail-closed edges (test-data/ref-reputation.json.gz), the scoring, pricing and signed coverage quotes
/// of the sweep corpus (test-data/ref-core-sweep-java.json.gz; the underwriter is the seed "sweep/underwriter", "@u" its public key) and disputes from settlement records
/// (test-data/ref-core-research-java.json.gz; the guardian is the seed "research/guardian", "@g" its public key). A non-finite number is {"$num": text}.</summary>
public class RefReputationTests
{
    const string R = "ref-reputation", Sweep = "ref-core-sweep-java", Research = "ref-core-research-java";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    static readonly EdKey Underwriter = EdKey.FromSeed(Seed("sweep/underwriter"));
    static readonly EdKey Guardian = EdKey.FromSeed(Seed("research/guardian"));

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    [Fact] public void Constants() => Base.Check(R, "constants", _ => Reputation.Constants());
    [Fact] public void ValidateReputationInput() => Base.Check(R, "validateReputationInput", a => Reputation.Validate(Nums(a[0])), min: 38);
    [Fact] public void ReputationEdges() => Base.Check(R, "reputation", a => Reputation.Score(Nums(a[0])), min: 46);

    [Fact] public void ReputationSweep() => Base.Check(Sweep, "reputation", a => Reputation.Score(Nums(a[0])), min: 48);
    [Fact] public void PriceCoverage() => Base.Check(Sweep, "priceCoverage", a => Reputation.PriceCoverage(Nums(a[0]), Nums(a[1]), a.Count > 2 ? a[2] : null), min: 226);
    [Fact] public void IssueCoverageQuote() => Base.Check(Sweep, "issueCoverageQuote", a => Reputation.IssueCoverageQuote(Nums(a[0]), Nums(a[1]), Underwriter.Seed, Nums(a[2]), Nums(a[3]), a.Count > 4 ? a[4] : null), min: 43);

    [Fact]
    public void VerifyCoverageQuote() => Base.Check(Sweep, "verifyCoverageQuote",
        a => Reputation.VerifyCoverageQuote(a[0], a[1] is "@u" ? Underwriter.Id : a[1], a[2] == null ? double.NaN : a[2]), min: 27);

    [Fact]
    public void DisputesFromSettlements() => Base.Check(Research, "disputesFromSettlements", a =>
    {
        var map = (D)a[2]!;
        return Reputation.DisputesFromSettlements(a[0], a[1] is "@g" ? Guardian.Id : (string)a[1]!, id => map.GetValueOrDefault(id) as string);
    }, min: 42);

    static double Dn(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    // the capital pool script: "new" (initial capital), "collect" / "quote" (reputation, exposure, opts), "pay", "canCover", "state"; a throwing operation reads {"$err": "Error"}
    [Fact]
    public void CapitalPool() => Base.Check(Sweep, "pool", a =>
    {
        InsuranceCapitalPool? pool = null;
        var res = new L();
        foreach (var o in (L)a[0]!)
        {
            var op = (L)o!;
            try
            {
                switch ((string)op[0]!)
                {
                    case "new": pool = new InsuranceCapitalPool(Dn(op[1]), (rep, exposure, opts) => Reputation.PriceCoverage(Nums(rep), exposure, opts)); res.Add(pool.State().ToJson()); break;
                    case "collect": res.Add(pool!.CollectPremium(Nums(op[1]), Dn(op[2]), op[3] as D)); break;
                    case "quote": res.Add(pool!.Quote(Nums(op[1]), Dn(op[2]), op[3] as D)); break;
                    case "state": res.Add(pool!.State().ToJson()); break;
                    case "canCover": res.Add(pool!.CanCover(Dn(op[1]))); break;
                    case "pay": res.Add(pool!.PayClaim(Dn(op[1])).ToJson()); break;
                    default: throw new InvalidOperationException("op " + op[0]);
                }
            }
            catch (Exception) { res.Add(new D { ["$err"] = "Error" }); }
        }
        return res;
    }, min: 9);

    [Fact]
    public void Covers()
    {
        Base.Covers(R, new[] { "constants", "validateReputationInput", "reputation" });
        Assert.Equal(85, Base.Total(R));
    }
}
