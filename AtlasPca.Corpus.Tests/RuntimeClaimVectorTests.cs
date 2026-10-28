using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Runtime-class claims, replaying packages/pca/conformance/runtime-claim-vectors.json (decided by the TypeScript reference).
public class RuntimeClaimVectorTests
{
    static List<string> Strs(object? o) => L(o).Select(x => (string)x!).ToList();

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("runtime-claim-vectors.json");
        var t = D(doc["trust"]);
        var pinned = Strs(t["pinnedAttestors"]);
        var ev = Strs(t["verifiedEvidenceDigests"]);
        var pd = (string)t["passportDigest"]!;
        var cases = L(doc["cases"]);
        Assert.True(cases.Count >= 8);
        foreach (var x in cases)
        {
            var c = D(x);
            Assert.True((string)c["expect"]! == RuntimeClaim.VerifiedClass(c["claim"], pinned, pd, ev, c["now"]), (string)c["name"]!);
        }
        var first = D(cases[0]);
        Assert.Equal("none", RuntimeClaim.VerifiedClass(first["claim"], new List<string>(), pd, ev, first["now"]));
        Assert.Equal("none", RuntimeClaim.VerifiedClass(first["claim"], pinned, pd, new List<string>(), first["now"]));
        Assert.Equal("none", RuntimeClaim.VerifiedClass(null, pinned, pd, ev, null));
    }
}
