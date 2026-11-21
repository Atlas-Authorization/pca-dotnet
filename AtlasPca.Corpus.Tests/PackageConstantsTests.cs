using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class PackageConstantsTests
{
    [Fact]
    public void ValuesAndCoreTables()
    {
        Assert.Equal(402, PackageConstants.X402HttpStatus["failed"]);
        Assert.Equal(86_400_000, PackageConstants.RatePeriods["day"]);
        Assert.Equal(PackageConstants.HybridPqAlg, "ml-dsa-65");
        Assert.Equal(3, PackageConstants.EscMax);
        Assert.Equal(22, Actions.CoreTraitIds.Count);
        Assert.Equal("pca.money_moving", Actions.CoreTraitIds[0]);
        Assert.Equal(22, Actions.CoreTraitDefs.Count);
        Assert.Equal("critical", Actions.RoleSensitivityFloor["money.amount"]);
        Assert.Equal("critical", Actions.TagSensitivityFloor["secret"]);
        Assert.Equal(2, Actions.SensitivityRank["critical"]);
        Assert.Equal(96, PackageConstants.AmdMilanArkSpkiSha384.Length);
    }

    [Fact]
    public void IdClassesAndBodies()
    {
        Assert.Contains("-", PackageConstants.IdClassChars["uuid"]);
        Assert.DoesNotContain("-", PackageConstants.IdClassChars["hex"]);
        Assert.Equal(62, PackageConstants.IdClassChars["alnum"].Count);
        Assert.Equal(new[] { "challenge", "grant", "nonce" }, PackageConstants.StepUpMessage("g", "c", "n").Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("3", ((Num)PackageConstants.NeedRequestMessage("g", 3, new JL())["rev"]!).Raw);
    }
}

public class JoseCanonicalExtrasTests
{
    static string B(string json) => Pca.B64u(System.Text.Encoding.UTF8.GetBytes(json));

    [Fact]
    public void GateAndSegments()
    {
        var tok = B("{\"alg\":\"EdDSA\"}") + "." + B("{\"a\":1}") + "." + Pca.B64u(new byte[64]);
        Assert.True(AtlasPca.Jose.Jose.IsCanonicalCompactJws(tok));
        Assert.False(AtlasPca.Jose.Jose.IsCanonicalCompactJws(tok + "="));
        Assert.False(AtlasPca.Jose.Jose.IsCanonicalCompactJws(null));
        Assert.False(AtlasPca.Jose.Jose.IsCanonicalCompactJws(" " + tok));
        var h = AtlasPca.Jose.Jose.AssertCanonicalJwsSegments(B("{\"alg\":\"EdDSA\"}"), Pca.B64u(new byte[64]));
        Assert.Equal("EdDSA", h["alg"]);
        Assert.Equal("empty-segment", Assert.Throws<AtlasPca.Jose.CanonicalJwsException>(() => AtlasPca.Jose.Jose.AssertCanonicalJwsSegments("", "x")).Reason);
        Assert.Equal("not-a-string", Assert.Throws<AtlasPca.Jose.CanonicalJwsException>(() => AtlasPca.Jose.Jose.AssertCanonicalJwsSegments(1, "x")).Reason);
    }
}
