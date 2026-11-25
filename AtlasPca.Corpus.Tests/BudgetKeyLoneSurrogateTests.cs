using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The budget key percent-encodes the audience as encodeURIComponent does: a lone surrogate throws (it must never fold to U+FFFD and share
/// the key of another audience) and the characters !*'() stay literal.</summary>
public class BudgetKeyLoneSurrogateTests
{
    static string Key(string aud) => Pca.BudgetKeyOf(aud, new D { ["id"] = "g1" }, "g1", new D());

    [Fact] public void ALoneSurrogateAudienceIsRefused()
    {
        Assert.Throws<FormatException>(() => Key("a\uD800b"));
        Assert.Throws<FormatException>(() => Key("a\uDC00b"));
    }

    [Fact] public void AudienceEncodingMatchesEncodeUriComponent() => Assert.Equal("aud:https%3A%2F%2Fx.test%2F(a)!*'~:g1::budget", Key("https://x.test/(a)!*'~"));
}
