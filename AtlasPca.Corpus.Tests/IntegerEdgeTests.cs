using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

public class IntegerEdgeTests
{
    [Fact] public void LongMinValueIsRejectedAsUnsafeNotOverflow()
    {
        // Math.Abs(long.MinValue) throws OverflowException; the contract is the canonicalize InvalidOperationException.
        var e = Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(long.MinValue));
        Assert.Equal("canonicalize: unsafe integer", e.Message);
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(long.MaxValue));
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(-9007199254740992L));
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(9007199254740992L));
        Assert.Equal("9007199254740991", Pca.Canonicalize(9007199254740991L));
        Assert.Equal("-9007199254740991", Pca.Canonicalize(-9007199254740991L));
    }
}

public class ParserDepthTests
{
    [Fact] public void LenientParserCapsRecursionDepth()
    {
        Assert.NotNull(Pca.ParseJson(new string('[', 512) + new string(']', 512)));
        var e = Assert.Throws<StrictJsonException>(() => Pca.ParseJson(new string('[', 513) + new string(']', 513)));
        Assert.Contains("nesting too deep", e.Message);
        Assert.Throws<StrictJsonException>(() => Pca.ParseJson(string.Concat(Enumerable.Repeat("{\"a\":", 513)) + "1" + new string('}', 513)));
    }

    [Fact, Trait("Category", "Huge")] public void LenientParser_1M_Unterminated() =>
        Assert.Throws<StrictJsonException>(() => Pca.ParseJson(new string('[', 1_000_000)));

    [Fact] public void BoundedParserAndStrictBoundaries()
    {
        Assert.NotNull(Pca.ParseBounded(new string('[', 34) + new string(']', 34), 34));
        Assert.Throws<StrictJsonException>(() => Pca.ParseBounded(new string('[', 35) + new string(']', 35), 34));
        Assert.NotNull(Pca.ParseStrict(new string('[', 32) + new string(']', 32)));
        Assert.Throws<StrictJsonException>(() => Pca.ParseStrict(new string('[', 33) + new string(']', 33)));
    }

    [Fact, Trait("Category", "Huge")] public void StrictParser_200k_Unterminated() =>
        Assert.Throws<StrictJsonException>(() => Pca.ParseStrict(new string('[', 200_000)));
}
