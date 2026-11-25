using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback.</summary>
public class BaseClockTests
{
    [Fact]
    public void HeaderClockIsRead() =>
        Assert.Equal(1_700_000_000_000.0, Base.ClockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"clockMs\":1700000000000,\"cases\":["));

    [Fact]
    public void MissingHeaderClockFallsBack() =>
        Assert.Equal(Base.FallbackClockMs, Base.ClockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"cases\":["));

    [Fact]
    public void HeaderClockCasesAreRead()
    {
        var named = Base.ClockCasesOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"clockMs\":1700000000000,\"clockCases\":[\"f/a\",\"f/b\"],\"cases\":[");
        Assert.Equal(new[] { "f/a", "f/b" }, named.OrderBy(x => x, StringComparer.Ordinal).ToArray());
        Assert.Empty(Base.ClockCasesOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"cases\":["));
    }
}
