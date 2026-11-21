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
}
