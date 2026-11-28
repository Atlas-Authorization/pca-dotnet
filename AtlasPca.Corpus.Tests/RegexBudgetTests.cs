using Xunit;

namespace AtlasPca.Corpus.Tests;

public class RegexBudgetTests
{
    [Fact]
    public void DocumentBudgetCapsEvaluationsAndPoisonsAfterTheFirstRefusal()
    {
        var b = new RegexBudget();
        for (var i = 0; i < 64; i++) Assert.True(b.Charge("a" + i, 3));
        Assert.False(b.Charge("b", 3));
        Assert.False(b.Charge("c", 0)); // poisoned: even a cheaper pattern is refused now
        Assert.Equal(2, b.Refusals);
        Assert.False(new RegexBudget().Charge("(", 1)); // outside the subset: refused, counted
    }

    [Fact]
    public void RequestBudgetIsChargedByEveryDocumentInsideIt()
    {
        var req = RegexBudget.Request("client-1");
        var docs = Enumerable.Range(0, 5).Select(_ => new RegexBudget(1, req, true)).ToList();
        var ok = 0;
        foreach (var d in docs) for (var i = 0; i < 64; i++) if (d.Charge("x" + i, 1)) ok++;
        Assert.Equal(4 * 64, ok); // the request cap is RequestScale documents' worth
        Assert.False(req.IsDocument);
        Assert.Equal("client-1", req.Source);
        Assert.Same(req, docs[0].ParentBudget);
    }

    [Fact]
    public void RunInstallsTheScopeAndChargeRegexUsesIt()
    {
        var b = new RegexBudget();
        b.Run(() => { Assert.True(SafeRegex.ChargeRegex("a+", 2)); Assert.Equal(0, SafeRegex.RegexRefusals()); return 0; });
        Assert.Equal(1, b.Evaluations);
        Assert.Equal(0, SafeRegex.RegexRefusals()); // outside every scope
        // the ambient provider is the enclosing budget of a document opened with no scope
        var req = RegexBudget.Request();
        SafeRegex.SetRegexBudgetProvider(() => req);
        try { Assert.True(SafeRegex.ChargeRegex("z", 1)); Assert.Equal(1, req.Evaluations); }
        finally { SafeRegex.SetRegexBudgetProvider(null); }
    }

    [Fact]
    public void CacheIsLruAndASourceReplacesItsOwnOldestEntry()
    {
        var src = "tenant-A";
        RegexCache.SetSourceProvider(() => src);
        try
        {
            for (var i = 0; i < RegexCache.MaxPerSource + 5; i++) Assert.NotNull(SafeRegex.CompileCached("cache" + i + "x"));
            Assert.False(RegexCache.Has("cache0x"));                              // the source's own oldest entries were replaced
            Assert.True(RegexCache.Has("cache" + (RegexCache.MaxPerSource + 4) + "x"));
            Assert.Equal(RegexCache.MaxPerSource, RegexCache.Stats().BySource["tenant-A"]);
            Assert.Null(SafeRegex.CompileCached("(unclosed"));                    // a refusal verdict is cached too
            Assert.True(RegexCache.Has("(unclosed"));
        }
        finally { RegexCache.SetSourceProvider(null); }
    }
}
