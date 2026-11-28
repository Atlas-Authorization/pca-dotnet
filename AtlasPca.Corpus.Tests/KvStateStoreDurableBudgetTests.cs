using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The state store over a durable state directory, whose values are JSON documents: the claim counter and the trust budget both persist and compare-and-set.</summary>
public class KvStateStoreDurableBudgetTests
{
    [Fact]
    public void TheTrustBudgetPersistsAndCompareAndSetsOverTheDurableState()
    {
        var dir = Directory.CreateTempSubdirectory("pca-kv-budget-").FullName;
        try
        {
            var s = new KvStateStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir }));
            Assert.Null(s.Budget("g"));
            var b1 = new TrustBudget(0.9045000000000001, 1_700_000_000_000, 1_700_000_000_000);
            var b2 = new TrustBudget(0.5, 1_700_000_000_000, null);
            Assert.True(s.BudgetCas("g", null, b1));
            Assert.Equal(b1, s.Budget("g"));
            Assert.False(s.BudgetCas("g", null, b2)); // the stored budget is no longer absent
            Assert.True(s.BudgetCas("g", b1, b2));
            Assert.Equal(b2, new KvStateStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir })).Budget("g")); // a new handle reads it back
            Assert.True(s.Claim("g:h", 3)!.Ok);
            Assert.False(s.Claim("g:h", 3)!.Ok);
        }
        finally { try { Directory.Delete(dir, true); } catch (Exception) { } }
    }
}
