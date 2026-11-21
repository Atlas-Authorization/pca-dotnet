using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The corpora other language lanes generated for the same functions are appended to the module's own cases (<see cref="Base.VariantCorpora"/>) and replayed by that
/// module's tests; here each one must be present and well formed, so a dropped file cannot silently shrink the replay.</summary>
public class VariantCorporaTests
{
    [Fact]
    public void EveryVariantCorpusIsPresentAndWellFormed()
    {
        int files = 0;
        foreach (var (module, variants) in Base.VariantCorpora)
            foreach (var v in variants)
            {
                files++;
                Assert.True(Base.Cases(v).Count > 0, $"{module}: variant corpus {v} has no cases");
            }
        Assert.Equal(12, files);
    }
}
