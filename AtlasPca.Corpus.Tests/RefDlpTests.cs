using AtlasPca.Research;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The data-flow governance (DLP) evaluation against the TypeScript reference.</summary>
public class RefDlpTests
{
    const string M = "ref-dlp";

    [Fact] public void EvaluateDlp() => Base.Check(M, "evaluateDlp", a => Dlp.EvaluateDlp(a[0] as D, (D)a[1]!), min: 1000);
    [Fact] public void DefaultDlpPolicy() => Base.Check(M, "defaultDlpPolicy", a => Dlp.DefaultDlpPolicy(a.Count > 0 ? a[0] as D ?? (a[0] == null ? throw new ArgumentException("opts is null") : new D()) : null));

    [Fact] public void Covers() { Base.Covers(M, new[] { "evaluateDlp", "defaultDlpPolicy" }); Assert.Equal(5444, Base.Total(M)); }
}
