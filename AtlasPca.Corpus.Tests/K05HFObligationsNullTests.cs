using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>A JSON null obligations value is not an absent one (obligations.ts: undefined is the empty list, null is "obligations must be an array").</summary>
public class K05HFObligationsNullTests
{
    const string NotArray = "obligations must be an array";
    static L Supported => new() { "log" };

    [Fact]
    public void ValidationRefusesNullAndAcceptsAbsent()
    {
        Assert.Equal(NotArray, Obligations.ObligationsError(null));
        Assert.Null(Obligations.ObligationsError(Obligations.Absent));
        Assert.Null(Obligations.ObligationsError(new L()));
    }

    [Fact]
    public void TheGateDeniesANullListAndAllowsAnAbsentOne()
    {
        var nul = Obligations.PepObligationGate("allow", false, null, Supported);
        Assert.Equal("deny", nul.Decision);
        Assert.Equal("malformed obligations: " + NotArray, nul.Reason);
        Assert.Empty(nul.Perform);
        var absent = Obligations.PepObligationGate("allow", false, Obligations.Absent, Supported);
        Assert.Equal("allow", absent.Decision);
        Assert.Empty(absent.Perform);
        Assert.Null(absent.Reason);
        // a deny passes through unchanged whatever the list (nothing is read)
        Assert.Equal("deny", Obligations.PepObligationGate("deny", false, null, Supported).Decision);
    }

    [Fact]
    public void TheOutcomeTreatsNullAsMalformedAndAbsentAsEmpty()
    {
        var nul = Obligations.Outcome(null, new L(), IntentJs.OfLong(5));
        Assert.Equal("escalate", nul.Outcome);
        Assert.Equal("obligation_unmet", nul.Status);
        Assert.Empty(nul.Overdue);
        var absent = Obligations.Outcome(Obligations.Absent, new L(), IntentJs.OfLong(5));
        Assert.Equal("ok", absent.Outcome);
        Assert.Null(absent.Status);
    }

    [Fact]
    public void MergeRefusesANullListAndMergesAnAbsentOneAsEmpty()
    {
        var nul = Obligations.Merge(new L { null });
        Assert.False(nul.Ok);
        Assert.Equal(NotArray, nul.Reason);
        var absent = Obligations.Merge(new L { Obligations.Absent, new L() });
        Assert.True(absent.Ok);
        Assert.Empty(absent.Obligations);
    }
}
