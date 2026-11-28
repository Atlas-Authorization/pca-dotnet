using AtlasPca.Adapters;
using AtlasPca.Testing;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>RunAdapterAcceptance through a tiny in-process adapter built on Pca.Authorize: the matrix must equal the expected table; a fail-open adapter must not.</summary>
public class AdapterAcceptanceMatrixTests
{
    static Func<AcceptanceRequest, AcceptanceObservation> Harness(AcceptanceOptions options) => req =>
    {
        var opD = PcaTesting.AcceptanceOperation(new D { ["method"] = req.Method, ["url"] = req.Path, ["body"] = req.Body });
        if (opD == null) return new AcceptanceObservation(403, false);
        if (!req.Headers.TryGetValue(PcaAdapters.PcaHeader, out var h)) return new AcceptanceObservation(401, false);
        var text = Pca.DecodePcaHeader(h);
        if (text == null) return new AcceptanceObservation(401, false);
        object? bundle = null;
        if (req.Headers.TryGetValue(PcaAdapters.ProvHeader, out var ph) && Pca.DecodePcaHeader(ph) is { } pt) bundle = Pca.ParseStrict(pt);
        var op = new Operation((string)opD["verb"]!, (string)opD["resource"]!, opD["params"]);
        var r = Pca.Authorize(Pca.ParseStrict(text), options.ToInput(op, bundle));
        if (!r.Allow) return new AcceptanceObservation(r.Status is 401 or 403 ? r.Status : 403, false);
        return new AcceptanceObservation(200, true, r.Operation);
    };

    [Fact]
    public void TheAcceptanceMatrixEqualsTheExpectedTable()
    {
        var got = PcaTesting.RunAdapterAcceptance(o => Harness(o));
        Assert.Equal(Base.Show(PcaTesting.AdapterAcceptanceExpected()), Base.Show(got));
    }

    [Fact]
    public void AFailOpenAdapterDoesNotEqualTheTable()
    {
        var got = PcaTesting.RunAdapterAcceptance(o => req => new AcceptanceObservation(200, true));
        Assert.NotEqual(Base.Show(PcaTesting.AdapterAcceptanceExpected()), Base.Show(got));
    }
}
