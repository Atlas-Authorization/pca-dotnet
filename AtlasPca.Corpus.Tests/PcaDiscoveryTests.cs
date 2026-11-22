using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class PcaDiscoveryTests
{
    static string Doc(string extra = "") =>
        "{\"audience\":\"ins_1\",\"pca_versions\":[2],\"signature_suites\":[\"ed25519\",\"ml-dsa-65\"],\"action_header\":\"PCA-Action\"" + extra + "}";

    [Fact]
    public void ParsesAndNarrows()
    {
        var d = PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson(Doc(",\"endpoints\":{\"stepup\":\"https://x/s\"},\"intent\":{\"versions\":[1,2],\"tiers\":{\"pay\":3}}")));
        Assert.Equal("ins_1", d["audience"]);
        Assert.True(PcaDiscovery.AcceptsSuite(d, "ml-dsa-65"));
        Assert.False(PcaDiscovery.AcceptsSuite(d, "less-cat1"));
        Assert.Equal(new L { new Num("1"), new Num("2") }, (L)((D)d["intent"]!)["versions"]!);
        Assert.Throws<ArgumentException>(() => PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson("{\"audience\":\"\"}")));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson(Doc(",\"intent\":{\"versions\":[3]}"))));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson(Doc(",\"intent\":{\"versions\":[1],\"tiers\":{\"pay\":5}}"))));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson(Doc(",\"intent\":{\"versions\":[1],\"x\":1}"))));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.ParseDiscoveryDocument(Pca.ParseJson(Doc(",\"obligations_supported\":[1]"))));
    }

    [Fact]
    public async Task FetchAppendsThePathAndRefusesNon2xx()
    {
        string? seen = null;
        var d = await PcaDiscovery.FetchDiscovery("https://api.example.com//", url => { seen = url; return Task.FromResult((true, 200, Doc())); });
        Assert.Equal("https://api.example.com/.well-known/pca-configuration", seen);
        Assert.Equal("ins_1", d["audience"]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => PcaDiscovery.FetchDiscovery("https://x", _ => Task.FromResult((false, 404, ""))));
    }

    [Fact]
    public void CollectObligationsAddsDutiesOnUndecidable()
    {
        L Rules(string when) => (L)Pca.ParseJson("[{\"id\":\"r1\",\"when\":" + when + ",\"obligations\":[{\"kind\":\"log\",\"params\":{\"sink\":\"audit\"}}]}]")!;
        var ctx = new D { ["action"] = new D { ["verb"] = "pay" } };
        var yes = Obligations.CollectObligations(Rules("{\"field\":\"action.verb\",\"op\":\"eq\",\"value\":\"pay\"}"), ctx);
        Assert.True(yes.Ok); Assert.Single(yes.Obligations);
        var no = Obligations.CollectObligations(Rules("{\"field\":\"action.verb\",\"op\":\"eq\",\"value\":\"read\"}"), ctx);
        Assert.True(no.Ok); Assert.Empty(no.Obligations);
        var unknown = Obligations.CollectObligations(Rules("{\"field\":\"env.missing\",\"op\":\"eq\",\"value\":\"x\"}"), ctx);
        Assert.Single(unknown.Obligations); // undecidable: the duty applies
        Assert.True(Obligations.CollectObligations(null, ctx).Ok);
        Assert.False(Obligations.CollectObligations("x", ctx).Ok);
        Assert.False(Obligations.CollectObligations(Pca.ParseJson("[{\"id\":\"a\",\"when\":{},\"obligations\":[]}]"), ctx).Ok);
    }
}
