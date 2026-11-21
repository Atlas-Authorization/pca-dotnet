using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class PolicyLinkTemplatesTests
{
    static JD Def() => (JD)Pca.ParseJson(
        "{\"v\":1,\"kind\":\"pca-policy-template\",\"id\":\"refunds\",\"version\":\"1\",\"slots\":{\"cap\":{\"type\":\"integer\",\"min\":1,\"max\":1000}},"
        + "\"body\":{\"predicates\":[{\"verb\":\"stripe.refund\",\"resource\":\"*\",\"where\":{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":{\"$slot\":\"cap\"}}}]}}")!;

    [Fact]
    public void LinkCarriesSlotsOrOnlyTheirDigest()
    {
        var def = Def();
        Assert.Null(PolicyAuthoring.TemplateDefError(def));
        var slots = new JD { ["cap"] = new Num("500") };
        var link = PolicyAuthoring.CreateLink(def, slots);
        Assert.Equal("refunds", link["template_id"]);
        Assert.Equal(PolicyAuthoring.TemplateDigest(def), link["version_digest"]);
        Assert.Equal(Pca.Canonicalize(slots), Pca.Canonicalize(link["slots"]));
        Assert.Null(PolicyAuthoring.TemplateRefError(link));
        var bound = PolicyAuthoring.CreateLink(def, slots, bindParams: true);
        Assert.Equal(PolicyAuthoring.SlotsDigest(slots), bound["bind_params_digest"]);
        Assert.False(bound.ContainsKey("slots"));
        Assert.Null(PolicyAuthoring.TemplateRefError(bound));
        Assert.NotEqual(PolicyAuthoring.LinkDigest(link), PolicyAuthoring.LinkDigest(bound));
        Assert.Throws<ArgumentException>(() => PolicyAuthoring.CreateLink(def, new JD { ["cap"] = new Num("5000") })); // above the slot's maximum
    }

    [Fact]
    public void RoleTemplatesAndTheBuilder()
    {
        Assert.Equal(new[] { "read-only", "support-agent", "finance-bot", "dev-assistant" }, PolicyTemplates.ListTemplates().Select(t => t.Name));
        Assert.Throws<ArgumentException>(() => PolicyTemplates.FromTemplate("nope", new FromTemplateOptions()));
        Assert.Throws<ArgumentException>(() => PolicyBuilder.From("nope"));
        Assert.Throws<InvalidOperationException>(() => new PolicyBuilder().Build());
        var b = PolicyBuilder.From("finance-bot").Allow("stripe", "refund", "void").Allow("stripe", "void").Limit("refund", "$100/day").Build();
        Assert.Equal(new[] { "refund", "void" }, ((JL)b.Permissions["stripe"]!).Cast<string>());
        Assert.Equal("$100/day", b.Limits["refund"]);
        Assert.Null(b.RiskPolicy);
        var r = new PolicyBuilder().Allow("a", "x").Risk(new JD { ["kappa"] = new Num("2") }).Build();
        Assert.Equal("2", ((Num)r.RiskPolicy!["kappa"]!).Raw);
    }
}
