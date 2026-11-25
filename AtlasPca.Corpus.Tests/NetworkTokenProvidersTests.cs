using AtlasPca.Payments;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class NetworkTokenProvidersTests
{
    sealed class Transport(Func<string, D, D> reply) : IPartnerTransport
    {
        public List<(string Path, D Body)> Calls { get; } = new();
        public Task<D> PostAsync(string path, D body) { Calls.Add((path, body)); return Task.FromResult(reply(path, body)); }
    }

    static D Limits() => new()
    {
        ["currency"] = "USD", ["perAuthorizationMax"] = new Num("5000"), ["totalMax"] = new Num("20000"), ["categories"] = new L { "5734" }, ["merchants"] = new L { "m1" },
    };

    static D Opts(D grant, byte[] seed) => new()
    {
        ["limits"] = Limits(), ["grant"] = grant, ["agentId"] = "agent-1", ["holderSecret"] = seed, ["holderPublic"] = EdKey.FromSeed(seed).Pub, ["issuerNonce"] = "0123456789abcdef0123",
    };

    [Fact]
    public async Task IssuanceCopiesTheRailLimitsAndBindsTheToken()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var grant = new D { ["id"] = "g1" };
        var t = new Transport((_, _) => new D { ["token_ref"] = "tok_abcdef123456" });
        var p = NetworkTokens.VisaIntelligentCommerceAdapter(t);
        Assert.Equal("visa_ic", p.Id);
        var (binding, controls) = await NetworkTokens.IssueBoundNetworkTokenAsync(p, Opts(grant, seed));
        Assert.Equal("/tokens", t.Calls[0].Path);
        var scope = (D)t.Calls[0].Body["instructions"]!;
        Assert.Equal("5000", ((Num)scope["per_authorization_max"]!).Raw);
        Assert.Same(controls["metadata"], t.Calls[0].Body["metadata"]);
        Assert.Equal("tok_abcdef123456", binding["token_ref"]);
        Assert.Null(NetworkTokens.VerifyNetworkTokenBinding(binding, new D { ["grant"] = grant, ["holder"] = EdKey.FromSeed(seed).Id, ["issuerNonce"] = "0123456789abcdef0123" }));
        Assert.Equal("mastercard_agent_pay", NetworkTokens.MastercardAgentPayAdapter(t).Id);
    }

    [Fact]
    public async Task RefusesAPanShapedReferenceAndSuspendsOnRevoke()
    {
        var bad = NetworkTokens.MastercardAgentPayAdapter(new Transport((_, _) => new D { ["token_ref"] = "4111111111111111" }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => NetworkTokens.IssueBoundNetworkTokenAsync(bad, Opts(new D { ["id"] = "g" }, Enumerable.Repeat((byte)1, 32).ToArray())));
        var t = new Transport((_, _) => new D());
        await NetworkTokens.SuspendOnRevokeAsync(NetworkTokens.VisaIntelligentCommerceAdapter(t), new D { ["token_ref"] = "tok/abc def" });
        Assert.Equal("/tokens/tok%2Fabc%20def/suspend", t.Calls[0].Path);
        Assert.Equal("grant_revoked", t.Calls[0].Body["reason"]);
    }
}
