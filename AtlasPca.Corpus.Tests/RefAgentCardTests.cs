using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.A2aPkg;
using Xunit;
using Cards = AtlasPca.AgentCard.AgentCards;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the signed Agent Card / AgentFacts package against the TypeScript reference (test-data/ref-agentcard.json.gz).
/// A reason that quotes the JOSE library is compared up to the first colon, as the oracle does.</summary>
public class RefAgentCardTests
{
    const string M = "ref-agentcard";

    static string Fix(string s) => Regex.Replace(s, @"^(signature( \d+)? did not verify|could not resolve verification key): .*$", "$1", RegexOptions.Singleline);

    static D Norm(D r)
    {
        var c = new D(r);
        if (c.GetValueOrDefault("reason") is string reason) c["reason"] = Fix(reason);
        if (c.GetValueOrDefault("attestations") is L list)
            c["attestations"] = list.Select(a => a is D ad && ad.GetValueOrDefault("reason") is string rs ? new D(ad) { ["reason"] = Fix(rs) } : a).ToList();
        return c;
    }

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["DEFAULT_ALG"] = Cards.DefaultAlg,
        ["AGENT_FACTS_CONTEXT"] = Cards.AgentFactsContext.Cast<object?>().ToList(),
        ["PCA_ATTESTOR_ID"] = Cards.PcaAttestorId,
        ["WELL_KNOWN_AGENT_CARD_PATH"] = Cards.WellKnownAgentCardPath,
        ["WELL_KNOWN_AGENT_FACTS_PATH"] = Cards.WellKnownAgentFactsPath,
    });

    [Fact] public void JcsBytes() => Base.Check(M, "jcsBytes", a => Cards.JcsBytes(a[0]));
    [Fact] public void ValidateAgentCard1() => Base.Check(M, "validateAgentCard1", a => Cards.ValidateAgentCard1(a[0]));
    [Fact] public void BuildAgentCard() => Base.Check(M, "buildAgentCard", a => Cards.BuildAgentCard(a[0], (D)a[1]!));

    [Fact]
    public void IssueSignedAgentCard() => Base.Check(M, "issueSignedAgentCard", a =>
    {
        var io = new A2aPca.IssueOptions();
        if (a.Count > 2)
        {
            var o = (D)a[2]!;
            io.Alg = o.GetValueOrDefault("alg") as string;
            io.Kid = o.GetValueOrDefault("kid") as string;
            io.Profile = o.GetValueOrDefault("profile") as string;
            io.Schema = o.GetValueOrDefault("schema") as string;
            io.Passport = o.GetValueOrDefault("passport") as D;
        }
        return Cards.IssueSignedAgentCard(a[0], a[1], io);
    });

    [Fact]
    public void VerifyAgentCard() => Base.Check(M, "verifyAgentCard", a =>
    {
        var o = (D)a[1]!;
        var vo = new A2aPca.VerifyCardOptions
        {
            Jwks = o.GetValueOrDefault("jwks"), HasKey = o.ContainsKey("key"), Key = o.GetValueOrDefault("key"),
            Alg = o.GetValueOrDefault("alg") as string, Schema = o.GetValueOrDefault("schema") as string,
        };
        return Norm(Cards.VerifyAgentCard(a[0], vo));
    });

    [Fact] public void IssueAgentFacts() => Base.Check(M, "issueAgentFacts", a => Cards.IssueAgentFacts(a[0], (D)a[1]!));
    [Fact] public void AddAttestation() => Base.Check(M, "addAttestation", a => Cards.AddAttestation(a[0], (D)a[1]!));
    [Fact] public void VerifyAgentFacts() => Base.Check(M, "verifyAgentFacts", a => Norm(Cards.VerifyAgentFacts(a[0], (D)a[1]!)));

    static object? Serve(Cards.PathHandler h, object? req) =>
        req is L reqs ? reqs.Select(r => (object?)h((string)r!)).ToList() : h((string)req!);

    [Fact] public void AgentCardHandler() => Base.Check(M, "agentCardHandler", a => Serve(Cards.AgentCardHandler(a[0], a[1] as string), a[2]));
    [Fact] public void AgentFactsHandler() => Base.Check(M, "agentFactsHandler", a => Serve(Cards.AgentFactsHandler(a[0], a[1] as string), a[2]));
    [Fact] public void ToRegistryEntry() => Base.Check(M, "toRegistryEntry", a => Cards.ToRegistryEntry(a[0], a[1]));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "jcsBytes", "validateAgentCard1", "buildAgentCard", "issueSignedAgentCard", "verifyAgentCard", "issueAgentFacts", "addAttestation",
        "verifyAgentFacts", "agentCardHandler", "agentFactsHandler", "toRegistryEntry",
    }); Assert.Equal(449, Base.Total(M)); }
}
