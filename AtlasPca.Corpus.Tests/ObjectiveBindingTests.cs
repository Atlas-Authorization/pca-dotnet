using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The binding of the objective risk to a grant: nothing committed is "none"; a commitment the instance reproduces is "objective"; every way of not reproducing it is a "mismatch" that is
/// denied unless the grant asks for the heuristic AND the instance opts in.</summary>
public class ObjectiveBindingTests
{
    static readonly D Action = new() { ["verb"] = "read", ["resource"] = "doc:1" };

    // the envelope is read, not verified: a hand-built grant carries one caveat of the envelope kind
    static D GrantWith(D? objectiveRisk)
    {
        var env = new D
        {
            ["type"] = Issue.EnvelopeCaveat, ["goal_commit"] = "g", ["predicates"] = new L(), ["caveats"] = new L(), ["agent_binding"] = new D(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
        };
        if (objectiveRisk != null) env["objective_risk"] = objectiveRisk;
        return new D { ["caveats"] = new L { env } };
    }

    static D Instance() => new()
    {
        ["registry"] = new D { ["trusted_verifiers"] = new L(), ["entries"] = new L() },
        ["graph"] = new D { ["nodes"] = new L { new D { ["id"] = "doc:1" } }, ["edges"] = new L() },
    };

    static D Commitment(string? onMismatch = null)
    {
        var emb = ObjectiveRisk.NativeEmbedder(null);
        var graph = new ResourceGraph().AddNode(new D { ["id"] = "doc:1" });
        var c = new D
        {
            ["v"] = 1L,
            ["embedder"] = new D { ["scheme"] = "native", ["model_id"] = emb.ModelId, ["config"] = ObjectiveRisk.DefaultNativeConfig() },
            ["goal"] = ObjectiveRisk.CommitGoal(emb, Action),
            ["registry_digest"] = new InMemoryInverseRegistry().Digest(),
            ["graph_digest"] = graph.Digest(),
            ["authorized_kinds"] = new L(),
        };
        if (onMismatch != null) c["on_mismatch"] = onMismatch;
        return c;
    }

    [Fact]
    public void NothingCommittedIsNone() => Assert.Equal("none", ObjectiveBinding.ResolveObjectiveRisk(GrantWith(null), Action, Instance())["mode"]);

    [Fact]
    public void AMalformedCommitmentIsADeniedMismatch()
    {
        var r = ObjectiveBinding.ResolveObjectiveRisk(GrantWith(new D { ["v"] = 2L }), Action, Instance());
        Assert.Equal("mismatch", r["mode"]);
        Assert.Equal("deny", r["onMismatch"]);
        Assert.Equal("objective_risk: unsupported shape/version", Assert.Single((L)r["reasons"]!));
    }

    [Fact]
    public void AReproducedCommitmentIsObjective()
    {
        var r = ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment()), Action, Instance());
        Assert.Equal("objective", r["mode"]);
        var inputs = (D)r["inputs"]!;
        Assert.Equal(new[] { "blastRadius", "reversibility", "semanticDistance" }, inputs.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.False(string.IsNullOrEmpty((string?)r["evidenceDigest"]));
    }

    [Fact]
    public void AnInstanceThatCannotReproduceTheDigestsIsAMismatch()
    {
        var other = Instance();
        ((D)other["graph"]!)["nodes"] = new L { new D { ["id"] = "doc:1" }, new D { ["id"] = "doc:2" } };
        var r = ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment()), Action, other);
        Assert.Equal("mismatch", r["mode"]);
        Assert.Contains("graph digest does not match the committed digest", ((L)r["reasons"]!).Cast<string>());
        Assert.Equal("mismatch", ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment()), Action, null)["mode"]);
    }

    [Fact]
    public void AGrantCannotAskForTheHeuristicOnItsOwn()
    {
        var other = Instance();
        ((D)other["graph"]!)["nodes"] = new L();
        Assert.Equal("deny", ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment("heuristic")), Action, other)["onMismatch"]);
        other["allow_heuristic_fallback"] = true;
        Assert.Equal("heuristic", ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment("heuristic")), Action, other)["onMismatch"]);
        Assert.Equal("deny", ObjectiveBinding.ResolveObjectiveRisk(GrantWith(Commitment("deny")), Action, other)["onMismatch"]);
    }
}
