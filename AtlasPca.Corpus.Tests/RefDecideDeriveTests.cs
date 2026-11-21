using AtlasPca.Authzen;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the derivation of the Policy VM decision input from a PCActn and the verifier's context, alone and followed by the decision
/// (test-data/ref-decide-derive.json.gz, 112 cases each). A context without the verifier's own stored grant is refused with the code <c>grant_required</c>.</summary>
public class RefDecideDeriveTests
{
    const string M = "ref-decide-derive";

    [Fact] public void DeriveDecideInput() => Base.Check(M, "deriveDecideInput", a => PolicyVmDecide.DeriveDecideInput(a[0], a[1]), min: 112);

    [Fact]
    public void DeriveThenDecide() => Base.Check(M, "deriveThenDecide", a =>
    {
        var input = PolicyVmDecide.DeriveDecideInput(a[0], a[1]);
        return new D { ["input"] = input, ["decision"] = PolicyVmDecide.Decide(input) };
    }, min: 112);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "deriveDecideInput", "deriveThenDecide" });
        Assert.Equal(240, Base.Cases(M).Count);
    }
}
