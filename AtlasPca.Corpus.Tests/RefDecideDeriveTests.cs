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
        // the corpus writes a non-finite number as {"$num"}: the decision runs on the number, and prints it the same way
        return new D { ["input"] = input, ["decision"] = Encode(PolicyVmDecide.Decide(Decode(input))) };
    }, min: 112);

    static object? Decode(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? (object?)double.NaN : s == "Infinity" ? (object?)double.PositiveInfinity : s == "-Infinity" ? (object?)double.NegativeInfinity : v,
        D m => m.ToDictionary(e => e.Key, e => Decode(e.Value)),
        List<object?> l => l.Select(Decode).ToList(),
        _ => v,
    };

    static object? Encode(object? v) => v switch
    {
        double d when !double.IsFinite(d) => new D { ["$num"] = double.IsNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Encode(e.Value)),
        List<object?> l => l.Select(Encode).ToList(),
        _ => v,
    };

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "deriveDecideInput", "deriveThenDecide" });
        Assert.Equal(240, Base.Cases(M).Count);
    }
}
