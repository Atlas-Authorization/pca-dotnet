using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the signing half of action pins (test-data/ref-action-pin.json.gz, 111 cases): the constants, signing a registry document and an evolution record under three suites, the registry key entry, the
/// principal's re-approval and the verify side over documents the oracle signs. A reference throw requires a refusal. Every fn has a handler and the totals are asserted.</summary>
public class RefActionPinTests
{
    const string M = "ref-action-pin";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static (string? Alg, SuiteSecretKeys? Keys) Suite(object? s)
    {
        if (s is not D d) return (null, null);
        return (d.GetValueOrDefault("alg") as string, d.GetValueOrDefault("pqSeed") is { } seed ? new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) } : null);
    }

    static Dictionary<string, Func<L, object?>> Fns => new()
    {
        ["constants"] = _ => ActionPinOps.Constants(),
        ["signRegistryDoc"] = a => { var (alg, keys) = Suite(a.Count > 4 ? a[4] : null); return ActionPinOps.SignRegistryDoc((string)a[0]!, Nums(a[1]), (string)a[2]!, Base.Bytes(a[3]), alg, keys); },
        ["signEvolutionRecord"] = a => { var (alg, keys) = Suite(a.Count > 3 ? a[3] : null); return ActionPinOps.SignEvolutionRecord((D)Nums(a[0])!, (string)a[1]!, Base.Bytes(a[2]), alg, keys); },
        ["registryKeyOf"] = a => { var (alg, keys) = Suite(a.Count > 2 ? a[2] : null); return ActionPinOps.RegistryKeyOf((string)a[0]!, Base.Bytes(a[1]), alg, keys); },
        ["signReapproval"] = a => { var o = (D)a[0]!; return ActionPinOps.SignReapproval((string)o["grantId"]!, (D)o["record"]!, Base.Bytes(o["principalSecret"])); },
        ["verifyRegistrySig"] = a => ActionPinOps.VerifyRegistrySig((string)a[0]!, (D)Nums(a[1])!, (D)Nums(a[2])!, Nums(a[3])),
        ["verifyEvolutionRecord"] = a => ActionPinOps.VerifyEvolutionRecord(Nums(a[0]), Nums(a[1])),
        ["reapprovalValid"] = a => Actions.ReapprovalValid(Nums(a[0]), a[1], a[2], a[3], a[4]),
    };

    static void Fn(string fn, int min) => Base.Check(M, fn, a => Base.Json(Fns[fn](a)), null, null, min);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void SignRegistryDoc() => Fn("signRegistryDoc", 20);
    [Fact] public void SignEvolutionRecord() => Fn("signEvolutionRecord", 33);
    [Fact] public void RegistryKeyOf() => Fn("registryKeyOf", 5);
    [Fact] public void SignReapproval() => Fn("signReapproval", 8);
    [Fact] public void VerifyRegistrySig() => Fn("verifyRegistrySig", 6);
    [Fact] public void VerifyEvolutionRecord() => Fn("verifyEvolutionRecord", 21);
    [Fact] public void ReapprovalValid() => Fn("reapprovalValid", 17);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(111, Base.Total(M));
        Assert.Equal(new Dictionary<string, int>
        {
            ["signEvolutionRecord"] = 33, ["verifyEvolutionRecord"] = 21, ["signRegistryDoc"] = 20, ["reapprovalValid"] = 17, ["signReapproval"] = 8, ["verifyRegistrySig"] = 6, ["registryKeyOf"] = 5, ["constants"] = 1,
        }, Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
    }
}
