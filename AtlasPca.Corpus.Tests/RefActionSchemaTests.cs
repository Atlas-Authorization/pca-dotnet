using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the action schema surface (test-data/ref-action-schema.json.gz, 173 cases, and ref-action-schema-draft.json.gz, 104 cases): the exported constants, value-dependent reversibility, wallet floors, the verb
/// lookup, signing under three suites, the key entry, the digest, verification, the MCP annotation hints and the drafting importers (MCP tool lists and OpenAPI documents). A reference throw requires a refusal. The reasons of
/// verifyActionSchema are exact except the two families that carry the reference's own exception text (prefix only). Every fn has a handler and the totals are asserted.</summary>
public class RefActionSchemaTests
{
    const string M = "ref-action-schema";
    const string MD = "ref-action-schema-draft";

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

    static object? Sign(L a)
    {
        var (alg, keys) = Suite(a.Count > 3 ? a[3] : null);
        return ActionSchemaOps.SignActionSchema((D)Nums(a[0])!, (string)a[1]!, Base.Bytes(a[2]), alg, keys);
    }

    static object? KeyOf(L a)
    {
        var (alg, keys) = Suite(a.Count > 2 ? a[2] : null);
        return ActionSchemaOps.ActionSchemaKeyOf((string)a[0]!, Base.Bytes(a[1]), alg, keys);
    }

    static bool Same(D c, object? have)
    {
        var want = c["out"];
        if ((string)c["fn"]! == "verifyActionSchema" && want is D w && w.GetValueOrDefault("reason") is string wr && have is D h)
            foreach (var p in new[] { "schema verification error:", "malformed schema:" })
                if (wr.StartsWith(p, StringComparison.Ordinal)) return Equals(w["ok"], h.GetValueOrDefault("ok")) && h.GetValueOrDefault("reason") is string hr && hr.StartsWith(p, StringComparison.Ordinal);
        return Base.Show(want) == Base.Show(have);
    }

    static Dictionary<string, Func<L, object?>> Fns => new()
    {
        ["constants"] = _ => ActionSchemaOps.Constants(),
        ["reversibilityOf"] = a => ActionSchemaOps.ReversibilityOf((D)Nums(a[0])!, (D)Nums(a[1])!),
        ["floorApplies"] = a => ActionSchemaOps.FloorApplies((string)a[0]!, a.Count > 1 ? a[1] as D : null),
        ["schemaVerb"] = a => ActionSchemaOps.SchemaVerb(Nums(a[0]), (string)a[1]!),
        ["signActionSchema"] = Sign,
        ["actionSchemaKeyOf"] = KeyOf,
        ["actionSchemaDigest"] = a => ActionSchemaOps.ActionSchemaDigest(Nums(a[0])),
        ["verifyActionSchema"] = a => ActionSchemaOps.VerifyActionSchema(Nums(a[0]), Nums(a[1])),
        ["reversibilityFromMcpHints"] = a => ActionSchemaOps.ReversibilityFromMcpHints(a.Count > 0 ? a[0] : null),
        ["draftSchemaFromMcpTools"] = a => ActionSchemaOps.DraftSchemaFromMcpTools(a[0], a[1]),
        ["draftSchemaFromOpenApi"] = a => ActionSchemaOps.DraftSchemaFromOpenApi(a[0], a[1]),
    };

    static void Fn(string module, string fn, int min) => Base.Check(module, fn, a => Base.Json(Fns[fn](a)), (c, have) => Same(c, have), null, min);

    [Fact] public void Constants() => Fn(M, "constants", 1);
    [Fact] public void ReversibilityOf() => Fn(M, "reversibilityOf", 20);
    [Fact] public void FloorApplies() => Fn(M, "floorApplies", 19);
    [Fact] public void SchemaVerb() => Fn(M, "schemaVerb", 9);
    [Fact] public void SignActionSchema() => Fn(M, "signActionSchema", 12);
    [Fact] public void ActionSchemaKeyOf() => Fn(M, "actionSchemaKeyOf", 6);
    [Fact] public void ActionSchemaDigest() => Fn(M, "actionSchemaDigest", 4);
    [Fact] public void VerifyActionSchema() => Fn(M, "verifyActionSchema", 30);
    [Fact] public void ReversibilityFromMcpHints() => Fn(M, "reversibilityFromMcpHints", 9);
    [Fact] public void DraftSchemaFromMcpTools() => Fn(M, "draftSchemaFromMcpTools", 31);
    [Fact] public void DraftSchemaFromOpenApi() => Fn(M, "draftSchemaFromOpenApi", 32);

    [Fact] public void DraftCorpusReversibilityOf() => Fn(MD, "reversibilityOf", 72);
    [Fact] public void DraftCorpusOpenApi() => Fn(MD, "draftSchemaFromOpenApi", 16);
    [Fact] public void DraftCorpusMcpHints() => Fn(MD, "reversibilityFromMcpHints", 9);
    [Fact] public void DraftCorpusSchemaVerb() => Fn(MD, "schemaVerb", 7);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(173, Base.Total(M));
        Assert.Equal(new Dictionary<string, int>
        {
            ["draftSchemaFromOpenApi"] = 32, ["draftSchemaFromMcpTools"] = 31, ["verifyActionSchema"] = 30, ["reversibilityOf"] = 20, ["floorApplies"] = 19, ["signActionSchema"] = 12, ["schemaVerb"] = 9,
            ["reversibilityFromMcpHints"] = 9, ["actionSchemaKeyOf"] = 6, ["actionSchemaDigest"] = 4, ["constants"] = 1,
        }, Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
        Base.Covers(MD, new[] { "reversibilityOf", "draftSchemaFromOpenApi", "reversibilityFromMcpHints", "schemaVerb" });
        Assert.Equal(104, Base.Total(MD));
        Assert.Equal(new Dictionary<string, int> { ["reversibilityOf"] = 72, ["draftSchemaFromOpenApi"] = 16, ["reversibilityFromMcpHints"] = 9, ["schemaVerb"] = 7 },
            Base.Cases(MD).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
    }
}
