using AtlasPca;
using AtlasPca.Connectors;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the seeded connector provider catalog (test-data/ref-connectors-providers.json.gz, 40 cases): each of the 15 provider manifests by name (the manifest itself, its digest, that it validates), the
/// structural invariants every built-in holds, the built-in order (part of the contract for display) with the catalog digest, and ids outside the catalog, which are never found. Every fn has a handler and the
/// totals are asserted.</summary>
public class RefConnectorsProvidersTests
{
    const string M = "ref-connectors-providers";
    static readonly string[] Names = ["google", "github", "slack", "notion", "hubspot", "atlassian", "salesforce", "microsoft", "shopify", "snowflake", "linear", "zoom", "stripe", "dropbox", "airtable"];

    static D Builtin(string id) => ConnectorProviders.BuiltinManifests().Cast<D>().First(m => (string)m["id"]! == id);

    static object? Provider(L a)
    {
        var m = Builtin((string)a[0]!);
        return new D { ["manifest"] = m, ["digest"] = PcaConnectors.ManifestDigest(m), ["valid"] = PcaConnectors.ValidateManifest(m)["ok"] is true };
    }

    static object? Invariants(L a)
    {
        var id = (string)a[0]!;
        var m = Builtin(id);
        var available = ((L)m["scopesAvailable"]!).Cast<string>().ToList();
        return new D
        {
            ["defaultScopesSubset"] = ((L)m["defaultScopes"]!).Cast<string>().All(available.Contains), ["scopesUnique"] = available.Distinct().Count() == available.Count,
            ["idMatchesKey"] = (string)m["id"]! == id, ["httpsEndpoints"] = new[] { (string)m["authorizeUrl"]!, (string)m["tokenUrl"]! }.All(u => u.StartsWith("https://", StringComparison.Ordinal)),
        };
    }

    static object? Builtins()
    {
        var all = ConnectorProviders.BuiltinManifests().Cast<D>().ToList();
        return new D
        {
            ["ids"] = all.Select(m => m["id"]).ToList(), ["digests"] = all.Select(m => (object?)PcaConnectors.ManifestDigest(m)).ToList(), ["catalogDigest"] = PcaConnectors.CatalogDigest(),
        };
    }

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), null, null, min);

    [Fact] public void ProviderManifests() => Fn("provider", Provider, 15);
    [Fact] public void ProviderInvariants() => Fn("invariants", Invariants, 15);
    [Fact] public void BuiltinManifestOrder() => Fn("builtinManifests", _ => Builtins(), 1);
    [Fact] public void UnknownProviderIds() => Fn("unknownProvider", a => new D { ["found"] = PcaConnectors.GetProvider((string)a[0]!) != null }, 9);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "provider", "invariants", "builtinManifests", "unknownProvider" });
        Assert.Equal(40, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int> { ["provider"] = 15, ["invariants"] = 15, ["builtinManifests"] = 1, ["unknownProvider"] = 9 }, counts);
        Assert.Equal(Names, Base.Cases(M).Where(c => (string)c["fn"]! == "provider").Select(c => (string)Base.Args(c)[0]!).ToArray());
        Assert.Equal(Names.OrderBy(x => x), ConnectorProviders.BuiltinManifests().Cast<D>().Select(m => (string)m["id"]!).OrderBy(x => x));
    }
}
