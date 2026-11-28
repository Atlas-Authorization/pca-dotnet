using AtlasPca.Schema;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the wire JSON Schemas and the structural validator (test-data/ref-schema-dotnet.json.gz, TS reference @atlasauth/pca-schema).
/// A string first argument names a published schema; an object is an ad-hoc schema.</summary>
public class RefSchemaTests
{
    const string M = "ref-schema-dotnet";

    static object? Pick(object? s) => s is string name
        ? name switch
        {
            "PCActn" => PcaSchema.PcactnSchema(),
            "Capability" => PcaSchema.CapabilitySchema(),
            "PcaDiscoveryDocument" => PcaSchema.DiscoverySchema(),
            _ => throw new ArgumentException("unknown schema " + name),
        }
        : s;

    [Fact] public void Schemas() => Base.Check(M, "schemas", _ => PcaSchema.AllSchemas());
    [Fact] public void Validate() => Base.Check(M, "validate", a => PcaSchema.Validate(Pick(a[0]), a[1]).ToJson());

    [Fact] public void AllFnsCovered() { Base.Covers(M, new[] { "schemas", "validate" }); Assert.Equal(3216, Base.Total(M)); }
}
