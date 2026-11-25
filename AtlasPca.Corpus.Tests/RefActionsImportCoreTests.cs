using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers against the TypeScript reference.</summary>
public class RefActionsImportCoreTests
{
    const string M = "ref-actions-import-core";

    [Fact] public void TokensOf() => Base.Check(M, "tokensOf", a => ImportCommon.TokensOf(a[0]));
    [Fact] public void Humanize() => Base.Check(M, "humanize", a => ImportCommon.Humanize(a[0]));
    [Fact] public void VerbOf() => Base.Check(M, "verbOf", a => ImportCommon.VerbOf((string)a[0]!, a[1]));
    [Fact] public void AliasOf() => Base.Check(M, "aliasOf", a => ImportCommon.AliasOf(a[0], (string)a[1]!));
    [Fact] public void ParamSeg() => Base.Check(M, "paramSeg", a => ImportCommon.ParamSeg((string)a[0]!));
    [Fact] public void Clip() => Base.Check(M, "clip", a => ImportCommon.Clip(a[0], (int)Base.Long(a[1])));
    [Fact] public void Pointer() => Base.Check(M, "pointer", a => ImportCommon.Pointer(a[0], a[1]));
    [Fact] public void ResolveLimits() => Base.Check(M, "resolveLimits", a => ImportLimits.Resolve(a.Count > 0 ? a[0] : null).ToJson());
    [Fact] public void CheckParsed() => Base.Check(M, "checkParsed", a => ImportLimits.Resolve(a[1]).CheckParsed(a[0]));
    [Fact] public void TextSizeCheck() => Base.Check(M, "textSizeCheck", a => { ImportLimits.Resolve(a[1]).TextSizeCheck((string)a[0]!); return null; });
    [Fact] public void ImportOpenApi() => Base.Check(M, "importOpenApi", a => OpenApiImporter.ImportOpenApi(a[0], (D)a[1]!));
    [Fact] public void ImportMcp() => Base.Check(M, "importMcp", a => McpImporter.ImportMcp(a[0], (D)a[1]!));
    [Fact] public void ImportJsonSchema() => Base.Check(M, "importJsonSchema", a => JsonSchemaImporter.ImportJsonSchema(a[0], (D)a[1]!));
    [Fact] public void ImportAsyncApi() => Base.Check(M, "importAsyncApi", a => AsyncApiImporter.ImportAsyncApi(a[0], (D)a[1]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "tokensOf", "humanize", "verbOf", "aliasOf", "paramSeg", "clip", "pointer", "resolveLimits", "checkParsed", "textSizeCheck",
        "importOpenApi", "importMcp", "importJsonSchema", "importAsyncApi" }); Assert.Equal(1267, Base.Total(M)); }
}
