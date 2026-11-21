using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the GraphQL and gRPC importers and their parsers against the TypeScript reference.</summary>
public class RefActionsImportSdlTests
{
    const string M = "ref-actions-import-sdl";
    static object? Src(object? a) => Base.IsBytes(a) ? Base.Bytes(a) : a;

    [Fact] public void ParseGraphqlSdl() => Base.Check(M, "parseGraphqlSdl", a => GraphqlImporter.ParseGraphqlSdl((string)a[0]!).ToJson());
    [Fact] public void FromIntrospection() => Base.Check(M, "fromIntrospection", a => GraphqlImporter.FromIntrospection(a[0]).ToJson());
    [Fact] public void ParseProto() => Base.Check(M, "parseProto", a => GrpcImporter.ParseProto((string)a[0]!).ToJson());
    [Fact] public void ParseDescriptorSet() => Base.Check(M, "parseDescriptorSet", a => GrpcImporter.ParseDescriptorSet(Base.Bytes(a[0])).ToJson());
    [Fact] public void ImportGraphql() => Base.Check(M, "importGraphql", a => GraphqlImporter.ImportGraphql(a[0], (D)a[1]!));
    [Fact] public void ImportGrpc() => Base.Check(M, "importGrpc", a => GrpcImporter.ImportGrpc(Src(a[0]), (D)a[1]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "parseGraphqlSdl", "fromIntrospection", "parseProto", "parseDescriptorSet", "importGraphql", "importGrpc" }); Assert.Equal(1033, Base.Total(M)); }
}
