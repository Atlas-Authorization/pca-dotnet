using AtlasPca.Rag;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the reference vectors of the retrieval filter (ACL extraction, policy compilation, principal derivation, the fail-closed filter and its decision digest).</summary>
public class RefRagTests
{
    const string M = "ref-rag";

    [Fact] public void AclsFromMetadata() => Base.Check(M, "aclsFromMetadata", a => RagFilter.AclsFromMetadata(a[0], a[1]));

    [Fact] public void CompilePolicy() => Base.Check(M, "compilePolicy", a => RagFilter.CompilePolicy(a[0]));

    [Fact] public void PrincipalFromPCActn() => Base.Check(M, "principalFromPCActn", a => RagFilter.PrincipalFromPCActn(a[0], a[1] as D));

    [Fact]
    public void FilterDocuments() => Base.Check(M, "filterDocuments", a =>
    {
        var r = RagFilter.FilterDocuments(a[0], a[1], a[2]);
        return new D { ["documents"] = r.Documents, ["decision"] = r.Decision };
    });

    [Fact]
    public void GroupAttributeAdmitsAndOthersDrop()
    {
        var pred = new D { ["verb"] = "can_view", ["where"] = new L { new D { ["field"] = "subject.group", ["op"] = "eq", ["value"] = "g1" } } };
        var doc = new D { ["id"] = "d", ["acl"] = new D { ["relation"] = "can_view", ["object"] = "document:d" } };
        var ok = new D { ["id"] = "u", ["attributes"] = new D { ["group"] = "g1" } };
        var no = new D { ["id"] = "u", ["attributes"] = new D { ["group"] = "g2" } };
        Assert.Equal("d", (string)((L)RagFilter.FilterDocuments(ok, new L { doc }, new L { pred }).Decision["allowedIds"]!)[0]!);
        Assert.Equal("d", (string)((L)RagFilter.FilterDocuments(no, new L { doc }, new L { pred }).Decision["droppedIds"]!)[0]!);
    }

    [Fact] public void Covers() { Base.Covers(M, new[] { "aclsFromMetadata", "compilePolicy", "principalFromPCActn", "filterDocuments" }); Assert.Equal(397, Base.Total(M)); }
}
