using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The compact mesh proof's layout on unusual evidence, as the TypeScript reference (mesh.ts assembleMeshProof) builds it:
/// entries dedupe by canonical JSON, absent members stay absent (a present null is kept), JS-falsy bracketing leaves and bindings are
/// dropped, cosignatures merge by witness (a non-object one has none, a null one is refused) and head cosigs must be an array.</summary>
public class MeshProofParityTests
{
    static JD Keys => D(Load("producer-vectors.json")["keys"]);
    static JD J(string json) => D(Pca.ParseJson(json));

    static JD Assemble(params string[] hops) =>
        Signers.AssembleMeshProof(new List<JD> { J("""{"id":"c0"}""") }, hops.Select(J).ToList(), J("""{"verb":"read"}"""),
            EdKey.FromSeed(Pca.B64uDecode(D(Keys["agent"])["seed"], 32)!));

    static void Is(string want, object? got) => Assert.Equal(Pca.Canonicalize(Pca.ParseJson(want)), Pca.Canonicalize(got));
    static string Refusal(params string[] hops) => Assert.Throws<ArgumentException>(() => Assemble(hops)).Message;

    static string Hop(string cosigs) =>
        """{"domain":"d","head":{"head":1,"sig":"s","cosigs":""" + cosigs + """},"inclusion":{},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}""";

    [Fact]
    public void HeadsAndLeavesDedupeByCanonicalJson()
    {
        var p = Assemble(
            """{"domain":"d","head":{"head":{"a":1,"b":3},"sig":"s","cosigs":[{"witness":"w1"}]},"inclusion":{},"revocation":{"cap":{"size":2,"lo":{"id":"x","n":3},"hi":0},"issuer_key":{"size":2,"lo":"","hi":false}},"binding":false}""",
            """{"domain":"d","head":{"head":{"b":3,"a":1},"sig":"s","cosigs":[{"witness":"w2"}]},"inclusion":{},"revocation":{"cap":{"size":2},"issuer_key":{"size":2,"hi":{"n":3,"id":"x"}}},"binding":{"k":1}}""");
        Is("""[{"head":{"a":1,"b":3},"sig":"s","cosigs":[{"witness":"w1"},{"witness":"w2"}]}]""", p["heads"]);
        Is("""[{"id":"x","n":3}]""", p["rev_leaves"]);
        Is("""[{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{"size":2,"lo":0},"issuer_key":{"size":2}}},""" +
           """{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{"size":2},"issuer_key":{"size":2,"hi":0}},"binding":{"k":1}}]""", p["hops"]);
    }

    [Fact]
    public void AbsentMembersStayAbsentAndNullsAreKept()
    {
        var p = Assemble("""{"head":{"cosigs":[]},"revocation":{"cap":{},"issuer_key":{"size":1}}}""");
        Is("""[{"cosigs":[]}]""", p["heads"]);
        Is("""[{"head":0,"revocation":{"cap":{},"issuer_key":{"size":1}}}]""", p["hops"]);
        p = Assemble("""{"domain":null,"inclusion":null,"head":{"head":null,"sig":null,"cosigs":[]},"revocation":{"cap":{"size":null},"issuer_key":{}}}""");
        Is("""[{"head":null,"sig":null,"cosigs":[]}]""", p["heads"]);
        Is("""[{"domain":null,"head":0,"inclusion":null,"revocation":{"cap":{"size":null},"issuer_key":{}}}]""", p["hops"]);
        // a non-object bracketing side has no size or leaves, as a property read on a primitive in the reference
        p = Assemble("""{"head":{"cosigs":[]},"revocation":{"cap":5,"issuer_key":"ab"}}""");
        Is("""[{"head":0,"revocation":{"cap":{},"issuer_key":{}}}]""", p["hops"]);
    }

    [Fact]
    public void CosignaturesMergeByWitness()
    {
        // a non-object cosignature and a witness-less one both read as undefined; an explicit null witness is a different value
        Is("""[{"head":1,"sig":"s","cosigs":["junk"]}]""", Assemble(Hop("""["junk"]"""), Hop("""[{"sig":"z"},5]"""))["heads"]);
        Is("""[{"head":1,"sig":"s","cosigs":[{"witness":null},{"sig":"z"},7]}]""", Assemble(Hop("""[{"witness":null}]"""), Hop("""[{"sig":"z"},7]"""))["heads"]);
        Is("""[{"head":1,"sig":"s","cosigs":[{"sig":"z"},{"witness":null}]}]""", Assemble(Hop("""[{"sig":"z"}]"""), Hop("""[5,{"witness":null}]"""))["heads"]);
        Is("""[{"head":1,"sig":"s","cosigs":[{"witness":"w1"},{"witness":"w2"}]}]""",
            Assemble(Hop("""[{"witness":"w1"}]"""), Hop("""[{"witness":"w1","sig":"q"},{"witness":"w2"}]"""))["heads"]);
        // a null cosignature is copied on first sight and refused once a merge reads its witness
        Is("""[{"head":1,"sig":"s","cosigs":[null]}]""", Assemble(Hop("[null]"))["heads"]);
        Assert.Equal("assembleMeshProof: a cosignature is null", Refusal(Hop("[null]"), Hop("[]")));
        Assert.Equal("assembleMeshProof: a cosignature is null", Refusal(Hop("[]"), Hop("[null]")));
    }

    [Fact]
    public void HeadCosigsMustBeAnArray()
    {
        const string want = "assembleMeshProof: head cosigs must be an array";
        Assert.Equal(want, Refusal("""{"domain":"d","head":{"head":1,"sig":"s"},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}"""));
        // the reference spreads a string into its characters; refused here
        foreach (var bad in new[] { "null", "\"ab\"", "{}", "5" }) Assert.Equal(want, Refusal(Hop(bad)));
        Assert.Equal(want, Refusal(Hop("[]"), """{"domain":"d","head":{"head":1,"sig":"s"},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}"""));
    }
}
