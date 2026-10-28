using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Build provenance gates (track K9), replaying packages/pca/conformance/provenance-vectors.json (decided by the TypeScript reference).
public class ProvenanceVectorTests
{
    static List<object?> Table(string name) => L(D(Load("provenance-vectors.json")["primitives"])[name]);

    static void Same(object? want, object? got, object? name) =>
        Assert.True(IntentJs.JsonEquals(want, got), $"{name}");

    [Fact]
    public void MerkleInclusionMatchesTheReference()
    {
        var rows = Table("merkle_inclusion");
        Assert.Equal(44, rows.Count);
        foreach (var x in rows)
        {
            var v = D(x);
            var i = D(v["input"]);
            var ok = ProvenanceGate.VerifyRfc9162Inclusion(
                ProvenanceGate.Rfc9162LeafHash(Convert.FromHexString((string)i["leaf_hex"]!)),
                N(i["index"]),
                N(i["size"]),
                L(i["proof_hex"]).Select(h => Convert.FromHexString((string)h!)).ToList(),
                Convert.FromHexString((string)i["root_hex"]!));
            Same(v["expect"], new Dictionary<string, object?> { ["ok"] = ok }, v["name"]);
        }
    }

    [Fact]
    public void GateMatchesTheReference()
    {
        var rows = Table("gate");
        Assert.Equal(45, rows.Count);
        foreach (var x in rows)
        {
            var v = D(x);
            var r = ProvenanceGate.Gate(v["input"]);
            var got = r.Ok
                ? new Dictionary<string, object?> { ["ok"] = true, ["level"] = r.Level, ["claims"] = r.Claims }
                : new Dictionary<string, object?> { ["ok"] = false, ["code"] = r.Code };
            Same(v["expect"], got, v["name"]);
        }
    }

    [Fact]
    public void ModelPathMatchesTheReference()
    {
        var rows = Table("model_path");
        Assert.Equal(7, rows.Count);
        foreach (var x in rows)
        {
            var v = D(x);
            Same(v["expect"], new Dictionary<string, object?> { ["model"] = PcaDecision.IsModelDerivedPath(D(v["input"])["path"]) }, v["name"]);
        }
    }

    [Fact]
    public void CaveatDefaultsAndOrder()
    {
        var c = ProvenanceGate.ProvenanceCaveat(new ProvenanceCaveatOptions("slsa", 3, SourceRepo: "r"));
        Same(Pca.ParseJson("""{"type":"needs_discharge","id":"provenance","issuer":"slsa","issuer_class":"artifact","bind":"action","ttl_ms":300000,"require":[{"claim":"slsa_level","op":"gte","value":3},{"claim":"source_repo","op":"eq","value":"r"},{"claim":"runtime_bound","op":"eq","value":true}]}"""), c, "defaults");
        Assert.Equal(new[] { "type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require" }, c.Keys.ToArray());
        Assert.Null(CaveatLang.NeedsDischargeError(c));
        var all = ProvenanceGate.ProvenanceCaveat(new ProvenanceCaveatOptions("slsa", 2, Id: "prov", BuilderIds: new[] { "b" }, OidcIssuer: "i", RequireRuntime: false, Bind: "chain_hop", TtlMs: 1000));
        Same(Pca.ParseJson("""[{"claim":"slsa_level","op":"gte","value":2},{"claim":"builder_id","op":"in","value":["b"]},{"claim":"oidc_issuer","op":"eq","value":"i"}]"""), all["require"], "require");
        Assert.Equal(new object?[] { "prov", "chain_hop", 1000L }, new[] { all["id"], all["bind"], all["ttl_ms"] });
    }
}
