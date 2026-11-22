using System.Security.Cryptography;
using System.Text;
using AtlasPca.Evidence;
using AtlasPca.Scitt;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the reference vectors of the evidence bundle's SCITT signed statement (test-data/ref-evidence-statement.json.gz): the COSE bytes are deterministic (Ed25519).</summary>
public class RefEvidenceStatementTests
{
    const string M = "ref-evidence-statement";

    [Fact]
    public void EvidenceSignedStatement() => Base.Check(M, "evidenceSignedStatement", a =>
    {
        var spec = (D)a[1]!;
        // the corpus names the key by label, or (resolved by the loader) carries it as a seed
        var seed = spec.TryGetValue("label", out var lbl) ? SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)lbl!)) : Pca.B64uDecode(spec["seed"])!;
        var opts = new SignStatementOpts((string)spec["alg"]!, CoseKey.Ed25519Private(seed), (string)spec["issuer"]!, spec.GetValueOrDefault("subject") as string);
        return EvidenceScitt.EvidenceSignedStatement(a[0], opts);
    });

    [Fact] public void EveryFnHasATest() { Base.Covers(M, new[] { "evidenceSignedStatement" }); Assert.Equal(32, Base.Total(M)); }
}
