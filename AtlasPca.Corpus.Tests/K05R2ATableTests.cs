using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// Round 2, agent A: constant tables pinned to the reference (packages/pca/src: refusal-help.ts, attest-amd-snp.ts, assurance.ts,
// server/require-pca.ts authnFailed, x509 curve and signature OIDs). Private tables are read by reflection and compared whole.
public class K05R2ATableTests
{
    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;

    // the library tables are per-access properties (some still fields): read either
    static object Field(Type t, string name) => (t.GetField(name, NP) is { } f ? f.GetValue(null) : t.GetProperty(name, NP)!.GetValue(null))!;

    [Fact]
    public void RefusalTableIsTheReferenceTable()
    {
        // SHA-256 over check US meaning US fix US docs, rows joined by LF, from explainRefusal(check) in refusal-help.ts
        var names = "authorize_config,authorize,operation,audience,replay,counter_format,plan_root_authorized,plan_state,revocation,validity,grant_ref,grant_ref_bound,policy,delegated_caveats,threshold,risk_inputs,chain,leaf_signature,wire,malformed,freshness,provenance_flow,undo_window,template".Split(',');
        var rows = names.Select(n => { var h = Refusals.Explain(n); return string.Join("\u001f", h.Check, h.Meaning, h.Fix, h.Docs); });
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", rows)))).ToLowerInvariant();
        Assert.Equal("8f1d792821720eeda711153bbe012c23feae224364cbb7173348fd9c8fdd5efd", hash);
    }

    [Fact]
    public void AuthnChecksAreTheReferenceList()
    {
        // require-pca.ts authnFailed, with the .NET name "chain" for cap_chain
        Assert.Equal(new[] { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref", "pq_pin" }, Pca.AuthnChecks.ToArray());
    }

    [Fact]
    public void AssuranceRankTablesAreTheReferenceTables()
    {
        var att = (Dictionary<string, int>)Field(typeof(Assurance), "AttRank");
        Assert.Equal(new Dictionary<string, int> { ["unknown"] = 0, ["software"] = 1, ["hardware"] = 2, ["multi_root"] = 3 }.OrderBy(x => x.Key), att.OrderBy(x => x.Key));
        var zk = (Dictionary<string, int>)Field(typeof(Assurance), "ZkRank");
        Assert.Equal(new Dictionary<string, int>
        {
            ["unknown"] = 0, ["attested_vm"] = 1, ["attested_vm_hw"] = 1, ["stark"] = 2, ["zkvm"] = 2, ["groth16"] = 3, ["policyvm_snark"] = 3,
        }.OrderBy(x => x.Key), zk.OrderBy(x => x.Key));
    }

    [Fact]
    public void AmdArkPinsAreTheReferencePins()
    {
        Assert.Equal(new Dictionary<string, string>
        {
            ["milan"] = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
            ["genoa"] = "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
            ["turin"] = "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
        }.OrderBy(x => x.Key), AmdVerifier.ArkSpkiSha384.OrderBy(x => x.Key));
    }

    [Fact]
    public void ProvenanceLevelsAreTheLattice()
    {
        Assert.Equal(new[] { "trusted", "first_party", "tool", "web", "agent" }, ArgProvenance.Levels);
    }

    [Fact]
    public void MediatorPinMembersAreClosed()
    {
        var pk = Pca.B64u(new byte[32]);
        Assert.True(ArgProvenance.IsMediatorPin(new Dictionary<string, object?> { ["mediator"] = "m", ["kid"] = "k", ["pk"] = pk }));
        Assert.True(ArgProvenance.IsMediatorPin(new Dictionary<string, object?> { ["mediator"] = "m", ["kid"] = "k", ["pk"] = pk, ["pq_pk"] = "x" }));
        foreach (var missing in new[] { "mediator", "kid", "pk" })
        {
            var d = new Dictionary<string, object?> { ["mediator"] = "m", ["kid"] = "k", ["pk"] = pk };
            d.Remove(missing);
            Assert.False(ArgProvenance.IsMediatorPin(d));
        }
        Assert.False(ArgProvenance.IsMediatorPin(new Dictionary<string, object?> { ["mediator"] = "m", ["kid"] = "k", ["pk"] = pk, ["extra"] = 1 }));
    }

    [Fact]
    public void CertCurveTableIsTheReferenceTable()
    {
        var t = (IDictionary)Field(typeof(AttestCerts), "Curves");
        var got = t.Keys.Cast<string>().OrderBy(k => k, StringComparer.Ordinal)
            .Select(k => { var v = (ITuple)t[k]!; return $"{k}={v[0]},{v[1]},{v[2]}"; }).ToArray();
        Assert.Equal(new[]
        {
            "1.2.840.10045.3.1.7=prime256v1,P-256,32", "1.3.132.0.33=secp224r1,P-224,28", "1.3.132.0.34=secp384r1,P-384,48", "1.3.132.0.35=secp521r1,P-521,66",
        }.OrderBy(k => k, StringComparer.Ordinal), got);
    }

    [Fact]
    public void CertSignatureHashTableIsTheReferenceTable()
    {
        var t = (Dictionary<string, string>)Field(typeof(AttestCerts), "SigHashes");
        Assert.Equal(new Dictionary<string, string>
        {
            ["1.2.840.10045.4.3.2"] = "SHA256", ["1.2.840.10045.4.3.3"] = "SHA384", ["1.2.840.10045.4.3.4"] = "SHA512",
            ["1.2.840.113549.1.1.11"] = "SHA256", ["1.2.840.113549.1.1.12"] = "SHA384", ["1.2.840.113549.1.1.13"] = "SHA512",
        }.OrderBy(x => x.Key, StringComparer.Ordinal), t.OrderBy(x => x.Key, StringComparer.Ordinal));
    }
}
