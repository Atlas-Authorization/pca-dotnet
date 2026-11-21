using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of build provenance as a K1 discharge (test-data/k05-provgate.json.gz, TS reference
/// packages/pca/src/provenance-gate.ts). Byte arguments are base64url strings (decoded as Node's Buffer does).</summary>
public class K05ProvGateDiffTests
{
    const string M = "provgate";

    static byte[] Ub(object? s)
    {
        var t = ((string)s!).Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }

    [Fact] public void FactsError() => K05.Check(M, "provenanceFactsError", a => ProvenanceGate.ProvenanceFactsError(a[0]));
    [Fact] public void PolicyError() => K05.Check(M, "provenancePolicyError", a => ProvenanceGate.ProvenancePolicyError(a[0]));

    [Fact]
    public void Gate() => K05.Check(M, "provenanceGate", a =>
    {
        var r = ProvenanceGate.Gate(a[0]);
        return r.Ok ? new D { ["ok"] = true, ["level"] = r.Level, ["claims"] = r.Claims } : new D { ["ok"] = false, ["code"] = r.Code };
    });

    [Fact]
    public void Inclusion() => K05.Check(M, "verifyRfc9162Inclusion", a =>
        ProvenanceGate.VerifyRfc9162Inclusion(Ub(a[0]), K05.Long(a[1]), K05.Long(a[2]), ((L)a[3]!).Select(Ub).ToList(), Ub(a[4])));

    [Fact] public void LeafHash() => K05.Check(M, "rfc9162LeafHash", a => ProvenanceGate.Rfc9162LeafHash(Ub(a[0])));

    [Fact]
    public void Caveat() => K05.Check(M, "provenanceCaveat", a =>
    {
        var o = (D)a[0]!;
        string? S(string k) => o.GetValueOrDefault(k) as string;
        return ProvenanceGate.ProvenanceCaveat(new ProvenanceCaveatOptions(
            (string)o["issuer"]!, K05.Long(o["min_level"]), S("id"), S("source_repo"),
            o.GetValueOrDefault("builder_ids") is L b ? b.Select(x => (string)x!).ToList() : null, S("oidc_issuer"),
            o.GetValueOrDefault("require_runtime") as bool?, S("bind"), o.TryGetValue("ttl_ms", out var t) ? (long?)K05.Long(t) : null));
    });

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "provenanceFactsError", "provenancePolicyError", "provenanceGate", "verifyRfc9162Inclusion", "rfc9162LeafHash", "provenanceCaveat",
    });
}
