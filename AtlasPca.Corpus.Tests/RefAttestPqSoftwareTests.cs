using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the post-quantum software attestation root (test-data/ref-attest-pq-software.json.gz, 137 cases): statement minting under PQ and hybrid suites (byte-exact), attestor construction and the
/// verifier's scenarios and construction refusals. Keys are label seeds (an Ed25519 secret and the ML-DSA keygen seed); SLH-DSA statements are verify-only inputs. The case "wrong-key-family" gives ML-DSA-65 key
/// material to an ML-DSA-87 attestor (the corpus carries only the seed): each key is derived in the family of the label its seed came from. Every fn has a handler and the totals are asserted.</summary>
public class RefAttestPqSoftwareTests
{
    const string M = "ref-attest-pq-software";

    static byte[] B64(object? s) => Pca.B64uDecode(s) ?? throw new InvalidDataException("bad base64url");

    // the generator derives each key's seed from the label alg: seed -> the family of that label
    static readonly Dictionary<string, Pq.Prim> SeedFamily = Pq.RegisteredSuites
        .Where(a => Pq.Suites.TryGetValue(a, out var s) && s.Pq is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87)
        .ToDictionary(a => Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes($"atlas-pca-conformance/pq-software/{a}/pq"))), a => Pq.Suites[a].Pq);

    static (string? Alg, byte[]? Ed, SuiteSecretKeys Keys) Keys(D spec)
    {
        var alg = spec.GetValueOrDefault("alg") as string;
        var keys = new SuiteSecretKeys();
        if (spec.GetValueOrDefault("seed") is string seed && Pq.Suites.TryGetValue(alg ?? "ed25519", out var suite) && suite.Pq is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87)
        {
            var family = SeedFamily.TryGetValue(seed, out var f) ? f : suite.Pq;
            if (family == Pq.Prim.MlDsa65) keys.MlDsa = PqSuites.MlDsa65Keygen(B64(seed)); else keys.MlDsa87 = PqSuites.MlDsa87Keygen(B64(seed));
        }
        return (alg, spec.GetValueOrDefault("edSecret") is { } ed ? B64(ed) : null, keys);
    }

    static D AttestorOut(PqSoftwareAttestor t, D? statement)
    {
        var o = new D { ["pqPublicKey"] = t.PqPublicKey };
        if (t.Ed25519PublicKey != null) o["ed25519PublicKey"] = t.Ed25519PublicKey;
        if (statement != null) o["statement"] = statement;
        return o;
    }

    static object? Attest(L a)
    {
        var (alg, ed, keys) = Keys((D)a[0]!);
        var t = AttestPqSoftware.CreatePqSoftwareAttestor(alg, keys, ed);
        return AttestorOut(t, t.Attest((D)a[1]!));
    }

    static object? BuildAttestor(L a)
    {
        var (alg, ed, keys) = Keys((D)a[0]!);
        return AttestorOut(AttestPqSoftware.CreatePqSoftwareAttestor(alg, keys, ed), null);
    }

    static D Config(D c, object? evidence)
    {
        var cfg = c.Where(e => e.Key != "noEvidenceSeam").ToDictionary(e => e.Key, e => e.Value);
        if (c.GetValueOrDefault("noEvidenceSeam") is not true) cfg["resolveEvidence"] = (Func<object?, object?, object?>)((_, _) => evidence);
        return cfg;
    }

    static object? Verify(L a)
    {
        var sc = (D)a[0]!;
        var input = (D)sc["input"]!;
        var inp = new D { ["document"] = new D(), ["ctx"] = new D(), ["nowMs"] = input["nowMs"] };
        if (input.GetValueOrDefault("expected") != null) inp["expected"] = input["expected"];
        return AttestPqSoftware.CreatePqSoftwareVerifier(Config((D)sc["config"]!, sc.GetValueOrDefault("evidence"))).Verify(inp);
    }

    static object? BuildVerifier(L a)
    {
        AttestPqSoftware.CreatePqSoftwareVerifier(Config((D)a[0]!, null));
        return new D { ["built"] = true };
    }

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), null, null, min);

    [Fact] public void Constants() => Fn("constants", _ => AttestPqSoftware.Constants(), 1);
    [Fact] public void AttestMinting() => Fn("attest", Attest, 29);
    [Fact] public void BuildAttestorCases() => Fn("buildAttestor", BuildAttestor, 9);
    [Fact] public void VerifyPqScenarios() => Fn("verifyPq", Verify, 90);
    [Fact] public void BuildVerifierCases() => Fn("buildVerifier", BuildVerifier, 8);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "attest", "buildAttestor", "verifyPq", "buildVerifier" });
        Assert.Equal(137, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int> { ["constants"] = 1, ["attest"] = 29, ["buildAttestor"] = 9, ["verifyPq"] = 90, ["buildVerifier"] = 8 }, counts);
    }
}
