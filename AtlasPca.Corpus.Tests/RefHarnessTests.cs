using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.Harness;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the attested orchestration harness (plan inclusion, taint fold, trust budget, signing) and its allowlisting attestation
/// verifier against the TypeScript reference. The clock is constant between steps and the nonce of the k-th build is <c>n&lt;k&gt;</c>.</summary>
public class RefHarnessTests
{
    const string M = "ref-harness";
    const long T0 = 1_800_000_000_000;

    static SuiteKey KeyOf(string label) => SuiteKey.Ed25519(EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label))));

    [Fact]
    public void Consts() => Base.Check(M, "consts", _ => new D
    {
        ["HARNESS_VERSION"] = PcaHarness.HarnessVersion,
        ["HARNESS_MODEL_ID"] = PcaHarness.HarnessModelId,
        ["ENFORCED_CHECKS"] = PcaHarness.EnforcedChecks.Cast<object?>().ToList(),
    });

    [Fact] public void ComputeHarnessMeasurement() => Base.Check(M, "computeHarnessMeasurement", a => PcaHarness.ComputeHarnessMeasurement(a[0], a[1], a[2]));
    [Fact] public void HarnessAttest() => Base.Check(M, "harnessAttest", a => HarnessAttestation.CreateHarnessAttestationVerifier(a[0])(a[1]));

    [Fact]
    public void Scenarios() => Base.Check(M, "harness", a =>
    {
        var spec = (D)a[0]!;
        var op = (D)spec["opts"]!;
        double t = T0;
        long k = 0;
        PcaHarness h;
        try
        {
            h = new PcaHarness(new HarnessOptions
            {
                Grant = (D)op["grant"]!, Chain = op.GetValueOrDefault("chain") as L, Signer = KeyOf((string)op["label"]!), Plan = op.GetValueOrDefault("plan"),
                Audience = op.GetValueOrDefault("audience"), Budget = op.GetValueOrDefault("budget"), Policy = op.GetValueOrDefault("policy"), BaseRisk = op.GetValueOrDefault("baseRisk"),
                Now = () => t, TtlMs = op.GetValueOrDefault("ttlMs") is Num tn ? Jx.ToNumber(tn) : null, MeasurementManifest = op.GetValueOrDefault("manifest"),
                Nonce = () => "n" + k++, Attestation = op.GetValueOrDefault("attestation"),
            });
        }
        catch (Exception) { return new D { ["$err"] = true }; }
        var outs = new L();
        foreach (var so in (L)spec["steps"]!)
        {
            var st = (D)so!;
            if ((string)st["op"]! == "now") { t = Jx.ToNumber(st["t"]); outs.Add(null); continue; }
            var orc = (D)st["oracle"]!;
            outs.Add(h.Step(() =>
            {
                var kind = (string)orc["kind"]!;
                if (kind == "throw") throw new Exception((string)orc["msg"]!);
                return kind == "bad" ? orc["v"] : orc["c"];
            }));
        }
        return new D { ["steps"] = outs, ["budget"] = h.Budget, ["counter"] = h.Counter, ["planRoot"] = h.PlanRoot, ["measurement"] = h.HarnessMeasurement() };
    });

    [Fact] public void CoversEveryFn() { Base.Covers(M, new[] { "consts", "computeHarnessMeasurement", "harnessAttest", "harness" }); Assert.Equal(824, Base.Total(M)); }
}
