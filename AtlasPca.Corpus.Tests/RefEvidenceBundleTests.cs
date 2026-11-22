using AtlasPca.Evidence;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of verifyEvidenceBundle (the dispute evidence replay: findings, summary, report digest) against the TypeScript reference over the chargeback
/// walkthrough and its tampered / re-trusted variants. <c>trust.verifiers</c> members are constant verdicts (an object) or a kind (ok, fail, throws) the native ports return.</summary>
public class RefEvidenceBundleTests
{
    static EvidencePort Port(object? spec) => (_, _) => spec switch
    {
        string kind when kind == "throws" => throw new InvalidOperationException("boom"),
        string kind => kind == "ok" ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = "port refused" },
        D v => v,
        _ => throw new InvalidOperationException("bad port spec"),
    };

    static D Run(L a)
    {
        D? trust = a.Count > 1 ? a[1] as D : null;
        var ports = new Dictionary<string, EvidencePort>();
        if (trust != null && trust.GetValueOrDefault("verifiers") is D vs)
        {
            foreach (var kv in vs) ports[kv.Key] = Port(kv.Value);
            trust = trust.Where(kv => kv.Key != "verifiers").ToDictionary(kv => kv.Key, kv => kv.Value);
        }
        return EvidenceVerify.VerifyEvidenceBundle(a[0], trust, ports);
    }

    [Fact] public void BundlePy() => Base.Check("ref-evidence-bundle-py", "verifyEvidenceBundle", Run, min: 200);
    [Fact] public void BundleJavaExtra2() => Base.Check("ref-evidence-java-extra2", "verifyEvidenceBundle", Run, min: 190);
    [Fact] public void EveryFnIsHandled() { Base.Covers("ref-evidence-bundle-py", new[] { "verifyEvidenceBundle" }); Assert.Equal(204, Base.Total("ref-evidence-bundle-py")); Base.Covers("ref-evidence-java-extra2", new[] { "verifyEvidenceBundle" }); Assert.Equal(196, Base.Total("ref-evidence-java-extra2")); }
}
