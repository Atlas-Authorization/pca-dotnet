using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the full core verify entry (test-data/ref-core-verify-java.json.gz) against the TypeScript reference: hooks, enforcement gates, PQ pins,
/// the audience opt-out, the plan-root policy and the assurance report, with the reference's check names and order.</summary>
public class RefCoreVerifyTests
{
    const string M = "ref-core-verify-java";

    static PcaCore.Hook Hook(object? d)
    {
        var h = (D)d!;
        var r = h.GetValueOrDefault("enforced") is true
            ? PcaCore.HookResult.Of(h.GetValueOrDefault("ok") is true, h.GetValueOrDefault("reason") as string, IntentJs.NumOf(h.GetValueOrDefault("t")))
            : PcaCore.HookResult.None;
        return _ => r;
    }

    static PcaCore.Options Options(D j)
    {
        var o = new PcaCore.Options((D)j["grant"]!) { GrantFromArtifact = j.GetValueOrDefault("grantFromArtifact") is true };
        if (j.ContainsKey("nowEpoch")) o.NowEpoch = IntentJs.Lng(j["nowEpoch"]);
        if (j.ContainsKey("pqPins")) o.PqPins = ((D)j["pqPins"]!).ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
        if (j.ContainsKey("allowedSuites")) o.AllowedSuites = ((L)j["allowedSuites"]!).Cast<string>().ToList();
        if (j.ContainsKey("audience")) { if (j["audience"] == null) o.AudienceAny(); else o.WithAudience((string)j["audience"]!); }
        var roots = j.ContainsKey("authorizedPlanRoots") ? ((L)j["authorizedPlanRoots"]!).Cast<string>().ToList() : null;
        o.PlanRoots = new PlanRootPolicy(roots, j.GetValueOrDefault("insecureSkipPlanRootCheck") is true);
        if (j.ContainsKey("hooks"))
        {
            var hm = (D)j["hooks"]!;
            o.Hooks = new PcaCore.Hooks
            {
                Attestation = hm.ContainsKey("attestation") ? Hook(hm["attestation"]) : null,
                Threshold = hm.ContainsKey("threshold") ? Hook(hm["threshold"]) : null,
                Revocation = hm.ContainsKey("revocation") ? Hook(hm["revocation"]) : null,
                Zk = hm.ContainsKey("zk") ? Hook(hm["zk"]) : null,
            };
        }
        if (j.ContainsKey("enforce"))
        {
            var em = (D)j["enforce"]!;
            var e = new PcaCore.Enforce();
            if (em.ContainsKey("freshness"))
            {
                var f = (D)em["freshness"]!;
                e.Freshness = new PcaCore.FreshnessGate(IntentJs.NumOf(f["maxAgeMs"])!.Value)
                {
                    EpochMs = f.ContainsKey("epochMs") ? IntentJs.NumOf(f["epochMs"]) : null,
                    ClockSkewMs = f.ContainsKey("clockSkewMs") ? IntentJs.NumOf(f["clockSkewMs"]) : null,
                    Now = f.ContainsKey("now") ? IntentJs.Lng(f["now"]) : null,
                };
            }
            if (em.ContainsKey("attestation"))
            {
                var a = (D)em["attestation"]!;
                e.Attestation = new PcaCore.AttestationGate(Hook(a["verifier"])) { Required = !a.ContainsKey("required") || a["required"] is true };
            }
            o.Enforce = e;
        }
        o.Assurance = j.GetValueOrDefault("assurance") is true;
        if (j.ContainsKey("requireAssurance")) o.RequireAssurance = AssuranceRequirement.FromJson(j["requireAssurance"]);
        if (j.ContainsKey("intent")) o.IntentPolicy = IntentPolicy.FromJson(j["intent"]);
        return o;
    }

    static D Out(PcaCore.Result r)
    {
        var o = new D { ["allow"] = r.Allow, ["checks"] = r.Checks.ToDictionary(kv => kv.Key, kv => (object?)kv.Value) };
        if (r.Reason != null) o["reason"] = r.Reason;
        if (r.Assurance != null) o["assurance"] = r.Assurance.ToJson();
        return o;
    }

    [Fact] public void VerifyCore() => Base.Check(M, "verifyCore", a => Out(PcaCore.Verify(a[0], Options((D)a[1]!))), min: 300);

    /// <summary>The reference reports checks in a fixed order; the JSON comparison ignores member order, so pin it here.</summary>
    [Fact]
    public void CheckOrderIsNormative()
    {
        foreach (var c in Base.Of(M, "verifyCore"))
        {
            var want = ((D)((D)c["out"]!)["checks"]!).Keys.ToList();
            var a = Base.Args(c);
            Assert.True(want.SequenceEqual(PcaCore.Verify(a[0], Options((D)a[1]!)).Checks.Keys), (string)c["name"]!);
        }
    }

    [Fact] public void EveryFnIsHandled() { Base.Covers(M, new[] { "verifyCore" }); Assert.Equal(329, Base.Total(M)); }
}
