using AtlasPca.Ap2;
using Xunit;
using Ap2Api = AtlasPca.Ap2.Ap2;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the reference vectors of the AP2 PCA binding verification (test-data/ref-ap2-java-extra.json.gz).</summary>
public class RefAp2BindingTests
{
    static Func<D, D, ThresholdHookResult?>? Hook(object? d)
    {
        if (d is not D h) return null;
        var r = h.GetValueOrDefault("enforced") is true
            ? new ThresholdHookResult(true, h.GetValueOrDefault("ok") is true, h.GetValueOrDefault("t") is Num t ? double.Parse(t.Raw, System.Globalization.CultureInfo.InvariantCulture) : null, h.GetValueOrDefault("reason") as string)
            : new ThresholdHookResult(false, false);
        return (_, _) => r;
    }

    static VerifyPcaBindingInput Input(D j)
    {
        var i = new VerifyPcaBindingInput
        {
            Open = (D)j["open"]!, Closed = (D)j["closed"]!, OpenHash = (string)j["openHash"]!, ExpectedPrincipal = (string)j["expectedPrincipal"]!,
            Audience = (string)j["audience"]!, Mandate = j.GetValueOrDefault("mandate") as D,
        };
        if (j.GetValueOrDefault("pqPins") is D pins) i.PqPins = pins.ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
        if (j.GetValueOrDefault("now") is Num now) i.Now = long.Parse(now.Raw);
        i.RecentChargeTimes = j.GetValueOrDefault("recentChargeTimes") is L l ? l : j.GetValueOrDefault("recentChargeTimes") is null ? null : new L { "not-a-list" };
        if (j.GetValueOrDefault("hooks") is D h)
        {
            i.ThresholdHook = Hook(h.GetValueOrDefault("threshold")); i.AttestationHook = Hook(h.GetValueOrDefault("attestation"));
            i.RevocationHook = Hook(h.GetValueOrDefault("revocation")); i.ZkHook = Hook(h.GetValueOrDefault("zk"));
        }
        if (j.GetValueOrDefault("enforce") is D e && e.GetValueOrDefault("freshness") is D f && f.GetValueOrDefault("maxAgeMs") is Num m) i.FreshnessMaxAgeMs = double.Parse(m.Raw, System.Globalization.CultureInfo.InvariantCulture);
        return i;
    }

    [Fact]
    public void VerifyPcaBinding() => Base.Check("ref-ap2-java-extra", "verifyPcaBinding", a =>
    {
        var r = Ap2Api.VerifyPcaBinding(Input((D)a[0]!));
        return r.Ok ? new D { ["ok"] = true, ["pcactn"] = r.Pcactn, ["grant"] = r.Grant, ["terms"] = r.Terms } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    static D ValidCase() => (D)((L)Base.Cases("ref-ap2-java-extra").First(c => c["out"] is D o && o.GetValueOrDefault("ok") is true && ((D)((L)c["args"]!)[0]!).GetValueOrDefault("enforce") is null && ((D)((L)c["args"]!)[0]!).GetValueOrDefault("hooks") is null)["args"]!)[0]!;

    static string? Reason(VerifyPcaBindingInput i) { var r = Ap2Api.VerifyPcaBinding(i); return r.Ok ? null : r.Reason; }

    [Fact]
    public void TheTaintGateDeniesUnverifiableLineageBeforeTheOtherGates()
    {
        Assert.True(Ap2Api.VerifyPcaBinding(Input(ValidCase())).Ok);
        var i = Input(ValidCase());
        i.EnforceTaint = new TaintGate(new TaintContext(new InMemoryTrustedInputRegistry()), 0);
        i.AttestationGate = (_, _) => null; // would deny too, but the taint gate comes first
        Assert.StartsWith("PCActn: taint_gate: ", Reason(i));
    }

    [Fact]
    public void TheFreshnessGateRefusesAMisconfigurationAndAStubAnchor()
    {
        // the corpus fixtures carry a stub anchor (epoch 0): an enabled gate refuses it, whatever the epoch length, clock and skew
        var i = Input(ValidCase());
        i.FreshnessMaxAgeMs = 1e15;
        Assert.Contains("anchor is missing", Reason(i));
        i.FreshnessEpochMs = 1000;
        i.FreshnessNow = 5;
        i.FreshnessClockSkewMs = 1e9;
        Assert.Contains("anchor is missing", Reason(i));
        i.FreshnessEpochMs = 0;
        Assert.Contains("misconfigured", Reason(i));
        i.FreshnessEpochMs = -5;
        Assert.Contains("misconfigured", Reason(i));
        i = Input(ValidCase());
        i.FreshnessMaxAgeMs = -1;
        Assert.Contains("misconfigured", Reason(i));
        i.FreshnessMaxAgeMs = double.NaN;
        Assert.Contains("misconfigured", Reason(i));
    }

    [Fact]
    public void TheAttestationGateTakesTheHookSlotAndIsRequiredByDefault()
    {
        var i = Input(ValidCase());
        i.AttestationGate = (_, _) => new ThresholdHookResult(true, true);
        Assert.Null(Reason(i));
        i.AttestationGate = (_, _) => new ThresholdHookResult(true, false, null, "bad quote");
        Assert.Equal("PCActn: attestation: bad quote", Reason(i));
        i.AttestationGate = (_, _) => new ThresholdHookResult(false, false);
        Assert.Equal("PCActn: attestation: attestation required but the verifier reported not-enforced / no document (fail closed)", Reason(i));
        i.AttestationRequired = false;
        Assert.Null(Reason(i));
        i.AttestationHook = (_, _) => new ThresholdHookResult(true, false, null, "hook says no"); // the gate replaces the hook
        Assert.Null(Reason(i));
    }

    [Fact]
    public void Covers() { Base.Covers("ref-ap2-java-extra", new[] { "verifyPcaBinding" }); Assert.Equal(127, Base.Total("ref-ap2-java-extra")); }
}
