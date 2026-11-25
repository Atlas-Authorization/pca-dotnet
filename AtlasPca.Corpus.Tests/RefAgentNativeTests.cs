using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the agent-native module (test-data/ref-agent-native.json.gz: caution, rationale binding, the tool-schema firewall, envelope
/// introspection, authority leases; 1632 cases) against the TypeScript reference. Total functions compare their returned value, reason strings included; a
/// <c>{"$throws"}</c> case needs the native to throw. <c>{"$num"}</c> arguments are the non-finite doubles, <c>{"$bytes"}</c> the signing seeds.</summary>
public class RefAgentNativeTests
{
    const string M = "ref-agent-native";

    static object? Dec(object? v) => v switch
    {
        L l => l.Select(Dec).ToList(),
        D m when m.Count == 1 && m.TryGetValue("$num", out var n) && n is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m when m.Count == 1 && m.ContainsKey("$bytes") => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Dec(e.Value)),
        _ => v,
    };

    static object? Arg(L a, int i) => i < a.Count ? Dec(a[i]) : null;

    static EdKey Key(object? seed) => EdKey.FromSeed((byte[])seed!);

    static Func<string, object?, object?> Judge(string spec) => spec switch
    {
        "true" => (_, _) => true,
        "false" => (_, _) => false,
        "throw" => (_, _) => throw new InvalidOperationException("judge"),
        "truthy" => (_, _) => "yes",
        _ when spec.StartsWith("contains:", StringComparison.Ordinal) => (r, _) => r.Contains(spec["contains:".Length..], StringComparison.Ordinal),
        _ when spec.StartsWith("action-verb:", StringComparison.Ordinal) => (_, a) => a is D m && m.GetValueOrDefault("verb") is string v && v == spec["action-verb:".Length..],
        _ => throw new InvalidOperationException("unknown judge spec " + spec),
    };

    static D Firewall((bool Ok, string? Reason) r)
    {
        var o = new D { ["ok"] = r.Ok };
        if (r.Reason != null) o["reason"] = r.Reason;
        return o;
    }

    [Fact] public void SignCaution() => Base.Check(M, "signCaution", a => Signers.SignCaution((D)Arg(a, 0)!, Key(Arg(a, 1))), min: 30);
    [Fact] public void SignHeartbeat() => Base.Check(M, "signHeartbeat", a => Signers.SignHeartbeat((D)Arg(a, 0)!, Key(Arg(a, 1))), min: 5);
    [Fact] public void VerifyCaution() => Base.Check(M, "verifyCaution", a => AgentNative.VerifyCaution(Arg(a, 0), Arg(a, 1), Arg(a, 2)), min: 100);
    [Fact] public void CombineCaution() => Base.Check(M, "combineCaution", a => AgentNative.CombineCaution(Arg(a, 0), Arg(a, 1)), min: 100);
    [Fact] public void CombineSignedCaution() => Base.Check(M, "combineSignedCaution", a => AgentNative.CombineSignedCaution(Arg(a, 0), Arg(a, 1), Arg(a, 2), Arg(a, 3)), min: 10);
    [Fact] public void CheckCautionMonotone() => Base.Check(M, "checkCautionMonotone", a => AgentNative.CheckCautionMonotone(Arg(a, 0)), min: 10);
    [Fact] public void IsStrongSalt() => Base.Check(M, "isStrongSalt", a => AgentNative.IsStrongSalt(Arg(a, 0)), min: 20);
    [Fact] public void BindRationale() => Base.Check(M, "bindRationale", a => AgentNative.BindRationale(Arg(a, 0), Arg(a, 1), Arg(a, 2)), min: 40);
    [Fact] public void VerifyRationale() => Base.Check(M, "verifyRationale", a => a.Count < 3 ? AgentNative.VerifyRationale(Arg(a, 0), Arg(a, 1)) : AgentNative.VerifyRationale(Arg(a, 0), Arg(a, 1), Arg(a, 2)), min: 25);
    [Fact] public void AuditRationale() => Base.Check(M, "auditRationale", a => AgentNative.AuditRationale(Arg(a, 0), Arg(a, 1), Arg(a, 2), Judge((string)Arg(a, 3)!)), min: 20);
    [Fact] public void ValidateArgSchema() => Base.Check(M, "validateArgSchema", a => Pca.ValidateArgSchema(Arg(a, 0)), min: 70);
    [Fact] public void ToolSchemaCaveat() => Base.Check(M, "toolSchemaCaveat", a => AgentNative.ToolSchemaCaveat(Arg(a, 0), Arg(a, 1)), min: 90);
    [Fact] public void EvaluateToolSchema() => Base.Check(M, "evaluateToolSchema", a => Firewall(Pca.EvaluateToolSchemaJson(Arg(a, 0), Arg(a, 1))), min: 100);
    [Fact] public void ToolSchemaEvaluator() => Base.Check(M, "toolSchemaEvaluator", a => AgentNative.ToolSchemaEvaluator(Arg(a, 0), Arg(a, 1)), min: 5);
    [Fact] public void PredicatesCaveat() => Base.Check(M, "predicatesCaveat", a => AgentNative.PredicatesCaveat(Arg(a, 0)), min: 5);
    [Fact] public void ActionSpendUsd() => Base.Check(M, "actionSpendUsd", a => AgentNative.ActionSpendUsd(Arg(a, 0)) is double d ? d : null, min: 25);
    [Fact] public void AgentNativeCaveatEvaluator() => Base.Check(M, "agentNativeCaveatEvaluator", a => AgentNative.AgentNativeCaveatEvaluator(Arg(a, 0), Arg(a, 1)), min: 50);
    [Fact] public void DescribeEnvelope() => Base.Check(M, "describeEnvelope", a => AgentNative.DescribeEnvelope(Arg(a, 0), Arg(a, 1), (string?)Arg(a, 2), (D?)Arg(a, 3)), min: 100);
    [Fact] public void EnvelopePermits() => Base.Check(M, "envelopePermits", a => AgentNative.EnvelopePermits(Arg(a, 0), Arg(a, 1), Arg(a, 2), Arg(a, 3), Arg(a, 4)), min: 400);
    [Fact] public void EnvelopePermitsToolCall() => Base.Check(M, "envelopePermitsToolCall", a => AgentNative.EnvelopePermitsToolCall(Arg(a, 0), Arg(a, 1)), min: 70);
    [Fact] public void GrantLease() => Base.Check(M, "grantLease", a => AgentNative.GrantLease(Arg(a, 0)), min: 40);
    [Fact] public void LeaseState() => Base.Check(M, "leaseState", a => AgentNative.LeaseState(Arg(a, 0), Arg(a, 1)), min: 90);
    [Fact] public void RenewLease() => Base.Check(M, "renewLease", a => AgentNative.RenewCapabilityLease(Arg(a, 0), Arg(a, 1), Arg(a, 2)), min: 45);
    [Fact] public void Constants() => Base.Check(M, "constants", _ => AgentNative.Constants(), min: 1);

    [Fact]
    public void EveryFnIsHandled()
    {
        Base.Covers(M, new[]
        {
            "signCaution", "signHeartbeat", "verifyCaution", "combineCaution", "combineSignedCaution", "checkCautionMonotone", "isStrongSalt", "bindRationale",
            "verifyRationale", "auditRationale", "validateArgSchema", "toolSchemaCaveat", "evaluateToolSchema", "toolSchemaEvaluator", "predicatesCaveat",
            "actionSpendUsd", "agentNativeCaveatEvaluator", "describeEnvelope", "envelopePermits", "envelopePermitsToolCall", "grantLease", "leaseState",
            "renewLease", "constants",
        });
        Assert.Equal(1632, Base.Cases(M).Count);
    }
}
