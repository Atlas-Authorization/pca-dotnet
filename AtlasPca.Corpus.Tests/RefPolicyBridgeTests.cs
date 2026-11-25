using AtlasPca.PolicyBridgeKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the policy bridge (Cedar, OPA/Rego, OpenFGA and strict-CEL translators, deny-overrides-permit decide) against the
/// TypeScript reference. A mutated policy text is hostile input: the translators must report, never throw, exactly as the reference does.</summary>
public class RefPolicyBridgeTests
{
    const string M = "ref-policy-bridge";

    [Fact] public void CedarToPca() => Base.Check(M, "cedarToPca", a => Cedar.CedarToPca((string)a[0]!));
    [Fact] public void TranslateCedar() => Base.Check(M, "translateCedar", a => Cedar.TranslateCedar((string)a[0]!, (bool)a[1]!));
    [Fact] public void RegoToPca() => Base.Check(M, "regoToPca", a => Rego.RegoToPca((string)a[0]!));
    [Fact] public void OpenfgaToPca() => Base.Check(M, "openfgaToPca", a => OpenFga.OpenfgaToPca(a[0], a[1]));
    [Fact] public void Decide() => Base.Check(M, "decide", a => PolicyBridge.Decide((D)a[0]!, (D)a[1]!));
    [Fact] public void CelToCondition() => Base.Check(M, "celToCondition", a => Cel.CelToCondition((string?)a[0], a[1]));
    [Fact] public void ParseCel() => Base.Check(M, "parseCel", a => Cel.ParseCel((string?)a[0]));

    [Fact]
    public void CelToPredicate() => Base.Check(M, "celToPredicate", a =>
    {
        var scope = (D)a[2]!;
        return Cel.CelToPredicate((string?)a[0], a[1], scope.GetValueOrDefault("verb"), (string?)scope.GetValueOrDefault("resource"));
    });

    [Fact] public void CelConditionsToPca() => Base.Check(M, "celConditionsToPca", a => Cel.CelConditionsToPca((L)a[0]!, a[1]));

    /// <summary>A forbid that matches overrides a matching permit; an incomplete translation denies everything.</summary>
    [Fact]
    public void DenyOverridesPermit()
    {
        var r = Cedar.CedarToPca("permit (principal, action, resource); forbid (principal, action == Action::\"delete\", resource);");
        D Ctx(string verb) => new() { ["subject"] = new D { ["id"] = "u" }, ["action"] = new D { ["verb"] = verb, ["resource"] = "r" } };
        Assert.Equal(true, PolicyBridge.Decide(r, Ctx("read"))["allowed"]);
        Assert.Equal("forbidden by deny policy", PolicyBridge.Decide(r, Ctx("delete"))["reason"]);
        var bad = Cedar.CedarToPca("forbid (principal, action, resource) when { resource.a + 1 < 2 };");
        Assert.NotEmpty((L)((D)bad["report"]!)["errors"]!);
        Assert.Equal("translation incomplete (fail closed)", PolicyBridge.Decide(bad, Ctx("read"))["reason"]);
    }

    [Fact]
    public void EveryFnHasATest() { Base.Covers(M, new[]
    {
        "cedarToPca", "translateCedar", "regoToPca", "openfgaToPca", "decide", "celToCondition", "celToPredicate", "celConditionsToPca", "parseCel",
    }); Assert.Equal(4361, Base.Total(M)); }
}
