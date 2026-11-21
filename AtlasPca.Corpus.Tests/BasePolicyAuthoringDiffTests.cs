using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of policy authoring (test-data/base-policyauthoring.json.gz, TS reference packages/pca/src/policy-link.ts
/// and forbid-certificate.ts): template definitions, slot objects, references and overlays, a slot-value grid, registries with overlays and
/// bound parameter objects, and forbid-wins certificate tables with every single-field corruption. Exact reasons and exact policies; a
/// reference refusal ending in "(fail closed)" (the reference threw on a malformed registry) only requires a .NET refusal; a forbid
/// certificate whose table is not well typed only requires .NET to reject it (as Java).</summary>
public class BasePolicyAuthoringDiffTests
{
    const string M = "policyauthoring";

    static List<string> Strs(object? o) => o is L l ? l.Cast<string>().ToList() : new List<string>();
    static bool FailClosed(object? reason) => reason is string s && s.EndsWith("(fail closed)", StringComparison.Ordinal);

    // a reason (or null): a fail-closed reference reason needs any .NET reason
    static bool ReasonEq(D c, object? have) => FailClosed(c["out"]) ? have is string : Base.Eq(c["out"], have);

    // {ok, reason} / {ok, policy[, overlays]}: a fail-closed reference refusal needs any .NET refusal (no policy, a reason)
    static bool ResultEq(D c, object? have)
    {
        var want = (D)c["out"]!;
        if (FailClosed(want.GetValueOrDefault("reason")))
            return have is D h && h["ok"] is false && h.GetValueOrDefault("reason") is string && !h.ContainsKey("policy");
        return Base.Eq(want, have);
    }

    static D Result(D? policy, string? reason, int? overlays)
    {
        if (policy == null)
        {
            var r = new D { ["ok"] = false, ["reason"] = reason };
            if (overlays is int n && n != 0) r["overlays"] = n; // a refusal that counts applied overlays diverges
            return r;
        }
        var o = new D { ["ok"] = true, ["policy"] = policy };
        if (overlays != null) o["overlays"] = overlays;
        if (reason != null) o["reason"] = reason; // a reason alongside a policy diverges
        return o;
    }

    [Fact] public void TemplateDef() => Base.Check(M, "templateDef", a => PolicyAuthoring.TemplateDefError(a[0]), eq: ReasonEq, min: 1450);
    [Fact] public void Tighten() => Base.Check(M, "tighten", a => PolicyAuthoring.TightenOverlayError(a[0]), eq: ReasonEq, min: 370);
    [Fact] public void TemplateRef() => Base.Check(M, "templateRef", a => PolicyAuthoring.TemplateRefError(a[0]), eq: ReasonEq, min: 200);
    [Fact] public void VerifyTemplate() => Base.Check(M, "verifyTemplate", a => PolicyAuthoring.VerifyTemplate(a[0], Strs(a[1])), eq: ReasonEq, min: 2780);
    [Fact] public void VerifyTighten() => Base.Check(M, "verifyTighten", a => PolicyAuthoring.VerifyTighten(a[0], Strs(a[1])), eq: ReasonEq, min: 830);

    [Fact]
    public void Instantiate() => Base.Check(M, "instantiate", a =>
    {
        var (policy, reason) = PolicyAuthoring.InstantiateTemplate(a[0], a[1]);
        return Result(policy, reason, null);
    }, eq: ResultEq, min: 2670);

    [Fact]
    public void Resolve() => Base.Check(M, "resolve", a =>
    {
        var (policy, overlays, reason) = PolicyAuthoring.ResolveLink(a[0], a[1]);
        return Result(policy, reason, overlays);
    }, eq: ResultEq, min: 2640);

    [Fact]
    public void Forbid()
    {
        int typedTrue = 0, typedFalse = 0;
        foreach (var c in Base.Of(M, "forbid"))
        {
            var o = (D)c["out"]!;
            if (o["typed"] is true) { if (o["ok"] is true) typedTrue++; else typedFalse++; }
        }
        Assert.True(typedTrue > 1000 && typedFalse > 1000, $"certificate corpus too thin: {typedTrue} / {typedFalse}");
        // an ill-typed table is refused by .NET even where the reference's loose compare passes
        Base.Check(M, "forbid", a => PolicyAuthoring.ForbidCertificateConsistent(a[0], a[1] == null ? null : Strs(a[1])),
            eq: (c, h) => { var o = (D)c["out"]!; return h is bool b && b == (o["typed"] is true && o["ok"] is true); }, min: 6500);
    }

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "templateDef", "tighten", "templateRef", "verifyTemplate", "verifyTighten", "instantiate", "resolve", "forbid" }); Assert.Equal(19418, Base.Total(M)); }
}
