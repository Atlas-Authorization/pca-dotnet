using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the analyzer (static analysis of authority) against the TypeScript reference. Every function of the corpus is replayed (listed in Covers).</summary>
public class RefAnalyzerTests
{
    const string M = "ref-analyzer";

    static NumInterval Iv(object? o) => o is D d
        ? new NumInterval(double.Parse(((Num)d["lo"]!).Raw, CultureInfo.InvariantCulture), (bool)d["loInclusive"]!, double.Parse(((Num)d["hi"]!).Raw, CultureInfo.InvariantCulture), (bool)d["hiInclusive"]!)
        : Field.FullInterval;

    /// <summary>{"$num": "Infinity"} back to the number (a diff carries infinite exposure deltas, which JSON cannot).</summary>
    static object? Dec(object? v) => v switch
    {
        L l => l.Select(Dec).ToList(),
        D m when m.Count == 1 && m.TryGetValue("$num", out var s) && s is string t => (object)(t == "Infinity" ? double.PositiveInfinity : t == "-Infinity" ? double.NegativeInfinity : double.NaN),
        D m => m.ToDictionary(e => e.Key, e => Dec(e.Value)),
        _ => v,
    };

    static D Ctx(object? x)
    {
        var a = (D)x!;
        var act = new D(); foreach (var (k, v) in a) act[k] = v;
        if (!act.ContainsKey("params") || act["params"] == null) act["params"] = new D();
        return new D { ["action"] = act, ["subject"] = a.GetValueOrDefault("subject") ?? new D(), ["env"] = a.GetValueOrDefault("env") ?? new D() };
    }

    static ProbeInputs Inputs(object? o)
    {
        var d = (D)o!;
        return new ProbeInputs
        {
            PredicateSets = ((L)d["predicateSets"]!).Select(x => (L)x!).ToList(),
            ExtraVerbs = d.GetValueOrDefault("extraVerbs") is L ev ? ev.Select(x => (string)x!).ToList() : new(),
            ExtraResources = d.GetValueOrDefault("extraResources") is L er ? er.Select(x => (x is string s ? s : null) ?? throw new InvalidOperationException("TypeError: resource.startsWith is not a function")).ToList() : new(),
            ExtraFieldConditions = d.GetValueOrDefault("extraFieldConditions") is L ef ? ef.Select(x => { var m = (D)x!; return ((string)m["path"]!, (D)m["cond"]!); }).ToList() : new(),
            VaryReversibility = (bool)d["varyReversibility"]!,
        };
    }

    static object? ProbeJson(Probes p) => new D
    {
        ["verbs"] = p.Verbs.Cast<object?>().ToList(), ["resources"] = p.Resources.Cast<object?>().ToList(), ["revClasses"] = p.RevClasses.Cast<object?>().ToList(),
        ["fields"] = p.Fields.Select(f => (object?)new D { ["path"] = f.Path, ["values"] = f.Values.Select(v => ReferenceEquals(v, Enumerate.Absent) ? new D { ["$absent"] = true } : v).ToList() }).ToList(),
    };

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    static string Pub(string label) { using var k = EdKey.FromSeed(Seed(label)); return k.Id; }

    /// <summary>"$key:LABEL" stands for the b64u public key of that label.</summary>
    static object? Keyed(object? v) => v switch
    {
        string s when s.StartsWith("$key:", StringComparison.Ordinal) => Pub(s[5..]),
        L l => l.Select(Keyed).ToList(),
        D m => m.ToDictionary(e => e.Key, e => Keyed(e.Value)),
        _ => v,
    };

    static object? At(L a, int i) => a.Count > i ? a[i] : null;

    static string? Str(object? o) => o as string;

    [Fact] public void AnalyzeCaveats() => Base.Check(M, "analyzeCaveats", a => CaveatAnalysis.AnalyzeCaveats(a[0]).ToJson());
    [Fact] public void NumericConjunctionSatisfiable() => Base.Check(M, "numericConjunctionSatisfiable", a => Field.NumericConjunctionSatisfiable((L)a[0]!));
    [Fact] public void TightenInterval() => Base.Check(M, "tightenInterval", a => Field.TightenInterval(Iv(a[0]), a[1], a[2]).ToJson());
    [Fact] public void IntervalEmpty() => Base.Check(M, "intervalEmpty", a => Field.IntervalEmpty(Iv(a[0])));
    [Fact] public void FieldProbes() => Base.Check(M, "fieldProbes", a => Field.FieldProbes((L)a[0]!));
    [Fact] public void VetoesFromConstitution() => Base.Check(M, "vetoesFromConstitution", a => Constitution.VetoesFromConstitution(a[0]));
    [Fact] public void ToModel() => Base.Check(M, "toModel", a => Enumerate.ToModel(a[0]).ToJson());
    [Fact] public void CollectProbes() => Base.Check(M, "collectProbes", a => ProbeJson(Enumerate.CollectProbes(Inputs(a[0]))));

    [Fact]
    public void Representatives() => Base.Check(M, "representatives", a =>
    {
        var p = Enumerate.CollectProbes(Inputs(a[0]));
        if (Enumerate.ProductSize(p) > 400) throw new InvalidOperationException("grid too large for the corpus");
        return Enumerate.Representatives(p).Select(r =>
        {
            var o = new D { ["verb"] = r.Verb, ["resource"] = r.Resource };
            if (r.RevClass != null) o["revClass"] = r.RevClass;
            o["assignments"] = r.AssignmentsDict();
            o["action"] = Enumerate.RepToAction(r);
            return (object?)o;
        }).ToList();
    });

    [Fact] public void DecideAction() => Base.Check(M, "decideAction", a => Enumerate.DecideAction(Enumerate.ToModel(a[0]), a[1]));
    [Fact] public void AdmitsConcrete() => Base.Check(M, "admitsConcrete", a => AnalyzerCore.AdmitsConcrete(a[0], a[1]));
    [Fact] public void VetoApplies() => Base.Check(M, "vetoApplies", a => Enumerate.VetoApplies(a[0], Ctx(a[1])));
    [Fact] public void ThresholdsOf() => Base.Check(M, "thresholdsOf", a => Exposure.ThresholdsOf(Enumerate.ToModel(a[0]), (string)a[1]!).Select(Jx_N).ToList());
    static object? Jx_N(double d) => new Num(d.ToString("R", CultureInfo.InvariantCulture));

    [Fact] public void Reachable() => Base.Check(M, "reachable", a => AnalyzerCore.Reachable(a[0], a[1], a[2]));
    [Fact] public void AlwaysDenies() => Base.Check(M, "alwaysDenies", a => AnalyzerCore.AlwaysDenies(a[0], Str(a[1]), a[2]));
    [Fact] public void AlwaysAllows() => Base.Check(M, "alwaysAllows", a => AnalyzerCore.AlwaysAllows(a[0], (string)a[1]!, a[2]));
    [Fact] public void Subsumes() => Base.Check(M, "subsumes", a => AnalyzerCore.Subsumes(a[0], a[1], a[2]));
    [Fact] public void Disjoint() => Base.Check(M, "disjoint", a => AnalyzerCore.Disjoint(a[0], a[1], a[2]));
    [Fact] public void Equivalent() => Base.Check(M, "equivalent", a => AnalyzerCore.Equivalent(a[0], a[1], a[2]));
    [Fact] public void IntentConformance() => Base.Check(M, "intentConformance", a => AnalyzerCore.IntentConformance(a[0], a[1], a[2]));
    [Fact] public void PredicateNumericSatisfiable() => Base.Check(M, "predicateNumericSatisfiable", a => AnalyzerCore.PredicateNumericSatisfiable(a[0]));
    [Fact] public void MaxExposure() => Base.Check(M, "maxExposure", a => Exposure.MaxExposure(a[0], a[1]).ToJson());
    [Fact] public void EscalationSurface() => Base.Check(M, "escalationSurface", a => Exposure.EscalationSurface(a[0], a[1]));
    [Fact] public void DelegationEnvelope() => Base.Check(M, "delegationEnvelope", a => Exposure.DelegationEnvelope(a[0], a[1]));
    [Fact] public void DiffPolicies() => Base.Check(M, "diffPolicies", a => Exposure.DiffPolicies(a[0], a[1], a[2]));
    [Fact] public void DiffGate() => Base.Check(M, "diffGate", a => a[1] == null ? Exposure.DiffGate(Dec(a[0])) : Exposure.DiffGate(Dec(a[0]), a[1]));

    [Fact]
    public void FindWithBackend() => Base.Check(M, "findWithBackend", a =>
    {
        var spec = (D)a[1]!;
        return Exposure.FindWithBackend((string)spec["name"]!, _ => (D)spec["result"]!, (D)a[0]!);
    });

    [Fact] public void Residual() => Base.Check(M, "residual", a => AtlasPca.Analyzer.Residual.Compute(a[0], a[1], a[2]));
    [Fact] public void ResidualPolicy() => Base.Check(M, "residualPolicy", a => AtlasPca.Analyzer.Residual.PolicyOf(a[0]));
    [Fact] public void EvaluateResidual() => Base.Check(M, "evaluateResidual", a => AtlasPca.Analyzer.Residual.Evaluate(a[0], a[1]));
    [Fact] public void WhatMayIDo() => Base.Check(M, "whatMayIDo", a => AtlasPca.Analyzer.Residual.WhatMayIDo(a[0], a[1], a[2], a[3]));
    [Fact] public void ToFilter() => Base.Check(M, "toFilter", a => Filter.ToFilter(AtlasPca.Analyzer.Residual.Compute(a[0], a[1], a[2]), a[3]));
    [Fact] public void EvalFilter() => Base.Check(M, "evalFilter", a => Filter.EvalFilter(a[0], a[1]));
    [Fact] public void ToUcast() => Base.Check(M, "toUcast", a => Filter.ToUcast((D)a[0]!));
    [Fact] public void EvalUcast() => Base.Check(M, "evalUcast", a => Filter.EvalUcast(a[0], a[1]));

    [Fact] public void SuggestNarrowing() => Base.Check(M, "suggestNarrowing", a => Narrowing.SuggestNarrowing(a[0], a[1], At(a, 2)));
    [Fact] public void SignAccessRequest() => Base.Check(M, "signAccessRequest", a => Narrowing.SignAccessRequest(a[0], Seed((string)a[1]!), Pub((string)a[1]!)));
    [Fact] public void VerifyAccessRequest() => Base.Check(M, "verifyAccessRequest", a => Narrowing.VerifyAccessRequest(a[0], Keyed(At(a, 1)) as string));
    [Fact] public void WitnessOf() => Base.Check(M, "witnessOf", a => Coverage.WitnessOf(Enumerate.ToModel(a[0]), a[1]));
    [Fact] public void CoverageOf() => Base.Check(M, "coverage", a => Coverage.Compute(a[0], a[1], At(a, 2)));
    [Fact] public void CoverageGate() => Base.Check(M, "coverageGate", a => Coverage.Gate(a[0], At(a, 1)));
    [Fact] public void MinimalFlip() => Base.Check(M, "minimalFlip", a => Flip.MinimalFlip(a[0], a[1], At(a, 2)));

    [Fact] public void VerbShapes() => Base.Check(M, "verbShapes", a => Validate.VerbShapes(a[0]));
    [Fact] public void VerbShapesFromActionDefs() => Base.Check(M, "verbShapesFromActionDefs", a => Validate.VerbShapesFromActionDefs(a[0]));
    [Fact] public void ValidatePolicyAgainstSchema() => Base.Check(M, "validatePolicyAgainstSchema", a => Validate.ValidatePolicyAgainstSchema(a[0], a[1], At(a, 2)));
    [Fact] public void PolicyTestsDoc() => Base.Check(M, "policyTestsDoc", a => TestRunner.PolicyTestsDoc(a[0], a[1]));
    [Fact] public void RunPolicyTests() => Base.Check(M, "runPolicyTests", a => TestRunner.RunPolicyTests(a[0], a[1], At(a, 2)));
    [Fact] public void GenerateBoundaryTests() => Base.Check(M, "generateBoundaryTests", a => TestRunner.GenerateBoundaryTests(a[0], At(a, 1)));
    [Fact] public void DecideAll() => Base.Check(M, "decideAll", a => TestRunner.DecideAll(a[0], a[1]));
    [Fact] public void SignPolicyTests() => Base.Check(M, "signPolicyTests", a => TestRunner.SignPolicyTests(a[0], Seed((string)a[1]!), Pub((string)a[1]!)));
    [Fact] public void VerifyPolicyTests() => Base.Check(M, "verifyPolicyTests", a => TestRunner.VerifyPolicyTests(a[0], Keyed(At(a, 1)) as string));

    [Fact] public void DagExposure() => Base.Check(M, "dagExposure", a => DagAnalysis.DagExposure(a[0]));

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "analyzeCaveats", "numericConjunctionSatisfiable", "tightenInterval", "intervalEmpty", "fieldProbes", "vetoesFromConstitution", "toModel", "collectProbes",
            "representatives", "decideAction", "admitsConcrete", "vetoApplies", "thresholdsOf", "reachable", "alwaysDenies", "alwaysAllows", "subsumes", "disjoint", "equivalent",
            "intentConformance", "predicateNumericSatisfiable", "maxExposure", "escalationSurface", "delegationEnvelope", "diffPolicies", "diffGate", "findWithBackend", "dagExposure",
            "residual", "residualPolicy", "evaluateResidual", "whatMayIDo", "toFilter", "evalFilter", "toUcast", "evalUcast",
            "suggestNarrowing", "signAccessRequest", "verifyAccessRequest", "witnessOf", "coverage", "coverageGate", "minimalFlip",
            "verbShapesFromActionDefs", "verbShapes", "validatePolicyAgainstSchema",
            "policyTestsDoc", "runPolicyTests", "generateBoundaryTests", "decideAll", "signPolicyTests", "verifyPolicyTests",
        }); Assert.Equal(6309, Base.Total(M));
    }
}
