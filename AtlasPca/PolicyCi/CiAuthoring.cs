// Authoring gates built on the analyzer, for CI: diff (does a change widen authority or raise the most that can leave?), test (a policy test
// document against a policy, pinned by digest) and coverage (which clauses and thresholds the tests or traffic never exercise, and which mutations
// they cannot tell apart). Each returns {ok, exitCode, lines}: the lines to print and an exit code (0 ok, 1 a gate failed, 2 unusable input).
// None of them signs or changes anything.
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.PolicyCi.CiJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

public static class CiAuthoring
{
    static D Result(bool ok, int exitCode, L lines) => Obj(("ok", ok), ("exitCode", N(exitCode)), ("lines", lines));
    static D Bad(string line) => Result(false, 2, new L { line });

    /// <summary>A policy document as the analyzer reads it: any shape lint accepts, plus optional <c>vetoes</c> and <c>tighten</c> members.</summary>
    public static D ToAnalyzerPolicy(object? doc)
    {
        var n = CiNormalize.NormalizePolicyInput(doc);
        if (n["ok"] is not true) return n;
        var np = (D)n["policy"]!;
        var policy = Obj(("predicates", np["predicates"]), ("caveats", np["caveats"]));
        if (doc is D)
        {
            if (G(doc, "vetoes") is L v) policy["vetoes"] = v;
            if (G(doc, "tighten") is L t) policy["tighten"] = t;
        }
        return Obj(("ok", true), ("policy", policy));
    }

    /// <summary><c>diff</c>: options allowWiden, verb, amountField, integer, windowSecs, maxExposureIncrease.</summary>
    public static D DiffCommand(object? oldDoc, object? newDoc, object? o = null)
    {
        o ??= new D();
        var a = ToAnalyzerPolicy(oldDoc);
        var b = ToAnalyzerPolicy(newDoc);
        if (a["ok"] is not true) return Bad($"old policy: {Str(a["reason"])}");
        if (b["ok"] is not true) return Bad($"new policy: {Str(b["reason"])}");
        var dopts = new D();
        var verb = Jx.Prop(o, "verb");
        if (!Jx.IsUndef(verb))
        {
            var ex = Obj(("verb", verb));
            var af = Jx.Prop(o, "amountField"); if (Truthy(af)) ex["amountField"] = af;
            if (Truthy(Jx.Prop(o, "integer"))) ex["integer"] = true;
            var ws = Jx.Prop(o, "windowSecs"); if (!Jx.IsUndef(ws)) ex["windowSecs"] = ws;
            dopts["exposure"] = ex;
        }
        var d = Exposure.DiffPolicies(a["policy"], b["policy"], dopts);
        var allow = Obj(("widen", Jx.Prop(o, "allowWiden") is true));
        var mei = Jx.Prop(o, "maxExposureIncrease"); if (!Jx.IsUndef(mei)) allow["maxExposureIncrease"] = mei;
        var gate = Exposure.DiffGate(d, allow);
        var gateOk = gate["ok"] is true;
        var summary = (L)d["summary"]!;
        var lines = d["equivalent"] is true ? new L { "no change in what is admitted" } : summary.Count > 0 ? new L(summary) : new L { "no witness found" };
        if (!gateOk) foreach (var r in (L)gate["reasons"]!) lines.Add($"FAIL: {Str(r)}");
        lines.Add(gateOk ? "PASS" : "FAIL");
        return Result(gateOk, gateOk ? 0 : 1, lines);
    }

    /// <summary><c>test</c>: a policy test document run against a policy; option requireDigest.</summary>
    public static D TestCommand(object? policyDoc, object? testsDoc, object? o = null)
    {
        o ??= new D();
        var p = ToAnalyzerPolicy(policyDoc);
        if (p["ok"] is not true) return Bad($"policy: {Str(p["reason"])}");
        if (testsDoc is not D || !(G(testsDoc, "kind") is string k && k == "pca-policy-tests") || G(testsDoc, "cases") is not L) return Bad("tests: not a pca-policy-tests document");
        var opts = new D();
        var rd = Jx.Prop(o, "requireDigest"); if (!Jx.IsUndef(rd)) opts["requireDigest"] = rd;
        var r = AtlasPca.Analyzer.TestRunner.RunPolicyTests(p["policy"], testsDoc, opts);
        var lines = new L();
        foreach (var fo in (L)r["failures"]!)
        {
            var f = (D)fo!;
            var by = Jx.Prop(f, "expectedDecidedBy");
            var got = f["decidedBy"];
            lines.Add($"FAIL {Str(Jx.Prop(f, "name"))}: expected {Str(Jx.Prop(f, "expected"))}{(Truthy(by) ? " by " + Str(by) : "")}, got {Str(f["got"])} by {(got != null ? Str(got) : "no clause")}");
        }
        if (r["digestMatch"] is not true) lines.Add($"{(Truthy(rd) && !Jx.IsUndef(rd) ? "FAIL" : "note")}: the policy differs from the one the examples were confirmed against");
        var ok = r["ok"] is true;
        lines.Add($"{Str(r["passed"])}/{Str(r["total"])} examples {(ok ? "PASS" : "FAIL")}");
        return Result(ok, ok ? 0 : 1, lines);
    }

    /// <summary><c>coverage</c>: options minClauses, minBoundaries, minMutation, maxSurvivors.</summary>
    public static D CoverageCommand(object? policyDoc, object? trafficDoc, object? o = null)
    {
        o ??= new D();
        var p = ToAnalyzerPolicy(policyDoc);
        if (p["ok"] is not true) return Bad($"policy: {Str(p["reason"])}");
        // traffic: an array of actions, or a pca-policy-tests document (its cases are the traffic)
        L? actions = trafficDoc as L;
        if (actions == null && trafficDoc is D && G(trafficDoc, "cases") is L cases) actions = new L(cases.Select(c => c is D ? G(c, "action") : c));
        if (actions == null || actions.Any(a => a is not D || G(a, "verb") is not string || G(a, "resource") is not string))
            return Bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document");
        var r = AtlasPca.Analyzer.Coverage.Compute(p["policy"], actions);
        var th = new D();
        void Th(string src, string dst) { var v = Jx.Prop(o, src); if (!Jx.IsUndef(v)) th[dst] = v; }
        Th("minClauses", "clauses"); Th("minBoundaries", "boundaries"); Th("minMutation", "mutation"); Th("maxSurvivors", "maxSurvivors");
        var gate = AtlasPca.Analyzer.Coverage.Gate(r, th);
        var score = (D)r["score"]!; var mutants = (D)r["mutants"]!;
        string Pct(string k) => ToFixed(Jx.ToNumber(score[k]) * 100, 0);
        var lines = new L
        {
            $"clauses decisive {Pct("clauses")}%, boundaries covered {Pct("boundaries")}%, mutants killed {Pct("mutation")}% ({Str(mutants["killed"])}/{NumStr(Jx.ToNumber(mutants["total"]) - Jx.ToNumber(mutants["equivalent"]))})",
        };
        foreach (var id in (L)r["untested"]!) lines.Add($"untested: {Str(id)}");
        foreach (var mo in (L)mutants["survivors"]!)
        {
            var m = (D)mo!;
            var killer = m.GetValueOrDefault("killer");
            lines.Add($"survives: {Str(m["description"])}{(Truthy(killer) ? $" (kill with {Stringify(killer)})" : "")}");
        }
        foreach (var x in (L)gate["reasons"]!) lines.Add($"FAIL: {Str(x)}");
        var ok = gate["ok"] is true;
        lines.Add(ok ? "PASS" : "FAIL");
        return Result(ok, ok ? 0 : 1, lines);
    }
}
