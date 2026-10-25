// The W-B checks of an Intent Layer v2 verifier (packages/pca/src/intent-env.ts decideIntentWB), mirroring IntentWB.java:
// rules 16 (`facts`), 17 (`provenance`) and 18 (`classes`) in that order. Each is REPORTED only when its member is present
// or its policy is active; the first failing check denies and later checks are not reported. A rule-17 `question`
// continues (outcome `question`). Never throws on well-typed input.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentWB
{
    /// <summary>The W-B result. <c>Checks</c>: insertion order facts, provenance, classes; values pass / question / fail.</summary>
    public sealed class Result
    {
        public string Outcome { get; internal set; } = "admit";
        public List<KeyValuePair<string, string>> Checks { get; } = new();
        public D? World { get; internal set; }
        public D? Prov { get; internal set; }
        public D? Class { get; internal set; }
        public string? Reason { get; internal set; }
        public string? Friction { get; internal set; }
        public List<string>? SingleSource { get; internal set; }
        public string? Check(string name) => Checks.Where(c => c.Key == name).Select(c => c.Value).FirstOrDefault();
    }

    /// <summary>Run rules 16-18 over <c>{now, aud, session, action, intent_session, artifacts?, policy}</c> (already normalized).</summary>
    public static Result Decide(D input)
    {
        var output = new Result();
        var ce = ContextError(input);
        if (ce != null) return Deny(output, "facts", "facts: the W-B context is malformed: " + ce);
        var s = input["intent_session"];
        var a = (D)IntentJs.Opt(input, "artifacts", new D())!;
        var policy = IntentJs.Opt(input, "policy", new D());
        var worldPolicy = IntentJs.Opt(policy, "world", new D());

        var committed = new D();
        if (IntentJs.Own(s, "facts")) committed["facts"] = IntentJs.Get(s, "facts");
        if (IntentJs.Own(s, "offer_set")) committed["offer_set"] = IntentJs.Get(s, "offer_set");
        if (OracleFacts.IntentWorldActive(committed, worldPolicy))
        {
            var wi = new D
            {
                ["now"] = IntentJs.Get(input, "now"), ["session"] = IntentJs.Get(input, "session"),
                ["action"] = IntentJs.Get(input, "action"), ["committed"] = committed,
            };
            if (input.ContainsKey("aud")) wi["aud"] = input["aud"]; // an absent aud stays absent (the reference prints it as 'undefined')
            if (a.ContainsKey("facts")) wi["facts"] = a["facts"];
            if (a.ContainsKey("offer_set")) wi["offer_set"] = a["offer_set"];
            wi["policy"] = worldPolicy;
            var w = OracleFacts.Decide(wi);
            if (!w.Ok) return Deny(output, "facts", w.Reason);
            output.Checks.Add(new("facts", "pass"));
            output.World = w.World;
            if (w.SingleSource!.Count > 0) output.SingleSource = w.SingleSource;
        }
        if (ProvenanceActive(s, policy))
        {
            var pi = new D { ["session"] = IntentJs.Get(input, "session"), ["action"] = IntentJs.Get(input, "action") };
            if (input.ContainsKey("aud")) pi["aud"] = input["aud"];
            if (IntentJs.Own(s, "prov")) pi["prov"] = IntentJs.Get(s, "prov");
            if (IntentJs.Own(s, "labels")) pi["committed_labels"] = IntentJs.Get(s, "labels");
            if (a.ContainsKey("labels")) pi["labels"] = a["labels"];
            pi["policy"] = IntentJs.Opt(policy, "provenance", new D { ["params"] = new D() });
            var p = ParamProvenance.Decide(pi);
            if (p.Outcome == "deny") return Deny(output, "provenance", p.Reason);
            output.Checks.Add(new("provenance", p.Outcome == "question" ? "question" : "pass"));
            output.Prov = p.Env;
            if (p.Outcome == "question")
            {
                output.Outcome = "question";
                output.Reason = p.Reason;
                output.Friction = p.Friction;
            }
        }
        var clsPolicy = new D { ["classifiers"] = IntentJs.Opt(policy, "classifiers", new L()) };
        var committedClasses = IntentJs.Get(s, "classes");
        if (IntentClassifier.ClassifierCheckActive(committedClasses, clsPolicy))
        {
            var ci = new D { ["session"] = IntentJs.Get(input, "session"), ["action"] = IntentJs.Get(input, "action") };
            if (IntentJs.Own(s, "classes")) ci["committed"] = committedClasses;
            if (a.ContainsKey("verdicts")) ci["verdicts"] = a["verdicts"];
            ci["policy"] = clsPolicy;
            var c = IntentClassifier.Decide(ci);
            if (!c.Ok) return Deny(output, "classes", c.Reason);
            output.Checks.Add(new("classes", "pass"));
            output.Class = c.Classes;
        }
        return output;
    }

    /// <summary>The W-B context (absent = empty; present with null or the wrong JSON type = malformed; closed member sets).</summary>
    internal static string? ContextError(D input)
    {
        if (IntentJs.Get(input, "intent_session") is not D) return "intent_session must be an object";
        if (input.ContainsKey("artifacts"))
        {
            if (input["artifacts"] is not D a) return "artifacts must be an object";
            var am = IntentArtifacts.ClosedMembers(a, Array.Empty<string>(), new[] { "facts", "labels", "verdicts", "offer_set" }, "artifacts");
            if (am != null) return am;
            foreach (var k in new[] { "facts", "labels", "verdicts" }) if (a.ContainsKey(k) && a[k] is not L) return $"artifacts.{k} must be an array";
            if (a.ContainsKey("offer_set") && a["offer_set"] is not D) return "artifacts.offer_set must be an object";
        }
        if (input.ContainsKey("policy"))
        {
            if (input["policy"] is not D p) return "policy must be an object";
            var pm = IntentArtifacts.ClosedMembers(p, Array.Empty<string>(), new[] { "world", "provenance", "classifiers" }, "policy");
            if (pm != null) return pm;
            foreach (var k in new[] { "world", "provenance" }) if (p.ContainsKey(k) && p[k] is not D) return $"policy.{k} must be an object";
            if (p.ContainsKey("classifiers") && p["classifiers"] is not L) return "policy.classifiers must be an array";
        }
        return null;
    }

    /// <summary>Rule 17 is active iff <c>prov</c> is present (any value), <c>labels</c> a non-empty array, or the policy a plain object.</summary>
    public static bool ProvenanceActive(object? intentSession, object? policy) =>
        IntentJs.Own(intentSession, "prov") || OracleFacts.NonEmpty(IntentJs.Get(intentSession, "labels")) || IntentJs.Get(policy, "provenance") is D;

    /// <summary>The <c>primitives.intent_wb_active</c> entry point: which of facts / provenance / classes are reported.</summary>
    public static (bool Facts, bool Provenance, bool Classes) Active(object? input)
    {
        var inp = (D)IntentJs.Normalize(input)!;
        var s = IntentJs.Opt(inp, "intent_session", new D());
        var p = IntentJs.Opt(inp, "policy", new D());
        var committed = new D();
        if (IntentJs.Own(s, "facts")) committed["facts"] = IntentJs.Get(s, "facts");
        if (IntentJs.Own(s, "offer_set")) committed["offer_set"] = IntentJs.Get(s, "offer_set");
        return (OracleFacts.IntentWorldActive(committed, IntentJs.Opt(p, "world", new D())), ProvenanceActive(s, p),
            IntentClassifier.ClassifierCheckActive(IntentJs.Get(s, "classes"), new D { ["classifiers"] = IntentJs.Get(p, "classifiers") }));
    }

    static Result Deny(Result output, string check, string? reason)
    {
        output.Outcome = "deny";
        output.Checks.Add(new(check, "fail"));
        output.Reason = reason;
        output.World = null;
        output.Prov = null;
        output.Class = null;
        output.Friction = null;
        output.SingleSource = null;
        return output;
    }
}
