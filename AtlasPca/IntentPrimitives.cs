// The Intent Layer v2 conformance primitives (`primitives.intent_schema`, `intent_revocation`, `intent_world`,
// `intent_provenance`, `intent_classifier`, `intent_wb_active`, `intent_map_commit`, `intent_map`, `intent_read_purpose`): one entry point that answers a primitive's `input` in exactly
// the shape of its `expect`, and the README comparison (reason strings are never compared). Used by the conformance runner,
// the corpus tests, the reason snapshot and the diff-fuzz driver.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentPrimitives
{
    /// <summary>The primitive kinds, in runner order.</summary>
    public static readonly string[] Kinds = { "intent_schema", "intent_revocation", "intent_world", "intent_provenance", "intent_classifier", "intent_wb_active", "intent_map_commit", "intent_map", "intent_read_purpose" };

    /// <summary>The verdict of one primitive in the shape of its <c>expect</c>; null for an unknown kind.</summary>
    public static D? Result(string kind, object? input)
    {
        switch (kind)
        {
            case "intent_schema":
                {
                    var inp = (D)IntentJs.Normalize(input)!;
                    bool sig = ActionSchema.Verify(IntentJs.Get(inp, "schema"), IntentJs.Get(inp, "keys")) == null;
                    var c = ActionSchema.ConformAction(IntentJs.Get(inp, "schema"), IntentJs.Get(inp, "verb") as string ?? "", IntentJs.Get(inp, "params"));
                    var conform = new D { ["ok"] = c.Ok };
                    if (c.Code != null) conform["code"] = c.Code;
                    if (c.Path != null) conform["path"] = c.Path;
                    var o = new D { ["sig"] = sig };
                    if (sig) o["digest"] = ActionSchema.Digest(IntentJs.Get(inp, "schema"));
                    o["conform"] = conform;
                    return o;
                }
            case "intent_revocation":
                return new D { ["ok"] = IntentRevocation.CheckPrimitive(input) };
            case "intent_world":
                {
                    var w = OracleFacts.DecideIntentWorld(input);
                    return w.Ok ? new D { ["ok"] = true, ["world"] = w.World, ["single_source"] = w.SingleSource!.Cast<object?>().ToList() } : new D { ["ok"] = false };
                }
            case "intent_provenance":
                {
                    var p = ParamProvenance.Decide(input);
                    var o = new D { ["outcome"] = p.Outcome };
                    if (p.Outcome != "deny")
                    {
                        if (p.Outcome == "question") o["friction"] = p.Friction;
                        o["labels"] = p.Labels;
                        o["classes"] = p.Classes;
                    }
                    return o;
                }
            case "intent_classifier":
                {
                    var c = IntentClassifier.Decide(input);
                    return c.Ok ? new D { ["ok"] = true, ["classes"] = c.Classes } : new D { ["ok"] = false };
                }
            case "intent_wb_active":
                {
                    var a = IntentWB.Active(input);
                    return new D { ["facts"] = a.Facts, ["provenance"] = a.Provenance, ["classes"] = a.Classes };
                }
            case "intent_read_purpose":
                {
                    var r = ParamProvenance.DecideReadPurpose(input);
                    return new D { ["outcome"] = r.Outcome, ["minimise"] = r.Minimise.Cast<object?>().ToList(), ["uncovered"] = r.Uncovered.Cast<object?>().ToList() };
                }
            case "intent_map_commit":
                return new D { ["map_commit"] = IntentMap.CommitLeaves(IntentJs.Get(input, "leaves")) };
            case "intent_map":
                {
                    var d = IntentMap.DecidePrimitive(input);
                    return d.Ok
                        ? new D { ["ok"] = true, ["cell"] = d.Cell!.Select(x => (object?)IntentJs.OfLong(x)).ToList(), ["p_ppm"] = IntentJs.OfLong(d.PPpm) }
                        : new D { ["ok"] = false };
                }
            default:
                return null;
        }
    }

    /// <summary>The refusal reason of a primitive (null when it passes).</summary>
    public static string? Reason(string kind, object? input)
    {
        switch (kind)
        {
            case "intent_schema":
                {
                    var inp = (D)IntentJs.Normalize(input)!;
                    return ActionSchema.Verify(IntentJs.Get(inp, "schema"), IntentJs.Get(inp, "keys"))
                        ?? ActionSchema.ConformAction(IntentJs.Get(inp, "schema"), IntentJs.Get(inp, "verb") as string ?? "", IntentJs.Get(inp, "params")).Reason;
                }
            case "intent_revocation": return IntentRevocation.PrimitiveReason(input);
            case "intent_world": return OracleFacts.DecideIntentWorld(input).Reason;
            case "intent_provenance": return ParamProvenance.Decide(input).Reason;
            case "intent_classifier": return IntentClassifier.Decide(input).Reason;
            case "intent_map": return IntentMap.DecidePrimitive(input).Reason;
            default: return null;
        }
    }

    /// <summary>The first suite a vector's <c>requires_suite</c> (a string or a list) names that this SDK does not implement, else null.</summary>
    public static string? MissingRequiredSuite(object? requiresSuite) => requiresSuite switch
    {
        string s => Pq.Suites.ContainsKey(s) ? null : s,
        L l => l.OfType<string>().FirstOrDefault(s => !Pq.Suites.ContainsKey(s)),
        _ => null,
    };

    /// <summary>Null when a primitive entry meets its <c>expect</c> under the README comparison (an entry whose
    /// <c>requires_suite</c> this SDK lacks must fail with <c>unsupported_suite</c>; <c>reason_contains</c> is honoured).</summary>
    public static string? Mismatch(string kind, D entry)
    {
        // input_json (raw JSON text, parsed with this SDK's parser) takes precedence over input (it keeps -0)
        var input = IntentJs.Get(entry, "input_json") is string raw ? Pca.ParseJson(raw) : IntentJs.Get(entry, "input");
        var expect = (D)entry["expect"]!;
        var missing = MissingRequiredSuite(IntentJs.Get(entry, "requires_suite"));
        var reason = Reason(kind, input);
        if (missing != null) return reason != null && reason.Contains(IntentJs.UnsupportedSuite) ? null : $"requires_suite {missing}: must fail with unsupported_suite ({reason})";
        var why = Mismatch(kind, input, expect);
        if (why == null && IntentJs.Get(expect, "reason_contains") is string rc && (reason == null || !reason.Contains(rc))) why = $"reason '{reason}' does not contain {rc}";
        return why;
    }

    /// <summary>Null when <paramref name="input"/> meets <paramref name="expect"/> under the README comparison, else what differs.</summary>
    public static string? Mismatch(string kind, object? input, D expect)
    {
        var got = Result(kind, input);
        if (got == null) return "unknown kind";
        bool Eq(string k) => IntentJs.JsonEquals(IntentJs.Get(got, k), IntentJs.Get(expect, k));
        switch (kind)
        {
            case "intent_schema":
                {
                    if (!Eq("sig")) return "sig=" + got["sig"];
                    if (got["sig"] is true && !Eq("digest")) return "digest";
                    var gc = (D)got["conform"]!;
                    var wc = (D)expect["conform"]!;
                    if (!IntentJs.JsonEquals(gc["ok"], IntentJs.Get(wc, "ok"))) return "conform.ok=" + gc["ok"];
                    if (gc["ok"] is false && (!IntentJs.JsonEquals(IntentJs.Get(gc, "code"), IntentJs.Get(wc, "code")) || !IntentJs.JsonEquals(IntentJs.Get(gc, "path"), IntentJs.Get(wc, "path"))))
                        return "conform.code/path=" + IntentJs.Get(gc, "code") + "/" + IntentJs.Get(gc, "path");
                    return null;
                }
            case "intent_world":
                if (!Eq("ok")) return "ok=" + got["ok"];
                return got["ok"] is true && (!Eq("world") || !Eq("single_source")) ? "world / single_source" : null;
            case "intent_provenance":
                if (!Eq("outcome")) return "outcome=" + got["outcome"];
                if (got["outcome"] as string == "deny") return null;
                if (!Eq("labels") || !Eq("classes")) return "labels / classes";
                return got["outcome"] as string == "question" && !Eq("friction") ? "friction=" + got["friction"] : null;
            case "intent_classifier":
                if (!Eq("ok")) return "ok=" + got["ok"];
                return got["ok"] is true && !Eq("classes") ? "classes" : null;
            case "intent_wb_active":
                return Eq("facts") && Eq("provenance") && Eq("classes") ? null : $"active={got["facts"]},{got["provenance"]},{got["classes"]}";
            case "intent_read_purpose":
                return Eq("outcome") && Eq("minimise") && Eq("uncovered") ? null : $"outcome={got["outcome"]}";
            case "intent_map_commit":
                return Eq("map_commit") ? null : "map_commit=" + got["map_commit"];
            case "intent_map":
                if (!Eq("ok")) return "ok=" + got["ok"];
                return got["ok"] is true && (!Eq("cell") || !Eq("p_ppm")) ? "cell / p_ppm" : null;
            default:
                return Eq("ok") ? null : "ok=" + got["ok"];
        }
    }
}
