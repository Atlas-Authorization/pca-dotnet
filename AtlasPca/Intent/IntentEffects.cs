// Outcome verification: postconditions on observed effects. A postcondition is a set of conditions in the ordinary predicate language over
// the requested action (action.params.*, action.resource) and the observed effect at env.effect.*, evaluated by the one evaluator. A clause
// whose ref names an action parameter the action does not carry is not applicable and is skipped. Results: ok, violated (a negative runtime
// observation), pending (the effect record lacks a field a clause reads).
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentEffects
{
    static D Leaf(string field, string op, string? reference, object? value)
    {
        var m = new D { ["field"] = "env.effect." + field, ["op"] = op };
        if (reference != null) m["ref"] = reference;
        else m["value"] = value;
        return m;
    }

    static D Pc(string id, string verb, string description, params D[] where) => new() { ["id"] = id, ["verb"] = verb, ["description"] = description, ["where"] = where.Select(x => (object?)x).ToList() };

    static readonly Num Zero = new("0");

    /// <summary>Postconditions for the built-in connectors' state-changing verbs.</summary>
    public static readonly IReadOnlyList<D> DefaultPostconditions = new List<D>
    {
        Pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", Leaf("amount", "lte", "action.params.amount", null), Leaf("amount", "gte", null, Zero)),
        Pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", Leaf("recipient", "eq", "action.params.recipient", null)),
        Pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", Leaf("amount", "lte", "action.params.amount", null), Leaf("amount", "gte", null, Zero)),
        Pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", Leaf("amount", "lte", "action.params.amount", null), Leaf("amount", "gte", null, Zero)),
        Pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", Leaf("recipient", "eq", "action.params.recipient", null)),
        Pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", Leaf("to", "eq", "action.params.to", null)),
        Pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", Leaf("channel", "eq", "action.params.channel", null)),
        Pc("files.write.path", "files.write", "the written path is the requested resource", Leaf("path", "eq", "action.resource", null)),
        Pc("files.delete.path", "files.delete", "the deleted path is the requested resource", Leaf("path", "eq", "action.resource", null)),
        Pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", Leaf("repo", "eq", "action.resource", null)),
        Pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", Leaf("hour", "eq", "env.hour", null)),
    };

    static object? Get(object? o, string k) => o is D m ? m.GetValueOrDefault(k) : null;
    static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);

    static void Leaves(object? c, List<(string Field, string? Ref)> o)
    {
        if (c is not D) return;
        if (Has(c, "all_of") || Has(c, "any_of") || Has(c, "not"))
        {
            if (Has(c, "all_of") && Get(c, "all_of") is L a) foreach (var x in a) Leaves(x, o);
            else if (Has(c, "any_of") && Get(c, "any_of") is L b) foreach (var x in b) Leaves(x, o);
            else if (Has(c, "not")) Leaves(Get(c, "not"), o);
            return;
        }
        if (Get(c, "field") is string f) o.Add((f, Get(c, "ref") as string));
    }

    /// <summary>Is the dotted path an own member chain of the context (undefined = not found)?</summary>
    static bool Defined(object? root, string path)
    {
        var cur = root;
        foreach (var k in path.Split('.'))
        {
            if (cur is not D m || !m.TryGetValue(k, out var next)) return false;
            cur = next;
        }
        return true;
    }

    /// <summary>The evaluator's context for an action plus its observed effect.</summary>
    public static D EffectContext(VerbSpace vs, Outcome o, D effect)
    {
        var a = IntentPolicyKit.OutcomeToAction(vs, o);
        var action = new D
        {
            ["verb"] = a["verb"], ["resource"] = a["resource"], ["params"] = IntentRuntime.JsonNums(a.GetValueOrDefault("params")), ["reversibility_class"] = vs.Reversibility,
        };
        var ctx = new D { ["action"] = action };
        if (a.GetValueOrDefault("subject") != null) ctx["subject"] = IntentRuntime.JsonNums(a["subject"]);
        var env = new D();
        if (a.GetValueOrDefault("env") != null) foreach (var e in Obj(IntentRuntime.JsonNums(a["env"]))) env[e.Key] = e.Value;
        env["effect"] = effect;
        ctx["env"] = env;
        return ctx;
    }

    /// <summary>{status, violated, missing, checked, notApplicable}.</summary>
    public static D CheckPostconditions(VerbSpace vs, Outcome o, D effect, IEnumerable<object?>? pcs = null)
    {
        pcs ??= DefaultPostconditions;
        var ctx = EffectContext(vs, o, effect);
        var violated = new List<string>();
        var checkedIds = new List<string>();
        var notApplicable = new List<string>();
        var missing = new List<string>();
        foreach (var pc in pcs)
        {
            if (o.Verb != (Get(pc, "verb") as string)) continue;
            var ls = new List<(string Field, string? Ref)>();
            foreach (var c in (L)Get(pc, "where")!) Leaves(c, ls);
            bool na = false;
            foreach (var l in ls) if (l.Ref != null && !l.Ref.StartsWith("env.effect.", StringComparison.Ordinal) && !Defined(ctx, l.Ref)) na = true;
            if (na) { notApplicable.Add((string)Get(pc, "id")!); continue; }
            var need = new List<string>();
            foreach (var l in ls)
            {
                if (l.Field.StartsWith("env.effect.", StringComparison.Ordinal) && !need.Contains(l.Field)) need.Add(l.Field);
                if (l.Ref != null && l.Ref.Length > 0 && l.Ref.StartsWith("env.effect.", StringComparison.Ordinal) && !need.Contains(l.Ref)) need.Add(l.Ref);
            }
            var lacking = need.Where(f => !Defined(ctx, f)).ToList();
            if (lacking.Count > 0) { missing.AddRange(lacking); continue; }
            checkedIds.Add((string)Get(pc, "id")!);
            var pred = new D { ["verb"] = o.Verb, ["resource"] = "*", ["where"] = Get(pc, "where") };
            if (!Predicates.EvaluatePredicates(new L { pred }, ctx)) violated.Add((string)Get(pc, "id")!);
        }
        var miss = new SortedSet<string>(missing, StringComparer.Ordinal).ToList();
        return new D
        {
            ["status"] = violated.Count > 0 ? "violated" : miss.Count > 0 ? "pending" : "ok",
            ["violated"] = violated.Select(x => (object?)x).ToList(),
            ["missing"] = miss.Select(x => (object?)x).ToList(),
            ["checked"] = checkedIds.Select(x => (object?)x).ToList(),
            ["notApplicable"] = notApplicable.Select(x => (object?)x).ToList(),
        };
    }
}
