using static AtlasPca.PolicyBridgeKit.PbJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>OpenFGA / Zanzibar ReBAC model and tuples to PCA predicates: one permit per (user, object, relation) triple that holds, evaluated at
/// translation time over the whole tuple set (direct, computedUserset, union, intersection, difference and tupleToUserset, bounded and cycle-guarded).
/// Userset-valued tuples are reported and not expanded; anything unmodeled grants nothing.</summary>
public static class OpenFga
{
    const int MaxDepth = 32;

    /// <summary>A translation with no tuples argument (the reference's undefined).</summary>
    public static D OpenfgaToPca(object? model) => Translate(model, null, false);

    /// <summary>A translation over <paramref name="tuples"/>; anything but a list is an error (the reference's null).</summary>
    public static D OpenfgaToPca(object? model, object? tuples) => Translate(model, tuples, true);

    // ---- resolution plan ----

    enum PK { Direct, Computed, Union, Intersection, Difference, Ttu }

    sealed class Plan(PK kind)
    {
        public readonly PK Kind = kind;
        public string Relation = "", Tupleset = "", Computed = "";
        public List<Plan> Children = new();
        public Plan? Base, Subtract;
    }

    sealed record Built(bool Ok, Plan? Plan, bool Partial, string? Reason)
    {
        public static Built Fail(string reason) => new(false, null, false, reason);
    }

    sealed record Tuple(string User, string Relation, string Object);

    static string DescribePlan(Plan plan) => plan.Kind switch
    {
        PK.Direct => "direct",
        PK.Computed => "computed " + plan.Relation,
        PK.Union => "union[" + string.Join(", ", plan.Children.Select(DescribePlan)) + "]",
        PK.Intersection => "intersection[" + string.Join(", ", plan.Children.Select(DescribePlan)) + "]",
        PK.Difference => "difference(" + DescribePlan(plan.Base!) + " - " + DescribePlan(plan.Subtract!) + ")",
        _ => plan.Computed + " from " + plan.Tupleset,
    };

    static bool HasOwn(object? o, string k) => o is D m && m.ContainsKey(k);
    static object? Get(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : null;
    static bool IsRewrite(object? v) => v is D || v is L;

    static L? ChildNodes(object? container) => Get(container, "child") as L;

    /// <summary>The <c>.relation</c> string of a <c>{ relation }</c> object, or null.</summary>
    static string? RelationOf(object? v) => Get(v, "relation") is string rel && rel.Length > 0 ? rel : null;

    static Built BuildPlan(object? node)
    {
        if (HasOwn(node, "this")) return new Built(true, new Plan(PK.Direct), false, null);

        if (HasOwn(node, "computedUserset"))
        {
            var rel = RelationOf(Get(node, "computedUserset"));
            if (rel == null) return Built.Fail("computedUserset without a relation");
            return new Built(true, new Plan(PK.Computed) { Relation = rel }, false, null);
        }

        if (HasOwn(node, "union"))
        {
            var children = ChildNodes(Get(node, "union"));
            if (children == null) return Built.Fail("union without children");
            var subs = new List<Plan>();
            bool partial = false;
            foreach (var child in children)
            {
                if (!IsRewrite(child)) { partial = true; continue; }
                var sub = BuildPlan(child);
                if (!sub.Ok || sub.Plan == null) { partial = true; continue; }
                if (sub.Partial) partial = true;
                subs.Add(sub.Plan);
            }
            if (subs.Count == 0) return new Built(false, null, partial, "union with no modeled children");
            return new Built(true, new Plan(PK.Union) { Children = subs }, partial, null);
        }

        if (HasOwn(node, "intersection"))
        {
            var children = ChildNodes(Get(node, "intersection"));
            if (children == null) return Built.Fail("intersection without children");
            var subs = new List<Plan>();
            foreach (var child in children)
            {
                if (!IsRewrite(child)) return Built.Fail("intersection child is not a rewrite");
                var sub = BuildPlan(child);
                if (!sub.Ok || sub.Plan == null) return Built.Fail("intersection child unmodeled (" + (sub.Reason ?? "unsupported") + ")");
                subs.Add(sub.Plan);
            }
            if (subs.Count == 0) return Built.Fail("intersection with no children");
            return new Built(true, new Plan(PK.Intersection) { Children = subs }, false, null);
        }

        if (HasOwn(node, "difference"))
        {
            var diff = Get(node, "difference");
            if (!IsRewrite(diff)) return Built.Fail("malformed difference");
            var baseNode = Get(diff, "base"); var subNode = Get(diff, "subtract");
            if (!IsRewrite(baseNode) || !IsRewrite(subNode)) return Built.Fail("difference needs both base and subtract");
            var bas = BuildPlan(baseNode);
            var subtract = BuildPlan(subNode);
            if (!bas.Ok || bas.Plan == null) return Built.Fail("difference base unmodeled (" + (bas.Reason ?? "?") + ")");
            if (!subtract.Ok || subtract.Plan == null) return Built.Fail("difference subtract unmodeled (" + (subtract.Reason ?? "?") + ")");
            return new Built(true, new Plan(PK.Difference) { Base = bas.Plan, Subtract = subtract.Plan }, bas.Partial || subtract.Partial, null);
        }

        if (HasOwn(node, "tupleToUserset"))
        {
            var ttu = Get(node, "tupleToUserset");
            if (!IsRewrite(ttu)) return Built.Fail("malformed tupleToUserset");
            var tuplesetRel = RelationOf(Get(ttu, "tupleset"));
            var computedRel = RelationOf(Get(ttu, "computedUserset"));
            if (tuplesetRel == null) return Built.Fail("tupleToUserset without a tupleset relation");
            if (computedRel == null) return Built.Fail("tupleToUserset without a computedUserset relation");
            return new Built(true, new Plan(PK.Ttu) { Tupleset = tuplesetRel, Computed = computedRel }, false, null);
        }

        return Built.Fail("unknown rewrite node");
    }

    // ---- model / tuple parsing ----

    /// <summary>type to (relation to rewrite node), in the reference's iteration order; null when the model is unusable.</summary>
    static List<KeyValuePair<string, List<KeyValuePair<string, object?>>>>? ParseModel(object? model, D report)
    {
        if (!IsRewrite(model))
        {
            PolicyBridge.ListOf(report, "errors").Add("model is not an object");
            return null;
        }
        if (Get(model, "type_definitions") is not L defs)
        {
            PolicyBridge.ListOf(report, "errors").Add("model.type_definitions is missing or not an array");
            return null;
        }
        // a later definition of the same type replaces the earlier one in place (Map.set semantics)
        var order = new List<string>();
        var byType = new Dictionary<string, List<KeyValuePair<string, object?>>>(StringComparer.Ordinal);
        foreach (var def in defs)
        {
            if (!IsRewrite(def)) continue;
            if (Get(def, "type") is not string type || type.Length == 0) continue;
            var relMap = new List<KeyValuePair<string, object?>>();
            var rels = Entries(Get(def, "relations"));
            if (rels != null) foreach (var e in rels) if (IsRewrite(e.Value)) relMap.Add(e);
            if (!byType.ContainsKey(type)) order.Add(type);
            byType[type] = relMap;
        }
        return order.Select(t => new KeyValuePair<string, List<KeyValuePair<string, object?>>>(t, byType[t])).ToList();
    }

    static List<Tuple> ParseTuples(object? tuples, bool given, D report)
    {
        if (tuples is not L tl)
        {
            if (given) PolicyBridge.ListOf(report, "errors").Add("tuples is not an array");
            return new List<Tuple>();
        }
        var outp = new List<Tuple>();
        foreach (var t in tl)
        {
            if (t is not D m) continue;
            if (m.GetValueOrDefault("user") is string user && m.GetValueOrDefault("relation") is string relation && m.GetValueOrDefault("object") is string obj)
                outp.Add(new Tuple(user, relation, obj));
        }
        return outp;
    }

    static bool IsWildcard(string user) => user.EndsWith(":*", StringComparison.Ordinal) && user.Length > 2 && user.IndexOf('#') < 0;

    static string EscapeGlob(string t)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in t)
        {
            if (c == '*' || c == '?' || c == '\\') sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    static string TypeOf(string obj) { int i = obj.IndexOf(':'); return i < 0 ? obj : obj[..i]; }
    static string ObjectOfUserset(string p) { int i = p.IndexOf('#'); return i < 0 ? p : p[..i]; }
    static string Key(string a, string b) => a + "\0" + b;

    // ---- translation ----

    static D Translate(object? model, object? tuples, bool tuplesGiven)
    {
        var report = PolicyBridge.NewReport("openfga");
        var predicates = new L();

        var typeRelations = ParseModel(model, report);
        var tupleList = ParseTuples(tuples, tuplesGiven, report);
        if (typeRelations == null) return PolicyBridge.Result(predicates, new L(), report);

        var direct = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var usersSeen = new HashSet<string>(StringComparer.Ordinal);
        var wildcardTypes = new HashSet<string>(StringComparer.Ordinal);
        var objectsSeen = new HashSet<string>(StringComparer.Ordinal);
        int usersetTuples = 0;
        foreach (var t in tupleList)
        {
            objectsSeen.Add(t.Object);
            var k = Key(t.Object, t.Relation);
            if (!direct.TryGetValue(k, out var set)) direct[k] = set = new List<string>();
            if (!set.Contains(t.User)) set.Add(t.User);
            if (t.User.IndexOf('#') >= 0) usersetTuples++;
            else if (IsWildcard(t.User)) wildcardTypes.Add(t.User[..^2]);
            else usersSeen.Add(t.User);
        }
        if (usersetTuples > 0)
            PolicyBridge.ListOf(report, "skipped").Add(usersetTuples + " userset-valued tuple(s) (user contains '#') not expanded to concrete users");

        var plans = new Dictionary<string, Plan>(StringComparer.Ordinal);
        foreach (var te in typeRelations)
            foreach (var re in te.Value)
            {
                var type = te.Key; var relation = re.Key;
                var built = BuildPlan(re.Value);
                if (!built.Ok || built.Plan == null)
                {
                    PolicyBridge.ListOf(report, "skipped").Add("relation " + type + "#" + relation + ": " + (built.Reason ?? "unsupported rewrite") + " — skipped");
                    continue;
                }
                if (built.Partial)
                    PolicyBridge.ListOf(report, "skipped").Add("relation " + type + "#" + relation + ": some union children unsupported and dropped (under-approximated)");
                plans[Key(type, relation)] = built.Plan;
                PolicyBridge.ListOf(report, "translated").Add("relation " + type + "#" + relation + " (" + DescribePlan(built.Plan) + ")");
            }

        var ev = new Evaluator(direct, plans);

        var sortedUsers = usersSeen.OrderBy(x => x, StringComparer.Ordinal).ToList();
        var sortedObjects = objectsSeen.OrderBy(x => x, StringComparer.Ordinal).ToList();
        var sortedWildcards = wildcardTypes.OrderBy(x => x, StringComparer.Ordinal).ToList();
        var relationsByType = typeRelations.ToDictionary(e => e.Key, e => e.Value, StringComparer.Ordinal);
        foreach (var obj in sortedObjects)
        {
            var type = TypeOf(obj);
            if (!relationsByType.TryGetValue(type, out var relations))
            {
                PolicyBridge.ListOf(report, "skipped").Add("object " + obj + ": type \"" + type + "\" not defined in model — ignored");
                continue;
            }
            foreach (var relation in relations.Select(r => r.Key).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (!plans.ContainsKey(Key(type, relation))) continue;
                foreach (var user in sortedUsers)
                {
                    if (ev.HoldsRel(user, obj, relation, 0, new HashSet<string>(StringComparer.Ordinal)))
                        predicates.Add(Obj("verb", relation, "resource", obj, "where", new L { Obj("field", "subject.id", "op", "eq", "value", user) }));
                }
                // A public tuple (`type:*`) grants every subject of that type, including ones no tuple names; decide for a subject that no tuple
                // names. The named ones were decided above (a difference or intersection may exclude them).
                foreach (var wtype in sortedWildcards)
                {
                    if (!ev.HoldsRel(wtype + ":\0anyone", obj, relation, 0, new HashSet<string>(StringComparer.Ordinal))) continue;
                    var named = new L();
                    foreach (var u in sortedUsers) if (TypeOf(u) == wtype) named.Add(u);
                    var where = new L { Obj("field", "subject.id", "op", "like", "value", EscapeGlob(wtype) + ":*") };
                    if (named.Count > 0) where.Add(Obj("not", Obj("field", "subject.id", "op", "in", "value", named)));
                    predicates.Add(Obj("verb", relation, "resource", obj, "where", where));
                }
            }
        }

        return PolicyBridge.Result(predicates, new L(), report);
    }

    /// <summary>Bounded, cycle-guarded evaluation of the plans over the direct tuples.</summary>
    sealed class Evaluator(Dictionary<string, List<string>> direct, Dictionary<string, Plan> plans)
    {
        public bool HoldsRel(string user, string obj, string relation, int depth, HashSet<string> visited)
        {
            var k = Key(obj, relation);
            if (depth > MaxDepth || visited.Contains(k)) return false;
            if (!plans.TryGetValue(Key(TypeOf(obj), relation), out var plan)) return false;
            var next = new HashSet<string>(visited, StringComparer.Ordinal) { k };
            return EvalPlan(user, obj, relation, plan, depth, next);
        }

        bool EvalPlan(string user, string obj, string relation, Plan plan, int depth, HashSet<string> visited)
        {
            switch (plan.Kind)
            {
                case PK.Direct:
                    return direct.TryGetValue(Key(obj, relation), out var set) && (set.Contains(user) || set.Contains(TypeOf(user) + ":*"));
                case PK.Computed:
                    return HoldsRel(user, obj, plan.Relation, depth + 1, visited);
                case PK.Union:
                    foreach (var c in plan.Children) if (EvalPlan(user, obj, relation, c, depth, visited)) return true;
                    return false;
                case PK.Intersection:
                    foreach (var c in plan.Children) if (!EvalPlan(user, obj, relation, c, depth, visited)) return false;
                    return true;
                case PK.Difference:
                    return EvalPlan(user, obj, relation, plan.Base!, depth, visited) && !EvalPlan(user, obj, relation, plan.Subtract!, depth, visited);
                default:
                {
                    if (!direct.TryGetValue(Key(obj, plan.Tupleset), out var related)) return false;
                    foreach (var p in related) if (HoldsRel(user, ObjectOfUserset(p), plan.Computed, depth + 1, visited)) return true;
                    return false;
                }
            }
        }
    }
}
