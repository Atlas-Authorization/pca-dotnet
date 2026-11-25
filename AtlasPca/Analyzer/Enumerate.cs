using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>The analyzable form of a policy: its predicates, caveats, vetoes, tighten rules and meet-composed parents, plus what the
/// caveats and conditions let the engine decide exactly.</summary>
public sealed class PolicyModel
{
    public L Predicates { get; init; } = new();
    public L Caveats { get; init; } = new();
    public L Vetoes { get; init; } = new();
    public L Tighten { get; init; } = new();
    public List<PolicyModel> Meets { get; init; } = new();
    public bool CaveatSat { get; set; }
    public string? CaveatReason { get; set; }
    public int? RevCap { get; set; }
    public List<string> Undecidable { get; set; } = new();

    public PolicyModel WithVetoes(L vetoes) => new()
    {
        Predicates = Predicates, Caveats = Caveats, Vetoes = vetoes, Tighten = Tighten, Meets = Meets,
        CaveatSat = CaveatSat, CaveatReason = CaveatReason, RevCap = RevCap, Undecidable = Undecidable,
    };

    public D ToJson()
    {
        var o = new D
        {
            ["predicates"] = Predicates, ["caveats"] = Caveats, ["vetoes"] = Vetoes, ["tighten"] = Tighten,
            ["meets"] = Meets.Select(m => (object?)m.ToJson()).ToList(), ["caveatSat"] = CaveatSat,
        };
        if (CaveatReason != null) o["caveatReason"] = CaveatReason;
        if (RevCap != null) o["revCap"] = Jx.N(RevCap.Value);
        o["undecidable"] = Undecidable.Cast<object?>().ToList();
        return o;
    }
}

/// <summary>Probe values per dimension (verbs, resources, reversibility classes, fields); the product is the representative grid.</summary>
public sealed class Probes
{
    public List<string> Verbs { get; set; } = new();
    public List<string> Resources { get; set; } = new();
    public List<string?> RevClasses { get; set; } = new();
    public List<ProbeField> Fields { get; set; } = new();
    public Probes Clone() => new() { Verbs = Verbs, Resources = Resources, RevClasses = RevClasses, Fields = Fields };
}

public sealed record ProbeField(string Path, List<object?> Values);

/// <summary>One point of the grid: a verb, a resource, a reversibility class and the field assignments.</summary>
public sealed class Rep
{
    public string Verb { get; init; } = "";
    public string Resource { get; init; } = "";
    public string? RevClass { get; init; }
    internal Jx.OMap Assignments { get; init; } = new();
    /// <summary>The field assignments as a map (path to value).</summary>
    public D AssignmentsDict() => Assignments.ToDict();
}

public sealed class ProbeInputs
{
    public List<L> PredicateSets { get; init; } = new();
    public List<string> ExtraVerbs { get; init; } = new();
    public List<string> ExtraResources { get; init; } = new();
    public List<(string Path, D Cond)> ExtraFieldConditions { get; init; } = new();
    public bool VaryReversibility { get; init; }
}

public readonly record struct SearchOutcome(Rep? Hit, bool Overflow);

public static class Enumerate
{
    /// <summary>The marker of a field left out of a representative (the reference's absent symbol).</summary>
    public static readonly object Absent = new();
    const string FreshVerb = "\u0000atlas-analyzer::fresh-verb\u0000";
    const string FreshResource = "\u0000atlas-analyzer::fresh-resource\u0000";
    public const long DefaultMaxCombinations = 200_000;

    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    static L ListOf(D p, string k, bool requireKey = false) => p.GetValueOrDefault(k) is L l ? l : new L();

    /// <summary>normalizePolicy: the four lists of a policy; anything that is not an object has none.</summary>
    public static (L Predicates, L Caveats, L Vetoes, L Tighten) NormalizePolicy(object? p)
    {
        if (p is not D d) return (new L(), new L(), new L(), new L());
        return (ListOf(d, "predicates"), ListOf(d, "caveats"), ListOf(d, "vetoes"), ListOf(d, "tighten"));
    }

    /// <summary>probeSet: the predicates (plus the conditions of vetoes, unless-clauses, thresholds and tighten rules, and of every meet parent) whose literals the grid must cover.</summary>
    public static L ProbeSet(PolicyModel m)
    {
        var o = new L(m.Predicates);
        foreach (var v in m.Vetoes)
        {
            o.Add(Jx.Prop(v, "when"));
            var unless = Jx.Prop(v, "unless");
            var len = unless is L ul ? ul.Count : unless is string us ? us.Length : -1;
            if (len > 0) o.Add(new D { ["verb"] = "*", ["where"] = unless });
            var over = Jx.Prop(v, "over");
            if (Jx.Truthy(over))
            {
                var c = new D(); Jx.Set(c, "field", Jx.Prop(over, "path")); c["op"] = "gt"; Jx.Set(c, "value", Jx.Prop(over, "threshold"));
                o.Add(new D { ["verb"] = "*", ["where"] = new L { c } });
            }
        }
        foreach (var t in m.Tighten) o.Add(new D { ["verb"] = "*", ["where"] = new L { Jx.Prop(t, "when") } });
        foreach (var x in m.Meets) o.AddRange(ProbeSet(x));
        return o;
    }

    static void ConditionUndecidable(object? c, Jx.OSet reasons)
    {
        if (c is not D d) return;
        if (IsGroup(d))
        {
            if (d.ContainsKey("all_of") && d["all_of"] is L a) foreach (var x in a) ConditionUndecidable(x, reasons);
            else if (d.ContainsKey("any_of") && d["any_of"] is L b) foreach (var x in b) ConditionUndecidable(x, reasons);
            else if (d.ContainsKey("not")) ConditionUndecidable(d["not"], reasons);
            return;
        }
        if (!Field.IsLeaf(d)) return;
        if (d.ContainsKey("ref")) reasons.Add("cross-field `ref` condition — the relation between two fields is not resolved");
        var field = (string)d["field"]!;
        if (field == "action.params") reasons.Add("condition on the whole `action.params` object is not enumerated precisely");
        var op = d.GetValueOrDefault("op") as string;
        if ((op == "lt" || op == "lte" || op == "gt" || op == "gte") && Jx.Fin(d.TryGetValue("value", out var vv) ? vv : Jx.Undef) == null)
            reasons.Add($"`{op}` against a non-numeric operand — string ordering is not enumerated exactly");
        if (op == "like" || op == "matches" || op == "is_a" || op == "member_of")
            reasons.Add($"`{op}` condition — matched by over-approximation, not enumerated exactly");
    }

    static List<string> DetectUndecidable(IEnumerable<object?> predicates)
    {
        var reasons = new Jx.OSet();
        foreach (var po in predicates)
        {
            if (po is not D p) continue;
            if (p.GetValueOrDefault("resource") is string r && r.StartsWith("re:", StringComparison.Ordinal))
                reasons.Add("re: regex resource matcher — resource dimension cannot be soundly enumerated");
            if (p.GetValueOrDefault("where") is L w) foreach (var c in w) ConditionUndecidable(c, reasons);
        }
        return reasons.ToList();
    }

    /// <summary>toModel: the analyzable model of a policy (a bare policy or one composed with meet parents).</summary>
    public static PolicyModel ToModel(object? p)
    {
        var (predicates, caveats, vetoes, tighten) = NormalizePolicy(p);
        var ca = CaveatAnalysis.AnalyzeCaveats(caveats);
        var meets = p is D pd && pd.GetValueOrDefault("meet") is L ml ? ml.Select(ToModel).ToList() : new List<PolicyModel>();
        int? rev = ca.RevCap;
        foreach (var x in meets) if (x.RevCap != null) rev = rev == null ? x.RevCap : Math.Min(rev.Value, x.RevCap.Value);
        var m = new PolicyModel
        {
            Predicates = predicates, Caveats = caveats, Vetoes = vetoes, Tighten = tighten, Meets = meets,
            CaveatSat = ca.Sat && meets.All(x => x.CaveatSat),
            CaveatReason = ca.Sat ? meets.FirstOrDefault(x => !x.CaveatSat)?.CaveatReason : ca.Reason,
            RevCap = rev,
        };
        var u = new Jx.OSet();
        foreach (var r in DetectUndecidable(ProbeSet(m))) u.Add(r);
        foreach (var x in meets) foreach (var r in x.Undecidable) u.Add(r);
        m.Undecidable = u.ToList();
        return m;
    }

    // ---- probes ----

    static void AddVerbLiterals(D c, Jx.OSet into)
    {
        var v = c.TryGetValue("value", out var vv) ? vv : Jx.Undef;
        var op = c.GetValueOrDefault("op") as string;
        if (op is "eq" or "ne" or "prefix" or "like" or "is_a") { if (v is string s) into.Add(s); }
        else if ((op == "in" || op == "nin") && v is L l) foreach (var x in l) if (x is string xs) into.Add(xs);
    }

    /// <summary>collectProbes: the verbs, resources, reversibility classes and per-field values that distinguish every condition.</summary>
    public static Probes CollectProbes(ProbeInputs inputs)
    {
        var verbLiterals = new Jx.OSet(); foreach (var v in inputs.ExtraVerbs) verbLiterals.Add(v);
        var resourceLiterals = new Jx.OSet();
        var fieldOrder = new List<string>(); var fieldConds = new Dictionary<string, List<object?>>(StringComparer.Ordinal);

        void ClassifyResource(object? r)
        {
            if (Jx.IsUndef(r)) return;
            if (r is string rs && rs == "*") return;
            if (r is not string str) throw JsX.TypeError("resource.startsWith is not a function");
            if (str.StartsWith("re:", StringComparison.Ordinal)) return;
            if (str.EndsWith('*'))
            {
                var body = str[..^1];
                resourceLiterals.Add(body); resourceLiterals.Add(body + "x");
                return;
            }
            resourceLiterals.Add(str);
        }

        void HandleCond(object? c)
        {
            if (c is not D d) return;
            if (IsGroup(d))
            {
                if (d.ContainsKey("all_of") && d["all_of"] is L a) foreach (var x in a) HandleCond(x);
                else if (d.ContainsKey("any_of") && d["any_of"] is L b) foreach (var x in b) HandleCond(x);
                else if (d.ContainsKey("not")) HandleCond(d["not"]);
                return;
            }
            if (!Field.IsLeaf(d)) return;
            var field = (string)d["field"]!;
            var v = d.TryGetValue("value", out var vv) ? vv : Jx.Undef;
            if (field == "action.verb") { AddVerbLiterals(d, verbLiterals); return; }
            if (field == "action.resource")
            {
                if ((d.GetValueOrDefault("op") as string) == "prefix" && v is string ps) ClassifyResource(ps + "*");
                else if (v is string s) ClassifyResource(s);
                else if (v is L l) foreach (var x in l) if (x is string xs) ClassifyResource(xs);
                return;
            }
            if (!fieldConds.TryGetValue(field, out var arr)) { arr = new List<object?>(); fieldConds[field] = arr; fieldOrder.Add(field); }
            arr.Add(d);
        }

        foreach (var list in inputs.PredicateSets)
        {
            foreach (var po in list)
            {
                if (po is not D p) continue;
                var verb = p.GetValueOrDefault("verb");
                if (verb is string vs) { if (vs != "*") verbLiterals.Add(vs); }
                else if (verb is L vl) foreach (var v in vl) if (v is string s && s != "*") verbLiterals.Add(s);
                ClassifyResource(p.TryGetValue("resource", out var res) ? res : Jx.Undef);
                if (p.GetValueOrDefault("where") is L w) foreach (var c in w) HandleCond(c);
            }
        }
        foreach (var r in inputs.ExtraResources) ClassifyResource(r);
        foreach (var (path, cond) in inputs.ExtraFieldConditions) { var c2 = Jx.Copy(cond); c2["field"] = path; HandleCond(c2); }

        var verbs = verbLiterals.ToList(); verbs.Add(FreshVerb);
        var resources = resourceLiterals.ToList(); resources.Add(FreshResource);
        return new Probes
        {
            Verbs = verbs,
            Resources = resources,
            RevClasses = inputs.VaryReversibility ? CaveatAnalysis.ReversibilityOrder.Select(x => (string?)x).ToList() : new List<string?> { null },
            Fields = fieldOrder.Select(f => { var vals = Field.FieldProbes(fieldConds[f]); vals.Add(Absent); return new ProbeField(f, vals); }).ToList(),
        };
    }

    /// <summary>The number of grid points (a double: it can exceed long range).</summary>
    public static double ProductSize(Probes pr)
    {
        double n = (double)pr.Verbs.Count * pr.Resources.Count * pr.RevClasses.Count;
        foreach (var f in pr.Fields) n *= f.Values.Count;
        return n;
    }

    // ---- representatives ----

    static IEnumerable<Jx.OMap> EnumerateFields(List<ProbeField> fields, int i, Jx.OMap acc)
    {
        if (i >= fields.Count) { yield return acc.Clone(); yield break; }
        var f = fields[i];
        foreach (var v in f.Values)
        {
            if (ReferenceEquals(v, Absent)) acc.Delete(f.Path); else acc.Set(f.Path, v);
            foreach (var r in EnumerateFields(fields, i + 1, acc)) yield return r;
        }
    }

    /// <summary>representatives: every grid point, verb-major.</summary>
    public static IEnumerable<Rep> Representatives(Probes pr)
    {
        foreach (var verb in pr.Verbs)
            foreach (var resource in pr.Resources)
                foreach (var rev in pr.RevClasses)
                    foreach (var asg in EnumerateFields(pr.Fields, 0, new Jx.OMap()))
                        yield return new Rep { Verb = verb, Resource = resource, RevClass = rev, Assignments = asg };
    }

    // ---- decisions ----

    sealed class Node
    {
        internal bool Leaf; internal object? Value; internal readonly List<KeyValuePair<string, Node>> Children = new();
        internal Node? Get(string k) { foreach (var kv in Children) if (kv.Key == k) return kv.Value; return null; }
        internal void Put(string k, Node n) { for (int i = 0; i < Children.Count; i++) if (Children[i].Key == k) { Children[i] = new(k, n); return; } Children.Add(new(k, n)); }
    }

    static void Insert(Node root, string[] segs, int from, object? value)
    {
        var node = root;
        for (int i = from; i < segs.Length - 1; i++)
        {
            if (node.Leaf) return;
            var next = node.Get(segs[i]);
            if (next == null || next.Leaf) { var created = new Node(); node.Put(segs[i], created); node = created; }
            else node = next;
        }
        if (segs.Length > from && !node.Leaf) node.Put(segs[^1], new Node { Leaf = true, Value = value });
    }

    static D Materialize(Node node)
    {
        var o = new D();
        if (node.Leaf) return o;
        foreach (var (k, child) in node.Children) o[k] = child.Leaf ? child.Value : Materialize(child);
        return o;
    }

    static (D Action, D Subject, D Env) BuildRoots(Rep rep)
    {
        var action = new Node(); var subject = new Node(); var env = new Node();
        foreach (var (path, value) in rep.Assignments.Items)
        {
            var segs = path.Split('.');
            if (segs.Length < 2) continue;
            var root = segs[0] == "action" ? action : segs[0] == "subject" ? subject : segs[0] == "env" ? env : null;
            if (root == null) continue;
            Insert(root, segs, 1, value);
        }
        var act = new D { ["verb"] = rep.Verb, ["resource"] = rep.Resource, ["params"] = new D() };
        foreach (var (key, child) in action.Children)
        {
            if (key == "verb" || key == "resource") continue;
            if (key == "params") { if (!child.Leaf) act["params"] = Materialize(child); }
            else act[key] = child.Leaf ? child.Value : Materialize(child);
        }
        if (rep.RevClass != null) act["reversibility_class"] = rep.RevClass;
        return (act, Materialize(subject), Materialize(env));
    }

    static bool ReversibilityOk(PolicyModel model, object? revClass)
    {
        if (model.RevCap == null) return true;
        if (revClass == null || Jx.IsUndef(revClass)) return false;
        var idx = CaveatAnalysis.ReversibilityOrder.ToList().IndexOf(revClass as string ?? "\u0001");
        return idx >= 0 && idx <= model.RevCap;
    }

    /// <summary>vetoApplies: whether a veto fires in a context (an approval veto only above its threshold; unless-clauses lift a deny veto).</summary>
    public static bool VetoApplies(object? v, D ctx)
    {
        if (!Prohibitions.WhenMatches(JsX.JsonOf(Jx.Prop(v, "when")), ctx)) return false;
        var over = Jx.Prop(v, "over");
        if (Jx.Truthy(over))
        {
            var r = Predicates.ResolvePath(ctx, Jx.Prop(over, "path"));
            var thr = Jx.ToNumber(Jx.Prop(over, "threshold"));
            var overIt = !r.Found || Jx.Fin(r.Value) is not double rv || rv < 0 || rv > thr;
            if (!overIt) return false;
        }
        var unless = Jx.Prop(v, "unless");
        if ((Jx.Prop(v, "kind") as string) != "approval" && Jx.Truthy(unless))
        {
            if (unless is not L ul) throw JsX.TypeError("unless.every is not a function");
            if (ul.All(c => Predicates.EvaluateCondition(c, ctx))) return false;
        }
        return true;
    }

    /// <summary>decisionAtContext: 'allow', 'escalate' or 'deny' of a model at a concrete context.</summary>
    public static string DecisionAtContext(PolicyModel model, D ctx)
    {
        if (!Predicates.EvaluatePredicates(model.Predicates, ctx)) return "deny";
        var escalate = false;
        foreach (var v in model.Vetoes)
        {
            if (!VetoApplies(v, ctx)) continue;
            if ((Jx.Prop(v, "kind") as string) == "deny") return "deny";
            escalate = true;
        }
        foreach (var t in model.Tighten)
        {
            if (Predicates.EvaluateConditionTri(JsX.JsonOf(Jx.Prop(t, "when")), ctx) == Predicates.Tri.False) continue;
            if ((Jx.Prop(t, "signal") as string) == "deny") return "deny";
            escalate = true;
        }
        var own = escalate ? "escalate" : "allow";
        foreach (var x in model.Meets)
        {
            var d = DecisionAtContext(x, ctx);
            if (d == "deny") return "deny";
            if (d == "escalate") own = "escalate";
        }
        return own;
    }

    static D ContextOfRoots((D Action, D Subject, D Env) r) => new() { ["action"] = r.Action, ["subject"] = r.Subject, ["env"] = r.Env };

    /// <summary>decide: the decision of a model for a representative.</summary>
    public static string Decide(PolicyModel model, Rep rep)
    {
        if (!model.CaveatSat) return "deny";
        if (!ReversibilityOk(model, rep.RevClass)) return "deny";
        return DecisionAtContext(model, ContextOfRoots(BuildRoots(rep)));
    }

    public static bool Admits(PolicyModel model, Rep rep) => Decide(model, rep) != "deny";

    /// <summary>contextOfAction: the evaluation context of a concrete action (an undefined member stays absent).</summary>
    public static D ContextOfAction(object? action)
    {
        var act = new D();
        Jx.Set(act, "verb", Jx.Prop(action, "verb")); Jx.Set(act, "resource", Jx.Prop(action, "resource"));
        var prm = Jx.Prop(action, "params");
        act["params"] = JsX.Spread(prm == null || Jx.IsUndef(prm) ? new D() : prm);
        var rc = Jx.Prop(action, "reversibilityClass");
        if (!Jx.IsUndef(rc)) act["reversibility_class"] = rc;
        var subj = Jx.Prop(action, "subject"); var env = Jx.Prop(action, "env");
        return new D
        {
            ["action"] = act,
            ["subject"] = JsX.Spread(subj == null || Jx.IsUndef(subj) ? new D() : subj),
            ["env"] = JsX.Spread(env == null || Jx.IsUndef(env) ? new D() : env),
        };
    }

    /// <summary>decideAction: the decision of a model for a concrete action.</summary>
    public static string DecideAction(PolicyModel model, object? action)
    {
        if (!model.CaveatSat) return "deny";
        if (!ReversibilityOk(model, Jx.Prop(action, "reversibilityClass"))) return "deny";
        return DecisionAtContext(model, ContextOfAction(action));
    }

    public static bool AdmitsAction(PolicyModel model, object? action) => DecideAction(model, action) != "deny";

    /// <summary>repToAction: the concrete action a representative stands for.</summary>
    public static D RepToAction(Rep rep)
    {
        var roots = BuildRoots(rep);
        var action = new D { ["verb"] = rep.Verb, ["resource"] = rep.Resource, ["params"] = Jx.Copy((D)roots.Action["params"]!) };
        if (rep.RevClass != null) action["reversibilityClass"] = rep.RevClass;
        if (roots.Subject.Count > 0) action["subject"] = roots.Subject;
        if (roots.Env.Count > 0) action["env"] = roots.Env;
        return action;
    }

    /// <summary>search: the first representative satisfying the predicate, or overflow when the grid exceeds the bound.</summary>
    public static SearchOutcome Search(Probes pr, Func<Rep, bool> predicate, double max)
    {
        if (ProductSize(pr) > max) return new SearchOutcome(null, true);
        foreach (var rep in Representatives(pr)) if (predicate(rep)) return new SearchOutcome(rep, false);
        return new SearchOutcome(null, false);
    }

    /// <summary>collect: up to <paramref name="limit"/> representatives satisfying the predicate.</summary>
    public static (List<Rep> Hits, bool Overflow) Collect(Probes pr, Func<Rep, bool> predicate, double max, int limit)
    {
        if (ProductSize(pr) > max) return (new List<Rep>(), true);
        var hits = new List<Rep>();
        foreach (var rep in Representatives(pr))
            if (predicate(rep)) { hits.Add(rep); if (hits.Count >= limit) break; }
        return (hits, false);
    }
}
