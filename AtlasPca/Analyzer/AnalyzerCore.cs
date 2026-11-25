using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Static analysis of authority over the bounded decision engine: reachability, vacuity, subsumption, equivalence, disjointness
/// and intent conformance. Policies, actions and results are parsed-JSON trees; an inconclusive grid is reported approximate.</summary>
public static class AnalyzerCore
{
    public static IReadOnlyList<string> ReversibilityOrder => CaveatAnalysis.ReversibilityOrder;
    public const long DefaultMaxCombinations = Enumerate.DefaultMaxCombinations;

    internal static double BoundOf(object? opts)
    {
        var m = Jx.Opt(opts, "maxCombinations");
        return Jx.Fin(m) is double d && d >= 0 ? d : DefaultMaxCombinations;
    }

    static string Join(IEnumerable<string> xs) => string.Join("; ", xs);

    static Probes ProbesFor(IEnumerable<PolicyModel> models, string? verb)
    {
        var ms = models.ToList();
        var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = ms.Select(Enumerate.ProbeSet).ToList(), VaryReversibility = ms.Any(m => m.RevCap != null) });
        if (verb != null) pr.Verbs = new List<string> { verb };
        return pr;
    }

    static string? OwnString(object? x) => x as string;

    /// <summary>reachable: can any input make the policy admit this (possibly partial) action? Provided params are kept, the rest enumerated.</summary>
    public static D Reachable(object? policy, object? action, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var max = BoundOf(opts);
        if (!model.CaveatSat) return new D { ["reachable"] = false, ["reason"] = "caveats unsatisfiable: " + (model.CaveatReason ?? "unknown") };
        var rc = Jx.Prop(action, "reversibilityClass");
        if (!Jx.IsUndef(rc) && model.RevCap != null)
        {
            var idx = rc is string rcs ? ReversibilityOrder.ToList().IndexOf(rcs) : -1;
            if (idx < 0 || idx > model.RevCap) return new D { ["reachable"] = false, ["reason"] = $"reversibility class '{JsX.Str(rc)}' exceeds the caveat cap" };
        }
        if (Enumerate.AdmitsAction(model, action)) return new D { ["reachable"] = true, ["witness"] = action };

        var bs = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        var prov = Jx.Prop(action, "params");
        var provided = prov == null || Jx.IsUndef(prov) ? new D() : prov;
        var fields = bs.Fields.Select(f =>
        {
            if (f.Path.StartsWith("action.params.", StringComparison.Ordinal) && provided is D pd)
            {
                var key = f.Path["action.params.".Length..];
                if (pd.TryGetValue(key, out var pv)) return new ProbeField(f.Path, new List<object?> { pv });
            }
            return f;
        }).ToList();
        var revClasses = !Jx.IsUndef(rc) ? new List<string?> { rc as string }
            : model.RevCap != null ? ReversibilityOrder.Select(x => (string?)x).ToList() : new List<string?> { null };
        var pr = new Probes
        {
            Verbs = new List<string> { OwnString(Jx.Prop(action, "verb")) ?? "" },
            Resources = new List<string> { OwnString(Jx.Prop(action, "resource")) ?? "" },
            RevClasses = revClasses, Fields = fields,
        };
        var outcome = Enumerate.Search(pr, rep => Enumerate.Admits(model, rep), max);
        if (outcome.Hit != null) return new D { ["reachable"] = true, ["witness"] = MergeWitness(Enumerate.RepToAction(outcome.Hit), action) };
        if (outcome.Overflow) return new D { ["reachable"] = true, ["approximate"] = true, ["reason"] = "representative grid exceeded the bound; could not prove unreachable" };
        if (model.Undecidable.Count > 0)
            return new D { ["reachable"] = true, ["approximate"] = true, ["reason"] = $"over-approximated ({Join(model.Undecidable)}); could not construct a witness but cannot prove unreachable" };
        return new D { ["reachable"] = false, ["reason"] = "no predicate admits this action for any input (proven over the decided fragment)" };
    }

    static D MergeWitness(D witness, object? provided)
    {
        var pp = Jx.Prop(provided, "params");
        var prm = JsX.Spread(witness["params"]);
        foreach (var (k, v) in JsX.Spread(pp == null || Jx.IsUndef(pp) ? new D() : pp)) prm[k] = v;
        var o = new D();
        Jx.Set(o, "verb", Jx.Prop(provided, "verb")); Jx.Set(o, "resource", Jx.Prop(provided, "resource")); o["params"] = prm;
        var rc = Jx.Prop(provided, "reversibilityClass");
        if (rc == null || Jx.IsUndef(rc)) rc = witness.GetValueOrDefault("reversibilityClass") ?? Jx.Undef;
        if (!Jx.IsUndef(rc)) o["reversibilityClass"] = rc;
        if (witness.TryGetValue("subject", out var s)) o["subject"] = s;
        if (witness.TryGetValue("env", out var e)) o["env"] = e;
        return o;
    }

    /// <summary>alwaysDenies: no input is admitted (optionally for one verb); approximate when the grid or the model cannot prove it.</summary>
    public static D AlwaysDenies(object? policy, string? verb = null, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var max = BoundOf(opts);
        if (!model.CaveatSat) return new D { ["alwaysDenies"] = true, ["reason"] = "caveats unsatisfiable: " + (model.CaveatReason ?? "unknown") };
        var outcome = Enumerate.Search(ProbesFor(new[] { model }, verb), rep => Enumerate.Admits(model, rep), max);
        if (outcome.Hit != null) return new D { ["alwaysDenies"] = false, ["witness"] = Enumerate.RepToAction(outcome.Hit) };
        if (outcome.Overflow) return new D { ["alwaysDenies"] = false, ["approximate"] = true, ["reason"] = "grid exceeded the bound; cannot prove vacuity" };
        if (model.Undecidable.Count > 0) return new D { ["alwaysDenies"] = false, ["approximate"] = true, ["reason"] = $"over-approximated ({Join(model.Undecidable)}); cannot prove vacuity" };
        return new D { ["alwaysDenies"] = true };
    }

    /// <summary>alwaysAllows: every input of the verb is admitted; the counterexample is a denied representative.</summary>
    public static D AlwaysAllows(object? policy, string verb, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var max = BoundOf(opts);
        if (!model.CaveatSat) return new D { ["alwaysAllows"] = false, ["reason"] = "caveats unsatisfiable: " + (model.CaveatReason ?? "unknown") };
        var outcome = Enumerate.Search(ProbesFor(new[] { model }, verb), rep => !Enumerate.Admits(model, rep), max);
        if (outcome.Hit != null) return new D { ["alwaysAllows"] = false, ["counterexample"] = Enumerate.RepToAction(outcome.Hit) };
        if (outcome.Overflow) return new D { ["alwaysAllows"] = false, ["approximate"] = true, ["reason"] = "grid exceeded the bound; cannot prove totality" };
        if (model.Undecidable.Count > 0) return new D { ["alwaysAllows"] = false, ["approximate"] = true, ["reason"] = $"over-approximated ({Join(model.Undecidable)}); cannot prove totality" };
        return new D { ["alwaysAllows"] = true };
    }

    static string? ApproxNote(IEnumerable<PolicyModel> models, bool overflow)
    {
        if (overflow) return "representative grid exceeded the bound; cannot prove the relation";
        var reasons = new Jx.OSet();
        foreach (var m in models) foreach (var r in m.Undecidable) reasons.Add(r);
        return reasons.Count > 0 ? $"over-approximated ({Join(reasons.ToList())}); cannot prove the relation" : null;
    }

    static D Relation(object? a, object? b, object? opts, string key, Func<PolicyModel, PolicyModel, Func<Rep, bool>> pred, string hitKey)
    {
        var ma = Enumerate.ToModel(a); var mb = Enumerate.ToModel(b);
        var max = BoundOf(opts);
        var outcome = Enumerate.Search(ProbesFor(new[] { ma, mb }, null), pred(ma, mb), max);
        if (outcome.Hit != null) return new D { [key] = false, [hitKey] = Enumerate.RepToAction(outcome.Hit) };
        var note = ApproxNote(new[] { ma, mb }, outcome.Overflow);
        if (note != null) return new D { [key] = false, ["approximate"] = true, ["reason"] = note };
        return new D { [key] = true };
    }

    /// <summary>subsumes: every action b admits, a admits too.</summary>
    public static D Subsumes(object? a, object? b, object? opts = null) =>
        Relation(a, b, opts, "subsumes", (ma, mb) => rep => Enumerate.Admits(mb, rep) && !Enumerate.Admits(ma, rep), "counterexample");

    /// <summary>disjoint: no action is admitted by both.</summary>
    public static D Disjoint(object? a, object? b, object? opts = null) =>
        Relation(a, b, opts, "disjoint", (ma, mb) => rep => Enumerate.Admits(ma, rep) && Enumerate.Admits(mb, rep), "witness");

    /// <summary>equivalent: both admit exactly the same actions.</summary>
    public static D Equivalent(object? a, object? b, object? opts = null) =>
        Relation(a, b, opts, "equivalent", (ma, mb) => rep => Enumerate.Admits(ma, rep) != Enumerate.Admits(mb, rep), "counterexample");

    static bool ScopeMatches(string scope, string resource)
    {
        if (scope == "*") return true;
        if (scope.StartsWith("re:", StringComparison.Ordinal))
        {
            var src = scope[3..];
            if (src.Length > 200 || resource.Length > Predicates.MaxReResourceLen || !SafeRegex.IsSafeSource(src)) return false;
            return SafeRegex.FullMatch(src, resource) == true;
        }
        if (scope.EndsWith('*')) return resource.StartsWith(scope[..^1], StringComparison.Ordinal);
        return scope == resource;
    }

    static L ViolationKinds(D action, object? intent, string amountField, double minAmount)
    {
        var kinds = new L();
        var verbs = (L)Jx.Prop(intent, "verbs")!;
        var verb = action.GetValueOrDefault("verb");
        if (!(verbs.Any(v => v is string s && s == "*") || verbs.Any(v => Jx.IsUndef(verb) ? false : JsX.StrictEq(v, verb)))) kinds.Add("off-verb");
        var scopes = Jx.Prop(intent, "resourceScopes") is L sc ? sc : new L();
        var resource = (string)(action.GetValueOrDefault("resource") ?? "");
        if (scopes.Count > 0 && !scopes.Any(s => ScopeMatches((string)s!, resource))) kinds.Add("off-scope");
        var maxA = Jx.Prop(intent, "maxAmount");
        if (!Jx.IsUndef(maxA))
        {
            var prm = action.GetValueOrDefault("params") as D;
            var amt = prm != null && prm.TryGetValue(amountField, out var av) ? av : null;
            if (Jx.Fin(amt) is double a)
            {
                if (a > Jx.ToNumber(maxA)) kinds.Add("over-amount");
                else if (a < minAmount) kinds.Add("under-amount");
            }
        }
        return kinds;
    }

    /// <summary>intentConformance: does the policy admit anything outside the declared intent (verbs, resource scopes, amount range)?</summary>
    public static D IntentConformance(object? policy, object? intent, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var max = BoundOf(opts);
        var af = Jx.Prop(intent, "amountField");
        var amountField = af == null || Jx.IsUndef(af) ? "amount" : JsX.Str(af);
        var mn = Jx.Prop(intent, "minAmount");
        var minAmount = mn == null || Jx.IsUndef(mn) ? 0.0 : Jx.ToNumber(mn);
        if (!model.CaveatSat) return new D { ["conforms"] = true, ["violations"] = new L() };

        var extra = new List<(string, D)>();
        var maxA = Jx.Prop(intent, "maxAmount");
        if (!Jx.IsUndef(maxA))
        {
            var path = "action.params." + amountField;
            extra.Add((path, new D { ["field"] = path, ["op"] = "lte", ["value"] = maxA }));
            extra.Add((path, new D { ["field"] = path, ["op"] = "gte", ["value"] = mn == null || Jx.IsUndef(mn) ? Jx.N(0) : mn }));
        }
        var verbsO = Jx.Prop(intent, "verbs");
        if (verbsO is not L verbs) throw JsX.TypeError("intent.verbs.filter is not a function");
        var scopesO = Jx.Prop(intent, "resourceScopes");
        var scopes = scopesO == null || Jx.IsUndef(scopesO) ? new L() : scopesO as L ?? throw JsX.TypeError("resourceScopes is not iterable");
        var pr = Enumerate.CollectProbes(new ProbeInputs
        {
            PredicateSets = new List<L> { Enumerate.ProbeSet(model) },
            ExtraVerbs = verbs.Where(v => !(v is string s && s == "*")).Select(JsX.Str).ToList(),
            ExtraResources = scopes.Select(s => s is string ss ? ss : throw JsX.TypeError("resource.startsWith is not a function")).ToList(),
            ExtraFieldConditions = extra,
            VaryReversibility = model.RevCap != null,
        });
        double fp = 1; foreach (var f in pr.Fields) fp *= f.Values.Count;
        if ((double)pr.Verbs.Count * pr.Resources.Count * pr.RevClasses.Count * fp > max)
            return new D { ["conforms"] = false, ["approximate"] = true, ["violations"] = new L(), ["reason"] = "grid exceeded the bound; cannot prove conformance" };

        var violations = new L();
        foreach (var rep in Enumerate.Representatives(pr))
        {
            if (!Enumerate.Admits(model, rep)) continue;
            var action = Enumerate.RepToAction(rep);
            var kinds = ViolationKinds(action, intent, amountField, minAmount);
            if (kinds.Count > 0)
            {
                violations.Add(new D { ["action"] = action, ["kinds"] = kinds });
                if (violations.Count >= 16) break;
            }
        }
        if (violations.Count > 0) return new D { ["conforms"] = false, ["violations"] = violations };
        var intentRegex = scopes.Any(s => s is string ss && ss.StartsWith("re:", StringComparison.Ordinal));
        if (model.Undecidable.Count > 0 || intentRegex)
        {
            var reasons = new List<string>(model.Undecidable);
            if (intentRegex) reasons.Add("re: intent resource scope not enumerated soundly");
            return new D { ["conforms"] = false, ["approximate"] = true, ["violations"] = new L(), ["reason"] = $"over-approximated ({Join(reasons)}); cannot prove conformance" };
        }
        return new D { ["conforms"] = true, ["violations"] = new L() };
    }

    /// <summary>admitsConcrete: does the policy admit this concrete action (an exact decision, no enumeration)?</summary>
    public static bool AdmitsConcrete(object? policy, object? action) => Enumerate.AdmitsAction(Enumerate.ToModel(policy), action);

    /// <summary>predicateNumericSatisfiable: false only when the numeric comparisons of a where clause contradict each other.</summary>
    public static bool PredicateNumericSatisfiable(object? where) => where is not L l || Field.NumericConjunctionSatisfiable(l);
}
