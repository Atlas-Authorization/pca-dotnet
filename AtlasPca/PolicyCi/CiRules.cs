using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.PolicyCi.CiJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

/// <summary>The policy-safety rules, each driving the static analyzer. Every rule is sound: a hard error is only emitted from a PROVEN
/// analyzer verdict (its result is not approximate); an undecidable feature downgrades to a warning or note that says so. A finding is
/// <c>{rule, severity, message, where?}</c>. A policy is the normalized <c>{predicates, caveats, riskPolicy?, kind}</c> object.</summary>
public static class CiRules
{
    /// <summary>Scope-narrowing caveat types (constrain WHAT or HOW MUCH, not merely WHEN).</summary>
    public static readonly IReadOnlyList<string> ScopeNarrowingCaveats = new[] { "max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth" };
    /// <summary>Blast, rate and budget gate caveat types (the safety-floor gates, distinct from a time bound).</summary>
    public static readonly IReadOnlyList<string> BudgetGateCaveats = new[] { "max_blast_radius", "rate", "budget_alloc" };

    // ---- util ----

    /// <summary>A predicate's verb as a list of concrete strings.</summary>
    internal static List<string> VerbsOf(object? verb)
    {
        var o = new List<string>();
        if (verb is string s) o.Add(s);
        else if (verb is L l) foreach (var x in l) if (x is string xs) o.Add(xs);
        return o;
    }

    /// <summary>Case-insensitive includes of a verb against a dangerous-substring set (a set that is not a list of strings throws, as the reference does).</summary>
    internal static bool IsDangerousVerb(string verb, object? dangerous)
    {
        var v = verb.ToLowerInvariant();
        if (dangerous is not L l) throw TypeErr("dangerous.some is not a function");
        foreach (var kw in l)
        {
            if (kw is not string ks) throw TypeErr("kw.toLowerCase is not a function");
            if (v.Contains(ks.ToLowerInvariant(), StringComparison.Ordinal)) return true;
        }
        return false;
    }

    /// <summary>A resource matcher that admits every resource: omitted or '*'.</summary>
    internal static bool IsWildcardResource(object? predicate) => !Has(predicate, "resource") || G(predicate, "resource") is string s && s == "*";

    internal static bool HasCaveatOfType(L caveats, IReadOnlyList<string> types) =>
        caveats.Any(c => c is D && G(c, "type") is string t && types.Contains(t));

    /// <summary>A one-line rendering of an analyzer witness or counterexample action.</summary>
    internal static string DescribeAction(object? a)
    {
        var parts = new List<object?> { G(a, "verb"), G(a, "resource") };
        var p = G(a, "params");
        if ((p is D pd && pd.Count > 0) || (p is L pl && pl.Count > 0)) parts.Add(Stringify(p));
        if (Has(a, "reversibilityClass")) parts.Add("[" + Str(G(a, "reversibilityClass")) + "]");
        return JoinSpace(parts);
    }

    static List<string> Uniq(IEnumerable<string> xs) => xs.Distinct(StringComparer.Ordinal).ToList();

    static D Find(string rule, string severity, string message, string? where)
    {
        var f = Obj(("rule", rule), ("severity", severity), ("message", message));
        if (where != null) f["where"] = where;
        return f;
    }

    static D AnalyzerInput(D p) => Obj(("predicates", p["predicates"]), ("caveats", p["caveats"]));
    static L PredicatesOf(D p) => (L)p["predicates"]!;
    static L CaveatsOf(D p) => (L)p["caveats"]!;

    /// <summary>Every concrete verb named across the predicate set.</summary>
    static List<string> DeclaredVerbs(L predicates)
    {
        var concrete = new List<string>();
        foreach (var p in predicates)
        {
            if (!IsObject(p)) continue;
            foreach (var v in VerbsOf(G(p, "verb"))) if (v != "*") concrete.Add(v);
        }
        return Uniq(concrete);
    }

    /// <summary>The budget / step-up gate that bounds a dangerous action, or null.</summary>
    static string? GateDescription(D policy)
    {
        var gates = new List<string>();
        var caveats = CaveatsOf(policy);
        if (HasCaveatOfType(caveats, BudgetGateCaveats))
        {
            var types = new List<string>();
            foreach (var c in caveats)
            {
                if (c == null) throw TypeErr("Cannot read properties of null (reading 'type')");
                if (c is D && G(c, "type") is string t && BudgetGateCaveats.Contains(t)) types.Add(t);
            }
            gates.Add(string.Join('/', types));
        }
        if (policy.ContainsKey("riskPolicy"))
        {
            var rp = policy["riskPolicy"];
            if (rp == null) throw TypeErr("Cannot read properties of null (reading 'theta2')");
            if (Fin(G(rp, "theta2")) is double t2 && t2 < 1) gates.Add("risk step-up (theta2 < 1)");
        }
        return gates.Count > 0 ? string.Join(", ", gates) : null;
    }

    // ---- 1. over-broad grant ----

    public static L RuleOverBroadGrant(D policy, object? dangerous, object? opts)
    {
        var o = new L();
        var input = AnalyzerInput(policy);
        var hasScopeNarrowing = HasCaveatOfType(CaveatsOf(policy), ScopeNarrowingCaveats);
        var preds = PredicatesOf(policy);
        for (int i = 0; i < preds.Count; i++)
        {
            var p = preds[i];
            if (!IsObject(p)) continue;
            var verbs = VerbsOf(G(p, "verb"));
            var where = $"predicates[{i}]";
            var w = G(p, "where");
            var hasWhere = w is L wl && wl.Count > 0;

            if (verbs.Contains("*")) o.Add(Find("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action", where));
            if (IsWildcardResource(p))
            {
                var dangerousVerbs = verbs.Where(v => IsDangerousVerb(v, dangerous)).ToList();
                if (dangerousVerbs.Count > 0)
                    o.Add(Find("over-broad-grant", "error", $"dangerous verb(s) {Stringify(new L(dangerousVerbs.Cast<object?>()))} granted on a WILDCARD resource ('*')", where));
                else if (!verbs.Contains("*"))
                    o.Add(Find("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix", where));
            }
            foreach (var v in verbs)
            {
                if (v != "*" && IsDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing)
                    o.Add(Find("over-broad-grant", "error",
                        $"dangerous verb '{v}' is granted with NO narrowing `where` and no scope-narrowing caveat ({string.Join('/', ScopeNarrowingCaveats)})", where));
            }
        }
        // Semantic always-allow: a verb the analyzer PROVES is total (admits every action of that verb).
        foreach (var v in DeclaredVerbs(preds))
        {
            var aa = AnalyzerCore.AlwaysAllows(input, v, opts);
            if (aa.GetValueOrDefault("alwaysAllows") is true && aa.GetValueOrDefault("approximate") is not true)
                o.Add(Find("over-broad-grant", "error", $"grants EVERY action of '{v}' — the authority has no effective constraint (always-allow)", null));
        }
        return o;
    }

    // ---- 2. privilege escalation in a chain ----

    static string ReasonSuffix(object? reason) => reason is string s && s.Length > 0 ? ": " + s : "";

    public static L RulePrivilegeEscalation(IReadOnlyList<object?> hops, object? opts)
    {
        var o = new L();
        for (int i = 1; i < hops.Count; i++)
        {
            var parent = (D)hops[i - 1]!; var child = (D)hops[i]!;
            // a well-attenuated child admits a SUBSET of its parent, i.e. the parent subsumes the child
            var s = AnalyzerCore.Subsumes(AnalyzerInput(parent), AnalyzerInput(child), opts);
            var where = $"hop[{i}]";
            if (s.GetValueOrDefault("subsumes") is true) continue;
            if (s.GetValueOrDefault("approximate") is true)
                o.Add(Find("privilege-escalation", "warn", $"could not prove hop {i} attenuation (undecidable{ReasonSuffix(s.GetValueOrDefault("reason"))}) — attenuation not verified", where));
            else
            {
                var cx = s.GetValueOrDefault("counterexample");
                var ex = cx != null ? $" — child admits '{DescribeAction(cx)}' which its parent denies" : "";
                o.Add(Find("privilege-escalation", "error", $"delegation hop {i} ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated){ex}", where));
            }
        }
        return o;
    }

    // ---- 3. unused / redundant caveat ----

    // for each type: the numeric field that carries its bound, and whether the strictest (binding) one is the min or the max
    static readonly (string Type, string Field, bool KeepMin)[] OrderedCaveats =
    {
        ("expires", "at", true), ("not_before", "at", false), ("max_blast_radius", "max", true), ("delegation_depth", "max", true), ("budget_alloc", "limit", true),
    };

    public static L RuleRedundantCaveat(D policy)
    {
        var o = new L();
        var caveats = CaveatsOf(policy);

        // (a) exact-duplicate caveats
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < caveats.Count; i++)
        {
            var cv = caveats[i];
            if (!IsObject(cv)) continue;
            var k = Stringify(cv);
            if (seen.TryGetValue(k, out var first))
                o.Add(Find("redundant-caveat", "warn", $"caveat {i} ('{Str(Has(cv, "type") ? G(cv, "type") : Jx.Undef)}') is an exact duplicate of caveat {first} — dead policy", $"caveats[{i}]"));
            else seen[k] = i;
        }

        // (b) same-type domination: a looser caveat that a stricter one of the same type always subsumes
        foreach (var (type, field, keepMin) in OrderedCaveats)
        {
            var vals = new List<(int I, double V)>();
            for (int i = 0; i < caveats.Count; i++)
            {
                var cv = caveats[i];
                if (cv is not D || !(G(cv, "type") is string t && t == type)) continue;
                if (Fin(G(cv, field)) is double v) vals.Add((i, v));
            }
            if (vals.Count < 2) continue;
            var binding = keepMin ? vals.Min(e => e.V) : vals.Max(e => e.V);
            foreach (var e in vals)
                if (e.V != binding)
                    o.Add(Find("redundant-caveat", "warn",
                        $"caveat {e.I} ('{type}' {field}={NumStr(e.V)}) is subsumed by a stricter '{type}' ({field}={NumStr(binding)}) — it can never bite", $"caveats[{e.I}]"));
        }

        // (c) a predicate whose numeric `where` conjunction is UNSATISFIABLE never matches — dead policy
        var preds = PredicatesOf(policy);
        for (int i = 0; i < preds.Count; i++)
        {
            var p = preds[i];
            if (!IsObject(p) || G(p, "where") is not L where) continue;
            if (!AnalyzerCore.PredicateNumericSatisfiable(where))
                o.Add(Find("redundant-caveat", "warn", $"predicate {i} can never match — its numeric `where` constraints are unsatisfiable (dead policy)", $"predicates[{i}]"));
            else o.AddRange(NonBindingConditions(where, i));
        }
        return o;
    }

    static readonly HashSet<string> NumericOps = new() { "lt", "lte", "gt", "gte", "eq" };

    /// <summary>A numeric leaf condition that does not tighten its field's interval is redundant (never binds).</summary>
    static L NonBindingConditions(L where, int predIndex)
    {
        var order = new List<string>();
        var byField = new Dictionary<string, List<(D C, int I)>>(StringComparer.Ordinal);
        for (int i = 0; i < where.Count; i++)
        {
            var c = where[i];
            if (!Field.IsLeaf(c)) continue;
            var cd = (D)c!;
            if (cd.ContainsKey("ref")) continue;
            if (cd.GetValueOrDefault("op") is not string op || !NumericOps.Contains(op)) continue;
            if (Fin(G(cd, "value")) == null) continue;
            var f = (string)cd["field"]!;
            if (!byField.TryGetValue(f, out var arr)) { byField[f] = arr = new(); order.Add(f); }
            arr.Add((cd, i));
        }
        var o = new L();
        foreach (var field in order)
        {
            var conds = byField[field];
            if (conds.Count < 2) continue;
            var full = conds.Aggregate(Field.FullInterval, (iv, e) => Field.TightenInterval(iv, G(e.C, "op"), G(e.C, "value")));
            if (Field.IntervalEmpty(full)) continue; // the whole-predicate unsat case is reported in (c)
            foreach (var e in conds)
            {
                var without = conds.Where(x => !ReferenceEquals(x.C, e.C)).Aggregate(Field.FullInterval, (iv, x) => Field.TightenInterval(iv, G(x.C, "op"), G(x.C, "value")));
                if (without.Lo == full.Lo && without.LoInclusive == full.LoInclusive && without.Hi == full.Hi && without.HiInclusive == full.HiInclusive)
                    o.Add(Find("redundant-caveat", "info",
                        $"condition on '{field}' ({Str(G(e.C, "op"))} {Str(G(e.C, "value"))}) does not tighten the authority — redundant with the other bounds on this field",
                        $"predicates[{predIndex}].where[{e.I}]"));
            }
        }
        return o;
    }

    // ---- 4. dangerous reachability ----

    public static L RuleDangerousReachability(D policy, object? dangerous, object? extraTargets, object? opts)
    {
        var o = new L();
        var input = AnalyzerInput(policy);
        var derived = DeclaredVerbs(PredicatesOf(policy)).Where(v => IsDangerousVerb(v, dangerous)).Select(v => (object?)Obj(("verb", v))).ToList();
        if (extraTargets is not L extra) throw TypeErr("extraTargets is not iterable");
        var targets = new L(derived); targets.AddRange(extra);
        var gate = GateDescription(policy);

        foreach (var t in targets)
        {
            var verbV = Jx.Prop(t, "verb");
            if (verbV is not (string or null) && !Jx.IsUndef(verbV)) throw TypeErr("verb is not a string");
            var verb = verbV as string;
            var verbText = Str(verbV);
            bool proven, approximate; object? reason; string witness;
            var res = Jx.Prop(t, "resource");
            if (!Jx.IsUndef(res))
            {
                var r = AnalyzerCore.Reachable(input, Obj(("verb", verbV), ("resource", res)), opts);
                proven = r.GetValueOrDefault("reachable") is true && r.GetValueOrDefault("approximate") is not true;
                approximate = r.GetValueOrDefault("approximate") is true;
                reason = r.GetValueOrDefault("reason");
                witness = $"{verbText} {Str(res)}";
            }
            else
            {
                var ad = AnalyzerCore.AlwaysDenies(input, verb, opts);
                proven = ad.GetValueOrDefault("alwaysDenies") is false && ad.GetValueOrDefault("approximate") is not true;
                approximate = ad.GetValueOrDefault("approximate") is true;
                reason = ad.GetValueOrDefault("reason");
                witness = ad.GetValueOrDefault("witness") is { } w ? DescribeAction(w) : verbText;
            }
            if (approximate)
                o.Add(Find("dangerous-reachability", "warn", $"could not decide reachability of dangerous verb '{verbText}' (undecidable{ReasonSuffix(reason)})", null));
            else if (proven)
            {
                if (gate == null) o.Add(Find("dangerous-reachability", "error", $"dangerous action '{witness}' is REACHABLE with no budget / rate / step-up gate", null));
                else o.Add(Find("dangerous-reachability", "info", $"dangerous action '{witness}' is reachable but gated by {gate}", null));
            }
        }
        return o;
    }

    // ---- 5. missing safety floor ----

    /// <summary>A grant is non-trivial when any predicate grants a dangerous or wildcard verb, a wildcard resource, or is unconstrained.</summary>
    static bool IsNonTrivial(D policy, object? dangerous)
    {
        foreach (var p in PredicatesOf(policy))
        {
            if (!IsObject(p)) continue;
            var verbs = VerbsOf(G(p, "verb"));
            var hasWhere = G(p, "where") is L w && w.Count > 0;
            if (verbs.Contains("*") || verbs.Any(v => IsDangerousVerb(v, dangerous)) || IsWildcardResource(p) || !hasWhere) return true;
        }
        return false;
    }

    public static L RuleMissingSafetyFloor(D policy, bool requireExpiry, bool requireScopeGate, object? dangerous)
    {
        var o = new L();
        if (PredicatesOf(policy).Count == 0) return o; // nothing is granted; default-deny needs no floor
        if (requireExpiry && !HasCaveatOfType(CaveatsOf(policy), new[] { "expires" }))
            o.Add(Find("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires", null));
        if (requireScopeGate && IsNonTrivial(policy, dangerous) && !HasCaveatOfType(CaveatsOf(policy), BudgetGateCaveats))
            o.Add(Find("missing-safety-floor", "warn", $"non-trivial grant has no blast-radius / rate / budget gate ({string.Join('/', BudgetGateCaveats)})", null));
        return o;
    }

    // ---- schema-mismatch ----

    /// <summary>The policy compared with the action schema it is written for (see <see cref="AtlasPca.Analyzer.Validate.ValidatePolicyAgainstSchema"/>).</summary>
    public static L RuleSchemaMismatch(D policy, object? schema, object? options)
    {
        var r = AtlasPca.Analyzer.Validate.ValidatePolicyAgainstSchema(AnalyzerInput(policy), schema, options);
        var o = new L();
        foreach (var fo in (L)r["findings"]!)
        {
            var f = (D)fo!;
            var m = Obj(("rule", "schema-mismatch"), ("severity", f["severity"]), ("message", $"{Str(f["code"])}: {Str(f["message"])}"));
            if (f.ContainsKey("where")) m["where"] = f["where"];
            o.Add(m);
        }
        return o;
    }
}
