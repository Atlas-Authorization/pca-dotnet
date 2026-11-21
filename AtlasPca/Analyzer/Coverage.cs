using System.Globalization;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Policy coverage ("opa test --coverage" for PCA). Over a body of traffic it reports which clauses of a policy ever DECIDED,
/// which never even matched, which the analyzer says are unreachable, how close the traffic came to each numeric threshold, and which
/// single-edit mutations of the policy (widen a cap, drop a prohibition, flip lte to lt) the traffic cannot tell from the original.
/// A surviving mutant is a missing test and comes with the action that would kill it; a mutant proven equivalent is not a gap.</summary>
public static class Coverage
{
    public static string PermitId(int i) => $"permit[{i.ToString(CultureInfo.InvariantCulture)}]";

    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    static object? IdOf(object? x) { var v = Jx.Prop(x, "id"); return Jx.IsUndef(v) ? null : v; }

    /// <summary>The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit. Returns
    /// {decision, winner: {kind, id}, also: [other clauses that fired]}.</summary>
    public static D WitnessOf(PolicyModel model, object? action)
    {
        var decision = Enumerate.DecideAction(model, action);
        var ctx = Enumerate.ContextOfAction(action);
        var permits = new List<object?>();
        for (int i = 0; i < model.Predicates.Count; i++) if (Predicates.PredicateMatches(model.Predicates[i], ctx)) permits.Add(PermitId(i));
        var vetoes = model.Vetoes.Where(v => Enumerate.VetoApplies(v, ctx)).ToList();
        var tighten = model.Tighten.Where(t => Predicates.EvaluateConditionTri(JsX.JsonOf(Jx.Prop(t, "when")), ctx) != Predicates.Tri.False).ToList();

        D Done(string kind, object? id)
        {
            var all = new List<object?>(permits);
            all.AddRange(vetoes.Select(IdOf));
            all.AddRange(tighten.Select(IdOf));
            return new D { ["decision"] = decision, ["winner"] = new D { ["kind"] = kind, ["id"] = id }, ["also"] = all.Where(x => !JsX.StrictEq(x, id)).ToList() };
        }

        if (!model.CaveatSat || decision == "deny")
        {
            if (!model.CaveatSat) return Done("caveat", "caveats");
            if (permits.Count == 0) return Done("none", null);
            foreach (var v in vetoes) if (Jx.Prop(v, "kind") is string k && k == "deny") return Done("veto", IdOf(v));
            foreach (var t in tighten) if (Jx.Prop(t, "signal") is string sg && sg == "deny") return Done("tighten", IdOf(t));
            return Done("caveat", "caveats"); // reversibility cap or an ancestor of the chain
        }
        if (decision == "escalate")
        {
            foreach (var v in vetoes) if (Jx.Prop(v, "kind") is string k && k == "approval") return Done("veto", IdOf(v));
            return Done("tighten", tighten.Count > 0 ? IdOf(tighten[0]) : null);
        }
        return Done("permit", permits.Count > 0 ? permits[0] : null);
    }

    // ---- mutation operators ----

    static readonly Dictionary<string, string> Flip = new()
    {
        ["lt"] = "lte", ["lte"] = "lt", ["gt"] = "gte", ["gte"] = "gt", ["eq"] = "ne", ["ne"] = "eq", ["in"] = "nin", ["nin"] = "in",
    };

    static readonly string[] NumOps = { "lt", "lte", "gt", "gte", "eq" };

    static L Kids(object? o) => o as L ?? throw JsX.TypeError("kids.forEach is not a function");

    static List<(object? Cond, string What)> VariantsOfCond(object? c, double eps)
    {
        var @out = new List<(object? Cond, string What)>();
        if (c is not D d) return @out;
        if (IsGroup(d))
        {
            if (d.ContainsKey("not"))
            {
                foreach (var v in VariantsOfCond(d["not"], eps)) @out.Add((new D { ["not"] = v.Cond }, $"not({v.What})"));
                return @out;
            }
            var isAll = d.ContainsKey("all_of");
            var key = isAll ? "all_of" : "any_of";
            var kids = Kids(d[key]);
            for (int i = 0; i < kids.Count; i++)
                foreach (var v in VariantsOfCond(kids[i], eps))
                {
                    var next = new L(kids) { [i] = v.Cond };
                    @out.Add((new D { [key] = next }, $"{key}[{i.ToString(CultureInfo.InvariantCulture)}] {v.What}"));
                }
            return @out;
        }
        if (!Field.IsLeaf(d) || d.ContainsKey("ref")) return @out;
        var field = (string)d["field"]!;
        var name = field.StartsWith("action.params.", StringComparison.Ordinal) ? field["action.params.".Length..] : field;
        var op = d.GetValueOrDefault("op");
        var value = d.GetValueOrDefault("value");
        if (Jx.Fin(value) is double x && op is string ops && NumOps.Contains(ops))
        {
            var up = Jx.Copy(d); up["value"] = Jx.N(x + eps);
            @out.Add((up, $"{name} {ops} {Jx.NumStr(x)} -> {Jx.NumStr(x + eps)}"));
            var down = Jx.Copy(d); down["value"] = Jx.N(x - eps);
            @out.Add((down, $"{name} {ops} {Jx.NumStr(x)} -> {Jx.NumStr(x - eps)}"));
        }
        if (op is string o2 && Flip.TryGetValue(o2, out var fl))
        {
            var f = Jx.Copy(d); f["op"] = fl;
            @out.Add((f, $"{name} {o2} -> {fl}"));
        }
        return @out;
    }

    sealed record Mutant(string Id, string Description, D Policy);

    static D Mk(PolicyModel p, L predicates, L vetoes, L tighten) => new() { ["predicates"] = predicates, ["caveats"] = p.Caveats, ["vetoes"] = vetoes, ["tighten"] = tighten };

    static L Without(L xs, int i) { var o = new L(xs); o.RemoveAt(i); return o; }
    static L Replaced(L xs, int i, object? v) { var o = new L(xs); o[i] = v; return o; }

    static List<Mutant> MutantsOf(PolicyModel policy, double eps)
    {
        var @out = new List<Mutant>();
        for (int i = 0; i < policy.Predicates.Count; i++)
        {
            var p = policy.Predicates[i];
            var pid = PermitId(i);
            @out.Add(new Mutant($"drop-{pid}", $"drop {pid}", Mk(policy, Without(policy.Predicates, i), policy.Vetoes, policy.Tighten)));
            var w = Jx.Prop(p, "where");
            if (w == null || Jx.IsUndef(w)) continue;
            var where = w as L ?? throw JsX.TypeError("(p.where ?? []).forEach is not a function");
            for (int j = 0; j < where.Count; j++)
            {
                var js = j.ToString(CultureInfo.InvariantCulture);
                foreach (var v in VariantsOfCond(where[j], eps))
                {
                    var np = JsX.Spread(p); np["where"] = Replaced(where, j, v.Cond);
                    @out.Add(new Mutant($"{pid}.where[{js}]:{v.What}", $"{pid}: {v.What}", Mk(policy, Replaced(policy.Predicates, i, np), policy.Vetoes, policy.Tighten)));
                }
                var np2 = JsX.Spread(p); np2["where"] = Without(where, j);
                @out.Add(new Mutant($"{pid}.where[{js}]:drop", $"{pid}: drop condition {js}", Mk(policy, Replaced(policy.Predicates, i, np2), policy.Vetoes, policy.Tighten)));
            }
        }
        for (int i = 0; i < policy.Vetoes.Count; i++)
        {
            var v = policy.Vetoes[i];
            var id = JsX.Str(Jx.Prop(v, "id"));
            @out.Add(new Mutant($"drop-veto:{id}", $"drop prohibition {id}", Mk(policy, policy.Predicates, Without(policy.Vetoes, i), policy.Tighten)));
            var over = Jx.Prop(v, "over");
            if (Jx.Truthy(over))
            {
                var nv = JsX.Spread(v);
                var no = JsX.Spread(over);
                no["threshold"] = Jx.N(Jx.ToNumber(Jx.Prop(over, "threshold")) + eps);
                nv["over"] = no;
                @out.Add(new Mutant($"veto:{id}:threshold+", $"raise the {id} threshold by {Jx.NumStr(eps)}", Mk(policy, policy.Predicates, Replaced(policy.Vetoes, i, nv), policy.Tighten)));
            }
        }
        for (int i = 0; i < policy.Tighten.Count; i++)
        {
            var id = JsX.Str(Jx.Prop(policy.Tighten[i], "id"));
            @out.Add(new Mutant($"drop-tighten:{id}", $"drop tighten rule {id}", Mk(policy, policy.Predicates, policy.Vetoes, Without(policy.Tighten, i))));
        }
        return @out;
    }

    static readonly string[] BoundOps = { "lt", "lte", "gt", "gte", "eq", "in", "nin" };

    static void WalkParams(object? c, Jx.OSet paths)
    {
        if (c is not D d) return;
        if (IsGroup(d))
        {
            if (d.ContainsKey("all_of")) foreach (var x in Kids(d["all_of"])) WalkParams(x, paths);
            else if (d.ContainsKey("any_of")) foreach (var x in Kids(d["any_of"])) WalkParams(x, paths);
            else WalkParams(d["not"], paths);
        }
        else if (Field.IsLeaf(d) && ((string)d["field"]!).StartsWith("action.params.", StringComparison.Ordinal) && d.GetValueOrDefault("op") is string op && BoundOps.Contains(op))
            paths.Add((string)d["field"]!);
    }

    /// <summary>reachable per the analyzer: true, false, or "unknown".</summary>
    static object Reach(PolicyModel model, string kind, int idx)
    {
        D r;
        if (kind == "permit") r = AnalyzerCore.AlwaysDenies(new D { ["predicates"] = new L { model.Predicates[idx] }, ["caveats"] = model.Caveats });
        else if (kind == "veto") r = AnalyzerCore.AlwaysDenies(new D { ["predicates"] = new L { Jx.Prop(model.Vetoes[idx], "when") } });
        else return "unknown";
        return Jx.Truthy(r.GetValueOrDefault("approximate")) ? "unknown" : (object)!(r.GetValueOrDefault("alwaysDenies") is true);
    }

    static double Ratio(double n, double d) => d == 0 ? 1 : n / d;

    static double OptNum(object? o, string k, double dflt)
    {
        var v = Jx.Opt(o, k);
        return v == null || Jx.IsUndef(v) ? dflt : Jx.ToNumber(v);
    }

    sealed class Clause { public object? Id; public string Kind = ""; public int Matched; public int Decisive; public object Reachable = "unknown"; }

    /// <summary>Coverage of <paramref name="policy"/> by <paramref name="traffic"/> (production traffic, simulated actions or the cases of a test
    /// document). Options: epsilon (default 1), maxMutants (200).</summary>
    public static D Compute(object? policy, object? traffic, object? o = null)
    {
        var model = Enumerate.ToModel(policy);
        var eps = OptNum(o, "epsilon", 1);
        var tr = traffic as L ?? throw JsX.TypeError("traffic is not iterable");
        var clauses = new List<Clause>();
        for (int i = 0; i < model.Predicates.Count; i++) clauses.Add(new Clause { Id = PermitId(i), Kind = "permit" });
        foreach (var v in model.Vetoes) clauses.Add(new Clause { Id = Jx.Prop(v, "id"), Kind = "veto" });
        foreach (var t in model.Tighten) clauses.Add(new Clause { Id = Jx.Prop(t, "id"), Kind = "tighten" });
        var matched = new Dictionary<string, int>(StringComparer.Ordinal);
        var decisive = new Dictionary<string, int>(StringComparer.Ordinal);
        static void Bump(Dictionary<string, int> m, object? id) { if (id == null || Jx.IsUndef(id)) return; var k = JsX.Str(id); m[k] = m.GetValueOrDefault(k) + 1; }
        foreach (var a in tr)
        {
            var w = WitnessOf(model, a);
            var winId = ((D)w["winner"]!)["id"];
            Bump(decisive, winId);
            Bump(matched, winId);
            foreach (var id in (L)w["also"]!) Bump(matched, id);
        }
        for (int n = 0; n < clauses.Count; n++)
        {
            var c = clauses[n];
            var idx = c.Kind == "permit" ? n : c.Kind == "veto" ? n - model.Predicates.Count : n - model.Predicates.Count - model.Vetoes.Count;
            var key = Jx.IsUndef(c.Id) || c.Id == null ? null : JsX.Str(c.Id);
            c.Matched = key == null ? 0 : matched.GetValueOrDefault(key);
            c.Decisive = key == null ? 0 : decisive.GetValueOrDefault(key);
            c.Reachable = Reach(model, c.Kind, idx);
        }

        var paths = new Jx.OSet();
        foreach (var p in Enumerate.ProbeSet(model))
        {
            var w = Jx.Prop(p, "where");
            if (w == null || Jx.IsUndef(w)) continue;
            foreach (var c in w as L ?? throw JsX.TypeError("(p.where ?? []).forEach is not a function")) WalkParams(c, paths);
        }
        foreach (var v in model.Vetoes)
        {
            var over = Jx.Prop(v, "over");
            if (Jx.Truthy(over) && Jx.Prop(over, "path") is string ps) paths.Add(ps);
        }
        var boundaries = new L();
        foreach (var path in paths.ToList().OrderBy(x => x, StringComparer.Ordinal))
        {
            var name = path["action.params.".Length..];
            var vals = new List<double>();
            foreach (var a in tr)
            {
                var pp = Jx.Prop(a, "params");
                var v = pp == null || Jx.IsUndef(pp) ? Jx.Undef : Jx.Prop(pp, name);
                if (Jx.IsNum(v)) vals.Add(IntentJs.NumOf(v)!.Value);
            }
            foreach (var t in Exposure.ThresholdsOf(model, path))
                boundaries.Add(new D
                {
                    ["path"] = path, ["threshold"] = Jx.NumOut(t),
                    ["below"] = vals.Any(v => v < t && v >= t - eps), ["at"] = vals.Any(v => v == t), ["above"] = vals.Any(v => v > t && v <= t + eps),
                });
        }

        var survivors = new L();
        int killed = 0, equiv = 0;
        var allM = MutantsOf(model, eps);
        var maxM = OptNum(o, "maxMutants", 200);
        // Array.prototype.slice(0, maxMutants)
        var cut = double.IsNaN(maxM) ? 0 : Math.Truncate(maxM);
        int take = cut < 0 ? (int)Math.Max(allM.Count + cut, 0) : (int)Math.Min(cut, allM.Count);
        allM = allM.Take(take).ToList();
        var baseDecisions = tr.Select(a => Enumerate.DecideAction(model, a)).ToList();
        foreach (var m in allM)
        {
            var mm = Enumerate.ToModel(m.Policy);
            var differs = false;
            for (int i = 0; i < tr.Count; i++) if (Enumerate.DecideAction(mm, tr[i]) != baseDecisions[i]) { differs = true; break; }
            if (differs) { killed++; continue; }
            var eq = AnalyzerCore.Equivalent(policy, m.Policy);
            if (eq.GetValueOrDefault("equivalent") is true) { equiv++; continue; }
            var s = new D { ["id"] = m.Id, ["description"] = m.Description };
            if (Jx.Truthy(eq.GetValueOrDefault("counterexample"))) s["killer"] = eq["counterexample"];
            survivors.Add(s);
        }
        var live = clauses.Where(c => !(c.Reachable is false)).ToList();
        var bFull = boundaries.Count(b => ((D)b!)["at"] is true && ((D)b)["below"] is true && ((D)b)["above"] is true);
        return new D
        {
            ["traffic"] = Jx.N(tr.Count),
            ["policyDigest"] = Residual.PolicyDigestOf(model),
            ["clauses"] = clauses.Select(c => (object?)new D { ["id"] = c.Id, ["kind"] = c.Kind, ["matched"] = Jx.N(c.Matched), ["decisive"] = Jx.N(c.Decisive), ["reachable"] = c.Reachable }).ToList(),
            ["neverMatched"] = clauses.Where(c => c.Matched == 0).Select(c => c.Id).ToList(),
            ["neverDecisive"] = clauses.Where(c => c.Decisive == 0).Select(c => c.Id).ToList(),
            ["untested"] = clauses.Where(c => !(c.Reachable is false) && c.Matched == 0).Select(c => c.Id).ToList(),
            ["unreachable"] = clauses.Where(c => c.Reachable is false).Select(c => c.Id).ToList(),
            ["boundaries"] = boundaries,
            ["mutants"] = new D { ["total"] = Jx.N(allM.Count), ["killed"] = Jx.N(killed), ["equivalent"] = Jx.N(equiv), ["survivors"] = survivors },
            ["score"] = new D
            {
                ["clauses"] = Jx.N(Ratio(live.Count(c => c.Decisive > 0), live.Count)),
                ["boundaries"] = Jx.N(Ratio(bFull, boundaries.Count)),
                ["mutation"] = Jx.N(Ratio(killed, allM.Count - equiv)),
            },
        };
    }

    /// <summary>JavaScript <c>x.toFixed(2)</c> for a value in [0, 1] (exact, a tie rounds up).</summary>
    static string ToFixed2(double r)
    {
        if (!double.IsFinite(r) || r < 0) return r.ToString("F2", CultureInfo.InvariantCulture);
        long bits = BitConverter.DoubleToInt64Bits(r);
        int exp = (int)((bits >> 52) & 0x7FF);
        var m = new System.Numerics.BigInteger(exp == 0 ? bits & 0xFFFFFFFFFFFFFL : (bits & 0xFFFFFFFFFFFFFL) | (1L << 52));
        int e = (exp == 0 ? 1 : exp) - 1075;
        System.Numerics.BigInteger n = e >= 0 ? (m << e) * 100 : ((m * 200) + (System.Numerics.BigInteger.One << -e)) >> (1 - e);
        return $"{n / 100}.{(int)(n % 100):D2}";
    }

    /// <summary>A CI gate over a coverage report: {ok, reasons}. <paramref name="min"/>: clauses, boundaries, mutation, maxSurvivors.</summary>
    public static D Gate(object? r, object? min = null)
    {
        var reasons = new L();
        var score = Jx.Prop(r, "score");
        double Sc(string k) => Jx.ToNumber(Jx.Prop(score, k));
        double Min(string k) => OptNum(min, k, 0);
        if (Sc("clauses") < Min("clauses")) reasons.Add($"clause coverage {ToFixed2(Sc("clauses"))} < {JsX.Str(Jx.Opt(min, "clauses"))}");
        if (Sc("boundaries") < Min("boundaries")) reasons.Add($"boundary coverage {ToFixed2(Sc("boundaries"))} < {JsX.Str(Jx.Opt(min, "boundaries"))}");
        if (Sc("mutation") < Min("mutation")) reasons.Add($"mutation score {ToFixed2(Sc("mutation"))} < {JsX.Str(Jx.Opt(min, "mutation"))}");
        var ms = Jx.Opt(min, "maxSurvivors");
        var surv = Jx.Prop(Jx.Prop(r, "mutants"), "survivors") as L ?? throw JsX.TypeError("survivors.length");
        if (!Jx.IsUndef(ms) && surv.Count > Jx.ToNumber(ms)) reasons.Add($"{surv.Count} surviving mutants > {JsX.Str(ms)}");
        var unr = Jx.Prop(r, "unreachable") as L ?? throw JsX.TypeError("unreachable.length");
        if (unr.Count > 0) reasons.Add("unreachable clauses: " + string.Join(", ", unr.Select(u => u == null ? "" : JsX.Str(u))));
        return new D { ["ok"] = reasons.Count == 0, ["reasons"] = reasons };
    }
}
