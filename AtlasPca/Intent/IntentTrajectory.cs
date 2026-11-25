// Trajectory intent as ordinary intent: the augmented outcome space adds to every verb one numeric dimension per accumulator (the value the accumulator
// would have after the action) and one categorical dimension per monitor (its state), the lift of a candidate action into it, the per-step admission
// rule, and the accumulators the wallet always adds. Psi, histories and schemas are JSON trees.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentTrajectory
{
    public const string AccDimPrefix = "env.acc.";
    public const string MonDimPrefix = "env.mon.";

    public static string AccDimPath(string id) => AccDimPrefix + id + ".post";

    public static string MonDimPath(string id) => MonDimPrefix + id + ".state";

    /// <summary>The v2 dimension kind of a path: param, acc, mon, canon, world, rel, prov, class or other.</summary>
    public static string DimKindOf(string path)
    {
        if (path.StartsWith("action.params.", StringComparison.Ordinal)) return "param";
        if (path.StartsWith(AccDimPrefix, StringComparison.Ordinal)) return "acc";
        if (path.StartsWith(MonDimPrefix, StringComparison.Ordinal)) return "mon";
        if (path.StartsWith("env.canon.", StringComparison.Ordinal)) return "canon";
        if (path.StartsWith("env.world.", StringComparison.Ordinal)) return "world";
        if (path.StartsWith("env.rel.", StringComparison.Ordinal)) return "rel";
        if (path.StartsWith("env.prov.", StringComparison.Ordinal)) return "prov";
        if (path.StartsWith("env.class.", StringComparison.Ordinal)) return "class";
        return "other";
    }

    static D? SchemaVerb(object? schema, string verb)
    {
        if (schema == null) return null;
        foreach (var v in Arr(Obj(schema).GetValueOrDefault("verbs"))) if (verb == (Obj(v).GetValueOrDefault("verb") as string)) return Obj(v);
        return null;
    }

    static List<string> PredicateVerbs(object? verb)
    {
        var o = new List<string>();
        if (verb is L l) foreach (var x in l) o.Add((string)x!);
        else o.Add((string)verb!);
        return o;
    }

    static bool Selects(D a, string verb, object? schema)
    {
        var sel = Obj(a.GetValueOrDefault("sel"));
        if (sel.GetValueOrDefault("verbs") is L vl && vl.Any(x => x is string s && s == verb)) return true;
        if (sel.GetValueOrDefault("accumulates_into") != null)
        {
            var v = SchemaVerb(schema, verb);
            return v != null && ActionSchema.AccumulationParams(v, (string)sel["accumulates_into"]!).Count > 0;
        }
        return false;
    }

    /// <summary>The augmented space from the outcome space and Psi ({accumulators, monitors}). opts: cuts? (accumulator id to cuts), scope? ("all" | "selected"), schema? ({verbs}).
    /// Wallet-held accumulators are not dimensions.</summary>
    public static Omega AugmentOmega(Omega omega, D psi, D? opts)
    {
        var o = opts ?? new D();
        bool selected = (o.GetValueOrDefault("scope") as string) == "selected";
        var cutsByAcc = o.GetValueOrDefault("cuts") == null ? new D() : Obj(o["cuts"]);
        var verbs = new List<VerbSpace>();
        foreach (var vs in omega.Verbs)
        {
            var extra = new List<Dim>();
            foreach (var ao in Arr(psi.GetValueOrDefault("accumulators")))
            {
                var a = Obj(ao);
                if ((Obj(a.GetValueOrDefault("holder")).GetValueOrDefault("kind") as string) == "wallet") continue;
                if (selected && !Selects(a, vs.Verb, o.GetValueOrDefault("schema"))) continue;
                if (a.GetValueOrDefault("domain_max") == null) throw new ArgumentException("augmentOmega: accumulator '" + JsX.Str(a.GetValueOrDefault("id")) + "' needs domain_max (A_ψ) to be a dimension of Ω̃");
                double dm = Dbl(a["domain_max"]);
                var cuts = new SortedSet<double>();
                if (a.GetValueOrDefault("id") is string aid && cutsByAcc.GetValueOrDefault(aid) != null)
                {
                    foreach (var c in Arr(cutsByAcc[aid]))
                    {
                        double x = IsNum(c) ? Dbl(c) : double.NaN;
                        if (x == Math.Floor(x) && Math.Abs(x) <= 9007199254740991.0 && x >= 0 && x <= dm) cuts.Add(x + 0.0);
                    }
                }
                extra.Add(new NumDim(AccDimPath((string)a["id"]!), 0, dm, cuts.ToArray(), "loguniform"));
            }
            foreach (var mo in Arr(psi.GetValueOrDefault("monitors")))
            {
                var mon = Obj(mo);
                if (selected)
                {
                    bool keep = mon.GetValueOrDefault("q") == null || PredicateVerbs(Obj(mon["q"]).GetValueOrDefault("verb")).Contains(vs.Verb) || PredicateVerbs(Obj(mon["q"]).GetValueOrDefault("verb")).Contains("*");
                    if (!keep) continue;
                }
                var values = (IntentAcc.MonitorStates(mon) ?? throw new InvalidOperationException("monitor kind has no state set")).Select(s => new CatValue("exact", s)).ToList();
                extra.Add(new CatDim(MonDimPath((string)mon["id"]!), values));
            }
            var dims = new List<Dim>();
            foreach (var d in vs.Dims) if (DimKindOf(d.Path) != "acc" && DimKindOf(d.Path) != "mon") dims.Add(d);
            dims.AddRange(extra);
            dims = dims.OrderBy(d => d.Path, Comparer<string>.Create(IntentJs.CompareUtf8)).ToList();
            verbs.Add(new VerbSpace(vs.Verb, vs.Reversibility, vs.Weight, dims));
        }
        return new Omega(verbs, new List<string>(omega.Approximate));
    }

    /// <summary>lift(history, action, t) as an outcome of the augmented space, or null when the verb is not in it. cand: verb, resource, params, t.
    /// Throws where the accumulator or monitor computation does.</summary>
    public static Outcome? LiftAction(Omega omegaTilde, D psi, L history, D cand, object? schema)
    {
        var verb = (string)cand["verb"]!;
        var vs = omegaTilde.Verbs.Find(v => v.Verb == verb);
        if (vs == null) return null;
        var decl = SchemaVerb(schema, verb);
        var parameters = Obj(cand.GetValueOrDefault("params"));
        var values = new Dictionary<string, object?>();
        foreach (var d in vs.Dims)
        {
            var k = DimKindOf(d.Path);
            if (k == "param")
            {
                var name = d.Path.Substring("action.params.".Length);
                var x = parameters.GetValueOrDefault(name);
                if (IsNum(x)) values[d.Path] = Dbl(x);
                else if (x is string) values[d.Path] = x;
            }
            else if (k == "canon")
            {
                var name = d.Path.Substring("env.canon.".Length);
                var pd = decl == null ? null : Obj(decl.GetValueOrDefault("params")).GetValueOrDefault("action.params." + name);
                if (pd != null && parameters.ContainsKey(name)) values[d.Path] = IntentSchema.CanonValue(Obj(pd), parameters[name]);
            }
            else if (k == "acc")
            {
                var id = d.Path.Substring(AccDimPrefix.Length, d.Path.Length - AccDimPrefix.Length - ".post".Length);
                foreach (var ao in Arr(psi.GetValueOrDefault("accumulators")))
                {
                    if (id == (Obj(ao).GetValueOrDefault("id") as string))
                    {
                        var post = IntentHistory.AccPost(Obj(ao), history, verb, parameters, cand.GetValueOrDefault("t"), schema);
                        if (post == null) throw new InvalidOperationException("liftAction: the accumulator '" + id + "' cannot be evaluated for this action");
                        values[d.Path] = (double)post.Value;
                        break;
                    }
                }
            }
            else if (k == "mon")
            {
                var id = d.Path.Substring(MonDimPrefix.Length, d.Path.Length - MonDimPrefix.Length - ".state".Length);
                foreach (var mo in Arr(psi.GetValueOrDefault("monitors")))
                {
                    if (id == (Obj(mo).GetValueOrDefault("id") as string))
                    {
                        var s = IntentHistory.MonitorState(Obj(mo), history);
                        if (s != null) values[d.Path] = s;
                        break;
                    }
                }
            }
            else if (d.Path == "action.resource") values[d.Path] = cand.GetValueOrDefault("resource");
        }
        return new Outcome(verb, values);
    }

    /// <summary>The space and per-dimension cell of a lifted outcome, or null when it lies outside the space.</summary>
    public sealed record LiftedCell(VerbSpace Vs, int[] Cell);

    public static LiftedCell? LiftedCellOf(Omega omegaTilde, Outcome o)
    {
        var vs = omegaTilde.Verbs.Find(v => v.Verb == o.Verb);
        if (vs == null) return null;
        var cell = CellOf(vs, o);
        return cell == null ? null : new LiftedCell(vs, cell);
    }

    /// <summary>The result of one step: whether it was admitted, the new history, and the lifted outcome.</summary>
    public sealed record Step(bool Admitted, L History, Outcome? Lifted);

    /// <summary>The trajectory-grant step rule: admit the action iff its lift lies in a cell inGrant accepts; the history gains a reserved event on admission.</summary>
    public static Step StepTrajectory(Omega omegaTilde, D psi, L history, D cand, Func<string, int[], bool> inGrant, object? schema)
    {
        var lifted = LiftAction(omegaTilde, psi, history, cand, schema);
        var c = lifted == null ? null : LiftedCellOf(omegaTilde, lifted);
        bool ok = c != null && inGrant((string)cand["verb"]!, c.Cell);
        var next = new L(history);
        if (ok)
            next.Add(new D
            {
                ["id"] = cand.GetValueOrDefault("id"), ["verb"] = cand.GetValueOrDefault("verb"), ["resource"] = cand.GetValueOrDefault("resource"),
                ["params"] = cand.GetValueOrDefault("params"), ["t"] = cand.GetValueOrDefault("t"), ["status"] = "reserved",
            });
        return new Step(ok, next, lifted);
    }

    static string Sanitize(string u)
    {
        var s = Regex.Replace(u, "[^A-Za-z0-9_]", "_");
        return s.Length > 58 ? s.Substring(0, 58) : s;
    }

    /// <summary>The accumulators the wallet always adds: a per-task spend sum for every accumulation unit any verb feeds, a per-verb spend sum for every untagged
    /// money.amount integer parameter, and the wallet-held question counter. holder defaults to site_local.</summary>
    public static List<D> DefaultAccumulators(object? schema, double spendDomainMax, double? questionCap, D? holderIn)
    {
        var holder = holderIn ?? new D { ["kind"] = "site_local" };
        var units = new SortedSet<string>(Comparer<string>.Create(IntentJs.CompareUtf8));
        var untagged = new List<string[]>();
        foreach (var vo in Arr(Obj(schema).GetValueOrDefault("verbs")))
        {
            var v = Obj(vo);
            foreach (var e in Obj(v.GetValueOrDefault("params")))
            {
                var d = Obj(e.Value);
                var into = d.GetValueOrDefault("accumulates_into") is L il ? il : new L();
                foreach (var u in into) units.Add((string)u!);
                if ((d.GetValueOrDefault("type") as string) == "integer" && (d.GetValueOrDefault("semantic") as string) == "money.amount" && into.Count == 0) untagged.Add(new[] { (string)v["verb"]!, e.Key });
            }
        }
        var o = new List<D>();
        foreach (var u in units)
            o.Add(new D
            {
                ["id"] = "spend_" + Sanitize(u), ["agg"] = "sum", ["unit"] = u, ["sel"] = new D { ["accumulates_into"] = u }, ["win"] = new D { ["kind"] = "task" },
                ["key"] = null, ["domain_max"] = N(spendDomainMax), ["holder"] = holder,
            });
        untagged = untagged.OrderBy(x => x[0] + x[1], Comparer<string>.Create(IntentJs.CompareUtf8)).ToList();
        foreach (var u in untagged)
        {
            var id = "spend_" + Sanitize(u[0]) + "_" + Sanitize(u[1].Substring("action.params.".Length));
            o.Add(new D
            {
                ["id"] = id.Length > 64 ? id.Substring(0, 64) : id, ["agg"] = "sum", ["val"] = u[1], ["sel"] = new D { ["verbs"] = new L { u[0] } },
                ["win"] = new D { ["kind"] = "task" }, ["key"] = null, ["domain_max"] = N(spendDomainMax), ["holder"] = holder,
            });
        }
        o.Add(new D
        {
            ["id"] = "questions", ["agg"] = "count", ["sel"] = new D { ["event"] = "intent_required" }, ["win"] = new D { ["kind"] = "task" }, ["key"] = null,
            ["cap"] = N(questionCap ?? 6.0), ["holder"] = new D { ["kind"] = "wallet" },
        });
        return o;
    }

    /// <summary>The fact line for an accumulator dimension of a cell (fmt: amount renderer, default the integer; thisAction may be null).</summary>
    public static string DescribeAccCell(NumDim d, int cellIndex, string label, double? thisAction, Func<double, string>? fmt = null)
    {
        var f = fmt ?? (x => JsX.JsNumString(x));
        var cells = NumCells(d);
        if (cellIndex < 0 || cellIndex >= cells.Count) throw new ArgumentException("describeAccCell: no such cell");
        var c = cells[cellIndex];
        var range = c.Lo == c.Hi ? "exactly " + f(c.Lo) : "between " + f(c.Lo) + " and " + f(c.Hi);
        return label + ": " + range + (thisAction != null ? " (this action: " + f(thisAction.Value) + ")" : "");
    }

    /// <summary>The per-session harm range of a trajectory Monte Carlo estimate: [0, L_max * H_max].</summary>
    public static double TrajectoryHarmRange(double maxSessionLength, double harmMax)
    {
        if (!(maxSessionLength == Math.Floor(maxSessionLength) && Math.Abs(maxSessionLength) <= 9007199254740991.0 && maxSessionLength >= 0) || !(harmMax >= 0)) throw new ArgumentException("trajectoryHarmRange: bad arguments");
        return maxSessionLength * harmMax;
    }
}
