// Multi-principal aggregation over replay-verified Intent Maps: the joint grant of a rule (unanimity, quorum, weighted, vetoers) per cell, its
// recomputation check, and the cross-organisation form that lifts maps over different outcome spaces onto their common refinement first. The layered
// lattice over a task learner (deny anywhere wins) lives here too. Maps are plain JSON trees.
using System.Text;
using static AtlasPca.IntentPkg.IntentOmega;
using NormalRule = AtlasPca.IntentPkg.IntentMulti.NormalRule;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentMultiAgg
{
    const double Ppm = 1_000_000;

    static double PpmOf(double x) => IntentMath.JsRound(x * Ppm);

    static bool Truthy(object? o) => o != null && !(o is bool b && !b) && !(o is string s && s.Length == 0);

    /// <summary>The error text of an own (reference-defined) failure, else a generic marker for engine-specific faults.</summary>
    internal static string OwnMessage(Exception e)
    {
        var m = e.Message;
        if (m != null && (m.StartsWith("aggregateIntentMaps", StringComparison.Ordinal) || m.StartsWith("ruleOf", StringComparison.Ordinal) || m.StartsWith("liftIntentMap", StringComparison.Ordinal)
            || m.StartsWith("crossOrgAggregate", StringComparison.Ordinal) || m.StartsWith("commonRefinement", StringComparison.Ordinal) || m.StartsWith("pca-intent", StringComparison.Ordinal)
            || m.StartsWith("refineOmega", StringComparison.Ordinal))) return m;
        return "error";
    }

    /// <summary>JSON.stringify of a JSON tree (insertion order).</summary>
    internal static string Stringify(object? v)
    {
        var sb = new StringBuilder();
        Str(sb, v);
        return sb.ToString();
    }

    static void Str(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); return;
            case bool b: sb.Append(b ? "true" : "false"); return;
            case string s:
                sb.Append('"');
                for (int i = 0; i < s.Length; i++)
                {
                    char c = s[i];
                    switch (c)
                    {
                        case '"': sb.Append("\\\""); break;
                        case '\\': sb.Append("\\\\"); break;
                        case '\b': sb.Append("\\b"); break;
                        case '\f': sb.Append("\\f"); break;
                        case '\n': sb.Append("\\n"); break;
                        case '\r': sb.Append("\\r"); break;
                        case '\t': sb.Append("\\t"); break;
                        default:
                            bool lone = char.IsSurrogate(c) && !(char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) && !(char.IsLowSurrogate(c) && i > 0 && char.IsHighSurrogate(s[i - 1]));
                            if (c < 0x20 || lone) sb.Append("\\u").Append(((int)c).ToString("x4"));
                            else sb.Append(c);
                            break;
                    }
                }
                sb.Append('"');
                return;
        }
        if (IsNum(v)) { sb.Append(((Num)N(Dbl(v))!).Raw); return; }
        if (v is L l)
        {
            sb.Append('[');
            for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); Str(sb, l[i]); }
            sb.Append(']');
            return;
        }
        sb.Append('{');
        bool first = true;
        foreach (var e in (D)v)
        {
            if (!first) sb.Append(',');
            first = false;
            Str(sb, e.Key);
            sb.Append(':');
            Str(sb, e.Value);
        }
        sb.Append('}');
    }

    static bool NullKey(D m, string k) => m.ContainsKey(k) && m[k] == null;

    static double Metric(D m, string k) => m.GetValueOrDefault(k) is { } v ? Dbl(v) : 0;

    /// <summary>Aggregate single-principal maps over a shared outcome space under a rule (orgs: intent_ref to organisation label, optional).</summary>
    public static D AggregateIntentMaps(L maps, D rule, D? orgs)
    {
        if (maps.Count == 0) throw new ArgumentException("aggregateIntentMaps: no maps");
        var om = Stringify(Obj(maps[0]).GetValueOrDefault("omega"));
        foreach (var m in maps) if (Stringify(Obj(m).GetValueOrDefault("omega")) != om) throw new ArgumentException("aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)");
        foreach (var mo in maps)
        {
            var m = Obj(mo);
            if (Truthy(m.GetValueOrDefault("aggregation")) || Arr(m.GetValueOrDefault("principals")).Count != 1 || m.GetValueOrDefault("intent_ref") is not string)
                throw new ArgumentException("aggregateIntentMaps: every input must be a single-principal map with an intent_ref");
        }
        var refs = maps.Select(m => (string)Obj(m)["intent_ref"]!).ToList();
        if (new HashSet<string>(refs, StringComparer.Ordinal).Count != refs.Count) throw new ArgumentException("aggregateIntentMaps: duplicate principal");
        var n = IntentMulti.NormalizeRule(rule, refs);
        var omega = IntentMapKit.OmegaFromJson(Obj(maps[0]).GetValueOrDefault("omega"));
        var stats = new List<double[]>();
        foreach (var vs in omega.Verbs)
        {
            double nc = VerbCellCount(vs);
            for (int c = 0; c < nc; c++)
            {
                var s = CellStats(vs, DecodeCell(vs, c), DefaultHarmModel);
                stats.Add(new[] { s.Mass, s.Harm });
            }
        }
        var c0 = Arr(Obj(maps[0]).GetValueOrDefault("cells"));
        var cells = new L();
        for (int i = 0; i < c0.Count; i++)
        {
            var c = Obj(c0[i]);
            var ps = new double[maps.Count];
            var ins = new bool[maps.Count];
            for (int k = 0; k < maps.Count; k++)
            {
                var ck = Obj(Arr(Obj(maps[k]).GetValueOrDefault("cells"))[i]);
                ps[k] = Dbl(ck.GetValueOrDefault("p_ppm")) / Ppm;
                ins[k] = ck.GetValueOrDefault("in_grant") is true;
            }
            cells.Add(new D
            {
                ["verb"] = c.GetValueOrDefault("verb"), ["cell"] = c.GetValueOrDefault("cell"),
                ["p_ppm"] = N(PpmOf(IntentMulti.JointAcceptance(n, ps))), ["in_grant"] = IntentMulti.RuleAdmits(n, ins),
            });
        }
        var predicates = new List<D>();
        var order = new[] { "reversible", "rate_limited", "irreversible" };
        int worstRev = -1;
        int off = 0;
        foreach (var vs in omega.Verbs)
        {
            int nc = (int)VerbCellCount(vs);
            var allowed = new byte[nc];
            bool any = false;
            for (int c = 0; c < nc; c++) if (Obj(cells[off + c]).GetValueOrDefault("in_grant") is true) { allowed[c] = 1; any = true; }
            off += nc;
            if (!any) continue;
            worstRev = Math.Max(worstRev, Array.IndexOf(order, vs.Reversibility));
            predicates.AddRange(IntentLearner.BoxesToPredicates(vs, allowed));
        }
        var caveats = new L();
        if (worstRev >= 0) caveats.Add(new D { ["type"] = "reversibility_max", ["class"] = order[worstRev] });
        var grant = new D { ["predicates"] = predicates.Select(x => (object?)x).ToList(), ["caveats"] = caveats };
        var pR = new double[maps.Count];
        var pB = new double[maps.Count];
        var pF = new double[maps.Count];
        for (int i = 0; i < maps.Count; i++)
        {
            double r = 0, b = 0, rmax = 0;
            var mc = Arr(Obj(maps[i]).GetValueOrDefault("cells"));
            for (int j = 0; j < mc.Count; j++)
            {
                double p = Dbl(Obj(mc[j]).GetValueOrDefault("p_ppm")) / Ppm;
                var st = stats[j];
                rmax += st[0] * (1 - p) * st[1];
                if (Obj(cells[j]).GetValueOrDefault("in_grant") is true) r += st[0] * (1 - p) * st[1];
                else b += st[0] * p;
            }
            pR[i] = r; pB[i] = b; pF[i] = rmax > 0 ? 1 - r / rmax : 1;
        }
        var kind = rule.GetValueOrDefault("kind");
        var agg = new D { ["rule"] = kind };
        if ((kind as string) == "quorum") agg["k"] = rule.GetValueOrDefault("k");
        if ((kind as string) == "weighted")
        {
            var w = new D();
            for (int i = 0; i < refs.Count; i++) w[refs[i]] = N(n.Weights[i]);
            agg["weights"] = w;
            agg["threshold"] = rule.GetValueOrDefault("threshold");
        }
        var vetoers = new L();
        for (int i = 0; i < refs.Count; i++) if (n.Veto[i]) vetoers.Add(refs[i]);
        agg["vetoers"] = vetoers;
        var per = new L();
        double maxR = double.NegativeInfinity, maxB = double.NegativeInfinity, minF = double.PositiveInfinity;
        for (int i = 0; i < refs.Count; i++)
        {
            var x = new D { ["intent_ref"] = refs[i] };
            var org = orgs?.GetValueOrDefault(refs[i]);
            if (Truthy(org)) x["org"] = org;
            double r = PpmOf(pR[i]), b = PpmOf(pB[i]);
            x["residual_risk_ppm"] = N(r);
            x["burden_ppm"] = N(b);
            per.Add(x);
            maxR = Math.Max(maxR, r); maxB = Math.Max(maxB, b); minF = Math.Min(minF, pF[i]);
        }
        agg["per_principal"] = per;
        bool anyNull = maps.Any(m => NullKey(Obj(Obj(m).GetValueOrDefault("metrics")), "log2_vs_mbits"));
        var metrics = new D
        {
            ["residual_risk_ppm"] = N(maxR),
            ["burden_ppm"] = N(maxB),
            ["uncertainty_ppm"] = N(Worst(maps, "uncertainty_ppm", false)),
            ["disagreement_ppm"] = N(Worst(maps, "disagreement_ppm", false)),
            ["mean_harm_ppm"] = Obj(Obj(maps[0]).GetValueOrDefault("metrics")).GetValueOrDefault("mean_harm_ppm"),
            ["fidelity_est_ppm"] = N(PpmOf(minF)),
            ["entropy_mbits"] = N(Worst(maps, "entropy_mbits", true)),
            ["log2_vs_mbits"] = anyNull ? null : N(Worst(maps, "log2_vs_mbits", true)),
            ["questions"] = N(Worst(maps, "questions", true)),
            ["conflicts"] = N(Worst(maps, "conflicts", true)),
        };
        var obs = new L();
        foreach (var m in maps) obs.AddRange(Arr(Obj(m).GetValueOrDefault("observations")));
        return new D
        {
            ["v"] = N(1),
            ["kind"] = "pca-intent-map",
            ["intent_ref"] = null,
            ["principals"] = refs.Select(x => (object?)x).ToList(),
            ["omega"] = Obj(maps[0]).GetValueOrDefault("omega"),
            ["learner"] = Obj(maps[0]).GetValueOrDefault("learner"),
            ["observations"] = obs,
            ["cells"] = cells,
            ["grant"] = grant,
            ["grant_digest"] = IntentMapKit.GrantDigest(grant),
            ["metrics"] = metrics,
            ["aggregation"] = agg,
        };
    }

    static double Worst(L maps, string k, bool sum)
    {
        double acc = sum ? 0 : double.NegativeInfinity;
        foreach (var m in maps)
        {
            double v = Metric(Obj(Obj(m).GetValueOrDefault("metrics")), k);
            acc = sum ? acc + v : Math.Max(acc, v);
        }
        return acc;
    }

    /// <summary>The unanimity rule: the joint grant is the intersection of the principals' conservative grants.</summary>
    public static D CombineIntentMaps(L maps, D? orgs) => AggregateIntentMaps(maps, new D { ["kind"] = "unanimity" }, orgs);

    /// <summary>The rule an aggregated map records.</summary>
    public static D RuleOf(object? aggMap)
    {
        var ao = Obj(aggMap).GetValueOrDefault("aggregation");
        if (!Truthy(ao)) throw new ArgumentException("ruleOf: not an aggregated map");
        var a = Obj(ao);
        var kind = a.GetValueOrDefault("rule") as string;
        if (kind == "unanimity") return new D { ["kind"] = "unanimity", ["vetoers"] = a.GetValueOrDefault("vetoers") };
        if (kind == "quorum") return new D { ["kind"] = "quorum", ["k"] = a.GetValueOrDefault("k"), ["vetoers"] = a.GetValueOrDefault("vetoers") };
        return new D { ["kind"] = "weighted", ["weights"] = a.GetValueOrDefault("weights"), ["threshold"] = a.GetValueOrDefault("threshold"), ["vetoers"] = a.GetValueOrDefault("vetoers") };
    }

    static D Result(bool ok, IEnumerable<string> problems) => new() { ["ok"] = ok, ["problems"] = problems.Select(p => (object?)p).ToList() };

    /// <summary>Verify an aggregated map against its inputs: replay-verify each input, recompute the aggregate and compare digests.</summary>
    public static D VerifyAggregate(object? agg, L inputs, D? orgs)
    {
        var problems = new List<string>();
        try
        {
            for (int i = 0; i < inputs.Count; i++)
            {
                var r = IntentMapKit.VerifyIntentMap(inputs[i]);
                if (!(r["ok"] is true))
                    problems.Add("input " + i + ": " + string.Join("; ", Arr(r["problems"]).Select(p => (string)p!)));
            }
            if (problems.Count > 0) return Result(false, problems);
            var again = AggregateIntentMaps(inputs, RuleOf(agg), orgs);
            if (IntentMapKit.IntentMapDigest(again) != IntentMapKit.IntentMapDigest(agg)) problems.Add("aggregate does not match its recomputation");
        }
        catch (Exception e)
        {
            problems.Add("recompute failed: " + OwnMessage(e));
        }
        return Result(problems.Count == 0, problems);
    }

    /// <summary>Lift a replay-verified single-principal map onto a refinement of its outcome space (unseen verbs are denied: null mass 1).</summary>
    public static D LiftIntentMap(object? mapO, Omega target)
    {
        var m = Obj(mapO);
        if (Truthy(m.GetValueOrDefault("aggregation")) || Arr(m.GetValueOrDefault("principals")).Count > 1) throw new ArgumentException("liftIntentMap: lift single-principal maps, then aggregate");
        var src = IntentMapKit.OmegaFromJson(m.GetValueOrDefault("omega"));
        var o = IntentMapKit.MapLearnerOptionsOf(m);
        var known = new HashSet<string>(src.Verbs.Select(v => v.Verb), StringComparer.Ordinal);
        var nullMass = new Dictionary<string, double>();
        foreach (var vs in target.Verbs)
        {
            double? own = o.NullMassByVerb != null && o.NullMassByVerb.TryGetValue(vs.Verb, out var ov) ? ov : null;
            nullMass[vs.Verb] = known.Contains(vs.Verb) ? (own ?? 0.2) : 1.0;
        }
        var o2 = new IntentMapKit.MapLearnerOptions
        {
            Eta = o.Eta, Tau = o.Tau, DefaultNullMass = o.DefaultNullMass, EtaPos = o.EtaPos, EtaNeg = o.EtaNeg, Strategy = o.Strategy, NullMassByVerb = nullMass,
            Anchor = o.Anchor, Anchors = o.Anchors, HypothesisClass = o.HypothesisClass, AgnosticSlack = o.AgnosticSlack, MonotonePaths = o.MonotonePaths,
            MonotoneOffMass = o.MonotoneOffMass, PriorMixBeta = o.PriorMixBeta, PriorMixCells = o.PriorMixCells,
        };
        var l = IntentMapKit.CreateLearner(target, o2);
        foreach (var obo in Arr(m.GetValueOrDefault("observations")))
        {
            var ob = Obj(obo);
            var verb = (string)ob["verb"]!;
            var svs = src.Verbs.Find(v => v.Verb == verb);
            var tvs = target.Verbs.Find(v => v.Verb == verb);
            if (svs == null || tvs == null) throw new ArgumentException("liftIntentMap: verb " + verb + " missing from Ω");
            var own = new Dictionary<string, object?>();
            foreach (var e in Obj(ob.GetValueOrDefault("values"))) own[e.Key] = IsNum(e.Value) ? Dbl(e.Value) : e.Value;
            var values = new Dictionary<string, object?>(own);
            foreach (var d in tvs.Dims) if (!values.ContainsKey(d.Path)) values[d.Path] = RepValue(d, 0);
            var cell = CellOf(svs, new Outcome(verb, own)) ?? throw new ArgumentException("liftIntentMap: an observation of " + verb + " lies outside the map's own Ω");
            var region = ob.GetValueOrDefault("region") != null ? IntentRegion.Region.FromJson(ob["region"]) : IntentRegion.RegionOfCell(svs, cell);
            l.Observe(new Outcome(verb, values), (int)Dbl(ob.GetValueOrDefault("y")), (string)ob["source"]!, region);
        }
        var ir = m.GetValueOrDefault("intent_ref");
        return IntentMapKit.EmitIntentMap(l, ir == null ? null : (string)ir);
    }

    /// <summary>The aggregate, the lifted maps and the common refinement of a cross-organisation aggregation.</summary>
    public sealed class CrossOrg
    {
        public D Aggregate { get; }
        public L Lifted { get; }
        public Omega Omega { get; }
        internal CrossOrg(D aggregate, L lifted, Omega omega) { Aggregate = aggregate; Lifted = lifted; Omega = omega; }
    }

    /// <summary>Replay-verify every map, lift them all onto the common refinement of their spaces, then aggregate.</summary>
    public static CrossOrg CrossOrgAggregate(L maps, D rule, D? orgs)
    {
        for (int i = 0; i < maps.Count; i++)
        {
            var r = IntentMapKit.VerifyIntentMap(maps[i]);
            if (!(r["ok"] is true)) throw new ArgumentException("crossOrgAggregate: map " + i + " does not verify: " + string.Join("; ", Arr(r["problems"]).Select(p => (string)p!)));
        }
        var omega = IntentMulti.CommonRefinement(maps.Select(m => IntentMapKit.OmegaFromJson(Obj(m).GetValueOrDefault("omega"))).ToList());
        var lifted = new L();
        foreach (var m in maps) lifted.Add(LiftIntentMap(m, omega));
        return new CrossOrg(AggregateIntentMaps(lifted, rule, orgs), lifted, omega);
    }

    /// <summary>Verify a cross-org aggregate by recomputing it from the original maps.</summary>
    public static D VerifyCrossOrgAggregate(object? agg, L maps, D? orgs)
    {
        try
        {
            var again = CrossOrgAggregate(maps, RuleOf(agg), orgs).Aggregate;
            return IntentMapKit.IntentMapDigest(again) == IntentMapKit.IntentMapDigest(agg) ? Result(true, Array.Empty<string>()) : Result(false, new[] { "aggregate does not match its recomputation" });
        }
        catch (Exception e)
        {
            return Result(false, new[] { OwnMessage(e) });
        }
    }

    /// <summary>The outcome space as canonical-order JSON text (for callers that compare maps).</summary>
    public static string OmegaKey(Omega o) => Stringify(IntentMapKit.OmegaToJson(o));
}

/// <summary>The layered lattice over a task learner: deny anywhere wins (a cell outside a ceiling is denied with reason ceiling and is never a question), the
/// effective grant, the uncertain cells (the only cells ever asked about), the wallet-side decision for a concrete outcome, and an organisation layer that
/// is itself a learned map.</summary>
public static class IntentLattice
{
    static L Ints(IEnumerable<int> a) => a.Select(x => (object?)N(x)).ToList();

    /// <summary>{effective, uncertain, ceiling}: cell keys {verb, cell} (ceiling ones with their layer) of the learner's cells under the ceilings.</summary>
    public static D LatticeView(IntentLearner task, IntentLayers.CeilingAdmitters ceilings)
    {
        var effective = new L();
        var uncertain = new L();
        var ceiling = new L();
        foreach (var c in task.Cells())
        {
            var vs = task.Omega.Verbs.Find(v => v.Verb == c.Verb)!;
            var layer = IntentLayers.CeilingOf(ceilings, vs, CellRep(vs, c.Cell));
            var key = new D { ["verb"] = c.Verb, ["cell"] = Ints(c.Cell) };
            if (layer != null)
            {
                key["layer"] = layer;
                ceiling.Add(key);
                continue;
            }
            if (c.Vetoed) continue;
            if (c.InGrant) effective.Add(key);
            else if (c.P > 1e-12 && c.P < task.Tau - 1e-12) uncertain.Add(key);
        }
        return new D { ["effective"] = effective, ["uncertain"] = uncertain, ["ceiling"] = ceiling };
    }

    /// <summary>The wallet-side decision for a concrete outcome against a task learner: {decision, layer?, by?}.</summary>
    public static D DecideOutcomeLayers(IntentLearner task, IntentLayers.CeilingAdmitters ceilings, Outcome o)
    {
        var r = new D();
        var vs = task.Omega.Verbs.Find(v => v.Verb == o.Verb);
        if (vs == null) { r["decision"] = "intent_denied"; return r; }
        var layer = IntentLayers.CeilingOf(ceilings, vs, o);
        if (layer != null) { r["decision"] = "ceiling"; r["layer"] = layer; return r; }
        if (task.IsVetoed(o) || task.Acceptance(o) <= 1e-12) { r["decision"] = "intent_denied"; return r; }
        if (task.AdmitsOutcome(o)) { r["decision"] = "admit"; r["by"] = N(0); return r; }
        r["decision"] = "intent_required";
        return r;
    }

    /// <summary>An org layer that is itself a learned map over a shared space: the joint grant of the approvers' maps under the org's rule. Returns {map, policy}.</summary>
    public static D OrgLayerFromMaps(L maps, D rule)
    {
        var map = IntentMultiAgg.AggregateIntentMaps(maps, rule, null);
        return new D { ["map"] = map, ["policy"] = map["grant"] };
    }
}
