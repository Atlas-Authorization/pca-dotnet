// The Intent Map: a content-addressed JSON artifact holding the outcome space, the prior, every answer, the learned acceptance per cell,
// the conservative grant and the quantified fidelity. Every probability and metric is an integer in parts per million, so the digest is
// language-portable. VerifyIntentMap replays the map and re-derives every number. Maps are plain JSON trees.
using System.Runtime.CompilerServices;
using static AtlasPca.IntentPkg.IntentOmega;
using AnchorSpec = AtlasPca.IntentPkg.IntentLearner.AnchorSpec;
using HypothesisClassSpec = AtlasPca.IntentPkg.IntentLearner.HypothesisClassSpec;
using LearnerOptions = AtlasPca.IntentPkg.IntentLearner.LearnerOptions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentMapKit
{
    public const string IntentMapDomain = "atlas-pca/intent-map/v1";
    const double Ppm = 1_000_000;

    static double JsRound(double x) => IntentMath.JsRound(x);
    static double PpmOf(double x) => JsRound(x * Ppm);
    static double Qz(double x) => JsRound(x * Ppm) / Ppm;

    // ---- options carried by a map ----

    public sealed class PolicyData
    {
        public object? Predicates { get; }
        public object? Caveats { get; }
        public PolicyData(object? predicates, object? caveats) { Predicates = predicates; Caveats = caveats; }
        public D ToJson() => new() { ["predicates"] = Predicates, ["caveats"] = Caveats ?? new L() };
    }

    public sealed class AnchorIn
    {
        public PolicyData Policy { get; }
        public double Lambda { get; }
        public AnchorIn(PolicyData policy, double lambda) { Policy = policy; Lambda = lambda; }
        internal static AnchorIn FromJson(object? o)
        {
            var m = Obj(o);
            var p = Obj(m.GetValueOrDefault("policy"));
            return new AnchorIn(new PolicyData(p.GetValueOrDefault("predicates"), p.GetValueOrDefault("caveats")), Dbl(m.GetValueOrDefault("lambda")));
        }
        internal D ToJson() => new() { ["policy"] = Policy.ToJson(), ["lambda"] = N(Lambda) };
    }

    public sealed class PriorMixCell
    {
        public string Verb { get; }
        public double Cell { get; }
        public double Q { get; }
        public PriorMixCell(string verb, double cell, double q) { Verb = verb; Cell = cell; Q = q; }
    }

    /// <summary>The serialisable learner parameters (every field optional; null = the default).</summary>
    public sealed class MapLearnerOptions
    {
        public double? Eta, Tau, DefaultNullMass, EtaPos, EtaNeg;
        public string? Strategy;
        public double? NullMassNumber;
        public Dictionary<string, double>? NullMassByVerb;
        public AnchorIn? Anchor;
        public List<AnchorIn>? Anchors;
        public HypothesisClassSpec? HypothesisClass;
        public double? AgnosticSlack;
        public List<string>? MonotonePaths;
        public double? MonotoneOffMass;
        public double? PriorMixBeta;
        public List<PriorMixCell>? PriorMixCells;

        public static MapLearnerOptions FromJson(object? o)
        {
            var r = new MapLearnerOptions();
            if (o == null) return r;
            var m = Obj(o);
            r.Eta = IntentLearner.NumOrNull(m.GetValueOrDefault("eta")); r.Tau = IntentLearner.NumOrNull(m.GetValueOrDefault("tau"));
            r.DefaultNullMass = IntentLearner.NumOrNull(m.GetValueOrDefault("defaultNullMass"));
            r.EtaPos = IntentLearner.NumOrNull(m.GetValueOrDefault("etaPos")); r.EtaNeg = IntentLearner.NumOrNull(m.GetValueOrDefault("etaNeg"));
            r.Strategy = m.GetValueOrDefault("strategy") as string;
            var nm = m.GetValueOrDefault("nullMass");
            if (nm != null)
            {
                if (IsNum(nm)) r.NullMassNumber = Dbl(nm);
                else
                {
                    r.NullMassByVerb = new Dictionary<string, double>();
                    foreach (var e in Obj(nm)) r.NullMassByVerb[e.Key] = Dbl(e.Value);
                }
            }
            if (m.GetValueOrDefault("anchor") != null) r.Anchor = AnchorIn.FromJson(m["anchor"]);
            if (m.GetValueOrDefault("anchors") != null)
            {
                r.Anchors = new List<AnchorIn>();
                foreach (var a in Arr(m["anchors"])) r.Anchors.Add(AnchorIn.FromJson(a));
            }
            if (m.GetValueOrDefault("hypothesisClass") != null) r.HypothesisClass = HypothesisClassSpec.FromJson(m["hypothesisClass"]);
            r.AgnosticSlack = IntentLearner.NumOrNull(m.GetValueOrDefault("agnosticSlack"));
            if (m.GetValueOrDefault("monotone") != null)
            {
                var mo = Obj(m["monotone"]);
                r.MonotonePaths = new List<string>();
                foreach (var x in Arr(mo.GetValueOrDefault("paths"))) r.MonotonePaths.Add((string)x!);
                r.MonotoneOffMass = IntentLearner.NumOrNull(mo.GetValueOrDefault("offMass"));
            }
            if (m.GetValueOrDefault("priorMix") != null)
            {
                var pm = Obj(m["priorMix"]);
                r.PriorMixBeta = Dbl(pm.GetValueOrDefault("beta"));
                r.PriorMixCells = new List<PriorMixCell>();
                foreach (var c in Arr(pm.GetValueOrDefault("cells")))
                {
                    var cm = Obj(c);
                    r.PriorMixCells.Add(new PriorMixCell((string)cm["verb"]!, Dbl(cm.GetValueOrDefault("cell")), Dbl(cm.GetValueOrDefault("q"))));
                }
            }
            return r;
        }

        /// <summary>The JSON form of these options (absent fields omitted).</summary>
        public D ToJson()
        {
            var m = new D();
            if (Eta != null) m["eta"] = N(Eta.Value);
            if (Tau != null) m["tau"] = N(Tau.Value);
            if (Strategy != null) m["strategy"] = Strategy;
            if (NullMassNumber != null) m["nullMass"] = N(NullMassNumber.Value);
            if (NullMassByVerb != null)
            {
                var nm = new D();
                foreach (var e in NullMassByVerb) nm[e.Key] = N(e.Value);
                m["nullMass"] = nm;
            }
            if (Anchor != null) m["anchor"] = Anchor.ToJson();
            if (Anchors != null) m["anchors"] = Anchors.Select(a => (object?)a.ToJson()).ToList();
            if (HypothesisClass != null)
            {
                var h = HypothesisClass;
                var hm = new D { ["kind"] = h.Kind };
                if (h.K != null) hm["k"] = N(h.K.Value);
                if (h.MaxRules != null) hm["maxRules"] = N(h.MaxRules.Value);
                if (h.Decay != null) hm["decay"] = N(h.Decay.Value);
                if (h.Conditions != null) hm["conditions"] = h.Conditions;
                m["hypothesisClass"] = hm;
            }
            if (AgnosticSlack != null) m["agnosticSlack"] = N(AgnosticSlack.Value);
            if (MonotonePaths != null)
            {
                var mo = new D { ["paths"] = MonotonePaths.Select(x => (object?)x).ToList() };
                if (MonotoneOffMass != null) mo["offMass"] = N(MonotoneOffMass.Value);
                m["monotone"] = mo;
            }
            if (EtaPos != null) m["etaPos"] = N(EtaPos.Value);
            if (EtaNeg != null) m["etaNeg"] = N(EtaNeg.Value);
            if (PriorMixBeta != null)
            {
                var pm = new D { ["beta"] = N(PriorMixBeta.Value) };
                pm["cells"] = PriorMixCells!.Select(c => (object?)new D { ["verb"] = c.Verb, ["cell"] = N(c.Cell), ["q"] = N(c.Q) }).ToList();
                m["priorMix"] = pm;
            }
            return m;
        }
    }

    // ---- omega <-> JSON ----

    public static D OmegaToJson(Omega o)
    {
        bool equal = true;
        foreach (var v in o.Verbs) if (!(Math.Abs(v.Weight - o.Verbs[0].Weight) < 1e-15)) equal = false;
        var verbs = new L();
        foreach (var v in o.Verbs)
        {
            var m = new D
            {
                ["verb"] = v.Verb,
                ["reversibility"] = v.Reversibility,
                ["w"] = equal ? N(1) : N(Math.Max(1, JsRound(v.Weight * Ppm))),
                ["dims"] = v.Dims.Select(d => (object?)DimToJson(d)).ToList(),
            };
            verbs.Add(m);
        }
        return new D { ["verbs"] = verbs, ["approximate"] = o.Approximate.Select(x => (object?)x).ToList() };
    }

    public static Omega OmegaFromJson(object? j)
    {
        var jm = Obj(j);
        var vs = Arr(jm.GetValueOrDefault("verbs"));
        double tot = 0;
        foreach (var v in vs) tot += Dbl(Obj(v).GetValueOrDefault("w"));
        var verbs = new List<VerbSpace>();
        foreach (var v in vs)
        {
            var vm = Obj(v);
            var dims = new List<Dim>();
            foreach (var d in Arr(vm.GetValueOrDefault("dims")))
            {
                var dm = Obj(d);
                if ((dm.GetValueOrDefault("kind") as string) == "num")
                {
                    var cs = dm.GetValueOrDefault("cuts") == null ? new L() : Arr(dm["cuts"]);
                    var cuts = new double[cs.Count];
                    for (int i = 0; i < cuts.Length; i++) cuts[i] = Dbl(cs[i]);
                    dims.Add(new NumDim((string)dm["path"]!, Dbl(dm.GetValueOrDefault("lo")), Dbl(dm.GetValueOrDefault("hi")), cuts, dm.GetValueOrDefault("dist") == null ? "uniform" : (string)dm["dist"]!));
                }
                else
                {
                    var cv = new List<CatValue>();
                    // a categorical dimension holds one of its values: with none it can hold nothing, so it is refused (never read as an empty list)
                    if (dm.GetValueOrDefault("values") is not L vl || vl.Count == 0) throw new ArgumentException($"omegaFromJSON: categorical dimension '{dm.GetValueOrDefault("path")}' has no values");
                    foreach (var x in vl) cv.Add(new CatValue((string)Obj(x)["kind"]!, (string)Obj(x)["value"]!));
                    dims.Add(new CatDim((string)dm["path"]!, cv));
                }
            }
            verbs.Add(new VerbSpace((string)vm["verb"]!, (string)vm["reversibility"]!, Dbl(vm.GetValueOrDefault("w")) / tot, dims));
        }
        var approx = new List<string>();
        foreach (var x in Arr(jm.GetValueOrDefault("approximate"))) approx.Add((string)x!);
        return new Omega(verbs, approx);
    }

    // ---- digests ----

    /// <summary>Content address of a grant ({predicates, caveats}).</summary>
    public static string GrantDigest(object? g)
    {
        var gm = Obj(g);
        var body = new D { ["predicates"] = gm.GetValueOrDefault("predicates"), ["caveats"] = gm.ContainsKey("caveats") ? gm["caveats"] : new L() };
        var top = new D { ["d"] = "atlas-pca/intent-grant/v1", ["g"] = body };
        return Pca.HashCanonical(IntentJs.Normalize(top));
    }

    /// <summary>Content address of an Intent Map.</summary>
    public static string IntentMapDigest(object? m)
    {
        var top = new D { ["d"] = IntentMapDomain, ["m"] = m };
        return Pca.HashCanonical(IntentJs.Normalize(top));
    }

    static D MetricsOf(IntentLearner l)
    {
        var m = l.Metrics();
        double rmax = 0;
        foreach (var c in l.Cells()) rmax += c.Mass * (1 - c.P) * c.Harm;
        return new D
        {
            ["residual_risk_ppm"] = N(PpmOf(m.ResidualRisk)),
            ["burden_ppm"] = N(PpmOf(m.Burden)),
            ["uncertainty_ppm"] = N(PpmOf(m.Uncertainty)),
            ["disagreement_ppm"] = N(PpmOf(m.DisagreementMass)),
            ["mean_harm_ppm"] = N(PpmOf(m.MeanHarm)),
            ["fidelity_est_ppm"] = N(PpmOf(rmax > 0 ? 1 - m.ResidualRisk / rmax : 1)),
            ["entropy_mbits"] = N(JsRound(m.EntropyBits * 1000)),
            ["log2_vs_mbits"] = m.Log2VersionSpace == null ? null : N(JsRound(m.Log2VersionSpace.Value * 1000)),
            ["questions"] = N(m.Questions),
            ["conflicts"] = N(m.Conflicts),
        };
    }

    // ---- learner construction ----

    static readonly ConditionalWeakTable<IntentLearner, MapLearnerOptions> Params = new();

    static double NullMassOf(MapLearnerOptions o, string verb)
    {
        if (o.NullMassNumber != null) return o.NullMassNumber.Value;
        if (o.NullMassByVerb != null && o.NullMassByVerb.TryGetValue(verb, out var own)) return own;
        return o.DefaultNullMass ?? 0.2;
    }

    static AnchorSpec AnchorOpt(AnchorIn a) => new(a.Policy.ToJson(), JsRound(a.Lambda * 1000) / 1000);

    static HypothesisClassSpec QuantizeClass(HypothesisClassSpec? h)
    {
        if (h == null || h.Kind == "box") return HypothesisClassSpec.Box;
        double decay = Qz(h.Decay ?? 0.25);
        return h.Kind == "union" ? new HypothesisClassSpec("union", h.K, null, decay, null)
            : new HypothesisClassSpec("decision-list", null, h.MaxRules, decay, h.Conditions ?? "box");
    }

    static IntentLearner.PriorMix PriorMixOf(MapLearnerOptions o)
    {
        var byVerb = new Dictionary<string, List<double[]>>();
        foreach (var c in o.PriorMixCells!)
        {
            double q = Qz(c.Q);
            if (!(q >= 0 && q <= 1) || !(c.Cell == Math.Floor(c.Cell) && Math.Abs(c.Cell) <= 9007199254740991.0) || c.Cell < 0)
                throw new ArgumentException("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0");
            if (!byVerb.TryGetValue(c.Verb, out var lst)) byVerb[c.Verb] = lst = new List<double[]>();
            lst.Add(new[] { c.Cell, DetMath.DetLn(q), DetMath.DetLn(1 - q) }); // DetLn / DetExp: the weights are recomputed and compared by verifiers
        }
        return new IntentLearner.PriorMix(Qz(o.PriorMixBeta!.Value), (vs, contains) =>
        {
            double lw = 0;
            if (byVerb.TryGetValue(vs.Verb, out var ts)) foreach (var t in ts) lw += t[0] <= int.MaxValue && contains((int)t[0]) ? t[1] : t[2];
            return DetMath.DetExp(lw);
        });
    }

    /// <summary>Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised).</summary>
    public static IntentLearner CreateLearner(Omega omega, MapLearnerOptions o)
    {
        var opts = new LearnerOptions();
        opts.Eta = Qz(o.Eta ?? 0);
        opts.Tau = Qz(o.Tau ?? ((o.Eta ?? 0) == 0 ? 1 : 0.95));
        opts.Strategy = o.Strategy ?? "disagreement";
        opts.NullMassFn = vs => Qz(NullMassOf(o, vs.Verb));
        opts.HypothesisClass = QuantizeClass(o.HypothesisClass);
        if (o.AgnosticSlack != null)
        {
            double s = o.AgnosticSlack.Value;
            if (!(s == Math.Floor(s) && s >= 0 && s <= int.MaxValue)) throw new ArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
            opts.AgnosticSlack = (int)s;
        }
        if (o.Anchor != null) opts.Anchor = AnchorOpt(o.Anchor);
        if (o.Anchors != null && o.Anchors.Count > 0) opts.Anchors = o.Anchors.Select(AnchorOpt).ToList();
        if (o.MonotonePaths != null) opts.Monotone = new IntentLearner.Monotone(new List<string>(o.MonotonePaths), Qz(o.MonotoneOffMass ?? 0));
        if (o.EtaPos != null) opts.EtaPos = Qz(o.EtaPos.Value);
        if (o.EtaNeg != null) opts.EtaNeg = Qz(o.EtaNeg.Value);
        if (o.PriorMixBeta != null) opts.PriorMix = PriorMixOf(o);
        var l = new IntentLearner(omega, opts);
        Params.Add(l, o);
        return l;
    }

    /// <summary>The serialisable parameters a learner was built with (CreateLearner only).</summary>
    public static MapLearnerOptions LearnerOptionsOf(IntentLearner l) =>
        Params.TryGetValue(l, out var o) ? o : throw new InvalidOperationException("pca-intent: build the learner with createLearner() so its parameters are serialisable");

    static D AnchorJson(AnchorIn a) => new() { ["policy"] = a.Policy.ToJson(), ["lambda_milli"] = N(JsRound(a.Lambda * 1000)) };

    static D ValuesJson(Dictionary<string, object?> v)
    {
        var o = new D();
        foreach (var (k, x) in v) o[k] = x is double d ? N(d) : x;
        return o;
    }

    public static D EmitIntentMap(IntentLearner l, string? intentRef = null)
    {
        var o = LearnerOptionsOf(l);
        var nullMass = new D();
        foreach (var vs in l.Omega.Verbs) nullMass[vs.Verb] = N(PpmOf(NullMassOf(o, vs.Verb)));
        var syn = l.Synthesize();
        var grant = new D { ["predicates"] = syn.Predicates.Select(x => (object?)x).ToList(), ["caveats"] = syn.Caveats.Select(x => (object?)x).ToList() };
        var hc = l.HypothesisClass;
        var learner = new D { ["hypothesis_class"] = IntentLearner.HypothesisClassName(hc) };
        if (hc.Kind == "union")
            learner["class_params"] = new D { ["k"] = N(hc.K!.Value), ["decay_ppm"] = N(PpmOf(hc.Decay ?? 0.25)) };
        if (hc.Kind == "decision-list")
            learner["class_params"] = new D { ["max_rules"] = N(hc.MaxRules!.Value), ["decay_ppm"] = N(PpmOf(hc.Decay ?? 0.25)) };
        if (l.AgnosticSlack != null) learner["agnostic_slack"] = N(l.AgnosticSlack.Value);
        learner["eta_ppm"] = N(PpmOf(l.Eta));
        learner["tau_ppm"] = N(PpmOf(l.Tau));
        learner["strategy"] = l.Strategy;
        learner["null_mass_ppm"] = nullMass;
        if (o.Anchor != null) learner["anchor"] = AnchorJson(o.Anchor);
        if (o.Anchors != null && o.Anchors.Count > 0) learner["anchors"] = o.Anchors.Select(a => (object?)AnchorJson(a)).ToList();
        if (o.MonotonePaths != null)
            learner["monotone"] = new D { ["paths"] = o.MonotonePaths.Select(x => (object?)x).ToList(), ["off_ppm"] = N(PpmOf(o.MonotoneOffMass ?? 0)) };
        if (o.EtaPos != null || o.EtaNeg != null)
            learner["noise"] = new D { ["eta_pos_ppm"] = N(PpmOf(l.EtaPos)), ["eta_neg_ppm"] = N(PpmOf(l.EtaNeg)) };
        if (o.PriorMixBeta != null)
            learner["prior_mix"] = new D
            {
                ["beta_ppm"] = N(PpmOf(o.PriorMixBeta.Value)),
                ["cells"] = o.PriorMixCells!.Select(c => (object?)new D { ["verb"] = c.Verb, ["cell"] = N(c.Cell), ["q_ppm"] = N(PpmOf(c.Q)) }).ToList(),
            };
        var obs = new L();
        foreach (var x in l.Observations)
        {
            var m = new D { ["verb"] = x.Verb, ["values"] = ValuesJson(x.Values), ["y"] = N(x.Y), ["source"] = x.Source };
            if (x.Region != null) m["region"] = x.Region.ToJson();
            obs.Add(m);
        }
        var cells = new L();
        foreach (var c in l.Cells())
            cells.Add(new D { ["verb"] = c.Verb, ["cell"] = c.Cell.Select(i => (object?)N(i)).ToList(), ["p_ppm"] = N(PpmOf(c.P)), ["in_grant"] = c.InGrant });
        var map = new D { ["v"] = N(1), ["kind"] = "pca-intent-map", ["intent_ref"] = intentRef };
        var principals = new L();
        if (!string.IsNullOrEmpty(intentRef)) principals.Add(intentRef);
        map["principals"] = principals;
        map["omega"] = OmegaToJson(l.Omega);
        map["learner"] = learner;
        map["observations"] = obs;
        map["cells"] = cells;
        map["grant"] = grant;
        map["grant_digest"] = GrantDigest(grant);
        map["metrics"] = MetricsOf(l);
        return map;
    }

    /// <summary>The learner parameters a map records (inverse of what EmitIntentMap writes).</summary>
    public static MapLearnerOptions MapLearnerOptionsOf(object? mapO)
    {
        var m = Obj(mapO);
        var ln = Obj(m.GetValueOrDefault("learner"));
        var r = new MapLearnerOptions { NullMassByVerb = new Dictionary<string, double>() };
        foreach (var e in Obj(ln.GetValueOrDefault("null_mass_ppm"))) r.NullMassByVerb[e.Key] = Dbl(e.Value) / Ppm;
        var cp = ln.GetValueOrDefault("class_params") == null ? null : Obj(ln["class_params"]);
        var hcn = ln.GetValueOrDefault("hypothesis_class") as string;
        double decay = (cp != null && cp.GetValueOrDefault("decay_ppm") != null ? Dbl(cp["decay_ppm"]) : 250_000) / Ppm;
        if (hcn == "per-verb-union/v1")
            r.HypothesisClass = new HypothesisClassSpec("union", cp != null && cp.GetValueOrDefault("k") != null ? Dbl(cp["k"]) : 2.0, null, decay, null);
        else if (hcn == "per-verb-decision-list/v1" || hcn == "per-verb-decision-list/v2")
            r.HypothesisClass = new HypothesisClassSpec("decision-list", null, cp != null && cp.GetValueOrDefault("max_rules") != null ? Dbl(cp["max_rules"]) : 2.0, decay,
                hcn == "per-verb-decision-list/v1" ? "atomic" : "box");
        else r.HypothesisClass = HypothesisClassSpec.Box;
        r.Eta = Dbl(ln.GetValueOrDefault("eta_ppm")) / Ppm;
        r.Tau = Dbl(ln.GetValueOrDefault("tau_ppm")) / Ppm;
        r.Strategy = ln.GetValueOrDefault("strategy") as string;
        if (ln.GetValueOrDefault("agnostic_slack") != null) r.AgnosticSlack = Dbl(ln["agnostic_slack"]);
        if (ln.GetValueOrDefault("anchor") != null) r.Anchor = AnchorBack(ln["anchor"]);
        if (ln.GetValueOrDefault("anchors") != null && Arr(ln["anchors"]).Count > 0) r.Anchors = Arr(ln["anchors"]).Select(AnchorBack).ToList();
        if (ln.GetValueOrDefault("monotone") != null)
        {
            var mo = Obj(ln["monotone"]);
            r.MonotonePaths = new List<string>();
            foreach (var x in Arr(mo.GetValueOrDefault("paths"))) r.MonotonePaths.Add((string)x!);
            r.MonotoneOffMass = Dbl(mo.GetValueOrDefault("off_ppm")) / Ppm;
        }
        if (ln.GetValueOrDefault("noise") != null)
        {
            var nz = Obj(ln["noise"]);
            r.EtaPos = Dbl(nz.GetValueOrDefault("eta_pos_ppm")) / Ppm;
            r.EtaNeg = Dbl(nz.GetValueOrDefault("eta_neg_ppm")) / Ppm;
        }
        if (ln.GetValueOrDefault("prior_mix") != null)
        {
            var pm = Obj(ln["prior_mix"]);
            r.PriorMixBeta = Dbl(pm.GetValueOrDefault("beta_ppm")) / Ppm;
            r.PriorMixCells = new List<PriorMixCell>();
            foreach (var c in Arr(pm.GetValueOrDefault("cells")))
            {
                var cm = Obj(c);
                r.PriorMixCells.Add(new PriorMixCell((string)cm["verb"]!, Dbl(cm.GetValueOrDefault("cell")), Dbl(cm.GetValueOrDefault("q_ppm")) / Ppm));
            }
        }
        return r;
    }

    static AnchorIn AnchorBack(object? o)
    {
        var a = Obj(o);
        var p = Obj(a.GetValueOrDefault("policy"));
        return new AnchorIn(new PolicyData(p.GetValueOrDefault("predicates"), p.GetValueOrDefault("caveats")), Dbl(a.GetValueOrDefault("lambda_milli")) / 1000);
    }

    /// <summary>Rebuild the learner a map describes (outcome space + prior + observations).</summary>
    public static IntentLearner LearnerFromMap(object? mapO)
    {
        var m = Obj(mapO);
        var l = CreateLearner(OmegaFromJson(m.GetValueOrDefault("omega")), MapLearnerOptionsOf(mapO));
        foreach (var oo in Arr(m.GetValueOrDefault("observations")))
        {
            var o = Obj(oo);
            var vals = new Dictionary<string, object?>();
            foreach (var e in Obj(o.GetValueOrDefault("values"))) vals[e.Key] = IsNum(e.Value) ? Dbl(e.Value) : e.Value;
            l.Observe(new Outcome((string)o["verb"]!, vals), (int)Dbl(o.GetValueOrDefault("y")), (string)o["source"]!,
                o.GetValueOrDefault("region") == null ? null : IntentRegion.Region.FromJson(o["region"]));
        }
        return l;
    }

    static string JsStr(object? v)
    {
        if (v == null) return "null";
        if (IsNum(v)) return ((Num)N(Dbl(v))!).Raw;
        return v is bool b ? (b ? "true" : "false") : v.ToString() ?? "null";
    }

    static D Result(bool ok, IEnumerable<string> problems) => new() { ["ok"] = ok, ["problems"] = problems.Select(p => (object?)p).ToList() };

    /// <summary>Replay a single-principal map and check every number, every cell and the grant.</summary>
    public static D VerifyIntentMap(object? mapO)
    {
        var problems = new List<string>();
        try
        {
            if (mapO is not D m) return Result(false, new[] { "not an intent map v1" });
            if (!(IsNum(m.GetValueOrDefault("v")) && Dbl(m["v"]) == 1) || (m.GetValueOrDefault("kind") as string) != "pca-intent-map") return Result(false, new[] { "not an intent map v1" });
            if (Arr(m.GetValueOrDefault("principals")).Count > 1 || m.GetValueOrDefault("aggregation") != null)
                return Result(false, new[] { "combined map: verify each principal map and recombine with verifyAggregate" });
            var ir = m.GetValueOrDefault("intent_ref");
            var r = EmitIntentMap(LearnerFromMap(m), ir == null ? null : (string)ir);
            string? gds = m.GetValueOrDefault("grant_digest") as string;
            if (gds == null || gds != (string)r["grant_digest"]! || GrantDigest(m.GetValueOrDefault("grant")) != gds) problems.Add("grant does not match the replayed posterior");
            var rc = Arr(r["cells"]);
            var mc = Arr(m.GetValueOrDefault("cells"));
            if (rc.Count != mc.Count) problems.Add("cell count differs");
            else
            {
                for (int i = 0; i < rc.Count; i++)
                {
                    var c = Obj(rc[i]);
                    var x = Obj(mc[i]);
                    if (!Equals(c["verb"], x.GetValueOrDefault("verb")) || !Equals(c["in_grant"], x.GetValueOrDefault("in_grant")) || !IsNum(x.GetValueOrDefault("p_ppm")) || !(Math.Abs(Dbl(c["p_ppm"]) - Dbl(x.GetValueOrDefault("p_ppm"))) <= 2)) // a missing or non-numeric claim is a mismatch (NaN compares false)
                        problems.Add("cell " + i + " differs");
                }
            }
            var rm = Obj(r["metrics"]);
            var mm = Obj(m.GetValueOrDefault("metrics"));
            foreach (var k in rm.Keys)
            {
                var a = rm[k];
                mm.TryGetValue(k, out var b);
                bool has = mm.ContainsKey(k);
                bool differs;
                if (a == null || (has && b == null)) differs = !(a == null && has && b == null);
                else differs = !has || !IsNum(b) || !(Math.Abs(Dbl(a) - Dbl(b)) <= 2); // a missing or non-numeric claim is a mismatch
                if (differs) problems.Add("metric " + k + " differs (" + (has ? JsStr(b) : "undefined") + " claimed, " + JsStr(a) + " replayed)");
            }
        }
        catch (Exception)
        {
            problems.Add("replay failed");
        }
        return Result(problems.Count == 0, problems);
    }

    /// <summary>A runtime divergence is one more labelled observation; a negative one also vetoes the cell. Returns {before, after, grant}.</summary>
    public static D ApplyDivergence(IntentLearner l, Outcome outcome, int y)
    {
        long before = l.Cells().Count(c => c.InGrant);
        l.Observe(outcome, y, "runtime", null);
        long after = l.Cells().Count(c => c.InGrant);
        var s = l.Synthesize();
        var grant = new D { ["predicates"] = s.Predicates.Select(x => (object?)x).ToList(), ["caveats"] = s.Caveats.Select(x => (object?)x).ToList() };
        return new D { ["before"] = N(before), ["after"] = N(after), ["grant"] = grant };
    }

    // ---- committed (Merkle) form ----

    static long NumCellCount(double lo, double hi, L cuts)
    {
        long n = 0;
        double cur = lo;
        foreach (var co in cuts)
        {
            double c = Dbl(co);
            if (c < lo || c > hi) continue;
            if (cur <= c - 1) n++;
            n++;
            cur = c + 1;
        }
        return cur <= hi ? n + 1 : n;
    }

    const long MaxCells = 1L << 20;

    /// <summary>The committed form of an Intent Map; <paramref name="secret"/> (32 bytes) derives every leaf salt.</summary>
    public static IntentMapCommitKit.CommittedMap CommitIntentMap(object? mapO, byte[] secret)
    {
        var m = Obj(mapO);
        var verbs = Arr(Obj(m.GetValueOrDefault("omega")).GetValueOrDefault("verbs"));
        var headers = new List<D>();
        foreach (var vo in verbs)
        {
            var v = Obj(vo);
            var dims = new L();
            foreach (var d in Arr(v.GetValueOrDefault("dims")))
            {
                var dm = Obj(d);
                var o = new D();
                if ((dm.GetValueOrDefault("kind") as string) == "num")
                {
                    double lo = Dbl(dm.GetValueOrDefault("lo")), hi = Dbl(dm.GetValueOrDefault("hi"));
                    var cuts = new L();
                    if (dm.GetValueOrDefault("cuts") != null) foreach (var c in Arr(dm["cuts"])) if (Dbl(c) >= lo && Dbl(c) <= hi) cuts.Add(c);
                    o["kind"] = "num"; o["path"] = dm.GetValueOrDefault("path"); o["lo"] = dm.GetValueOrDefault("lo"); o["hi"] = dm.GetValueOrDefault("hi"); o["cuts"] = cuts;
                }
                else
                {
                    var vals = new L();
                    if (dm.GetValueOrDefault("values") != null)
                        foreach (var x in Arr(dm["values"])) { var xm = Obj(x); vals.Add(new D { ["kind"] = xm.GetValueOrDefault("kind"), ["value"] = xm.GetValueOrDefault("value") }); }
                    o["kind"] = "cat"; o["path"] = dm.GetValueOrDefault("path"); o["values"] = vals;
                }
                dims.Add(o);
            }
            headers.Add(new D { ["verb"] = v.GetValueOrDefault("verb"), ["dims"] = dims });
        }
        var cells = new Dictionary<string, List<D>>();
        foreach (var vo in verbs)
        {
            var v = Obj(vo);
            var dims = Arr(v.GetValueOrDefault("dims"));
            var counts = new long[dims.Count];
            long total = 1;
            for (int j = 0; j < counts.Length; j++)
            {
                var dm = Obj(dims[j]);
                counts[j] = (dm.GetValueOrDefault("kind") as string) == "num"
                    ? NumCellCount(Dbl(dm.GetValueOrDefault("lo")), Dbl(dm.GetValueOrDefault("hi")), dm.GetValueOrDefault("cuts") == null ? new L() : Arr(dm["cuts"]))
                    : dm.GetValueOrDefault("values") == null ? 0 : Arr(dm["values"]).Count;
                total *= counts[j];
            }
            if (total > MaxCells) throw new ArgumentException("commitIntentMap: too many cells for " + v.GetValueOrDefault("verb"));
            var slots = new D?[total];
            foreach (var co in Arr(m.GetValueOrDefault("cells")))
            {
                var c = Obj(co);
                if (!Equals(v.GetValueOrDefault("verb"), c.GetValueOrDefault("verb"))) continue;
                var cell = Arr(c.GetValueOrDefault("cell"));
                if (cell.Count != counts.Length) throw new ArgumentException("commitIntentMap: cell of " + v.GetValueOrDefault("verb") + " has the wrong arity");
                long flat = 0;
                for (int j = 0; j < cell.Count; j++)
                {
                    var io = cell[j];
                    double i = IsNum(io) ? Dbl(io) : double.NaN;
                    if (!(i == Math.Floor(i) && Math.Abs(i) <= 9007199254740991.0 && i >= 0 && i < counts[j])) throw new ArgumentException("commitIntentMap: cell index out of range for " + v.GetValueOrDefault("verb"));
                    flat = flat * counts[j] + (long)i;
                }
                slots[flat] = new D { ["cell"] = new L(cell), ["p_ppm"] = c.GetValueOrDefault("p_ppm"), ["in_grant"] = c.GetValueOrDefault("in_grant") };
            }
            foreach (var s in slots) if (s == null) throw new ArgumentException("commitIntentMap: the map does not list every cell of " + v.GetValueOrDefault("verb"));
            cells[(string)v["verb"]!] = slots.Select(s => s!).ToList();
        }
        var metrics = new D();
        var mm = Obj(m.GetValueOrDefault("metrics"));
        foreach (var e in mm) if (e.Key != "log2_vs_mbits") metrics[e.Key] = e.Value;
        if (mm.GetValueOrDefault("log2_vs_mbits") != null) metrics["log2_vs_mbits"] = mm["log2_vs_mbits"];
        return IntentMapCommitKit.CommitMap(headers, cells, metrics, Pca.HashCanonical(IntentJs.Normalize(m.GetValueOrDefault("learner"))), secret);
    }
}

/// <summary>The builder side of the committed Intent Map (Merkle form, per-leaf salts derived from one session secret): the leaf layout,
/// salts, tree and Z0 disclosure that the core IntentMap verifies. Inputs and outputs are plain JSON trees.</summary>
public static class IntentMapCommitKit
{
    /// <summary>Informative per-leaf salt derivation tag (wallet side).</summary>
    public const string MapTagSalt = "atlas-pca/intent-map/salt/v1\0";

    public sealed class Leaf
    {
        public string Kind { get; }
        public object? Value { get; }
        public byte[] Salt { get; }
        internal Leaf(string kind, object? value, byte[] salt) { Kind = kind; Value = value; Salt = salt; }
    }

    public sealed class CommittedMap
    {
        public string MapCommit { get; }
        public int Size { get; }
        public List<Leaf> Leaves { get; }
        readonly List<byte[]> _hashes;
        readonly List<D> _full;

        internal CommittedMap(string mapCommit, int size, List<Leaf> leaves, List<byte[]> hashes, List<D> full)
        {
            MapCommit = mapCommit; Size = size; Leaves = leaves; _hashes = hashes; _full = full;
        }

        /// <summary>The leaves as JSON: [{kind, leaf, salt}].</summary>
        public L LeavesJson() => Leaves.Select(l => (object?)new D { ["kind"] = l.Kind, ["leaf"] = l.Value, ["salt"] = Pca.B64u(l.Salt) }).ToList();

        D Entry(int i)
        {
            var path = new List<byte[]>();
            AuditPath(_hashes, i, path);
            return new D
            {
                ["index"] = IntentOmega.N(i),
                ["salt"] = Pca.B64u(Leaves[i].Salt),
                ["leaf"] = Leaves[i].Value,
                ["path"] = path.Select(p => (object?)Pca.B64u(p)).ToList(),
            };
        }

        /// <summary>Z0 disclosure for an action; throws when the action lies outside the map.</summary>
        public D Disclose(string verb, object? resource, object? parameters)
        {
            int hi = _full.FindIndex(h => (string)h["verb"]! == verb);
            if (hi < 0) throw new ArgumentException("commitMap.disclose: verb " + verb + " is not in the map");
            var w = IntentMap.CellOf(_full[hi], resource, parameters);
            if (w == null) throw new ArgumentException("commitMap.disclose: the action lies outside the committed map's dimension");
            return new D
            {
                ["size"] = IntentOmega.N(Size),
                ["header"] = Entry(hi),
                ["cell"] = Entry((int)(IntentJs.Lng(_full[hi]["first"]) + w.Value.Flat)),
                ["metrics"] = Entry(Size - 2),
            };
        }
    }

    static long Split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }

    static byte[] NodeHash(byte[] l, byte[] r) => Pca.Sha256Of(IntentJs.Utf8(IntentMap.MapTagNode), l, r);

    static byte[] TreeRoot(List<byte[]> hs)
    {
        if (hs.Count == 1) return hs[0];
        int k = (int)Split(hs.Count);
        return NodeHash(TreeRoot(hs.GetRange(0, k)), TreeRoot(hs.GetRange(k, hs.Count - k)));
    }

    static void AuditPath(List<byte[]> hs, int idx, List<byte[]> o)
    {
        if (hs.Count == 1) return;
        int k = (int)Split(hs.Count);
        if (idx < k)
        {
            AuditPath(hs.GetRange(0, k), idx, o);
            o.Add(TreeRoot(hs.GetRange(k, hs.Count - k)));
        }
        else
        {
            AuditPath(hs.GetRange(k, hs.Count - k), idx - k, o);
            o.Add(TreeRoot(hs.GetRange(0, k)));
        }
    }

    /// <summary>Per-leaf salt: SHA-256(TAG_SALT || secret || u64be(index)).</summary>
    public static byte[] MapLeafSalt(byte[] secret, long index) => Pca.Sha256Of(IntentJs.Utf8(MapTagSalt), secret, IntentMap.U64be(index));

    static long DimCells(D d) => (d["kind"] as string) == "num" ? IntentMap.NumCells(d).Count : ((L)d["values"]!).Count;

    /// <summary>Build the committed form. headers: [{verb, dims}], cells: verb -> [{cell, p_ppm, in_grant}] in flat order, metrics: the metrics leaf,
    /// learnerDigest: the learner settings' content address. Throws on a malformed input.</summary>
    public static CommittedMap CommitMap(List<D> headers, Dictionary<string, List<D>> cells, D metrics, string learnerDigest, byte[] secret)
    {
        if (secret == null || secret.Length != 32) throw new ArgumentException("commitMap: the secret is 32 bytes");
        var heads = new List<D>(headers);
        // stable sort by verb in UTF-8 byte order
        heads = heads.OrderBy(h => (string)h["verb"]!, Comparer<string>.Create(IntentJs.CompareUtf8)).ToList();
        for (int i = 1; i < heads.Count; i++) if ((string)heads[i]["verb"]! == (string)heads[i - 1]["verb"]!) throw new ArgumentException("commitMap: duplicate verb");
        var counts = new long[heads.Count];
        for (int i = 0; i < counts.Length; i++)
        {
            long n = 1;
            foreach (var d in (L)heads[i]["dims"]!) n *= DimCells((D)d!);
            counts[i] = n;
        }
        long next = heads.Count;
        var full = new List<D>();
        for (int i = 0; i < heads.Count; i++)
        {
            full.Add(new D { ["verb"] = heads[i]["verb"], ["first"] = IntentOmega.N(next), ["cells"] = IntentOmega.N(counts[i]), ["dims"] = heads[i]["dims"] });
            next += counts[i];
        }
        var kinds = new List<string>();
        var leaves = new List<object?>();
        foreach (var h in full) { kinds.Add("header"); leaves.Add(h); }
        for (int hi = 0; hi < full.Count; hi++)
        {
            var h = full[hi];
            if (!cells.TryGetValue((string)h["verb"]!, out var cs) || cs.Count != counts[hi])
                throw new ArgumentException("commitMap: verb " + h["verb"] + " needs " + counts[hi] + " cell leaves");
            foreach (var c in cs)
            {
                leaves.Add(new D { ["verb"] = h["verb"], ["cell"] = c["cell"], ["p_ppm"] = c["p_ppm"], ["in_grant"] = c["in_grant"] });
                kinds.Add("cell");
            }
        }
        kinds.Add("metrics");
        leaves.Add(metrics);
        kinds.Add("learner");
        leaves.Add(new D { ["learner_digest"] = learnerDigest });
        for (int i = 0; i < leaves.Count; i++)
        {
            var leaf = leaves[i];
            var k = kinds[i];
            var e = k == "header" ? IntentMap.HeaderError(leaf) : k == "cell" ? IntentMap.CellError(leaf) : k == "metrics" ? IntentMap.MetricsError(leaf) : IntentMap.LearnerError(leaf);
            if (e != null) throw new ArgumentException("commitMap: " + e);
        }
        if (leaves.Count < 4 || leaves.Count > IntentMap.MaxMapLeaves) throw new ArgumentException("commitMap: the map has too few or too many leaves");
        var o = new List<Leaf>();
        var hashes = new List<byte[]>();
        for (int i = 0; i < leaves.Count; i++)
        {
            var salt = MapLeafSalt(secret, i);
            var norm = IntentJs.Normalize(leaves[i]);
            o.Add(new Leaf(kinds[i], norm, salt));
            hashes.Add(IntentMap.LeafHash(kinds[i], salt, norm));
        }
        var normFull = ((L)IntentJs.Normalize(full.Select(x => (object?)x).ToList())!).Select(x => (D)x!).ToList();
        return new CommittedMap(Pca.B64u(Pca.Sha256Of(IntentJs.Utf8(IntentMap.MapTagCommit), IntentMap.U64be(hashes.Count), TreeRoot(hashes))), hashes.Count, o, hashes, normFull);
    }
}
