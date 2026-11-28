// Cut refinement and partial answers: a "partly" answer refines the outcome space (inserts cuts, names values or adds a dimension),
// replays every earlier observation as a value-space region over the refined space, and records one observation per new sub-cell of
// the questioned cell.
using static AtlasPca.IntentPkg.IntentOmega;
using Observation = AtlasPca.IntentPkg.IntentLearner.Observation;
using Question = AtlasPca.IntentPkg.IntentLearner.Question;
using Region = AtlasPca.IntentPkg.IntentRegion.Region;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentRefine
{
    /// <summary>One refinement of a verb's space: numeric cuts, categorical values / prefixes, or a whole new dimension.</summary>
    public sealed class Refinement
    {
        public string Verb, Path;
        public double[]? Cuts;
        public List<string>? Values, Prefixes;
        public Dim? NewDim;

        public Refinement(string verb, string path) { Verb = verb; Path = path; }

        public static Refinement FromJson(object? o)
        {
            var m = Obj(o);
            var r = new Refinement((string)m["verb"]!, (string)m["path"]!);
            if (m.GetValueOrDefault("cuts") != null) r.Cuts = Doubles(m["cuts"]);
            if (m.GetValueOrDefault("values") != null) r.Values = Strings(m["values"]);
            if (m.GetValueOrDefault("prefixes") != null) r.Prefixes = Strings(m["prefixes"]);
            if (m.GetValueOrDefault("newDim") != null) r.NewDim = DimFromJson(m["newDim"]);
            return r;
        }
    }

    static double[] Doubles(object? o) => Arr(o).Select(Dbl).ToArray();
    static List<string> Strings(object? o) => Arr(o).Select(x => (string)x!).ToList();

    static List<CatValue> SortedCat(List<CatValue> values)
    {
        var ex = new SortedSet<string>(StringComparer.Ordinal);
        var pre = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var v in values)
        {
            if (v.Kind == "exact") ex.Add(v.Value);
            if (v.Kind == "prefix") pre.Add(v.Value);
        }
        var o = new List<CatValue>();
        foreach (var s in ex) o.Add(new CatValue("exact", s));
        foreach (var s in pre) o.Add(new CatValue("prefix", s));
        o.Add(new CatValue("other", Other));
        return o;
    }

    static double[] CutsOf(IEnumerable<double> xs, double lo, double hi)
    {
        var set = new SortedSet<double>();
        foreach (var c in xs) if (c >= lo && c <= hi) set.Add(c == 0 ? 0.0 : c);
        return set.ToArray();
    }

    static Dim CopyDim(Dim d) => d is NumDim n ? new NumDim(n.Path, n.Lo, n.Hi, (double[])n.Cuts.Clone(), n.Dist) : new CatDim(d.Path, new List<CatValue>(((CatDim)d).Values));

    /// <summary>The outcome space with one verb's dimension refined (the input is untouched).</summary>
    public static Omega RefineOmega(Omega omega, Refinement r)
    {
        var src = omega.Verbs.Find(v => v.Verb == r.Verb) ?? throw new ArgumentException("refineOmega: no verb " + r.Verb + " in Ω");
        var dims = new List<Dim>();
        int i = -1;
        for (int k = 0; k < src.Dims.Count; k++)
        {
            dims.Add(CopyDim(src.Dims[k]));
            if (i < 0 && src.Dims[k].Path == r.Path) i = k;
        }
        if (r.NewDim != null)
        {
            if (i >= 0) throw new ArgumentException("refineOmega: " + r.Path + " is already a dimension of " + r.Verb);
            if (r.NewDim.Path != r.Path) throw new ArgumentException("refineOmega: newDim.path must equal path");
            var d = CopyDim(r.NewDim);
            if (d is CatDim c) d = new CatDim(c.Path, SortedCat(c.Values));
            else
            {
                var n = (NumDim)d;
                d = new NumDim(n.Path, n.Lo, n.Hi, CutsOf(n.Cuts, n.Lo, n.Hi), n.Dist);
            }
            dims.Add(d);
            dims = dims.OrderBy(x => x.Path, StringComparer.Ordinal).ToList();
        }
        else
        {
            if (i < 0) throw new ArgumentException("refineOmega: " + r.Verb + " has no dimension " + r.Path + " (pass newDim to add it)");
            var d = dims[i];
            if (d is NumDim n)
            {
                if ((r.Values != null && r.Values.Count > 0) || (r.Prefixes != null && r.Prefixes.Count > 0)) throw new ArgumentException("refineOmega: " + r.Path + " is numeric");
                var all = new List<double>(n.Cuts);
                if (r.Cuts != null) foreach (var c in r.Cuts) if (c == Math.Floor(c) && !double.IsInfinity(c)) all.Add(c);
                dims[i] = new NumDim(n.Path, n.Lo, n.Hi, CutsOf(all, n.Lo, n.Hi), n.Dist);
            }
            else
            {
                var c = (CatDim)d;
                if (r.Cuts != null && r.Cuts.Length > 0) throw new ArgumentException("refineOmega: " + r.Path + " is categorical");
                var all = new List<CatValue>(c.Values);
                if (r.Values != null) foreach (var s in r.Values) all.Add(new CatValue("exact", s));
                if (r.Prefixes != null) foreach (var s in r.Prefixes) all.Add(new CatValue("prefix", s));
                var sorted = SortedCat(all);
                if (sorted.Count > 20) throw new ArgumentException("refineOmega: " + r.Path + " would have more than 20 values");
                dims[i] = new CatDim(c.Path, sorted);
            }
        }
        var verbs = new List<VerbSpace>();
        foreach (var v in omega.Verbs)
            verbs.Add(ReferenceEquals(v, src) ? new VerbSpace(v.Verb, v.Reversibility, v.Weight, dims) : new VerbSpace(v.Verb, v.Reversibility, v.Weight, new List<Dim>(v.Dims)));
        return new Omega(verbs, new List<string>(omega.Approximate));
    }

    /// <summary>The value-space region an observation was about, in the space it was recorded in.</summary>
    public static Region RegionOfObservation(Omega omega, Observation o)
    {
        if (o.Region != null) return o.Region;
        foreach (var v in omega.Verbs) if (v.Verb == o.Verb) return IntentRegion.RegionOfCell(v, o.Cell);
        throw new ArgumentException("regionOfObservation: no verb " + o.Verb);
    }

    public static IntentLearner RefineLearner(IntentLearner l, Refinement r, Func<Observation, Region, Region>? rescope = null)
    {
        var omega = RefineOmega(l.Omega, r);
        var next = IntentMapKit.CreateLearner(omega, IntentMapKit.LearnerOptionsOf(l));
        foreach (var o in l.Observations)
        {
            var region = RegionOfObservation(l.Omega, o);
            if (rescope != null) region = rescope(o, region);
            var vs = omega.Verbs.Find(v => v.Verb == o.Verb)!;
            var values = new Dictionary<string, object?>(o.Values);
            foreach (var d in vs.Dims) if (!values.ContainsKey(d.Path)) values[d.Path] = RepValue(d, 0);
            next.Observe(new Outcome(o.Verb, values), o.Y, o.Source, region);
        }
        return next;
    }

    /// <summary>One labelled part of a partial answer: a numeric range, a set of exact values, or "every other value".</summary>
    public sealed class PartialPart
    {
        public double? Lo { get; }
        public double? Hi { get; }
        public List<string>? Values { get; }
        public int Y { get; }
        public bool IsRange { get; }
        public bool IsValues { get; }

        public PartialPart(double? lo, double? hi, List<string>? values, bool isRange, bool isValues, int y)
        {
            Lo = lo; Hi = hi; Values = values; IsRange = isRange; IsValues = isValues; Y = y;
        }

        public static PartialPart FromJson(object? o)
        {
            var m = Obj(o);
            int y = (int)Dbl(m.GetValueOrDefault("y"));
            if (m.ContainsKey("lo")) return new PartialPart(IntentLearner.NumOrNull(m["lo"]), IntentLearner.NumOrNull(m.GetValueOrDefault("hi")), null, true, false, y);
            if (m.ContainsKey("values")) return new PartialPart(null, null, Strings(m["values"]), false, true, y);
            return new PartialPart(null, null, null, false, false, y);
        }
    }

    /// <summary>"Partly": the refinement the answer implies and the label of every part.</summary>
    public sealed class PartialAnswer
    {
        public string Path = "";
        public double[]? Cuts;
        public List<string>? Values;
        public Dim? NewDim;
        public List<PartialPart> Parts = new();

        public static PartialAnswer FromJson(object? o)
        {
            var m = Obj(o);
            var a = new PartialAnswer { Path = (string)m["path"]! };
            if (m.GetValueOrDefault("cuts") != null) a.Cuts = Doubles(m["cuts"]);
            if (m.GetValueOrDefault("values") != null) a.Values = Strings(m["values"]);
            if (m.GetValueOrDefault("newDim") != null) a.NewDim = DimFromJson(m["newDim"]);
            foreach (var p in Arr(m.GetValueOrDefault("parts"))) a.Parts.Add(PartialPart.FromJson(p));
            return a;
        }
    }

    static int? PartLabel(Dim d, int j, List<PartialPart> parts)
    {
        var x = RepValue(d, j);
        foreach (var p in parts)
        {
            if (p.IsRange)
            {
                if (d is not NumDim n) continue;
                var c = NumCells(n)[j];
                if (p.Lo != null && p.Hi != null && c.Lo >= p.Lo && c.Hi <= p.Hi) return p.Y;
            }
            else if (p.IsValues)
            {
                if (d is CatDim c && c.Values[j].Kind == "exact" && p.Values!.Contains((string)x)) return p.Y;
            }
            else if (d is CatDim c2 && c2.Values[j].Kind != "exact") return p.Y;
        }
        return null;
    }

    static List<int> SubCells(Dim d, Region region)
    {
        int n = CellCount(d);
        region.Dims.TryGetValue(d.Path, out var rd);
        var o = new List<int>();
        for (int j = 0; j < n; j++)
        {
            if (rd == null) o.Add(j);
            else if (d is NumDim nd && rd.Kind == "num")
            {
                var c = NumCells(nd)[j];
                if (c.Lo >= rd.Lo && c.Hi <= rd.Hi) o.Add(j);
            }
            else if (d is CatDim && rd.Kind == "cat")
            {
                int cell = CatCellOf(new CatDim(d.Path, rd.Values), (string)RepValue(d, j));
                if (rd.Cells.Contains(cell)) o.Add(j);
            }
        }
        return o;
    }

    static D RangePart(double lo, double hi) => new() { ["lo"] = N(lo), ["hi"] = N(hi) };
    static D CellsPart(IEnumerable<int> cells) => new() { ["cells"] = cells.Select(c => (object?)N(c)).ToList() };

    static VerbSpace? VerbOf(Omega o, string verb) => o.Verbs.Find(v => v.Verb == verb);

    public sealed class PartialResult
    {
        public IntentLearner Learner { get; }
        public List<Observation> Added { get; }
        internal PartialResult(IntentLearner learner, List<Observation> added) { Learner = learner; Added = added; }
    }

    /// <summary>Apply a partial answer to question q: a NEW learner over the refined space and the observations the answer added.</summary>
    public static PartialResult AnswerPartial(IntentLearner l, Question q, PartialAnswer a)
    {
        var oldVs = VerbOf(l.Omega, q.Verb) ?? throw new ArgumentException("answerPartial: no verb " + q.Verb);
        var qRegion = IntentRegion.RegionOfCell(oldVs, q.Cell);
        var r = new Refinement(q.Verb, a.Path) { Cuts = a.Cuts, Values = a.Values, NewDim = a.NewDim };
        var refined = RefineOmega(l.Omega, r);
        var nvs = VerbOf(refined, q.Verb)!;
        Dim dd = nvs.Dims.First(x => x.Path == a.Path);
        Func<Observation, Region, Region>? rescope = null;
        if (a.NewDim != null)
        {
            var yes = new List<int>();
            for (int j = 0; j < CellCount(dd); j++) if (PartLabel(dd, j, a.Parts) == 1) yes.Add(j);
            rescope = (o, region) =>
            {
                if (o.Verb != q.Verb || o.Y != 1) return region;
                if (dd is CatDim) return IntentRegion.RestrictRegion(region, dd, CellsPart(yes));
                var nd = (NumDim)dd;
                if (yes.Count == 0) return IntentRegion.RestrictRegion(region, dd, RangePart(nd.Hi + 1, nd.Hi + 1));
                var cells = NumCells(nd);
                return IntentRegion.RestrictRegion(region, dd, RangePart(cells[yes[0]].Lo, cells[yes[^1]].Hi));
            };
        }
        var next = RefineLearner(l, r, rescope);
        var added = new List<Observation>();
        foreach (int j in SubCells(dd, qRegion))
        {
            var y = PartLabel(dd, j, a.Parts);
            if (y == null) continue;
            Region region;
            if (dd is NumDim nd)
            {
                var c = NumCells(nd)[j];
                region = IntentRegion.RestrictRegion(qRegion, dd, RangePart(c.Lo, c.Hi));
            }
            else region = IntentRegion.RestrictRegion(qRegion, dd, CellsPart(new[] { j }));
            var values = new Dictionary<string, object?>(q.Outcome.Values) { [dd.Path] = RepValue(dd, j) };
            foreach (var x in nvs.Dims) if (!values.ContainsKey(x.Path)) values[x.Path] = RepValue(x, 0);
            var ob = next.Observe(new Outcome(q.Verb, values), y.Value, "elicitation", region);
            if (ob != null) added.Add(ob);
        }
        return new PartialResult(next, added);
    }

    public sealed class AdaptiveElicitResult
    {
        public string Stop { get; }
        public int Questions { get; }
        public int AuditQuestions { get; }
        public int SeedQuestions { get; }
        public int Refinements { get; }
        public List<Question> Asked { get; }
        public IntentLearner Learner { get; }

        internal AdaptiveElicitResult(string stop, int questions, int auditQuestions, int seedQuestions, List<Question> asked, IntentLearner learner, int refinements)
        {
            Stop = stop; Questions = questions; AuditQuestions = auditQuestions; SeedQuestions = seedQuestions; Asked = asked; Learner = learner; Refinements = refinements;
        }
    }

    /// <summary>Elicitation that accepts yes, no and partly (the answer is 0, 1 as an int, or a <see cref="PartialAnswer"/>); after maxRefinements
    /// (default 8) partial answers further ones count as "no".</summary>
    public static AdaptiveElicitResult ElicitAdaptive(IntentLearner learner, Func<Question, IntentLearner, object> answer, IntentLearner.ElicitOptions o, int? maxRefinements = null)
    {
        var l = learner;
        var asked = new List<Question>();
        int refinements = 0;
        int maxRef = maxRefinements ?? 8;
        void Apply(Question q)
        {
            var a = answer(q, l);
            asked.Add(q);
            if (a is PartialAnswer pa)
            {
                if (refinements < maxRef)
                {
                    l = AnswerPartial(l, q, pa).Learner;
                    refinements++;
                }
                else l.Observe(q.Outcome, 0, "elicitation", null);
            }
            else l.Observe(q.Outcome, Convert.ToInt32(a), "elicitation", null);
        }
        int seedQuestions = 0;
        foreach (var s in o.Seed)
        {
            if (asked.Count >= o.MaxQuestions) break;
            var vs = VerbOf(l.Omega, s.Verb);
            var cell = s.Cell;
            if (vs == null || cell.Length != vs.Dims.Count) continue;
            var values = new Dictionary<string, object?>();
            for (int k = 0; k < vs.Dims.Count; k++) values[vs.Dims[k].Path] = RepValue(vs.Dims[k], cell[k]);
            var outcome = new Outcome(s.Verb, values);
            double p = l.Acceptance(outcome);
            if (p <= 1e-9 || p >= 1 - 1e-9 || l.IsVetoed(outcome)) continue;
            Apply(new Question(s.Verb, (int[])cell.Clone(), outcome, p, 0));
            seedQuestions++;
        }
        string? stop = null;
        while (stop == null)
        {
            var m = l.Metrics();
            if (m.ResidualRisk <= o.EpsRisk && m.Burden <= o.EpsBurden) stop = "converged";
            else if (asked.Count >= o.MaxQuestions) stop = "budget";
            else
            {
                var q = l.NextQuestion();
                if (q == null) stop = "no-disagreement";
                else Apply(q);
            }
        }
        int auditQuestions = 0;
        if (o.Audit)
        {
            for (; ; )
            {
                var pending = l.UnconfirmedGrantCells();
                double mass = 0;
                foreach (var x in pending) mass += x.Weight;
                if (pending.Count == 0 || mass <= o.EpsRisk) break;
                if (asked.Count >= o.MaxQuestions) { stop = "budget"; break; }
                var top = pending[0];
                var vs = VerbOf(l.Omega, top.Verb)!;
                var outcome = CellRep(vs, top.Cell);
                Apply(new Question(top.Verb, top.Cell, outcome, l.Acceptance(outcome), top.Weight));
                auditQuestions++;
            }
        }
        return new AdaptiveElicitResult(stop, asked.Count, auditQuestions, seedQuestions, asked, l, refinements);
    }
}
