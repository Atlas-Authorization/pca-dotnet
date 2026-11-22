// Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision lists), the
// conservative grant G_tau, the residual-risk / burden / uncertainty metrics, the next-question rule and the synthesis of the grant as
// predicates. Floating-point evaluation order follows the reference exactly.
using static AtlasPca.IntentPkg.IntentOmega;
using static AtlasPca.IntentPkg.IntentRegion;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public sealed class IntentLearner
{
    // ---- options ----

    /// <summary>The hypothesis class. Kind is box, union or decision-list; K / MaxRules / Decay / Conditions apply to the richer classes.</summary>
    public sealed class HypothesisClassSpec
    {
        public string Kind { get; }
        public double? K { get; }
        public double? MaxRules { get; }
        public double? Decay { get; }
        public string? Conditions { get; }

        public HypothesisClassSpec(string kind, double? k, double? maxRules, double? decay, string? conditions)
        {
            Kind = kind; K = k; MaxRules = maxRules; Decay = decay; Conditions = conditions;
        }

        public static readonly HypothesisClassSpec Box = new("box", null, null, null, null);

        public static HypothesisClassSpec FromJson(object? o)
        {
            var m = Obj(o);
            return new HypothesisClassSpec((string)m["kind"]!, NumOrNull(m.GetValueOrDefault("k")), NumOrNull(m.GetValueOrDefault("maxRules")),
                NumOrNull(m.GetValueOrDefault("decay")), m.GetValueOrDefault("conditions") as string);
        }
    }

    /// <summary>The canonical name of a hypothesis class (stored in the Intent Map).</summary>
    public static string HypothesisClassName(HypothesisClassSpec h)
    {
        if (h.Kind == "box") return "per-verb-box/v1";
        if (h.Kind == "union") return "per-verb-union/v1";
        return (h.Conditions ?? "box") == "atomic" ? "per-verb-decision-list/v1" : "per-verb-decision-list/v2";
    }

    public sealed class AnchorSpec
    {
        public object? Policy { get; }
        public double Lambda { get; }
        public AnchorSpec(object? policy, double lambda) { Policy = policy; Lambda = lambda; }
    }

    public sealed class PriorMix
    {
        public double Beta { get; }
        /// <summary>weight(verbSpace, contains) of a hypothesis; contains tests a flat cell.</summary>
        public Func<VerbSpace, Func<int, bool>, double> Weight { get; }
        public PriorMix(double beta, Func<VerbSpace, Func<int, bool>, double> weight) { Beta = beta; Weight = weight; }
    }

    public sealed class Monotone
    {
        public List<string> Paths { get; }
        public double? OffMass { get; }
        public Monotone(List<string> paths, double? offMass) { Paths = paths; OffMass = offMass; }
    }

    /// <summary>Learner options; every field is optional (null = the default).</summary>
    public sealed class LearnerOptions
    {
        public double? Eta, EtaPos, EtaNeg, Tau;
        public PriorMix? PriorMix;
        public double? NullMass;
        public Func<VerbSpace, double>? NullMassFn;
        public AnchorSpec? Anchor;
        public List<AnchorSpec>? Anchors;
        public HarmModel? Harm;
        public int? MaxHypotheses, MaxEnumeration;
        public string? Strategy;
        public HypothesisClassSpec? HypothesisClass;
        public int? AgnosticSlack;
        public Monotone? Monotone;

        /// <summary>Reads the plain-data options (functions, the harm model and the prior-mixture weight are set by the caller).</summary>
        public static LearnerOptions FromJson(object? o)
        {
            var p = new LearnerOptions();
            if (o == null) return p;
            var m = Obj(o);
            p.Eta = NumOrNull(m.GetValueOrDefault("eta")); p.EtaPos = NumOrNull(m.GetValueOrDefault("etaPos"));
            p.EtaNeg = NumOrNull(m.GetValueOrDefault("etaNeg")); p.Tau = NumOrNull(m.GetValueOrDefault("tau"));
            p.NullMass = NumOrNull(m.GetValueOrDefault("nullMass"));
            if (m.GetValueOrDefault("anchor") != null) p.Anchor = AnchorOf(m["anchor"]);
            if (m.GetValueOrDefault("anchors") != null)
            {
                p.Anchors = new List<AnchorSpec>();
                foreach (var a in Arr(m["anchors"])) p.Anchors.Add(AnchorOf(a));
            }
            var mh = NumOrNull(m.GetValueOrDefault("maxHypotheses"));
            var me = NumOrNull(m.GetValueOrDefault("maxEnumeration"));
            var sl = NumOrNull(m.GetValueOrDefault("agnosticSlack"));
            if (mh != null) p.MaxHypotheses = JInt(Math.Min(int.MaxValue, mh.Value));
            if (me != null) p.MaxEnumeration = JInt(Math.Min(int.MaxValue, me.Value));
            if (sl != null)
            {
                if (sl != Math.Floor(sl.Value) || sl < 0 || sl > int.MaxValue) throw new ArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
                p.AgnosticSlack = (int)sl.Value;
            }
            p.Strategy = m.GetValueOrDefault("strategy") as string;
            if (m.GetValueOrDefault("hypothesisClass") != null) p.HypothesisClass = HypothesisClassSpec.FromJson(m["hypothesisClass"]);
            if (m.GetValueOrDefault("monotone") != null)
            {
                var mo = Obj(m["monotone"]);
                var paths = new List<string>();
                foreach (var x in Arr(mo["paths"])) paths.Add((string)x!);
                p.Monotone = new Monotone(paths, NumOrNull(mo.GetValueOrDefault("offMass")));
            }
            return p;
        }

        static AnchorSpec AnchorOf(object? o)
        {
            var m = Obj(o);
            return new AnchorSpec(m.GetValueOrDefault("policy"), Dbl(m["lambda"]));
        }
    }

    internal static double? NumOrNull(object? o) => o == null ? null : Dbl(o);

    /// <summary>A Java-style (int) cast of a double: NaN is 0, out-of-range saturates.</summary>
    internal static int JInt(double d) => double.IsNaN(d) ? 0 : d >= int.MaxValue ? int.MaxValue : d <= int.MinValue ? int.MinValue : (int)d;

    /// <summary>One recorded answer.</summary>
    public sealed class Observation
    {
        public string Verb { get; }
        public Dictionary<string, object?> Values { get; }
        public int[] Cell { get; }
        public int Y { get; }
        public string Source { get; }
        public Region? Region { get; }
        public bool Conflict { get; set; }

        public Observation(string verb, Dictionary<string, object?> values, int[] cell, int y, string source, Region? region)
        {
            Verb = verb; Values = values; Cell = cell; Y = y; Source = source; Region = region;
        }

        public D ToJson()
        {
            var o = new D { ["verb"] = Verb };
            var vals = new D();
            foreach (var (k, v) in Values) vals[k] = v is double d ? N(d) : v;
            o["values"] = vals;
            o["cell"] = Cell.Select(x => (object?)N(x)).ToList();
            o["y"] = N(Y);
            o["source"] = Source;
            if (Region != null) o["region"] = Region.ToJson();
            if (Conflict) o["conflict"] = true;
            return o;
        }
    }

    public sealed class Question
    {
        public string Verb { get; }
        public int[] Cell { get; }
        public Outcome Outcome { get; }
        public double P { get; }
        public double Score { get; }
        public Question(string verb, int[] cell, Outcome outcome, double p, double score) { Verb = verb; Cell = cell; Outcome = outcome; P = p; Score = score; }
    }

    public sealed class LearnerMetrics
    {
        public double ResidualRisk, Burden, Uncertainty, EntropyBits, DisagreementMass, MeanHarm;
        public double? Log2VersionSpace;
        public int Questions, Conflicts;
    }

    public sealed class CellView
    {
        public string Verb { get; }
        public int[] Cell { get; }
        public double P { get; }
        public double Mass { get; }
        public double Harm { get; }
        public bool InGrant { get; }
        public bool Vetoed { get; }
        internal CellView(string verb, int[] cell, double p, double mass, double harm, bool inGrant, bool vetoed)
        {
            Verb = verb; Cell = cell; P = p; Mass = mass; Harm = harm; InGrant = inGrant; Vetoed = vetoed;
        }
    }

    public sealed class Unconfirmed
    {
        public string Verb { get; }
        public int[] Cell { get; }
        public double Weight { get; }
        internal Unconfirmed(string verb, int[] cell, double weight) { Verb = verb; Cell = cell; Weight = weight; }
    }

    public sealed class Synthesis
    {
        public List<D> Predicates { get; }
        public List<D> Caveats { get; }
        internal Synthesis(List<D> p, List<D> c) { Predicates = p; Caveats = c; }
    }

    // ---- verb model ----

    sealed class VerbModel
    {
        public VerbSpace Vs = null!;
        public int[] NChoice = null!;
        public byte[][] Contains = null!;
        public int[] NCellsD = null!;
        public int Nh;
        public int[] Choice = null!;
        public byte[]? Member;
        public int[]? Complexity;
        public double[] Prior = null!, W = null!;
        public int[] Err = null!;
        public int NCells;
        public int[] CellIdx = null!;
        public double[] Mass = null!, Harm = null!, P = null!;
        public byte[] Veto = null!, Seen = null!;
        public bool Dirty;
    }

    // the binary entropy feeds the next-question argmax: DetLog2 (not a libm log) so the chosen question is identical on every platform and language; the same argument
    // recurs for every cell of a model, so the value is memoized (bounded: cleared when it grows past 4096 entries)
    [ThreadStatic] static Dictionary<double, double>? _binEntMemo;

    internal static double BinEnt(double p)
    {
        if (p <= 0 || p >= 1) return 0;
        var memo = _binEntMemo ??= new Dictionary<double, double>();
        if (memo.TryGetValue(p, out var hit)) return hit;
        var v = -(p * DetMath.DetLog2(p) + (1 - p) * DetMath.DetLog2(1 - p));
        if (memo.Count >= 4096) memo.Clear();
        memo[p] = v;
        return v;
    }

    static List<int[]> RangeChoices(int n)
    {
        var o = new List<int[]>();
        for (int i = 0; i < n; i++) for (int j = i; j < n; j++) o.Add(new[] { i, j });
        return o;
    }

    sealed class FullOpts
    {
        public readonly int MaxHypotheses, MaxEnumeration;
        public readonly HypothesisClassSpec HypothesisClass;
        public FullOpts(LearnerOptions o)
        {
            MaxHypotheses = o.MaxHypotheses ?? 400_000;
            MaxEnumeration = o.MaxEnumeration ?? 4_000_000;
            HypothesisClass = o.HypothesisClass ?? HypothesisClassSpec.Box;
        }
    }

    static void BuildBoxTables(VerbSpace vs, int[] nCellsD, List<byte[]> contains, int[] nChoice)
    {
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            int n = nCellsD[k];
            if (d.Kind == "num")
            {
                var ch = RangeChoices(n);
                var t = new byte[ch.Count * n];
                for (int c = 0; c < ch.Count; c++) for (int x = ch[c][0]; x <= ch[c][1]; x++) t[c * n + x] = 1;
                contains.Add(t);
                nChoice[k] = ch.Count;
            }
            else
            {
                if (n > 20) throw new InvalidOperationException("pca-intent: categorical dimension " + d.Path + " has " + n + " values (max 20 for exact enumeration)");
                int m = (1 << n) - 1;
                var t = new byte[m * n];
                for (int mask = 1; mask <= m; mask++) for (int x = 0; x < n; x++) if ((mask & (1 << x)) != 0) t[(mask - 1) * n + x] = 1;
                contains.Add(t);
                nChoice[k] = m;
            }
        }
    }

    static string KeyOf(byte[] m)
    {
        var c = new char[m.Length];
        for (int i = 0; i < m.Length; i++) c[i] = (char)(48 + m[i]);
        return new string(c);
    }

    static List<byte[]> BoxMasks(VerbSpace vs, int nCells, int[] cellIdx, int[] nCellsD, byte[][] contains, int[] nChoice, int cap)
    {
        int dn = vs.Dims.Count;
        double boxes = 1;
        foreach (int c in nChoice) boxes *= c;
        if (!(boxes <= cap)) throw new InvalidOperationException("pca-intent: " + JsNum(boxes) + " boxes for " + vs.Verb + " exceed the enumeration cap; coarsen the cuts");
        var o = new List<byte[]>();
        var cur = new int[dn];
        for (long b = 0; b < (long)boxes; b++)
        {
            var mask = new byte[nCells];
            for (int c = 0; c < nCells; c++)
            {
                bool inside = true;
                for (int d = 0; d < dn && inside; d++) if (contains[d][cur[d] * nCellsD[d] + cellIdx[c * dn + d]] == 0) inside = false;
                if (inside) mask[c] = 1;
            }
            o.Add(mask);
            for (int d = dn - 1; d >= 0; d--)
            {
                cur[d]++;
                if (cur[d] < nChoice[d]) break;
                cur[d] = 0;
            }
        }
        return o;
    }

    static string JsNum(double x) => x == Math.Round(x) && Math.Abs(x) < 1e21 ? ((long)x).ToString(System.Globalization.CultureInfo.InvariantCulture) : x.ToString("R", System.Globalization.CultureInfo.InvariantCulture);

    sealed class SetsOut
    {
        public readonly List<byte[]> Sets = new();
        public readonly List<int> Complexity = new();
    }

    static SetsOut EnumerateUnions(List<byte[]> boxes, int k, int cap, string verb)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var o = new SetsOut();
        var frontier = new List<byte[]>();
        foreach (var b in boxes)
        {
            if (!seen.Add(KeyOf(b))) continue;
            o.Sets.Add(b);
            o.Complexity.Add(1);
            frontier.Add(b);
        }
        long work = 0;
        for (int level = 2; level <= k; level++)
        {
            var next = new List<byte[]>();
            foreach (var s in frontier)
            {
                foreach (var b in boxes)
                {
                    work += 1;
                    if (work > cap) throw new InvalidOperationException("pca-intent: the union-of-" + k + "-boxes class for " + verb + " exceeds the enumeration cap; coarsen the cuts or lower k");
                    var u = new byte[s.Length];
                    for (int i = 0; i < s.Length; i++) u[i] = (byte)(s[i] | b[i]);
                    if (!seen.Add(KeyOf(u))) continue;
                    o.Sets.Add(u);
                    o.Complexity.Add(level);
                    next.Add(u);
                }
            }
            frontier = next;
        }
        return o;
    }

    static List<byte[]> AtomicTests(VerbSpace vs, int nCells, int[] cellIdx, int[] nCellsD)
    {
        int dn = vs.Dims.Count;
        var tests = new List<byte[]>();
        for (int k = 0; k < dn; k++)
        {
            var d = vs.Dims[k];
            int n = nCellsD[k];
            if (d.Kind == "num")
            {
                for (int i = 0; i < n - 1; i++) { int ii = i; AddAtomic(tests, nCells, cellIdx, dn, k, x => x <= ii); }
                for (int i = 1; i < n; i++) { int ii = i; AddAtomic(tests, nCells, cellIdx, dn, k, x => x >= ii); }
                if (n > 2) for (int i = 1; i < n - 1; i++) { int ii = i; AddAtomic(tests, nCells, cellIdx, dn, k, x => x == ii); }
            }
            else for (int i = 0; i < n; i++) { int ii = i; AddAtomic(tests, nCells, cellIdx, dn, k, x => x == ii); }
        }
        return DedupMasks(tests);
    }

    static void AddAtomic(List<byte[]> tests, int nCells, int[] cellIdx, int dn, int k, Func<int, bool> pred)
    {
        var m = new byte[nCells];
        bool any = false, all = true;
        for (int c = 0; c < nCells; c++)
        {
            if (pred(cellIdx[c * dn + k])) { m[c] = 1; any = true; } else all = false;
        }
        if (any && !all) tests.Add(m);
    }

    static List<byte[]> DedupMasks(List<byte[]> masks)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var o = new List<byte[]>();
        foreach (var t in masks) if (seen.Add(KeyOf(t))) o.Add(t);
        return o;
    }

    static void EmitList(SetsOut o, HashSet<string> seen, byte[] acc, byte[] decided, int rules, int nCells)
    {
        for (int def = 0; def <= 1; def++)
        {
            var s = new byte[nCells];
            bool any = false;
            for (int c = 0; c < nCells; c++)
            {
                s[c] = decided[c] != 0 ? acc[c] : (byte)def;
                if (s[c] != 0) any = true;
            }
            if (!any) continue;
            if (!seen.Add(KeyOf(s))) continue;
            o.Sets.Add(s);
            o.Complexity.Add(Math.Max(1, rules));
        }
    }

    static SetsOut EnumerateDecisionLists(List<byte[]> tests, int nCells, int maxRules, int cap, string verb)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var o = new SetsOut();
        var frontier = new List<byte[][]> { new[] { new byte[nCells], new byte[nCells] } }; // {decided, acc}
        EmitList(o, seen, frontier[0][1], frontier[0][0], 0, nCells);
        long work = 0;
        for (int depth = 1; depth <= maxRules; depth++)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            var states = new List<byte[][]>();
            foreach (var st in frontier)
            {
                foreach (var t in tests)
                {
                    for (int label = 0; label <= 1; label++)
                    {
                        work += 1;
                        if (work > cap) throw new InvalidOperationException("pca-intent: the decision-list class (≤ " + maxRules + " rules) for " + verb + " exceeds the enumeration cap");
                        var decided = new byte[nCells];
                        var acc = new byte[nCells];
                        bool fresh = false;
                        for (int c = 0; c < nCells; c++)
                        {
                            if (st[0][c] != 0) { decided[c] = 1; acc[c] = st[1][c]; }
                            else if (t[c] != 0) { decided[c] = 1; acc[c] = (byte)label; fresh = true; }
                        }
                        if (!fresh) continue;
                        if (!keys.Add(KeyOf(decided) + "|" + KeyOf(acc))) continue;
                        states.Add(new[] { decided, acc });
                    }
                }
            }
            frontier = states;
            foreach (var st in frontier) EmitList(o, seen, st[1], st[0], depth, nCells);
        }
        return o;
    }

    static bool IsIntD(double? x) => x != null && !double.IsNaN(x.Value) && !double.IsInfinity(x.Value) && x.Value == Math.Floor(x.Value);

    static VerbModel BuildVerbModel(VerbSpace vs, FullOpts opts, HarmModel harm)
    {
        int dn = vs.Dims.Count;
        var nCellsD = new int[dn];
        for (int k = 0; k < dn; k++) nCellsD[k] = CellCount(vs.Dims[k]);
        var nChoice = new int[dn];
        var containsL = new List<byte[]>();
        BuildBoxTables(vs, nCellsD, containsL, nChoice);
        var contains = containsL.ToArray();
        double ncd = VerbCellCount(vs);
        if (ncd > int.MaxValue) throw new InvalidOperationException("pca-intent: too many cells for " + vs.Verb);
        int nCells = (int)ncd;
        var cellIdx = new int[nCells * dn];
        var mass = new double[nCells];
        var hm = new double[nCells];
        for (int c = 0; c < nCells; c++)
        {
            var idx = DecodeCell(vs, c);
            for (int d = 0; d < dn; d++) cellIdx[c * dn + d] = idx[d];
            var s = CellStats(vs, idx, harm);
            mass[c] = s.Mass;
            hm[c] = s.Harm;
        }
        var hc = opts.HypothesisClass;
        int nh;
        var choice = new int[1];
        byte[]? member = null;
        int[]? complexity = null;
        if (hc.Kind == "box")
        {
            double boxes = 1;
            foreach (int c in nChoice) boxes *= c;
            if (!(boxes + 1 <= opts.MaxHypotheses))
                throw new InvalidOperationException("pca-intent: |Θ_" + vs.Verb + "| = " + JsNum(boxes + 1) + " exceeds maxHypotheses " + opts.MaxHypotheses + "; coarsen the cuts");
            nh = (int)boxes + 1;
            choice = new int[Math.Max(1, (int)boxes * dn)];
            var cur = new int[dn];
            for (int h = 0; h < (int)boxes; h++)
            {
                for (int d = 0; d < dn; d++) choice[h * dn + d] = cur[d];
                for (int d = dn - 1; d >= 0; d--)
                {
                    cur[d]++;
                    if (cur[d] < nChoice[d]) break;
                    cur[d] = 0;
                }
            }
        }
        else
        {
            SetsOut so;
            if (hc.Kind == "union")
            {
                if (!(IsIntD(hc.K) && hc.K >= 1)) throw new ArgumentException("pca-intent: union class needs an integer k ≥ 1");
                var boxes = BoxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.MaxEnumeration);
                so = EnumerateUnions(boxes, (int)hc.K!.Value, opts.MaxEnumeration, vs.Verb);
            }
            else
            {
                if (!(IsIntD(hc.MaxRules) && hc.MaxRules >= 1)) throw new ArgumentException("pca-intent: decision-list class needs an integer maxRules ≥ 1");
                string cond = hc.Conditions ?? "box";
                if (cond != "box" && cond != "atomic") throw new ArgumentException("pca-intent: decision-list conditions must be 'box' or 'atomic'");
                var tests = cond == "atomic" ? AtomicTests(vs, nCells, cellIdx, nCellsD) : DedupMasks(BoxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.MaxEnumeration));
                so = EnumerateDecisionLists(tests, nCells, (int)hc.MaxRules!.Value, opts.MaxEnumeration, vs.Verb);
            }
            if (so.Sets.Count + 1 > opts.MaxHypotheses)
                throw new InvalidOperationException("pca-intent: |Θ_" + vs.Verb + "| = " + (so.Sets.Count + 1) + " exceeds maxHypotheses " + opts.MaxHypotheses + "; coarsen the cuts");
            nh = so.Sets.Count + 1;
            if ((long)nh * nCells > int.MaxValue) throw new InvalidOperationException("pca-intent: hypothesis table too large for " + vs.Verb);
            member = new byte[nh * nCells];
            complexity = new int[nh];
            for (int i = 0; i < so.Sets.Count; i++)
            {
                Array.Copy(so.Sets[i], 0, member, (i + 1) * nCells, nCells);
                complexity[i + 1] = so.Complexity[i];
            }
        }
        return new VerbModel
        {
            Vs = vs, NChoice = nChoice, Contains = contains, NCellsD = nCellsD, Nh = nh, Choice = choice, Member = member, Complexity = complexity,
            Prior = new double[nh], W = new double[nh], Err = new int[nh], NCells = nCells, CellIdx = cellIdx, Mass = mass, Harm = hm,
            P = new double[nCells], Veto = new byte[nCells], Seen = new byte[nCells], Dirty = true,
        };
    }

    static bool Holds(VerbModel m, int h, int c)
    {
        if (m.Member != null) return m.Member[h * m.NCells + c] == 1;
        int dn = m.Vs.Dims.Count;
        int bs = (h - 1) * dn;
        for (int d = 0; d < dn; d++)
        {
            int n = m.NCellsD[d];
            if (m.Contains[d][m.Choice[bs + d] * n + m.CellIdx[c * dn + d]] == 0) return false;
        }
        return true;
    }

    public sealed class SetsResult
    {
        public List<byte[]> Sets { get; } = new();
        public List<int> Complexity { get; } = new();
    }

    /// <summary>The non-empty hypotheses of a verb's class as cell masks (index 0 = the empty hypothesis omitted), with their Occam complexity.</summary>
    public static SetsResult HypothesisCellSets(VerbSpace vs, HypothesisClassSpec? hc, int? maxHypotheses, int? maxEnumeration)
    {
        var o = new LearnerOptions { MaxHypotheses = maxHypotheses, MaxEnumeration = maxEnumeration, HypothesisClass = hc ?? HypothesisClassSpec.Box };
        var m = BuildVerbModel(vs, new FullOpts(o), DefaultHarmModel);
        var r = new SetsResult();
        for (int h = 1; h < m.Nh; h++)
        {
            var s = new byte[m.NCells];
            for (int c = 0; c < m.NCells; c++) if (Holds(m, h, c)) s[c] = 1;
            r.Sets.Add(s);
            r.Complexity.Add(m.Complexity != null ? m.Complexity[h] : 1);
        }
        return r;
    }

    static void ApplyMonotonePrior(VerbModel m, Monotone mono)
    {
        double off = mono.OffMass ?? 0;
        if (!(off >= 0 && off <= 1)) throw new ArgumentException("pca-intent: monotone.offMass must be in [0, 1]");
        int dn = m.Vs.Dims.Count;
        var ks = new List<int>();
        for (int k = 0; k < dn; k++) if (m.Vs.Dims[k].Kind == "num" && mono.Paths.Contains(m.Vs.Dims[k].Path)) ks.Add(k);
        if (ks.Count == 0) return;
        var stride = new int[ks.Count];
        for (int i = 0; i < ks.Count; i++)
        {
            int s = 1;
            for (int j = ks[i] + 1; j < dn; j++) s *= m.NCellsD[j];
            stride[i] = s;
        }
        for (int h = 1; h < m.Nh; h++)
        {
            bool isMono = true;
            for (int c = 0; c < m.NCells && isMono; c++)
            {
                if (!Holds(m, h, c)) continue;
                for (int i = 0; i < ks.Count; i++)
                {
                    if (m.CellIdx[c * dn + ks[i]] > 0 && !Holds(m, h, c - stride[i])) { isMono = false; break; }
                }
            }
            if (!isMono) m.W[h] = m.W[h] * off;
        }
    }

    static bool HoldsAll(VerbModel m, int h, int[] cells)
    {
        if (h == 0) return false;
        foreach (int c in cells) if (!Holds(m, h, c)) return false;
        return true;
    }

    // ---- learner ----

    public Omega Omega { get; }
    public double Eta { get; }
    public double EtaPos { get; }
    public double EtaNeg { get; }
    readonly bool _noisy;
    public double Tau { get; }
    public string Strategy { get; }
    public HarmModel Harm { get; }
    public HypothesisClassSpec HypothesisClass { get; }
    public int? AgnosticSlack { get; }
    public List<Observation> Observations { get; } = new();
    readonly List<VerbModel> _models = new();
    readonly LearnerOptions _opts;

    public IntentLearner(Omega omega) : this(omega, new LearnerOptions()) { }

    public IntentLearner(Omega omega, LearnerOptions opts)
    {
        Omega = omega;
        _opts = opts;
        Eta = opts.Eta ?? 0;
        if (!(Eta >= 0 && Eta < 0.5)) throw new ArgumentException("pca-intent: eta must be in [0, 0.5)");
        EtaPos = opts.EtaPos ?? Eta;
        EtaNeg = opts.EtaNeg ?? Eta;
        if (!(EtaPos >= 0 && EtaPos < 0.5 && EtaNeg >= 0 && EtaNeg < 0.5)) throw new ArgumentException("pca-intent: etaPos and etaNeg must be in [0, 0.5)");
        _noisy = EtaPos != 0 || EtaNeg != 0;
        Tau = opts.Tau ?? (_noisy ? 0.95 : 1);
        Strategy = opts.Strategy ?? "disagreement";
        Harm = opts.Harm ?? DefaultHarmModel;
        HypothesisClass = opts.HypothesisClass ?? HypothesisClassSpec.Box;
        AgnosticSlack = opts.AgnosticSlack;
        if (AgnosticSlack != null)
        {
            if (AgnosticSlack < 0) throw new ArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
            if (_noisy) throw new ArgumentException("pca-intent: agnostic selection replaces the noise model; use eta = 0");
        }
        var full = new FullOpts(opts);
        foreach (var vs in omega.Verbs) _models.Add(BuildVerbModel(vs, full, Harm));
        InitPrior();
    }

    void InitPrior()
    {
        var anchors = new List<AnchorSpec>();
        if (_opts.Anchor != null) anchors.Add(_opts.Anchor);
        if (_opts.Anchors != null) anchors.AddRange(_opts.Anchors);
        anchors.RemoveAll(a => !(a.Lambda > 0));
        var admitters = new List<IntentPolicyKit.Admitter>();
        var lambdas = new List<double>();
        foreach (var a in anchors) { admitters.Add(IntentPolicyKit.MakeAdmitter(a.Policy)); lambdas.Add(a.Lambda); }
        double decay = HypothesisClass.Kind == "box" ? 1 : (HypothesisClass.Decay ?? 0.25);
        if (!(decay > 0 && decay <= 1)) throw new ArgumentException("pca-intent: decay must be in (0, 1]");
        foreach (var m in _models)
        {
            double nm = _opts.NullMassFn != null ? _opts.NullMassFn(m.Vs) : (_opts.NullMass ?? 0.2);
            if (!(nm >= 0 && nm <= 1)) throw new ArgumentException("pca-intent: nullMass must be in [0, 1]");
            m.W[0] = nm;
            double z = 0;
            for (int h = 1; h < m.Nh; h++)
            {
                double raw = m.Complexity != null ? DetMath.DetPowInt(decay, (long)(m.Complexity[h] - 1)) : 1;
                m.W[h] = raw;
                z += raw;
            }
            for (int h = 1; h < m.Nh; h++) m.W[h] = ((1 - nm) * m.W[h]) / (z == 0 ? 1 : z);
            if (_opts.Monotone != null) ApplyMonotonePrior(m, _opts.Monotone);
            if (admitters.Count > 0)
            {
                double tot = 0;
                for (int c = 0; c < m.NCells; c++) tot += m.Mass[c];
                var accs = new List<byte[]>();
                foreach (var adm in admitters)
                {
                    var acc = new byte[m.NCells];
                    for (int c = 0; c < m.NCells; c++) acc[c] = (byte)(adm.Admits(m.Vs, CellRep(m.Vs, DecodeCell(m.Vs, c))) ? 1 : 0);
                    accs.Add(acc);
                }
                for (int h = 0; h < m.Nh; h++)
                {
                    double mix = 0;
                    for (int i = 0; i < accs.Count; i++)
                    {
                        var acc = accs[i];
                        double dist = 0;
                        for (int c = 0; c < m.NCells; c++)
                        {
                            int inH = h == 0 ? 0 : Holds(m, h, c) ? 1 : 0;
                            if (inH != acc[c]) dist += m.Mass[c];
                        }
                        mix += DetMath.DetExp((-lambdas[i] * dist) / (tot == 0 ? 1 : tot));
                    }
                    m.W[h] = m.W[h] * (mix / accs.Count);
                }
            }
            Normalize(m.W);
            if (_opts.PriorMix != null) MixPrior(m, _opts.PriorMix);
            Array.Copy(m.W, 0, m.Prior, 0, m.Nh);
            m.Dirty = true;
        }
    }

    bool InGrant(VerbModel m, int c) => m.Veto[c] == 0 && m.P[c] >= Tau - 1e-12;

    VerbModel? Model(string verb)
    {
        foreach (var m in _models) if (m.Vs.Verb == verb) return m;
        return null;
    }

    static void Refresh(VerbModel m)
    {
        if (!m.Dirty) return;
        Array.Clear(m.P, 0, m.P.Length);
        var anyIn = new byte[m.NCells];
        var anyOut = new byte[m.NCells];
        bool live = false;
        for (int h = 0; h < m.Nh; h++)
        {
            double w = m.W[h];
            if (w == 0) continue;
            live = true;
            for (int c = 0; c < m.NCells; c++)
            {
                if (h > 0 && Holds(m, h, c)) { m.P[c] = m.P[c] + w; anyIn[c] = 1; } else anyOut[c] = 1;
            }
        }
        for (int c = 0; c < m.NCells; c++) m.P[c] = !live || anyIn[c] == 0 ? 0 : anyOut[c] == 0 ? 1 : Math.Min(1, Math.Max(0, m.P[c]));
        m.Dirty = false;
    }

    static int Flat(VerbModel m, int[] idx)
    {
        int f = 0;
        for (int d = 0; d < idx.Length; d++) f = f * m.NCellsD[d] + idx[d];
        return f;
    }

    /// <summary>p_n(outcome); 0 outside the space (the conservative reading).</summary>
    public double Acceptance(Outcome o)
    {
        var m = Model(o.Verb);
        if (m == null) return 0;
        var idx = CellOf(m.Vs, o);
        if (idx == null) return 0;
        Refresh(m);
        return m.P[Flat(m, idx)];
    }

    /// <summary>Is the outcome inside the current conservative grant (p_n &gt;= tau and not vetoed)?</summary>
    public bool AdmitsOutcome(Outcome o)
    {
        var m = Model(o.Verb);
        if (m == null) return false;
        var idx = CellOf(m.Vs, o);
        if (idx == null) return false;
        Refresh(m);
        return InGrant(m, Flat(m, idx));
    }

    public bool IsVetoed(Outcome o)
    {
        var m = Model(o.Verb);
        var idx = m != null ? CellOf(m.Vs, o) : null;
        return m != null && idx != null && m.Veto[Flat(m, idx)] == 1;
    }

    /// <summary>Every vetoed cell as "verb|flat" keys.</summary>
    public List<string> VetoedCells()
    {
        var o = new List<string>();
        foreach (var m in _models) for (int c = 0; c < m.NCells; c++) if (m.Veto[c] != 0) o.Add(m.Vs.Verb + "|" + c);
        return o;
    }

    public Observation? Observe(Outcome o, int y) => Observe(o, y, "elicitation", null);

    /// <summary>Record the answer y to "should the outcome (or every outcome of the region) be allowed?"; null outside the space or on an empty region.</summary>
    public Observation? Observe(Outcome o, int y, string source, Region? region)
    {
        var m = Model(o.Verb);
        if (m == null) return null;
        var idx = CellOf(m.Vs, o);
        if (idx == null) return null;
        int[] cells;
        if (region != null)
        {
            var rc = RegionCells(m.Vs, region, y == 1);
            cells = new int[rc.Count];
            for (int i = 0; i < cells.Length; i++) cells[i] = (int)rc[i];
        }
        else cells = new[] { Flat(m, idx) };
        if (cells.Length == 0) return null;
        Refresh(m);
        var obs = new Observation(o.Verb, new Dictionary<string, object?>(o.Values), idx, y, source, region);
        double regionP = 0;
        for (int h = 1; h < m.Nh; h++) if (m.W[h] > 0 && HoldsAll(m, h, cells)) regionP += m.W[h];
        bool contradictsAll = y == 0 ? regionP >= 1 - 1e-12 : regionP <= 1e-12;
        if (source == "runtime" && y == 0) foreach (int c in cells) m.Veto[c] = 1;
        foreach (int c in cells) m.Seen[c] = 1;
        if (AgnosticSlack != null)
        {
            for (int h = 0; h < m.Nh; h++) if ((HoldsAll(m, h, cells) ? 1 : 0) != y) m.Err[h] = m.Err[h] + 1;
            double minErr = double.PositiveInfinity;
            for (int h = 0; h < m.Nh; h++) if (m.Prior[h] > 0) minErr = Math.Min(minErr, m.Err[h]);
            for (int h = 0; h < m.Nh; h++) m.W[h] = m.Err[h] <= minErr + AgnosticSlack.Value ? m.Prior[h] : 0;
            Normalize(m.W);
            if (contradictsAll)
            {
                obs.Conflict = true;
                if (y == 0) foreach (int c in cells) m.Veto[c] = 1;
            }
        }
        else
        {
            double[]? prev = EtaPos == 0 || EtaNeg == 0 ? (double[])m.W.Clone() : null;
            double sum = 0;
            for (int h = 0; h < m.Nh; h++)
            {
                int inH = HoldsAll(m, h, cells) ? 1 : 0;
                double lik = inH == 1 ? (y == 1 ? 1 - EtaNeg : EtaNeg) : y == 1 ? EtaPos : 1 - EtaPos;
                m.W[h] = m.W[h] * lik;
                sum += m.W[h];
            }
            if (sum == 0 && prev != null)
            {
                Array.Copy(prev, 0, m.W, 0, m.Nh);
                obs.Conflict = true;
                if (y == 0) foreach (int c in cells) m.Veto[c] = 1;
            }
            else Normalize(m.W);
        }
        m.Dirty = true;
        Observations.Add(obs);
        return obs;
    }

    public List<CellView> Cells()
    {
        var o = new List<CellView>();
        foreach (var m in _models)
        {
            Refresh(m);
            for (int c = 0; c < m.NCells; c++) o.Add(new CellView(m.Vs.Verb, DecodeCell(m.Vs, c), m.P[c], m.Mass[c], m.Harm[c], InGrant(m, c), m.Veto[c] == 1));
        }
        return o;
    }

    public LearnerMetrics Metrics()
    {
        double risk = 0, burden = 0, unc = 0, ent = 0, vsum = 0, dis = 0, meanHarm = 0;
        foreach (var m in _models)
        {
            Refresh(m);
            for (int c = 0; c < m.NCells; c++)
            {
                double p = m.P[c];
                double mu = m.Mass[c];
                meanHarm += mu * m.Harm[c];
                if (InGrant(m, c)) risk += mu * (1 - p) * m.Harm[c];
                else burden += mu * p;
                unc += mu * Math.Min(p, 1 - p);
                if (p > 1e-12 && p < 1 - 1e-12) dis += mu;
            }
            int alive = 0;
            for (int h = 0; h < m.Nh; h++)
            {
                double w = m.W[h];
                if (w > 0) { alive++; ent -= w * DetMath.DetLog2(w); }
            }
            vsum += DetMath.DetLog2(Math.Max(1, alive));
        }
        var r = new LearnerMetrics
        {
            ResidualRisk = risk, Burden = burden, Uncertainty = unc, EntropyBits = ent,
            Log2VersionSpace = _noisy ? null : vsum, DisagreementMass = dis, MeanHarm = meanHarm,
        };
        foreach (var o in Observations)
        {
            if (o.Source == "elicitation") r.Questions++;
            if (o.Conflict) r.Conflicts++;
        }
        return r;
    }

    /// <summary>The next question: argmax expected information (times mass and harm for the risk strategy); null when nothing is uncertain.</summary>
    public Question? NextQuestion()
    {
        Question? best = null;
        double hPos = BinEnt(EtaPos);
        double hNeg = BinEnt(EtaNeg);
        foreach (var m in _models)
        {
            Refresh(m);
            for (int c = 0; c < m.NCells; c++)
            {
                if (m.Veto[c] != 0) continue;
                double p = m.P[c];
                if (p <= 1e-9 || p >= 1 - 1e-9) continue;
                double pe = p * (1 - EtaNeg) + (1 - p) * EtaPos;
                double score = BinEnt(pe) - (EtaPos == EtaNeg ? hPos : p * hNeg + (1 - p) * hPos);
                if (Strategy == "risk") score *= m.Mass[c] * m.Harm[c];
                if (score <= 1e-15) continue;
                if (best == null || score > best.Score + 1e-12)
                {
                    var cell = DecodeCell(m.Vs, c);
                    best = new Question(m.Vs.Verb, cell, CellRep(m.Vs, cell), p, score);
                }
            }
        }
        return best;
    }

    /// <summary>Grant cells inferred but never directly observed, most consequential first.</summary>
    public List<Unconfirmed> UnconfirmedGrantCells()
    {
        var o = new List<Unconfirmed>();
        foreach (var m in _models)
        {
            Refresh(m);
            for (int c = 0; c < m.NCells; c++)
            {
                if (m.Seen[c] != 0 || !InGrant(m, c)) continue;
                o.Add(new Unconfirmed(m.Vs.Verb, DecodeCell(m.Vs, c), m.Mass[c] * m.Harm[c]));
            }
        }
        // stable, descending by weight (Java's List.sort is stable; OrderBy is too)
        return o.OrderByDescending(u => u.Weight, Comparer<double>.Create((a, b) => a.CompareTo(b))).ToList();
    }

    /// <summary>The conservative grant as predicates plus the reversibility caveat.</summary>
    public Synthesis Synthesize()
    {
        var predicates = new List<D>();
        var order = new List<string> { "reversible", "rate_limited", "irreversible" };
        int worst = -1;
        foreach (var m in _models)
        {
            Refresh(m);
            var allowed = new byte[m.NCells];
            bool any = false;
            for (int c = 0; c < m.NCells; c++) if (InGrant(m, c)) { allowed[c] = 1; any = true; }
            if (!any) continue;
            worst = Math.Max(worst, order.IndexOf(m.Vs.Reversibility));
            predicates.AddRange(BoxesToPredicates(m.Vs, allowed));
        }
        var caveats = new List<D>();
        if (worst >= 0) caveats.Add(new D { ["type"] = "reversibility_max", ["class"] = order[worst] });
        return new Synthesis(predicates, caveats);
    }

    /// <summary>Replay observations onto a fresh learner.</summary>
    public static IntentLearner Replay(Omega omega, LearnerOptions opts, IEnumerable<Observation> observations)
    {
        var l = new IntentLearner(omega, opts);
        foreach (var o in observations) l.Observe(new Outcome(o.Verb, o.Values), o.Y, o.Source, o.Region);
        return l;
    }

    static void Normalize(double[] w)
    {
        double s = 0;
        foreach (double x in w) s += x;
        if (s > 0) for (int i = 0; i < w.Length; i++) w[i] = w[i] / s;
    }

    static void MixPrior(VerbModel m, PriorMix mix)
    {
        if (!(mix.Beta >= 0 && mix.Beta < 1)) throw new ArgumentException("pca-intent: priorMix.beta must be in [0, 1)");
        var pop = new double[m.Nh];
        double z = 0;
        for (int h = 0; h < m.Nh; h++)
        {
            int hh = h;
            double x = mix.Weight(m.Vs, c => hh != 0 && c >= 0 && c < m.NCells && Holds(m, hh, c));
            if (!(double.IsFinite(x) && x >= 0)) throw new ArgumentException("pca-intent: priorMix.weight must be finite and >= 0");
            pop[h] = x;
            z += x;
        }
        if (!(z > 0)) return;
        for (int h = 0; h < m.Nh; h++) m.W[h] = (1 - mix.Beta) * m.W[h] + (mix.Beta * pop[h]) / z;
    }

    // ---- synthesis: allowed cells -> union of boxes -> predicates ----

    sealed class Box
    {
        /// <summary>numeric: {lo, hi}; categorical: null here and a value set (insertion ordered) at the same index in Sets.</summary>
        public readonly int[]?[] Ranges;
        public readonly List<int>?[] Sets;
        public Box(int n) { Ranges = new int[n][]; Sets = new List<int>?[n]; }
    }

    static List<int[]> BoxCells(Box box)
    {
        var acc = new List<int[]> { Array.Empty<int>() };
        for (int k = 0; k < box.Ranges.Length; k++)
        {
            var vals = new List<int>();
            if (box.Ranges[k] != null) { for (int i = box.Ranges[k]![0]; i <= box.Ranges[k]![1]; i++) vals.Add(i); }
            else { vals.AddRange(box.Sets[k]!); vals.Sort(); }
            var next = new List<int[]>();
            foreach (var pre in acc) foreach (int v in vals)
            {
                var n = new int[pre.Length + 1];
                Array.Copy(pre, n, pre.Length);
                n[pre.Length] = v;
                next.Add(n);
            }
            acc = next;
        }
        return acc;
    }

    static int Encode(int[] nCellsD, int[] idx)
    {
        int f = 0;
        for (int i = 0; i < nCellsD.Length; i++) f = f * nCellsD[i] + idx[i];
        return f;
    }

    static D Cond(string field, string op, object? value) => new() { ["field"] = field, ["op"] = op, ["value"] = value };

    static D Single(string k, object? v) => new() { [k] = v };

    static D? CatCondition(CatDim d, List<int> s)
    {
        if (s.Count == d.Values.Count) return null;
        var exacts = new List<string>();
        var prefixes = new List<string>();
        foreach (var v in d.Values)
        {
            if (v.Kind == "exact") exacts.Add(v.Value);
            if (v.Kind == "prefix") prefixes.Add(v.Value);
        }
        var alts = new List<D>();
        var allowedExacts = new L();
        foreach (int i in s) if (d.Values[i].Kind == "exact") allowedExacts.Add(d.Values[i].Value);
        if (allowedExacts.Count == 1) alts.Add(Cond(d.Path, "eq", allowedExacts[0]));
        else if (allowedExacts.Count > 1) alts.Add(Cond(d.Path, "in", allowedExacts));
        var sorted = new List<int>(s);
        sorted.Sort();
        foreach (int i in sorted)
        {
            var v = d.Values[i];
            if (v.Kind == "exact") continue;
            var parts = new List<D>();
            if (v.Kind == "prefix")
            {
                parts.Add(Cond(d.Path, "prefix", v.Value));
                var under = new L();
                foreach (var e in exacts) if (e.StartsWith(v.Value, StringComparison.Ordinal)) under.Add(e);
                if (under.Count > 0) parts.Add(Cond(d.Path, "nin", under));
                foreach (var q in prefixes) if (q != v.Value && q.StartsWith(v.Value, StringComparison.Ordinal)) parts.Add(Single("not", Cond(d.Path, "prefix", q)));
            }
            else
            {
                if (exacts.Count > 0) parts.Add(Cond(d.Path, "nin", exacts.Select(x => (object?)x).ToList()));
                foreach (var q in prefixes) parts.Add(Single("not", Cond(d.Path, "prefix", q)));
            }
            if (parts.Count == 1) alts.Add(parts[0]);
            else if (parts.Count > 1) alts.Add(Single("all_of", parts.Select(x => (object?)x).ToList()));
        }
        if (alts.Count == 0) return null;
        return alts.Count == 1 ? alts[0] : Single("any_of", alts.Select(x => (object?)x).ToList());
    }

    static D BoxToPredicate(VerbSpace vs, Box box)
    {
        var where = new L();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            if (d is NumDim nd && box.Ranges[k] != null)
            {
                var cells = NumCells(nd);
                where.Add(Cond(d.Path, "gte", N(cells[box.Ranges[k]![0]].Lo)));
                where.Add(Cond(d.Path, "lte", N(cells[box.Ranges[k]![1]].Hi)));
            }
            else if (d is CatDim cd && box.Sets[k] != null)
            {
                var c = CatCondition(cd, box.Sets[k]!);
                if (c != null) where.Add(c);
            }
        }
        var p = new D { ["verb"] = vs.Verb, ["resource"] = "*" };
        if (where.Count > 0) p["where"] = where;
        return p;
    }

    /// <summary>Cover the allowed cell set exactly with greedily grown maximal boxes; one predicate per box.</summary>
    public static List<D> BoxesToPredicates(VerbSpace vs, byte[] allowed)
    {
        int dn = vs.Dims.Count;
        var nCellsD = new int[dn];
        for (int k = 0; k < dn; k++) nCellsD[k] = CellCount(vs.Dims[k]);
        var covered = new byte[allowed.Length];
        var o = new List<D>();
        for (int c = 0; c < allowed.Length; c++)
        {
            if (allowed[c] == 0 || covered[c] != 0) continue;
            var idx = DecodeCell(vs, c);
            var box = new Box(dn);
            for (int k = 0; k < dn; k++)
            {
                if (vs.Dims[k].Kind == "num") box.Ranges[k] = new[] { idx[k], idx[k] };
                else box.Sets[k] = new List<int> { idx[k] };
            }
            for (int k = 0; k < dn; k++)
            {
                var d = vs.Dims[k];
                if (d.Kind == "num")
                {
                    int n = nCellsD[k];
                    var r = box.Ranges[k]!;
                    while (r[1] + 1 < n)
                    {
                        r[1]++;
                        if (!AllIn(box, allowed, nCellsD)) { r[1]--; break; }
                    }
                    while (r[0] > 0)
                    {
                        r[0]--;
                        if (!AllIn(box, allowed, nCellsD)) { r[0]++; break; }
                    }
                }
                else
                {
                    var s = box.Sets[k]!;
                    for (int v = 0; v < ((CatDim)d).Values.Count; v++)
                    {
                        if (s.Contains(v)) continue;
                        s.Add(v);
                        if (!AllIn(box, allowed, nCellsD)) s.Remove(v);
                    }
                }
            }
            foreach (var bi in BoxCells(box)) covered[Encode(nCellsD, bi)] = 1;
            o.Add(BoxToPredicate(vs, box));
        }
        return o;
    }

    static bool AllIn(Box b, byte[] allowed, int[] nCellsD)
    {
        foreach (var idx in BoxCells(b)) if (allowed[Encode(nCellsD, idx)] != 1) return false;
        return true;
    }

    // ---- elicitation loop ----

    public sealed class ElicitOptions
    {
        public double EpsRisk, EpsBurden;
        public int MaxQuestions;
        public bool Audit;
        public List<(string Verb, int[] Cell)> Seed = new();

        public ElicitOptions(double epsRisk, double epsBurden, int maxQuestions, bool audit)
        {
            EpsRisk = epsRisk; EpsBurden = epsBurden; MaxQuestions = maxQuestions; Audit = audit;
        }
    }

    public sealed class ElicitResult
    {
        public string Stop { get; }
        public int Questions { get; }
        public int AuditQuestions { get; }
        public int SeedQuestions { get; }
        public List<Question> Asked { get; }
        internal ElicitResult(string stop, int questions, int auditQuestions, int seedQuestions, List<Question> asked)
        {
            Stop = stop; Questions = questions; AuditQuestions = auditQuestions; SeedQuestions = seedQuestions; Asked = asked;
        }
    }

    static Question? SeedQuestion(IntentLearner learner, string verb, int[] cell)
    {
        var vs = learner.Omega.Verbs.Find(v => v.Verb == verb);
        if (vs == null || cell.Length != vs.Dims.Count) return null;
        var outcome = CellRep(vs, cell);
        double p = learner.Acceptance(outcome);
        if (p <= 1e-9 || p >= 1 - 1e-9 || learner.IsVetoed(outcome)) return null;
        return new Question(verb, (int[])cell.Clone(), outcome, p, 0);
    }

    public static ElicitResult Elicit(IntentLearner learner, Func<Question, int> answer, ElicitOptions o)
    {
        var asked = new List<Question>();
        int seedQuestions = 0;
        foreach (var s in o.Seed)
        {
            if (asked.Count >= o.MaxQuestions) break;
            var m = learner.Metrics();
            if (m.ResidualRisk <= o.EpsRisk && m.Burden <= o.EpsBurden) break;
            var q = SeedQuestion(learner, s.Verb, s.Cell);
            if (q == null) continue;
            learner.Observe(q.Outcome, answer(q), "elicitation", null);
            asked.Add(q);
            seedQuestions++;
        }
        string? stop = null;
        while (stop == null)
        {
            var m = learner.Metrics();
            if (m.ResidualRisk <= o.EpsRisk && m.Burden <= o.EpsBurden) stop = "converged";
            else if (asked.Count >= o.MaxQuestions) stop = "budget";
            else
            {
                var q = learner.NextQuestion();
                if (q == null) stop = "no-disagreement";
                else
                {
                    learner.Observe(q.Outcome, answer(q), "elicitation", null);
                    asked.Add(q);
                }
            }
        }
        var audit = AuditRound(learner, answer, o.EpsRisk, o.MaxQuestions, o.Audit, asked);
        if (audit[1] == 1) stop = "budget";
        return new ElicitResult(stop, asked.Count, audit[0], seedQuestions, asked);
    }

    /// <summary>The audit round on its own: {questions asked, 1 when the budget ran out before the unconfirmed weight fell to epsRisk}. Appends to asked.</summary>
    public static int[] AuditRound(IntentLearner learner, Func<Question, int> answer, double epsRisk, int maxQuestions, bool audit, List<Question> asked)
    {
        int n = 0;
        if (!audit) return new[] { 0, 0 };
        for (; ; )
        {
            var pending = learner.UnconfirmedGrantCells();
            double mass = 0;
            foreach (var x in pending) mass += x.Weight;
            if (pending.Count == 0 || mass <= epsRisk) return new[] { n, 0 };
            if (asked.Count >= maxQuestions) return new[] { n, 1 };
            var top = pending[0];
            var vs = learner.Omega.Verbs.Find(v => v.Verb == top.Verb)!;
            var oc = CellRep(vs, top.Cell);
            var q = new Question(top.Verb, top.Cell, oc, learner.Acceptance(oc), top.Weight);
            learner.Observe(q.Outcome, answer(q), "elicitation", null);
            asked.Add(q);
            n++;
        }
    }
}
