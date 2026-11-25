// The intent outcome space (omega): a typed, finite cell grid per verb. Numeric dimensions are integer ranges partitioned by
// cuts, categorical dimensions are value lists ending in OTHER; the workload is a product measure and the harm model is
// separable. Every figure is binary64 computed in the reference's operation order (logarithm and exponential from fdlibm), so
// the doubles match the reference bit for bit. Values arriving as JSON trees (Dictionary / List / Num / string / bool / null)
// convert with the *FromJson helpers and back with the *ToJson helpers.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentOmega
{
    /// <summary>The categorical "any other value" sentinel.</summary>
    public const string Other = "⊥";
    public const int ExactSpan = 4096;
    public const int HarmQuadraturePieces = 1024;
    const double EulerGamma = 0.5772156649015329;

    public sealed record CatValue(string Kind, string Value);

    public sealed record NumCell(double Lo, double Hi);

    public sealed record Stats(double Mass, double Harm);

    /// <summary>A dimension of a verb space: numeric (<c>Kind == "num"</c>) or categorical (<c>"cat"</c>).</summary>
    public abstract class Dim
    {
        public string Kind { get; }
        public string Path { get; }
        protected Dim(string kind, string path) { Kind = kind; Path = path; }
    }

    public sealed class NumDim : Dim
    {
        public double Lo { get; }
        public double Hi { get; }
        public double[] Cuts { get; }
        public string Dist { get; }
        internal List<NumCell>? CellCache;
        internal double? Total;
        public NumDim(string path, double lo, double hi, double[] cuts, string dist) : base("num", path) { Lo = lo; Hi = hi; Cuts = cuts; Dist = dist; }
    }

    public sealed class CatDim : Dim
    {
        public List<CatValue> Values { get; }
        public CatDim(string path, List<CatValue> values) : base("cat", path) { Values = values; }
    }

    public sealed class VerbSpace
    {
        public string Verb { get; }
        public string Reversibility { get; }
        public double Weight { get; set; }
        public List<Dim> Dims { get; }
        public VerbSpace(string verb, string reversibility, double weight, List<Dim> dims) { Verb = verb; Reversibility = reversibility; Weight = weight; Dims = dims; }
    }

    public sealed class Omega
    {
        public List<VerbSpace> Verbs { get; }
        public List<string> Approximate { get; }
        public Omega(List<VerbSpace> verbs, List<string> approximate) { Verbs = verbs; Approximate = approximate; }
    }

    /// <summary>A concrete outcome: the verb and one value per dimension path (a double or a string; any other JSON value lies outside every dimension).</summary>
    public sealed class Outcome
    {
        public string Verb { get; }
        public Dictionary<string, object?> Values { get; }
        public Outcome(string verb, Dictionary<string, object?> values) { Verb = verb; Values = values; }
        internal object? ValueAt(string path) => Values.TryGetValue(path, out var v) ? v : null;
    }

    public sealed record Sample(VerbSpace Vs, Outcome O);

    public abstract class HarmModel
    {
        public abstract double Verb(VerbSpace vs);
        public abstract double Factor(Dim d, object? x);
        /// <summary>Optional closed form of the mean of <see cref="Factor"/> over an integer interval; null when absent.</summary>
        public virtual double? DimMean(NumDim d, double lo, double hi) => null;
    }

    // ---- JSON <-> typed ----

    internal static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new InvalidOperationException("not a number");
    internal static D Obj(object? o) => o as D ?? throw new InvalidOperationException("not an object");
    internal static L Arr(object? o) => o as L ?? throw new InvalidOperationException("not an array");
    internal static bool IsNum(object? o) => IntentJs.NumOf(o) != null;
    /// <summary>A double as the reference's JSON prints it; a non-finite value as {"$num": text} (JSON cannot carry it).</summary>
    internal static object? N(double d) => double.IsFinite(d) ? JsX.Number(d) : new D { ["$num"] = JsX.JsNumString(d) };
    internal static string Str(object? o) => o as string ?? throw new InvalidOperationException("not a string");

    /// <summary>A parsed JSON value as an outcome value: numbers become doubles, everything else stays as is.</summary>
    internal static object? Value(object? o) => IntentJs.NumOf(o) is double d ? d : o;

    public static Dim DimFromJson(object? o)
    {
        var m = Obj(o);
        var path = Str(m.GetValueOrDefault("path"));
        if (m.GetValueOrDefault("kind") is "num")
            return new NumDim(path, Dbl(m.GetValueOrDefault("lo")), Dbl(m.GetValueOrDefault("hi")), Arr(m.GetValueOrDefault("cuts")).Select(Dbl).ToArray(), Str(m.GetValueOrDefault("dist")));
        return new CatDim(path, Arr(m.GetValueOrDefault("values")).Select(CatValueFromJson).ToList());
    }

    internal static CatValue CatValueFromJson(object? x) => new(Str(Obj(x).GetValueOrDefault("kind")), Str(Obj(x).GetValueOrDefault("value")));

    internal static D CatValueToJson(CatValue v) => new() { ["kind"] = v.Kind, ["value"] = v.Value };

    public static D DimToJson(Dim d)
    {
        var m = new D { ["kind"] = d.Kind, ["path"] = d.Path };
        if (d is NumDim n)
        {
            m["lo"] = N(n.Lo);
            m["hi"] = N(n.Hi);
            m["cuts"] = n.Cuts.Select(c => N(c)).ToList();
            m["dist"] = n.Dist;
        }
        else m["values"] = ((CatDim)d).Values.Select(v => (object?)CatValueToJson(v)).ToList();
        return m;
    }

    public static VerbSpace VerbSpaceFromJson(object? o)
    {
        var m = Obj(o);
        return new VerbSpace(Str(m.GetValueOrDefault("verb")), Str(m.GetValueOrDefault("reversibility")), Dbl(m.GetValueOrDefault("weight")),
            Arr(m.GetValueOrDefault("dims")).Select(DimFromJson).ToList());
    }

    public static D VerbSpaceToJson(VerbSpace vs) => new()
    {
        ["verb"] = vs.Verb,
        ["reversibility"] = vs.Reversibility,
        ["weight"] = N(vs.Weight),
        ["dims"] = vs.Dims.Select(d => (object?)DimToJson(d)).ToList(),
    };

    public static Omega OmegaFromJson(object? o)
    {
        var m = Obj(o);
        var ap = m.GetValueOrDefault("approximate") is L a ? a.Select(Str).ToList() : new List<string>();
        return new Omega(Arr(m.GetValueOrDefault("verbs")).Select(VerbSpaceFromJson).ToList(), ap);
    }

    public static D OmegaToJson(Omega om) => new()
    {
        ["v"] = new Num("1"),
        ["verbs"] = om.Verbs.Select(v => (object?)VerbSpaceToJson(v)).ToList(),
        ["approximate"] = om.Approximate.Select(s => (object?)s).ToList(),
    };

    public static Outcome OutcomeFromJson(object? o)
    {
        var m = Obj(o);
        var vals = new Dictionary<string, object?>();
        foreach (var (k, v) in Obj(m.GetValueOrDefault("values"))) vals[k] = Value(v);
        return new Outcome(Str(m.GetValueOrDefault("verb")), vals);
    }

    public static D OutcomeToJson(Outcome o)
    {
        var vals = new D();
        foreach (var (k, v) in o.Values) vals[k] = v is double d ? N(d) : v;
        return new D { ["verb"] = o.Verb, ["values"] = vals };
    }

    public static D StatsToJson(Stats s) => new() { ["mass"] = N(s.Mass), ["harm"] = N(s.Harm) };

    // ---- cells ----

    /// <summary>The ordered cells of a numeric dimension (inclusive integer ranges; empty cells dropped).</summary>
    public static List<NumCell> NumCells(NumDim d)
    {
        if (d.CellCache != null) return d.CellCache;
        var output = new List<NumCell>();
        double cur = d.Lo;
        foreach (var c in d.Cuts)
        {
            if (c < d.Lo || c > d.Hi) continue;
            if (cur <= c - 1) output.Add(new NumCell(cur, c - 1));
            output.Add(new NumCell(c, c));
            cur = c + 1;
        }
        if (cur <= d.Hi) output.Add(new NumCell(cur, d.Hi));
        d.CellCache = output;
        return output;
    }

    public static int CellCount(Dim d) => d is NumDim n ? NumCells(n).Count : ((CatDim)d).Values.Count;

    /// <summary>The number of cells of a verb (the product of the per-dimension counts), a binary64 like the reference's.</summary>
    public static double VerbCellCount(VerbSpace vs)
    {
        double n = 1;
        foreach (var d in vs.Dims) n *= CellCount(d);
        return n;
    }

    /// <summary>Per-dimension cell indices of a flat cell index (the last dimension varies fastest).</summary>
    public static int[] DecodeCell(VerbSpace vs, double flat)
    {
        var idx = new int[vs.Dims.Count];
        for (int i = vs.Dims.Count - 1; i >= 0; i--)
        {
            int n = CellCount(vs.Dims[i]);
            idx[i] = (int)(flat % n);
            flat = Math.Floor(flat / n);
        }
        return idx;
    }

    public static double EncodeCell(VerbSpace vs, IReadOnlyList<int> idx)
    {
        double flat = 0;
        for (int i = 0; i < vs.Dims.Count; i++) flat = flat * CellCount(vs.Dims[i]) + idx[i];
        return flat;
    }

    /// <summary>The cell of a categorical dimension a string falls in: exact, then the longest prefix, then OTHER.</summary>
    public static int CatCellOf(CatDim d, string s)
    {
        int best = -1, bestLen = -1;
        for (int i = 0; i < d.Values.Count; i++)
        {
            var v = d.Values[i];
            if (v.Kind == "exact" && v.Value == s) return i;
            if (v.Kind == "prefix" && s.StartsWith(v.Value, StringComparison.Ordinal) && v.Value.Length > bestLen) { best = i; bestLen = v.Value.Length; }
        }
        if (best >= 0) return best;
        return d.Values.FindIndex(v => v.Kind == "other");
    }

    /// <summary>The cell a value falls in, or -1 outside the dimension's domain or type.</summary>
    public static int CellOfValue(Dim d, object? x)
    {
        if (d is NumDim n)
        {
            if (x is not double v || !double.IsFinite(v)) return -1;
            var cells = NumCells(n);
            for (int i = 0; i < cells.Count; i++) if (v >= cells[i].Lo && v <= cells[i].Hi) return i;
            return -1;
        }
        return x is string s ? CatCellOf((CatDim)d, s) : -1;
    }

    /// <summary>Per-dimension cell indices of an outcome, or null when a value lies outside the space.</summary>
    public static int[]? CellOf(VerbSpace vs, Outcome o)
    {
        var idx = new int[vs.Dims.Count];
        for (int k = 0; k < idx.Length; k++)
        {
            int i = CellOfValue(vs.Dims[k], o.ValueAt(vs.Dims[k].Path));
            if (i < 0) return null;
            idx[k] = i;
        }
        return idx;
    }

    /// <summary>A concrete string that falls in categorical cell <paramref name="i"/>.</summary>
    public static string CatRep(CatDim d, int i)
    {
        var v = d.Values[i];
        if (v.Kind == "exact") return v.Value;
        var b = v.Kind == "prefix" ? v.Value + "x" : "other";
        for (int k = 0; k < 64; k++)
        {
            var s = b + (k == 0 ? "" : k.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (CatCellOf(d, s) == i) return s;
        }
        return b;
    }

    /// <summary>The question point of a numeric cell: a boundary witness (lowest value of a cell with a left neighbour, else the highest).</summary>
    public static double NumRep(NumDim d, int i)
    {
        var c = NumCells(d)[i];
        return i > 0 ? c.Lo : c.Hi;
    }

    /// <summary>A double for a numeric dimension, a string for a categorical one.</summary>
    public static object RepValue(Dim d, int i) => d is NumDim n ? NumRep(n, i) : CatRep((CatDim)d, i);

    public static Outcome CellRep(VerbSpace vs, IReadOnlyList<int> idx)
    {
        var values = new Dictionary<string, object?>();
        for (int i = 0; i < vs.Dims.Count; i++) values[vs.Dims[i].Path] = RepValue(vs.Dims[i], idx[i]);
        return new Outcome(vs.Verb, values);
    }

    // ---- workload and harm ----

    static bool LogUniform(NumDim d) => d.Dist == "loguniform" && d.Lo >= 0;

    internal static double PointWeight(NumDim d, double x) => LogUniform(d) ? 1 / (x + 1) : 1;

    static readonly Regex Amount = new(@"(^|\.)amount\z", RegexOptions.CultureInvariant);

    static bool LinearAmount(Dim d) => d is NumDim && Amount.IsMatch(d.Path);

    sealed class DefaultHarm : HarmModel
    {
        public override double Verb(VerbSpace vs) => vs.Reversibility == "irreversible" ? 10 : vs.Reversibility == "rate_limited" ? 3 : 1;
        public override double Factor(Dim d, object? x) => LinearAmount(d) && x is double v ? 1 + Math.Max(0, v) / 100 : 1;
        public override double? DimMean(NumDim d, double lo, double hi) => LinearAmount(d) ? 1 + Math.Max(0, IntervalMeanX(d, Math.Max(lo, 0), hi, lo)) / 100 : 1.0;
    }

    /// <summary>Irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100.</summary>
    public static readonly HarmModel DefaultHarmModel = new DefaultHarm();

    /// <summary>Upper bound of the harm model over the space.</summary>
    public static double HarmMax(Omega omega, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        double m = 0;
        foreach (var vs in omega.Verbs)
        {
            double f = harm.Verb(vs);
            foreach (var d in vs.Dims)
            {
                if (d is NumDim n) f *= Math.Max(harm.Factor(d, n.Lo), harm.Factor(d, n.Hi));
                else
                {
                    var c = (CatDim)d;
                    double mx = double.NegativeInfinity;
                    for (int i = 0; i < c.Values.Count; i++) mx = Math.Max(mx, harm.Factor(d, CatRep(c, i)));
                    f *= mx;
                }
            }
            m = Math.Max(m, f);
        }
        return m;
    }

    static double Harmonic(double n)
    {
        if (n <= 0) return 0;
        if (n <= ExactSpan)
        {
            double s = 0;
            for (double k = n; k >= 1; k--) s += 1 / k;
            return s;
        }
        double n2 = n * n;
        return DetMath.DetLn(n) + EulerGamma + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2);
    }

    /// <summary>The sum of the point weight over the integers a..b (0 for an empty interval).</summary>
    public static double IntervalWeight(NumDim d, double a, double b)
    {
        if (b < a) return 0;
        if (!LogUniform(d)) return b - a + 1;
        if (b - a + 1 <= ExactSpan)
        {
            double s = 0;
            for (double x = b; x >= a; x--) s += 1 / (x + 1);
            return s;
        }
        return Harmonic(b + 1) - Harmonic(a);
    }

    static double IntervalFirstMoment(NumDim d, double a, double b)
    {
        if (b < a) return 0;
        if (!LogUniform(d)) return ((a + b) * (b - a + 1)) / 2;
        return b - a + 1 - IntervalWeight(d, a, b);
    }

    static double IntervalMeanX(NumDim d, double a, double b, double cellLo)
    {
        double whole = IntervalWeight(d, cellLo, b);
        return whole > 0 ? IntervalFirstMoment(d, a, b) / whole : 0;
    }

    /// <summary>The reference's Math.round: ties toward positive infinity.</summary>
    static double JsRound(double x)
    {
        double f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    static double IntervalHarm(NumDim d, double a, double b, HarmModel harm)
    {
        var mean = harm.DimMean(d, a, b);
        if (mean != null) return mean.Value;
        double n = b - a + 1;
        double wTot = IntervalWeight(d, a, b);
        if (!(wTot > 0)) return harm.Factor(d, a);
        if (n <= ExactSpan)
        {
            double s0 = 0;
            for (double x = a; x <= b; x++) s0 += PointWeight(d, x) * harm.Factor(d, x);
            return s0 / wTot;
        }
        double s = 0;
        for (int i = 0; i < HarmQuadraturePieces; i++)
        {
            double pa = a + Math.Floor((i * n) / HarmQuadraturePieces);
            double pb = a + Math.Floor(((i + 1) * n) / HarmQuadraturePieces) - 1;
            if (pb < pa) continue;
            double w = IntervalWeight(d, pa, pb);
            s += w * harm.Factor(d, JsRound((pa + pb) / 2));
        }
        return s / wTot;
    }

    static double DimTotal(NumDim d) => d.Total ??= IntervalWeight(d, d.Lo, d.Hi);

    /// <summary>The mass of one dimension cell and the expected harm over it (categorical values are uniform).</summary>
    public static Stats DimCellStats(Dim d, int i, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        if (d is CatDim c) return new Stats(1.0 / c.Values.Count, harm.Factor(d, CatRep(c, i)));
        var n = (NumDim)d;
        var cell = NumCells(n)[i];
        double wm = IntervalWeight(n, cell.Lo, cell.Hi);
        return new Stats(wm / DimTotal(n), wm > 0 ? IntervalHarm(n, cell.Lo, cell.Hi, harm) : harm.Factor(n, cell.Lo));
    }

    static double QuantileValue(NumDim d, double target)
    {
        double acc = 0;
        var cells = NumCells(d);
        foreach (var c in cells)
        {
            double w = IntervalWeight(d, c.Lo, c.Hi);
            if (target < acc + w || ReferenceEquals(c, cells[^1]))
            {
                double r = target - acc;
                if (c.Hi - c.Lo + 1 <= ExactSpan)
                {
                    for (double x = c.Lo; x < c.Hi; x++)
                    {
                        r -= PointWeight(d, x);
                        if (r < 0) return x;
                    }
                    return c.Hi;
                }
                if (!LogUniform(d)) return Math.Min(c.Hi, c.Lo + Math.Floor(r));
                double xx = Math.Floor((c.Lo + 1) * DetMath.DetExp(r) - 1);
                return Math.Max(c.Lo, Math.Min(c.Hi, xx));
            }
            acc += w;
        }
        return d.Hi;
    }

    /// <summary>Exact mass of a whole cell and the expected harm over it (product measure, separable harm).</summary>
    public static Stats CellStats(VerbSpace vs, IReadOnlyList<int> idx, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        double mass = vs.Weight;
        double h = harm.Verb(vs);
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var s = DimCellStats(vs.Dims[k], idx[k], harm);
            mass *= s.Mass;
            h *= s.Harm;
        }
        return new Stats(mass, h);
    }

    /// <summary>Exact harm of a concrete outcome.</summary>
    public static double HarmOf(VerbSpace vs, Outcome o, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        double h = harm.Verb(vs);
        foreach (var d in vs.Dims) h *= harm.Factor(d, o.ValueAt(d.Path));
        return h;
    }

    /// <summary>mulberry32: a small seeded generator, so every Monte Carlo number is reproducible. The seed is taken as an unsigned 32-bit integer.</summary>
    public static Func<double> Rng(double seed)
    {
        uint a = unchecked((uint)(long)(double.IsFinite(seed) ? Math.Truncate(seed) % 4294967296.0 : 0));
        return () =>
        {
            unchecked
            {
                a += 0x6d2b79f5u;
                uint t = a;
                t = (t ^ (t >> 15)) * (t | 1);
                t ^= t + (t ^ (t >> 7)) * (t | 61);
                return (t ^ (t >> 14)) / 4294967296.0;
            }
        };
    }

    /// <summary>Draw an outcome from the workload. An empty space throws (no verb to draw).</summary>
    public static Sample SampleOutcome(Omega omega, Func<double> rand)
    {
        double u = rand();
        if (omega.Verbs.Count == 0) throw new InvalidOperationException("the space has no verbs");
        var vs = omega.Verbs[^1];
        foreach (var v in omega.Verbs)
        {
            if (u < v.Weight) { vs = v; break; }
            u -= v.Weight;
        }
        var values = new Dictionary<string, object?>();
        foreach (var d in vs.Dims)
        {
            if (d is CatDim c)
            {
                values[d.Path] = CatRep(c, Math.Min(c.Values.Count - 1, (int)Math.Floor(rand() * c.Values.Count)));
                continue;
            }
            var n = (NumDim)d;
            values[d.Path] = QuantileValue(n, rand() * DimTotal(n));
        }
        return new Sample(vs, new Outcome(vs.Verb, values));
    }

    public static VerbSpace? VerbSpaceOf(Omega omega, string verb) => omega.Verbs.Find(v => v.Verb == verb);
}
