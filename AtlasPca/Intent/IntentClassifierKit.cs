// Classifier error folded into the residual risk: a confusion matrix estimated on a labelled calibration set with per-entry Clopper-Pearson upper bounds
// (union bound), the risk in true coordinates (exact decomposition), the label-sound bound, the classifier-aware residual risk of a learner over the
// augmented space, and the cells a maximum-error gate sends to just-in-time consent. Calibrations and specs are JSON trees.
using System.Numerics;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentClassifierKit
{
    static L Row(double[] r) => r.Select(x => N(x)).ToList();

    /// <summary>Calibrate a classifier on labelled examples ({truth, predicted}); labels outside the set are refused. deltaGamma defaults to 0.05.</summary>
    public static D CalibrateConfusion(L samples, L labels, double? deltaGamma = null)
    {
        double delta = deltaGamma ?? 0.05;
        var set = new SortedSet<string>(Comparer<string>.Create(IntentJs.CompareUtf8));
        foreach (var l in labels) set.Add((string)l!);
        var lab = set.ToList();
        if (lab.Count == 0) throw new ArgumentException("calibrateConfusion: empty label set");
        if (!(delta > 0 && delta < 1)) throw new ArgumentException("calibrateConfusion: delta must be in (0, 1)");
        int n = lab.Count;
        var counts = new double[n][];
        for (int i = 0; i < n; i++) counts[i] = new double[n];
        foreach (var so in samples)
        {
            var s = Obj(so);
            int t = s.GetValueOrDefault("truth") is string ts ? lab.IndexOf(ts) : -1;
            int p = s.GetValueOrDefault("predicted") is string ps ? lab.IndexOf(ps) : -1;
            if (t < 0 || p < 0) throw new ArgumentException("calibrateConfusion: label outside L (" + JsX.Str(s.GetValueOrDefault("truth")) + " / " + JsX.Str(s.GetValueOrDefault("predicted")) + ")");
            counts[t][p] = counts[t][p] + 1;
        }
        double alpha = delta / ((double)n * n);
        var cs = new L();
        var gs = new L();
        var bs = new L();
        foreach (var r in counts)
        {
            double total = 0;
            foreach (var c in r) total += c;
            var g = new double[n];
            var b = new double[n];
            for (int i = 0; i < n; i++)
            {
                g[i] = total != 0 ? r[i] / total : 0;
                b[i] = IntentStats.ClopperPearsonUpper(r[i], total, alpha);
            }
            cs.Add(Row(r)); gs.Add(Row(g)); bs.Add(Row(b));
        }
        return new D
        {
            ["labels"] = lab.Select(x => (object?)x).ToList(),
            ["counts"] = cs,
            ["gamma"] = gs,
            ["gammaBar"] = bs,
            ["delta_ppm"] = N(IntentMath.JsRound(delta * 1_000_000)),
        };
    }

    /// <summary>The calibration's content address (labels, counts, delta).</summary>
    public static string ConfusionDigest(D c) =>
        Pca.HashCanonical(IntentJs.Normalize(new D
        {
            ["d"] = "atlas-pca/intent-classifier-calibration/v1", ["labels"] = c.GetValueOrDefault("labels"), ["counts"] = c.GetValueOrDefault("counts"), ["delta_ppm"] = c.GetValueOrDefault("delta_ppm"),
        }));

    /// <summary>The published error rate shown on cards: the maximum over true labels of the upper bound of any other label, capped at 1.</summary>
    public static double PublishedErrorRate(D c)
    {
        double worst = 0;
        var gb = Arr(c.GetValueOrDefault("gammaBar"));
        for (int t = 0; t < gb.Count; t++)
        {
            double s = 0;
            var r = Arr(gb[t]);
            for (int p = 0; p < r.Count; p++) if (p != t) s = s + Dbl(r[p]);
            double e = Math.Min(1, s);
            if (e > worst) worst = e;
        }
        return worst;
    }

    /// <summary>The exact value of a finite non-negative double rounded half up to one decimal, as plain text (a BigDecimal of the double, scale 1).</summary>
    static string OneDecimal(double d)
    {
        long bits = BitConverter.DoubleToInt64Bits(d);
        int e = (int)((bits >> 52) & 0x7ff);
        long frac = bits & 0xfffffffffffffL;
        BigInteger mant = e == 0 ? frac : frac | (1L << 52);
        int exp = (e == 0 ? 1 : e) - 1075;
        BigInteger rounded;
        if (exp >= 0) rounded = mant * BigInteger.Pow(2, exp) * 10;
        else
        {
            var num = mant * 10;
            var den = BigInteger.Pow(2, -exp);
            rounded = (2 * num + den) / (2 * den);
        }
        var q = BigInteger.DivRem(rounded, 10, out var rem);
        return q.ToString() + "." + rem.ToString();
    }

    /// <summary>The fixed card note for a classifier dimension.</summary>
    public static string ClassifierCardNote(string id, D c) =>
        "\"" + id + "\" is decided by an attested classifier, not by a person. Published error rate: up to " + OneDecimal(PublishedErrorRate(c) * 100) + "%.";

    // ---- risk on explicit arrays ----

    static double[][] Mat(object? o) => Arr(o).Select(r => Arr(r).Select(Dbl).ToArray()).ToArray();
    static bool[][] BMat(object? o) => Arr(o).Select(r => Arr(r).Select(x => x is true).ToArray()).ToArray();

    static double GammaOfSet(double[][] g, List<int> a, int t)
    {
        double s = 0;
        foreach (int p in a) s = s + g[p][t];
        return Math.Min(1, s);
    }

    static List<int> Members(bool[] inG)
    {
        var a = new List<int>();
        for (int p = 0; p < inG.Length; p++) if (inG[p]) a.Add(p);
        return a;
    }

    /// <summary>R_kappa(G) over explicit arrays {mu, a, h, inG, g}: sum of mu (1 - a) h Gamma(A_G(x) | l), the set mass capped at 1.</summary>
    public static double ClassifierRisk(D arrays)
    {
        double[][] mu = Mat(arrays.GetValueOrDefault("mu")), a = Mat(arrays.GetValueOrDefault("a")), h = Mat(arrays.GetValueOrDefault("h")), g = Mat(arrays.GetValueOrDefault("g"));
        var inG = BMat(arrays.GetValueOrDefault("inG"));
        double r = 0;
        for (int x = 0; x < mu.Length; x++)
        {
            var set = Members(inG[x]);
            for (int t = 0; t < mu[x].Length; t++) r += mu[x][t] * (1 - a[x][t]) * h[x][t] * GammaOfSet(g, set, t);
        }
        return r;
    }

    /// <summary>True iff a(x, l) = 1 for every (x, l) in G.</summary>
    public static bool LabelSound(D arrays)
    {
        var a = Mat(arrays.GetValueOrDefault("a"));
        var inG = BMat(arrays.GetValueOrDefault("inG"));
        for (int x = 0; x < inG.Length; x++) for (int p = 0; p < inG[x].Length; p++) if (inG[x][p] && a[x][p] != 1) return false;
        return true;
    }

    /// <summary>The bound for a label-sound grant: hMax times the mass of unacceptable cells weighted by the set error.</summary>
    public static double LabelSoundBound(D arrays, double hMax)
    {
        double[][] mu = Mat(arrays.GetValueOrDefault("mu")), a = Mat(arrays.GetValueOrDefault("a")), g = Mat(arrays.GetValueOrDefault("g"));
        var inG = BMat(arrays.GetValueOrDefault("inG"));
        double s = 0;
        for (int x = 0; x < mu.Length; x++)
        {
            var set = Members(inG[x]);
            for (int t = 0; t < mu[x].Length; t++) if (a[x][t] == 0) s += mu[x][t] * GammaOfSet(g, set, t);
        }
        return hMax * s;
    }

    // ---- risk from a learner over the augmented space ----

    sealed record Member(int[] Cell, double P, double Mass, double Harm, bool InGrant);

    sealed record Groups(CatDim Dim, Dictionary<string, Dictionary<int, Member>> Map);

    static VerbSpace? VerbOf(IntentLearner l, string verb) => l.Omega.Verbs.Find(v => v.Verb == verb);

    static Groups GroupsOf(IntentLearner l, D spec)
    {
        var verb = (string)spec["verb"]!;
        var path = (string)spec["path"]!;
        var vs = VerbOf(l, verb) ?? throw new ArgumentException("classifier: no verb " + verb + " in Ω");
        int k = vs.Dims.FindIndex(d => d.Path == path);
        if (k < 0 || vs.Dims[k] is not CatDim dim) throw new ArgumentException("classifier: " + verb + " has no categorical dimension " + path);
        var groups = new Dictionary<string, Dictionary<int, Member>>();
        foreach (var c in l.Cells())
        {
            if (c.Verb != verb) continue;
            var key = new System.Text.StringBuilder();
            for (int i = 0; i < c.Cell.Length; i++) if (i != k) key.Append(c.Cell[i]).Append(',');
            if (!groups.TryGetValue(key.ToString(), out var g)) groups[key.ToString()] = g = new Dictionary<int, Member>();
            g[c.Cell[k]] = new Member(c.Cell, c.P, c.Mass, c.Harm, c.InGrant);
        }
        return new Groups(dim, groups);
    }

    static double Gbar(D spec, CatDim dim, int pred, int truth)
    {
        var pv = dim.Values[pred];
        var tv = dim.Values[truth];
        if (pv.Kind != "exact") return 0;
        var cal = Obj(spec.GetValueOrDefault("cal"));
        var labels = Arr(cal.GetValueOrDefault("labels"));
        int pi = labels.FindIndex(x => x is string s && s == pv.Value);
        if (pi < 0) return 0;
        int ti = tv.Kind == "exact" ? labels.FindIndex(x => x is string s && s == tv.Value) : -1;
        if (ti < 0) return 1;
        return Dbl(Arr(Arr(cal.GetValueOrDefault("gammaBar"))[ti])[pi]);
    }

    static List<int> Admitted(Dictionary<int, Member> g) => g.Where(e => e.Value.InGrant).Select(e => e.Key).ToList();

    static double SetError(D spec, CatDim dim, List<int> a, int t)
    {
        double s = 0;
        foreach (int p in a) s = s + Gbar(spec, dim, p, t);
        return Math.Min(1, s);
    }

    /// <summary>R-hat of the learner's grant with classifier error folded in: {total, perVerb}. specs: [{verb, path, cal}].</summary>
    public static D ClassifierAwareResidualRisk(IntentLearner l, L specs)
    {
        var perVerb = new Dictionary<string, double>();
        var specOf = new Dictionary<string, object?>();
        foreach (var s in specs) specOf[(string)Obj(s)["verb"]!] = s;
        foreach (var c in l.Cells())
        {
            if (specOf.ContainsKey(c.Verb)) continue;
            double prev = perVerb.GetValueOrDefault(c.Verb, 0.0);
            perVerb[c.Verb] = c.InGrant ? prev + c.Mass * (1 - c.P) * c.Harm : prev;
        }
        foreach (var so in specs)
        {
            var spec = Obj(so);
            var gr = GroupsOf(l, spec);
            double r = 0;
            foreach (var g in gr.Map.Values)
            {
                var a = Admitted(g);
                foreach (var e in g)
                {
                    var mem = e.Value;
                    r += mem.Mass * (1 - mem.P) * mem.Harm * SetError(spec, gr.Dim, a, e.Key);
                }
            }
            perVerb[(string)spec["verb"]!] = r;
        }
        double total = 0;
        var pv = new D();
        foreach (var e in perVerb) { total += e.Value; pv[e.Key] = N(e.Value); }
        return new D { ["total"] = N(total), ["perVerb"] = pv };
    }

    /// <summary>The maximum-error gate: cells admitted on a classifier label that go to just-in-time consent, as [{verb, cell, flat}] sorted by flat index.</summary>
    public static List<D> ClassifierJitCells(IntentLearner l, D spec, double gammaMax)
    {
        var gr = GroupsOf(l, spec);
        var vs = VerbOf(l, (string)spec["verb"]!)!;
        var o = new List<(double Flat, D Item)>();
        foreach (var g in gr.Map.Values)
        {
            var a = Admitted(g);
            if (a.Count == 0) continue;
            double worst = 0;
            foreach (var e in g)
            {
                if (e.Value.InGrant || gr.Dim.Values[e.Key].Kind != "exact") continue;
                worst = Math.Max(worst, SetError(spec, gr.Dim, a, e.Key));
            }
            if (worst > gammaMax)
            {
                foreach (int p in a)
                {
                    var cell = g[p].Cell;
                    double flat = EncodeCell(vs, cell);
                    o.Add((flat, new D { ["verb"] = spec["verb"], ["cell"] = cell.Select(x => (object?)N(x)).ToList(), ["flat"] = N(flat) }));
                }
            }
        }
        return o.OrderBy(x => x.Flat).Select(x => x.Item).ToList();
    }
}
