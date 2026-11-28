// Opt-in, privacy-preserving population priors of the wallet (PCA Intent Layer v2): one vote per principal, cell and period; a central
// (epsilon, delta)-DP Gaussian release (sigma = L2 sensitivity * sqrt(2 ln(1.25/delta)) / epsilon, L2 sensitivity sqrt(2 * maxCells));
// local-DP randomized response with its debiasing; the mixture prior for the learner, and the mass it admits beyond the base prior.
// Randomness is an injected source; the default is the OS CSPRNG. Votes and releases are JSON trees with the reference's member names.
using System.Security.Cryptography;
using AtlasPca.IntentPkg;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

public sealed class PopulationAggregator
{
    public string SchemaDigest { get; }
    public object? Period { get; }
    readonly double _maxCells;
    readonly Func<double> _rand;
    readonly Dictionary<string, (double Yes, double Total)> _votes = new();
    readonly Dictionary<string, HashSet<string>> _perPrincipal = new();

    /// <summary>The cell cap per principal defaults to 32; it must be a positive integer.</summary>
    public PopulationAggregator(string schemaDigest, object? period, double? maxCellsPerPrincipal = null, Func<double>? rand = null)
    {
        if (!WalletCore.IsB64u32(schemaDigest)) throw new WalletException("PopulationAggregator: schemaDigest must be a canonical b64u digest");
        SchemaDigest = schemaDigest;
        Period = period;
        _maxCells = maxCellsPerPrincipal ?? 32;
        if (!(double.IsFinite(_maxCells) && _maxCells == Math.Floor(_maxCells) && _maxCells > 0)) throw new WalletException("PopulationAggregator: maxCellsPerPrincipal must be a positive integer");
        _rand = rand ?? (Func<double>)WalletPopulation.CryptoRand;
    }

    static D Refuse(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema or period.
    /// shortcut: a vote's cellKey must be a string (the reference accepts any value as a map key); upgrade if non-string keys must be tolerated.</summary>
    public D Contribute(D v)
    {
        if (!JsX.StrictEq(WalletCore.G(v, "schemaDigest"), SchemaDigest)) return Refuse("vote for another schema");
        if (!JsX.StrictEq(WalletCore.G(v, "period"), Period)) return Refuse("vote for another period");
        var y = WalletCore.G(v, "y");
        if (!(WalletCore.IsNum(y) && (WalletCore.Dn(y) == 0 || WalletCore.Dn(y) == 1))) return Refuse("y must be 0 or 1");
        if (!(WalletCore.G(v, "principal") is string principal && principal.Length > 0)) return Refuse("an accountable principal is required");
        var key = (string)WalletCore.G(v, "cellKey")!;
        var mine = _perPrincipal.TryGetValue(principal, out var s) ? s : new HashSet<string>();
        if (mine.Contains(key)) return Refuse("one vote per principal per cell per period (sensitivity 1)");
        if (mine.Count >= _maxCells) return Refuse($"at most {JsJson.NumberToString(_maxCells)} cells per principal per period");
        mine.Add(key);
        _perPrincipal[principal] = mine;
        var c = _votes.TryGetValue(key, out var cur) ? cur : (Yes: 0.0, Total: 0.0);
        _votes[key] = (c.Yes + WalletCore.Dn(y), c.Total + 1);
        return new D { ["ok"] = true };
    }

    /// <summary>The (epsilon, delta)-DP release. Cells whose noisy count is below <paramref name="minCount"/> are suppressed (q would be pure noise).</summary>
    public D Release(double epsilon, double delta, double? qMin = null, double? minCount = null)
    {
        double sensitivity = Math.Sqrt(2 * _maxCells);
        double sigma = WalletPopulation.GaussianSigma(epsilon, delta, sensitivity);
        double qm = qMin ?? 0.02;
        if (!(qm > 0 && qm < 0.5)) throw new WalletException("release: qMin must be in (0, 0.5)");
        double mc = minCount ?? 3 * sigma;
        var cells = new D();
        var keys = _votes.Keys.ToList();
        keys.Sort(StringComparer.Ordinal); // Array.prototype.sort: UTF-16 code unit order
        foreach (var key in keys)
        {
            var c = _votes[key];
            double yes = c.Yes + sigma * WalletPopulation.Gaussian(_rand);
            double total = c.Total + sigma * WalletPopulation.Gaussian(_rand);
            if (!(total >= mc)) continue;
            cells[key] = new D { ["q"] = WalletCore.N(Math.Min(1 - qm, Math.Max(qm, yes / total))), ["n"] = WalletCore.N(IntentMath.JsRound(total)) };
        }
        return new D
        {
            ["v"] = new Num("1"), ["kind"] = "pca-intent-population-prior", ["schema"] = SchemaDigest, ["period"] = Period, ["epsilon"] = WalletCore.N(epsilon),
            ["delta"] = WalletCore.N(delta), ["sigma"] = WalletCore.N(sigma), ["sensitivity"] = WalletCore.N(sensitivity), ["cells"] = cells,
        };
    }
}

public static class WalletPopulation
{
    public const string PopulationVoteDomain = "atlas-pca/intent-population-cell/v1";
    public const double BetaMax = 0.9;

    /// <summary>The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.</summary>
    public static string PopulationCellKey(string schemaDigest, IntentOmega.VerbSpace vs, IReadOnlyList<int> idx) =>
        Pca.HashCanonical(new D { ["d"] = PopulationVoteDomain, ["s"] = schemaDigest, ["v"] = vs.Verb, ["c"] = WalletCore.CoordsOfCell(vs, idx) });

    /// <summary>Uniform (0, 1) from 53 random bits of the OS CSPRNG.</summary>
    public static double CryptoRand()
    {
        var w = RandomNumberGenerator.GetBytes(8);
        uint hi = (uint)((w[0] << 24) | (w[1] << 16) | (w[2] << 8) | w[3]) >> 5;
        uint lo = (uint)((w[4] << 24) | (w[5] << 16) | (w[6] << 8) | w[7]) >> 6;
        return (hi * 67108864.0 + lo + 0.5) / 9007199254740992.0;
    }

    /// <summary>A standard normal draw (Box-Muller) from a uniform source.</summary>
    public static double Gaussian(Func<double> rand)
    {
        double u = rand();
        while (u <= 0) u = rand();
        double v = rand();
        return Math.Sqrt(-2 * IntentMath.Log(u)) * Math.Cos(2 * Math.PI * v);
    }

    /// <summary>Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1)).</summary>
    public static double GaussianSigma(double epsilon, double delta, double l2Sensitivity)
    {
        if (!(epsilon > 0 && epsilon < 1)) throw new WalletException("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)");
        if (!(delta > 0 && delta < 1)) throw new WalletException("gaussianSigma: delta must be in (0, 1)");
        if (!(l2Sensitivity > 0)) throw new WalletException("gaussianSigma: sensitivity must be > 0");
        return l2Sensitivity * Math.Sqrt(2 * IntentMath.Log(1.25 / delta)) / epsilon;
    }

    // ---- local DP ----

    public static double RrKeepProbability(double epsilon)
    {
        if (!(epsilon > 0 && double.IsFinite(epsilon))) throw new WalletException("randomized response: epsilon must be > 0");
        return IntentMath.Exp(epsilon) / (1 + IntentMath.Exp(epsilon));
    }

    /// <summary>epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y.</summary>
    public static int RandomizedResponse(int y, double epsilon, Func<double>? rand = null) => (rand ?? (Func<double>)CryptoRand)() < RrKeepProbability(epsilon) ? y : 1 - y;

    /// <summary>Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1).</summary>
    public static double DebiasRandomizedResponse(double yesReports, double total, double epsilon)
    {
        bool Int(double x) => double.IsFinite(x) && x == Math.Floor(x);
        if (!(Int(yesReports) && Int(total) && total > 0 && yesReports >= 0 && yesReports <= total)) throw new WalletException("debias: bad counts");
        double p = RrKeepProbability(epsilon);
        return (yesReports / total - (1 - p)) / (2 * p - 1);
    }

    // ---- the mixture prior ----

    sealed record Tables(List<int> Cells, List<double> Lq, List<double> Lnq);

    /// <summary>The learner's prior mixture for a release: weight(theta) = prod over the verb's released cells c of q_c^(c in theta) * (1 - q_c)^(c not in theta)
    /// (unreleased cells contribute the constant 1/2 and drop out), mixed with weight beta &lt;= BetaMax &lt; 1.</summary>
    public static IntentLearner.PriorMix PopulationPrior(D release, double beta)
    {
        if (!(beta >= 0 && beta <= BetaMax)) throw new WalletException($"populationPrior: beta must be in [0, {JsJson.NumberToString(BetaMax)}] (full support needs beta < 1)");
        var perVerb = new Dictionary<IntentOmega.VerbSpace, Tables>();
        Tables TablesOf(IntentOmega.VerbSpace vs)
        {
            if (perVerb.TryGetValue(vs, out var hit)) return hit;
            var t = new Tables(new List<int>(), new List<double>(), new List<double>());
            long n = (long)IntentOmega.VerbCellCount(vs);
            var cells = (D)release["cells"]!;
            var schema = (string)release["schema"]!;
            for (long c = 0; c < n; c++)
            {
                if (!cells.TryGetValue(PopulationCellKey(schema, vs, IntentOmega.DecodeCell(vs, c)), out var r) || r == null) continue;
                double q = WalletCore.Dn(WalletCore.G(r, "q"));
                t.Cells.Add((int)c);
                t.Lq.Add(IntentMath.Log(q));
                t.Lnq.Add(IntentMath.Log(1 - q));
            }
            perVerb[vs] = t;
            return t;
        }
        return new IntentLearner.PriorMix(beta, (vs, contains) =>
        {
            var t = TablesOf(vs);
            double lw = 0;
            for (int i = 0; i < t.Cells.Count; i++) lw += contains(t.Cells[i]) ? t.Lq[i] : t.Lnq[i];
            return IntentMath.Exp(lw);
        });
    }

    /// <summary>The mu-mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not without it, after the
    /// same observations. Zero at tau = 1 under noise-free answers.</summary>
    public static double PriorAdmittedPpm(IntentOmega.Omega omega, IntentLearner.LearnerOptions bas, IReadOnlyList<IntentLearner.Observation> observations, IntentLearner.PriorMix mix)
    {
        IntentLearner.LearnerOptions Copy(IntentLearner.PriorMix? pm) => new()
        {
            Eta = bas.Eta, EtaPos = bas.EtaPos, EtaNeg = bas.EtaNeg, Tau = bas.Tau, PriorMix = pm, NullMass = bas.NullMass, NullMassFn = bas.NullMassFn, Anchor = bas.Anchor,
            Anchors = bas.Anchors, Harm = bas.Harm, MaxHypotheses = bas.MaxHypotheses, MaxEnumeration = bas.MaxEnumeration, Strategy = bas.Strategy,
            HypothesisClass = bas.HypothesisClass, AgnosticSlack = bas.AgnosticSlack, Monotone = bas.Monotone,
        };
        var a = IntentLearner.Replay(omega, Copy(null), observations).Cells();
        var b = IntentLearner.Replay(omega, Copy(mix), observations).Cells();
        double mass = 0;
        for (int i = 0; i < b.Count; i++) if (b[i].InGrant && !a[i].InGrant) mass += b[i].Mass;
        return IntentMath.JsRound(mass * 1_000_000);
    }
}
