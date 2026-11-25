using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.FheParts;

/// <summary>
/// The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the public
/// gate policy, the risk claim binding read from a signed action, and the plaintext reference verdict. Values are parsed JSON (maps, lists,
/// <see cref="Num"/>); a JavaScript number that is not finite is the fail-closed worst case, as in the reference. The BFV evaluation itself
/// is in the separate AtlasPca.Fhe assembly (Microsoft SEAL); the policy it takes is the typed form of the map built here.
/// </summary>
public static class FheRisk
{
    public const int PolyModulusDegree = 8192;
    public const long PlainModulus = 1_073_692_673L;
    public const long SignedBound = PlainModulus / 2;
    public const long DefaultScale = 1000;
    public const int RiskDim = 6;

    static readonly string[] InputFields = { "semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age" };

    static double Num_(object? o) => IntentJs.NumOf(o) ?? double.NaN;
    static bool Finite(double x) => double.IsFinite(x);
    static double Clamp01(double x) => x < 0 ? 0 : x > 1 ? 1 : x;
    static double Unit(double x, double worst) => Finite(x) ? Clamp01(x) : worst;
    static double Wt(double x) => Finite(x) && x > 0 ? x : 0;

    static D Obj(object? o) => o as D ?? throw new ArgumentException("not an object");
    static double Field(D? m, string k) => m is null ? throw new ArgumentException("cannot read a member of null") : Num_(m.GetValueOrDefault(k));

    /// <summary>[d, 1 - rev, bl, taint, 1 - conf, age], each through Unit with the worst case of the risk score.</summary>
    public static double[] TransformedInputs(D i) => new[]
    {
        Unit(Field(i, "semanticDistance"), 1),
        1 - Unit(Field(i, "reversibility"), 0),
        Unit(Field(i, "blastRadius"), 1),
        Unit(Field(i, "taint"), 1),
        1 - Unit(Field(i, "confidence"), 0),
        Unit(Field(i, "age"), 1),
    };

    /// <summary>The weight vector of the risk score in canonical order with its clamp applied.</summary>
    public static double[] WeightVector(D w) => new[]
    {
        Wt(Field(w, "alpha")), Wt(Field(w, "beta")), Wt(Field(w, "gamma")), Wt(Field(w, "delta")), Wt(Field(w, "epsilon")), Wt(Field(w, "zeta")),
    };

    /// <summary>JavaScript Math.round (ties toward +infinity), exact.</summary>
    static double JsRound(double x)
    {
        if (!Finite(x)) return x;
        var f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    static void RequireScale(double s)
    {
        if (!Finite(s) || s != Math.Round(s) || s <= 0) throw new ArgumentException("scale must be a positive integer");
    }

    /// <summary>round(x_i * scale) for each transformed input: the integer vector the agent encrypts.</summary>
    public static double[] QuantizeRiskInputs(D i, object? scale = null)
    {
        var s = scale is null ? DefaultScale : IntentJs.NumOf(scale) ?? double.NaN; // only a number is a scale (text and null are not)
        RequireScale(s);
        return TransformedInputs(i).Select(t => JsRound(t * s)).ToArray();
    }

    /// <summary>A JSON number for a JavaScript number; a non-finite value has none (the reference refuses it).</summary>
    internal static Num NumVal(double d) =>
        Finite(d) ? (Num)IntentJs.Normalize(d)! : throw new ArgumentException("not a finite number");

    static L NumVals(double[] a) => a.Select(x => (object?)NumVal(x)).ToList();

    /// <summary>
    /// The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights round(w_i S),
    /// kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could overflow the signed
    /// plain-modulus range (a wrap would silently corrupt the verdict).
    /// </summary>
    public static D FheRiskPolicy(D core, object? budget, object? scaleArg = null)
    {
        var scale = scaleArg is null ? DefaultScale : Num_(scaleArg);
        RequireScale(scale);
        var b = Num_(budget);
        if (!(Finite(b) && b >= 0)) throw new ArgumentException("budget must be finite and >= 0");
        var kappa = Field(core, "kappa");
        if (!(Finite(kappa) && kappa > 0)) throw new ArgumentException("policy.kappa must be finite and > 0");
        var w = WeightVector(Obj(core.GetValueOrDefault("weights")));
        var ws = new double[w.Length]; var kws = new double[w.Length];
        double sumW = 0, sumK = 0;
        for (int i = 0; i < w.Length; i++)
        {
            ws[i] = JsRound(w[i] * scale);
            kws[i] = JsRound(kappa * w[i] * scale);
            sumW += ws[i]; sumK += kws[i];
        }
        var budgetScaled = JsRound(b * scale * scale);
        var maxAbs = Math.Max(Math.Max(sumW * scale, sumK * scale), budgetScaled);
        if (maxAbs >= SignedBound)
            throw new ArgumentException($"policy/scale overflow the plain modulus: max |value| {maxAbs} must be < SignedBound {SignedBound}. Lower the scale or the weights/budget.");
        return new D
        {
            ["scale"] = NumVal(scale), ["dim"] = IntentJs.OfLong(RiskDim), ["weightsScaled"] = NumVals(ws),
            ["kappaWeightsScaled"] = NumVals(kws), ["budgetScaled"] = NumVal(budgetScaled), ["kappa"] = NumVal(kappa),
        };
    }

    /// <summary>The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed).</summary>
    public static D RiskInputsFromPCActn(D p)
    {
        var src = Obj(Obj(p.GetValueOrDefault("risk_claim")).GetValueOrDefault("inputs"));
        var o = new D();
        foreach (var k in InputFields)
        {
            var v = src.GetValueOrDefault(k);
            o[k] = IntentJs.IsNumber(v) ? v : double.NaN;
        }
        return o;
    }

    /// <summary>The replay binding of a signed action: audience, action digest, counter and the optional nonce.</summary>
    public static D BindingFromPCActn(D p)
    {
        var m = new D { ["aud"] = p.GetValueOrDefault("aud"), ["actionRef"] = Obj(p.GetValueOrDefault("action")).GetValueOrDefault("params_digest"), ["counter"] = p.GetValueOrDefault("counter") };
        if (p.ContainsKey("nonce")) m["nonce"] = p["nonce"];
        return m;
    }

    /// <summary>The plaintext reference verdict: r = risk score, admit iff kappa-cost(r) &lt;= budget. Returns {r, admit}.</summary>
    public static D PlaintextVerdict(D inputs, D core, object? budget)
    {
        var w = Obj(core.GetValueOrDefault("weights"));
        var r = Clamp01(Wt(Field(w, "alpha")) * Unit(Field(inputs, "semanticDistance"), 1)
            + Wt(Field(w, "beta")) * (1 - Unit(Field(inputs, "reversibility"), 0))
            + Wt(Field(w, "gamma")) * Unit(Field(inputs, "blastRadius"), 1)
            + Wt(Field(w, "delta")) * Unit(Field(inputs, "taint"), 1)
            + Wt(Field(w, "epsilon")) * (1 - Unit(Field(inputs, "confidence"), 0))
            + Wt(Field(w, "zeta")) * Unit(Field(inputs, "age"), 1));
        var kappa = Field(core, "kappa");
        var cost = (Finite(kappa) && kappa > 0 ? kappa : 0) * Clamp01(Finite(r) ? r : 1);
        return new D { ["r"] = NumVal(r), ["admit"] = double.IsFinite(Num_(budget)) && cost <= Num_(budget) };
    }
}
