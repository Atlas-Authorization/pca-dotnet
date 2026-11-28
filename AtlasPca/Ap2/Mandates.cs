// AP2 mandate vocabulary: currency minor units and the well-formedness checks of open / closed payment and checkout mandates.
using System.Numerics;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

public static partial class Ap2
{
    public const string VctCheckout = "mandate.checkout.1";
    public const string VctCheckoutOpen = "mandate.checkout.open.1";
    public const string VctPayment = "mandate.payment.1";
    public const string VctPaymentOpen = "mandate.payment.open.1";
    public const string PcaClaim = "x_pca";
    public const string Ap2Commit = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
    public const int PcaBindingVersion = 1;
    public static IReadOnlyList<string> Frequencies => new[] { "ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY" };
    public static IReadOnlyList<string> TypTerminal => new[] { "kb+sd-jwt", "kb-sd-jwt" };
    public static IReadOnlyList<string> TypIntermediate => new[] { "kb+sd-jwt+kb", "kb-sd-jwt+kb" };

    static readonly HashSet<string> ZeroDecimal = new() { "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF" };
    static readonly HashSet<string> ThreeDecimal = new() { "BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND" };
    static readonly HashSet<string> FourDecimal = new() { "CLF", "UYW" };

    /// <summary>Decimal places of an ISO 4217 alpha-3 currency (0, 2, 3 or 4); throws otherwise.</summary>
    public static int CurrencyExponent(object? currency)
    {
        // the reference tests the regular expression on String(currency)
        var s = S(currency);
        if (s.Length != 3 || !s.All(c => c >= 'A' && c <= 'Z')) throw new Ap2Exception($"currency must be an ISO 4217 alpha-3 code, got {JsJson.Stringify(currency)}");
        if (currency is string c3)
        {
            if (ZeroDecimal.Contains(c3)) return 0;
            if (ThreeDecimal.Contains(c3)) return 3;
            if (FourDecimal.Contains(c3)) return 4;
        }
        return 2;
    }

    static readonly double[] Pow10 = { 1, 10, 100, 1000, 10000 };

    /// <summary>JavaScript <c>x.toFixed(f)</c> for a finite non-negative x below 1e21, from the exact binary value.</summary>
    static string ToFixed(double x, int f)
    {
        long bits = BitConverter.DoubleToInt64Bits(x);
        int exp = (int)((bits >> 52) & 0x7ff);
        long frac = bits & 0xfffffffffffffL;
        BigInteger mant = exp == 0 ? frac : frac | (1L << 52);
        int e2 = (exp == 0 ? 1 : exp) - 1075;
        BigInteger scale = BigInteger.Pow(10, f);
        BigInteger n;
        if (e2 >= 0) n = (mant << e2) * scale;
        else
        {
            var den = BigInteger.One << -e2;
            n = (2 * mant * scale + den) / (2 * den); // round half up
        }
        var digits = n.ToString().PadLeft(f + 1, '0');
        return f == 0 ? digits : digits[..^f] + "." + digits[^f..];
    }

    /// <summary>A major-unit amount as integer minor units; throws unless it is exactly representable.</summary>
    public static object? ToMinorUnits(object? major, object? currency)
    {
        var e = CurrencyExponent(currency);
        if (JsX.NumOf(major) is not double m || !double.IsFinite(m) || m < 0) throw new Ap2Exception($"amount must be a finite non-negative number, got {S(major)}");
        if (m >= 1e21) throw new Ap2Exception($"amount {S(major)} is outside the safe integer range in minor units");
        var fixedText = ToFixed(m, e);
        if (double.Parse(fixedText, System.Globalization.CultureInfo.InvariantCulture) != m) throw new Ap2Exception($"amount {S(major)} is not exactly representable in {S(currency)} minor units");
        var minor = double.Parse(fixedText.Replace(".", ""), System.Globalization.CultureInfo.InvariantCulture);
        if (minor > 9007199254740991.0) throw new Ap2Exception($"amount {S(major)} is outside the safe integer range in minor units");
        return Num_(minor);
    }

    /// <summary>Integer minor units as a major-unit number.</summary>
    public static object? FromMinorUnits(object? minor, object? currency)
    {
        var e = CurrencyExponent(currency);
        if (!IntentJs.IsInt(minor) || Dbl(minor) < 0) throw new Ap2Exception($"minor-unit amount must be a non-negative safe integer, got {S(minor)}");
        return Num_(Dbl(minor) / Pow10[e]);
    }

    // ===== well-formedness =====

    static List<string> MerchantProblems(object? v, string at)
    {
        if (v is not D o) return new() { $"{at}: not an object" };
        var p = new List<string>();
        if (!IsNonEmptyStr(G(o, "id"))) p.Add($"{at}.id: required string");
        if (!IsNonEmptyStr(G(o, "name"))) p.Add($"{at}.name: required string");
        if (!IsUndef(G(o, "website")) && !IsStr(G(o, "website"))) p.Add($"{at}.website: must be a string");
        return p;
    }

    static List<string> AmountProblems(object? v, string at)
    {
        if (v is not D o) return new() { $"{at}: not an object" };
        var p = new List<string>();
        if (!IsNonNegInt(G(o, "amount"))) p.Add($"{at}.amount: must be a non-negative integer (minor units)");
        if (!IsUpper3(G(o, "currency"))) p.Add($"{at}.currency: must be an ISO 4217 alpha-3 code");
        return p;
    }

    static List<string> InstrumentProblems(object? v, string at)
    {
        if (v is not D o) return new() { $"{at}: not an object" };
        var p = new List<string>();
        if (!IsNonEmptyStr(G(o, "id"))) p.Add($"{at}.id: required string");
        if (!IsNonEmptyStr(G(o, "type"))) p.Add($"{at}.type: required string");
        if (!IsUndef(G(o, "description")) && !IsStr(G(o, "description"))) p.Add($"{at}.description: must be a string");
        return p;
    }

    static List<string> PispProblems(object? v, string at)
    {
        if (v is not D o) return new() { $"{at}: not an object" };
        return new[] { "legal_name", "brand_name", "domain_name" }.Where(k => !IsNonEmptyStr(G(o, k))).Select(k => $"{at}.{k}: required string").ToList();
    }

    static List<string> TimeProblems(D v)
    {
        var p = new List<string>();
        foreach (var k in new[] { "iat", "exp" })
            if (!IsUndef(G(v, k)) && !IsNonNegInt(G(v, k))) p.Add($"{k}: must be an integer epoch-seconds");
        return p;
    }

    static List<string> CnfProblems(object? v)
    {
        if (v is not D o || G(o, "jwk") is not D jwk) return new() { "cnf: must be { jwk }" };
        try { AssertP256Jwk(jwk, "cnf.jwk"); return new(); }
        catch (Ap2Exception e) { return new() { e.Message }; }
    }

    static List<string> PcaClaimProblems(D v) => !IsUndef(G(v, PcaClaim)) && !IsObject(G(v, PcaClaim)) ? new() { $"{PcaClaim}: must be an object" } : new();

    static List<string> ListProblems(object? v, string at, Func<object?, string, List<string>> each)
    {
        if (v is not L l) return new() { $"{at}: must be an array" };
        var o = new List<string>();
        for (int i = 0; i < l.Count; i++) o.AddRange(each(l[i], $"{at}[{i}]"));
        return o;
    }

    static List<string> PaymentConstraintProblems(object? c, string at)
    {
        if (c is not D o || G(o, "type") is not string type) return new() { $"{at}: constraint must be an object with a string type" };
        var p = new List<string>();
        switch (type)
        {
            case "payment.agent_recurrence":
                if (G(o, "frequency") is not string fr || !Frequencies.Contains(fr)) p.Add($"{at}.frequency: not a known frequency");
                if (!IsUndef(G(o, "max_occurrences")) && !(IsInt(G(o, "max_occurrences")) && Dbl(G(o, "max_occurrences")) > 0)) p.Add($"{at}.max_occurrences: must be a positive integer");
                return p;
            case "payment.allowed_payees": return ListProblems(G(o, "allowed"), $"{at}.allowed", MerchantProblems);
            case "payment.allowed_payment_instruments": return ListProblems(G(o, "allowed"), $"{at}.allowed", InstrumentProblems);
            case "payment.allowed_pisps": return ListProblems(G(o, "allowed"), $"{at}.allowed", PispProblems);
            case "payment.amount_range":
                if (!IsUpper3(G(o, "currency"))) p.Add($"{at}.currency: must be an ISO 4217 alpha-3 code");
                if (!IsNonNegInt(G(o, "max"))) p.Add($"{at}.max: must be a non-negative integer (minor units)");
                if (!IsUndef(G(o, "min")) && !IsNonNegInt(G(o, "min"))) p.Add($"{at}.min: must be a non-negative integer (minor units)");
                if (IsInt(G(o, "max")) && IsInt(G(o, "min")) && Dbl(G(o, "min")) > Dbl(G(o, "max"))) p.Add($"{at}: min exceeds max");
                return p;
            case "payment.budget":
                if (!IsUpper3(G(o, "currency"))) p.Add($"{at}.currency: must be an ISO 4217 alpha-3 code");
                if (JsX.NumOf(G(o, "max")) is not double mx || !double.IsFinite(mx) || mx < 0) p.Add($"{at}.max: must be a non-negative number (major units)");
                return p;
            case "payment.execution_date":
                return new[] { "not_before", "not_after" }.Where(k => !IsUndef(G(o, k)) && !IsStr(G(o, k))).Select(k => $"{at}.{k}: must be a string").ToList();
            case "payment.reference":
                return IsNonEmptyStr(G(o, "conditional_transaction_id")) ? new() : new() { $"{at}.conditional_transaction_id: required string" };
            default:
                return new() { $"{at}: unknown constraint type {type}" };
        }
    }

    static List<string> CheckoutConstraintProblems(object? c, string at)
    {
        if (c is not D o || G(o, "type") is not string type) return new() { $"{at}: constraint must be an object with a string type" };
        if (type == "checkout.allowed_merchants") return ListProblems(G(o, "allowed"), $"{at}.allowed", MerchantProblems);
        if (type == "checkout.line_items")
        {
            if (G(o, "items") is not L items || items.Count == 0) return new() { $"{at}.items: must be a non-empty array" };
            var res = new List<string>();
            for (int i = 0; i < items.Count; i++)
            {
                var a = $"{at}.items[{i}]";
                if (items[i] is not D it) { res.Add($"{a}: not an object"); continue; }
                if (!IsNonEmptyStr(G(it, "id"))) res.Add($"{a}.id: required string");
                if (!IsInt(G(it, "quantity")) || Dbl(G(it, "quantity")) <= 0) res.Add($"{a}.quantity: must be a positive integer");
                res.AddRange(ListProblems(G(it, "acceptable_items"), $"{a}.acceptable_items", (x, ax) =>
                    x is not D xo ? new() { $"{ax}: not an object" } : new[] { "id", "title" }.Where(k => !IsNonEmptyStr(G(xo, k))).Select(k => $"{ax}.{k}: required string").ToList()));
            }
            return res;
        }
        return new() { $"{at}: unknown constraint type {type}" };
    }

    static List<string> VctProblem(D v, string want) => JsX.StrictEq(G(v, "vct"), want) ? new() : new() { $"vct: must be {want}" };

    public static List<string> OpenPaymentMandateProblems(object? v)
    {
        if (v is not D o) return new() { "mandate: not an object" };
        var p = new List<string>();
        p.AddRange(VctProblem(o, VctPaymentOpen)); p.AddRange(TimeProblems(o)); p.AddRange(CnfProblems(G(o, "cnf"))); p.AddRange(PcaClaimProblems(o));
        p.AddRange(ListProblems(G(o, "constraints"), "constraints", PaymentConstraintProblems));
        if (G(o, "constraints") is L cs && !cs.Any(c => c is D cd && JsX.StrictEq(G(cd, "type"), "payment.reference"))) p.Add("constraints: must contain a payment.reference constraint");
        if (!IsUndef(G(o, "payee"))) p.AddRange(MerchantProblems(G(o, "payee"), "payee"));
        if (!IsUndef(G(o, "payment_amount"))) p.AddRange(AmountProblems(G(o, "payment_amount"), "payment_amount"));
        if (!IsUndef(G(o, "payment_instrument"))) p.AddRange(InstrumentProblems(G(o, "payment_instrument"), "payment_instrument"));
        if (!IsUndef(G(o, "pisp"))) p.AddRange(PispProblems(G(o, "pisp"), "pisp"));
        if (!IsUndef(G(o, "execution_date")) && !IsStr(G(o, "execution_date"))) p.Add("execution_date: must be a string");
        if (!IsUndef(G(o, "risk_data")) && !IsObject(G(o, "risk_data"))) p.Add("risk_data: must be an object");
        return p;
    }

    public static List<string> PaymentMandateProblems(object? v)
    {
        if (v is not D o) return new() { "mandate: not an object" };
        var p = new List<string>();
        p.AddRange(VctProblem(o, VctPayment)); p.AddRange(TimeProblems(o)); p.AddRange(PcaClaimProblems(o));
        if (!IsNonEmptyStr(G(o, "transaction_id"))) p.Add("transaction_id: required string");
        p.AddRange(MerchantProblems(G(o, "payee"), "payee")); p.AddRange(AmountProblems(G(o, "payment_amount"), "payment_amount")); p.AddRange(InstrumentProblems(G(o, "payment_instrument"), "payment_instrument"));
        if (!IsUndef(G(o, "pisp"))) p.AddRange(PispProblems(G(o, "pisp"), "pisp"));
        if (!IsUndef(G(o, "execution_date")) && !IsStr(G(o, "execution_date"))) p.Add("execution_date: must be a string");
        if (!IsUndef(G(o, "risk_data")) && !IsObject(G(o, "risk_data"))) p.Add("risk_data: must be an object");
        return p;
    }

    public static List<string> OpenCheckoutMandateProblems(object? v)
    {
        if (v is not D o) return new() { "mandate: not an object" };
        var p = new List<string>();
        p.AddRange(VctProblem(o, VctCheckoutOpen)); p.AddRange(TimeProblems(o)); p.AddRange(CnfProblems(G(o, "cnf"))); p.AddRange(PcaClaimProblems(o));
        p.AddRange(ListProblems(G(o, "constraints"), "constraints", CheckoutConstraintProblems));
        if (G(o, "constraints") is L cs && !cs.Any(c => c is D cd && JsX.StrictEq(G(cd, "type"), "checkout.line_items"))) p.Add("constraints: must contain a checkout.line_items constraint");
        return p;
    }

    public static List<string> CheckoutMandateProblems(object? v)
    {
        if (v is not D o) return new() { "mandate: not an object" };
        var p = new List<string>();
        p.AddRange(VctProblem(o, VctCheckout)); p.AddRange(TimeProblems(o)); p.AddRange(PcaClaimProblems(o));
        if (!IsNonEmptyStr(G(o, "checkout_jwt"))) p.Add("checkout_jwt: required string");
        if (!IsNonEmptyStr(G(o, "checkout_hash"))) p.Add("checkout_hash: required string");
        return p;
    }

    /// <summary>Returns <paramref name="v"/> when <paramref name="problems"/> finds none, else throws with every problem.</summary>
    public static object? AssertValid(object? v, Func<object?, List<string>> problems, string what)
    {
        var p = problems(v);
        if (p.Count > 0) throw new Ap2Exception($"{what}: {string.Join("; ", p)}");
        return v;
    }
}
