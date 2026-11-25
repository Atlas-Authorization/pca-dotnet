// AP2 mandates bound to PCA mandate terms: the open-mandate constraints a PCA payment mandate implies, the x_pca claim, the exact budget.max
// representation, risk ratio and binding nonce, and open mandates issued from PCA terms. A PCA payment mandate is the JSON object
// <c>{grant, terms}</c>; terms are <c>{currency, perTransactionCap, cumulativeCap, merchants, categories, maxTransactionsPerPeriod?, periodEnd?}</c>.
using System.Text;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

public static partial class Ap2
{
    static double MinorTerm(object? v, string name)
    {
        if (!IntentJs.IsNonNeg(v)) throw new Ap2Exception($"PCA term {name} must be a non-negative integer in minor units, got {S(v)}");
        return Dbl(v);
    }

    /// <summary>JSON.parse(JSON.stringify(v)): the value as plain JSON; undefined throws.</summary>
    static object? ToJson(object? v)
    {
        if (IsUndef(v)) throw new Ap2Exception("\"undefined\" is not valid JSON");
        return Pca.ParseJson(JsJson.Stringify(v));
    }

    /// <summary>The <c>x_pca</c> claim of an open mandate: <c>{v, grant, terms}</c>.</summary>
    public static D PcaOpenClaim(object? mandate)
        => new() { ["v"] = N(PcaBindingVersion), ["grant"] = ToJson(G(mandate, "grant")), ["terms"] = ToJson(G(mandate, "terms")) };

    static double OpenExpiry(object? terms, D o)
    {
        var pe = G(terms, "periodEnd");
        double? periodEnd = !IsUndef(pe) ? Math.Floor(JsJson.ToJsNumber(pe) / 1000) : null;
        var expO = Nn(G(o, "exp"), null);
        double? exp = expO != null ? JsJson.ToJsNumber(expO) : periodEnd;
        if (exp == null) throw new Ap2Exception("exp is required when the PCA terms have no period end");
        if (periodEnd != null && exp > periodEnd) throw new Ap2Exception("exp must not exceed the PCA period end");
        return exp.Value;
    }

    static L MerchantsFor(object? terms, object? merchants)
    {
        var ids = G(terms, "merchants") as L ?? throw JsX.TypeError("terms.merchants.map is not a function");
        var list = merchants as L ?? throw JsX.TypeError("merchants.find is not a function");
        return ids.Select(id =>
        {
            var m = list.FirstOrDefault(x => JsX.StrictEq(G(x, "id"), id));
            return m ?? throw new Ap2Exception($"no merchant descriptor supplied for PCA merchant {S(id)}");
        }).ToList();
    }

    static double NextUp(double x) => BitConverter.Int64BitsToDouble(BitConverter.DoubleToInt64Bits(x) + 1);

    /// <summary>The largest exact <c>payment.budget.max</c> (major units) for a cumulative cap in minor units, or a throw when none exists.</summary>
    public static object? Ap2BudgetMax(object? capMinor, object? currency)
    {
        var cap = MinorTerm(capMinor, "cumulativeCap");
        var e = CurrencyExponent(currency);
        double sdkTarget = e <= 2 ? cap : Math.Floor(cap / Pow10[e - 2]);
        double d = cap / Pow10[Math.Max(e, 2)];
        for (int i = 0; i < 8 && d > 0 && Math.Truncate(d * 100) < sdkTarget; i++) d = NextUp(d);
        if (Math.Truncate(d * 100) != sdkTarget || JsRound(d * Pow10[e]) > cap) throw new Ap2Exception($"cumulativeCap {JsX.JsNumString(cap)} {S(currency)} has no exact AP2 budget.max representation");
        return Num_(d);
    }

    /// <summary>How a verifier reads <c>budget.max</c>: <c>{sdk: trunc(max*100), major: round(max*10^exponent)}</c>.</summary>
    public static D Ap2BudgetReads(object? max, object? currency)
    {
        var e = CurrencyExponent(currency);
        if (JsX.NumOf(max) is not double m || !double.IsFinite(m) || m < 0) throw new Ap2Exception($"budget.max must be a finite non-negative number, got {S(max)}");
        return new D { ["sdk"] = Num_(Math.Truncate(m * 100)), ["major"] = Num_(JsRound(m * Pow10[e])) };
    }

    /// <summary>The open payment constraints a PCA payment mandate's terms imply.</summary>
    public static L PaymentConstraintsFromTerms(object? terms, object? merchants, string checkoutReference)
    {
        var cur = G(terms, "currency");
        var perTx = MinorTerm(G(terms, "perTransactionCap"), "perTransactionCap");
        var budgetMax = Ap2BudgetMax(G(terms, "cumulativeCap"), cur);
        var rec = new D { ["type"] = "payment.agent_recurrence", ["frequency"] = "ON_DEMAND" };
        var maxTx = G(terms, "maxTransactionsPerPeriod");
        if (!IsUndef(maxTx)) rec["max_occurrences"] = maxTx;
        return new L
        {
            new D { ["type"] = "payment.amount_range", ["currency"] = cur, ["min"] = N(0), ["max"] = Num_(perTx) },
            new D { ["type"] = "payment.allowed_payees", ["allowed"] = MerchantsFor(terms, merchants) },
            new D { ["type"] = "payment.reference", ["conditional_transaction_id"] = checkoutReference },
            new D { ["type"] = "payment.budget", ["currency"] = cur, ["max"] = budgetMax },
            rec,
        };
    }

    /// <summary>Issue an open payment mandate from a PCA payment mandate. <paramref name="o"/>: agentJwk, merchants (descriptors), iat, exp?, checkoutReference.</summary>
    public static string OpenPaymentMandateFromPca(object? mandate, D o, MandateIssuer issuer, Func<string>? salt = null)
    {
        var exp = OpenExpiry(G(mandate, "terms"), o);
        var pca = PcaOpenClaim(mandate);
        var constraints = PaymentConstraintsFromTerms(G(mandate, "terms"), G(o, "merchants"), (string)G(o, "checkoutReference")!);
        var input = new D { ["agentJwk"] = G(o, "agentJwk"), ["iat"] = G(o, "iat"), ["exp"] = Num_(exp), ["pca"] = pca, ["constraints"] = constraints };
        return IssueOpenPaymentMandate(input, issuer, salt);
    }

    /// <summary>Issue an open checkout mandate from a PCA payment mandate. <paramref name="o"/>: agentJwk, merchants (descriptors), iat, exp?, lineItems.</summary>
    public static string OpenCheckoutMandateFromPca(object? mandate, D o, MandateIssuer issuer, Func<string>? salt = null)
    {
        var exp = OpenExpiry(G(mandate, "terms"), o);
        var pca = PcaOpenClaim(mandate);
        var constraints = new L
        {
            new D { ["type"] = "checkout.line_items", ["items"] = G(o, "lineItems") },
            new D { ["type"] = "checkout.allowed_merchants", ["allowed"] = MerchantsFor(G(mandate, "terms"), G(o, "merchants")) },
        };
        var input = new D { ["agentJwk"] = G(o, "agentJwk"), ["iat"] = G(o, "iat"), ["exp"] = Num_(exp), ["pca"] = pca, ["constraints"] = constraints };
        return IssueOpenCheckoutMandate(input, issuer, salt);
    }

    /// <summary>The nonce a PCActn carries to bind one AP2 transaction: <c>ap2:</c> + the canonical hash of <c>{v: 1, ...facts}</c>.</summary>
    public static string PcaBindingNonce(D facts)
    {
        var d = new D { ["v"] = N(PcaBindingVersion) };
        foreach (var kv in facts) d[kv.Key] = kv.Value;
        return "ap2:" + Pca.HashCanonical(d);
    }

    /// <summary>The charge's share of the per-transaction cap, rounded up to 12 decimals and clamped to [0, 1] (1 when the cap is not positive).</summary>
    public static object? RiskRatio(double amount, double cap)
    {
        double r = cap > 0 ? amount / cap : 1;
        return Num_(Math.Min(1, Math.Max(0, Math.Ceiling(r * 1e12 - 1e-6) / 1e12)));
    }

    /// <summary>Build the <c>x_pca</c> claim of a closed payment mandate: a PCActn authorising exactly this charge. <paramref name="input"/>:
    /// <c>{mandate, open, agentJwk, agentSecret (byte[] Ed25519 seed), audience, counter, transactionId, payee, amount: {amount, currency}, instrumentId,
    /// category?, now?}</c>; <paramref name="cosign"/> returns the threshold shares over the built PCActn for a charge that needs a human co-sign.</summary>
    public static D BuildPcaPaymentBinding(D input, Func<D, object?>? cosign = null)
    {
        var amountObj = G(input, "amount");
        var major = MinorTerm(G(amountObj, "amount"), "amount"); // the charge amount is integer minor units, as in the mandate
        var payee = G(input, "payee");
        var mandate = G(input, "mandate");
        var category = G(input, "category");
        var charge = new D { ["merchant"] = G(payee, "id"), ["amount"] = Num_(major), ["currency"] = G(amountObj, "currency") };
        if (!IsUndef(category)) charge["category"] = category;
        var facts = new D
        {
            ["transactionId"] = G(input, "transactionId"),
            ["payeeId"] = G(payee, "id"),
            ["amount"] = G(amountObj, "amount"),
            ["currency"] = G(amountObj, "currency"),
            ["instrumentId"] = G(input, "instrumentId"),
            ["openHash"] = SdHashOf(ParseSdJwtHop(G(input, "open"))),
            ["agentJkt"] = JwkThumbprint(G(input, "agentJwk")),
        };
        var risk = RiskRatio(major, Dbl(G(G(mandate, "terms"), "perTransactionCap")));
        var nodeId = "ap2:" + S(G(input, "transactionId"));
        var node = AtlasPca.Payments.Payments.ChargePlanNode(mandate, charge, nodeId);
        var prm = AtlasPca.Payments.Payments.ChargeParams(mandate, charge);
        var grant = G(mandate, "grant") as D ?? throw JsX.TypeError("cannot read a member of undefined");
        if (G(input, "agentSecret") is not byte[] secret) throw new Ap2Exception("agentSecret must be an Ed25519 seed");
        if (!Pca.SafeInt(G(input, "counter"), out var counter)) throw new Ap2Exception("counter must be a safe integer");
        using var signer = SuiteKey.Ed25519(EdKey.FromSeed(secret));
        var spec = new ActSpec
        {
            Grant = grant,
            Chain = new L { grant },
            Plan = Issue.CommitPlan(new[] { node }),
            NodeId = nodeId,
            Params = prm,
            Counter = counter,
            Signer = signer,
            Aud = G(input, "audience") as string ?? "",
            Nonce = PcaBindingNonce(facts),
            RiskClaim = new D { ["r"] = risk, ["inputs"] = new D(prm) { ["blastRadius"] = risk } },
        };
        var now = G(input, "now");
        if (!IsUndef(now) && Pca.SafeInt(now, out var iat)) spec.Iat = iat;
        var built = Issue.BuildPCActn(spec);
        var pcactn = cosign == null ? built : new D(built) { ["threshold"] = cosign(built) };
        var outCharge = new D { ["amount"] = Num_(major), ["currency"] = G(amountObj, "currency") };
        if (!IsUndef(category)) outCharge["category"] = category;
        return new D { ["v"] = N(PcaBindingVersion), ["charge"] = outCharge, ["pcactn"] = ToJson(pcactn) };
    }
}
