// AP2 settlement payloads: the x402 payment challenge and the Stripe shared-payment-token instruction a closed payment mandate maps to.
using System.Numerics;
using System.Text;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

public static partial class Ap2
{
    /// <summary>A minor-unit amount as an atomic-unit decimal string for a token with <paramref name="decimals"/> decimals (0..18); throws when it is
    /// not exactly expressible.</summary>
    public static string ToAtomicUnits(object? amount, object? decimals)
    {
        if (JsX.NumOf(decimals) is not double dd || !double.IsFinite(dd) || dd != Math.Floor(dd) || dd < 0 || dd > 18)
            throw new Ap2Exception($"x402: decimals must be an integer in 0..18, got {S(decimals)}");
        int dec = (int)dd;
        var a = G(amount, "amount");
        if (!IntentJs.IsNonNeg(a)) throw new Ap2Exception($"x402: amount {S(a)} cannot be expressed in atomic units with {dec} decimals");
        var exp = CurrencyExponent(G(amount, "currency"));
        var minor = new BigInteger(Dbl(a));
        if (dec >= exp) return (minor * BigInteger.Pow(10, dec - exp)).ToString();
        var div = BigInteger.Pow(10, exp - dec);
        if (!(minor % div).IsZero) throw new Ap2Exception($"x402: amount {S(a)} cannot be expressed in atomic units with {dec} decimals");
        return (minor / div).ToString();
    }

    static object? CtxGet(object? ctx, string k) => JsX.Opt(ctx, k);

    /// <summary>The x402 rail: the 402 challenge for a closed payment mandate. <paramref name="ctx"/>: resourceUrl?, payTo?, network?, asset?, decimals?, maxTimeoutSeconds?.</summary>
    public static D X402Settlement(object? payment, object? ctx = null)
    {
        var pa = G(payment, "payment_amount");
        var network = Nn(CtxGet(ctx, "network"), "base-sepolia");
        var req = new D { ["scheme"] = "exact", ["network"] = network };
        req["maxAmountRequired"] = ToAtomicUnits(pa, Nn(CtxGet(ctx, "decimals"), N(6)));
        req["resource"] = Nn(CtxGet(ctx, "resourceUrl"), "");
        req["description"] = $"AP2 payment mandate {S(G(payment, "transaction_id"))}";
        Put(req, "payTo", Nn(CtxGet(ctx, "payTo"), G(G(payment, "payee"), "id")));
        Put(req, "asset", Nn(CtxGet(ctx, "asset"), G(pa, "currency")));
        req["mimeType"] = "application/json";
        req["maxTimeoutSeconds"] = Nn(CtxGet(ctx, "maxTimeoutSeconds"), N(60));
        var xp = new D { ["x402Version"] = N(1), ["scheme"] = "exact", ["network"] = network };
        var inner = new D();
        Put(inner, "transactionId", G(payment, "transaction_id"));
        Put(inner, "amount", G(pa, "amount"));
        Put(inner, "currency", G(pa, "currency"));
        xp["payload"] = inner;
        var xPayment = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsJson.Stringify(xp)));
        var r = new D { ["rail"] = "x402", ["amount"] = pa };
        Put(r, "merchant", G(G(payment, "payee"), "id"));
        r["payload"] = new D
        {
            ["httpStatus"] = N(402), ["x402Version"] = N(1), ["error"] = "X-PAYMENT header is required",
            ["accepts"] = new L { req }, ["header"] = new D { ["X-PAYMENT"] = xPayment },
        };
        return r;
    }

    /// <summary>The Stripe shared-payment-token rail: the instruction for a closed payment mandate whose instrument is a shared payment token.</summary>
    public static D StripeSptSettlement(object? payment, object? ctx = null)
    {
        var pi = G(payment, "payment_instrument");
        if (!JsX.StrictEq(G(pi, "type"), "shared_payment_token")) throw new Ap2Exception($"stripe-spt: the payment instrument must be of type shared_payment_token, got {S(G(pi, "type"))}");
        var pa = G(payment, "payment_amount");
        var payload = new D();
        Put(payload, "shared_payment_token", G(pi, "id"));
        Put(payload, "amount", G(pa, "amount"));
        if (G(pa, "currency") is not string cur) throw JsX.TypeError("currency.toLowerCase is not a function");
        payload["currency"] = AtlasPca.Acp.Acp.JsLower(cur);
        var payTo = CtxGet(ctx, "payTo");
        if (Truthy(payTo)) payload["on_behalf_of"] = payTo;
        var r = new D { ["rail"] = "stripe-spt", ["amount"] = pa };
        Put(r, "merchant", G(G(payment, "payee"), "id"));
        r["payload"] = payload;
        return r;
    }
}
