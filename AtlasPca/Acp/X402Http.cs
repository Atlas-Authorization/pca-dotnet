// x402 v2 HTTP transport: three headers, each the base64 of a JSON object. PAYMENT-REQUIRED (see X402V2.cs), PAYMENT-SIGNATURE (client to
// server, the PaymentPayload) and PAYMENT-RESPONSE (server to client, the SettlementResponse). No I/O.
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Acp;

public static partial class Acp
{
    public const string X402PaymentSignatureHeader = "PAYMENT-SIGNATURE";
    public const string X402PaymentResponseHeader = "PAYMENT-RESPONSE";
    public const int X402StatusPaymentRequired = 402;
    public const int X402StatusMalformed = 400;
    public const int X402StatusFailed = 402;
    public const int X402StatusInternalError = 500;
    public const int X402StatusSettled = 200;

    /// <summary>Problems with a v2 <c>PaymentPayload</c> (empty = valid).</summary>
    public static List<string> PaymentPayloadV2Problems(object? p)
    {
        if (p is not D o) return new() { "PaymentPayload must be an object" };
        var r = new List<string>();
        if (!JsX.StrictEq(G(o, "x402Version"), N(2))) r.Add("x402Version must be 2");
        if (!IsUndef(G(o, "resource"))) r.AddRange(ResourceInfoProblems(G(o, "resource")));
        r.AddRange(RequirementV2Problems(G(o, "accepted")).Select(m => "accepted." + m));
        if (!IsObj(G(o, "payload"))) r.Add("payload must be an object");
        if (!IsUndef(G(o, "extensions")) && !IsObj(G(o, "extensions"))) r.Add("extensions must be an object");
        return r;
    }

    /// <summary>Problems with a <c>SettlementResponse</c> (empty = valid). A success must not carry an errorReason; a failure must.</summary>
    public static List<string> SettlementResponseProblems(object? v)
    {
        if (v is not D o) return new() { "SettlementResponse must be an object" };
        var r = new List<string>();
        var success = G(o, "success");
        if (success is not bool) r.Add("success must be a boolean");
        var tx = G(o, "transaction");
        if (tx is not string txs) r.Add("transaction must be a string");
        else if (success is true && txs.Length == 0) r.Add("a successful settlement needs a transaction");
        if (G(o, "network") is not string net || !Caip2.IsMatch(net)) r.Add("network must be a CAIP-2 identifier");
        var er = G(o, "errorReason");
        if (!IsUndef(er) && er is not string) r.Add("errorReason must be a string");
        if (success is true && !IsUndef(er)) r.Add("errorReason must be omitted on success");
        if (success is false && !(er is string ers && ers.Length > 0)) r.Add("errorReason is required on failure");
        if (!IsUndef(G(o, "payer")) && G(o, "payer") is not string) r.Add("payer must be a string");
        var amount = G(o, "amount");
        if (!IsUndef(amount) && !(amount is string a && DecimalAtomic.IsMatch(a))) r.Add("amount must be a decimal string of atomic units");
        if (!IsUndef(G(o, "extensions")) && !IsObj(G(o, "extensions"))) r.Add("extensions must be an object");
        return r;
    }

    static string EncodeHeader(object? obj, List<string> problems)
    {
        Throw(problems);
        return Base64Of(JsJson.Stringify(obj));
    }

    /// <summary>Encode a <c>PaymentPayload</c> for the PAYMENT-SIGNATURE request header (validates first; throws).</summary>
    public static string EncodePaymentSignatureHeader(object? p) => EncodeHeader(p, PaymentPayloadV2Problems(p));

    static D DecodeSignature(object? value)
    {
        var doc = DecodeHeaderJson(value, "PAYMENT-SIGNATURE");
        Throw(PaymentPayloadV2Problems(doc));
        return (D)doc!;
    }

    /// <summary>Decode and validate a PAYMENT-SIGNATURE header value; throws <see cref="AcpTypeException"/>.</summary>
    public static D DecodePaymentSignatureHeader(string value) => DecodeSignature(value);

    /// <summary>Encode a <c>SettlementResponse</c> for the PAYMENT-RESPONSE response header.</summary>
    public static string EncodePaymentResponseHeader(object? r) => EncodeHeader(r, SettlementResponseProblems(r));

    /// <summary>Decode and validate a PAYMENT-RESPONSE header value.</summary>
    public static D DecodePaymentResponseHeader(string value)
    {
        var doc = DecodeHeaderJson(value, "PAYMENT-RESPONSE");
        Throw(SettlementResponseProblems(doc));
        return (D)doc!;
    }

    /// <summary>Server side: read the client's PAYMENT-SIGNATURE header from a header map (case-insensitive name, first value of a list). A missing
    /// header is 402; a present but undecodable or invalid one is 400. Returns <c>{ok:true, payload}</c> or <c>{ok:false, status, reason}</c>.</summary>
    public static D ReadPaymentSignature(D headers)
    {
        object? v = JsX.Undef;
        foreach (var k in IntentJs.JsKeys(headers.Keys))
        {
            if (JsLower(k) != "payment-signature") continue;
            var raw = headers[k];
            v = raw is L l ? (l.Count > 0 ? l[0] : JsX.Undef) : raw;
            break;
        }
        if (IsUndef(v) || v is "") return new D { ["ok"] = false, ["status"] = N(X402StatusPaymentRequired), ["reason"] = "PAYMENT-SIGNATURE header is required" };
        try { return new D { ["ok"] = true, ["payload"] = DecodeSignature(v) }; }
        catch (AcpTypeException e) { return new D { ["ok"] = false, ["status"] = N(X402StatusMalformed), ["reason"] = e.Message }; }
    }

    /// <summary>Server side: the status and PAYMENT-RESPONSE header for a settlement outcome <c>{settled, transaction?, payer?, amount?, reason?}</c>;
    /// <paramref name="network"/> is the CAIP-2 id. Throws if the response would be invalid.</summary>
    public static D X402SettlementResponse(D outcome, object? network)
    {
        bool settled = JsX.Truthy(G(outcome, "settled"));
        var body = new D();
        if (settled)
        {
            body["success"] = true;
            SetDefined(body, "transaction", G(outcome, "transaction"));
            body["network"] = network;
            SetDefined(body, "payer", G(outcome, "payer"));
            SetDefined(body, "amount", G(outcome, "amount"));
        }
        else
        {
            body["success"] = false;
            SetDefined(body, "errorReason", G(outcome, "reason"));
            body["transaction"] = Nn(G(outcome, "transaction"), "");
            body["network"] = network;
            SetDefined(body, "payer", G(outcome, "payer"));
        }
        return new D
        {
            ["status"] = N(settled ? X402StatusSettled : X402StatusFailed),
            ["headers"] = new D { [X402PaymentResponseHeader] = EncodePaymentResponseHeader(body) },
        };
    }

    /// <summary>Client side: the request header to attach on the retry, from a payload built for an offered requirement.</summary>
    public static D X402PaymentSignatureHeaders(object? p) => new() { [X402PaymentSignatureHeader] = EncodePaymentSignatureHeader(p) };
}
