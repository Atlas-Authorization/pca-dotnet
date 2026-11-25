// x402 v2 alongside v1, negotiated (x402 core specification v2): PaymentRequired / PaymentRequirements / ResourceInfo validation, the
// base64 PAYMENT-REQUIRED header, version negotiation, accepted-requirement matching and payload normalization. No I/O.
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using AtlasPca.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Acp;

public static partial class Acp
{
    public const int X402Version1 = 1;
    public const int X402Version2 = 2;
    /// <summary>Versions this package can speak, newest first.</summary>
    public static IReadOnlyList<int> X402SupportedVersions => new[] { 2, 1 };
    public const string X402V2PaymentRequiredHeader = "PAYMENT-REQUIRED";

    static readonly Regex Caip2 = new(@"\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\z", RegexOptions.CultureInvariant);
    static readonly Regex DecimalAtomic = new(@"\A(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant);
    static readonly Regex Base64Header = new(@"\A[A-Za-z0-9+/]+={0,2}\z", RegexOptions.CultureInvariant);

    static bool AsciiPrintable(string s) => s.All(c => c >= 0x20 && c <= 0x7e);

    static bool AbsoluteHttp(object? u)
    {
        if (u is not string s) return false;
        var p = WhatwgUrl.TryParse(s)?.Protocol;
        return p == "https:" || p == "http:";
    }

    /// <summary>Problems with a <c>ResourceInfo</c> (empty = valid).</summary>
    public static List<string> ResourceInfoProblems(object? r)
    {
        if (r is not D o) return new() { "resource must be an object" };
        var p = new List<string>();
        if (!AbsoluteHttp(G(o, "url"))) p.Add("resource.url must be an absolute http(s) URL");
        foreach (var k in new[] { "description", "mimeType" })
            if (!IsUndef(G(o, k)) && G(o, k) is not string) p.Add($"resource.{k} must be a string");
        var sn = G(o, "serviceName");
        if (!IsUndef(sn) && !(sn is string s && s.Length <= 32 && AsciiPrintable(s))) p.Add("resource.serviceName must be printable ASCII up to 32 characters");
        var tags = G(o, "tags");
        if (!IsUndef(tags) && !(tags is L tl && tl.Count <= 5 && tl.All(t => t is string ts && ts.Length <= 32 && AsciiPrintable(ts)))) p.Add("resource.tags must be up to 5 printable ASCII strings of up to 32 characters");
        var icon = G(o, "iconUrl");
        if (!IsUndef(icon) && !(AbsoluteHttp(icon) && ((string)icon!).Length <= 2048)) p.Add("resource.iconUrl must be an absolute http(s) URL up to 2048 characters");
        return p;
    }

    /// <summary>Problems with one v2 <c>PaymentRequirements</c> (empty = valid).</summary>
    public static List<string> RequirementV2Problems(object? q)
    {
        if (q is not D o) return new() { "requirements must be an object" };
        var p = new List<string>();
        if (!NonEmpty(G(o, "scheme"))) p.Add("scheme is required");
        if (G(o, "network") is not string net || !Caip2.IsMatch(net)) p.Add("network must be a CAIP-2 identifier");
        if (G(o, "amount") is not string am || !DecimalAtomic.IsMatch(am) || am == "0") p.Add("amount must be a positive decimal string of atomic units");
        if (!NonEmpty(G(o, "asset"))) p.Add("asset is required");
        if (!NonEmpty(G(o, "payTo"))) p.Add("payTo is required");
        var t = G(o, "maxTimeoutSeconds");
        if (!JsX.SafeInt(t) || JsX.NumOf(t)!.Value <= 0) p.Add("maxTimeoutSeconds must be a positive integer");
        if (!IsUndef(G(o, "extra")) && !IsObj(G(o, "extra"))) p.Add("extra must be an object");
        return p;
    }

    /// <summary>Problems with a v2 <c>PaymentRequired</c> (empty = valid).</summary>
    public static List<string> PaymentRequiredV2Problems(object? pr)
    {
        if (pr is not D o) return new() { "PaymentRequired must be an object" };
        var p = new List<string>();
        if (!JsX.StrictEq(G(o, "x402Version"), N(2))) p.Add("x402Version must be 2");
        if (!IsUndef(G(o, "error")) && G(o, "error") is not string) p.Add("error must be a string");
        p.AddRange(ResourceInfoProblems(G(o, "resource")));
        if (G(o, "accepts") is not L acc || acc.Count == 0) p.Add("accepts must be a non-empty array");
        else for (int i = 0; i < acc.Count; i++) p.AddRange(RequirementV2Problems(acc[i]).Select(m => $"accepts[{i}].{m}"));
        var ext = G(o, "extensions");
        if (!IsUndef(ext))
        {
            if (ext is not D eo) p.Add("extensions must be an object");
            else foreach (var k in IntentJs.JsKeys(eo.Keys))
                {
                    var v = eo[k];
                    if (v is not D vo || G(vo, "info") is not D || G(vo, "schema") is not D) p.Add($"extensions.{k} needs info and schema objects");
                }
        }
        return p;
    }

    static string Base64Of(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

    /// <summary>The bytes Node's lenient base64 decoder yields for a string that matched <c>^[A-Za-z0-9+/]+={0,2}$</c>.</summary>
    static byte[] NodeBase64(string v)
    {
        var end = v.IndexOf('=');
        var s = end < 0 ? v : v[..end];
        if (s.Length % 4 == 1) s = s[..^1];
        s += new string('=', (4 - s.Length % 4) % 4);
        return Convert.FromBase64String(s);
    }

    /// <summary>Decode a base64 header value holding JSON (throws <see cref="AcpTypeException"/> on bad base64 or bad JSON).</summary>
    static object? DecodeHeaderJson(object? value, string name)
    {
        if (value is not string s || !Base64Header.IsMatch(s)) throw new AcpTypeException($"x402: {name} is not base64");
        try { return Pca.ParseJson(new UTF8Encoding(false, false).GetString(NodeBase64(s))); }
        catch (Exception) { throw new AcpTypeException($"x402: {name} is not JSON"); }
    }

    static void Throw(List<string> problems) { if (problems.Count > 0) throw new AcpTypeException("x402: " + string.Join("; ", problems)); }

    /// <summary>Encode a <c>PaymentRequired</c> for the PAYMENT-REQUIRED header (validates first; throws on a problem).</summary>
    public static string EncodePaymentRequiredHeader(object? pr)
    {
        Throw(PaymentRequiredV2Problems(pr));
        return Base64Of(JsJson.Stringify(pr));
    }

    /// <summary>Decode and validate a PAYMENT-REQUIRED header value; throws <see cref="AcpTypeException"/>.</summary>
    public static D DecodePaymentRequiredHeader(string value)
    {
        var doc = DecodeHeaderJson(value, "PAYMENT-REQUIRED");
        Throw(PaymentRequiredV2Problems(doc));
        return (D)doc!;
    }

    /// <summary>The v2 402 challenge: JSON body plus the base64 PAYMENT-REQUIRED header. <paramref name="resource"/> is a URL string or a ResourceInfo.
    /// <paramref name="opts"/>: amount, asset, payTo, network, scheme, maxTimeoutSeconds, extra, error, extensions.</summary>
    public static D X402ChallengeV2(object? resource, D opts)
    {
        var amount = G(opts, "amount");
        if (!JsX.SafeInt(amount) || JsX.NumOf(amount)!.Value <= 0) throw new AcpTypeException("x402Challenge: amount must be a positive integer in atomic units");
        var info = resource is string url ? new D { ["url"] = url } : JsX.Spread(resource);
        var req = new D { ["scheme"] = Nn(G(opts, "scheme"), "exact") };
        SetDefined(req, "network", G(opts, "network"));
        req["amount"] = S(amount);
        SetDefined(req, "asset", G(opts, "asset"));
        SetDefined(req, "payTo", G(opts, "payTo"));
        req["maxTimeoutSeconds"] = Nn(G(opts, "maxTimeoutSeconds"), N(60));
        if (!IsUndef(G(opts, "extra"))) req["extra"] = G(opts, "extra");
        var body = new D
        {
            ["x402Version"] = N(2),
            ["error"] = Nn(G(opts, "error"), "PAYMENT-SIGNATURE header is required"),
            ["resource"] = info,
            ["accepts"] = new L { req },
        };
        if (!IsUndef(G(opts, "extensions"))) body["extensions"] = G(opts, "extensions");
        var header = EncodePaymentRequiredHeader(body);
        return new D
        {
            ["status"] = N(402),
            ["headers"] = new D { ["Content-Type"] = "application/json", [X402V2PaymentRequiredHeader] = header },
            ["body"] = body,
        };
    }

    /// <summary>Version negotiation: the highest version both sides support, or null. <paramref name="offered"/> null means the client
    /// sent nothing (the reference's undefined; treated as [1]); an empty list is also [1].</summary>
    public static int? X402Negotiate(L? offered, L? supported = null)
    {
        supported ??= X402SupportedVersions.Select(v => (object?)N(v)).ToList();
        var mine = supported.Where(v => JsX.NumOf(v) is 1.0 or 2.0).Select(v => (int)JsX.NumOf(v)!.Value).OrderByDescending(v => v).ToList();
        var theirs = offered == null || offered.Count == 0 ? new L { N(1) } : offered;
        foreach (var v in mine) if (theirs.Any(t => JsX.NumOf(t) == v)) return v;
        return null;
    }

    static string Stable(object? v) => v switch
    {
        D o => "{" + string.Join(",", o.Keys.OrderBy(k => k, StringComparer.Ordinal).Select(k => JsJson.Quote(k) + ":" + Stable(o[k]))) + "}",
        L l => "[" + string.Join(",", l.Select(Stable)) + "]",
        _ => JsJson.Stringify(v),
    };

    /// <summary>True when <paramref name="accepted"/> (echoed by the client) is exactly one of the requirements the server offered.</summary>
    public static bool X402AcceptedMatches(L offered, object? accepted)
    {
        if (RequirementV2Problems(accepted).Count > 0) return false;
        var a = Stable(accepted);
        return offered.Any(o => Stable(o) == a);
    }

    static bool X402AcceptedMatchesAny(object? offered, object? accepted)
    {
        if (RequirementV2Problems(accepted).Count > 0) return false;
        if (offered is not L ol) throw JsX.TypeError("offered.some is not a function");
        return X402AcceptedMatches(ol, accepted);
    }

    internal sealed class Norm
    {
        public bool Ok;
        public string Reason = "";
        public int Version;
        public string Token = "";
        public object? Merchant = JsX.Undef;
        public object? Amount = JsX.Undef;
        public D? Accepted;
    }

    static Norm NormalizeX402(object? raw)
    {
        if (raw is not D o) return new Norm { Reason = "x402 payment payload is not an object" };
        var ver = G(o, "x402Version");
        if (JsX.StrictEq(ver, N(2)))
        {
            if (G(o, "payload") is not D inner || G(inner, "token") is not string tok || tok.Length == 0) return new Norm { Reason = "x402 v2 payload is missing payload.token" };
            var problems = RequirementV2Problems(G(o, "accepted"));
            if (problems.Count > 0) return new Norm { Reason = $"x402 v2 payload.accepted is invalid: {string.Join("; ", problems)}" };
            var accepted = (D)G(o, "accepted")!;
            var n = new Norm { Ok = true, Version = 2, Token = tok, Accepted = accepted };
            var amount = JsJson.ToJsNumber(accepted["amount"]);
            if (double.IsFinite(amount) && amount == Math.Floor(amount) && Math.Abs(amount) <= 9007199254740991.0) n.Amount = Num_(amount);
            return n;
        }
        if (!IsUndef(ver) && !JsX.StrictEq(ver, N(1))) return new Norm { Reason = $"unsupported x402Version {S(ver)}" };
        if (G(o, "token") is not string token) return new Norm { Reason = "x402 payment payload is missing a token" };
        var r = new Norm { Ok = true, Version = 1, Token = token };
        if (G(o, "merchant") is string m) r.Merchant = m;
        if (JsX.NumOf(G(o, "amount")) != null) r.Amount = G(o, "amount");
        return r;
    }

    /// <summary>Read a client payload of either version: <c>{ok:true, version, token, merchant?, amount?, accepted?}</c> or <c>{ok:false, reason}</c>.</summary>
    public static D NormalizeX402Payload(object? raw)
    {
        var n = NormalizeX402(raw);
        if (!n.Ok) return new D { ["ok"] = false, ["reason"] = n.Reason };
        var d = new D { ["ok"] = true, ["version"] = N(n.Version), ["token"] = n.Token };
        if (!IsUndef(n.Merchant)) d["merchant"] = n.Merchant;
        if (!IsUndef(n.Amount)) d["amount"] = n.Amount;
        if (n.Accepted != null) d["accepted"] = n.Accepted;
        return d;
    }
}
