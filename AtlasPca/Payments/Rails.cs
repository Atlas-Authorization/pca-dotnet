// Spend rails (packages/pca-payments rails.ts and rails-stripe.ts): the limits an instrument for a mandate may carry, the settlement
// reconciliation, and the Stripe Issuing adapter (webhook signature, card parameters, authorization and settlement normalisation,
// the real-time authorization webhook). The rail is a SECOND enforcement point: PCA never relaxes because the rail would have blocked.
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

public static partial class Rails
{
    static readonly Regex MccTrait = new(@"\Amcc\.c([0-9]{4})\z", RegexOptions.CultureInvariant);

    /// <summary>The MCC codes a verb's <c>mcc.cNNNN</c> traits allow (distinct, sorted).</summary>
    public static JL CategoriesFromTraits(object? traits)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var t in traits as JL ?? throw new InvalidOperationException("traits is not iterable"))
        {
            var m = MccTrait.Match(Js.Str(t));
            if (m.Success && seen.Add(m.Groups[1].Value)) order.Add(m.Groups[1].Value);
        }
        return Js.SortStrings(order).Cast<object?>().ToList();
    }

    /// <summary>The limits an instrument for this mandate may carry (<c>{currency, perAuthorizationMax, totalMax, categories, merchants, expiresAt?}</c>).
    /// No autonomous capacity left throws; the categories are the mandate's allowlist narrowed by the action's traits. <paramref name="opts"/>: <c>{actionTraits?, allowAnyCategory?}</c>.</summary>
    public static JD RailLimits(object? mandate, object? now, object? opts)
    {
        var spt = Payments.SharedPaymentTokenLimits(mandate, now);
        var budget = Js.NotNull(Js.Read(mandate, "budget"));
        var total = Math.Floor(Js.ToNumber(Js.Has(budget, "B") ? Js.Prop(budget, "B") : double.NaN));
        var terms = Js.NotNull(Js.Read(mandate, "terms"));
        var fromMandate = Js.SpreadList(Js.Read(terms, "categories"));
        var traits = Js.Prop(opts, "actionTraits");
        var fromTraits = CategoriesFromTraits(traits ?? new JL());
        List<string> categories;
        if (fromMandate.Count > 0 && fromTraits.Count > 0)
        {
            categories = Js.SortStrings(fromMandate.Where(c => fromTraits.Any(t => t is string ts && c is string cs && ts == cs)).Select(c => (string)c!));
            if (categories.Count == 0) throw new ArgumentException("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent");
        }
        else categories = Js.SortStrings((fromMandate.Count > 0 ? fromMandate : fromTraits).Select(c => Js.Str(c)));
        if (categories.Count == 0 && Js.Prop(opts, "allowAnyCategory") is not true) throw new ArgumentException("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category");
        var currency = Js.Prop(terms, "currency") as string ?? throw new InvalidOperationException("currency.toUpperCase is not a function");
        var merchants = Js.SpreadList(Js.Prop(terms, "merchants"));
        var o = new JD
        {
            ["currency"] = currency.ToUpperInvariant(), ["perAuthorizationMax"] = spt["max_amount"], ["totalMax"] = Js.Out(total),
            ["categories"] = categories.Cast<object?>().ToList(), ["merchants"] = merchants,
        };
        if (spt.TryGetValue("expires_at", out var ea)) o["expiresAt"] = Js.Out(Js.D(ea) * 1000);
        return o;
    }

    /// <summary>Compare what settled with what PCA approved: <c>{ok: true}</c> on an exact fit, else <c>{ok: false, reasons, action: "freeze_grant"}</c>.</summary>
    public static JD ReconcileSettlement(object? approved, object? s)
    {
        var reasons = new JL();
        if (!StrictEq(s, "authorizationId", approved, "id")) reasons.Add("authorization_id_mismatch");
        if (Js.Gt(Js.Prop(s, "amount"), Js.Prop(approved, "amount"))) reasons.Add("settled_more_than_approved");
        var sc = Js.Prop(s, "currency") as string ?? throw new InvalidOperationException("currency.toUpperCase is not a function");
        if (sc.ToUpperInvariant() != (Js.Prop(approved, "currency") as string ?? throw new InvalidOperationException("currency.toUpperCase is not a function")).ToUpperInvariant()) reasons.Add("currency_mismatch");
        if (!StrictEq(s, "merchantId", approved, "merchantId")) reasons.Add("merchant_mismatch");
        if (Js.Gt(Js.Prop(s, "captures"), new Num("1"))) reasons.Add("second_capture");
        return reasons.Count == 0 ? new JD { ["ok"] = true } : new JD { ["ok"] = false, ["reasons"] = reasons, ["action"] = "freeze_grant" };
    }

    /// <summary>a.k !== b.k as JavaScript strict inequality over JSON values (a missing member is undefined, equal only to a missing member).</summary>
    internal static bool StrictEq(object? a, string ak, object? b, string bk)
    {
        bool ha = Js.Has(a, ak), hb = Js.Has(b, bk);
        if (ha != hb) return false;
        if (!ha) return true;
        var x = Js.Prop(a, ak); var y = Js.Prop(b, bk);
        return x switch
        {
            null => y == null,
            string s => y is string t && s == t,
            bool p => y is bool q && p == q,
            Num n => y is Num m && IntentJs.NumOf(n) == IntentJs.NumOf(m),
            _ => false,
        };
    }
}

public static class StripeRails
{
    public const int WebhookToleranceSec = 300;
    public const string ApiVersion = "2025-03-31.basil";
    static readonly Regex Digits = new(@"\A[0-9]{1,12}\z", RegexOptions.CultureInvariant);
    static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    static string Hmac(string secret, string t, string rawBody) =>
        Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(t + "." + rawBody))).ToLowerInvariant();

    /// <summary>The <c>Stripe-Signature</c> header Stripe would send: <c>t=&lt;sec&gt;,v1=&lt;hex hmac&gt;</c> (tests and local tooling).</summary>
    public static string SignStripePayload(string rawBody, string secret, object? tSec) => $"t={Js.Str(tSec)},v1={Hmac(secret, Js.Str(tSec), rawBody)}";

    /// <summary>Verify a <c>Stripe-Signature</c> header over the RAW body. Total: false on anything malformed, stale (beyond the tolerance) or mismatched.</summary>
    public static bool VerifyStripeSignature(object? rawBody, object? header, object? secret, object? nowSec, object? toleranceSec = null)
    {
        try
        {
            var tol = toleranceSec == null ? WebhookToleranceSec : Js.ToNumber(toleranceSec);
            if (header is not string h || secret is not string sec || sec.Length == 0 || !(double.IsFinite(tol) && tol > 0) || rawBody is not string body) return false;
            string? t = null;
            var v1 = new List<string>();
            foreach (var part in h.Split(','))
            {
                var i = part.IndexOf('=');
                if (i < 0) continue;
                var k = Js.Trim(part[..i]);
                var v = Js.Trim(part[(i + 1)..]);
                if (k == "t") t = v;
                else if (k == "v1") v1.Add(v);
            }
            if (t == null || !Digits.IsMatch(t) || v1.Count == 0) return false;
            if (!(Math.Abs(Js.ToNumber(nowSec) - double.Parse(t, System.Globalization.CultureInfo.InvariantCulture)) <= tol)) return false;
            var want = Convert.FromHexString(Hmac(sec, t, body));
            return v1.Any(sig => Hex64.IsMatch(sig) && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(sig), want));
        }
        catch (Exception) { return false; }
    }

    /// <summary>The form parameters of <c>POST /v1/issuing/cards</c> (virtual, active) that carry the rail limits; throws when an MCC has no Stripe category name.
    /// <paramref name="categoryNames"/>: MCC to Stripe name; <paramref name="metadata"/>: string to string (null: none).</summary>
    public static JD StripeCardParams(object? limits, object? categoryNames, object? cardholder, object? metadata)
    {
        var p = new JD
        {
            ["cardholder"] = cardholder, ["type"] = "virtual", ["status"] = "active",
            ["currency"] = (Js.Prop(limits, "currency") as string ?? throw new InvalidOperationException("currency.toLowerCase is not a function")).ToLowerInvariant(),
            ["spending_controls[spending_limits][0][amount]"] = Js.Str(Js.Prop(limits, "perAuthorizationMax"), Js.Has(limits, "perAuthorizationMax")),
            ["spending_controls[spending_limits][0][interval]"] = "per_authorization",
            ["spending_controls[spending_limits][1][amount]"] = Js.Str(Js.Prop(limits, "totalMax"), Js.Has(limits, "totalMax")),
            ["spending_controls[spending_limits][1][interval]"] = "all_time",
        };
        var cats = Js.Prop(limits, "categories") as JL ?? throw new InvalidOperationException("categories.forEach is not a function");
        for (int i = 0; i < cats.Count; i++)
        {
            var mcc = Js.Str(cats[i]);
            if (!Js.Has(categoryNames, mcc)) throw new ArgumentException($"stripeCardParams: no Stripe category name for MCC {mcc}");
            p[$"spending_controls[allowed_categories][{i}]"] = Js.Prop(categoryNames, mcc);
        }
        if (metadata is JD md) foreach (var kv in md) p[$"metadata[{kv.Key}]"] = kv.Value;
        return p;
    }

    static JD? Obj(object? v) => v as JD;

    /// <summary>Normalise an <c>issuing_authorization.request</c> event to <c>{id, instrumentId, amount, currency, merchantId?, mcc?}</c>; null when it is not a well-formed request with a pending amount.</summary>
    public static JD? StripeAuthorizationFromEvent(object? ev)
    {
        var e = Obj(ev);
        if (Js.Prop(e, "type") is not "issuing_authorization.request") return null;
        var a = Obj(Js.Prop(Obj(Js.Prop(e, "data")), "object"));
        var pending = Obj(Js.Prop(a, "pending_request"));
        var card = Obj(Js.Prop(a, "card"));
        var merchant = Obj(Js.Prop(a, "merchant_data"));
        if (a == null || pending == null || Js.Prop(a, "id") is not string id || Js.Prop(card, "id") is not string cardId) return null;
        var amount = Js.Prop(pending, "amount"); var currency = Js.Prop(pending, "currency");
        if (amount is not Num || currency is not string) return null;
        var o = new JD { ["id"] = id, ["instrumentId"] = cardId, ["amount"] = amount, ["currency"] = currency };
        if (Js.Prop(merchant, "network_id") is string nid && nid.Length > 0) o["merchantId"] = nid;
        if (Js.Prop(merchant, "category_code") is string cc) o["mcc"] = cc;
        return o;
    }

    static JD Reply(int status, string body, string version) =>
        new() { ["status"] = IntentJs.OfLong(status), ["headers"] = new JD { ["Stripe-Version"] = version, ["Content-Type"] = "application/json" }, ["body"] = body };

    /// <summary>The handler body of the <c>issuing_authorization.request</c> endpoint. A bad signature is 400 (nothing is decided); a request event gets 200 <c>{approved}</c>
    /// from the PCA decision (<paramref name="authorize"/> returns the verdict, whose <c>approved</c> must be exactly true); any other event type gets 200 <c>{}</c>.
    /// Returns <c>{status, headers, body}</c>.</summary>
    public static JD StripeIssuingWebhook(string rawBody, string? signature, string secret, long nowSec, Func<JD, JD> authorize, string? stripeVersion = null, double? toleranceSec = null)
    {
        var version = stripeVersion ?? ApiVersion;
        if (!VerifyStripeSignature(rawBody, signature, secret, IntentJs.OfLong(nowSec), toleranceSec == null ? null : Js.Out(toleranceSec.Value))) return Reply(400, "{\"error\":\"bad_signature\"}", version);
        object? ev;
        try { ev = Pca.ParseJson(rawBody); }
        catch (Exception) { return Reply(400, "{\"error\":\"bad_json\"}", version); }
        if (Js.Prop(Obj(ev), "type") is not "issuing_authorization.request") return Reply(200, "{}", version);
        var auth = StripeAuthorizationFromEvent(ev);
        if (auth == null) return Reply(200, "{\"approved\":false}", version);
        var v = authorize(auth);
        return Reply(200, Js.Prop(v, "approved") is true ? "{\"approved\":true}" : "{\"approved\":false}", version);
    }

    /// <summary>Normalise an <c>issuing_transaction.created</c> capture to a settlement (the amount of a capture is negative in Stripe's ledger); null otherwise.</summary>
    public static JD? StripeSettlementFromTransaction(object? txn)
    {
        var t = Obj(txn);
        var m = Obj(Js.Prop(t, "merchant_data"));
        if (t == null || Js.Prop(t, "type") is not "capture" || Js.Prop(t, "authorization") is not string auth || Js.Prop(t, "amount") is not Num amt || Js.Prop(t, "currency") is not string cur) return null;
        var o = new JD { ["authorizationId"] = auth, ["amount"] = Js.Out(-Js.D(amt)), ["currency"] = cur };
        if (Js.Prop(m, "network_id") is string nid) o["merchantId"] = nid;
        o["captures"] = new Num("1");
        return o;
    }
}
