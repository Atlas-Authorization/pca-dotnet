// Stripe Shared Payment Tokens (the Shared Payment Granted Token object): read and check the object and relate it to a PCA delegated
// payment token. No I/O; never calls Stripe. Whether Stripe accepts a token is Stripe's decision: these checks only refuse what PCA authority forbids.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Acp;

public static partial class Acp
{
    public const string StripeSptObject = "shared_payment.granted_token";
    static readonly string[] SptReasons = { "consumed", "expired", "resolved", "revoked" };
    static readonly Regex SptId = new(@"\Aspt_[A-Za-z0-9_]+\z", RegexOptions.CultureInvariant);
    static readonly Regex Alpha3 = new(@"\A[A-Za-z]{3}\z", RegexOptions.CultureInvariant);

    /// <summary>Problems with a Shared Payment Granted Token object (empty = well formed).</summary>
    public static List<string> StripeSptProblems(object? t)
    {
        if (t is not D o) return new() { "the token must be an object" };
        var p = new List<string>();
        if (!JsX.StrictEq(G(o, "object"), StripeSptObject)) p.Add($"object must be \"{StripeSptObject}\"");
        if (G(o, "id") is not string id || !SptId.IsMatch(id)) p.Add("id must be an spt_ identifier");
        if (!IntentJs.IsInt(G(o, "created"))) p.Add("created must be an integer timestamp");
        if (G(o, "livemode") is not bool) p.Add("livemode must be a boolean");
        var da = G(o, "deactivated_at");
        if (da != null && !IntentJs.IsInt(da)) p.Add("deactivated_at must be null or an integer timestamp");
        var dr = G(o, "deactivated_reason");
        if (dr != null && !(dr is string drs && SptReasons.Contains(drs))) p.Add("deactivated_reason must be null or one of consumed, expired, resolved, revoked");
        if (G(o, "usage_limits") is not D u) p.Add("usage_limits is required");
        else
        {
            if (!IsLower3(G(u, "currency"))) p.Add("usage_limits.currency must be a lowercase three-letter code");
            if (!IntentJs.IsNonNeg(G(u, "max_amount"))) p.Add("usage_limits.max_amount must be a non-negative integer in minor units");
            var ea = G(u, "expires_at");
            if (!Nullish(ea) && !IntentJs.IsInt(ea)) p.Add("usage_limits.expires_at must be an integer timestamp");
        }
        var ud = G(o, "usage_details");
        if (!Nullish(ud))
        {
            var c = ud is D udo ? G(udo, "amount_captured") : JsX.Undef;
            if (c is not D cd || !IntentJs.IsNonNeg(G(cd, "value")) || !IsLower3(G(cd, "currency"))) p.Add("usage_details.amount_captured needs a non-negative integer value and a lowercase currency");
        }
        foreach (var k in new[] { "payment_method_details", "agent_details", "shared_metadata" })
            if (!Nullish(G(o, k)) && G(o, k) is not D) p.Add($"{k} must be null or an object");
        if (G(o, "payment_method_details") is D pm && G(pm, "type") is not string) p.Add("payment_method_details.type must be a string");
        return p;
    }

    /// <summary>Parse a Shared Payment Granted Token; throws <see cref="AcpTypeException"/> listing every problem.</summary>
    public static D ParseStripeSpt(object? t)
    {
        var problems = StripeSptProblems(t);
        if (problems.Count > 0) throw new AcpTypeException("stripe spt: " + string.Join("; ", problems));
        return (D)t!;
    }

    /// <summary>Can this token still be used for this capture? <paramref name="use"/>: now (epoch seconds), amount (integer minor units), currency
    /// (case-insensitive), livemode (default true). Returns <c>{ok:true}</c> or <c>{ok:false, reason}</c>.</summary>
    public static D StripeSptUsable(object? t, object? use)
    {
        var problems = StripeSptProblems(t);
        if (problems.Count > 0) return Fail("malformed token: " + problems[0]);
        var spt = (D)t!;
        var now = G(use, "now");
        var amount = G(use, "amount");
        if (!IntentJs.IsInt(now) || !IntentJs.IsInt(amount) || JsX.NumOf(amount)!.Value <= 0) return Fail("now and amount must be integers and the amount positive");
        if (!JsX.StrictEq(Nn(G(use, "livemode"), true), spt["livemode"])) return Fail("the token is in the wrong mode");
        var reason = spt["deactivated_reason"];
        if (reason != null) return Fail($"the token is deactivated ({S(reason)})");
        var da = spt["deactivated_at"];
        if (da != null && !(JsX.NumOf(da)!.Value > JsX.NumOf(now)!.Value)) return Fail("the token is deactivated");
        var lim = (D)spt["usage_limits"]!;
        if (JsX.NumOf(G(lim, "expires_at")) is double ea && !(JsX.NumOf(now)!.Value < ea)) return Fail("the token has expired");
        if (G(use, "currency") is not string cur) throw JsX.TypeError("use.currency.toLowerCase is not a function");
        if ((string)lim["currency"]! != JsLower(cur)) return Fail("the capture currency differs from the token currency");
        var ud = G(spt, "usage_details");
        D? captured = ud is D udo ? G(udo, "amount_captured") as D : null;
        if (captured != null && (string)captured["currency"]! != (string)lim["currency"]!) return Fail("the captured amount is in another currency");
        var remaining = JsX.NumOf(lim["max_amount"])!.Value - (captured != null ? JsX.NumOf(captured["value"])!.Value : 0);
        if (!(JsX.NumOf(amount)!.Value <= remaining)) return Fail($"the amount {S(amount)} exceeds the remaining {JsX.JsNumString(remaining)}");
        return new D { ["ok"] = true };
    }

    /// <summary>The <c>usage_limits</c> to request for a PCA authority <c>{maxAmount, currency, expiresAtMs?}</c>: lowercase currency, integer minor units,
    /// expiry in whole seconds (rounded down).</summary>
    public static D StripeUsageLimitsFor(D authority)
    {
        var max = G(authority, "maxAmount");
        if (!IntentJs.IsInt(max) || JsX.NumOf(max)!.Value <= 0) throw new AcpTypeException("stripe spt: maxAmount must be a positive integer in minor units");
        if (G(authority, "currency") is not string cur || !Alpha3.IsMatch(cur)) throw new AcpTypeException("stripe spt: currency must be a three-letter code");
        var exp = G(authority, "expiresAtMs");
        if (!IsUndef(exp) && !(Finite(exp) is double e && e > 0)) throw new AcpTypeException("stripe spt: expiresAtMs must be a positive epoch-ms time");
        var r = new D { ["currency"] = cur.ToLowerInvariant(), ["max_amount"] = max };
        if (!IsUndef(exp)) r["expires_at"] = Num_(Math.Floor(Finite(exp)!.Value / 1000));
        return r;
    }

    /// <summary>A Shared Payment Token may be no wider than the delegated payment token it serves: same currency, <c>max_amount</c> not above the
    /// delegated amount, and an expiry present and not after the delegated token's. <paramref name="claims"/>: amount, currency, exp.</summary>
    public static D StripeSptWithinClaims(object? t, object? claims)
    {
        var problems = StripeSptProblems(t);
        if (problems.Count > 0) return Fail("malformed token: " + problems[0]);
        var lim = (D)((D)t!)["usage_limits"]!;
        if (G(claims, "currency") is not string cur) throw JsX.TypeError("claims.currency.toLowerCase is not a function");
        if ((string)lim["currency"]! != JsLower(cur)) return Fail("the token currency differs from the delegated currency");
        var amount = G(claims, "amount");
        if (!(double.IsFinite(JsJson.ToJsNumber(amount)) && JsX.NumOf(lim["max_amount"])!.Value <= JsJson.ToJsNumber(amount))) return Fail($"max_amount {S(lim["max_amount"])} exceeds the delegated amount {S(amount)}");
        if (JsX.NumOf(G(lim, "expires_at")) is not double ea) return Fail("the token has no expiry");
        if (!(double.IsFinite(JsJson.ToJsNumber(G(claims, "exp"))) && ea * 1000 <= JsJson.ToJsNumber(G(claims, "exp")))) return Fail("the token outlives the delegated payment token");
        return new D { ["ok"] = true };
    }
}
