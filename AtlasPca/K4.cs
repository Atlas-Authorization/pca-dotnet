// K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
// binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
// Signatures are Ed25519 (strict) over the UTF-8 bytes of HashCanonical({"kind": kind, "body": body}) (the digest string); body is the
// signed object without its "sig". Escalation is integer-only (BigInteger). Total: never throws.
using System.Numerics;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record PricingVerdict(bool Ask, string Reason);

public sealed record CalibrationState(long MultiplierPpm, IReadOnlyList<string> Seen);

public static class K4
{
    public const long Ppm = 1_000_000;
    public const long MaxMultiplierPpm = 100 * Ppm;
    public const string BindingKind = "pca.network_token_binding";
    static readonly Regex Ref = new(@"\A[A-Za-z0-9_.:\-]{8,128}\z", RegexOptions.CultureInvariant);
    static readonly Regex Addr = new(@"\A0x[0-9a-fA-F]{40}\z", RegexOptions.CultureInvariant);
    static readonly Regex Qty = new(@"\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z", RegexOptions.CultureInvariant);
    static readonly Regex Ctx = new(@"\A0x[0-9a-fA-F]+\z", RegexOptions.CultureInvariant);

    static bool Int(object? o, out long n) => Pca.SafeInt(o, out n);
    static bool Minor(object? o, out long n) => Pca.SafeNat(o, out n);
    static long L(object? o) => Int(o, out var n) ? n : 0;
    static Num N(long n) => new(n.ToString(System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>null when the key or signature does not decode; else the strict verification result.</summary>
    static bool? SigOk(object? pub, string kind, JD o)
    {
        if (pub is not string || o.GetValueOrDefault("sig") is not string || Pca.B64uDecode(pub) == null || Pca.B64uDecode(o["sig"]) == null) return null;
        var body = new JD(o);
        body.Remove("sig");
        return Pca.VerifyDigest(pub, Pca.HashCanonical(new JD { ["kind"] = kind, ["body"] = body }), o["sig"]);
    }

    // ---- network-token binding ----

    static bool Luhn(string d)
    {
        int sum = 0; bool dbl = false;
        for (int i = d.Length - 1; i >= 0; i--)
        {
            int n = d[i] - '0';
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    public static bool LooksLikePan(string s) =>
        Regex.Matches(Regex.Replace(s, @"[\s\-]", ""), "[0-9]+").Any(m => m.Length >= 13 && m.Length <= 19 && Luhn(m.Value));

    public static string? TokenRefError(object? r)
    {
        if (r is not string s || !Ref.IsMatch(s)) return "token_ref_malformed";
        return LooksLikePan(s) ? "token_ref_looks_like_pan" : null;
    }

    /// <summary>null = valid, else the reason. provider null = any.</summary>
    public static string? VerifyBinding(object? bo, object? grant, string holder, string issuerNonce, string? provider)
    {
        try
        {
            if (bo is not JD b || b.GetValueOrDefault("kind") as string != BindingKind) return "binding_malformed";
            var e = TokenRefError(b.GetValueOrDefault("token_ref"));
            if (e != null) return e;
            if (b.GetValueOrDefault("provider") is not string p || p.Length == 0 || (provider != null && p != provider)) return "provider_mismatch";
            if (b.GetValueOrDefault("grant_digest") as string != Pca.HashCanonical(grant)) return "grant_digest_mismatch";
            if (b.GetValueOrDefault("holder") as string != holder) return "holder_mismatch";
            if (b.GetValueOrDefault("issuer_nonce") as string != issuerNonce) return "issuer_nonce_mismatch";
            if (Pca.B64uDecode(holder) == null || Pca.B64uDecode(b.GetValueOrDefault("binding_proof")) == null) return "binding_malformed";
            var body = new JD { ["kind"] = BindingKind, ["v"] = N(1), ["provider"] = p, ["token_ref"] = b["token_ref"], ["grant_digest"] = b["grant_digest"], ["issuer_nonce"] = b["issuer_nonce"], ["holder"] = b["holder"] };
            return Pca.VerifyDigest(holder, Pca.HashCanonical(body), b["binding_proof"]) ? null : "binding_proof_invalid";
        }
        catch (Exception) { return "binding_malformed"; }
    }

    // ---- risk-priced escalation ----

    public static string? PricingConfigError(object? co)
    {
        try
        {
            if (co is not JD c || !Int(c.GetValueOrDefault("v"), out var v) || v != 1 || c.GetValueOrDefault("principal") is not string || c.GetValueOrDefault("currency") is not string || c.GetValueOrDefault("sig") is not string) return "config_malformed";
            if (!Minor(c.GetValueOrDefault("interruptionCost"), out var cost) || !Minor(c.GetValueOrDefault("maxInterruptionCost"), out var max) || !Minor(c.GetValueOrDefault("hardCeilingLoss"), out _) || !Minor(c.GetValueOrDefault("epoch"), out _)) return "config_amounts_invalid";
            if (cost > max) return "config_cost_above_max";
            if (!Int(c.GetValueOrDefault("tightenStepPpm"), out var st) || st < 0 || st > MaxMultiplierPpm) return "config_step_invalid";
            var r = SigOk(c["principal"], "pca.escalation_pricing", c);
            return r == null ? "config_malformed" : (r.Value ? null : "config_signature_invalid");
        }
        catch (Exception) { return "config_malformed"; }
    }

    static PricingVerdict Ask(string r) => new(true, r);

    /// <summary>Ask a person iff min(p * multiplier, 1e12) * loss > interruptionCost * 1e12; anything unexpected asks.</summary>
    public static PricingVerdict Decide(object? config, object? cal, object? ao)
    {
        var e = PricingConfigError(config);
        if (e != null) return Ask(e);
        var cfg = (JD)config!;
        if (ao is not JD a || a.GetValueOrDefault("currency") as string != (string)cfg["currency"]) return Ask("currency_mismatch");
        if (!Minor(a.GetValueOrDefault("loss"), out var loss) || !Int(a.GetValueOrDefault("pBadUpperPpm"), out var p) || p < 0 || p > Ppm) return Ask("risk_input_invalid");
        if (cal is not JD cm || !Int(cm.GetValueOrDefault("multiplierPpm"), out var mult) || mult < Ppm || mult > MaxMultiplierPpm) return Ask("calibration_invalid");
        if (loss > L(cfg["hardCeilingLoss"])) return Ask("above_hard_ceiling");
        var one = new BigInteger(Ppm) * Ppm;
        var capped = BigInteger.Min(new BigInteger(p) * mult, one);
        if (capped * loss > new BigInteger(L(cfg["interruptionCost"])) * one) return Ask("expected_loss_exceeds_interruption_cost");
        return new(false, "expected_loss_within_interruption_cost");
    }

    static bool AnswerOk(object? ao, string principal)
    {
        try
        {
            return ao is JD a && Int(a.GetValueOrDefault("v"), out var v) && v == 1 && a.GetValueOrDefault("principal") as string == principal
                && a.GetValueOrDefault("nonce") is string n && n.Length >= 8 && a.GetValueOrDefault("action_digest") is string
                && (a.GetValueOrDefault("answer") as string is "approve" or "deny") && SigOk(principal, "pca.escalation_answer", a) == true;
        }
        catch (Exception) { return false; }
    }

    /// <summary>Fold principal-signed answers into the calibration; the multiplier can only rise. risks: action digest to risk object.</summary>
    public static CalibrationState UpdateCalibration(object? config, long startMult, IReadOnlyList<string> startSeen, IReadOnlyList<object?> answers, IReadOnlyDictionary<string, object?> risks)
    {
        var order = new List<string>(startSeen);
        if (PricingConfigError(config) != null) return new(startMult, order);
        var cfg = (JD)config!;
        var principal = (string)cfg["principal"]!;
        var step = L(cfg["tightenStepPpm"]);
        var mult = startMult;
        foreach (var ao in answers)
        {
            if (!AnswerOk(ao, principal)) continue;
            var a = (JD)ao!;
            var nonce = (string)a["nonce"]!;
            if (order.Contains(nonce)) continue;
            order.Add(nonce);
            if ((string)a["answer"]! != "deny" || !risks.TryGetValue((string)a["action_digest"]!, out var risk) || risk == null) continue;
            if (!Decide(config, new JD { ["multiplierPpm"] = N(mult) }, risk).Ask) mult = Math.Min(MaxMultiplierPpm, mult + step);
        }
        return new(Math.Max(mult, startMult), order);
    }

    // ---- ERC-7715 granted-permission check ----

    static string Tok(JD o) => (o.GetValueOrDefault("tokenAddress") as string)?.ToLowerInvariant() ?? "";
    static string Lower(object? o) => o is string s ? s.ToLowerInvariant() : "\0";

    /// <summary>null when what the wallet granted is within the request and the grant. g = {grantDigest, expiresAtSec}.</summary>
    public static string? VerifyGranted(object? go, object? sentO, object? gotO, IReadOnlyList<string> allowedManagers, Func<string, string?>? contextOwner)
    {
        try
        {
            var g = (JD)go!; var sent = (JD)sentO!;
            if (gotO is not JD r || r.GetValueOrDefault("permission") is not JD perm) return "response_malformed";
            if (r.GetValueOrDefault("context") is not string ctx || !Ctx.IsMatch(ctx)) return "context_malformed";
            var owner = contextOwner?.Invoke(ctx);
            if (owner != null && owner != (string?)g["grantDigest"]) return "context_bound_to_other_grant";
            if (r.GetValueOrDefault("delegationManager") is not string m || !Addr.IsMatch(m) || !allowedManagers.Any(x => string.Equals(x, m, StringComparison.OrdinalIgnoreCase))) return "delegation_manager_not_allowed";
            if (Lower(r.GetValueOrDefault("chainId")) != Lower(sent.GetValueOrDefault("chainId"))) return "chain_mismatch";
            if (Lower(r.GetValueOrDefault("to")) != Lower(sent.GetValueOrDefault("to"))) return "recipient_mismatch";
            if (sent.GetValueOrDefault("from") != null && Lower(r.GetValueOrDefault("from")) != Lower(sent["from"])) return "from_mismatch";
            var sperm = (JD)sent["permission"]!;
            var pt = perm.GetValueOrDefault("type") as string;
            if (pt == null || pt != sperm["type"] as string || (pt != "native-token-allowance" && pt != "erc20-token-allowance")) return "permission_type_mismatch";
            if (perm.GetValueOrDefault("data") is not JD d) return "response_malformed";
            var sd = (JD)sperm["data"]!;
            if (Tok(d) != Tok(sd)) return "token_mismatch";
            if (d.GetValueOrDefault("allowance") is not string al || !Qty.IsMatch(al)) return "amount_malformed";
            if (BigInteger.Parse("0" + al[2..], System.Globalization.NumberStyles.HexNumber) > BigInteger.Parse("0" + ((string)sd["allowance"]!)[2..], System.Globalization.NumberStyles.HexNumber)) return "amount_widened";
            if (!Equals(perm.GetValueOrDefault("isAdjustmentAllowed"), sperm.GetValueOrDefault("isAdjustmentAllowed")) && Equals(perm.GetValueOrDefault("isAdjustmentAllowed"), true)) return "adjustment_widened";
            if (r.GetValueOrDefault("rules") is not List<object?> rules) return "expiry_missing";
            long? expiry = null;
            foreach (var ru in rules)
            {
                if (ru is not JD rule || rule.GetValueOrDefault("type") as string != "expiry") return "unknown_rule_type";
                if (expiry != null) return "duplicate_expiry";
                if (!(rule.GetValueOrDefault("data") is JD rd) || !Int(rd.GetValueOrDefault("timestamp"), out var ts)) return "expiry_malformed";
                expiry = ts;
            }
            if (expiry == null) return "expiry_missing";
            return expiry > L(g["expiresAtSec"]) ? "expiry_extended" : null;
        }
        catch (Exception) { return "response_malformed"; }
    }
}
