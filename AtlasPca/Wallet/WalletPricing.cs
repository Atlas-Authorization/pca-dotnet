// Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities in
// ppm, money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-signed
// configuration; anything missing, out of range or unsigned means ask. The only learned component is a per-principal multiplier that
// scales P(bad) up, so it can only add asks; asking less needs a principal-signed autonomy raise.
using System.Numerics;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

public static class WalletPricing
{
    public const long Ppm = 1_000_000;
    public const long MaxMultiplierPpm = 100 * Ppm;

    static bool IsMinor(object? n) => IntentJs.IsSafeInteger(n) && IntentJs.NumOf(n)!.Value >= 0;
    static bool IsOne(object? v) => IntentJs.NumOf(v) is double d && d == 1;
    static double Dn(object? o) => WalletCore.Dn(o);
    static object? G(object? o, string k) => WalletCore.G(o, k);
    static object? N(double d) => WalletCore.N(d);

    static byte[] Msg(string kind, object? body) => Encoding.UTF8.GetBytes(Pca.HashCanonical(new D { ["kind"] = kind, ["body"] = body }));
    static string Sig(byte[] secret, string kind, object? body) { using var k = EdKey.FromSeed(secret); return Pca.B64u(k.Sign(Msg(kind, body))); }

    /// <summary>Verify like the reference: the message is built first, then key and signature text that is not base64url throws (a malformed input); a key or signature of
    /// the wrong length is not a throw, it just does not verify.</summary>
    static bool Verify(string principal, string kind, object? body, string sig)
    {
        var message = Msg(kind, body);
        var pk = Pca.B64uDecode(principal) ?? throw new WalletException("bad key");
        var sg = Pca.B64uDecode(sig) ?? throw new WalletException("bad signature");
        return pk.Length == 32 && sg.Length == 64 && Pca.VerifyEd25519Strict(pk, message, sg);
    }

    static D WithoutSig(D x) { var b = new D(x); b.Remove("sig"); return b; }

    public static D SignPricingConfig(D body, byte[] principalSecret) => new(body) { ["sig"] = Sig(principalSecret, "pca.escalation_pricing", body) };

    /// <summary>Why a signed pricing configuration is refused, or null (a pure function of its content).</summary>
    public static string? PricingConfigError(object? c)
    {
        try
        {
            if (c is not D x) return "config_malformed";
            if (!IsOne(G(x, "v")) || G(x, "principal") is not string principal || G(x, "currency") is not string || G(x, "sig") is not string sig) return "config_malformed";
            if (!(IsMinor(G(x, "interruptionCost")) && IsMinor(G(x, "maxInterruptionCost")) && IsMinor(G(x, "hardCeilingLoss")) && IsMinor(G(x, "epoch")))) return "config_amounts_invalid";
            if (Dn(x["interruptionCost"]) > Dn(x["maxInterruptionCost"])) return "config_cost_above_max";
            var step = G(x, "tightenStepPpm");
            if (!IntentJs.IsSafeInteger(step) || Dn(step) < 0 || Dn(step) > MaxMultiplierPpm) return "config_step_invalid";
            return Verify(principal, "pca.escalation_pricing", WithoutSig(x), sig) ? null : "config_signature_invalid";
        }
        catch (Exception) { return "config_malformed"; }
    }

    public static D FreshCalibration() => new() { ["multiplierPpm"] = new Num(Ppm.ToString()), ["seen"] = new L() };

    static D Ask(bool ask, string reason) => new() { ["ask"] = ask, ["reason"] = reason };

    /// <summary>Pure and total: {ask, reason}. Anything unverifiable or out of range asks.</summary>
    public static D DecideEscalation(D config, object? cal, object? a)
    {
        var e = PricingConfigError(config);
        if (e != null) return Ask(true, e);
        if (a is not D || !(G(a, "currency") is string cur && cur == (string)config["currency"]!)) return Ask(true, "currency_mismatch");
        var loss = G(a, "loss"); var p = G(a, "pBadUpperPpm");
        if (!IsMinor(loss) || WalletCore.IsNegZero(loss) || !IntentJs.IsSafeInteger(p) || Dn(p) < 0 || WalletCore.IsNegZero(p) || Dn(p) > Ppm) return Ask(true, "risk_input_invalid");
        var mult = cal is D ? G(cal, "multiplierPpm") : null;
        if (!(IntentJs.IsSafeInteger(mult) && Dn(mult) >= Ppm && Dn(mult) <= MaxMultiplierPpm)) return Ask(true, "calibration_invalid");
        if (Dn(loss) > Dn(config["hardCeilingLoss"])) return Ask(true, "above_hard_ceiling");
        BigInteger pe = new BigInteger(Dn(p)) * new BigInteger(Dn(mult));
        BigInteger cap = (BigInteger)Ppm * Ppm;
        BigInteger lhs = (pe > cap ? cap : pe) * new BigInteger(Dn(loss));
        BigInteger rhs = new BigInteger(Dn(config["interruptionCost"])) * Ppm * Ppm;
        return lhs > rhs ? Ask(true, "expected_loss_exceeds_interruption_cost") : Ask(false, "expected_loss_within_interruption_cost");
    }

    public static D SignAnswer(D body, byte[] principalSecret) => new(body) { ["sig"] = Sig(principalSecret, "pca.escalation_answer", body) };

    static bool AnswerOk(object? a, string principal)
    {
        try
        {
            if (a is not D am || !IsOne(G(a, "v")) || !(G(a, "principal") is string pr && pr == principal)) return false;
            if (G(a, "nonce") is not string nonce || nonce.Length < 8 || G(a, "action_digest") is not string) return false;
            if (!(G(a, "answer") is string ans && (ans == "approve" || ans == "deny"))) return false;
            return Verify(principal, "pca.escalation_answer", WithoutSig(am), (string)am["sig"]!);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Fold signed answers into the calibration. A DENY the principal gave to an action that the current pricing would have
    /// auto-approved is a miss and adds tightenStepPpm (capped); anything else changes nothing. The multiplier never decreases.</summary>
    public static D UpdateCalibration(D config, D cal, L answers, D risks)
    {
        if (PricingConfigError(config) != null) return cal;
        double mult = Dn(cal["multiplierPpm"]);
        var seen = new HashSet<string>(((L)cal["seen"]!).Select(x => (string)x!));
        var order = new L(((L)cal["seen"]!));
        foreach (var a in answers)
        {
            if (!AnswerOk(a, (string)config["principal"]!) || seen.Contains((string)((D)a!)["nonce"]!)) continue;
            var ad = (D)a!;
            seen.Add((string)ad["nonce"]!);
            order.Add(ad["nonce"]);
            if ((string?)ad["answer"] != "deny" || !risks.TryGetValue((string)ad["action_digest"]!, out var risk)) continue;
            if (!(bool)DecideEscalation(config, new D { ["multiplierPpm"] = N(mult), ["seen"] = new L() }, risk)["ask"]!)
                mult = Math.Min(MaxMultiplierPpm, mult + Dn(config["tightenStepPpm"]));
        }
        return new D { ["multiplierPpm"] = N(Math.Max(mult, Dn(cal["multiplierPpm"]))), ["seen"] = order };
    }

    public static D SignAutonomyRaise(D b, byte[] secret) => new(b) { ["sig"] = Sig(secret, "pca.autonomy_raise", b) };

    /// <summary>A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within maxInterruptionCost.</summary>
    public static D ApplyAutonomyRaise(D config, D raise, byte[] principalSecret)
    {
        bool ok;
        try
        {
            ok = IsOne(G(raise, "v")) && G(raise, "principal") is string rp && rp == (string)config["principal"]!
                && Verify(rp, "pca.autonomy_raise", WithoutSig(raise), (string)raise["sig"]!);
        }
        catch (Exception) { ok = false; }
        if (!ok) throw new WalletException("applyAutonomyRaise: signature or principal invalid");
        if (!(Dn(raise["epoch"]) > Dn(config["epoch"]))) throw new WalletException("applyAutonomyRaise: epoch must advance");
        var cost = G(raise, "newInterruptionCost");
        if (!IsMinor(cost) || Dn(cost) > Dn(config["maxInterruptionCost"])) throw new WalletException("applyAutonomyRaise: above the configured maximum");
        var body = WithoutSig(config);
        body["interruptionCost"] = cost;
        body["epoch"] = raise["epoch"];
        return SignPricingConfig(body, principalSecret);
    }
}
