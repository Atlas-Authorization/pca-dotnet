// Optimistic-path verification (extension layer): bonded claims, the challenge window, fraud proofs (wire level) and
// guardian-signed settlement records. Inputs are parsed JSON values; nothing here throws on hostile input.
//
// A fraud proof is only convincing because the settlement layer RE-RUNS the Policy VM on its server-held open-time snapshot;
// FraudProofWireCheck does not do that (no native SDK evaluates the Policy VM decision). It checks that the proof is well formed,
// names this claim and bond, and carries the decision its kind requires.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Bounds a claim's issued_at skew and window length (milliseconds).</summary>
public sealed record ChallengeWindowPolicy(double MinWindowMs, double MaxWindowMs, double MaxSkewMs)
{
    /// <summary>The library default (1 s minimum, 24 h maximum, 5 s skew).</summary>
    public static readonly ChallengeWindowPolicy Default = new(1000, 86_400_000, 5000);
}

public static class Optimistic
{
    public const string ClaimDomain = "atlas-pca/optimistic/v1\0";
    public const string SettlementDomain = "atlas-pca/bond-settlement/v1\0";
    const string Irreversible = "irreversible";
    const double DefaultRMargin = 1e-9;

    static double? Finite(object? v) => IntentJs.NumOf(v) is double d && double.IsFinite(d) ? d : null;

    /// <summary>A JSON object (and, like JavaScript, an array) is an object; anything else is not.</summary>
    static bool Obj(object? v, out D o)
    {
        o = v as D ?? new D();
        return v is D || v is L;
    }

    /// <summary>sig over domain || lenient-canonical(body); Canon is false when the lenient form refuses the body.</summary>
    static (bool Good, bool Canon) SignedLenient(string pub, string domain, D body, object? sig)
    {
        var c = JsCanon.Lenient(body);
        if (c == null) return (false, false);
        return (sig is string && Pca.VerifyEdInternal(pub, IntentJs.Utf8(domain + c), sig), true);
    }

    /// <summary>The FIRST check a bonded claim fails, or "ok": malformed, irreversible, digest, claimed_r, window, signature.</summary>
    public static string ClaimCheck(object? claim, string expectedPcactnDigest, string signerPublic, double serverNow, ChallengeWindowPolicy p)
    {
        try
        {
            if (!Obj(claim, out var c)) return "malformed";
            if (c.GetValueOrDefault("reversibility_class") as string == Irreversible) return "irreversible";
            if (c.GetValueOrDefault("pcactn_digest") is not string d || d != expectedPcactnDigest) return "digest";
            if (Finite(c.GetValueOrDefault("claimed_r")) == null) return "claimed_r";
            var issued = Finite(c.GetValueOrDefault("issued_at")); var window = Finite(c.GetValueOrDefault("challenge_window_ms"));
            if (issued == null || window == null || !double.IsFinite(serverNow) || Math.Abs(issued.Value - serverNow) > p.MaxSkewMs
                || window < p.MinWindowMs || window > p.MaxWindowMs) return "window";
            var body = c.Where(kv => kv.Key != "sig").ToDictionary(kv => kv.Key, kv => kv.Value);
            var (good, canon) = SignedLenient(signerPublic, ClaimDomain, body, c.GetValueOrDefault("sig"));
            return !canon ? "malformed" : !good ? "signature" : "ok";
        }
        catch (Exception) { return "malformed"; }
    }

    /// <summary>The last instant (epoch ms) at which a challenge is accepted: issued_at + window.</summary>
    public static double ChallengeWindowEnd(double issuedAt, double windowMs) => issuedAt + windowMs;

    /// <summary>True while challenges are accepted: now &lt;= issued_at + window (inclusive end).</summary>
    public static bool WithinChallengeWindow(double issuedAt, double windowMs, double now) => double.IsFinite(now) && now <= ChallengeWindowEnd(issuedAt, windowMs);

    /// <summary>"open" while challenges are accepted, else "finalized".</summary>
    public static string ClaimStatus(double issuedAt, double windowMs, double now) => WithinChallengeWindow(issuedAt, windowMs, now) ? "open" : "finalized";

    /// <summary>JavaScript === between two JSON members (numbers by value, otherwise by canonical form; both absent equal).</summary>
    static bool MemberEq(D m1, D m2, string k)
    {
        bool h1 = m1.TryGetValue(k, out var a), h2 = m2.TryGetValue(k, out var b);
        if (h1 != h2) return false;
        if (!h1) return true;
        if (IntentJs.NumOf(a) is double x) return IntentJs.NumOf(b) is double y && x == y;
        return Ledger.Same(a, b);
    }

    /// <summary>The first wire-level check a fraud proof fails against the claim it names, or "ok": malformed, digest, bond,
    /// claimed_r, kind, consistency.</summary>
    public static string FraudProofWireCheck(object? claim, object? proof)
    {
        try
        {
            if (claim is not D c || proof is not D p) return "malformed";
            if (p.GetValueOrDefault("decision") is not D d) return "malformed";
            if (d.GetValueOrDefault("releaseGuardianShare") is not bool rel || d.GetValueOrDefault("optimisticAllowed") is not bool opt
                || Finite(d.GetValueOrDefault("r")) is not double r || p.GetValueOrDefault("pcactn_digest") is not string
                || p.GetValueOrDefault("bond_ref") is not string || p.GetValueOrDefault("reason") is not string) return "malformed";
            if (!MemberEq(p, c, "pcactn_digest")) return "digest";
            if (!MemberEq(p, c, "bond_ref")) return "bond";
            if (!MemberEq(p, c, "claimed_r")) return "claimed_r";
            var kind = p.GetValueOrDefault("kind") as string;
            double margin = Finite(p.GetValueOrDefault("r_margin")) is double m ? Math.Max(0, m) : DefaultRMargin;
            bool holds;
            switch (kind)
            {
                case "irreversible":
                    {
                        var ev = "";
                        if (p.GetValueOrDefault("evidence") is D e && e.GetValueOrDefault("action") is D a && a.GetValueOrDefault("action") is D a2)
                            ev = a2.GetValueOrDefault("reversibility_class") as string ?? "";
                        holds = c.GetValueOrDefault("reversibility_class") as string == Irreversible || ev == Irreversible;
                        break;
                    }
                case "policy-denied": holds = !rel; break;
                case "optimistic-not-allowed": holds = rel && !opt; break;
                case "risk-understated": holds = Finite(c.GetValueOrDefault("claimed_r")) is double cr && rel && opt && r > cr + margin; break;
                default: return "kind";
            }
            return holds ? "ok" : "consistency";
        }
        catch (Exception) { return "malformed"; }
    }

    static bool NonEmpty(object? v) => v is string s && s.Length > 0;
    static double? NonNeg(object? v) => Finite(v) is double f && f >= 0 ? f : null;

    /// <summary>The first check a settlement record fails, or "ok": malformed, suite, shape, split, signature. The record's guardian
    /// signature is checked last, over the lenient canonical body without sig / pq_sig.</summary>
    public static string SettlementWireCheck(object? record, string guardianPublic, IReadOnlyDictionary<string, string>? pins = null)
    {
        try
        {
            if (record is not D r) return "malformed";
            // TS answers `suite` only for an alg outside the registry; a registered suite this SDK cannot verify (e.g. LESS without its native) is `suite` here too
            if (r.TryGetValue("alg", out var alg) && !(alg is string an && Pq.Suites.ContainsKey(an))) return "suite";
            var action = r.GetValueOrDefault("action") as string;
            bool slash = action == "slash";
            var amountN = Finite(r.GetValueOrDefault("amount"));
            double amount = amountN ?? 0;
            bool hasSplit = r.ContainsKey("split");
            var ev = r.GetValueOrDefault("evidenceDigest") as string;
            bool atOk = Finite(r.GetValueOrDefault("at")) != null;
            bool sigOk = r.GetValueOrDefault("sig") is string;
            bool epochOk = !r.TryGetValue("guardian_epoch", out var e) || (IntentJs.IsSafeInteger(e) && IntentJs.NumOf(e) >= 0);
            if (!NonEmpty(r.GetValueOrDefault("claimId")) || !(action == "open" || action == "release" || slash)
                || amountN == null || amount <= 0 || !NonEmpty(r.GetValueOrDefault("from")) || !NonEmpty(r.GetValueOrDefault("to")) || !atOk || ev == null
                || (slash && ev == "") || (!slash && ev != "")
                || (slash && r.GetValueOrDefault("split") is not D) || (!slash && hasSplit) || !sigOk || !epochOk) return "shape";
            if (slash)
            {
                var sp = (D)r["split"]!;
                var saN = IntentJs.NumOf(sp.GetValueOrDefault("amount")); double sa = saN ?? 0;
                var cr = NonNeg(sp.GetValueOrDefault("challengerReward")); var vc = NonNeg(sp.GetValueOrDefault("victimCompensation")); var tr = NonNeg(sp.GetValueOrDefault("treasuryRemainder"));
                var to = r.GetValueOrDefault("to") as string;
                bool conserved = sa == amount && cr != null && vc != null && tr != null && (cr.Value + vc.Value) + tr.Value == amount
                    && NonEmpty(sp.GetValueOrDefault("victimAccount")) && sp.GetValueOrDefault("treasuryAccount") is string ta && ta == to;
                if (conserved)
                {
                    if (sp.GetValueOrDefault("challengerAccount") == null)
                        conserved = sp.ContainsKey("challengerAccount") && cr == 0 && vc == 0 && tr == amount;
                    else conserved = NonEmpty(sp["challengerAccount"]);
                }
                conserved = conserved && saN != null;
                if (!conserved) return "split";
            }
            var body = r.Where(kv => kv.Key is not ("sig" or "pq_sig")).ToDictionary(kv => kv.Key, kv => kv.Value);
            var c = JsCanon.Lenient(body);
            if (c == null) return "malformed";
            // the signed body keeps alg / pq_pk (TS verifySettlement); every suite the SDK verifies, PQ only under a pin
            bool good = IntentJs.VerifyPinnedSuite(r.GetValueOrDefault("alg"), r.ContainsKey("alg"), guardianPublic, r.GetValueOrDefault("pq_pk"),
                IntentJs.Utf8(SettlementDomain + c), r["sig"], r.GetValueOrDefault("pq_sig"), pins);
            return good ? "ok" : "signature";
        }
        catch (Exception) { return "malformed"; }
    }
}
