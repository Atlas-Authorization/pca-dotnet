// Reputation and underwriting of the reference (reputation.ts, reputation-evidence.ts): a score from an agent's activity and its settled disputes, the
// price of coverage for a score, signed coverage quotes, and disputes from guardian-signed settlement records. Values are the JSON tree; a reference
// throw is an exception and an absent member is "undefined".
using System.Globalization;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class Reputation
{
    public const int MaxRecords = 100_000;
    public const string QuoteDomain = "atlas-pca/coverage-quote/v1\0";
    static readonly HashSet<string> Outcomes = new(StringComparer.Ordinal) { "auto", "step_up", "deny", "executed" };

    static readonly object Undef = new();
    static bool Has(object? v) => !ReferenceEquals(v, Undef);

    static object? Prop(object? o, string k)
    {
        if (o == null || !Has(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static object? PropOpt(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;

    static bool IsNumber(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d);
    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;
    static object NumOut(double d) => double.IsFinite(d) ? Facade.JsNumber(d) : d;
    static string Js(double d) => JsJson.NumberToString(d);

    /// <summary>JavaScript's <c>toFixed</c> (exact decimal expansion, ties to the larger value) for the non-negative values the wording uses.</summary>
    static string Fixed(double d, int digits) => AtlasPca.Research.Immune.ToFixed(d, digits); // toFixed: a tie rounds up

    public static D Constants() => new() { ["MAX_REPUTATION_RECORDS"] = IntentJs.OfLong(MaxRecords), ["COVERAGE_QUOTE_DOMAIN"] = QuoteDomain };

    /// <summary>Why a reputation input is refused, or null: a non-empty string subject, array events and disputes of at most 100 000 records, known event outcomes,
    /// and disputes with an id, this subject, a boolean <c>slashed</c> and a finite non-negative <c>at</c> (and <c>amount</c> when present).</summary>
    public static string? Validate(object? input)
    {
        if (PropOpt(input, "subject") is not string { Length: > 0 } subject) return "subject must be a non-empty string";
        // an absent member defaults to []; a member that is JSON null is not an array
        object? Member(string k) => input is D d && d.TryGetValue(k, out var v) ? v : new L();
        if (Member("events") is not L el || Member("disputes") is not L dl) return "events and disputes must be arrays";
        if (el.Count > MaxRecords || dl.Count > MaxRecords) return "too many records";
        if (el.Any(e => PropOpt(e, "outcome") is not string o || !Outcomes.Contains(o))) return "event with an unknown outcome";
        foreach (var d in dl)
        {
            if (PropOpt(d, "id") is not string { Length: > 0 }) return "dispute without an id";
            if (!(PropOpt(d, "subject") is string ds && ds == subject)) return "dispute for another subject";
            if (PropOpt(d, "slashed") is not bool) return "dispute.slashed must be a boolean";
            var at = PropOpt(d, "at");
            if (!IsNumber(at) || Dv(at) < 0) return "dispute.at must be finite and >= 0";
            var amount = PropOpt(d, "amount");
            if (Has(amount) && (!IsNumber(amount) || Dv(amount) < 0)) return "dispute.amount must be finite and >= 0";
        }
        return null;
    }

    static D Rep(string subject, long actions, long autos, long stepUps, long denies, long slashes, long disputes, double score, params string[] factors) => new()
    {
        ["subject"] = subject, ["actions"] = IntentJs.OfLong(actions), ["autos"] = IntentJs.OfLong(autos), ["stepUps"] = IntentJs.OfLong(stepUps), ["denies"] = IntentJs.OfLong(denies),
        ["slashes"] = IntentJs.OfLong(slashes), ["disputes"] = IntentJs.OfLong(disputes), ["score"] = NumOut(score), ["factors"] = factors.Cast<object?>().ToList(),
    };

    /// <summary>A score in [0, 1] from the activity and the settled disputes (a dispute id counts once): <c>{subject, actions, autos, stepUps, denies, slashes, disputes,
    /// score, factors}</c>. No history is 0.5 ("unproven"); an invalid input is score 0 with the reason as its factor.</summary>
    public static D Score(object? input)
    {
        if (Validate(input) is { } bad)
        {
            var s = PropOpt(input, "subject");
            return Rep(!Has(s) || s == null ? "" : JsJson.ToJsString(s), 0, 0, 0, 0, 0, 0, 0, "invalid input: " + bad);
        }
        var subject = (string)((D)input!)["subject"]!;
        var events = (((D)input!).GetValueOrDefault("events") as L) ?? new L();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var disputes = ((((D)input!).GetValueOrDefault("disputes") as L) ?? new L()).Where(d => seen.Add((string)((D)d!)["id"]!)).ToList();
        long actions = events.Count;
        long autos = events.Count(e => (string)((D)e!)["outcome"]! == "auto"), stepUps = events.Count(e => (string)((D)e!)["outcome"]! == "step_up"), denies = events.Count(e => (string)((D)e!)["outcome"]! == "deny");
        long slashes = disputes.Count(d => ((D)d!)["slashed"] is true);
        if (actions == 0 && disputes.Count == 0) return Rep(subject, actions, autos, stepUps, denies, slashes, disputes.Count, 0.5, "unproven (no history)");
        var factors = new List<string>();
        double score = 1;
        if (actions > 0)
        {
            double denyRate = (double)denies / actions, stepUpRate = (double)stepUps / actions;
            if (denyRate > 0) { score -= 0.6 * denyRate; factors.Add($"deny rate {Fixed(denyRate * 100, 0)}%"); }
            if (stepUpRate > 0) { score -= 0.15 * stepUpRate; factors.Add($"step-up rate {Fixed(stepUpRate * 100, 0)}%"); }
        }
        if (slashes > 0)
        {
            score -= Math.Min(0.8, 0.3 * slashes);
            factors.Add($"{slashes} slashed dispute{(slashes > 1 ? "s" : "")}");
        }
        if (factors.Count == 0) factors.Add("clean history");
        return Rep(subject, actions, autos, stepUps, denies, slashes, disputes.Count, Math.Max(0, Math.Min(1, score)), factors.ToArray());
    }

    // ---- pricing

    static double Opt(object? opts, string key, double dflt) => PropOpt(opts, key) is { } v && Has(v) && IntentJs.NumOf(v) is double d ? d : dflt;

    static D Priced(bool declined, double premium, double coverage, string rationale) =>
        new() { ["declined"] = declined, ["premium"] = NumOut(premium), ["coverage"] = NumOut(coverage), ["rationale"] = rationale };

    /// <summary>The price of coverage for <c>{score}</c> and an exposure: <c>{declined, premium, coverage, rationale}</c>. A score that is not a number in [0, 1], or below the
    /// underwriting floor, is declined. <paramref name="opts"/>: <c>{baseRate?, riskLoad?, minScore?}</c> (defaults 0.01, 4, 0.25).</summary>
    public static D PriceCoverage(object? rep, object? exposure, object? opts = null)
    {
        double baseRate = Opt(opts, "baseRate", 0.01), riskLoad = Opt(opts, "riskLoad", 4), minScore = Opt(opts, "minScore", 0.25);
        var scoreO = Prop(rep, "score");
        if (!IsNumber(scoreO) || Dv(scoreO) < 0 || Dv(scoreO) > 1) return Priced(true, 0, 0, "invalid reputation score");
        double score = Dv(scoreO), exp = IsNumber(exposure) ? Math.Max(0, Dv(exposure)) : 0;
        if (score < minScore) return Priced(true, 0, 0, $"reputation {Fixed(score, 2)} below underwriting floor {Js(minScore)}");
        double load = 1 + riskLoad * (1 - score);
        return Priced(false, baseRate * exp * load, exp, $"base {Js(baseRate)} × exposure {Js(exp)} × load {Fixed(load, 2)} (score {Fixed(score, 2)})");
    }

    // ---- signed coverage quotes

    static byte[] QuoteMessage(D claim) =>
        [.. Encoding.UTF8.GetBytes(QuoteDomain), .. Encoding.UTF8.GetBytes(JsCanon.Lenient(claim) ?? throw new InvalidOperationException("canonicalize: non-finite number"))];

    /// <summary>A signed, expiring quote for a reputation record and an exposure. Throws on a negative or non-numeric exposure, a clock or ttl that is not finite (ttl &gt; 0), a score
    /// outside [0, 1] or a value the canonical form refuses.</summary>
    public static D IssueCoverageQuote(object? rep, object? exposure, byte[] underwriterSecret, object? now, object? ttlMs, object? opts = null)
    {
        if (!IsNumber(exposure) || Dv(exposure) < 0) throw new ArgumentException("issueCoverageQuote: exposure must be finite and >= 0");
        if (!IsNumber(now) || !(IntentJs.NumOf(ttlMs) > 0) || !IsNumber(ttlMs)) throw new ArgumentException("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0");
        var scoreO = Prop(rep, "score");
        if (!IsNumber(scoreO) || Dv(scoreO) < 0 || Dv(scoreO) > 1) throw new ArgumentException("issueCoverageQuote: invalid reputation score");
        double baseRate = Opt(opts, "baseRate", 0.01), riskLoad = Opt(opts, "riskLoad", 4), minScore = Opt(opts, "minScore", 0.25);
        var p = PriceCoverage(rep, exposure, new D { ["baseRate"] = NumOut(baseRate), ["riskLoad"] = NumOut(riskLoad), ["minScore"] = NumOut(minScore) });
        var key = EdKey.FromSeed(underwriterSecret);
        var claim = new D
        {
            ["v"] = IntentJs.OfLong(1), ["subject"] = Prop(rep, "subject"), ["score"] = scoreO, ["exposure"] = exposure, ["baseRate"] = NumOut(baseRate), ["riskLoad"] = NumOut(riskLoad),
            ["minScore"] = NumOut(minScore), ["declined"] = p["declined"], ["premium"] = p["premium"], ["coverage"] = p["coverage"], ["issued_at"] = now,
            ["expires_at"] = NumOut(Dv(now) + Dv(ttlMs)), ["underwriter"] = key.Id,
        };
        return new D(claim) { ["sig"] = Pca.B64u(key.Sign(QuoteMessage(claim))) };
    }

    /// <summary>Verify a quote offline: <c>{ok: true}</c> or <c>{ok: false, reason}</c> with reason one of malformed, underwriter, signature, not-yet-valid, expired,
    /// price-mismatch (the price is recomputed from the quote's own score, exposure and rates). Never throws.</summary>
    public static D VerifyCoverageQuote(object? quote, object? underwriter, object? now)
    {
        static D No(string r) => new() { ["ok"] = false, ["reason"] = r };
        try
        {
            if (quote is not D q || !(IntentJs.NumOf(q.GetValueOrDefault("v")) == 1) || q.GetValueOrDefault("sig") is not string sig) return No("malformed");
            if (new[] { "score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at" }.Any(k => !IsNumber(q.GetValueOrDefault(k)))
                || q.GetValueOrDefault("declined") is not bool declined || q.GetValueOrDefault("subject") is not string) return No("malformed");
            if (underwriter is not string uw || !(q.GetValueOrDefault("underwriter") is string qu && qu == uw)) return No("underwriter");
            var claim = q.Where(kv => kv.Key != "sig").ToDictionary(kv => kv.Key, kv => kv.Value);
            if (!Pca.VerifyEdInternal(qu, QuoteMessage(claim), sig)) return No("signature");
            if (!IsNumber(now) || Dv(now) < Dv(q["issued_at"])) return No("not-yet-valid");
            if (Dv(now) >= Dv(q["expires_at"])) return No("expired");
            var p = PriceCoverage(new D { ["score"] = q["score"] }, q["exposure"], new D { ["baseRate"] = q["baseRate"], ["riskLoad"] = q["riskLoad"], ["minScore"] = q["minScore"] });
            if ((bool)p["declined"]! != declined || !SameNumber(p["premium"], q["premium"]) || !SameNumber(p["coverage"], q["coverage"])) return No("price-mismatch");
            return new D { ["ok"] = true };
        }
        catch (Exception) { return No("malformed"); }
    }

    static bool SameNumber(object? a, object? b) => IntentJs.NumOf(a) == IntentJs.NumOf(b);

    // ---- disputes from settlements

    /// <summary>Disputes from guardian-signed settlement records (reputation-evidence.ts): <c>{disputes, rejected}</c>. A record whose claim has no subject
    /// (<paramref name="subjectOf"/> returns null) or whose signature does not verify under <paramref name="guardianPublicKey"/> is rejected; an open bond is no outcome.</summary>
    public static D DisputesFromSettlements(object? records, string guardianPublicKey, Func<string, string?> subjectOf, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (records is not L list) throw new InvalidOperationException("records is not iterable");
        var disputes = new L();
        long rejected = 0;
        foreach (var r in list)
        {
            var subject = r is D rd && rd.GetValueOrDefault("claimId") is string cid ? subjectOf(cid) : null;
            if (subject == null || !BondSettlement.VerifySettlement(r, guardianPublicKey, pins)) { rejected++; continue; }
            var rec = (D)r!;
            if (rec.GetValueOrDefault("action") is "open") continue;
            var dispute = new D { ["id"] = BondSettlement.SettlementRecordDigest(rec), ["subject"] = subject, ["slashed"] = rec.GetValueOrDefault("action") is "slash", ["at"] = PropOpt(rec, "at") is { } at && Has(at) ? at : null };
            if (rec.TryGetValue("amount", out var amount)) dispute["amount"] = amount;
            disputes.Add(dispute);
        }
        return new D { ["disputes"] = disputes, ["rejected"] = IntentJs.OfLong(rejected) };
    }
}
