// Runtime conformance: how an action the grant admits is routed (deny / allow / optimistic / jit-consent) from the map's posterior, the
// judge-panel hook and its intent-conformance attestation (IC-Att), re-verification of an IC-Att, recording a just-in-time consent
// decision as a runtime observation, the bond sizing of optimistic claims and the k-of-n semantic judge threshold.
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

/// <summary>Bond sizing for optimistic claims: max(floor, curve(k, exposure)) on the micro grid, linear by default, optionally convex.</summary>
public static class IntentBond
{
    public const double MicrosPerUnit = 1_000_000;
    const double MaxSafeMicros = 1e15;

    public sealed record Tier(double UpTo, double MarginalK);

    /// <summary>The sizing and per-depositor cap policy; CurveKind is null/linear, power (gamma) or piecewise (tiers).</summary>
    public sealed class BondPolicy
    {
        public double Floor = 1, K = 1, MaxOpenClaims = 100, MaxOpenAmount = double.PositiveInfinity;
        public string? CurveKind;
        public double Gamma = double.NaN;
        public List<Tier>? Tiers;
        public bool TiersIsArray = true;

        public static BondPolicy FromJson(object? o)
        {
            var m = Obj(o);
            var p = new BondPolicy
            {
                Floor = NumOr(m.GetValueOrDefault("floor")), K = NumOr(m.GetValueOrDefault("k")), MaxOpenClaims = NumOr(m.GetValueOrDefault("maxOpenClaims")),
                MaxOpenAmount = m.GetValueOrDefault("maxOpenAmount") == null ? double.PositiveInfinity : NumOr(m["maxOpenAmount"]),
            };
            if (m.GetValueOrDefault("curve") != null)
            {
                var c = Obj(m["curve"]);
                p.CurveKind = c.GetValueOrDefault("kind") as string;
                if (c.ContainsKey("gamma")) p.Gamma = NumOr(c["gamma"]);
                if (c.ContainsKey("tiers"))
                {
                    if (c["tiers"] is L)
                    {
                        p.Tiers = new List<Tier>();
                        foreach (var t in Arr(c["tiers"])) p.Tiers.Add(new Tier(NumOr(Obj(t).GetValueOrDefault("upTo")), NumOr(Obj(t).GetValueOrDefault("marginalK"))));
                    }
                    else p.TiersIsArray = false;
                }
            }
            return p;
        }
    }

    static double NumOr(object? o) => o != null && IsNum(o) ? Dbl(o) : double.NaN;

    public static readonly BondPolicy DefaultBondPolicy = new();

    /// <summary>Round an amount up onto the micro grid (a micro amount round-trips exactly; amounts too large for it are unchanged).</summary>
    public static double QuantizeUp(double x)
    {
        if (!double.IsFinite(x) || x <= 0) return x;
        double scaled = x * MicrosPerUnit;
        if (scaled > MaxSafeMicros) return x;
        double r = IntentMath.JsRound(scaled);
        double m = r / MicrosPerUnit == x || Math.Abs(scaled - r) <= 1e-3 ? r : Math.Ceiling(scaled);
        return m / MicrosPerUnit;
    }

    static double CurveComponent(BondPolicy p, double e)
    {
        var kind = p.CurveKind;
        if (kind == null || kind == "linear") return p.K * e;
        if (kind == "power")
        {
            if (!(double.IsFinite(p.Gamma) && p.Gamma >= 1)) throw new ArgumentException("bondAmount: power curve requires finite gamma >= 1");
            return p.K * Math.Pow(e, p.Gamma);
        }
        if (!p.TiersIsArray || p.Tiers == null || p.Tiers.Count == 0) throw new ArgumentException("bondAmount: piecewise curve requires at least one tier");
        double acc = 0, prevUpTo = 0, prevMarginal = 0;
        foreach (var t in p.Tiers)
        {
            if (!(double.IsFinite(t.UpTo) && t.UpTo > prevUpTo) && t.UpTo != double.PositiveInfinity) throw new ArgumentException("bondAmount: piecewise tier `upTo` must be strictly increasing");
            if (!(double.IsFinite(t.MarginalK) && t.MarginalK >= 0)) throw new ArgumentException("bondAmount: piecewise `marginalK` must be a finite number >= 0");
            if (t.MarginalK < prevMarginal) throw new ArgumentException("bondAmount: piecewise marginal rates must be non-decreasing (convex)");
            double width = Math.Min(e, t.UpTo) - prevUpTo;
            if (width > 0) acc += width * t.MarginalK;
            prevUpTo = t.UpTo;
            prevMarginal = t.MarginalK;
            if (e <= t.UpTo) break;
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal;
        return p.K * acc;
    }

    /// <summary>The bond for an exposure; a non-finite or non-positive exposure gives the floor.</summary>
    public static double BondAmount(BondPolicy policy, double exposure)
    {
        double e = double.IsFinite(exposure) && exposure > 0 ? exposure : 0;
        return QuantizeUp(Math.Max(policy.Floor, CurveComponent(policy, e)));
    }
}

/// <summary>The k-of-n semantic judge threshold: signed judge verdicts bound to one action and goal, one key one vote, an optional split-conformal
/// cutoff on the aggregate score. Verdicts are JSON {judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?, pq_pk?, pq_sig?}.
/// The attested-judge gate is injected as a predicate over a verdict: when given, a verdict it rejects does not vote.</summary>
public static class IntentSemantic
{
    public const string SemanticJudgeDomain = "atlas-pca/semantic-judge/v1\0";
    public const double ScoreScale = 1_000_000;

    /// <summary>A score on the integer grid [0, 1e6]; non-finite is 0.</summary>
    public static long QuantizeScore(double score)
    {
        if (!double.IsFinite(score)) return 0;
        double q = IntentMath.JsRound(score * ScoreScale) + 0;
        return (long)(q < 0 ? 0 : q > ScoreScale ? ScoreScale : q);
    }

    /// <summary>The signed statement of a verdict (suite fields bound in for a non-ed25519 suite).</summary>
    public static D StatementOf(D v)
    {
        var jm = v.GetValueOrDefault("judgeMeasurement");
        var @base = new D
        {
            ["v"] = N(1),
            ["actionDigest"] = v.GetValueOrDefault("actionDigest"),
            ["goalCommitment"] = v.GetValueOrDefault("goalCommitment"),
            ["faithful"] = v.GetValueOrDefault("faithful") is true,
            ["score_ppm"] = N(QuantizeScore(IntentJs.NumOf(v.GetValueOrDefault("score")) ?? double.NaN)),
            ["judgeMeasurement"] = jm == null ? "" : jm is string ? jm : IsNum(jm) ? JsX.JsNumString(Dbl(jm)) : JsX.Str(jm),
        };
        return IntentJs.BindSuiteFields(@base, v.GetValueOrDefault("alg"), v.ContainsKey("alg"), v.GetValueOrDefault("pq_pk"), v.ContainsKey("pq_pk"));
    }

    static Dictionary<string, string>? Pins(D? pqPins)
    {
        if (pqPins == null) return null;
        var o = new Dictionary<string, string>();
        foreach (var e in pqPins) if (e.Value is string pv) o[e.Key] = pv;
        return o;
    }

    /// <summary>Verify ONE verdict against an expected action / goal binding. Total: never throws.</summary>
    public static bool VerifyJudgeVerdict(object? vo, string? expectedAction, string? expectedGoal, D? pqPins)
    {
        try
        {
            if (vo is not D v) return false;
            if (v.GetValueOrDefault("judge") is not string judge || !IntentJs.B32(judge)) return false;
            if (v.GetValueOrDefault("actionDigest") is not string ad || v.GetValueOrDefault("goalCommitment") is not string gc) return false;
            if (ad != expectedAction || gc != expectedGoal) return false;
            if (v.GetValueOrDefault("faithful") is not bool) return false;
            var score = IntentJs.NumOf(v.GetValueOrDefault("score"));
            if (score == null || !double.IsFinite(score.Value) || score < 0 || score > 1) return false;
            if (v.GetValueOrDefault("judgeMeasurement") is not string) return false;
            if (v.GetValueOrDefault("sig") is not string) return false;
            bool algPresent = v.ContainsKey("alg");
            if (IntentJs.SuiteOf(v.GetValueOrDefault("alg"), algPresent) == null) return false;
            var msg = IntentJs.Message(SemanticJudgeDomain, StatementOf(v));
            return IntentJs.VerifyPinnedSuite(v.GetValueOrDefault("alg"), algPresent, judge, v.GetValueOrDefault("pq_pk"), msg, v.GetValueOrDefault("sig"), v.GetValueOrDefault("pq_sig"), Pins(pqPins));
        }
        catch (Exception)
        {
            return false;
        }
    }

    static double ClampAlpha(object? alpha)
    {
        double? a = alpha != null && IsNum(alpha) ? Dbl(alpha) : null;
        if (a == null || !double.IsFinite(a.Value)) return 1;
        if (a <= 0) return double.Epsilon;
        return a > 1 ? 1 : a.Value;
    }

    static bool UnfaithfulSample(object? so, out double score)
    {
        score = 0;
        if (so is not D s) return false;
        var sc = s.GetValueOrDefault("score");
        if (s.GetValueOrDefault("faithful") is false && sc != null && IsNum(sc) && double.IsFinite(Dbl(sc))) { score = Dbl(sc); return true; }
        return false;
    }

    static List<double> Unfaithful(object? samples)
    {
        var o = new List<double>();
        if (samples is not L l) return o;
        foreach (var so in l) if (UnfaithfulSample(so, out var sc)) o.Add(sc);
        return o;
    }

    /// <summary>The split-conformal upper quantile of the unfaithful scores (+Infinity when too few to certify alpha).</summary>
    public static double ConformalThreshold(object? calibration)
    {
        var c = calibration as D;
        double alpha = ClampAlpha(c?.GetValueOrDefault("alpha"));
        var u = Unfaithful(c?.GetValueOrDefault("samples"));
        int m = u.Count;
        if (m == 0) return double.PositiveInfinity;
        double rank = Math.Ceiling((m + 1) * (1 - alpha));
        if (rank > m) return double.PositiveInfinity;
        u.Sort();
        return u[(int)Math.Max(rank, 1) - 1];
    }

    /// <summary>Fraction of the unfaithful samples whose score exceeds the cutoff (0 with none).</summary>
    public static double EmpiricalFalseAllowRate(object? samples, double cutoff)
    {
        int m = 0, allowed = 0;
        if (samples is L l)
            foreach (var so in l)
                if (UnfaithfulSample(so, out var sc)) { m++; if (sc > cutoff) allowed++; }
        return m == 0 ? 0 : (double)allowed / m;
    }

    static string JsStrOf(object? k) => k == null ? "null" : IsNum(k) ? JsX.JsNumString(Dbl(k)) : k is bool b ? (b ? "true" : "false") : k.ToString() ?? "null";

    /// <summary>The verdict of a threshold check.</summary>
    public sealed record ThresholdResult(bool Ok, int AgreeCount, double AggregateScore, double? Cutoff, string? Reason)
    {
        public D ToJson()
        {
            var r = new D { ["ok"] = Ok, ["agreeCount"] = N(AgreeCount), ["aggregateScore"] = N(AggregateScore) };
            if (Cutoff != null) r["cutoff"] = N(Cutoff.Value);
            if (Reason != null) r["reason"] = Reason;
            return r;
        }
    }

    static ThresholdResult Fail(string reason) => new(false, 0, 0, null, reason);

    /// <summary>Verify a k-of-n ensemble. opts: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?. attestationGate (optional) must accept a verdict for it to vote.</summary>
    public static ThresholdResult VerifySemanticThreshold(object? verdicts, D opts, Func<D, bool>? attestationGate = null)
    {
        var k = opts.GetValueOrDefault("k");
        var allow = new HashSet<string>(StringComparer.Ordinal);
        if (opts.GetValueOrDefault("judgeKeys") is L keys)
            foreach (var key in keys) if (key is string ks && IntentJs.B32(ks)) allow.Add(ks);
        if (opts.GetValueOrDefault("actionDigest") is not string ad || opts.GetValueOrDefault("goalCommitment") is not string gc) return Fail("missing action/goal binding");
        double? kd = k != null && IsNum(k) ? Dbl(k) : null;
        if (kd == null || !double.IsFinite(kd.Value) || kd != Math.Floor(kd.Value) || kd < 1) return Fail("invalid quorum k=" + (opts.ContainsKey("k") ? JsStrOf(k) : "undefined"));
        var pins = opts.GetValueOrDefault("pqPins") as D;
        var byJudge = new List<(string Judge, HashSet<bool> Faithful, HashSet<long> Scores)>();
        if (verdicts is L vl)
        {
            foreach (var vo in vl)
            {
                if (vo is not D v || v.GetValueOrDefault("judge") is not string judge || !allow.Contains(judge)) continue;
                if (!VerifyJudgeVerdict(v, ad, gc, pins)) continue;
                if (attestationGate != null && !attestationGate(v)) continue;
                var g = byJudge.Find(x => x.Judge == judge);
                if (g.Judge == null) { g = (judge, new HashSet<bool>(), new HashSet<long>()); byJudge.Add(g); }
                g.Faithful.Add(v.GetValueOrDefault("faithful") is true);
                g.Scores.Add(QuantizeScore(Dbl(v.GetValueOrDefault("score"))));
            }
        }
        var agreeing = new List<(string Judge, long Score)>();
        foreach (var e in byJudge)
            if (e.Faithful.Count == 1 && e.Faithful.Contains(true) && e.Scores.Count == 1) agreeing.Add((e.Judge, e.Scores.First()));
        agreeing.Sort((a, b) => IntentJs.CompareUtf8(a.Judge, b.Judge));
        int agree = agreeing.Count;
        double acc = 0;
        foreach (var a in agreeing) acc += (double)a.Score / ScoreScale;
        double aggregate = agree == 0 ? 0 : acc / agree;
        if (agree < kd) return new ThresholdResult(false, agree, aggregate, null, "only " + agree + " distinct trusted judge(s) agree, need " + JsStrOf(k));
        if (opts.GetValueOrDefault("calibration") != null)
        {
            double cutoff = ConformalThreshold(opts["calibration"]);
            if (!(aggregate > cutoff))
                return new ThresholdResult(false, agree, aggregate, cutoff, "aggregateScore " + JsX.JsNumString(aggregate) + " does not exceed calibrated cutoff " + JsX.JsNumString(cutoff));
            return new ThresholdResult(true, agree, aggregate, cutoff, null);
        }
        return new ThresholdResult(true, agree, aggregate, null, null);
    }
}

/// <summary>The pure parts of runtime intent conformance: the judge input and the PCActn action shape for an outcome, the content addresses of the
/// conformance attestation, the calibration set and the just-in-time consent request, the consent prompt, and the monotone risk fold.</summary>
public static class IntentRuntime
{
    public const string IcAttDomain = "atlas-pca/intent-ic-att/v1";

    /// <summary>Deep copy with every double spelled as the JSON number JavaScript would print (hashed trees carry Num).</summary>
    internal static object? JsonNums(object? v) => v switch
    {
        double d => new Num(JsX.JsNumString(d)),
        D m => m.ToDictionary(e => e.Key, e => JsonNums(e.Value)),
        L l => l.Select(JsonNums).ToList(),
        _ => v,
    };

    /// <summary>The PCActn action shape for an outcome (params digest by the canonical rule).</summary>
    public static D PcactnActionOf(VerbSpace vs, Outcome o)
    {
        var a = IntentPolicyKit.OutcomeToAction(vs, o);
        return new D
        {
            ["verb"] = a["verb"],
            ["resource"] = a["resource"],
            ["params_digest"] = Pca.ParamsDigest(a.GetValueOrDefault("params") == null ? new D() : JsonNums(a["params"])),
            ["reversibility_class"] = vs.Reversibility,
        };
    }

    /// <summary>The digest every verdict must bind to.</summary>
    public static string ActionDigest(object? action) => Pca.HashCanonical(action);

    /// <summary>Digest of a verdict (strict canonical over the full verdict).</summary>
    public static string VerdictDigest(object? verdict) => Pca.HashCanonical(verdict);

    /// <summary>What every judge sees; p is the map's acceptance of the outcome; ctx: intentRef, mapDigest, statementText, slots, goalCommitment.</summary>
    public static D JudgeInputOf(VerbSpace vs, Outcome o, double p, D ctx)
    {
        var o2 = new D(ctx)
        {
            ["renderedAction"] = IntentRender.RenderAction(vs, o.Values),
            ["p"] = N(p),
            ["reversibility"] = vs.Reversibility,
            ["actionDigest"] = ActionDigest(PcactnActionOf(vs, o)),
        };
        return o2;
    }

    /// <summary>Digest of a calibration set ({alpha, samples: [{score, faithful}]}).</summary>
    public static string CalibrationDigest(D c)
    {
        var samples = new L();
        foreach (var s in Arr(c.GetValueOrDefault("samples"))) samples.Add(new D { ["score"] = Obj(s).GetValueOrDefault("score"), ["faithful"] = Obj(s).GetValueOrDefault("faithful") });
        return Pca.HashCanonical(new D { ["d"] = "atlas-pca/intent-calibration/v1", ["alpha"] = c.GetValueOrDefault("alpha"), ["samples"] = samples });
    }

    /// <summary>Content address of an IC-Att (the value a PCActn carries as ic_att_digest).</summary>
    public static string IcAttDigest(object? att) => Pca.HashCanonical(new D { ["d"] = IcAttDomain, ["a"] = att });

    /// <summary>The risk contribution of an aggregate judge score: 1 - score clamped to [0, 1] (1 when not finite).</summary>
    public static double SemanticRiskContribution(double aggregateScore)
    {
        if (!double.IsFinite(aggregateScore)) return 1;
        double r = 1 - aggregateScore;
        return r < 0 ? 0 : r > 1 ? 1 : r;
    }

    /// <summary>The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r.</summary>
    public static double FoldSemanticRisk(double r, D att) => Math.Max(r, SemanticRiskContribution(Dbl(att.GetValueOrDefault("aggregate_score_ppm")) / 1_000_000));

    /// <summary>The consent prompt for an action; p is the map's acceptance of the outcome.</summary>
    public static D JitConsentRequest(VerbSpace vs, Outcome o, double p, string? intentRef, string? mapDigest) => new()
    {
        ["v"] = new Num("1"),
        ["kind"] = "pca-intent-jit",
        ["intent_ref"] = intentRef,
        ["map_digest"] = mapDigest,
        ["verb"] = o.Verb,
        ["values"] = JsonNums(new D(o.Values)),
        ["reversibility"] = vs.Reversibility,
        ["p_ppm"] = N(IntentMath.JsRound(p * 1_000_000)),
        ["text"] = IntentRender.RenderAction(vs, o.Values) + " This cannot be undone. Approve?",
    };

    public static string JitConsentDigest(object? request) => Pca.HashCanonical(new D { ["d"] = "atlas-pca/intent-jit/v1", ["r"] = request });
}

/// <summary>Routing decisions and the judge-panel conformance attestation over a learner.</summary>
public static class IntentRouting
{
    /// <summary>Routing options; every field optional (null = default): theta2 (0.5), hMax (the space's harm maximum), bondPolicy.</summary>
    public sealed class RouteOptions
    {
        public double? Theta2, HMax;
        public IntentBond.BondPolicy? BondPolicy;

        public static RouteOptions FromJson(object? o)
        {
            var r = new RouteOptions();
            if (o == null) return r;
            var m = Obj(o);
            r.Theta2 = IntentLearner.NumOrNull(m.GetValueOrDefault("theta2"));
            r.HMax = IntentLearner.NumOrNull(m.GetValueOrDefault("hMax"));
            if (m.GetValueOrDefault("bondPolicy") != null) r.BondPolicy = IntentBond.BondPolicy.FromJson(m["bondPolicy"]);
            return r;
        }
    }

    static VerbSpace? VerbOf(IntentLearner l, string verb) => l.Omega.Verbs.Find(v => v.Verb == verb);

    /// <summary>The routing decision {route, p, inGrant, vetoed, reversibility, harm, risk, judges, bond?, reason}.</summary>
    public static D RouteAction(IntentLearner l, Outcome o, RouteOptions? opts = null)
    {
        opts ??= new RouteOptions();
        var vs = VerbOf(l, o.Verb);
        var r = new D();
        if (vs == null || CellOf(vs, o) == null)
        {
            r["route"] = "deny"; r["p"] = N(0); r["inGrant"] = false; r["vetoed"] = false;
            r["reversibility"] = vs == null ? "unknown" : vs.Reversibility;
            r["harm"] = N(0); r["risk"] = N(1); r["judges"] = false;
            r["reason"] = "outside the Intent Map's outcome space";
            return r;
        }
        double p = l.Acceptance(o);
        bool inGrant = l.AdmitsOutcome(o);
        bool vetoed = l.IsVetoed(o);
        double harm = HarmOf(vs, o, l.Harm);
        double hMax = opts.HMax ?? HarmMax(l.Omega, l.Harm);
        double risk = Math.Min(1, Math.Max(0, ((1 - p) * harm) / (hMax > 0 ? hMax : 1)));
        double theta2 = opts.Theta2 ?? 0.5;
        r["p"] = N(p); r["inGrant"] = inGrant; r["vetoed"] = vetoed; r["reversibility"] = vs.Reversibility; r["harm"] = N(harm); r["risk"] = N(risk);
        if (!inGrant)
        {
            r["route"] = "deny"; r["judges"] = false;
            r["reason"] = vetoed ? "the cell was vetoed by a runtime divergence" : "outside the conservative grant (p_n < τ)";
            return r;
        }
        bool judges = vs.Reversibility == "irreversible" || p < 1 - 1e-12 || risk >= theta2;
        if (vs.Reversibility == "irreversible")
        {
            r["route"] = "jit-consent"; r["judges"] = judges;
            r["reason"] = "irreversible: just-in-time consent on the rendered action";
            return r;
        }
        if (judges)
        {
            r["route"] = "optimistic"; r["judges"] = true;
            r["bond"] = N(IntentBond.BondAmount(opts.BondPolicy ?? IntentBond.DefaultBondPolicy, harm));
            r["reason"] = p < 1 - 1e-12 ? "unconfirmed region (p_n < 1): bonded claim + judges" : "risk ≥ θ₂: bonded claim + judges";
            return r;
        }
        r["route"] = "allow"; r["judges"] = false;
        r["reason"] = "confirmed region, reversible, low risk";
        return r;
    }

    /// <summary>The judge input for an outcome: ctx = {intentRef, mapDigest, statementText, slots, goalCommitment}.</summary>
    public static D JudgeInputOf(IntentLearner l, Outcome o, D ctx)
    {
        var vs = VerbOf(l, o.Verb) ?? throw new ArgumentException("judgeInputOf: no verb " + o.Verb + " in Ω");
        return IntentRuntime.JudgeInputOf(vs, o, l.Acceptance(o), ctx);
    }

    /// <summary>The consent prompt for an action.</summary>
    public static D JitConsentRequest(IntentLearner l, Outcome o, string? intentRef, string? mapDigest)
    {
        var vs = VerbOf(l, o.Verb) ?? throw new ArgumentException("jitConsentRequest: no verb " + o.Verb + " in Ω");
        return IntentRuntime.JitConsentRequest(vs, o, l.Acceptance(o), intentRef, mapDigest);
    }

    /// <summary>Record the principal's consent decision (approve = 1, deny = 0 and the cell is vetoed) as a runtime observation.</summary>
    public static D RecordJitDecision(IntentLearner l, D req, string? decision)
    {
        var vals = new Dictionary<string, object?>();
        foreach (var e in Obj(req.GetValueOrDefault("values"))) vals[e.Key] = IsNum(e.Value) ? Dbl(e.Value) : e.Value;
        return IntentMapKit.ApplyDivergence(l, new Outcome((string)req["verb"]!, vals), decision == "approve" ? 1 : 0);
    }

    static object? ToPpm(double x) => double.IsFinite(x) ? N(IntentMath.JsRound(x * 1_000_000)) : null;

    /// <summary>Verify a panel's verdicts for one action and produce the IC-Att. opts: judgeKeys, k, calibration?, pqPins?.</summary>
    public static D IntentConformanceAttestation(D input, L verdicts, D opts, Func<D, bool>? attestationGate = null)
    {
        var o = new D
        {
            ["judgeKeys"] = opts.GetValueOrDefault("judgeKeys"), ["k"] = opts.GetValueOrDefault("k"),
            ["goalCommitment"] = input.GetValueOrDefault("goalCommitment"), ["actionDigest"] = input.GetValueOrDefault("actionDigest"),
        };
        if (opts.GetValueOrDefault("calibration") != null) o["calibration"] = opts["calibration"];
        if (opts.GetValueOrDefault("pqPins") != null) o["pqPins"] = opts["pqPins"];
        var r = IntentSemantic.VerifySemanticThreshold(verdicts, o, attestationGate);
        var digests = verdicts.Select(IntentRuntime.VerdictDigest).ToList();
        digests.Sort(StringComparer.Ordinal);
        var att = new D
        {
            ["v"] = N(1),
            ["kind"] = "pca-ic-att",
            ["intent_ref"] = input.GetValueOrDefault("intentRef"),
            ["map_digest"] = input.GetValueOrDefault("mapDigest"),
            ["action_digest"] = input.GetValueOrDefault("actionDigest"),
            ["goal_commitment"] = input.GetValueOrDefault("goalCommitment"),
            ["verdict_digests"] = digests.Select(x => (object?)x).ToList(),
            ["calibration_digest"] = opts.GetValueOrDefault("calibration") != null ? IntentRuntime.CalibrationDigest(Obj(opts["calibration"])) : null,
            ["k"] = opts.GetValueOrDefault("k"),
            ["ok"] = r.Ok,
            ["agree_count"] = N(r.AgreeCount),
            ["aggregate_score_ppm"] = ToPpm(r.AggregateScore) ?? N(0),
            ["cutoff_ppm"] = r.Cutoff != null ? ToPpm(r.Cutoff.Value) : null,
        };
        if (r.Reason != null) att["reason"] = r.Reason;
        return att;
    }

    /// <summary>Ask the panel and attest: {att, verdicts}.</summary>
    public static D CheckIntentConformance(Func<D, L> panel, D input, D opts, Func<D, bool>? attestationGate = null)
    {
        var verdicts = panel(input);
        return new D { ["att"] = IntentConformanceAttestation(input, verdicts, opts, attestationGate), ["verdicts"] = verdicts };
    }

    /// <summary>Re-verify an IC-Att from the verdicts it names: {ok, problems}.</summary>
    public static D VerifyIcAtt(object? att, D input, L verdicts, D opts, Func<D, bool>? attestationGate = null)
    {
        var again = IntentConformanceAttestation(input, verdicts, opts, attestationGate);
        var problems = new L();
        if (IntentRuntime.IcAttDigest(again) != IntentRuntime.IcAttDigest(att)) problems.Add("IC-Att does not match the recomputation from its verdicts");
        if (!(again["ok"] is true)) problems.Add("panel does not pass: " + (again.GetValueOrDefault("reason") ?? "unknown"));
        return new D { ["ok"] = problems.Count == 0, ["problems"] = problems };
    }
}
