// The behavioural immune system: the per-principal risk baseline, the observation fold (Observe), the state validation and the threat read
// (Assess), the adaptation of a base policy to a threat (Adapt) with its no-widen check, signed tightening proposals and a durable store.
// A heuristic (EWMA and z-score over one principal's history): it can be gamed by a slow attacker who drifts the baseline and is no proof that
// an agent is compromised or benign.
//
// An immune state is {baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}; an observation is {r, at, stepUp?, denied?}. JSON values
// are the core's: Dictionary<string, object?>, List<object?>, string, bool, Num.
using System.Numerics;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Research;

public static class Immune
{
    const double MaxCount = 1e9;
    const double Alpha = 0.3;
    const double HalfLifeMs = 3_600_000.0;
    const double DriftZSat = 3.0;
    const double StepUpSat = 5.0;
    const double DenySat = 3.0;

    /// <summary>The default read-side tuning (DEFAULT_IMMUNE_CONFIG): alpha, halfLifeMs, driftZSat, stepUpSat, denySat.</summary>
    public static readonly IReadOnlyDictionary<string, double> DefaultImmuneConfig = new Dictionary<string, double>
    { ["alpha"] = Alpha, ["halfLifeMs"] = HalfLifeMs, ["driftZSat"] = DriftZSat, ["stepUpSat"] = StepUpSat, ["denySat"] = DenySat };

    /// <summary>The default adaptation caps (DEFAULT_ADAPT_CONFIG): maxKappaMult 3, minThetaMult 0.4.</summary>
    public static readonly IReadOnlyDictionary<string, double> DefaultAdaptConfig = new Dictionary<string, double>
    { ["maxKappaMult"] = 3.0, ["minThetaMult"] = 0.4 };

    // ---- JavaScript value semantics over parsed JSON ----
    static Num N(double d) => new(JsX.JsNumString(d));
    static Num N(long l) => IntentJs.OfLong(l);
    static bool IsNum(object? x) => IntentJs.NumOf(x) is double d && !double.IsNaN(d);
    static bool IsFinite(object? x) => IntentJs.IsFinite(x);
    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;
    static double NumOrNaN(object? x) => IntentJs.NumOf(x) ?? double.NaN;

    /// <summary>JavaScript's ToNumber for a relational comparison: null is 0, a boolean 0 or 1, a numeric text its value, undefined and anything else NaN.</summary>
    static double ToNumber(object? x) => x switch
    {
        null => 0,
        bool b => b ? 1 : 0,
        string t => t.Trim().Length == 0 ? 0 : double.TryParse(t.Trim(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : double.NaN,
        _ => ReferenceEquals(x, JsX.Undef) ? double.NaN : IntentJs.NumOf(x) ?? double.NaN,
    };
    static object? Get(D m, string k) => m.TryGetValue(k, out var v) ? v : null;
    static object? At(D m, string k) => m.TryGetValue(k, out var v) ? v : JsX.Undef;
    static bool Same(object? a, object? b) => ReferenceEquals(a, b) || JsX.StrictEq(a, b);

    static string Lenient(object? v) => JsCanon.Lenient(v) ?? throw new InvalidOperationException("canonicalize: unsupported value");
    static string HashLenient(object? v) => Pca.B64u(Pca.Sha(Encoding.UTF8.GetBytes(Lenient(v))));

    // JavaScript x.toFixed(digits): the exact decimal expansion of the binary value, ties away from zero on the magnitude
    internal static string ToFixed(double x, int digits)
    {
        if (double.IsNaN(x)) return "NaN";
        if (double.IsInfinity(x)) return x > 0 ? "Infinity" : "-Infinity";
        if (Math.Abs(x) >= 1e21) return JsX.JsNumString(x);
        long bits = BitConverter.DoubleToInt64Bits(Math.Abs(x));
        int exp = (int)((bits >> 52) & 0x7ff);
        long frac = bits & 0xfffffffffffffL;
        BigInteger mant = exp == 0 ? frac : frac | (1L << 52);
        int e2 = (exp == 0 ? 1 : exp) - 1075;
        BigInteger scale = BigInteger.Pow(10, digits);
        BigInteger n;
        if (e2 >= 0) n = (mant << e2) * scale;
        else
        {
            var den = BigInteger.One << -e2;
            n = (2 * mant * scale + den) / (2 * den);
        }
        var t = n.ToString().PadLeft(digits + 1, '0');
        var s = digits == 0 ? t : t[..^digits] + "." + t[^digits..];
        return (x < 0 || (x == 0 && BitConverter.DoubleToInt64Bits(x) < 0) ? "-" : "") + s;
    }

    // ---- state ----

    /// <summary>The empty baseline {n: 0, mean: 0, m2: 0}.</summary>
    public static D EmptyBaseline() => new() { ["n"] = N(0L), ["mean"] = N(0L), ["m2"] = N(0L) };

    /// <summary>The state of a principal with no history.</summary>
    public static D InitialState() => new()
    {
        ["baseline"] = EmptyBaseline(), ["ewma"] = N(0L), ["stepUps"] = N(0L), ["denies"] = N(0L), ["lastAt"] = N(0L), ["seeded"] = false,
    };

    /// <summary>Welford update of a baseline with one risk sample (a non-finite sample counts as 0).</summary>
    public static D UpdateBaseline(D b, double r)
    {
        var x = double.IsNaN(r) || double.IsInfinity(r) ? 0.0 : r;
        var cnt = Dv(Get(b, "n")) + 1;
        var delta = x - Dv(Get(b, "mean"));
        var mean = Dv(Get(b, "mean")) + delta / cnt;
        var m2 = Dv(Get(b, "m2")) + delta * (x - mean);
        return new D { ["n"] = N(cnt), ["mean"] = N(mean), ["m2"] = N(m2) };
    }

    /// <summary>Population standard deviation of the baseline (0 until at least 2 samples).</summary>
    public static double BaselineStd(D b)
    {
        var cnt = Dv(Get(b, "n"));
        return cnt >= 2 ? Math.Sqrt(Dv(Get(b, "m2")) / cnt) : 0.0;
    }

    static double Cfg(IReadOnlyDictionary<string, double>? c, string k, double d) => c != null && c.TryGetValue(k, out var v) ? v : d;

    static double Decay(double count, double dtMs, double halfLifeMs) => dtMs <= 0 || count == 0.0 ? count : count * Math.Pow(0.5, dtMs / halfLifeMs);

    /// <summary>Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters).</summary>
    public static D Observe(D state, D obs, IReadOnlyDictionary<string, double>? config = null)
    {
        var alpha = Cfg(config, "alpha", Alpha);
        var halfLife = Cfg(config, "halfLifeMs", HalfLifeMs);
        var r = Math.Max(0.0, Math.Min(1.0, IsFinite(Get(obs, "r")) ? Dv(Get(obs, "r")) : 0.0));
        var lastAt = Dv(Get(state, "lastAt"));
        var at = IsFinite(Get(obs, "at")) ? Dv(Get(obs, "at")) : lastAt;
        var seeded = Get(state, "seeded") is true;
        var dt = seeded ? Math.Max(0.0, at - lastAt) : 0.0;
        var baseline = UpdateBaseline((D)Get(state, "baseline")!, r);
        var ewma = seeded ? alpha * r + (1 - alpha) * Dv(Get(state, "ewma")) : r;
        var stepUps = Decay(Dv(Get(state, "stepUps")), dt, halfLife) + (JsX.Truthy(Get(obs, "stepUp")) ? 1 : 0);
        var denies = Decay(Dv(Get(state, "denies")), dt, halfLife) + (JsX.Truthy(Get(obs, "denied")) ? 1 : 0);
        return new D { ["baseline"] = baseline, ["ewma"] = N(ewma), ["stepUps"] = N(stepUps), ["denies"] = N(denies), ["lastAt"] = N(at), ["seeded"] = true };
    }

    static bool InRange(object? x, double lo, double hi) => IsFinite(x) && Dv(x) >= lo && Dv(x) <= hi;
    static bool IsInteger(object? x) => Dv(x) == Math.Floor(Dv(x));
    static bool NegZero(object? x) => Dv(x) == 0.0 && double.IsNegative(Dv(x));

    /// <summary>The reason a state is malformed (non-finite, negative, out of bound), or null.</summary>
    public static string? ValidateImmuneState(object? s)
    {
        if (s == null || !(s is D || s is L)) return "state must be an object";
        var x = s as D ?? new D(); // an array is an object without members
        var braw = Get(x, "baseline");
        if (braw == null || !(braw is D || braw is L)) return "baseline missing";
        var b = braw as D ?? new D();
        if (!InRange(Get(b, "n"), 0.0, MaxCount) || !IsInteger(Get(b, "n")) || NegZero(Get(b, "n"))) return "baseline.n must be an integer in [0, 1e9]";
        if (!InRange(Get(b, "mean"), 0.0, 1.0)) return "baseline.mean must be in [0, 1]";
        if (!InRange(Get(b, "m2"), 0.0, MaxCount)) return "baseline.m2 must be finite and >= 0";
        if (!InRange(Get(x, "ewma"), 0.0, 1.0)) return "ewma must be in [0, 1]";
        if (!InRange(Get(x, "stepUps"), 0.0, MaxCount)) return "stepUps must be finite and >= 0";
        if (!InRange(Get(x, "denies"), 0.0, MaxCount)) return "denies must be finite and >= 0";
        if (!InRange(Get(x, "lastAt"), 0.0, 9007199254740991.0)) return "lastAt must be a finite non-negative time";
        if (Get(x, "seeded") is not bool) return "seeded must be a boolean";
        return null;
    }

    static double Clamp01(double x) => Math.Max(0.0, Math.Min(1.0, x));

    /// <summary>The current threat from the immune state: {level: calm|elevated|high, score, signals, components: {drift, volatility, violation}}. The score is
    /// the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A malformed state is the maximal threat.</summary>
    public static D Assess(object? state, IReadOnlyDictionary<string, double>? config = null)
    {
        var bad = ValidateImmuneState(state);
        if (bad != null) return Threat("high", 1.0, new L { "invalid immune state: " + bad }, 1.0, 1.0, 1.0);
        var st = (D)state!;
        var bs = (D)Get(st, "baseline")!;
        var std = BaselineStd(bs);
        var signals = new L();
        var drift = 0.0;
        if (Dv(Get(bs, "n")) >= 5 && std > 1e-9)
        {
            var z = (Dv(Get(st, "ewma")) - Dv(Get(bs, "mean"))) / std;
            drift = Clamp01(z / Cfg(config, "driftZSat", DriftZSat));
            if (drift > 0.33) signals.Add("risk drifted " + ToFixed(z, 1) + "σ above baseline");
        }
        var stepUps = Dv(Get(st, "stepUps"));
        var denies = Dv(Get(st, "denies"));
        var volatility = Clamp01(stepUps / Cfg(config, "stepUpSat", StepUpSat));
        if (volatility > 0.33) signals.Add("elevated step-up rate (" + ToFixed(stepUps, 1) + ")");
        var violation = Clamp01(denies / Cfg(config, "denySat", DenySat));
        if (violation > 0.33) signals.Add("repeated policy violations (" + ToFixed(denies, 1) + ")");
        var score = Math.Max(drift, Math.Max(volatility, violation));
        return Threat(score >= 0.66 ? "high" : score >= 0.33 ? "elevated" : "calm", score, signals, drift, volatility, violation);
    }

    static D Threat(string level, double score, L signals, double drift, double volatility, double violation) => new()
    {
        ["level"] = level, ["score"] = N(score), ["signals"] = signals,
        ["components"] = new D { ["drift"] = N(drift), ["volatility"] = N(volatility), ["violation"] = N(violation) },
    };

    // ---- adaptation ----

    /// <summary>The adapted policy for a threat assessment, derived from the BASE policy (never compounded): {policy, changed, rationale}. Default caps: kappa x3, theta x0.4.</summary>
    public static D Adapt(object? baseIn, D assessment, double maxKappaMult = 3.0, double minThetaMult = 0.4)
    {
        var bs = baseIn as D ?? new D(); // a non-object spreads to nothing
        var s = IsFinite(Get(assessment, "score")) ? Clamp01(Dv(Get(assessment, "score"))) : 1.0; // a non-finite score is the worst case, never calm
        if (s == 0.0) return Adaptation(baseIn, false, "calm — baseline policy");
        if (baseIn == null) throw new ArgumentException("base policy missing");
        var kappaMult = 1 + (maxKappaMult - 1) * s;
        var thetaMult = 1 - (1 - minThetaMult) * s;
        var policy = new D(bs);
        policy["weights"] = Get(bs, "weights") is D w ? new D(w) : new D();
        policy["kappa"] = N(NumOrNaN(Get(bs, "kappa")) * kappaMult);
        policy["theta1"] = N(Clamp01(NumOrNaN(Get(bs, "theta1")) * thetaMult));
        policy["theta2"] = N(Clamp01(NumOrNaN(Get(bs, "theta2")) * thetaMult));
        var bad = Pca.ValidateRiskPolicy(policy) ?? NoWidenViolation(bs, policy);
        if (bad != null) return Adaptation(baseIn, false, "adaptation rejected (" + bad + ") — kept baseline");
        var sig = Get(assessment, "signals") as L ?? throw new InvalidOperationException("TypeError: signals is not a list");
        var why = sig.Count > 0 ? string.Join("; ", sig.Select(JsX.Str)) : "threat score " + ToFixed(s, 2);
        return Adaptation(policy, true, JsX.Str(Get(assessment, "level")) + ": " + why + " → κ ×" + ToFixed(kappaMult, 2) + ", θ ×" + ToFixed(thetaMult, 2));
    }

    static D Adaptation(object? policy, bool changed, string rationale) => new() { ["policy"] = policy, ["changed"] = changed, ["rationale"] = rationale };

    /// <summary>Why <paramref name="adapted"/> is looser than <paramref name="bs"/>, or null when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as looser.</summary>
    public static string? NoWidenViolation(D bs, D adapted)
    {
        if (!(ToNumber(At(adapted, "kappa")) >= ToNumber(At(bs, "kappa")))) return "kappa decreased";
        if (!(ToNumber(At(adapted, "theta1")) <= ToNumber(At(bs, "theta1")))) return "theta1 increased";
        if (!(ToNumber(At(adapted, "theta2")) <= ToNumber(At(bs, "theta2")))) return "theta2 increased";
        foreach (var k in new[] { "lambda", "rho", "bMax" }) if (!Same(At(adapted, k), At(bs, k))) return k + " changed";
        var bw = Get(bs, "weights") as D ?? throw new ArgumentException("base.weights missing");
        var aw = Get(adapted, "weights") as D ?? throw new ArgumentException("adapted.weights missing");
        foreach (var k in bw.Keys) if (!Same(At(aw, k), At(bw, k))) return "weights." + k + " changed";
        return null;
    }

    /// <summary>Throws unless <paramref name="adapted"/> only tightens <paramref name="bs"/>.</summary>
    public static void AssertNoWiden(D bs, D adapted)
    {
        var v = NoWidenViolation(bs, adapted);
        if (v != null) throw new InvalidOperationException("immune: adaptation widens the policy (" + v + ")");
    }

    // ---- signed tightening proposals ----

    public const string TighteningDomain = "atlas-pca/immune-tightening/v1\u0000";

    static byte[] TighteningMessage(D claim) => Encoding.UTF8.GetBytes(TighteningDomain + Lenient(claim));

    public static string PolicyDigest(D policy) => HashLenient(policy);
    public static string ImmuneStateDigest(D state) => HashLenient(state);

    /// <summary>Derive and sign the tightening for <paramref name="state"/>; throws on a malformed base, an epoch that is not an integer &gt;= 1, a non-finite
    /// <paramref name="now"/> or a malformed state (never an unsigned loosening). <paramref name="guardianSecret"/> is the 32-byte Ed25519 seed.</summary>
    public static D IssueTighteningProposal(D bs, D state, object? epoch, object? now, byte[] guardianSecret)
    {
        var bad = Pca.ValidateRiskPolicy(bs);
        if (bad != null) throw new ArgumentException("issueTighteningProposal: " + bad);
        if (!IntentJs.IsSafeInteger(epoch) || Dv(epoch) < 1) throw new ArgumentException("issueTighteningProposal: epoch must be an integer >= 1");
        if (!IsFinite(now)) throw new ArgumentException("issueTighteningProposal: now must be finite");
        using var key = EdKey.FromSeed(guardianSecret);
        var ad = Adapt(bs, Assess(state));
        var claim = new D
        {
            ["v"] = N(1L), ["base_digest"] = PolicyDigest(bs), ["state_digest"] = HashLenient(state), ["epoch"] = epoch, ["issued_at"] = now,
            ["policy"] = ad["policy"], ["rationale"] = ad["rationale"], ["guardian"] = key.Id,
        };
        var p = new D(claim) { ["sig"] = Pca.B64u(key.Sign(TighteningMessage(claim))) };
        return p;
    }

    static D Refused(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Verify a proposal and return {ok: true, policy, epoch} or {ok: false, reason}; never throws. <paramref name="o"/> holds the pinned <c>guardian</c>
    /// (b64u, required), <c>lastEpoch</c>, <c>now</c>, <c>maxAgeMs</c> and optionally <c>state</c> (a recompute check).</summary>
    public static D ApplyTightening(D bs, D? p, D o)
    {
        try { return ApplyUnchecked(bs, p, o); }
        catch (Exception) { return Refused("malformed"); }
    }

    static D ApplyUnchecked(D bs, D? p, D o)
    {
        if (p == null || !JsX.StrictEq(Get(p, "v"), N(1L)) || Get(p, "sig") is not string sig || Get(p, "guardian") is not string guardian) return Refused("malformed");
        if (Get(o, "guardian") is not string pinned || pinned != guardian) return Refused("guardian");
        var claim = new D(p);
        claim.Remove("sig");
        if (!IntentJs.VerifyEd(guardian, TighteningMessage(claim), sig)) return Refused("signature");
        var polObj = Get(p, "policy");
        if (Pca.ValidateRiskPolicy(bs) != null || Pca.ValidateRiskPolicy(polObj) != null) return Refused("invalid-policy");
        var pol = polObj as D ?? throw new InvalidOperationException("policy is not an object");
        if (!(Get(p, "base_digest") is string bd && bd == PolicyDigest(bs))) return Refused("base");
        var now = NumOrNaN(Get(o, "now"));
        var at = NumOrNaN(Get(p, "issued_at"));
        if (double.IsNaN(now) || double.IsInfinity(now) || double.IsNaN(at) || double.IsInfinity(at) || at > now || now - at > ToNumber(At(o, "maxAgeMs"))) return Refused("stale"); // x > undefined is false: an absent maximum age never makes a proposal stale
        var epoch = Get(p, "epoch");
        if (!IntentJs.IsInt(epoch) || !(NumOrNaN(epoch) > ToNumber(At(o, "lastEpoch")))) return Refused("replayed-epoch"); // null reads as 0
        if (NoWidenViolation(bs, pol) != null) return Refused("widens");
        var st = Get(o, "state");
        if (JsX.Truthy(st) && (!(Get(p, "state_digest") is string sd && sd == HashLenient(st)) || PolicyDigest((D)Adapt(bs, Assess(st))["policy"]!) != PolicyDigest(pol))) return Refused("state-mismatch");
        return new D { ["ok"] = true, ["policy"] = pol, ["epoch"] = epoch };
    }

    // ---- durable state ----

    /// <summary>Immune state and applied epoch for one subject over an atomic kv, so a restart keeps the history and the replay floor.</summary>
    public static ImmuneStore CreateImmuneStore(IAtomicKv kv, string subject) => new(kv, subject);

    public sealed class ImmuneStore
    {
        readonly IAtomicKv _kv;
        readonly string _sKey, _eKey;

        internal ImmuneStore(IAtomicKv kv, string subject)
        {
            _kv = kv;
            _sKey = "immune/state/" + subject;
            _eKey = "immune/epoch/" + subject;
        }

        object? Read(string key) { var t = _kv.Get(key); return t == null ? null : Pca.ParseJson(t); }

        /// <summary>The stored state, or the initial one.</summary>
        public object? Get() => _kv.Get(_sKey) == null ? InitialState() : Read(_sKey); // only an absent key is the initial state: a stored null reads back as null

        /// <summary>Folds one observation atomically; throws when the stored state is malformed (it is never silently reset to calm).</summary>
        public D Observe(D obs)
        {
            D? result = null;
            _kv.Update(_sKey, prev =>
            {
                object cur = prev == null ? InitialState() : Pca.ParseJson(prev)!;
                var bad = ValidateImmuneState(cur);
                if (bad != null) throw new InvalidOperationException("immune store: stored state invalid (" + bad + ")");
                result = Immune.Observe((D)cur, obs);
                return Lenient(result);
            });
            return result!;
        }

        public double LastEpoch() => Read(_eKey) is { } v && IsNum(v) ? Math.Truncate(Dv(v)) : 0;

        /// <summary>Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. <paramref name="o"/> is as for
        /// <see cref="ApplyTightening"/> without lastEpoch.</summary>
        public D Apply(D bs, D? p, D o)
        {
            var outcome = Refused("malformed");
            _kv.Update(_eKey, prev =>
            {
                var pv = prev == null ? null : Pca.ParseJson(prev);
                var oo = new D(o) { ["lastEpoch"] = IsNum(pv) ? pv : N(0L) };
                outcome = ApplyTightening(bs, p, oo);
                return outcome["ok"] is true ? Lenient(outcome["epoch"]) : null;
            });
            return outcome;
        }
    }
}
