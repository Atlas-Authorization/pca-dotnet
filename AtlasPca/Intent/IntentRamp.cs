// The trust ramp: runtime signal labels, the narrow starting configuration, the drift detector (a one-sided Bernoulli CUSUM on
// divergences: S_t = max(0, S_{t-1} + log LR_t), a sticky alarm at S_t >= h), signed runtime observations and the ramp itself.
// Start narrow, widen only through confirmed behaviour, and every negative runtime signal vetoes its cell for good; an alarm freezes
// widening: positive signals are queued until a rebase on a new signed statement, negative signals are always applied.
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentRamp
{
    /// <summary>y = 1 for jit-approve and principal-confirm; every other signal is y = 0 (a veto).</summary>
    public static int SignalLabel(string? signal) => signal == "jit-approve" || signal == "principal-confirm" ? 1 : 0;

    /// <summary>The narrow start: tau 1, eta 0, a high empty-set prior for every verb (very high for verbs the slots do not name).</summary>
    public static D NarrowStart(Omega omega, object? slots, double? slotNullMass, double? otherNullMass)
    {
        var nullMass = new D();
        var verbs = slots is D sm ? sm.GetValueOrDefault("verbs") : null;
        foreach (var vs in omega.Verbs)
        {
            bool named = false;
            if (verbs is L vl) foreach (var v in vl) if (v is string s && s == vs.Verb) named = true;
            nullMass[vs.Verb] = N(named ? (slotNullMass ?? 0.5) : (otherNullMass ?? 0.95));
        }
        return new D { ["eta"] = N(0), ["tau"] = N(1), ["nullMass"] = nullMass };
    }

    /// <summary>The detector's state.</summary>
    public sealed record DriftState(double Statistic, bool Alarm, double Informative, double Divergences)
    {
        public D ToJson() => new() { ["statistic"] = N(Statistic), ["alarm"] = Alarm, ["informative"] = N(Informative), ["divergences"] = N(Divergences) };
    }

    public sealed class DriftDetector
    {
        public double Rho0 { get; }
        public double Rho1 { get; }
        public double H { get; }
        DriftState _s = new(0, false, 0, 0);

        /// <summary>Defaults: rho0 0.02, rho1 0.25, h ln(100); a null member takes its default.</summary>
        public DriftDetector(double? rho0, double? rho1, double? h)
        {
            Rho0 = rho0 ?? 0.02;
            Rho1 = rho1 ?? 0.25;
            H = h ?? IntentMath.Log(100);
            if (!(Rho0 > 0 && Rho0 < Rho1 && Rho1 < 1)) throw new ArgumentException("DriftDetector: need 0 < rho0 < rho1 < 1");
            if (!(H > 0)) throw new ArgumentException("DriftDetector: h must be positive");
        }

        /// <summary>Feed one signal about an action inside the grant: <paramref name="diverged"/> = a negative signal.</summary>
        public DriftState Update(bool diverged)
        {
            double inc = diverged ? IntentMath.Log(Rho1 / Rho0) : IntentMath.Log((1 - Rho1) / (1 - Rho0));
            double statistic = Math.Max(0, _s.Statistic + inc);
            _s = new DriftState(statistic, _s.Alarm || statistic >= H, _s.Informative + 1, _s.Divergences + (diverged ? 1 : 0));
            return _s;
        }

        public DriftState State => _s;

        public void Reset() => _s = new DriftState(0, false, 0, 0);
    }
}

/// <summary>A signed runtime observation against an Intent Map: y = 0 says the outcome should NOT have been allowed (a divergence), y = 1
/// confirms it. Signed by whoever observed it (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins).</summary>
public static class IntentObservation
{
    public const string IntentObsSigDomain = "atlas-pca/intent-obs/v1\0";
    public static readonly string[] IntentObservationSources = { "runtime", "witness", "elicitation", "import" };
    static readonly string[] BodyKeys = { "v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer" };

    static D ObsBody(D o)
    {
        var b = new D();
        foreach (var k in BodyKeys) if (o.ContainsKey(k)) b[k] = o[k];
        return (D)IntentJs.Normalize(b)!;
    }

    static bool IsNumEq(object? o, double v) => IntentJs.NumOf(o) is double d && d == v;

    /// <summary>The first shape problem of an observation, or null.</summary>
    internal static string? ObsShapeError(object? oo)
    {
        if (oo is not D o || !IsNumEq(o.GetValueOrDefault("v"), 1)) return "not an intent observation v1";
        if (!IntentJs.B32(o.GetValueOrDefault("map_digest"))) return "map_digest is not canonical base64url (32 bytes)";
        if (o.GetValueOrDefault("verb") is not string verb || verb.Length == 0) return "verb must be a non-empty string";
        bool ok = o.GetValueOrDefault("values") is D;
        if (ok)
        {
            foreach (var x in ((D)o["values"]!).Values)
            {
                var d = IntentJs.NumOf(x);
                if (!(x is string) && !(d != null && double.IsFinite(d.Value))) ok = false;
            }
        }
        if (!ok) return "values must map paths to numbers or strings";
        if (!IsNumEq(o.GetValueOrDefault("y"), 0) && !IsNumEq(o.GetValueOrDefault("y"), 1)) return "y must be 0 or 1";
        if (o.GetValueOrDefault("source") is not string src || !IntentObservationSources.Contains(src)) return "unknown observation source";
        if (!IntentJs.IsInt(o.GetValueOrDefault("observed_at")) || IntentJs.NumOf(o["observed_at"])!.Value < 0) return "observed_at must be a non-negative safe integer";
        if (o.ContainsKey("pcactn_digest") && !IntentJs.B32(o["pcactn_digest"])) return "pcactn_digest is not canonical base64url (32 bytes)";
        if (!IntentJs.B32(o.GetValueOrDefault("signer"))) return "signer is not canonical base64url (32 bytes)";
        return null;
    }

    /// <summary>Sign an observation ({map_digest, verb, values, y, source, observed_at, pcactn_digest?}) as the holder of an Ed25519 seed.</summary>
    public static D SignIntentObservation(D o, byte[] signerSeed) => SignIntentObservation(o, SuiteKey.Ed25519(EdKey.FromSeed(signerSeed)));

    /// <summary>Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the observation.</summary>
    public static D SignIntentObservation(D o, SuiteKey key)
    {
        if (key.Ed == null) throw new ArgumentException("signIntentObservation: signer needs an Ed25519 identity key");
        var input = new D(o) { ["v"] = N(1), ["signer"] = key.Ed.Id };
        var body = ObsBody(input);
        var bad = ObsShapeError(body);
        if (bad != null) throw new ArgumentException("signIntentObservation: " + bad);
        var bound = new D(body);
        if (key.Alg != "ed25519") { bound["alg"] = key.Alg; bound["pq_pk"] = key.PqPk; }
        var (sig, pqSig) = key.Sign(IntentJs.Message(IntentObsSigDomain, bound));
        var result = new D(bound) { ["sig"] = sig };
        if (pqSig != null) result["pq_sig"] = pqSig;
        return result;
    }

    static D Verdict(string? reason)
    {
        var r = new D { ["ok"] = reason == null };
        if (reason != null) r["reason"] = reason;
        return r;
    }

    /// <summary>{ok: true} or {ok: false, reason}. Never throws.</summary>
    public static D VerifyIntentObservation(object? oo, string? expectedSigner = null, D? pqPins = null)
    {
        try
        {
            var bad = ObsShapeError(oo);
            if (bad != null) return Verdict(bad);
            var ob = (D)oo!;
            if (expectedSigner != null && !(ob.GetValueOrDefault("signer") is string sg && sg == expectedSigner)) return Verdict("signer mismatch");
            bool algPresent = ob.ContainsKey("alg");
            var suite = IntentJs.SuiteOf(ob.GetValueOrDefault("alg"), algPresent);
            if (suite == null) return Verdict("unknown signature suite");
            if (suite == "ed25519" && (ob.ContainsKey("pq_pk") || ob.ContainsKey("pq_sig"))) return Verdict("an ed25519 artifact must not carry pq_pk / pq_sig");
            var body = IntentJs.BindSuiteFields(ObsBody(ob), ob.GetValueOrDefault("alg"), algPresent, ob.GetValueOrDefault("pq_pk"), ob.ContainsKey("pq_pk"));
            var msg = IntentJs.Message(IntentObsSigDomain, body);
            Dictionary<string, string>? pins = null;
            if (pqPins != null)
            {
                pins = new Dictionary<string, string>();
                foreach (var e in pqPins) if (e.Value is string pv) pins[e.Key] = pv;
            }
            if (!IntentJs.VerifyPinnedSuite(ob.GetValueOrDefault("alg"), algPresent, (string)ob["signer"]!, ob.GetValueOrDefault("pq_pk"), msg, ob.GetValueOrDefault("sig"), ob.GetValueOrDefault("pq_sig"), pins))
                return Verdict("bad signature");
            return Verdict(null);
        }
        catch (Exception e)
        {
            return Verdict("malformed intent observation: " + e.Message);
        }
    }
}

/// <summary>Trust ramp over a learner: signals become runtime observations; a drift alarm freezes widening.</summary>
public sealed class IntentTrustRamp
{
    IntentLearner _l;
    public IntentRamp.DriftDetector Drift { get; }
    readonly List<(Outcome O, string Signal)> _queued = new();
    public List<RampRecord> Log { get; } = new();

    public IntentTrustRamp(IntentLearner learner, double? rho0 = null, double? rho1 = null, double? h = null)
    {
        _l = learner;
        Drift = new IntentRamp.DriftDetector(rho0, rho1, h);
    }

    /// <summary>One recorded signal.</summary>
    public sealed record RampRecord(string Signal, int Y, bool WasInGrant, int Before, int After, bool Applied, IntentRamp.DriftState DriftState)
    {
        public D ToJson() => new()
        {
            ["signal"] = Signal, ["y"] = N(Y), ["wasInGrant"] = WasInGrant, ["before"] = N(Before), ["after"] = N(After), ["applied"] = Applied, ["drift"] = DriftState.ToJson(),
        };
    }

    public IntentLearner Learner => _l;

    /// <summary>Widening is frozen while a drift alarm stands.</summary>
    public bool Frozen => Drift.State.Alarm;

    /// <summary>Positive signals held back by a freeze (released only by a rebase, which discards them).</summary>
    public List<D> Pending() => _queued.Select(q => new D { ["o"] = OutcomeToJson(q.O), ["signal"] = q.Signal }).ToList();

    int GrantSize() => _l.Cells().Count(c => c.InGrant);

    public RampRecord Record(Outcome o, string signal)
    {
        int y = IntentRamp.SignalLabel(signal);
        bool wasInGrant = _l.AdmitsOutcome(o);
        int before = GrantSize();
        var d = Drift.State;
        if (wasInGrant) d = Drift.Update(y == 0);
        bool applied = true;
        if (y == 1 && Frozen)
        {
            _queued.Add((o, signal));
            applied = false;
        }
        else _l.Observe(o, y, "runtime", null);
        var rec = new RampRecord(signal, y, wasInGrant, before, GrantSize(), applied, d);
        Log.Add(rec);
        return rec;
    }

    /// <summary>Record a SIGNED runtime observation: the signature must verify, the signer must be trusted, and the observation must be about this
    /// map and a runtime one. Returns {ok: true, record} or {ok: false, reason}.</summary>
    public D RecordObservation(object? obs, string mapDigest, List<string> trustedSigners, string? expectedSigner = null, D? pqPins = null)
    {
        var v = IntentObservation.VerifyIntentObservation(obs, expectedSigner, pqPins);
        if (!(v["ok"] is true)) return new D { ["ok"] = false, ["reason"] = v.GetValueOrDefault("reason") };
        var o = (D)obs!;
        if (!(o["signer"] is string sg && trustedSigners.Contains(sg))) return new D { ["ok"] = false, ["reason"] = "untrusted observation signer" };
        if (!(o["map_digest"] is string md && md == mapDigest)) return new D { ["ok"] = false, ["reason"] = "observation is about a different map" };
        if (!(o["source"] is string src && src == "runtime")) return new D { ["ok"] = false, ["reason"] = "only runtime observations feed the ramp" };
        var vals = new Dictionary<string, object?>();
        foreach (var e in (D)o["values"]!) vals[e.Key] = IsNum(e.Value) ? Dbl(e.Value) : e.Value;
        bool yes = Dbl(o["y"]) == 1;
        var rec = Record(new Outcome((string)o["verb"]!, vals), yes ? "principal-confirm" : "postcondition-violation");
        return new D { ["ok"] = true, ["record"] = rec.ToJson() };
    }

    /// <summary>Re-base on a new learner (the only way to clear an alarm): the old vetoes are not carried over and queued positives are discarded.</summary>
    public void Rebase(IntentLearner next)
    {
        _l = next;
        _queued.Clear();
        Drift.Reset();
    }
}
