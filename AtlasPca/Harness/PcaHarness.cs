// "Attest the mediator, not the weights": the orchestration harness. The model is an UNTRUSTED ORACLE that proposes a candidate action; the harness
// enforces the PCA invariants itself, BEFORE any candidate can become a signed PCActn: (1) plan inclusion (the candidate must be a node of the
// principal-authorised committed plan), (2) the taint fold (untrusted input lineage raises risk), (3) the trust budget (a machine-only action must be
// covered by the leaked budget), (4) signing with the leaf holder key (the oracle never holds it). What an attestation of the harness measures is its own
// policy-relevant surface (<see cref="PcaHarness.ComputeHarnessMeasurement"/>), a small auditable TCB, not the opaque model.
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Harness;

/// <summary>Inputs of <see cref="PcaHarness"/>. Plan, audience, budget, policy, base risk and the manifest are JSON-shaped values: the constructor refuses a malformed one.</summary>
public sealed class HarnessOptions
{
    /// <summary>The principal-signed root capability.</summary>
    public D Grant = new();
    /// <summary>The capability chain ending at the leaf the harness signs for; defaults to the grant alone.</summary>
    public L? Chain;
    /// <summary>The leaf holder's key: only the harness signs.</summary>
    public SuiteKey Signer = null!;
    /// <summary>The principal-authorised plan nodes (a non-empty list of <c>{id, verb, resource, ...}</c> with unique ids).</summary>
    public object? Plan;
    /// <summary>The audience the PCActns are for (a non-empty string).</summary>
    public object? Audience;
    /// <summary>The decaying trust budget <c>{B, tau, asOf}</c> (finite numbers, B >= 0).</summary>
    public object? Budget;
    /// <summary>The risk policy (weights, thresholds, kappa, lambda); defaults to the reference default.</summary>
    public object? Policy;
    /// <summary>Base risk inputs before taint folding; merged over the low, reversible default profile.</summary>
    public object? BaseRisk;
    /// <summary>Clock (epoch milliseconds); default the system clock.</summary>
    public Func<double>? Now;
    public double? TtlMs;
    /// <summary>Overrides the enforced-checks manifest that feeds the measurement.</summary>
    public object? MeasurementManifest;
    /// <summary>A deterministic nonce source; default a random 16-byte hex string.</summary>
    public Func<string>? Nonce;
    /// <summary>When set (<c>{operator, epoch?}</c>), stamps this harness's self-measurement into every emitted PCActn's attestation block.</summary>
    public object? Attestation;
}

public sealed class PcaHarness
{
    /// <summary>The ordered manifest of checks this harness enforces before signing; folded into the measurement.</summary>
    public static readonly IReadOnlyList<string> EnforcedChecks = new[] { "plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign" };
    /// <summary>Semantic version of the harness's policy-relevant surface. A bump changes the measurement.</summary>
    public const string HarnessVersion = "0.1.0";
    /// <summary>The model identifier the harness stamps into an emitted PCActn's attestation block: the auditable mediator, not an opaque model.</summary>
    public const string HarnessModelId = "@atlasauth/pca-harness";

    static object N(double d) => Jx.NumOut(d);
    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }

    /// <summary>Pure, deterministic self-measurement: a SHA-256 digest (b64u) over the harness version, the enforced-checks manifest and the risk-policy identity
    /// (weights, theta1, theta2, kappa). Throws when the policy lacks one of them.</summary>
    public static string ComputeHarnessMeasurement(object? version, object? enforcedChecks, object? policy) => Pca.HashCanonical(new D
    {
        ["harness"] = "@atlasauth/pca-harness",
        ["version"] = version,
        ["enforces"] = enforcedChecks,
        ["risk_policy"] = new D { ["weights"] = Jx.Prop(policy, "weights"), ["theta1"] = Jx.Prop(policy, "theta1"), ["theta2"] = Jx.Prop(policy, "theta2"), ["kappa"] = Jx.Prop(policy, "kappa") },
    });

    // ---- state ----

    readonly D grant;
    readonly L chain;
    readonly SuiteKey signer;
    readonly L plan;
    readonly Dictionary<string, D> planIndex = new(StringComparer.Ordinal);
    readonly Plan committed;
    readonly string audience;
    readonly object? policy;
    readonly D baseRisk;
    readonly Func<double> now;
    readonly double? ttlMs;
    readonly object? manifest;
    readonly Func<string> nonce;
    readonly object? attest;

    TrustBudget budget;
    long counter;

    static D DefaultBaseRisk() => Obj(("semanticDistance", new Num("0.1")), ("reversibility", new Num("1")), ("blastRadius", new Num("0.1")), ("taint", new Num("0")), ("confidence", new Num("1")), ("age", new Num("0")));

    static string RandomNonce() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public PcaHarness(HarnessOptions opts)
    {
        if (opts.Audience is not string aud || aud.Length == 0) throw new ArgumentException("Harness: `audience` is required (the resource-server / instance id PCActns are for)");
        if (opts.Signer == null) throw new ArgumentException("Harness: `signer` must be an Ed25519 key");
        if (opts.Plan is not L pl || pl.Count == 0) throw new ArgumentException("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)");
        var ids = pl.Select(n => Jx.Prop(n, "id")).ToList();
        for (int i = 0; i < ids.Count; i++)
            for (int j = 0; j < i; j++)
                if (JsX.StrictEq(ids[i], ids[j])) throw new ArgumentException("Harness: plan node ids must be unique");
        var b = opts.Budget;
        if (b == null || !(Jx.Fin(Jx.Prop(b, "B")) is double bb && bb >= 0) || Jx.Fin(Jx.Prop(b, "tau")) is not double tau || Jx.Fin(Jx.Prop(b, "asOf")) is not double asOf)
            throw new ArgumentException("Harness: `budget` must have finite B >= 0, tau and asOf");
        grant = opts.Grant;
        chain = opts.Chain ?? new L { opts.Grant };
        signer = opts.Signer;
        plan = pl;
        foreach (var n in pl) if (n is D nd && nd.GetValueOrDefault("id") is string s) planIndex[s] = nd;
        // commit the principal-authorised plan ONCE: every emitted action carries an inclusion proof under this root
        committed = Issue.CommitPlan(pl.Select(n => n as D ?? throw new ArgumentException("commitPlan: missing node id")));
        audience = aud;
        policy = opts.Policy ?? Issue.DefaultRiskPolicy();
        baseRisk = DefaultBaseRisk();
        var br = opts.BaseRisk;
        if (br != null) foreach (var (k, v) in JsX.Spread(br)) baseRisk[k] = v;
        now = opts.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        ttlMs = opts.TtlMs;
        manifest = opts.MeasurementManifest ?? new L(EnforcedChecks.Cast<object?>());
        nonce = opts.Nonce ?? RandomNonce;
        attest = opts.Attestation;
        budget = new TrustBudget(bb, tau, asOf);
    }

    /// <summary>The committed plan root the principal authorised.</summary>
    public string PlanRoot => committed.Root;

    /// <summary>Current (leaked to the last touch) trust budget as <c>{B, tau, asOf}</c>.</summary>
    public D Budget => Obj(("B", N(budget.B)), ("tau", N(budget.Tau)), ("asOf", budget.AsOf is double a ? N(a) : null));

    /// <summary>Monotonic action counter: the number of PCActns this harness has emitted.</summary>
    public long Counter => counter;

    /// <summary>The B1 self-measurement: what a remote attestation of the mediator would cover, in place of the unmeasurable model weights.</summary>
    public string HarnessMeasurement() => ComputeHarnessMeasurement(HarnessVersion, manifest, policy);

    static D Refusal(string reason, string detail) => Obj(("ok", false), ("reason", reason), ("detail", detail));

    /// <summary>JavaScript Math.round: half rounds up.</summary>
    static double JsRound(double x)
    {
        var f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    static double Weight(object? w, string k) => Jx.Fin(Jx.Prop(w, k)) ?? double.NaN;

    /// <summary>Asks the untrusted oracle for a candidate and, only if it survives the invariant gate, emits a signed PCActn:
    /// <c>{ok: true, pcactn, inclusionProof, risk, budget}</c> or a refusal <c>{ok: false, reason, detail, requiredT?, budget?}</c> (reason out_of_plan,
    /// over_budget or bad_candidate). An oracle that throws is a refusal, never an unhandled error.</summary>
    public D Step(Func<object?> proposeAction)
    {
        object? candidate;
        try { candidate = proposeAction(); }
        catch (Exception e) { return Refusal("bad_candidate", "oracle failed: " + e.Message); }
        return Process(candidate);
    }

    /// <summary>Like <see cref="Step"/> for an oracle that is an asynchronous model call.</summary>
    public async Task<D> StepAsync(Func<Task<object?>> proposeAction)
    {
        object? candidate;
        try { candidate = await proposeAction().ConfigureAwait(false); }
        catch (Exception e) { return Refusal("bad_candidate", "oracle failed: " + e.Message); }
        return Process(candidate);
    }

    D Process(object? candidate)
    {
        // (0) shape check: the oracle is untrusted, so validate before use
        if (!(candidate is D || candidate is L) || Jx.Prop(candidate, "nodeId") is not string nodeId || Jx.Prop(candidate, "verb") is not string verb || Jx.Prop(candidate, "resource") is not string resource)
            return Refusal("bad_candidate", "oracle returned a malformed candidate");

        // (1) plan inclusion: reject out-of-plan BEFORE signing (the core claim)
        if (!planIndex.TryGetValue(nodeId, out var node)) return Refusal("out_of_plan", $"node '{nodeId}' is not in the committed plan");
        if (!JsX.StrictEq(node.GetValueOrDefault("verb"), verb) || !JsX.StrictEq(node.GetValueOrDefault("resource"), resource))
            // the oracle named a real node but tried to smuggle a different action under it
            return Refusal("out_of_plan", $"action {verb} {resource} does not match committed node '{nodeId}' ({JsX.Str(node.GetValueOrDefault("verb"))} {JsX.Str(node.GetValueOrDefault("resource"))})");
        D inclusionProof;
        try { inclusionProof = committed.ProofFor(nodeId); }
        catch (Exception e) { return Refusal("out_of_plan", $"no inclusion proof for '{nodeId}': {e.Message}"); }

        // (2) taint fold: untrusted input lineage raises risk. Fail closed: only a well-formed 'trusted' input is trusted; anything else counts as untrusted
        // lineage, and a non-array `inputs` is itself a bad candidate
        var rawInputs = Jx.Prop(candidate, "inputs");
        if (!Jx.IsUndef(rawInputs) && rawInputs is not L) return Refusal("bad_candidate", "candidate.inputs is not an array");
        var inputs = new List<(string Ref, string Provenance)>();
        foreach (var i in rawInputs as L ?? new L())
        {
            var prov = Jx.Opt(i, "provenance"); var rf = Jx.Opt(i, "ref");
            if (i != null && (i is D || i is L) && prov is string p && p == "trusted" && rf is string rs) inputs.Add((rs, "trusted"));
            else inputs.Add((rf is string rs2 ? rs2 : "", "untrusted"));
        }
        var taint = inputs.Any(i => i.Provenance == "untrusted") ? 1L : 0L;
        var trustedRefs = new L(inputs.Where(i => i.Provenance == "trusted").Select(i => (object?)i.Ref));
        var riskInputs = new D(baseRisk);
        riskInputs["taint"] = new Num(taint.ToString());
        double In(string k) => Jx.Fin(riskInputs.GetValueOrDefault(k)) ?? double.NaN;
        var w = Jx.Prop(policy, "weights");
        var rp = new RiskPolicy(Weight(w, "alpha"), Weight(w, "beta"), Weight(w, "gamma"), Weight(w, "delta"), Weight(w, "epsilon"), Weight(w, "zeta"),
            Jx.Fin(Jx.Prop(policy, "theta1")) ?? double.NaN, Jx.Fin(Jx.Prop(policy, "theta2")) ?? double.NaN, Jx.Fin(Jx.Prop(policy, "kappa")) ?? double.NaN,
            Jx.Fin(Jx.Prop(policy, "lambda")) ?? double.NaN, 0, 0);
        // round to 6 d.p.: the float sum can exceed the 15-significant-digit plain-decimal bound of the canonical wire form
        var r = JsRound(Risk.Score(new RiskInputs(In("semanticDistance"), In("reversibility"), In("blastRadius"), In("taint"), In("confidence"), In("age")), rp) * 1e6) / 1e6;
        var rt = Risk.Required(r, rp.Theta1, rp.Theta2, node.GetValueOrDefault("reversibility_class") is string rc && rc == "irreversible");

        // (3) trust budget: meter machine-only actions; leak to now first
        var nowMs = now();
        var leaked = Risk.Leak(budget, nowMs, rp.Lambda);
        var c = Risk.Cost(r, rp.Kappa);
        if (rt.T < 3 && !(leaked.B >= c))
        {
            // the budget cannot cover even this in-plan action: escalate to a human step-up; nothing is debited and no PCActn is produced
            budget = leaked;
            var f = Refusal("over_budget", $"budget {Fixed4(leaked.B)} < cost {Fixed4(c)}; step up to a human co-sign");
            f["requiredT"] = new Num("3");
            f["budget"] = Budget;
            return f;
        }

        // (4) sign: only now is the PCActn built and signed with the leaf holder key
        var provenance = Obj(
            ("causal_hash", Pca.HashCanonical(new L(inputs.Select(i => (object?)Obj(("ref", i.Ref), ("provenance", i.Provenance)))))),
            ("taint_level", taint), ("trusted_refs", trustedRefs));
        D? attestation = null;
        if (attest != null && !Jx.IsUndef(attest) && JsX.Truthy(attest))
        {
            var ep = Jx.Opt(attest, "epoch");
            attestation = Obj(("quote_digest", ""), ("epoch", ep == null || Jx.IsUndef(ep) ? 0L : ep), ("model_id", HarnessModelId), ("measurement", HarnessMeasurement()), ("operator", Jx.Prop(attest, "operator")));
        }
        var nonceValue = nonce();
        D pcactn;
        try
        {
            var prm = Jx.Prop(candidate, "params");
            pcactn = Issue.BuildPCActn(new ActSpec
            {
                Grant = grant, Chain = chain, Plan = committed, NodeId = nodeId, Params = prm as D, Counter = counter + 1, Signer = signer, Aud = audience,
                Iat = (long)nowMs, TtlMs = ttlMs is double tm ? (long)tm : null, Nonce = nonceValue, Provenance = provenance,
                RiskClaim = Obj(("r", N(r)), ("inputs", new D(riskInputs))), Attestation = attestation,
            });
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // e.g. the params do not match the node's committed params_digest: still never emits an out-of-plan action
            return Refusal("bad_candidate", $"could not build PCActn: {e.Message}");
        }

        // debit only for a metered (machine-only, t < 3) action; commit the counter
        budget = rt.T < 3 ? Risk.Debit(leaked, c) : leaked;
        counter++;
        return Obj(("ok", true), ("pcactn", pcactn), ("inclusionProof", inclusionProof),
            ("risk", Obj(("r", N(r)), ("inputs", riskInputs), ("taint", new Num(taint.ToString())), ("t", new Num(rt.T.ToString())))), ("budget", Budget));
    }

    static string Fixed4(double x) => x.ToString("F4", System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>The resource-server verifier for an attested harness: a hook that admits a PCActn whose signed <c>attestation.measurement</c> is one of an
/// operator-allowlisted set of harness measurements. Fail closed throughout: an empty allowlist accepts nothing; an absent measurement fails when required (the
/// default); a declared model id other than the pinned one fails; a present measurement that is not allowlisted ALWAYS fails. The measurement's integrity rests
/// on the surrounding verdict requiring the leaf signature to verify; this hook only decides allowlisting.</summary>
public static class HarnessAttestation
{
    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }

    /// <summary>Builds the hook from <c>{measurements, required?, expectedModelId?}</c>: a function from a verify context to <c>{enforced, ok?, reason?}</c>.</summary>
    public static Func<object?, D> CreateHarnessAttestationVerifier(object? config)
    {
        var ms = Jx.Prop(config, "measurements");
        var allow = new HashSet<string>(StringComparer.Ordinal);
        if (ms is L ml) foreach (var m in ml) if (m is string s && s.Length > 0) allow.Add(s);
        var required = !(Jx.Prop(config, "required") is false);
        var emi = Jx.Prop(config, "expectedModelId");
        string? expected = emi is true ? PcaHarness.HarnessModelId : emi is string es && es.Length > 0 ? es : null;

        return ctx =>
        {
            if (allow.Count == 0) return Obj(("enforced", true), ("ok", false), ("reason", "harness attestation configured with an empty measurement allowlist (fail closed)"));
            var att = Jx.Opt(Jx.Opt(ctx, "pcactn"), "attestation");
            var measurement = Jx.Opt(att, "measurement") is string ms2 ? ms2 : "";
            if (measurement.Length == 0)
                return required
                    ? Obj(("enforced", true), ("ok", false), ("reason", "harness attestation required but the PCActn carries no harness measurement (fail closed)"))
                    : Obj(("enforced", false));
            if (expected != null && !JsX.StrictEq(Jx.Opt(att, "model_id"), expected))
                return Obj(("enforced", true), ("ok", false), ("reason", $"attestation.model_id '{JsX.Str(Jx.Opt(att, "model_id"))}' is not the required harness identity '{expected}'"));
            if (!allow.Contains(measurement)) return Obj(("enforced", true), ("ok", false), ("reason", "harness measurement is not in the allowlisted set (unattested or unknown mediator)"));
            return Obj(("enforced", true), ("ok", true));
        };
    }
}
