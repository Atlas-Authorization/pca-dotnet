using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The core verifier entry with the full option set: the equivalent of <c>verifyPCActnCore(pcactn, opts)</c> in the reference. Unlike
/// <see cref="Pca.VerifyPcactnCore"/> (a boolean verdict, the shape of the shared vectors) it reports every check as <c>pass | fail | not-enforced | unsupported</c>
/// under the reference's names (<c>cap_chain</c>), takes the verifier hooks (attestation, threshold, revocation, zk), the opt-in enforcement gates (taint, freshness,
/// attestation), the verifier-side PQ pins (<c>pq_pin</c>) and the assurance report, and supports the explicit audience opt-out.
/// <para>Check order (normative): wire (terminal on failure), version, audience, validity, cap_chain, pq_pin, grant_ref_bound, plan_inclusion, plan_root_authorized,
/// leaf_signature, counter_format, intent, the intent v2 checks, fresh_at, taint_gate, freshness, attestation, threshold, revocation, zk_compliance, bond. <c>Allow</c> is
/// "no check failed"; the reason is the first failure.</para>
/// <para>Not offered (the reference's legacy opt-out): <c>allowUnboundPq</c>. A pure-PQ or hybrid signer is always checked against its <c>holder_pq</c> commitment.
/// Hooks are synchronous; a hook that needs I/O blocks the caller.</para></summary>
public static class PcaCore
{
    public const string Pass = "pass", Fail = "fail", NotEnforced = "not-enforced", Unsupported = "unsupported";

    /// <summary>What a hook receives: the PCActn, the verifier's grant and the verification clock.</summary>
    public sealed record CoreContext(D Pcactn, D Grant, long NowEpoch);

    /// <summary><c>{enforced: false}</c> or <c>{enforced: true, ok, reason?, t?}</c>; a threshold hook reports the <c>t</c> it enforced.</summary>
    public sealed record HookResult(bool Enforced, bool Ok = false, string? Reason = null, double? T = null)
    {
        public static HookResult None => new(false);
        public static HookResult Of(bool ok, string? reason = null, double? t = null) => new(true, ok, reason, t);
    }

    public delegate HookResult Hook(CoreContext ctx);

    public sealed class Hooks
    {
        public Hook? Attestation { get; set; }
        public Hook? Threshold { get; set; }
        public Hook? Revocation { get; set; }
        public Hook? Zk { get; set; }
    }

    /// <summary><c>enforce.freshness</c>: reject a missing, stub or stale signed freshness anchor. Null members take the reference defaults.</summary>
    public sealed class FreshnessGate
    {
        public double MaxAgeMs { get; set; }
        public double? EpochMs { get; set; }
        public double? ClockSkewMs { get; set; }
        public long? Now { get; set; }
        public FreshnessGate(double maxAgeMs) { MaxAgeMs = maxAgeMs; }
    }

    /// <summary><c>enforce.attestation</c>: the real attestation verifier; with the gate on, a not-enforced result fails unless <see cref="Required"/> is false.</summary>
    public sealed class AttestationGate
    {
        public Hook Verifier { get; }
        public bool Required { get; set; } = true;
        public AttestationGate(Hook verifier) { Verifier = verifier; }
    }

    public sealed class Enforce
    {
        public FreshnessGate? Freshness { get; set; }
        /// <summary><c>enforce.taint</c>: re-classify every declared ref from server facts and refuse above <c>MaxTaint</c>.</summary>
        public TaintGate? Taint { get; set; }
        public AttestationGate? Attestation { get; set; }
    }

    public sealed class Options
    {
        /// <summary>The verifier's OWN stored grant.</summary>
        public D Grant { get; set; }
        /// <summary>The grant was lifted from the presented artifact: it is then not the trusted root and a PQ root verifies only under <see cref="PqPins"/>.</summary>
        public bool GrantFromArtifact { get; set; }
        /// <summary>Verifier-side pins <c>issuer -&gt; pq_pk</c>; an issuer with a pin also refuses a classical root (<c>pq_pin</c>).</summary>
        public IReadOnlyDictionary<string, string>? PqPins { get; set; }
        /// <summary>The verification clock (epoch ms); null reads the system clock.</summary>
        public long? NowEpoch { get; set; }
        /// <summary>Audience: <see cref="WithAudience"/> (must equal), <see cref="AudienceAny"/> (explicit opt-out), or unset (fails when the PCActn carries an <c>aud</c>).</summary>
        public string? Audience { get; set; }
        public bool AudienceGiven { get; set; }
        public Hooks? Hooks { get; set; }
        public Enforce? Enforce { get; set; }
        public IReadOnlyCollection<string>? AllowedSuites { get; set; }
        /// <summary><c>authorizedPlanRoots</c> and <c>insecureSkipPlanRootCheck</c>; null behaves as a policy with neither (the check fails).</summary>
        public PlanRootPolicy? PlanRoots { get; set; }
        public IntentPolicy? IntentPolicy { get; set; }
        public IntentV2Context? IntentV2 { get; set; }
        public FreshAtPolicy? FreshAt { get; set; }
        /// <summary>Attach the per-check assurance report.</summary>
        public bool Assurance { get; set; }
        public AssuranceRequirement? RequireAssurance { get; set; }

        public Options(D grant) { Grant = grant; }
        public Options WithAudience(string a) { Audience = a; AudienceGiven = true; return this; }
        public Options AudienceAny() { Audience = null; AudienceGiven = true; return this; }
    }

    public sealed class Result
    {
        public bool Allow { get; set; }
        /// <summary>Check name to status, in the normative order.</summary>
        public Dictionary<string, string> Checks { get; } = new();
        /// <summary>First failure; null when allowed.</summary>
        public string? Reason { get; set; }
        /// <summary>The per-check assurance report; null unless asked for.</summary>
        public AssuranceReport? Assurance { get; set; }
        /// <summary>The <c>t</c> a passing threshold hook reported (null when none did).</summary>
        public double? EnforcedT { get; set; }
    }

    sealed class State
    {
        public readonly Dictionary<string, string> Checks = new();
        public string? Reason;
        public bool Terminal;
        public void Set(string n, string s) => Checks[n] = s;
        public void FailRaw(string n, string reason) { Checks[n] = Fail; Reason ??= reason; }
        public void FailWith(string n, string why) => FailRaw(n, n + ": " + why);
        public bool Allow => !Terminal && !Checks.ContainsValue(Fail);
    }

    static Result ResultOf(State st)
    {
        var r = new Result { Allow = st.Allow };
        foreach (var kv in st.Checks) r.Checks[kv.Key] = kv.Value;
        r.Reason = r.Allow ? null : st.Reason;
        return r;
    }

    /// <summary>Verifies <paramref name="pcactn"/> under the options; total: hostile input is a failed result, never an exception.</summary>
    public static Result Verify(object? pcactn, Options o)
    {
        try { return VerifyUnchecked(pcactn, o); }
        catch (Exception ex)
        {
            var w = new State { Terminal = true };
            w.FailWith("wire", "malformed input (" + ex.GetType().Name + ")");
            return ResultOf(w);
        }
    }

    static Result VerifyUnchecked(object? pcactn, Options o)
    {
        var st = new State();
        var wire = Pca.ValidateWire(pcactn);
        if (wire != null)
        {
            st.Terminal = true;
            st.FailWith("wire", wire);
            return ResultOf(st);
        }
        var p = (D)pcactn!;
        var grant = o.Grant;
        long now = o.NowEpoch ?? AtlasPca.ReplayClock.NowMs();
        var ctx = new CoreContext(p, grant, now);
        var planRoots = o.PlanRoots ?? new PlanRootPolicy();
        var hooks = o.Hooks;
        double? enforcedT = null;
        st.Set("wire", Pass);
        try
        {
            // version
            var ver = IntentJs.Get(p, "ver");
            if (IntentJs.IsSafeInteger(ver) && IntentJs.NumOf(ver) == 2) st.Set("version", Pass);
            else st.FailWith("version", $"unsupported ver {IntentRevocation.JsText(ver, true)} (this verifier requires 2)");

            // audience: a string must equal, an explicit opt-out is not enforced, an omitted one fails when the PCActn carries an aud
            var aud = IntentJs.Get(p, "aud") as string;
            if (o.AudienceGiven && o.Audience == null) st.Set("audience", NotEnforced);
            else if (!o.AudienceGiven)
            {
                if (!string.IsNullOrEmpty(aud)) st.FailWith("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)");
                else st.Set("audience", NotEnforced);
            }
            else if (string.Equals(o.Audience, aud, StringComparison.Ordinal)) st.Set("audience", Pass);
            else st.FailWith("audience", "aud does not match this resource server / instance");

            // validity
            bool clockOk = Math.Abs(now) <= 9007199254740991L;
            long iat = IntentJs.Lng(IntentJs.Get(p, "iat")), exp = IntentJs.Lng(IntentJs.Get(p, "exp"));
            if (!clockOk) st.FailWith("validity", "the verifier clock is not a safe integer epoch-ms");
            else if (!(exp > iat)) st.FailWith("validity", "exp must be greater than iat");
            else if (exp - iat > Pca.MaxLifetimeMs) st.FailWith("validity", $"lifetime exceeds {Pca.MaxLifetimeMs} ms");
            else if (iat > now + Pca.MaxSkewMs) st.FailWith("validity", "iat is in the future (clock skew)");
            else if (now > exp) st.FailWith("validity", "the PCActn has expired");
            else st.Set("validity", Pass);

            // cap_chain: non-empty, rooted at the grant, then the walk (hop and caveat limits live in VerifyChain)
            var chain = IntentJs.Get(p, "cap_chain") as L ?? new L();
            if (chain.Count == 0) st.FailWith("cap_chain", "empty chain");
            else if (Pca.CapHash(chain[0]) != Pca.CapHash(grant)) st.FailWith("cap_chain", "chain root is not the grant");
            else
            {
                var gi = IntentJs.Get(grant, "issuer");
                var (why, ok) = Pca.VerifyChain(chain, gi, gi != null, o.AllowedSuites, o.GrantFromArtifact ? o.PqPins : null, o.GrantFromArtifact ? null : grant);
                if (ok) st.Set("cap_chain", Pass); else st.FailWith("cap_chain", why);
            }
            // a PQ pin for the root issuer says its grants are post-quantum protected: a classical root naming it is refused
            if (o.PqPins != null && (IntentJs.Get(grant, "alg") is null or "ed25519") && IntentJs.Get(grant, "issuer") is string gIss && o.PqPins.ContainsKey(gIss))
                st.FailWith("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused");

            // grant_ref_bound
            var gref = IntentJs.Get(p, "grant_ref");
            var rootId = chain.Count > 0 ? IntentJs.Get(chain[0], "id") : null;
            if (gref is string { Length: > 0 } gr && rootId is string rid && string.Equals(gr, rid, StringComparison.Ordinal)) st.Set("grant_ref_bound", Pass);
            else st.FailWith("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain");

            // plan inclusion + plan_root_authorized
            var plan = (D)p["plan"]!;
            var action = IntentJs.Get(p, "action") as D;
            var cond = IntentJs.Get(plan, "conditions_digest") as string ?? Pca.ConditionsDigest(null, null);
            var planRoot = IntentJs.Get(plan, "root") as string ?? "";
            bool incl;
            try
            {
                var leaf = Pca.PlanLeaf(IntentJs.Get(plan, "node_id"), action, cond);
                incl = leaf != null && Pca.VerifyInclusion(planRoot, IntentJs.Get(plan, "inclusion_proof") as D, leaf);
            }
            catch (Exception) { incl = false; }
            if (incl) st.Set("plan_inclusion", Pass); else st.FailWith("plan_inclusion", "action is not a node of the committed plan");
            if (planRoots.AuthorizedRoots == null)
            {
                if (planRoots.InsecureSkip) st.Set("plan_root_authorized", NotEnforced);
                else st.FailWith("plan_root_authorized", "no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)");
            }
            else if (planRoots.AuthorizedRoots.Contains(planRoot)) st.Set("plan_root_authorized", Pass);
            else st.FailWith("plan_root_authorized", "the plan root has not been authorized by the principal");

            // leaf signature (suite policy, F-2 binding, then the suite verification)
            bool sigOk = false;
            string? leafErr = null;
            if (chain.Count > 0 && chain[^1] is D leafCap)
            {
                bool algPresent = p.ContainsKey("alg");
                var alg = IntentJs.Get(p, "alg");
                if (Pca.SuitePolicyError(alg, "leaf", o.AllowedSuites) != null)
                    leafErr = $"signature suite '{(algPresent ? IntentRevocation.JsText(alg, true) : "ed25519")}' is not allowed by this verifier's suite policy";
                else leafErr = Pca.PqBindingError(p, IntentJs.Get(leafCap, "holder_pq"), "leaf");
                if (leafErr == null && IntentJs.Get(p, "sig") is string)
                    sigOk = Pca.VerifySuite(p, IntentJs.Get(leafCap, "holder"), Pca.ThresholdMessage(p), Pca.PinnedPq.Resolve(null, IntentJs.Get(p, "pq_pk"), holderPq: IntentJs.Get(leafCap, "holder_pq")));
            }
            if (leafErr != null) st.FailWith("leaf_signature", leafErr);
            else if (sigOk) st.Set("leaf_signature", Pass);
            else st.FailWith("leaf_signature", "signature does not verify under the leaf holder key / suite");

            // counter_format
            var counter = IntentJs.Get(p, "counter");
            if (IntentJs.IsSafeInteger(counter) && IntentJs.NumOf(counter) >= 0) st.Set("counter_format", Pass);
            else st.FailWith("counter_format", "missing or not a non-negative safe integer");

            // intent (reported iff the PCActn carries intent or the policy is active)
            var sess = IntentJs.Get(p, "intent_session") as D;
            var intentWhy = Pca.DecideIntent(IntentJs.Get(p, "intent"), p.ContainsKey("intent"), grant, o.IntentPolicy, IntentJs.Get(sess, "session") as string, IntentJs.Get(sess, "map_form"));
            if (intentWhy != null)
            {
                if (intentWhy.Length == 0) st.Set("intent", Pass); else st.FailWith("intent", intentWhy);
            }
            foreach (var c in IntentV2.Decide(p, grant, o.IntentV2, now).Checks)
            {
                if (c.Ok) st.Set(c.Name, Pass); else st.FailWith(c.Name, c.Reason ?? "rejected");
            }
            var fa = FreshAt.Decide(IntentJs.Get(p, "fresh_at"), p.ContainsKey("fresh_at"), o.FreshAt, now);
            if (fa.Status == "pass") st.Set("fresh_at", Pass);
            else if (fa.Status == "fail") st.FailWith("fresh_at", fa.Reason ?? "rejected");

            var en = o.Enforce;
            // M1 taint gate
            if (en?.Taint != null)
            {
                try
                {
                    var (tok, treason) = Taint.Gate(IntentJs.Get(p, "provenance"), en.Taint.Context, en.Taint.MaxTaint);
                    if (tok) st.Set("taint_gate", Pass); else st.FailWith("taint_gate", treason ?? "rejected");
                }
                catch (Exception e) { st.FailWith("taint_gate", "taint gate error (fail closed): " + e.Message); }
            }
            else st.Set("taint_gate", NotEnforced);

            // M3 freshness gate
            if (en?.Freshness is { } g)
            {
                double epochMs = g.EpochMs ?? 60_000;
                double fnow = g.Now ?? now;
                double skew = g.ClockSkewMs is double cs && double.IsFinite(cs) ? Math.Max(0, cs) : 0;
                var fr = IntentJs.Get(p, "freshness") as D;
                var br = IntentJs.Get(fr, "beacon_ref");
                var ep = IntentJs.Get(fr, "epoch");
                bool epochOk = IntentJs.IsSafeInteger(ep) && IntentJs.NumOf(ep) > 0;
                if (!(epochMs > 0) || !double.IsFinite(g.MaxAgeMs) || g.MaxAgeMs < 0 || !double.IsFinite(fnow))
                    st.FailWith("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)");
                else if (br is not string { Length: > 0 } || !epochOk)
                    st.FailWith("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)");
                else
                {
                    double anchor = IntentJs.NumOf(ep)!.Value * epochMs;
                    if (anchor > fnow + skew) st.FailWith("freshness", "freshness anchor is in the future");
                    else if (fnow - anchor > g.MaxAgeMs) st.FailWith("freshness", $"freshness anchor is stale (older than {JsCanon.NumberString(g.MaxAgeMs)} ms)");
                    else st.Set("freshness", Pass);
                }
            }

            // M5 attestation (the gate's verifier takes the slot of hooks.attestation), threshold, revocation
            var attGate = en?.Attestation;
            var attHook = attGate != null ? attGate.Verifier : hooks?.Attestation;
            RunHook(st, ctx, "attestation", attHook, ref enforcedT);
            if (attGate is { Required: true } && st.Checks.GetValueOrDefault("attestation") == NotEnforced)
                st.FailWith("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)");
            RunHook(st, ctx, "threshold", hooks?.Threshold, ref enforcedT);
            RunHook(st, ctx, "revocation", hooks?.Revocation, ref enforcedT);

            // zk_compliance: fail closed at the core
            if (p.ContainsKey("zk_compliance"))
            {
                RunHook(st, ctx, "zk_compliance", hooks?.Zk, ref enforcedT);
                var c = st.Checks.GetValueOrDefault("zk_compliance");
                if (c != Pass && c != Fail)
                    st.FailWith("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof");
            }
            if (p.ContainsKey("bond_ref")) st.Set("bond", NotEnforced);
        }
        catch (Exception e)
        {
            st.FailRaw("malformed", "malformed PCActn: " + e.Message);
        }

        if (!o.Assurance && o.RequireAssurance == null) return WithUnsupported(p, ResultOf(st), enforcedT);
        var src = new AssuranceSources
        {
            Pcactn = p,
            Hooks = new AssuranceHooks(hooks?.Attestation, hooks?.Zk, hooks?.Threshold, hooks?.Revocation),
            AttestationHook = o.Enforce?.Attestation?.Verifier,
        };
        if (o.RequireAssurance != null)
        {
            src.Checks = WithUnsupported(p, ResultOf(st), null).Checks.ToList();
            var unmet = Assurance.Unmet(Assurance.BuildReport(src), o.RequireAssurance);
            if (unmet == null) st.Set("assurance", Pass); else st.FailRaw("assurance", unmet); // the reason already starts "assurance: "
        }
        var outR = WithUnsupported(p, ResultOf(st), enforcedT);
        src.Checks = outR.Checks.ToList();
        outR.Assurance = Assurance.BuildReport(src);
        return outR;
    }

    static Result WithUnsupported(D p, Result r, double? t)
    {
        if (p.ContainsKey("bond_ref") && r.Checks.GetValueOrDefault("bond") == NotEnforced) r.Checks["bond"] = Unsupported;
        r.EnforcedT = t;
        return r;
    }

    static void RunHook(State st, CoreContext ctx, string name, Hook? hook, ref double? enforcedT)
    {
        var res = hook == null ? HookResult.None : hook(ctx);
        if (!res.Enforced) st.Set(name, NotEnforced);
        else if (res.Ok)
        {
            st.Set(name, Pass);
            if (name == "threshold" && res.T != null) enforcedT = res.T;
        }
        else st.FailWith(name, res.Reason ?? "rejected");
    }
}
