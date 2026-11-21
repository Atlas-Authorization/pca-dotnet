// The reference verifyPCActn: the full verdict { allow, r, requiredThreshold, checks, reasons, budget?, assurance? } with the reference check names and reason texts.
// The (pcactn, grant, AuthorizeInput) overload projects the Authorize pipeline into that shape; the VerifyPcactnOptions overload is the reference verifier itself.
using AtlasPca.Analyzer;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class Pca
{
    /// <summary>The worst-case threshold a verdict that stopped before pricing reports (the reference's <c>WORST_THRESHOLD</c>).</summary>
    static JD WorstThreshold => new() { ["t"] = 3L, ["proof"] = "strong", ["optimisticAllowed"] = false };

    /// <summary>
    /// Verify a PCActn against the stored <paramref name="grant"/> and report the reference verdict. <paramref name="options"/> carries what
    /// <see cref="Authorize"/> takes (audience, operation, context, revocation answer, suites, pins, intent policy, ...); it is not modified.
    /// A missing <c>ResolveGrant</c> resolves to <paramref name="grant"/>. A missing <c>StateStore</c> gets a private in-memory one and the
    /// <c>replay</c> check is not reported (the reference reports it only when a replay hook is given). The <c>operation</c> and the revocation
    /// answer are required, as in <see cref="Authorize"/>: without them the verdict denies (fail closed). <paramref name="assurance"/> attaches the
    /// per-check assurance report (always attached when <c>RequireAssurance</c> is set). Never throws.
    /// </summary>
    public static JD VerifyPcactn(object? pcactn, JD grant, AuthorizeInput options, bool assurance = false)
    {
        var input = options.Copy();
        bool ownStore = input.StateStore == null;
        input.ResolveGrant ??= _ => grant;
        input.StateStore ??= new MemoryStateStore();
        var r = Authorize(pcactn, input);
        var checks = new JD();
        foreach (var (k, v) in r.Checks)
        {
            if (ownStore && k == "replay") continue;
            checks[k == "chain" ? "cap_chain" : k] = v;
        }
        var verdict = new JD
        {
            ["allow"] = r.Allow,
            ["r"] = r.RiskScore ?? 1.0,
            ["requiredThreshold"] = r.RequiredThreshold is { } t ? new JD { ["t"] = (long)t.T, ["proof"] = t.Proof, ["optimisticAllowed"] = t.OptimisticAllowed } : WorstThreshold,
            ["checks"] = checks,
            ["reasons"] = new JL(r.Reasons.Cast<object?>()),
        };
        if (r.Budget is { } b)
        {
            var bd = new JD { ["B"] = b.B, ["tau"] = b.Tau };
            if (b.AsOf is { } asOf) bd["asOf"] = asOf;
            verdict["budget"] = bd;
        }
        if (assurance || input.RequireAssurance != null) verdict["assurance"] = r.Assurance.ToJson();
        return verdict;
    }
}

/// <summary>What a resource server knows about the call, for <see cref="Pca.VerifyPcactn(object?, VerifyPcactnOptions)"/> (the reference <c>PcaContext</c>).</summary>
public sealed class VerifyContext
{
    /// <summary>The server's copy of the plan (a list of plan nodes, parsed JSON). When it is given it must be the committed one.</summary>
    public IReadOnlyList<object?>? Plan { get; set; }
    /// <summary>The principal authorized <see cref="Plan"/>: true passes, false fails, null leaves the check not-enforced (and, without the explicit opt-out, denied).</summary>
    public bool? PlanAuthorized { get; set; }
    /// <summary>Plaintext action params; they must hash to <c>action.params_digest</c>.</summary>
    public Dictionary<string, object?>? Params { get; set; }
    public Dictionary<string, object?>? Subject { get; set; }
    public Dictionary<string, object?>? Env { get; set; }
    /// <summary>The server's authoritative reversibility class; the agent's declared class may only be stricter.</summary>
    public string? ReversibilityClass { get; set; }
    /// <summary>The risk inputs the server vouches for (any of semanticDistance, reversibility, blastRadius, taint, confidence, age); a missing one is priced at its worst case.</summary>
    public IReadOnlyDictionary<string, double>? Risk { get; set; }
    /// <summary>The leaf holder's trust budget. Absent: not-enforced, and a fail-closed B=0 budget applies.</summary>
    public TrustBudget? Budget { get; set; }
    public IReadOnlyList<double>? RecentActionTimes { get; set; }
    /// <summary>The guardian-signed revocation epoch of the grant (reported as <c>freshness</c>).</summary>
    public VerifyRevocationEpoch? RevocationEpoch { get; set; }
    /// <summary>The dead-man liveness beacon of the grant (reported as <c>beacon</c>).</summary>
    public BeaconPresented? Beacon { get; set; }
}

/// <summary>The signed epoch a verifier requires, its pinned guardian and the optional rollback floor and maximum age.</summary>
public sealed record VerifyRevocationEpoch(Dictionary<string, object?> Epoch, string GuardianPublic, double? LastAcceptedEpoch = null, double? MaxAgeMs = null);

/// <summary>The options of <see cref="Pca.VerifyPcactn(object?, VerifyPcactnOptions)"/> (the reference <c>VerifyPCActnOptions</c>).</summary>
public sealed class VerifyPcactnOptions
{
    public VerifyPcactnOptions(Dictionary<string, object?> grant) { Grant = grant; }
    /// <summary>The verifier's OWN stored grant.</summary>
    public Dictionary<string, object?> Grant { get; set; }
    /// <summary>Explicit opt-out of <c>plan_root_authorized</c> (reported not-enforced instead of denied).</summary>
    public bool InsecureSkipPlanRootCheck { get; set; }
    /// <summary>This verifier's audience: <see cref="WithAudience"/> (must equal the signed <c>aud</c>), <see cref="AudienceAny"/> (explicit opt-out) or unset (fails when the PCActn carries an <c>aud</c>).</summary>
    public string? Audience { get; set; }
    public bool AudienceGiven { get; set; }
    public VerifyPcactnOptions WithAudience(string a) { Audience = a; AudienceGiven = true; return this; }
    public VerifyPcactnOptions AudienceAny() { Audience = null; AudienceGiven = true; return this; }
    public PcaCore.Hooks? Hooks { get; set; }
    /// <summary>Epoch ms (default: the wall clock).</summary>
    public long? Now { get; set; }
    public VerifyContext? Context { get; set; }
    /// <summary>Checks that must be <c>pass</c>; null: <see cref="PcaServer.DefaultRequiredChecks"/>; empty: report only.</summary>
    public IReadOnlyList<string>? Require { get; set; }
    public IReadOnlyCollection<string>? AllowedSuites { get; set; }
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    public IntentPolicy? IntentPolicy { get; set; }
    public IntentV2Context? IntentV2 { get; set; }
    public FreshAtPolicy? FreshAt { get; set; }
    /// <summary>The operation the server will execute (never from the PCActn); absent: no <c>operation</c> check. Its params replace <c>Context.Params</c>.</summary>
    public Operation? Operation { get; set; }
    public PcaCore.Enforce? Enforce { get; set; }
    public IReadOnlyList<string>? RequireRiskInputs { get; set; }
    /// <summary>Attach the per-check assurance report.</summary>
    public bool Assurance { get; set; }
    public AssuranceRequirement? RequireAssurance { get; set; }
    public IReadOnlyCollection<string>? AllowUnsupported { get; set; }
    /// <summary>Caveat language v2 input in its parsed form (<c>pins</c>, <c>discharges</c>, <c>revoked_discharges</c>, <c>spiffe_id</c>, <c>history</c>, <c>narrow</c>).</summary>
    public Dictionary<string, object?>? K1 { get; set; }
}

public static partial class Pca
{
    static JD FailClosed(string reason, JD? checks = null)
    {
        var cs = new JD();
        if (checks != null) foreach (var kv in checks) cs[kv.Key] = kv.Value;
        cs["malformed"] = "fail";
        return new JD { ["allow"] = false, ["r"] = 1.0, ["requiredThreshold"] = WorstThreshold, ["checks"] = cs, ["reasons"] = new JL { reason } };
    }

    /// <summary>
    /// The reference <c>verifyPCActn</c>: verify a PCActn (an object, or its encoded text) against the verifier's own grant and report the full verdict
    /// <c>{ allow, r, requiredThreshold, checks, reasons, budget?, assurance?, k1Bound? }</c> with the reference's check names and reason texts. Offline and total:
    /// any internal error is a fail-closed verdict. The default <see cref="VerifyPcactnOptions.Require"/> denies unless the replay-free profile passed.
    /// </summary>
    public static JD VerifyPcactn(object? pcactn, VerifyPcactnOptions opts)
    {
        var v = VerifyChecks(pcactn, opts);
        // a verdict that stopped before the checks ran still reports its outcomes when asked
        if ((opts.Assurance || opts.RequireAssurance != null) && !v.ContainsKey("assurance"))
        {
            var cs = ((JD)v["checks"]!).Select(e => new KeyValuePair<string, string>(e.Key, (string)e.Value!)).ToList();
            v["assurance"] = Assurance.BuildReport(new AssuranceSources { Checks = cs }).ToJson();
        }
        return v;
    }

    static string Js1(object? x) => IntentRevocation.JsText(x, true);

    static JD VerifyChecks(object? pcactn, VerifyPcactnOptions opts)
    {
        try
        {
            object? p0;
            try { p0 = pcactn is string txt ? PcaHelpers.DecodePcactn(txt) : pcactn; }
            catch (Exception e) { return FailClosed("undecodable PCActn: " + e.Message); }
            if (p0 is not JD && p0 is not JL) return FailClosed("PCActn is not an object");
            var grant = opts.Grant;
            var ctx = opts.Context ?? new VerifyContext();
            long now = opts.Now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var op = opts.Operation;
            var ctxParams = ctx.Params;
            var prms = op?.Params != null ? op.Params as JD : ctx.Params; // the operation's params are the action params
            bool prmsGiven = op?.Params != null || ctx.Params != null;
            var grantEnv = ReadEnvelope(grant);
            bool needsModelRules = grantEnv != null && IntentV2.NeedsModelRules(grant);
            IntentV2Context? v2 = opts.IntentV2;
            if (v2 == null && needsModelRules) v2 = IntentV2Context.FromJson(new JD());
            if (v2 != null && v2.WellFormed) v2 = v2.WithDefaults(prms, ctx.Env);
            IntentV2.Decision? v2d = p0 is JD pj && (pj.ContainsKey("intent_session") || needsModelRules) ? IntentV2.Decide(pj, grant, v2, now) : null;

            var co = new PcaCore.Options(grant)
            {
                NowEpoch = now, Audience = opts.Audience, AudienceGiven = opts.AudienceGiven, Hooks = opts.Hooks, Enforce = opts.Enforce, AllowedSuites = opts.AllowedSuites,
                PlanRoots = PlanRootPolicy.Skip, IntentPolicy = opts.IntentPolicy, IntentV2 = v2, FreshAt = opts.FreshAt,
            };
            var core = PcaCore.Verify(p0, co);
            // a wire-form failure is terminal: nothing else is evaluated on a malformed object
            if (core.Checks.GetValueOrDefault("wire") == PcaCore.Fail) return FailClosed(core.Reason ?? "wire: malformed PCActn", new JD { ["wire"] = "fail" });
            var p = (JD)p0;

            var order = new List<string>();
            var st = new Dictionary<string, string>();
            var reasons = new List<string>();
            void Mark(string name, string s) { if (!st.ContainsKey(name)) order.Add(name); st[name] = s; }
            void Fail(string name, string why) { Mark(name, "fail"); reasons.Add(name + ": " + why); }
            var unsupported = new List<string>();
            foreach (var (k, c) in core.Checks)
            {
                if (c == PcaCore.Unsupported) unsupported.Add(k);
                Mark(k, c == PcaCore.Unsupported ? PcaCore.NotEnforced : c);
            }
            if (!core.Allow && core.Reason != null) reasons.Add(core.Reason);
            // the core keeps only its FIRST failure reason; every failed intent-v2 check is reported
            if (v2d != null)
            {
                var folded = PcaDecision.FoldV2Reasons(reasons, v2d.Checks.Select(c => new PcaDecision.V2CheckResult(c.Name, c.Ok, c.Reason)));
                reasons.AddRange(folded.Skip(reasons.Count));
            }

            // server-side PQ pin for a non-Ed25519 grant (fail closed)
            if (opts.PqPins is { } pqPins)
            {
                var alg = IntentJs.Get(grant, "alg") as string ?? "ed25519";
                var gi = IntentJs.Get(grant, "issuer") as string;
                var pin = gi != null && pqPins.TryGetValue(gi, out var pv) ? pv : null;
                if (alg == "ed25519")
                {
                    if (pin != null) Fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused");
                    else Mark("pq_pin", "pass");
                }
                else if (pin != null && IntentJs.Get(grant, "pq_pk") is string gpk && pin == gpk) Mark("pq_pin", "pass");
                else Fail("pq_pin", pin == null ? $"no server-side PQ pin for the grant issuer (suite {alg})" : "the grant pq_pk does not match the server-side pin");
            }

            // grant_ref binds the object to this grant
            if (Equals(IntentJs.Get(p, "grant_ref"), IntentJs.Get(grant, "id"))) Mark("grant_ref", "pass");
            else Fail("grant_ref", "does not reference the supplied grant");

            var action = IntentJs.Get(p, "action") as JD;
            // the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
            if (op != null)
            {
                var signed = $"{Js1(IntentJs.Get(action, "verb"))} on {Js1(IntentJs.Get(action, "resource"))}";
                if (op.Verb is not string || op.Resource is not string) Fail("operation", "the server operation has no verb / resource (fail closed)");
                else if (!Equals(IntentJs.Get(action, "verb"), op.Verb) || !Equals(IntentJs.Get(action, "resource"), op.Resource))
                    Fail("operation", $"the proof is for {signed}, but this operation is {op.Verb} on {op.Resource}");
                else if (op.Params != null && !Equals(HashCanonical(op.Params), IntentJs.Get(action, "params_digest")))
                    Fail("operation", $"the proof's params_digest does not match the params of this {op.Verb} operation");
                else if (op.Params != null && ctxParams != null && HashCanonical(ctxParams) != HashCanonical(op.Params))
                    Fail("operation", "context.params differ from the operation params");
                else Mark("operation", "pass");
            }

            // params plaintext must open the committed digest
            if (prmsGiven)
            {
                if (Equals(HashCanonical(op?.Params ?? ctx.Params), IntentJs.Get(action, "params_digest"))) Mark("params_digest", "pass");
                else Fail("params_digest", "supplied params do not hash to action.params_digest");
            }
            else Mark("params_digest", "not-enforced");

            // the RS's own copy of the plan must be the committed one
            var planObj = IntentJs.Get(p, "plan");
            var planRoot = IntentJs.Get(planObj, "root");
            if (ctx.Plan == null)
            {
                if (opts.InsecureSkipPlanRootCheck) Mark("plan_root_authorized", "not-enforced");
                else Fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)");
            }
            else if (!Equals(MerkleRoot(ctx.Plan.Select(n => (object?)NodeLeaf(n)).ToList()), planRoot)) Fail("plan_root_authorized", "known plan does not match plan.root");
            else if (ctx.PlanAuthorized == true) Mark("plan_root_authorized", "pass");
            else if (ctx.PlanAuthorized == false) Fail("plan_root_authorized", "the plan root has not been authorized by the principal");
            else if (opts.InsecureSkipPlanRootCheck) Mark("plan_root_authorized", "not-enforced");
            else Fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)");

            if (ctx.RevocationEpoch is { } re)
            {
                var r = RevocationFreshness.CheckEpoch(re.Epoch, new EpochCheckOptions
                {
                    GuardianPublic = re.GuardianPublic, Now = now, GrantRef = IntentJs.Get(grant, "id") as string,
                    LastAcceptedEpoch = re.LastAcceptedEpoch, MaxAgeMs = re.MaxAgeMs, PcactnEpoch = IntentJs.NumOf(IntentJs.Get(IntentJs.Get(p, "freshness"), "epoch")),
                });
                // an enforce.freshness failure from the core stands (a passing epoch never overwrites it)
                if (r.Ok) { if (st.GetValueOrDefault("freshness") != "fail") Mark("freshness", "pass"); }
                else Fail("freshness", r.Reason ?? "revocation epoch rejected");
            }
            else if (!st.ContainsKey("freshness")) Mark("freshness", "not-enforced");

            {
                var bc = ctx.Beacon;
                BeaconVerdict? br = bc == null ? null : Beacons.Verify(bc.Beacon, new BeaconCheck { Issuers = bc.Issuers, Now = now, Instance = bc.Instance, Scope = IntentJs.Get(grant, "id") as string, PqPins = bc.PqPins });
                var seq = bc == null ? null : IntentJs.NumOf(IntentJs.Get(bc.Beacon, "seq"));
                bool replayed = bc != null && br!.Ok && bc.LastAcceptedSeq != null && seq is double sq && sq < bc.LastAcceptedSeq;
                bool refBinds = bc != null && br!.Ok && !replayed && Equals(IntentJs.Get(IntentJs.Get(p, "freshness"), "beacon_ref"), Beacons.Ref(bc.Beacon));
                if (bc == null) Mark("beacon", "not-enforced");
                else if (!br!.Ok) Fail("beacon", br.Reason ?? "beacon rejected");
                else if (replayed) Fail("beacon", $"beacon seq {JsCanon.NumberString(seq!.Value)} is older than the last accepted {bc.LastAcceptedSeq} (replay)");
                else if (!refBinds) Fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon");
                else Mark("beacon", "pass");
            }

            // require-when-bound: a grant whose agent_binding constrains the agent REQUIRES a passing, bound attestation
            if (RequiresAttestation(grantEnv != null ? IntentJs.Get(grantEnv, "agent_binding") : null) && st.GetValueOrDefault("attestation") != "pass")
                Fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED");

            var chain = IntentJs.Get(p, "cap_chain") as JL ?? new JL();
            var leaf = chain.Count > 0 ? chain[^1] : null;
            int depth = Math.Max(0, chain.Count - 1);
            // fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0)
            var budgetIn = ctx.Budget ?? new TrustBudget(0, now, now);
            Mark("budget", ctx.Budget != null ? "pass" : "not-enforced");
            if (ctx.Budget == null) reasons.Add("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge");

            // only an RS-supplied value counts as a risk input
            var risk = ctx.Risk ?? new Dictionary<string, double>();
            if (opts.RequireRiskInputs is { Count: > 0 } req)
            {
                bool Supplied(string k) => (risk.TryGetValue(k, out var rv) && double.IsFinite(rv)) || (k == "semanticDistance" && ctx.Plan != null);
                var missing = req.Where(k => !Supplied(k)).ToList();
                if (missing.Count > 0) Fail("risk_inputs", "required risk input(s) not supplied by the server: " + string.Join(", ", missing));
                else Mark("risk_inputs", "pass");
            }

            // reversibility: the RS's authoritative class wins; the agent may only be STRICTER
            var declared = IntentJs.Get(action, "reversibility_class");
            object? reversibility = declared;
            if (ctx.ReversibilityClass != null)
            {
                int dr = ClassRank(declared), sr = ClassRank(ctx.ReversibilityClass);
                if (dr < sr) Fail("reversibility", $"declared class '{Js1(declared)}' is less restrictive than the authoritative '{ctx.ReversibilityClass}'");
                else Mark("reversibility", "pass");
                reversibility = dr > sr ? declared : ctx.ReversibilityClass;
            }

            var inner = new JD { ["verb"] = IntentJs.Get(action, "verb"), ["resource"] = IntentJs.Get(action, "resource") };
            if (prms != null) inner["params"] = prms;
            if (reversibility != null) inner["reversibility_class"] = reversibility;
            var actionCtx = new JD { ["action"] = inner };
            if (ctx.Subject != null) actionCtx["subject"] = ctx.Subject;
            var predEnv = V2Env(p, grant, v2, now, ctx.Env);
            if (predEnv != null) actionCtx["env"] = predEnv;
            if (IntentJs.Get(p, "tool_binding") is string tb) actionCtx["toolBinding"] = tb;

            var digest = CaveatLang.DischargeActionDigest(p);
            JD? k1For(bool withNarrow)
            {
                if (opts.K1 == null) return null;
                var k = new JD(opts.K1);
                if (!withNarrow) k.Remove("narrow");
                k["action_digest"] = digest;
                return k;
            }
            var nodeId = IntentJs.Get(planObj, "node_id");
            var dIn = new JD { ["grant"] = grant, ["trustedRoot"] = grant, ["action"] = actionCtx, ["now"] = Jx.N(now) };
            if (opts.PqPins != null) dIn["pqPins"] = opts.PqPins.ToDictionary(e => e.Key, e => (object?)e.Value);
            if (ctx.Plan != null) dIn["plan"] = new JL(ctx.Plan);
            if (nodeId != null) dIn["nodeId"] = nodeId;
            var riskD = new JD();
            foreach (var (rk, rv) in risk) riskD[rk] = Jx.N(rv);
            dIn["risk"] = riskD;
            var budgetD = new JD { ["B"] = Jx.N(ctx.Budget == null ? 0 : budgetIn.B), ["tau"] = Jx.N(budgetIn.Tau) };
            if (budgetIn.AsOf != null) budgetD["asOf"] = Jx.N(budgetIn.AsOf.Value);
            dIn["budget"] = budgetD;
            var cav = new JD { ["delegationDepth"] = Jx.N(depth) };
            if (ctx.RecentActionTimes != null) cav["recentActionTimes"] = ctx.RecentActionTimes.Select(t => Jx.N(t)).ToList<object?>();
            dIn["caveatContext"] = cav;
            if (k1For(false) is { } k1d) dIn["k1"] = k1d;
            if (IntentJs.Get(p, "caution") is object cau && IntentJs.NumOf(cau) is double cn) dIn["rFloor"] = Jx.N(cn);
            var d = Authzen.PolicyVmDecide.Decide(dIn);
            bool release = d["releaseGuardianShare"] is true;
            var rt = (JD)d["requiredThreshold"]!;
            int tNeed = (int)IntentJs.NumOf(rt["t"])!.Value;
            var proof = (string)rt["proof"]!;
            double rScore = IntentJs.NumOf(d["r"])!.Value;

            // caveats added by delegation hops (beyond the root's) are conjunctive too
            K1Result? k1r = null;
            if (leaf != null)
            {
                var gcs = IntentJs.Get(grant, "caveats") as JL ?? new JL();
                var lcs = IntentJs.Get(leaf, "caveats") as JL ?? throw new InvalidOperationException("leaf.caveats.slice is not a function");
                var extra = lcs.Skip(gcs.Count).ToList();
                bool useK1 = lcs.Any(c => CaveatLang.IsK1Caveat(c)) || (opts.K1 != null && opts.K1.ContainsKey("narrow"));
                if (useK1) k1r = CaveatLang.EvaluateK1(grant, chain, Authzen.PolicyVmDecide.K1Of(k1For(true)), new K1Context(now, inner));
                var cctx = new JD { ["now"] = now, ["delegation_depth"] = (long)depth, ["action"] = inner };
                if (risk.TryGetValue("blastRadius", out var bl)) cctx["blast_radius"] = Jx.N(bl);
                var rc = ResolveReversibilityClass(actionCtx, ctx.Plan, nodeId as string);
                if (rc != null) cctx["reversibility_class"] = rc;
                if (ctx.RecentActionTimes != null) cctx["recent_action_times"] = ctx.RecentActionTimes.Select(t => Jx.N(t)).ToList<object?>();
                var plain = extra.Where(c => !CaveatLang.IsK1Caveat(c)).Concat(k1r?.Plain ?? Array.Empty<object?>()).ToList();
                var cv = EvaluateAgentCaveats(plain, cctx, actionCtx, ToolCallOf(actionCtx));
                if (cv.Ok && (k1r?.Ok ?? true)) Mark("delegated_caveats", "pass");
                else Fail("delegated_caveats", $"delegation caveat(s) not satisfied: {string.Join(", ", cv.Failed.Concat(k1r?.Failed ?? Array.Empty<string>()))}{(k1r != null && !k1r.Ok ? $" ({string.Join("; ", k1r.Reasons)})" : "")}");
            }

            // policy: the check mirrors the Policy VM's release decision; its reasons (also the informational ones when released) are kept in order
            Mark("policy", release ? "pass" : "fail");
            foreach (var x in (JL)d["reasons"]!) reasons.Add("policy: " + (string)x!);

            // threshold: t > 1 needs an ENFORCED threshold hook that reported at least the SERVER-derived t
            double? hookT = core.EnforcedT;
            double? hookTInt = hookT is double ht0 && !double.IsNaN(ht0) ? (ht0 >= 9007199254740991.0 ? 9007199254740991.0 : ht0 <= -9007199254740991.0 ? -9007199254740991.0 : Math.Floor(ht0)) : null;
            var th = st.GetValueOrDefault("threshold");
            if (tNeed > 1 && release)
            {
                if (th == "pass" && !(hookTInt is double hi && hi >= tNeed))
                    Fail("threshold", $"threshold hook enforced t={(hookT is double hv ? (double.IsNaN(hv) ? "NaN" : double.IsPositiveInfinity(hv) ? "Infinity" : double.IsNegativeInfinity(hv) ? "-Infinity" : JsCanon.NumberString(hv)) : "unreported")} but the server requires t={tNeed} (below the server-derived threshold; derive t from server-held data)");
                else if (th == "fail") Fail("threshold", $"t={tNeed} required and the threshold proof was rejected");
                else if (th != "pass") Fail("threshold", $"t={tNeed} ({proof}) required but no threshold verifier is enforced");
            }

            var required = opts.Require ?? PcaServer.DefaultRequiredChecks;
            bool wantAssurance = opts.Assurance || opts.RequireAssurance != null;
            var hk = opts.Hooks;
            AssuranceSources Src(IEnumerable<KeyValuePair<string, string>> cs) => new()
            {
                Pcactn = p, Hooks = new AssuranceHooks(hk?.Attestation, hk?.Zk, hk?.Threshold, hk?.Revocation), AttestationHook = opts.Enforce?.Attestation?.Verifier ?? hk?.Attestation,
                ThresholdT = hookT, Checks = cs.ToList(),
                Degraded = v2d is { Legacy: true } ? new Dictionary<string, string> { ["tighten"] = LegacyPolarityDegraded } : null,
            };
            if (opts.RequireAssurance != null)
            {
                var unmet = Assurance.Unmet(Assurance.BuildReport(Src(order.Select(n => new KeyValuePair<string, string>(n, st[n])))), opts.RequireAssurance);
                if (unmet == null) Mark("assurance", "pass");
                else { Mark("assurance", "fail"); reasons.Add(unmet); }
            }

            bool allow = !st.ContainsValue("fail") && release && core.Allow;
            foreach (var n in unsupported) if (st.GetValueOrDefault(n) == "not-enforced") st[n] = "unsupported";
            // a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
            var refused = unsupported.Where(n => !(opts.AllowUnsupported?.Contains(n) ?? false)).ToList();
            JD Finish(bool a, List<string> rs, JD? extraFields)
            {
                var ev = PcaServer.EnforceRequired(a, order.Select(n => new KeyValuePair<string, string>(n, st[n])), rs, required);
                var cd = new JD();
                foreach (var (k, v) in ev.Checks) cd[k] = v;
                var o = new JD { ["allow"] = ev.Allow, ["r"] = rScore, ["requiredThreshold"] = new JD { ["t"] = (long)tNeed, ["proof"] = proof, ["optimisticAllowed"] = rt["optimisticAllowed"] is true }, ["checks"] = cd, ["reasons"] = new JL(ev.Reasons) };
                if (extraFields != null) foreach (var kv in extraFields) o[kv.Key] = kv.Value;
                return o;
            }
            JD BudgetOut() { var bd = (JD)d["budget"]!; var b = new JD { ["B"] = IntentJs.NumOf(bd["B"])!.Value, ["tau"] = IntentJs.NumOf(bd["tau"])!.Value }; if (bd.TryGetValue("asOf", out var ao) && IntentJs.NumOf(ao) is double av) b["asOf"] = av; return b; }
            void Assure(JD o)
            {
                if (!wantAssurance) return;
                var cs = ((JD)o["checks"]!).Select(e => new KeyValuePair<string, string>(e.Key, (string)e.Value!)).ToList();
                o["assurance"] = Assurance.Refresh(Assurance.BuildReport(Src(cs)), cs).ToJson();
            }
            if (refused.Count > 0)
            {
                var rs = reasons.Concat(refused.Select(n => $"{n}: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)")).ToList();
                var o = Finish(false, rs, null);
                Assure(o);
                return o;
            }
            var ex = new JD();
            if (allow && ctx.Budget != null) ex["budget"] = BudgetOut();
            if (k1r != null && k1r.Bound.Any(b => IntentJs.Get(b.Caveat, "type") as string == "max_uses"))
                ex["k1Bound"] = k1r.Bound.Select(b => (object?)new JD { ["caveat"] = b.Caveat, ["hop"] = (long)b.Hop, ["cap_hash"] = b.CapHash }).ToList();
            var outv = Finish(allow, reasons, ex);
            // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
            if (!(bool)outv["allow"]! && ctx.Budget != null && PcaDecision.DecisionOf(outv) == "escalate") outv["budget"] = BudgetOut();
            if (!(bool)outv["allow"]! && ((JL)outv["reasons"]!).Count == 0) outv["reasons"] = new JL { "denied" };
            Assure(outv);
            return outv;
        }
        catch (Exception e) { return FailClosed("verifier error (fail closed): " + e.Message); }
    }
}
