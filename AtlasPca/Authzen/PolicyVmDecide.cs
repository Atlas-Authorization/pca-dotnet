using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Authzen;

/// <summary><c>deriveDecideInput</c> was called without <c>ctx.grant</c> (the verifier's own stored grant). The presented chain root is never used as the grant.</summary>
public sealed class DecideInputGrantRequiredException() : Exception("deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant")
{
    public string Code => "grant_required";
}

/// <summary>The Policy VM decision: whether the guardian share may be released for an action, the threshold and proof it then needs, the risk,
/// the budget admission and the budget afterwards. Pure and total: any fault is a denial carrying a reason (fail closed).
/// The input and the result are parsed-JSON trees. Input members: <c>grant</c>, <c>pqPins?</c>, <c>trustedRoot?</c>, <c>chain?</c>, <c>action</c>
/// ({action: {verb, resource, params, reversibility_class}, subject?, env?, toolBinding?}), <c>plan?</c>, <c>risk</c> (any of semanticDistance,
/// reversibility, blastRadius, taint, confidence, age), <c>budget</c> ({B, tau, asOf?}), <c>now</c>, <c>nodeId?</c>, <c>goalNodeId?</c>,
/// <c>caveatContext?</c>, <c>ageHorizonMs?</c>, <c>rFloor?</c>, <c>chainVerified?</c>, <c>k1?</c>. Result members: releaseGuardianShare,
/// requiredThreshold {t, proof, optimisticAllowed}, r, admit, needStepUp, reasons, budget, k1Bound?.</summary>
public static class PolicyVmDecide
{
    /// <summary>Classes recognised as non-irreversible (so the optimistic fast path may be offered); anything else is treated as irreversible.</summary>
    static readonly string[] FastPathClasses = { "reversible", "rate_limited", "costly" };

    static D Denied(string reason, object? budget) => new()
    {
        ["releaseGuardianShare"] = false,
        ["requiredThreshold"] = new D { ["t"] = Jx.N(3), ["proof"] = "strong", ["optimisticAllowed"] = false },
        ["r"] = Jx.N(1),
        ["admit"] = false,
        ["needStepUp"] = true,
        ["reasons"] = new L { reason },
        ["budget"] = Jx.IsUndef(budget) ? null : budget,
    };

    /// <summary>The default Policy VM of the AuthZEN PDP: derives the decision input from the PCActn and the context, then decides.</summary>
    public static D Vm(D pcactn, D ctx) => Decide(DeriveDecideInput(pcactn, ctx));

    /// <summary>Decides <paramref name="input"/>; never throws.</summary>
    public static D Decide(object? input)
    {
        var budgetIn = Jx.Opt(input, "budget");
        object? fallback = budgetIn == null || Jx.IsUndef(budgetIn) ? new D { ["B"] = Jx.N(0), ["tau"] = Jx.N(0) } : budgetIn;
        try { return SafeRegex.WithBudget(() => DecideInner(input, budgetIn)); }
        catch (Exception e) { return Denied("policy evaluation error (fail closed): " + e.Message, fallback); }
    }

    static object? NoK1(object? cs) => cs is L l ? l.Where(c => !CaveatLang.IsK1Caveat(c)).ToList() : cs;

    static IReadOnlyDictionary<string, string>? PinsOf(object? o)
    {
        if (o is not D d) return null;
        var m = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in d) if (v is string s) m[k] = s;
        return m;
    }

    static string? S(object? o) => o as string;

    internal static K1Input? K1Of(object? k1)
    {
        if (k1 is not D d) return null;
        List<DischargePin>? pins = null;
        if (d.GetValueOrDefault("pins") is L pl)
            pins = pl.OfType<D>().Select(p => new DischargePin(S(p.GetValueOrDefault("label")) ?? "", S(p.GetValueOrDefault("class")) ?? "", S(p.GetValueOrDefault("pk")) ?? "",
                S(p.GetValueOrDefault("pq_pk")), S(p.GetValueOrDefault("spiffe_id")))).ToList();
        var discharges = d.GetValueOrDefault("discharges") as L;
        var revoked = (d.GetValueOrDefault("revoked_discharges") as L)?.OfType<string>().ToList();
        var history = d.GetValueOrDefault("history") as L;
        var spiffe = S(d.GetValueOrDefault("spiffe_id"));
        var digest = S(d.GetValueOrDefault("action_digest"));
        return d.TryGetValue("narrow", out var narrow)
            ? new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = spiffe, History = history, ActionDigest = digest, Narrow = narrow }
            : new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = spiffe, History = history, ActionDigest = digest };
    }

    static TrustBudget BudgetOf(object? o)
    {
        D? d = null;
        double? bn = null;
        if ((d = o as D) is null || (bn = Jx.Fin(d.GetValueOrDefault("B"))) is null)
            throw new ArgumentException("budget is not a trust budget");
        var b = bn.Value;
        // a missing, non-numeric or non-finite tau is a budget the leak depletes (fail closed), not a malformed one
        var tau = Jx.IsNum(d.GetValueOrDefault("tau")) ? IntentJs.NumOf(d.GetValueOrDefault("tau")) ?? double.NaN : double.NaN;
        return new TrustBudget(b, tau, Jx.Fin(d.GetValueOrDefault("asOf")));
    }

    static D BudgetJson(TrustBudget b, bool tauGiven = true)
    {
        var o = new D { ["B"] = Jx.N(b.B) };
        if (tauGiven) o["tau"] = double.IsFinite(b.Tau) ? Jx.N(b.Tau) : (object?)b.Tau; // a budget given without a tau prints without one; a non-finite one stays a number (JSON prints it as null)
        if (b.AsOf != null) o["asOf"] = Jx.N(b.AsOf.Value);
        return o;
    }

    static D DecideInner(object? input, object? budgetIn)
    {
        var grant = Jx.Prop(input, "grant");
        var env = Pca.ReadEnvelope(grant);
        if (env == null) return Denied("grant carries no valid envelope", budgetIn);
        if (Jx.Fin(Jx.Prop(input, "now")) is not double now) return Denied("invalid decision time", budgetIn);
        var chainO = Jx.Prop(input, "chain");
        var hasChain = !Jx.IsUndef(chainO);

        // an unverified capability chain is DENIED here: unless the caller vouches it was verified, decide re-verifies it
        if (!(Jx.Prop(input, "chainVerified") is true))
        {
            var toVerify = chainO is L cl && cl.Count > 0 ? cl : new L { grant };
            var issuer = Jx.Opt(grant, "issuer");
            var (why, ok) = Pca.VerifyChain(toVerify, issuer is string ? issuer : null, issuer is string, null, PinsOf(Jx.Prop(input, "pqPins")), Jx.Prop(input, "trustedRoot") as D);
            if (!ok) return Denied("capability chain unverified: " + why, budgetIn);
        }

        var rp = Risk.PolicyOf(env["risk_policy"]) ?? throw new InvalidOperationException("risk policy");
        var reasons = new List<string>();
        var actionCtx = Jx.Prop(input, "action") as D ?? new D();
        var inner = actionCtx.GetValueOrDefault("action") as D;

        // 1. semantic predicates (default deny)
        var denial = Pca.EnvelopePredicates(env["predicates"], actionCtx);
        var prOk = denial == null;
        if (!prOk) reasons.Add(denial!);

        var nodeId = Jx.Prop(input, "nodeId");
        var plan = Jx.Prop(input, "plan");
        var risk = Jx.Prop(input, "risk");

        // the class the action is bound to: its own, else the plan node it names, else unknown (fail closed)
        object? revClass = Jx.Undef;
        var own = inner == null ? Jx.Undef : Jx.Prop(inner, "reversibility_class");
        if (!Jx.IsUndef(own) && own != null) revClass = own;
        else if (nodeId is string nid && plan is L planList)
            foreach (var n in planList)
                if (n != null && JsX.StrictEq(Jx.Opt(n, "id"), nid)) { revClass = Jx.Opt(n, "reversibility_class"); break; }

        // 2. envelope caveats
        var cctx = new D { ["now"] = Jx.Prop(input, "now"), ["action"] = inner ?? new D() };
        var bl = Jx.Opt(risk, "blastRadius");
        if (!Jx.IsUndef(bl)) cctx["blast_radius"] = bl;
        if (!Jx.IsUndef(revClass)) cctx["reversibility_class"] = revClass;
        if (Jx.Prop(input, "caveatContext") is D over)
            foreach (var (camel, snake) in new[] { ("now", "now"), ("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"), ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times") })
                if (over.TryGetValue(camel, out var ov)) cctx[snake] = ov;
        var toolParams = inner?.GetValueOrDefault("params") as D ?? new D();
        var toolCall = new ToolCall(inner?.GetValueOrDefault("verb") as string ?? "", toolParams, actionCtx.GetValueOrDefault("toolBinding") as string);

        var chainOk = true;
        var extra = new L();
        if (hasChain)
        {
            if (chainO is not L ch || ch.Count == 0)
            {
                chainOk = false;
                reasons.Add("delegation chain is empty or malformed");
            }
            else
            {
                cctx["delegation_depth"] = Jx.N(ch.Count - 1);
                var lcs = Jx.Prop(ch[^1], "caveats") as L ?? throw JsX.TypeError("slice is not a function");
                var gcs = Jx.Prop(grant, "caveats") as L ?? new L();
                extra = lcs.Skip(gcs.Count).ToList();
            }
        }
        var ecv = Pca.EvaluateAgentCaveats(env["caveats"], cctx, actionCtx, toolCall);
        if (!ecv.Ok) reasons.Add("caveat(s) not satisfied: " + string.Join(", ", ecv.Failed));

        // root caveats outside the envelope are signed authority too; the caveat-language (K1) types are evaluated over the whole chain
        var leafSrc = hasChain && chainO is L lc && lc.Count > 0 ? lc[^1] : grant;
        var k1In = Jx.Opt(input, "k1");
        var narrowPresent = k1In is D kd && kd.TryGetValue("narrow", out var nv) && !Jx.IsUndef(nv);
        var useK1 = (Jx.Opt(leafSrc, "caveats") is L leafCaveats && leafCaveats.Any(c => CaveatLang.IsK1Caveat(c))) || narrowPresent;
        K1Result? k1 = null;
        if (useK1)
        {
            var nowLong = now == Math.Floor(now) && Math.Abs(now) <= 9007199254740991.0 ? (long)now : long.MinValue;
            k1 = CaveatLang.EvaluateK1(grant, hasChain ? chainO : null, K1Of(k1In), new K1Context(nowLong, inner));
        }
        var rcv = Pca.EvaluateAgentCaveats(NoK1(Pca.RootCaveats(grant)), cctx, actionCtx, toolCall);
        if (!rcv.Ok) reasons.Add("root caveat(s) not satisfied: " + string.Join(", ", rcv.Failed));
        var cvOk = ecv.Ok && rcv.Ok;
        var dl = ((L)NoK1(extra)!).ToList();
        if (k1 != null) dl.AddRange(k1.Plain);
        var dcv = Pca.EvaluateAgentCaveats(dl, cctx, actionCtx, toolCall);
        var dcvOk = dcv.Ok;
        if (!dcv.Ok) reasons.Add("delegated caveat(s) not satisfied: " + string.Join(", ", dcv.Failed));
        if (k1 != null && !k1.Ok)
        {
            dcvOk = false;
            for (int i = 0; i < k1.Reasons.Count; i++) reasons.Add($"caveat language: {k1.Failed[i]}: {k1.Reasons[i]}");
        }

        // 3. risk
        var budget = BudgetOf(budgetIn);
        var tauGiven = budgetIn is D bin && bin.ContainsKey("tau");
        var leaked = Risk.Leak(budget, now, rp.Lambda);
        var keys = Risk.InputKeys;
        var inputs = new double[] { 1, 0, 1, 1, 0, 1 };
        var missing = new List<string>();
        for (int i = 0; i < keys.Length; i++)
        {
            if (Jx.Fin(Jx.Opt(risk, keys[i])) is double v) inputs[i] = v;
            else if (i != 5) missing.Add(keys[i]);
        }
        if (Jx.Truthy(plan) && Jx.IsUndef(Jx.Opt(risk, "semanticDistance")))
        {
            var goal = Jx.Prop(input, "goalNodeId");
            if (goal == null || Jx.IsUndef(goal)) goal = plan is L pl && pl.Count > 0 ? Jx.Opt(pl[^1], "id") : Jx.Undef;
            inputs[0] = !Jx.IsUndef(nodeId) && !Jx.IsUndef(goal) ? Risk.PlanGeodesic(plan, nodeId as string, goal as string) : 1;
            missing.Remove("semanticDistance");
        }
        if (Jx.IsUndef(Jx.Opt(risk, "age")))
        {
            var h = Jx.Prop(input, "ageHorizonMs");
            inputs[5] = Jx.IsUndef(h) ? Risk.AgeSinceTouch(leaked, now) : Risk.AgeSinceTouch(leaked, now, Jx.IsNum(h) ? IntentJs.NumOf(h) ?? double.NaN : double.NaN);
        }
        if (missing.Count > 0) reasons.Add("risk input(s) missing, assumed worst case: " + string.Join(", ", missing));
        var rFloor = Jx.Fin(Jx.Prop(input, "rFloor")) is double rf ? Math.Min(1, Math.Max(0, rf)) : 0;
        var r = Math.Max(Risk.Score(new RiskInputs(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5]), rp), rFloor);

        // reversibility fails CLOSED for the optimistic fast path: only a recognised non-irreversible class is eligible
        var rc = cctx.GetValueOrDefault("reversibility_class");
        var irreversible = !(rc is string rcs && FastPathClasses.Contains(rcs));
        var rt = Risk.Required(r, rp.Theta1, rp.Theta2, irreversible);

        // 4. budget admission
        var adm = Risk.AdmitOf(Risk.Required(r, rp.Theta1, rp.Theta2, false).T, double.IsFinite(leaked.B) && leaked.B >= Risk.Cost(r, rp.Kappa));
        if (adm.NeedStepUp)
            reasons.Add(rt.T < 3 && adm.T == 3 ? "trust budget depleted: human recharge required" : $"risk {Risk.ToFixed3(r)} exceeds auto threshold: step-up to t={adm.T}");

        // 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
        var dec = Risk.DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm);
        var outBudget = dec.Debit ? Risk.Debit(leaked, Risk.Cost(r, rp.Kappa)) : leaked;
        var res = new D
        {
            ["releaseGuardianShare"] = dec.Release,
            ["requiredThreshold"] = new D { ["t"] = Jx.N(dec.Threshold.T), ["proof"] = dec.Threshold.Proof, ["optimisticAllowed"] = dec.Threshold.OptimisticAllowed },
            ["r"] = Jx.N(r),
            ["admit"] = dec.Admit,
            ["needStepUp"] = dec.NeedStepUp,
            ["reasons"] = reasons.Cast<object?>().ToList(),
            ["budget"] = BudgetJson(outBudget, tauGiven),
        };
        if (k1 != null)
            res["k1Bound"] = k1.Bound.Select(b => (object?)new D { ["caveat"] = b.Caveat, ["hop"] = Jx.N(b.Hop), ["cap_hash"] = b.CapHash }).ToList();
        return res;
    }

    /// <summary>Assembles a <see cref="Decide"/> input from a PCActn plus the resource server's context, so caller and verifier derive the action, node
    /// id and chain identically. <paramref name="ctx"/>: grant (REQUIRED: the verifier's OWN stored grant, never the artifact's chain root; it is also
    /// the chain's trusted root), plan?, params? (checked by the caller against the action's params_digest), risk, budget, chain?, now, pqPins?,
    /// goalNodeId?, subject?, env?, caveatContext?, ageHorizonMs?. Throws <see cref="DecideInputGrantRequiredException"/> when there is no grant.</summary>
    public static D DeriveDecideInput(object? p, object? ctx)
    {
        var grant = Jx.Prop(ctx, "grant");
        if (grant == null || Jx.IsUndef(grant) || !(grant is D || grant is L)) throw new DecideInputGrantRequiredException();
        var chain = Jx.Prop(ctx, "chain");
        if (chain == null || Jx.IsUndef(chain)) chain = Jx.Prop(p, "cap_chain");
        var pa = Jx.Opt(p, "action");
        var inner = new D();
        Jx.Set(inner, "verb", Jx.Opt(pa, "verb"));
        Jx.Set(inner, "resource", Jx.Opt(pa, "resource"));
        var prm = Jx.Prop(ctx, "params");
        inner["params"] = prm == null || Jx.IsUndef(prm) ? new D() : prm;
        Jx.Set(inner, "reversibility_class", Jx.Opt(pa, "reversibility_class"));
        var action = new D { ["action"] = inner };
        var subject = Jx.Prop(ctx, "subject"); var env = Jx.Prop(ctx, "env");
        if (Jx.Truthy(subject)) action["subject"] = subject;
        if (Jx.Truthy(env)) action["env"] = env;

        var o = new D { ["grant"] = grant, ["trustedRoot"] = grant };
        Jx.Set(o, "pqPins", Jx.Prop(ctx, "pqPins"));
        Jx.Set(o, "chain", chain);
        o["action"] = action;
        Jx.Set(o, "plan", Jx.Prop(ctx, "plan"));
        Jx.Set(o, "nodeId", Jx.Opt(Jx.Opt(p, "plan"), "node_id"));
        Jx.Set(o, "goalNodeId", Jx.Prop(ctx, "goalNodeId"));
        Jx.Set(o, "risk", Jx.Prop(ctx, "risk"));
        Jx.Set(o, "budget", Jx.Prop(ctx, "budget"));
        Jx.Set(o, "now", Jx.Prop(ctx, "now"));
        Jx.Set(o, "caveatContext", Jx.Prop(ctx, "caveatContext"));
        Jx.Set(o, "ageHorizonMs", Jx.Prop(ctx, "ageHorizonMs"));
        return o;
    }
}
