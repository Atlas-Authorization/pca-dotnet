// The agent-facing half of human approvals: review an intended action against a facade agent (auto / deny / step-up with its goal lineage and
// canonical render), the goal lineage a step-up carries, batch review, standing "approve this class for N hours" coverage and time-boxing a
// grant. Nothing here authorizes anything; the resource server's verifier stays the authority.
using System.Globalization;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Options of <see cref="Approvals.ReviewAction"/>; every member is optional.</summary>
public sealed class ReviewOptions
{
    /// <summary>The clock (epoch ms); null: the wall clock.</summary>
    public long? Now;
    /// <summary>Plaintext goal carried on a step-up request (shown to the approver).</summary>
    public string? Goal;
    /// <summary>Standing class approvals that can downgrade a step-up to auto.</summary>
    public IReadOnlyList<object?>? Standing;
    /// <summary>Builds the canonical approval render of an action (what the approver must be shown). A throw makes the review a deny; without a renderer
    /// (and without <see cref="InsecureUnboundApproval"/>) a step-up is a deny: what the approver sees is what is signed.</summary>
    public Func<string, string, D?, D>? Renderer;
    /// <summary>DOCUMENTED INSECURE opt-out: keep the pre-render behaviour of an unbound request.</summary>
    public bool InsecureUnboundApproval;
}

public static class Approvals
{
    static double NumOf(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    static bool ResourceMatches(string? pattern, string resource)
    {
        if (pattern == null || pattern == "*") return true;
        if (pattern.EndsWith('*')) return resource.StartsWith(pattern[..^1], StringComparison.Ordinal);
        return pattern == resource;
    }

    /// <summary>True while the standing approval is in force (grantedAt &lt;= now &lt; grantedAt + ttlMs) and covers the verb and the resource.</summary>
    public static bool ClassApprovalCovers(D a, string verb, string resource, double now)
    {
        double granted = NumOf(a.GetValueOrDefault("grantedAt")), ttl = NumOf(a.GetValueOrDefault("ttlMs"));
        if (!double.IsFinite(now) || !double.IsFinite(granted) || !double.IsFinite(ttl)) return false;
        if (!(now >= granted) || !(now < granted + ttl)) return false;
        if (a.GetValueOrDefault("verbs") is not L verbs || !verbs.Any(v => v is string s && s == verb)) return false;
        return ResourceMatches(a.GetValueOrDefault("resource") as string, resource);
    }

    public static bool CoveredByAny(IEnumerable<object?> approvals, string verb, string resource, double now) =>
        approvals.Any(a => a is D d && ClassApprovalCovers(d, verb, resource, now));

    /// <summary>The step-up requests among a batch of reviews ({kind: step_up, request}).</summary>
    public static L PendingRequests(IEnumerable<object?> reviews)
    {
        var o = new L();
        foreach (var r in reviews) if (r is D m && m.GetValueOrDefault("kind") is "step_up") o.Add(m["request"]);
        return o;
    }

    // ---- goal lineage -------------------------------------------------------------------------------------------------------

    static string JsText(double d) => JsX.JsNumString(d);

    static string FormatLimit(ParsedLimit limit)
    {
        var b = limit.Unit == "usd" ? "$" + JsText(limit.Amount) : JsText(limit.Amount);
        if (limit.PeriodMs is not long ms) return b;
        double hours = ms / 3_600_000d;
        var period = hours % 24 == 0 && hours >= 24 ? JsText(hours / 24) + "d" : hours >= 1 ? JsText(hours) + "h" : JsText(Math.Floor(ms / 60_000d + 0.5)) + "m";
        return b + "/" + period;
    }

    static string? SummarizeParams(D? prms, string? amountField)
    {
        if (prms == null) return null;
        if (amountField != null && prms.ContainsKey(amountField)) return amountField + "=" + JsX.Str(prms[amountField]);
        var keys = IntentJs.JsKeys(prms.Keys).ToList();
        if (keys.Count == 0) return null;
        return string.Join(", ", keys.Take(4).Select(k => k + "=" + (prms[k] is null or D or L ? JsJson.Stringify(prms[k]) : JsX.Str(prms[k]))));
    }

    static D Node(string kind, string label, string? detail)
    {
        var n = new D { ["kind"] = kind, ["label"] = label };
        if (detail != null) n["detail"] = detail;
        return n;
    }

    public static string GoalCommitOf(AgentHandle agent) => Pca.ReadEnvelope(agent.Grant) is { } env && env.GetValueOrDefault("goal_commit") is string s ? s : "";

    /// <summary>The goal lineage of one intended action ("you approved X because you asked to Y"): the grant's goal commitment, threaded through the delegated
    /// authority that admits the verb, down to the action. <paramref name="goal"/> (plaintext, may be null) is checked against the commitment with the agent's
    /// salt: goalVerified says whether it opens it, so an inbox shows "unverified" rather than lie. Signs nothing.</summary>
    public static D BuildGoalLineage(AgentHandle agent, string verb, string resource, D? prms, string? goal)
    {
        var goalCommit = GoalCommitOf(agent);
        bool verified = goal != null && goalCommit.Length > 0 && !string.IsNullOrEmpty(agent.GoalSalt) && Issue.GoalCommit(goal, agent.GoalSalt) == goalCommit;
        var spec = agent.Policy.Actions.FirstOrDefault(s => s.Verb == verb);
        ParsedLimit? limit = null;
        foreach (var kv in agent.Policy.Limits) if (kv.Key == verb) limit = kv.Value;

        var goalLabel = goal != null ? "Pursue the goal: “" + goal + "”" : "Pursue the grant’s committed goal";
        var goalDetail = goal != null
            ? (verified ? "verified: this goal opens the signed grant commitment" : "unverified: the revealed goal does not open the grant commitment")
            : goalCommit.Length > 0 ? "committed as " + goalCommit : null;
        var authorityLabel = "Delegated authority to " + verb + (limit != null ? " (up to " + FormatLimit(limit) + ")" : "");
        var chain = new L
        {
            Node("goal", goalLabel, goalDetail),
            Node("authority", authorityLabel, spec != null && !string.IsNullOrEmpty(spec.Description) ? spec.Description : null),
            Node("action", verb + " " + resource, SummarizeParams(prms, spec?.AmountField)),
        };
        var because = goal != null
            ? "Approving " + verb + " on " + resource + " because you asked to “" + goal + "”."
            : "Approving " + verb + " on " + resource + ", authorized under the grant’s committed goal.";
        var o = new D();
        if (goal != null) o["goal"] = goal;
        o["goalCommit"] = goalCommit;
        o["goalVerified"] = verified;
        o["chain"] = chain;
        o["because"] = because;
        return o;
    }

    /// <summary>A lineage flattened to plain text lines (SMS, plain email, Slack fallback): "label — detail", or the label alone when the hop has no
    /// (truthy) detail. A label that is not a string is returned as is, like the reference.</summary>
    public static L DescribeGoalLineage(D? lineage)
    {
        if (lineage == null) throw new ArgumentException("describeGoalLineage: lineage required");
        if (lineage.GetValueOrDefault("chain") is not L chain) throw new ArgumentException("describeGoalLineage: chain must be a list");
        var o = new L();
        foreach (var h in chain)
        {
            if (h == null) throw new ArgumentException("describeGoalLineage: a hop must not be null");
            if (h is not D n) { o.Add(null); continue; } // a primitive has no label or detail
            var detail = n.GetValueOrDefault("detail"); var label = n.GetValueOrDefault("label");
            if (JsX.Truthy(detail)) o.Add((n.ContainsKey("label") ? JsX.Str(label) : "undefined") + " — " + JsX.Str(detail));
            else o.Add(label);
        }
        return o;
    }

    // ---- review -------------------------------------------------------------------------------------------------------------

    static double RiskForReview(AgentHandle agent, string verb, D? prms)
    {
        var spec = agent.Policy.Actions.FirstOrDefault(s => s.Verb == verb);
        double? kappa = IntentJs.NumOf(agent.Policy.RiskPolicy.GetValueOrDefault("kappa")) is double k && double.IsFinite(k) ? k : null;
        if (agent.Policy.BudgetModel == "dollars" && spec?.AmountField is { } f)
        {
            var amt = Actions.JsNumber(prms?.GetValueOrDefault(f), prms != null && prms.ContainsKey(f));
            if (double.IsFinite(amt) && kappa is > 0) return Math.Max(0, Math.Min(1, amt / kappa.Value));
        }
        return Math.Max(0, Math.Min(1, spec != null ? spec.BlastRadius : 0.8));
    }

    static D Review(string kind, string? reason = null)
    {
        var m = new D { ["kind"] = kind };
        if (reason != null) m["reason"] = reason;
        return m;
    }

    /// <summary>Review an intended action against the agent's grant. {kind: auto}: no human needed; {kind: deny, reason}: the grant's predicates or caveats forbid
    /// it, or no complete approval render could be made (fail closed); {kind: step_up, request}: admissible but needs a tier-2/3 co-sign, unless a standing class
    /// approval covers it. A step-up carries the canonical render and its digest, unless InsecureUnboundApproval is set and no renderer given.</summary>
    public static D ReviewAction(AgentHandle agent, string verb, string resource, D? prms = null, ReviewOptions? opts = null)
    {
        var op = opts ?? new ReviewOptions();
        long now = op.Now ?? AtlasPca.ReplayClock.NowMs();
        var dr = agent.DryRun(verb, resource, prms, now);
        if (!dr.Allowed) return Review("deny", dr.Reason ?? "denied by policy");
        if (dr.T is null or 1) return Review("auto");
        if (op.Standing != null && CoveredByAny(op.Standing, verb, resource, now)) return Review("auto");
        int tier = dr.T.Value;
        D? render = null; string? renderDigest = null;
        if (op.Renderer == null && !op.InsecureUnboundApproval)
            return Review("deny", "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true");
        if (op.Renderer != null)
        {
            try
            {
                render = op.Renderer(verb, resource, prms);
                renderDigest = Approval.RenderDigest(render);
            }
            catch (Exception err) { return Review("deny", "approval render failed (fail closed): " + err.Message); }
        }
        var goalCommit = GoalCommitOf(agent);
        var lineage = BuildGoalLineage(agent, verb, resource, prms, op.Goal);
        var request = new D
        {
            ["id"] = Pca.HashCanonical(new D { ["d"] = "atlas-pca/stepup/v1", ["verb"] = verb, ["resource"] = resource, ["params"] = prms, ["at"] = now }),
            ["verb"] = verb, ["resource"] = resource,
        };
        if (prms != null) request["params"] = prms;
        request["tier"] = (long)tier;
        request["reason"] = dr.Reason ?? "requires tier " + tier + " co-sign";
        request["goalCommit"] = goalCommit;
        if (op.Goal != null) request["goal"] = op.Goal;
        request["lineage"] = lineage;
        request["r"] = JsX.Number(RiskForReview(agent, verb, prms));
        request["requestedAt"] = now;
        if (render != null && renderDigest != null) { request["render"] = render; request["renderDigest"] = renderDigest; }
        return new D { ["kind"] = "step_up", ["request"] = request };
    }

    /// <summary>Review a batch of intended actions ({verb, resource, params?} each): the inbox's "N actions waiting".</summary>
    public static L BatchReview(AgentHandle agent, IEnumerable<D> calls, ReviewOptions? opts = null) =>
        new(calls.Select(c => (object?)ReviewAction(agent, (string)c["verb"]!, (string)c["resource"]!, c.GetValueOrDefault("params") as D, opts)));

    /// <summary>Narrow a capability to expire <paramref name="ttlMs"/> after <paramref name="now"/> by appending an expires caveat signed by the holder.
    /// Caveats are conjunctive and append-only, so this can only restrict, never widen.</summary>
    public static D TimeBox(D parent, SuiteKey holder, double ttlMs, double now)
    {
        var at = now + ttlMs;
        if (!double.IsFinite(at)) throw new ArgumentException("timeBox: the expiry must be a finite number");
        return Issue.Attenuate(parent, new L { new D { ["type"] = "expires", ["at"] = JsX.Number(at) } }, holder);
    }

    /// <summary>Mint a standing class approval ("approve these verbs for the next N hours"): <c>{id, verbs, resource?, grantedAt, ttlMs, by}</c>; the id commits to the
    /// sorted verbs, the resource, the grant time and the approver. <paramref name="now"/> null: the wall clock.</summary>
    public static D ApproveClass(IReadOnlyList<string> verbs, double ttlMs, string by, double? now = null, string? resource = null)
    {
        var grantedAt = now ?? AtlasPca.ReplayClock.NowMs();
        var sorted = verbs.ToList();
        sorted.Sort(IntentJs.CompareUtf8);
        var o = new D
        {
            ["id"] = Pca.HashCanonical(new D
            {
                ["d"] = "atlas-pca/class-approval/v1", ["verbs"] = new L(sorted.Cast<object?>()), ["resource"] = resource, ["grantedAt"] = JsX.Number(grantedAt), ["by"] = by,
            }),
            ["verbs"] = new L(verbs.Cast<object?>()),
        };
        if (resource != null) o["resource"] = resource;
        o["grantedAt"] = JsX.Number(grantedAt);
        o["ttlMs"] = JsX.Number(ttlMs);
        o["by"] = by;
        return o;
    }

    /// <summary>A human's decision on a request, as pure audit-trail data: <c>{requestId, decision, by, at}</c>.</summary>
    public static D RecordDecision(D request, string decision, string by, double? at = null) => new()
    {
        ["requestId"] = request.GetValueOrDefault("id"), ["decision"] = decision, ["by"] = by, ["at"] = JsX.Number(at ?? AtlasPca.ReplayClock.NowMs()),
    };

    /// <summary>Apply a human co-sign to the trust budget: a partial recharge (rho per co-sign) by default, or a full recharge to bMax. The only thing that raises the budget.</summary>
    public static TrustBudget ApplyCosign(TrustBudget budget, RiskPolicy policy, double now, bool full = false) =>
        full ? Risk.RechargeFull(policy.BMax, now) : Risk.Recharge(budget, policy.Rho, policy.BMax, now);
}
