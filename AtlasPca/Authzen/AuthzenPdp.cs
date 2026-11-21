using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Authzen;

/// <summary>How an AuthZEN request resolves to PCA authority. <see cref="Resolve"/> returns a context map {grant, chain?, policy, plan?, risk?,
/// budget?, enforce?, toAction? (Func&lt;D, D&gt;)} or null (deny). The verifier enforcement gates (<c>enforce</c>) are not supported natively:
/// a context carrying them fails closed. The Policy-VM decision defaults to <see cref="PolicyVmDecide"/>; <see cref="PolicyVm"/> replaces it.</summary>
public sealed class AuthzenPdpConfig
{
    public Func<D, D?> Resolve { get; init; } = _ => null;
    /// <summary>The verifier's own audience. <see cref="AudienceSet"/> false = omitted (fail closed when the PCActn carries an aud); set with a null <see cref="Audience"/> = accept any.</summary>
    public string? Audience { get; init; }
    public bool AudienceSet { get; init; }
    public IReadOnlyList<string>? AuthorizedPlanRoots { get; init; }
    public bool? InsecureSkipPlanRootCheck { get; init; }
    public Func<long>? Now { get; init; }
    public Func<string, string>? ToolCapability { get; init; }
    public bool? RequireProof { get; init; }
    /// <summary>The replay / revocation authorizer: input {operation, pcactn, provenance?}, result {allow, reason?}.</summary>
    public Func<D, Task<D>>? Authorizer { get; init; }
    public bool? RequireAuthorizer { get; init; }
    public int? MaxEvaluations { get; init; }
    /// <summary>Replaces the default Policy-VM (<see cref="PolicyVmDecide.Vm"/>): (pcactn, {grant, chain, plan?, params, risk, budget, now, subject?, env?}) to {releaseGuardianShare, admit, r, requiredThreshold, reasons}.</summary>
    public Func<D, D, D>? PolicyVm { get; init; }
}

/// <summary>PCA behind the OpenID AuthZEN Authorization API 1.0: Access Evaluation, the Access Evaluations boxcar and the COAZ tool profile.
/// Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any thrown error is decision false.</summary>
public sealed class AuthzenPdp
{
    public const int DefaultMaxEvaluations = 100;
    readonly AuthzenPdpConfig _cfg;
    public AuthzenPdp(AuthzenPdpConfig config) { _cfg = config; }

    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;

    /// <summary>x.k for the reference's property reads: null or undefined throws the V8 message.</summary>
    static object? Pv(object? o, string k)
    {
        if (o == null || Jx.IsUndef(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return G(o, k);
    }

    static D Deny(string reason, int? status = null)
    {
        var context = new D { ["reason_admin"] = new D { ["denied"] = true, ["reason"] = reason }, ["reason_user"] = new D { ["message"] = reason } };
        if (status != null) context["error"] = new D { ["status"] = Jx.N(status.Value), ["message"] = reason };
        return new D { ["decision"] = false, ["context"] = context };
    }

    static D Permit(string reason) => new() { ["decision"] = true, ["context"] = new D { ["reason_admin"] = new D { ["reason"] = reason } } };

    static object? PcActnFromContext(object? context)
    {
        if (context is not D c) return null;
        var raw = G(c, AuthzenGuards.PcaActionKey);
        if (Jx.IsUndef(raw) || raw == null) return null;
        if (raw is not string s) return "malformed";
        try
        {
            if (Pca.ArtifactTooLarge(s)) return "malformed";
            return Pca.ParseStrict(s) is D p ? p : "malformed";
        }
        catch (Exception) { return "malformed"; }
    }

    static D FreshBudget(object? grant, long now)
    {
        var env = Pca.ReadEnvelope(grant);
        var bMax = Jx.Fin(G(G(env, "risk_policy"), "bMax"));
        return new D { ["B"] = Jx.N(bMax ?? 0), ["tau"] = Jx.N(now), ["asOf"] = Jx.N(now) };
    }

    /// <summary>evaluate: one Access Evaluation request to {decision, context?}.</summary>
    public async Task<D> Evaluate(D req)
    {
        var now = (_cfg.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))();
        try
        {
            var ctx = _cfg.Resolve(req);
            if (ctx == null) return Deny("no PCA authority resolved for this request");
            var mapped = ctx.GetValueOrDefault("toAction") is Func<D, D> f ? f(req) : AuthzenGuards.DefaultToAction(req);
            var carried = PcActnFromContext(G(req, "context"));
            if (carried is string) return Deny("context carries a malformed PCActn");

            if (carried == null)
            {
                if (_cfg.RequireProof != false) return Deny("a signed PCActn is required (requireProof)");
                return AnalyzerCore.AdmitsConcrete(ctx.GetValueOrDefault("policy"), mapped)
                    ? Permit("statically admissible under the declared authority")
                    : Deny("action is not admissible under the declared authority");
            }

            var p = (D)carried;
            if (_cfg.RequireAuthorizer != false && _cfg.Authorizer == null) return Deny("no replay/revocation authorizer is configured (requireAuthorizer)");

            var act = Pv(p, "action");
            var verb = Pv(act, "verb"); var resource = Pv(act, "resource");
            var mv = mapped["verb"]; var mr = mapped["resource"];
            if (!(verb is string vs && mv is string mvs && vs == mvs) || !(resource is string rs && mr is string mrs && rs == mrs))
                return Deny($"the PCActn authorizes {JsX.Str(verb)} on {JsX.Str(resource)}, not the requested {JsX.Str(mv)} on {JsX.Str(mr)}");
            var reqParams = mapped.GetValueOrDefault("params") as D ?? new D();
            if (!(Pv(act, "params_digest") is string pd && Pca.ParamsDigest(reqParams) == pd))
                return Deny("the request attributes do not match the PCActn's signed params_digest");

            if (ctx.GetValueOrDefault("enforce") != null) throw new InvalidOperationException("authzen: enforce gates are not supported by this verifier (fail closed)");
            var grant = ctx.GetValueOrDefault("grant") as D ?? new D();
            var audience = _cfg.AudienceSet ? (_cfg.Audience ?? G(p, "aud") as string ?? "\u0000") : "\u0000"; // omitted: matches no aud (fail closed)
            var verify = PcaCore.Verify(p, new PcaCore.Options(grant) { NowEpoch = now, PlanRoots = new PlanRootPolicy(_cfg.AuthorizedPlanRoots, _cfg.InsecureSkipPlanRootCheck == true) }.WithAudience(audience));
            if (!verify.Allow)
            {
                return new D
                {
                    ["decision"] = false,
                    ["context"] = new D
                    {
                        ["reason_admin"] = new D { ["denied"] = true, ["stage"] = "verify", ["checks"] = verify.Checks.ToDictionary(kv => kv.Key, kv => (object?)kv.Value), ["reason"] = !string.IsNullOrEmpty(verify.Reason) ? verify.Reason : "PCActn verification failed" },
                        ["reason_user"] = new D { ["message"] = "the proof-carrying action did not verify" },
                    },
                };
            }

            var budget = ctx.GetValueOrDefault("budget") ?? FreshBudget(grant, now);
            var dctx = new D { ["grant"] = grant, ["chain"] = ctx.GetValueOrDefault("chain") ?? p.GetValueOrDefault("cap_chain") };
            if (ctx.GetValueOrDefault("plan") != null) dctx["plan"] = ctx["plan"];
            dctx["params"] = reqParams; dctx["risk"] = ctx.GetValueOrDefault("risk") ?? new D(); dctx["budget"] = budget; dctx["now"] = Jx.N(now);
            if (mapped.GetValueOrDefault("subject") != null) dctx["subject"] = mapped["subject"];
            if (mapped.GetValueOrDefault("env") != null) dctx["env"] = mapped["env"];
            var decision = (_cfg.PolicyVm ?? PolicyVmDecide.Vm)(p, dctx);

            if (!Jx.Truthy(G(decision, "releaseGuardianShare")))
                return new D
                {
                    ["decision"] = false,
                    ["context"] = new D
                    {
                        ["reason_admin"] = new D { ["denied"] = true, ["stage"] = "policy", ["reasons"] = G(decision, "reasons"), ["risk"] = G(decision, "r") },
                        ["reason_user"] = new D { ["message"] = "the policy does not permit this action" },
                    },
                };

            if (Jx.Truthy(G(decision, "admit")))
            {
                if (_cfg.Authorizer != null)
                {
                    var provenance = G(req, "context") is D rc ? G(rc, AuthzenGuards.PcaProvenanceKey) : Jx.Undef;
                    var input = new D { ["operation"] = new D { ["verb"] = mv, ["resource"] = mr, ["params"] = reqParams }, ["pcactn"] = p };
                    if (!Jx.IsUndef(provenance)) input["provenance"] = provenance;
                    var az = await _cfg.Authorizer(input).ConfigureAwait(false);
                    if (!Jx.Truthy(G(az, "allow")))
                    {
                        var adm = new D { ["denied"] = true, ["stage"] = "authorize" };
                        Jx.Set(adm, "reason", G(az, "reason"));
                        return new D { ["decision"] = false, ["context"] = new D { ["reason_admin"] = adm, ["reason_user"] = new D { ["message"] = "the proof-carrying action was not authorized" } } };
                    }
                }
                return new D { ["decision"] = true, ["context"] = new D { ["reason_admin"] = new D { ["stage"] = "policy", ["risk"] = G(decision, "r"), ["threshold"] = G(decision, "requiredThreshold") } } };
            }
            return ApprovalRequired(p, decision, grant, now);
        }
        catch (Exception err) { return Deny("evaluation error (fail closed): " + err.Message, 500); }
    }

    static D ApprovalRequired(D p, D decision, object? grant, long now)
    {
        var th = G(decision, "requiredThreshold");
        var tier = Jx.Fin(G(th, "t")) is double t && t >= 3 ? 3 : 2;
        var reasons = G(decision, "reasons") as L;
        var reason = reasons != null && reasons.Count > 0 && reasons[0] != null ? JsX.Str(reasons[0]) : $"requires tier-{tier} co-sign";
        var act = G(p, "action");
        var id = Pca.HashCanonical(new D
        {
            ["d"] = "atlas-pca/authzen/aarp/v1", ["verb"] = G(act, "verb"), ["resource"] = G(act, "resource"), ["params_digest"] = G(act, "params_digest"),
            ["counter"] = G(p, "counter"), ["at"] = Jx.N(now),
        });
        var gc = G(Pca.ReadEnvelope(grant), "goal_commit") as string ?? "";
        var pending = new D
        {
            ["approval_required"] = true, ["auth_req_id"] = id, ["tier"] = Jx.N(tier), ["required_threshold"] = th, ["goal_commit"] = gc,
            ["risk"] = G(decision, "r"), ["reason"] = reason, ["requested_at"] = Jx.N(now),
        };
        return new D
        {
            ["decision"] = false,
            ["context"] = new D
            {
                ["id"] = id,
                ["reason_admin"] = new D { ["stage"] = "step_up", ["risk"] = G(decision, "r"), ["threshold"] = th, ["reasons"] = G(decision, "reasons") },
                ["reason_user"] = new D { ["message"] = "approval required before this action can proceed" },
                [AuthzenGuards.PcaApprovalKey] = pending,
            },
        };
    }

    static D? Merge(D defaults, object? item)
    {
        object? Pick(string k) { var v = Pv(item, k); return v == null || Jx.IsUndef(v) ? G(defaults, k) : v; }
        var subject = Pick("subject"); var action = Pick("action"); var resource = Pick("resource"); var context = Pick("context");
        if (!AuthzenGuards.IsAuthzenSubject(subject) || !AuthzenGuards.IsAuthzenAction(action) || !AuthzenGuards.IsAuthzenResource(resource)) return null;
        var o = new D { ["subject"] = subject, ["action"] = action, ["resource"] = resource };
        if (!Jx.IsUndef(context)) o["context"] = context;
        return o;
    }

    /// <summary>evaluations: the boxcar endpoint with default inheritance and the three evaluation semantics.</summary>
    public async Task<D> Evaluations(D req)
    {
        var evs = Pv(req, "evaluations");
        if (evs is not L items) return new D { ["evaluations"] = new L() };
        var opts = Pv(req, "options");
        var sem = G(opts, "evaluations_semantic");
        var semantic = sem == null || Jx.IsUndef(sem) ? "execute_all" : sem;
        D[] RefuseAll(string reason) => items.Select(_ => Deny(reason, 400)).ToArray();
        D Wrap(IEnumerable<D> xs) => new() { ["evaluations"] = xs.Cast<object?>().ToList() };
        if (!(semantic is string s && (s == "execute_all" || s == "deny_on_first_deny" || s == "permit_on_first_permit"))) return Wrap(RefuseAll("unsupported evaluations_semantic"));
        var max = _cfg.MaxEvaluations ?? DefaultMaxEvaluations;
        if (items.Count > max) return Wrap(RefuseAll($"too many evaluations (limit {max})"));
        var merged = items.Select(i => Merge(req, i)).ToList();
        var outl = new List<D>();
        foreach (var m in merged)
        {
            var r = m == null ? Deny("incomplete evaluation (missing subject/action/resource)", 400) : await Evaluate(m).ConfigureAwait(false);
            outl.Add(r);
            if ((string)semantic == "deny_on_first_deny" && (bool)r["decision"]! == false) break;
            if ((string)semantic == "permit_on_first_permit" && (bool)r["decision"]! == true) break;
        }
        return Wrap(outl);
    }

    /// <summary>evaluateTool: the COAZ MCP-tool profile (tool to required capability to decision).</summary>
    public async Task<D> EvaluateTool(D req)
    {
        var tool = Pv(req, "tool");
        var name = Pv(tool, "name");
        string capability;
        try { capability = (_cfg.ToolCapability ?? (n => n))((string)name!); }
        catch (Exception err)
        {
            var r = Deny("evaluation error (fail closed): " + err.Message, 500);
            return new D { ["decision"] = false, ["tool"] = name, ["required_capability"] = "", ["context"] = r["context"] };
        }
        var action = new D { ["name"] = capability };
        var args = G(tool, "arguments");
        if (!Jx.IsUndef(args)) action["properties"] = args;
        var mapped = new D { ["subject"] = G(req, "subject"), ["action"] = action, ["resource"] = new D { ["type"] = "mcp_tool", ["id"] = name } };
        var ctx = G(req, "context");
        if (!Jx.IsUndef(ctx)) mapped["context"] = ctx;
        var resp = await Evaluate(mapped).ConfigureAwait(false);
        var o = new D { ["decision"] = resp["decision"], ["tool"] = name, ["required_capability"] = capability };
        if (resp.TryGetValue("context", out var c) && c != null) o["context"] = c;
        return o;
    }
}

/// <summary>The framework-agnostic AuthZEN HTTP handler over {path, body} maps.</summary>
public static class AuthzenHandler
{
    public const string EvaluationPath = "/access/v1/evaluation";
    public const string EvaluationsPath = "/access/v1/evaluations";
    public const string CoazToolPath = "/access/v1/mcp/tool/evaluation";

    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;
    static D Res(int status, object? body) => new() { ["status"] = Jx.N(status), ["body"] = body };
    static D Err(int status, string msg) => Res(status, new D { ["error"] = msg });

    /// <summary>The handler: a non-200 is a deny to a PEP, an internal failure never leaks detail.</summary>
    public static async Task<D> Handle(AuthzenPdp pdp, D req)
    {
        try
        {
            var path = G(req, "path"); var body = G(req, "body");
            switch (path as string)
            {
                case EvaluationPath:
                    if (!AuthzenGuards.IsAccessEvaluationRequest(body)) return Err(400, "invalid AuthZEN Access Evaluation request");
                    return Res(200, await pdp.Evaluate((D)body!).ConfigureAwait(false));
                case EvaluationsPath:
                    if (body is D bd && (Jx.IsUndef(G(bd, "evaluations")) || (G(bd, "evaluations") is L el && el.Count == 0)))
                    {
                        if (!AuthzenGuards.IsAccessEvaluationRequest(body)) return Err(400, "invalid AuthZEN Access Evaluations request");
                        return Res(200, await pdp.Evaluate(bd).ConfigureAwait(false));
                    }
                    if (!AuthzenGuards.IsAccessEvaluationsRequest(body)) return Err(400, "invalid AuthZEN Access Evaluations request");
                    return Res(200, await pdp.Evaluations((D)body!).ConfigureAwait(false));
                case CoazToolPath:
                    if (!AuthzenGuards.IsCoazToolAuthorizationRequest(body)) return Err(400, "invalid COAZ MCP-tool authorization request");
                    return Res(200, await pdp.EvaluateTool((D)body!).ConfigureAwait(false));
                default:
                    return Err(404, "unknown AuthZEN path: " + JsX.Str(path));
            }
        }
        catch (Exception) { return Err(500, "internal error"); }
    }
}
