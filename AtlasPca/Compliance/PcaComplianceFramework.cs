using System.Globalization;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Compliance;

public static partial class PcaCompliance
{
    // ---- framework report (console activity stream) ----
    sealed class BaseSummary
    {
        public int TotalActions, Autonomous, HumanOverseen, Denied, AttributableAgents;
        public double AutonomousBound, MaxTaintObserved;

        public D ToD() => new()
        {
            ["totalActions"] = TotalActions, ["autonomous"] = Autonomous, ["humanOverseen"] = HumanOverseen, ["denied"] = Denied,
            ["attributableAgents"] = AttributableAgents, ["autonomousBound"] = AutonomousBound, ["maxTaintObserved"] = MaxTaintObserved,
        };
    }

    static double SafetyBound(object? p)
    {
        var kappa = At(p, "kappa"); var bMax = At(p, "bMax");
        if (!Gt(kappa, new Num("0"))) return 0;
        var b = ToNum(bMax);
        return (double.IsNaN(b) ? double.NaN : Math.Max(0.0, b)) / ToNum(kappa);
    }

    static BaseSummary ComputeBase(object? inp)
    {
        if (At(inp, "events") is not L events) throw TypeError("e.filter is not a function");
        var p = At(At(inp, "policy"), "riskPolicy");
        var decisions = Opt(inp, "decisions");
        var dlen = Nullish(decisions) ? 0 : Length(decisions);
        double taint = 0.0;
        foreach (var x in events)
        {
            var t = At(x, "taint");
            var v = ReferenceEquals(t, Undef) ? 0.0 : Finite(t) ? Dbl(t) : double.PositiveInfinity;
            taint = Math.Max(taint, v);
        }
        var agents = new JsSet();
        foreach (var x in events) agents.Add(At(x, "agent"));
        int Count(Func<object?, bool> f) => events.Count(f);
        var kap = ToNum(At(p, "kappa"));
        return new BaseSummary
        {
            TotalActions = events.Count,
            Autonomous = Count(x => At(x, "outcome") is string o && (o == "auto" || o == "executed")),
            HumanOverseen = Count(x => At(x, "outcome") is string o && o == "step_up") + (dlen ?? 0),
            Denied = Count(x => At(x, "outcome") is string o && o == "deny"),
            AttributableAgents = agents.Size,
            AutonomousBound = SafetyBound(p) * kap,
            MaxTaintObserved = taint,
        };
    }

    static D Period(L events)
    {
        object? lo = null, hi = null; double dl = 0, dh = 0;
        foreach (var e in events)
        {
            var a = At(e, "at");
            if (!Finite(a)) continue;
            var d = Dbl(a);
            if (lo == null || d < dl) { lo = a; dl = d; }
            if (hi == null || d > dh) { hi = a; dh = d; }
        }
        return new D { ["from"] = lo ?? new Num("0"), ["to"] = hi ?? new Num("0") };
    }

    static D Ctl(string id, string name, string status, string evidence) => new() { ["id"] = id, ["name"] = name, ["status"] = status, ["evidence"] = evidence };

    static string PassWarn(bool ok) => ok ? "pass" : "warn";

    static L EuAiActControls(object? inp, BaseSummary s)
    {
        var logged = s.TotalActions > 0;
        var bound = s.AutonomousBound;
        var oversight = s.HumanOverseen > 0 || double.IsFinite(bound);
        var goal = Truthy(Own(inp, "hasGoalCommitment"));
        return new L
        {
            Ctl("art12-record-keeping", "Automatic logging of events", PassWarn(logged), $"{I(s.TotalActions)} attributable actions recorded"),
            Ctl("art14-human-oversight", "Human oversight", PassWarn(oversight), $"{I(s.HumanOverseen)} human-reviewed actions; autonomous bound {JsNumString(bound)}"),
            Ctl("art15-robustness", "Bounded autonomy (accuracy/robustness)", double.IsFinite(bound) ? "pass" : "fail", $"machine-checked safety bound = {JsNumString(bound)} between human co-signs"),
            Ctl("art13-transparency", "Transparency / traceability", PassWarn(goal), goal ? "every action binds to a signed goal commitment (lineage)" : "no goal commitment supplied"),
        };
    }

    static L Soc2Controls(object? inp, BaseSummary s)
    {
        var constrained = Opt(Own(inp, "policy"), "predicates") is L preds && preds.Count > 0;
        const string noPreds = "the supplied policy lists no predicates";
        return new L
        {
            Ctl("cc6.1-access", "Logical access — least privilege", PassWarn(constrained), constrained ? "actions constrained by signed predicates + capability attenuation (deny by default)" : noPreds),
            Ctl("cc7.2-monitoring", "Monitoring of anomalies", PassWarn(s.TotalActions > 0), $"{I(s.Denied)} denied + {I(s.HumanOverseen)} escalated actions captured"),
            Ctl("cc7.3-audit-trail", "Audit trail", PassWarn(s.TotalActions > 0), $"{I(s.TotalActions)} content-addressed actions across {I(s.AttributableAgents)} agents"),
            Ctl("cc8.1-change", "Change management (policy integrity)", PassWarn(constrained), constrained ? "policy is signed into the grant; tampering breaks verification" : noPreds),
        };
    }

    static L GdprControls(object? inp, BaseSummary s)
    {
        var goal = Truthy(Own(inp, "hasGoalCommitment"));
        var erasure = Truthy(Own(inp, "erasureSupported"));
        return new L
        {
            Ctl("art5-purpose", "Purpose limitation", PassWarn(goal), goal ? "actions bound to a committed goal/purpose" : "no goal commitment supplied"),
            Ctl("art5-minimization", "Data minimisation", PassWarn(s.TotalActions > 0), $"taint-gated data flows; max taint observed = {JsNumString(s.MaxTaintObserved)}"),
            Ctl("art5-accountability", "Accountability", PassWarn(s.AttributableAgents > 0), $"{I(s.AttributableAgents)} attributable agent identities"),
            Ctl("art17-erasure", "Right to erasure", PassWarn(erasure), erasure ? "erasure path wired" : "erasure path not asserted"),
        };
    }

    /// <summary>A compliance evidence report for a framework from the console activity stream: <paramref name="inp"/> is
    /// <c>{policy, events, decisions?, hasGoalCommitment?, erasureSupported?}</c>; the time defaults to the clock.</summary>
    public static D FrameworkReport(object? framework, object? inp, Func<long>? clock = null) =>
        FrameworkReport(framework, inp, new Num(NowMs(clock).ToString(CultureInfo.InvariantCulture)));

    /// <summary>As <see cref="FrameworkReport(object?, object?, Func{long}?)"/> with an explicit <c>generatedAt</c> (any JSON value, as given).</summary>
    public static D FrameworkReport(object? framework, object? inp, object? now)
    {
        var summary = ComputeBase(inp);
        if (!(framework is string fw && FrameworkIds.Contains(fw)))
            throw new ArgumentException($"frameworkReport: unknown framework '{Tpl(framework)}' (have: {string.Join(", ", FrameworkIds)})");
        var controls = fw switch { "eu-ai-act" => EuAiActControls(inp, summary), "soc2" => Soc2Controls(inp, summary), _ => GdprControls(inp, summary) };
        return new D
        {
            ["framework"] = fw,
            ["generatedAt"] = now,
            ["period"] = Period((L)At(inp, "events")!),
            ["summary"] = summary.ToD(),
            ["controls"] = controls,
            ["pass"] = controls.All(c => (string)((D)c!)["status"]! != "fail"),
        };
    }

    static string DateIso(object? v) => ToIsoString(v == null ? 0 : v is bool b ? (b ? 1 : 0) : v);

    /// <summary>A short Markdown block of a framework report, for an audit package.</summary>
    public static string FrameworkReportToMarkdown(object? r)
    {
        var summary = At(r, "summary");
        if (At(r, "controls") is not L controls) throw TypeError("r.controls.map is not a function");
        var lines = new List<string>
        {
            "# PCA compliance evidence — " + Tpl(At(r, "framework")),
            "",
            $"Generated {DateIso(At(r, "generatedAt"))} · {Tpl(At(summary, "totalActions"))} actions · {Tpl(At(summary, "attributableAgents"))} agents · overall: {(Truthy(At(r, "pass")) ? "PASS" : "FAIL")}",
            "",
            "| Control | Status | Evidence |",
            "| --- | --- | --- |",
        };
        foreach (var c in controls)
            lines.Add($"| {Tpl(At(c, "name"))} ({Tpl(At(c, "id"))}) | {Upper(At(c, "status"))} | {Tpl(At(c, "evidence"))} |");
        lines.Add("");
        lines.Add("_Evidence mapping, not a legal certification._");
        return string.Join("\n", lines);
    }
}
