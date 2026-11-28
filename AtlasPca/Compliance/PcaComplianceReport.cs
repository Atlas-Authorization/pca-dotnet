using System.Globalization;
using System.Text;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Compliance;

public static partial class PcaCompliance
{
    // ---- ComplianceReport ----
    sealed class Stats
    {
        public int Total, Verifiable, Denied, StepUp, Allowed, HumanOverrides, WithChain, WithPlanRoot, Agents, Principals;
        public object? MaxDepth = new Num("0");
        public object? SampleDigest = Undef;
    }

    static Stats ComputeStats(List<object?> events)
    {
        var agents = new JsSet(); var principals = new JsSet();
        var s = new Stats { Total = events.Count };
        foreach (var e in events)
        {
            if (!Truthy(e)) continue;
            if (Truthy(At(At(e, "evidence"), "cryptographicallyVerifiable"))) s.Verifiable++;
            var outcome = At(At(e, "decision"), "outcome");
            if (outcome is string o1 && o1 == "deny") s.Denied++;
            else if (outcome is string o2 && o2 == "step-up") s.StepUp++;
            else s.Allowed++;
            if (Truthy(Opt(Own(e, "humanOverride"), "humanApproved"))) s.HumanOverrides++;
            if (Length(At(At(e, "delegation"), "hops")) is int hl && hl > 0) s.WithChain++;
            if (!(At(At(e, "evidence"), "planRoot") is string pr && pr == "(none)")) s.WithPlanRoot++;
            var depth = At(At(e, "delegation"), "depth");
            if (Gt(depth, s.MaxDepth)) s.MaxDepth = depth;
            agents.Add(At(At(e, "agent"), "holder"));
            var principal = At(At(e, "agent"), "principal");
            if (!ReferenceEquals(principal, Undef)) principals.Add(principal);
            var digest = At(At(e, "evidence"), "pcactnDigest");
            if (ReferenceEquals(s.SampleDigest, Undef) && !(digest is string dg && dg == "(undigestible)")) s.SampleDigest = digest;
        }
        s.Agents = agents.Size; s.Principals = principals.Size;
        return s;
    }

    static string Status3(int n, int total) => n == total ? "satisfied" : n > 0 ? "partial" : "not-evidenced";

    static (string Status, string Evidence, L Findings) EvaluateControl(string controlId, Stats s)
    {
        var findings = new L();
        var total = s.Total;
        var digestNote = ReferenceEquals(s.SampleDigest, Undef) ? "" : " (e.g. " + Short(s.SampleDigest, 16) + ")";
        if (total == 0) return ("not-evidenced", "no actions in the reporting period", new L { "no events supplied — nothing to evidence" });
        switch (controlId)
        {
            case "eu-ai-act:art-12":
                if (s.Verifiable < total) findings.Add($"{I(total - s.Verifiable)} of {I(total)} entries are not cryptographically verifiable");
                return (s.Verifiable == total ? "satisfied" : "partial", $"{I(total)} actions logged; {I(s.Verifiable)}/{I(total)} cite a cryptographically verifiable proof{digestNote}", findings);
            case "eu-ai-act:art-50":
                return ("satisfied", $"{I(total)} actions each disclose the acting agent, the principal ({I(s.Principals)} distinct) and the automated decision outcome", findings);
            case "iso-42001:A.6.2.8":
                return ("satisfied", $"{I(total)} actions each carry a decision reason + risk/tier/budget reasoning trace", findings);
            case "iso-42001:A.9.2":
                if (s.WithChain < total) findings.Add($"{I(total - s.WithChain)} entries have no delegation chain");
                return (Status3(s.WithChain, total), $"{I(s.WithChain)}/{I(total)} actions carry an explicit delegation chain (max depth {Tpl(s.MaxDepth)}, {I(s.Principals)} authorizing principal(s))", findings);
            case "iso-42001:A.9.3":
                if (s.HumanOverrides > 0)
                    return ("satisfied", $"{I(s.HumanOverrides)} step-up(s) approved by a signed human co-signature; {I(s.StepUp)} step-up(s) and {I(s.Denied)} denial(s) show oversight enforced", findings);
                if (s.StepUp > 0 || s.Denied > 0)
                {
                    findings.Add("no human step-up co-signature was exercised in this period");
                    return ("partial", $"oversight boundary enforced ({I(s.StepUp)} step-up(s), {I(s.Denied)} denial(s)) but no signed human co-signature observed in the period", findings);
                }
                findings.Add("no higher-impact action required human oversight in this period");
                return ("partial", "all actions were auto-admitted within policy; no oversight event was triggered in the period", findings);
            case "iso-42001:A.6.2.2":
                if (s.WithPlanRoot < total) findings.Add($"{I(total - s.WithPlanRoot)} entries are not bound to a committed plan root");
                return (Status3(s.WithPlanRoot, total), $"{I(s.WithPlanRoot)}/{I(total)} actions are bound to a committed plan root (intended-use binding)", findings);
            case "soc2:CC6.1":
                if (s.Denied > 0) findings.Add($"{I(s.Denied)} out-of-scope action(s) denied — access control actively enforced");
                return ("satisfied", $"deny-by-default access over {I(total)} actions ({I(s.Allowed)} allowed, {I(s.StepUp)} step-up, {I(s.Denied)} denied); all gated by signed predicates + attenuation", findings);
            case "soc2:CC6.2":
                if (s.WithChain < total) findings.Add($"{I(total - s.WithChain)} entries are not traceable to an authorizing principal");
                return (Status3(s.WithChain, total), $"{I(s.Agents)} agent identit(ies) traceable to {I(s.Principals)} authorizing principal(s) via signed delegation chains", findings);
            case "soc2:CC6.3":
            {
                var narrowed = ToNum(s.MaxDepth) >= 1;
                if (!narrowed && s.Denied == 0) findings.Add("no attenuating hop or denial observed in the period");
                return (narrowed || s.Denied > 0 ? "satisfied" : "partial", $"access narrowed by attenuation (max delegation depth {Tpl(s.MaxDepth)}) and {I(s.Denied)} denied action(s)", findings);
            }
        }
        return ("not-evidenced", "no evaluator for this control", new L { "unmapped control" });
    }

    /// <summary>A structured ComplianceReport for <c>opts.framework</c> from AuditEvents: per-control status and evidence, the
    /// PCA-unique assurances and a coverage summary. <c>opts.now</c> (epoch ms) defaults to the clock.</summary>
    public static D ToComplianceReport(object? events, object? opts, Func<long>? clock = null)
    {
        var framework = At(opts, "framework");
        AssertFramework(framework);
        var fw = (string)framework!;
        var lst = new List<object?>();
        if (events is L el) foreach (var e in el) if (Truthy(e)) lst.Add(e);
        var now = Own(opts, "now");
        if (Nullish(now)) now = new Num(NowMs(clock).ToString(CultureInfo.InvariantCulture));
        var s = ComputeStats(lst);
        var items = new List<D>();
        foreach (var m in Table())
        {
            if ((string)m["framework"]! != fw) continue;
            var (status, evidence, findings) = EvaluateControl((string)m["controlId"]!, s);
            items.Add(new D
            {
                ["controlId"] = m["controlId"], ["controlTitle"] = m["controlTitle"], ["clause"] = m["clause"], ["framework"] = m["framework"],
                ["status"] = status, ["pcaEvidence"] = m["pcaEvidence"], ["evidence"] = evidence, ["findings"] = findings,
            });
        }
        var satisfied = items.Count(i => (string)i["status"]! == "satisfied");
        var partial = items.Count(i => (string)i["status"]! == "partial");
        var notEvidenced = items.Count(i => (string)i["status"]! == "not-evidenced");
        var total = items.Count;
        var fraction = total > 0 ? (double)satisfied / total : 0.0;
        object? frm = null, to = null; double lo = 0, hi = 0;
        foreach (var e in lst)
        {
            var x = At(At(At(e, "timestamps"), "issuedAt"), "epochMs");
            if (!Finite(x)) continue;
            var d = Dbl(x);
            if (frm == null || d < lo) { frm = x; lo = d; }
            if (to == null || d > hi) { to = x; hi = d; }
        }
        var st = s.Total;
        var assurances = new D
        {
            ["cryptographicallyVerifiable"] = st > 0 && s.Verifiable == st,
            ["explicitDelegationChain"] = st > 0 && s.WithChain == st,
            ["signedHumanOverrides"] = s.HumanOverrides > 0,
            ["narrative"] = st == 0 ? "No events in scope."
                : $"{I(s.Verifiable)}/{I(st)} entries cite a cryptographically verifiable proof; {I(s.WithChain)}/{I(st)} carry an explicit delegation chain; {I(s.HumanOverrides)} step-up(s) carry a signed human co-signature.",
        };
        var summary = $"{fw}: {I(satisfied)}/{I(total)} controls satisfied{(partial > 0 ? $", {I(partial)} partial" : "")}{(notEvidenced > 0 ? $", {I(notEvidenced)} not evidenced" : "")} over {I(st)} action(s).";
        return new D
        {
            ["schema"] = "atlas-pca/compliance-report/v1",
            ["framework"] = fw,
            ["generatedAt"] = Ts(now),
            ["period"] = new D { ["from"] = Ts(frm ?? new Num("0")), ["to"] = Ts(to ?? new Num("0")) },
            ["eventCount"] = st,
            ["assurances"] = assurances,
            ["items"] = items.Cast<object?>().ToList(),
            ["coverage"] = new D
            {
                ["total"] = total, ["satisfied"] = satisfied, ["partial"] = partial, ["notEvidenced"] = notEvidenced,
                ["satisfiedFraction"] = fraction, ["satisfiedPercent"] = JsRound(fraction * 100),
            },
            ["summary"] = summary,
        };
    }

    // ---- renderers ----
    /// <summary>The report as stable, pretty JSON (<c>JSON.stringify(report, null, 2)</c>).</summary>
    public static string RenderJson(object? report) => Pretty(report);

    static string Glyph(object? status) => status is string s ? s switch { "satisfied" => "✓", "partial" => "◐", "not-evidenced" => "·", _ => "undefined" } : "undefined";

    static string Upper(object? v)
    {
        var s = v as string;
        if (s is null) throw TypeError("toUpperCase is not a function");
        return s.Replace("ß", "SS", StringComparison.Ordinal).ToUpperInvariant();
    }

    static object? Walk(object? o, params string[] path)
    {
        foreach (var k in path) o = At(o, k);
        return o;
    }

    /// <summary>The elements of a <c>for (const x of v)</c>: a string yields its code points.</summary>
    static IEnumerable<object?> Iterate(object? v)
    {
        if (v is L l) return l;
        if (v is string s)
        {
            var o = new List<object?>();
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(s.Substring(i, 2)); i++; }
                else o.Add(s[i].ToString());
            }
            return o;
        }
        throw TypeError("not iterable");
    }

    /// <summary>The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail).</summary>
    public static string RenderMarkdown(object? report)
    {
        var r = report;
        object? G(params string[] path) => Walk(r, path);
        var lines = new List<string>
        {
            "# PCA compliance evidence — " + Tpl(G("framework")),
            "",
            $"Generated {Tpl(G("generatedAt", "iso"))} · {Tpl(G("eventCount"))} action(s) · coverage: {Tpl(G("coverage", "satisfied"))}/{Tpl(G("coverage", "total"))} satisfied ({Tpl(G("coverage", "satisfiedPercent"))}%)",
        };
        if (Gt(G("eventCount"), new Num("0")))
        {
            lines.Add("");
            lines.Add($"Reporting period: {Tpl(G("period", "from", "iso"))} → {Tpl(G("period", "to", "iso"))}");
        }
        lines.Add("");
        lines.Add("## Why this trail is admissible (what PCA uniquely provides)");
        lines.Add("");
        lines.Add($"- **Cryptographically verifiable** — {(Truthy(G("assurances", "cryptographicallyVerifiable")) ? "YES" : "PARTIAL")}: every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.");
        lines.Add($"- **Explicit delegation chain** — {(Truthy(G("assurances", "explicitDelegationChain")) ? "YES" : "PARTIAL")}: each action records who authorized what scope, hop by hop, rooted at a principal.");
        lines.Add($"- **Signed human-overrides** — {(Truthy(G("assurances", "signedHumanOverrides")) ? "YES" : "none in period")}: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.");
        lines.Add("");
        lines.Add("> " + Tpl(G("assurances", "narrative")));
        lines.Add("");
        lines.Add("## Coverage summary");
        lines.Add("");
        lines.Add("| Satisfied | Partial | Not evidenced | Total |");
        lines.Add("| --- | --- | --- | --- |");
        lines.Add($"| {Tpl(G("coverage", "satisfied"))} | {Tpl(G("coverage", "partial"))} | {Tpl(G("coverage", "notEvidenced"))} | {Tpl(G("coverage", "total"))} |");
        lines.Add("");
        lines.Add("## Controls");
        lines.Add("");
        lines.Add("| Control | Clause | Status | Evidence in period |");
        lines.Add("| --- | --- | --- | --- |");
        var items = G("items") as L;
        if (items is null) throw TypeError("items is not iterable");
        foreach (var i in items)
            lines.Add($"| {Tpl(At(i, "controlTitle"))} (`{Tpl(At(i, "controlId"))}`) | {Tpl(At(i, "clause"))} | {Glyph(At(i, "status"))} {Upper(At(i, "status"))} | {Tpl(At(i, "evidence"))} |");
        lines.Add("");
        lines.Add("## Control detail");
        lines.Add("");
        foreach (var i in items)
        {
            lines.Add($"### {Tpl(At(i, "controlId"))} — {Tpl(At(i, "controlTitle"))}");
            lines.Add("");
            lines.Add("- Clause: " + Tpl(At(i, "clause")));
            lines.Add($"- Status: {Glyph(At(i, "status"))} {Upper(At(i, "status"))}");
            lines.Add("- PCA evidence basis: " + Tpl(At(i, "pcaEvidence")));
            lines.Add("- Evidence in period: " + Tpl(At(i, "evidence")));
            if (Length(At(i, "findings")) is int n && n > 0)
            {
                lines.Add("- Findings:");
                foreach (var f in Iterate(At(i, "findings"))) lines.Add("  - " + Tpl(f));
            }
            lines.Add("");
        }
        lines.Add("---");
        lines.Add("");
        lines.Add("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._");
        return string.Join("\n", lines);
    }
}
