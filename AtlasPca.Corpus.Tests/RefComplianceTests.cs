using AtlasPca;
using AtlasPca.Compliance;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the compliance evidence module (AuditEvent normalisation, the control-mapping table, per-framework
/// reports and their renderers, the console-activity framework report) against the TypeScript reference
/// (test-data/ref-compliance.json.gz). Reports must match text for text; a non-finite double is {"$num": text} in the oracle.</summary>
public class RefComplianceTests
{
    const string M = "ref-compliance";

    /// <summary>Non-finite doubles become the oracle's {"$num": text}; everything else is left to Base.Json.</summary>
    static object? Fix(object? v) => v switch
    {
        double d when !double.IsFinite(d) => new D { ["$num"] = AtlasPca.InteropJs.JsX.JsNumString(d) },
        D m => m.ToDictionary(e => e.Key, e => Fix(e.Value)),
        L l => l.Select(Fix).ToList(),
        _ => v,
    };

    [Fact]
    public void Constants() => Base.Check(M, "constants", a => Fix(PcaCompliance.Constants()));

    [Fact]
    public void ControlMappings() => Base.Check(M, "controlMappings", a => a.Count == 0 ? PcaCompliance.ControlMappings() : PcaCompliance.ControlMappings(a[0]));

    [Fact]
    public void ToAuditEvent() => Base.Check(M, "toAuditEvent", a => Fix(PcaCompliance.ToAuditEvent(a[0])));

    [Fact]
    public void ToComplianceReport() => Base.Check(M, "toComplianceReport", a => Fix(PcaCompliance.ToComplianceReport(a[0], a[1])));

    [Fact]
    public void RenderJson() => Base.Check(M, "renderJson", a => PcaCompliance.RenderJson(a[0]));

    [Fact]
    public void RenderMarkdown() => Base.Check(M, "renderMarkdown", a => PcaCompliance.RenderMarkdown(a[0]));

    [Fact]
    public void FrameworkReport() => Base.Check(M, "frameworkReport", a => Fix(a.Count > 2 ? PcaCompliance.FrameworkReport(a[0], a[1], a[2]) : PcaCompliance.FrameworkReport(a[0], a[1])));

    [Fact]
    public void FrameworkReportToMarkdown() => Base.Check(M, "frameworkReportToMarkdown", a => PcaCompliance.FrameworkReportToMarkdown(a[0]));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[] { "constants", "controlMappings", "toAuditEvent", "toComplianceReport", "renderJson", "renderMarkdown", "frameworkReport", "frameworkReportToMarkdown" }); Assert.Equal(812, Base.Total(M)); }
}
