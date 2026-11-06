using System.Reflection;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of K5 workflow (DAG) authorization (test-data/k05-workflow.json.gz, TS reference
/// packages/pca/src/workflow.ts). Admission results compare in full (decision, code, step, at, pending).</summary>
public class K05WorkflowDiffTests
{
    const string M = "workflow";

    // AdmitInput is typed: a non-string pinned key or a non-integer clock cannot be passed (the reference denies them bad_workflow)
    static string? TypedAdmit(D c)
    {
        var a = K05.Args(c);
        if (a[1] is not (null or string) || a[2] is not (null or string)) return "non-string pinned key (typed port)";
        return K05.IsJsonInt(a[4]) && ((Num)a[4]!).Raw != "-0" ? null : "non-integer / -0 now (typed port: long Now)";
    }

    static AdmitInput In(L a) => new(a[0], (string?)a[1], (string?)a[2], a[3], K05.Long(a[4]), a[5]);

    [Fact] public void Admit() => K05.Check(M, "admit", a => Workflow.AdmitStep(In(a)).ToJson(), skip: TypedAdmit, min: 7800);
    [Fact] public void Bind() => K05.Check(M, "bind", a => Workflow.BindPromises(In(a)).ToJson(), skip: TypedAdmit, min: 2000);
    [Fact] public void ValidBody() => K05.Check(M, "validBody", a => Workflow.ValidWorkflowBody(a[0]), min: 3250);
    // the oracle only feeds valid bodies, so DagErrorOf's "malformed workflow" guard is never the answer
    [Fact] public void Dag() => K05.Check(M, "dag", a => Workflow.DagErrorOf((D)a[0]!), min: 440);

    // Ancestors / ParseBody are private (no internal entry point): reached by reflection, as UnitKillTests does for Pca internals
    static readonly MethodInfo ParseBody = typeof(Workflow).GetMethod("ParseBody", BindingFlags.NonPublic | BindingFlags.Static)!;
    static readonly MethodInfo AncestorsOf = typeof(Workflow).GetMethod("Ancestors", BindingFlags.NonPublic | BindingFlags.Static)!;

    [Fact]
    public void Ancestors() => K05.Check(M, "ancestors", a =>
    {
        var m = (Dictionary<string, HashSet<string>>?)AncestorsOf.Invoke(null, new[] { ParseBody.Invoke(null, new[] { a[0] }) });
        return m?.ToDictionary(e => e.Key, e => (object?)e.Value.OrderBy(s => s, StringComparer.Ordinal).Cast<object?>().ToList());
    }, min: 440);

    [Fact]
    public void PlanRoot() => K05.Check(M, "planRoot", a => Workflow.PlanRootAuthorized(a[0], (string?)a[1], K05.Long(a[2]), (string?)a[3]),
        skip: c => K05.Args(c)[1] is null or string && K05.Args(c)[3] is null or string && K05.IsJsonInt(K05.Args(c)[2]) ? null : "non-string key / non-integer now (typed port)",
        min: 105);

    [Fact] public void ValueDigest() => K05.Check(M, "valueDigest", a => Workflow.ValueDigest(a[0]), min: 9);
    [Fact] public void WorkflowDigest() => K05.Check(M, "workflowDigest", a => Workflow.WorkflowDigest((D)a[0]!), min: 1);
    [Fact] public void ReceiptRef() => K05.Check(M, "receiptRef", a => Workflow.ReceiptRef((D)a[0]!), min: 2);

    [Fact]
    public void EveryFn() => K05.Covers(M, new[] { "admit", "bind", "validBody", "dag", "ancestors", "planRoot", "valueDigest", "workflowDigest", "receiptRef" });
}
