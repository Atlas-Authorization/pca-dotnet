using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.AspNetCore.Tests;

// K5 (C-308): workflow admission inside Pca.Authorize, replaying packages/pca/conformance/authorize-workflow-fixtures.json
// (`pca-authorize-workflow-fixtures/1`, decided by the TypeScript reference). Each case threads its steps through ONE replay store; the
// fixture's plan is the principal-authorized plan. A missing fixture file FAILS the test.
public class WorkflowAuthorizeTests
{
    internal static JD Load()
    {
        var d = AppContext.BaseDirectory;
        for (var i = 0; i < 14 && d != null; i++, d = Path.GetDirectoryName(d))
            foreach (var rel in new[] { Path.Combine("packages", "pca", "conformance"), "conformance" })
            {
                var f = Path.Combine(d, rel, "authorize-workflow-fixtures.json");
                if (File.Exists(f)) return (JD)Pca.ParseJson(File.ReadAllText(f))!;
            }
        throw new FileNotFoundException("authorize-workflow-fixtures.json is missing (a fixture file is never skipped)", AppContext.BaseDirectory);
    }

    static JD D(object? o) => (JD)o!;
    static List<object?> L(object? o) => (List<object?>)o!;
    static long N(object? o) => long.Parse(((Num)o!).Raw, CultureInfo.InvariantCulture);

    static AuthorizeInput Input(JD F, JD step, IStateStore store, bool workflow, bool required)
    {
        var op = D(step["operation"]);
        var grant = D(F["grant"]);
        var input = new AuthorizeInput
        {
            Operation = new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]),
            Audience = (string)F["audience"]!,
            ResolveGrant = r => r == (string)grant["id"]! ? grant : null,
            StateStore = store, IsRevoked = (_, _) => false, Now = N(F["now"]), Plan = null,
            Context = _ => new JD { ["plan"] = F["plan"], ["plan_authorized"] = true },
        };
        if (workflow) input.Workflow = new WorkflowGate((string)F["principal"]!, (string)F["rs_signer"]!, required);
        if (step.GetValueOrDefault("workflow") is JD w)
            input.WorkflowCall = new WorkflowCall(w["commitment"], w["receipts"], w["step"] as string, w.GetValueOrDefault("units"), w.GetValueOrDefault("goal_digest") as string);
        return input.WithProv();
    }

    [Fact]
    public void SharedFixturesReplayThroughAuthorize()
    {
        var F = Load();
        Assert.Equal("pca-authorize-workflow-fixtures/1", F["format"]);
        Assert.True(L(F["cases"]).Count >= 14);
        foreach (var co in L(F["cases"]))
        {
            var c = D(co);
            var store = new MemoryStateStore(); // ONE replay store per case
            foreach (var so in L(c["steps"]))
            {
                var s = D(so);
                var r = Pca.Authorize(s["pcactn"], Input(F, s, store, true, (bool)c["required"]!));
                var e = D(s["expect"]);
                var failed = r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
                var want = L(e["failed"]).Select(x => (string)x!).ToList();
                Assert.True((bool)e["allow"]! == r.Allow && (string)e["decision"]! == r.Decision && N(e["status"]) == r.Status && failed.SequenceEqual(want),
                    $"{c["name"]}: allow={r.Allow} decision={r.Decision} status={r.Status} failed=[{string.Join(",", failed)}] ({r.Reason})");
                if (e.GetValueOrDefault("reason") is string reason) Assert.True(!r.Allow && (r.Reason ?? "").Contains(reason, StringComparison.Ordinal), $"{c["name"]}: reason '{r.Reason}' lacks '{reason}'");
            }
        }
    }

    [Fact]
    public void NoWorkflowOptionChangesNothing()
    {
        var F = Load();
        var c = D(L(F["cases"]).Cast<JD>().First(x => (string)x["name"]! == "pay-after-quote"));
        var s = D(L(c["steps"])[0]);
        // a workflow step on the call is ignored while the option is absent
        var r = Pca.Authorize(D(s["pcactn"]), Input(F, s, new MemoryStateStore(), false, false));
        Assert.True(r.Allow);
        Assert.Equal("allow", r.Decision);
    }
}
