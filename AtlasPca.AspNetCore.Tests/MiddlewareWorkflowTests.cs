using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// K5 (C-308): the workflow option through PcaMiddleware (PcaAuthorizeOptions.Workflow / WorkflowCall), built from the first cases of
// authorize-workflow-fixtures.json. The step comes from the callback, else from the JSON body member `workflow` (body mode only).
public class MiddlewareWorkflowTests
{
    static JD D(object? o) => (JD)o!;
    static JD Step(JD F, string name) => D(((JL)D(((JL)F["cases"]!).First(c => (string)D(c)["name"]! == name))["steps"]!)[0]);

    static async Task<(DefaultHttpContext Ctx, bool Ran)> Run(string name, bool workflow, bool required, bool viaCallback = false, bool dropStep = false)
    {
        var F = WorkflowAuthorizeTests.Load();
        var s = Step(F, name);
        var grant = D(F["grant"]);
        var op = D(s["operation"]);
        var wf = s.GetValueOrDefault("workflow") as JD;
        WorkflowCall? Call() => wf == null || dropStep ? null
            : new WorkflowCall(wf["commitment"], wf["receipts"], wf["step"] as string, wf.GetValueOrDefault("units"), wf.GetValueOrDefault("goal_digest") as string);
        var ran = false;
        var az = new PcaAuthorizeOptions
        {
            StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = null,
            Operation = _ => Task.FromResult<Operation?>(new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"])),
            Context = (_, _) => new JD { ["plan"] = F["plan"], ["plan_authorized"] = true },
            ProvenanceFlow = ProvHarness.Options,
        };
        if (workflow)
        {
            az.Workflow = new WorkflowGate((string)F["principal"]!, (string)F["rs_signer"]!, required);
            if (viaCallback) az.WorkflowCall = (_, _) => Call();
        }
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, new PcaOptions
        {
            Audience = (string)F["audience"]!, Clock = () => long.Parse(((Num)F["now"]!).Raw, CultureInfo.InvariantCulture),
            GrantResolver = r => Task.FromResult<JD?>(r == (string)grant["id"]! ? grant : null),
            Authorize = az,
        });
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        // the provenance bundle travels as the body member here (the other suites use the header)
        var env = new JD { ["pcactn"] = s["pcactn"], [ArgProvenance.BodyMember] = ProvHarness.Bundle(new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"])) };
        if (!viaCallback && wf != null && !dropStep) env["workflow"] = wf; // the default reader: the body member
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(Pca.Canonicalize(env)));
        ctx.Request.ContentType = "application/json";
        await mw.InvokeAsync(ctx);
        return (ctx, ran);
    }

    static string Body(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body).ReadToEnd();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidStepPasses(bool viaCallback)
    {
        var (ctx, ran) = await Run("pay-after-quote", true, false, viaCallback);
        Assert.True(ran, Body(ctx));
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EdgeViolationIs403WithTheReason(bool viaCallback)
    {
        var (ctx, ran) = await Run("amount-over-the-quote", true, false, viaCallback);
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("workflow: edge_relation (step pay)", Body(ctx));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequiredAndAbsentIs403(bool viaCallback)
    {
        var (ctx, ran) = await Run("workflow-required-but-absent", true, true, viaCallback);
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("workflow: this call carries no workflow step (fail closed)", Body(ctx));
        // a step-carrying case with the step dropped is refused the same way
        var (c2, ran2) = await Run("pay-after-quote", true, true, viaCallback, dropStep: true);
        Assert.False(ran2);
        Assert.Equal(403, c2.Response.StatusCode);
    }

    [Fact]
    public async Task OptionalAndAbsentPasses()
    {
        var (ctx, ran) = await Run("workflow-optional-and-absent", true, false);
        Assert.True(ran, Body(ctx));
    }

    [Fact]
    public async Task NoWorkflowOptionChangesNothing()
    {
        // the body member is ignored while the option is off
        var (ctx, ran) = await Run("pay-after-quote", false, false);
        Assert.True(ran, Body(ctx));
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ThrowingCallbackDenies()
    {
        var F = WorkflowAuthorizeTests.Load();
        var grant = D(F["grant"]);
        var s = Step(F, "pay-after-quote");
        var op = D(s["operation"]);
        var ran = false;
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, new PcaOptions
        {
            Audience = (string)F["audience"]!, Clock = () => long.Parse(((Num)F["now"]!).Raw, CultureInfo.InvariantCulture),
            GrantResolver = r => Task.FromResult<JD?>(r == (string)grant["id"]! ? grant : null),
            Authorize = new PcaAuthorizeOptions
            {
                StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = null,
                Operation = _ => Task.FromResult<Operation?>(new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"])),
                Context = (_, _) => new JD { ["plan"] = F["plan"], ["plan_authorized"] = true },
                Workflow = new WorkflowGate((string)F["principal"]!, (string)F["rs_signer"]!),
                WorkflowCall = (_, _) => throw new InvalidOperationException("boom"),
                ProvenanceFlow = ProvHarness.Options,
            },
        });
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(Pca.Canonicalize(new JD { ["pcactn"] = s["pcactn"] })));
        ctx.Request.ContentType = "application/json";
        await mw.InvokeAsync(ctx);
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task UndecodablePcactnIs401BeforeTheGate()
    {
        // the middleware decodes first: a non-object PCActn is its own 401 (invalid_request), the gate never runs
        var F = WorkflowAuthorizeTests.Load();
        var mw = new PcaMiddleware(_ => Task.CompletedTask, new PcaOptions
        {
            Audience = (string)F["audience"]!, GrantResolver = _ => Task.FromResult<JD?>(null),
            Authorize = new PcaAuthorizeOptions
            {
                StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = null,
                Operation = _ => Task.FromResult<Operation?>(new Operation("a", "b", new JD())),
                Workflow = new WorkflowGate((string)F["principal"]!, (string)F["rs_signer"]!, true),
            },
        });
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"pcactn\":\"not-a-pcactn\"}"));
        ctx.Request.ContentType = "application/json";
        await mw.InvokeAsync(ctx);
        Assert.Equal(401, ctx.Response.StatusCode);
    }
}
