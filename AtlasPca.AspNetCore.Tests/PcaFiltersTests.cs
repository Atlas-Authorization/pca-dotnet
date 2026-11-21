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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// The minimal-API endpoint filter and the MVC resource filter gate exactly like the middleware: the handler runs only on an allow.
public class PcaFiltersTests
{
    static readonly string FixText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json"));
    static JD Fix => (JD)Pca.ParseJson(FixText)!;
    static readonly string Aud = System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("audience").GetString()!;
    static readonly long Now = long.Parse(System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("now").GetRawText(), CultureInfo.InvariantCulture);
    static JD Case => ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static JD Grant => (JD)Case["grant"]!;
    static JD Step => (JD)((JL)Case["steps"]!)[0]!;
    static JD Pcactn => (JD)Step["pcactn"]!;
    static Operation Op => new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);

    static PcaOptions Options() => new()
    {
        Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null),
        Authorize = new PcaAuthorizeOptions { Plan = "single-step", StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options },
    };

    static DefaultHttpContext Ctx(bool withProof)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        if (withProof)
        {
            ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
            ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        }
        return ctx;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EndpointFilterRunsTheHandlerOnlyOnAllow(bool withProof)
    {
        var filter = new PcaEndpointFilter(Options());
        var ctx = Ctx(withProof);
        var ran = false;
        var result = await filter.InvokeAsync(EndpointFilterInvocationContext.Create(ctx), _ => { ran = true; return ValueTask.FromResult<object?>("ok"); });
        Assert.Equal(withProof, ran);
        if (withProof)
        {
            Assert.Equal("ok", result);
            Assert.IsType<PcaAuthResult>(ctx.Items["pca"]);
        }
        else
        {
            Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
            Assert.False(ctx.Items.ContainsKey("pca"));
        }
    }

    [Fact]
    public void EndpointFilterRefusesTheExecutor()
    {
        var o = Options();
        o.Executor = new PcaExecutorOptions { Operations = new MemoryOperationStore() };
        Assert.Throws<InvalidOperationException>(() => new PcaEndpointFilter(o));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ResourceFilterRunsTheActionOnlyOnAllow(bool withProof)
    {
        var filter = new PcaResourceFilter(Options());
        var ctx = Ctx(withProof);
        var action = new ActionContext(ctx, new RouteData(), new ActionDescriptor());
        var executing = new ResourceExecutingContext(action, new List<IFilterMetadata>(), new List<IValueProviderFactory>());
        var ran = false;
        await filter.OnResourceExecutionAsync(executing, () => { ran = true; return Task.FromResult(new ResourceExecutedContext(action, new List<IFilterMetadata>())); });
        Assert.Equal(withProof, ran);
        if (withProof) Assert.Null(executing.Result);
        else
        {
            Assert.IsType<EmptyResult>(executing.Result);
            Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        }
    }
}
