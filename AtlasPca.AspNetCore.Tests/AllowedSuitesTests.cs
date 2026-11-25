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

// The middleware forwards AllowedSuites to the verifier in both modes (require-pca.ts:292, :804). The fixture PCActn is signed with Ed25519.
public class AllowedSuitesTests
{
    static readonly string FixText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json"));
    static JD Fix => (JD)Pca.ParseJson(FixText)!;
    static readonly string Aud = System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("audience").GetString()!;
    static readonly long Now = long.Parse(System.Text.Json.JsonDocument.Parse(FixText).RootElement.GetProperty("now").GetRawText(), CultureInfo.InvariantCulture);
    static JD Case => ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static JD Grant => (JD)Case["grant"]!;
    static JD Step => (JD)((JL)Case["steps"]!)[0]!;
    static JD Pcactn => (JD)Step["pcactn"]!;
    static JD OpJ => (JD)Step["operation"]!;
    static Operation Op => new((string)OpJ["verb"]!, (string)OpJ["resource"]!, OpJ["params"]);

    static async Task<bool> Run(IReadOnlyCollection<string>? suites, bool authorize)
    {
        var ran = false;
        var options = new PcaOptions
        {
            Audience = Aud, Clock = () => Now, AllowedSuites = suites, SignatureOnly = !authorize, InsecureSkipPlanRootCheck = true, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null),
        };
        if (authorize)
            options.Authorize = new PcaAuthorizeOptions { StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = "single-step", Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options };
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, options);
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        await mw.InvokeAsync(ctx);
        return ran;
    }

    [Fact]
    public async Task TheCoreGuardForwardsTheSuitePolicy()
    {
        Assert.True(await Run(null, false));
        Assert.True(await Run(new[] { "ed25519" }, false));
        Assert.False(await Run(new[] { "ml-dsa-65" }, false));
    }

    [Fact]
    public async Task TheAuthorizeModeForwardsTheSuitePolicy()
    {
        Assert.True(await Run(new[] { "ed25519" }, true));
        Assert.False(await Run(new[] { "ml-dsa-65" }, true));
    }
}
