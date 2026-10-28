using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// PcaProtect.Create (secure defaults in one call, revoke handle, caller options win) and the `doc` member of refusal bodies.
public class ProtectTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    const string Ref = "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md";

    static Protected Make(Action<PcaOptions>? configure = null, Func<JD, bool>? isRevoked = null) =>
        PcaProtect.Create(Aud, new[] { Grant }, _ => Task.FromResult<Operation?>(Op), o => { o.Clock = () => Now; configure?.Invoke(o); }, isRevoked);

    static async Task<(DefaultHttpContext Ctx, bool Ran)> Send(Protected p)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        var ran = false;
        await new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, p.Options).InvokeAsync(ctx);
        return (ctx, ran);
    }

    static JsonElement Body(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return JsonDocument.Parse(new StreamReader(ctx.Response.Body).ReadToEnd()).RootElement;
    }

    [Fact]
    public async Task AllowsOnce_ThenRefusesTheReplay_WithDoc()
    {
        var p = Make();
        var (ok, ran) = await Send(p);
        Assert.True(ran);
        Assert.Equal(200, ok.Response.StatusCode);
        var (again, ranAgain) = await Send(p);
        Assert.False(ranAgain);
        Assert.Equal(403, again.Response.StatusCode);
        var b = Body(again);
        Assert.StartsWith("replay:", b.GetProperty("error_description").GetString());
        Assert.Equal(Ref + "#replay", b.GetProperty("doc").GetString());
    }

    [Fact]
    public async Task Revoke_RefusesTheGrant()
    {
        var p = Make();
        p.Revoke((string)Grant["id"]!);
        var (ctx, ran) = await Send(p);
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Equal(Ref + "#revocation", Body(ctx).GetProperty("doc").GetString());
    }

    [Fact]
    public async Task ExtraIsRevoked_AndUnknownGrant_Refuse()
    {
        Assert.False((await Send(Make(isRevoked: _ => true))).Ran);
        var none = PcaProtect.Create(Aud, new List<JD>(), _ => Task.FromResult<Operation?>(Op), o => o.Clock = () => Now);
        var (ctx, ran) = await Send(none);
        Assert.False(ran);
        Assert.True(ctx.Response.StatusCode is 401 or 403);
    }

    [Fact]
    public async Task CallerOptionsWin()
    {
        // replacing the revocation source is the caller's call, even if it undoes the revoke handle
        var p = Make(o => o.Authorize!.IsRevoked = (_, _) => false);
        p.Revoke((string)Grant["id"]!);
        Assert.True((await Send(p)).Ran);
        Assert.Equal("single-step", Make().Options.Authorize!.Plan);
        Assert.Throws<ArgumentNullException>(() => PcaProtect.Create(Aud, (IEnumerable<JD>)null!, _ => Task.FromResult<Operation?>(Op)));
    }

    [Fact]
    public async Task NoProof_IsUnknownCheck_DocIsThePage()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        await new PcaMiddleware(_ => Task.CompletedTask, Make().Options).InvokeAsync(ctx);
        Assert.Equal(401, ctx.Response.StatusCode);
        Assert.Equal(Ref, Body(ctx).GetProperty("doc").GetString());
    }
}

public class RefusalsTests
{
    const string Docs = "https://github.com/Atlas-Authorization/pca/blob/main/docs";

    [Theory]
    [InlineData("audience: the proof is for ins_a, this server is ins_b", "audience", "/reference/refusals.md#audience")]
    [InlineData("replay: 5 was already claimed (replay)", "replay", "/reference/refusals.md#replay")]
    [InlineData("authorize_config: missing required component(s): state_store (fail closed)", "authorize_config", "/guides/resource-server-quickstart.md")]
    [InlineData("threshold: needs a co-signature", "threshold", "/concepts/threshold-and-step-up.md")]
    [InlineData("wire: no PCActn presented", "wire", "/reference/wire-formats.md")]
    [InlineData("see plan_state: not executable", "plan_state", "/reference/refusals.md#plan_root_authorized")]
    public void KnownReasonsMapToTheirEntry(string reason, string check, string docSuffix)
    {
        var h = Refusals.Explain(reason);
        Assert.Equal(check, h.Check);
        Assert.Equal(Docs + docSuffix, h.Docs);
        Assert.NotEmpty(h.Meaning);
        Assert.NotEmpty(h.Fix);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Something else entirely")]
    public void UnknownReasonsGetTheGenericEntry(string? reason)
    {
        var h = Refusals.Explain(reason);
        Assert.Equal("unknown", h.Check);
        Assert.Equal(Docs + "/reference/refusals.md", h.Docs);
    }

    [Fact]
    public void ReplayMeaningMatchesTheTypeScriptTable() =>
        Assert.Equal("This proof (or an older counter) was already used.", Refusals.Explain("replay: x").Meaning);
}
