using System;
using System.Collections.Generic;
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

namespace AtlasPca.AspNetCore.Tests;

/// <summary>The per-request callbacks the middleware hands the pipeline receive the request's HttpContext, the signature-only path tells an
/// authentication failure (401) from a policy denial (403), and the beacon option needs a pin-capable store.</summary>
public class PcaMiddlewareWiringKillTests
{
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_wiring";

    static SuiteKey Issuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x61, 32).ToArray()));
    static SuiteKey Holder => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x62, 32).ToArray()));
    static JD Amount() => new() { ["amount"] = 5L };
    static Operation Op => new("pay", "inv/1", Amount());

    static JD RiskGrant() => Issue.MintGrant(Issuer, Holder.Id!, null, new JD
    {
        ["predicates"] = new List<object?> { new JD { ["verb"] = "*" } },
        ["caveats"] = new List<object?>(),
        ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "wiring").Grant;

    static JD Act(JD grant) => new Agent(Holder, Aud, grant, null, 0) { Clock = () => Now }.Act("pay", "inv/1", Amount(), null);

    static async Task<DefaultHttpContext> Send(PcaOptions o, JD pcactn)
    {
        var mw = new PcaMiddleware(_ => Task.CompletedTask, o);
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(pcactn)));
        ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        await mw.InvokeAsync(ctx);
        return ctx;
    }

    static PcaOptions Options(JD grant, Action<PcaAuthorizeOptions>? tweak = null)
    {
        var g = Issue.NormJ(grant);
        var az = new PcaAuthorizeOptions
        {
            Plan = "single-step", StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false,
            Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options,
        };
        tweak?.Invoke(az);
        return new PcaOptions { Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)g["id"]! ? g : null), Authorize = az };
    }

    [Fact]
    public async Task TheServerRiskCallbackReceivesTheRequestContext()
    {
        var grant = RiskGrant();
        HttpContext? seen = null;
        string? verb = null;
        var ctx = await Send(Options(grant, a => a.ServerRiskFor = (c, op, _, _) => { seen = c; verb = op.Verb; return null; }), Act(grant));
        Assert.Same(ctx, seen);
        Assert.Equal("pay", verb);
    }

    [Fact]
    public async Task TheThresholdHookReceivesTheRequestContext()
    {
        var grant = RiskGrant();
        HttpContext? seen = null;
        var ctx = await Send(Options(grant, a => a.ThresholdHook = (c, _, _) => { seen = c; return null; }), Act(grant));
        Assert.Same(ctx, seen);
    }

    [Fact]
    public async Task TheBeaconCallbackReceivesTheRequestContext()
    {
        var grant = RiskGrant();
        HttpContext? seen = null;
        string? gref = null;
        var ctx = await Send(Options(grant, a => a.Beacon = (c, g, _) => { seen = c; gref = g; return null; }), Act(grant));
        Assert.Same(ctx, seen);
        Assert.Equal((string)Issue.NormJ(grant)["id"]!, gref);
    }

    static PcaOptions SignatureOnly(JD grant, string audience, IReadOnlyList<string>? roots)
    {
        var o = Options(grant);
        o.Authorize = null;
        o.SignatureOnly = true;
        o.Audience = audience;
        o.AuthorizedPlanRoots = roots;
        return o;
    }

    [Fact]
    public async Task APolicyDenialOnTheSignatureOnlyPathIs403AccessDenied()
    {
        var grant = RiskGrant();
        var ctx = await Send(SignatureOnly(grant, Aud, new[] { "not-the-plan-root" }), Act(grant));
        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Contains("error=\"access_denied\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
        ctx.Response.Body.Position = 0;
        var body = JsonDocument.Parse(new StreamReader(ctx.Response.Body).ReadToEnd()).RootElement;
        Assert.Equal("access_denied", body.GetProperty("error").GetString());
        Assert.Equal("plan_root_authorized: the plan root has not been authorized by the principal", body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task AnAuthenticationFailureOnTheSignatureOnlyPathIs401InvalidPcactn()
    {
        var grant = RiskGrant();
        var ctx = await Send(SignatureOnly(grant, "another-audience", null), Act(grant));
        Assert.Equal(401, ctx.Response.StatusCode);
        Assert.Contains("error=\"invalid_pcactn\"", ctx.Response.Headers["WWW-Authenticate"].ToString());
        ctx.Response.Body.Position = 0;
        var body = JsonDocument.Parse(new StreamReader(ctx.Response.Body).ReadToEnd()).RootElement;
        Assert.Equal("invalid_pcactn", body.GetProperty("error").GetString());
        Assert.Equal("audience: aud does not match this resource server / instance", body.GetProperty("error_description").GetString());
    }

    sealed class NoPins : IStateStore
    {
        public ClaimResult? Claim(string key, long counter) => throw new InvalidOperationException("not used");
    }

    static PcaOptions WithBeacon(IStateStore store) => new()
    {
        Audience = "a", Clock = () => Now, GrantResolver = _ => Task.FromResult<JD?>(null),
        Authorize = new PcaAuthorizeOptions { Plan = "single-step", Beacon = (_, _, _) => null, StateStore = store },
    };

    [Fact]
    public void ABeaconNeedsAStoreThatKeepsPins()
    {
        WithBeacon(new MemoryStateStore()).Validate();
        Assert.Equal(Pca.BeaconNeedsPins, Assert.Throws<InvalidOperationException>(WithBeacon(new NoPins()).Validate).Message);
    }
}
