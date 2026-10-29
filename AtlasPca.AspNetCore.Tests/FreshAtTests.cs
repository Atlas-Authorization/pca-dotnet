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
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// AuthorizeInput.FreshAt / PcaOptions.FreshAt reach the core verifier: ok, stale => escalate, no policy => refused (a PCActn carrying the
// member), and the side-carried `pca-fresh-at` header (read only when the PCActn has no member; unparseable = bad token).
public class FreshAtTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly JD OpJ = (JD)Step["operation"]!;
    static readonly Operation Op = new((string)OpJ["verb"]!, (string)OpJ["resource"]!, OpJ["params"]);

    static readonly byte[] Seed = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    static readonly string Signer = Pca.B64u(Pk());
    static byte[] Pk() { var pk = new byte[32]; Ed25519.GeneratePublicKey(Seed, 0, pk, 0); return pk; }
    static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    static JD Token(long revocationEpoch)
    {
        var body = new JD
        {
            ["v"] = N(1), ["scope"] = "inst_1", ["revocation_epoch"] = N(revocationEpoch), ["ledger_tree_size"] = N(10), ["budget_version"] = N(1),
            ["policy_revision"] = N(1), ["policy_digest"] = "pd", ["issued_at"] = N(Now - 1000), ["signer"] = Signer,
        };
        var msg = IntentJs.Message(FreshAt.Domain, body);
        var sig = new byte[64];
        Ed25519.Sign(Seed, 0, msg, 0, msg.Length, sig, 0);
        body["sig"] = Pca.B64u(sig);
        return body;
    }

    // the verifier's own state: revocation epoch 5
    static FreshAtPolicy Policy(JD? sideCarried = null) =>
        new(Signer, "inst_1", new FreshAtState(5, 10, 1, 1, "pd"), hasSideCarried: sideCarried != null, sideCarried: sideCarried);

    static AuthorizeResult Az(JD pcactn, FreshAtPolicy? policy) => Pca.Authorize(pcactn, new AuthorizeInput
    {
        Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = new MemoryStateStore(),
        IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", FreshAt = policy,
    }.WithProv());

    static JD WithMember(JD token) => new(Pcactn) { ["fresh_at"] = token };

    [Fact] public void SideCarriedTokenAtOrBehindTheVerifierIsOk()
    {
        var r = Az(Pcactn, Policy(Token(5)));
        Assert.Equal("pass", r.Checks["fresh_at"]);
        Assert.True(r.Allow, r.Reason);
    }

    [Fact] public void StaleVerifierEscalates()
    {
        var r = Az(Pcactn, Policy(Token(6)));
        Assert.False(r.Allow);
        Assert.Equal("escalate", r.Decision);
        Assert.Contains(r.Reasons, x => x.Contains("stale_state"));
    }

    [Fact] public void NoPolicyIsRefusedWhenThePCActnCarriesTheMemberAndUnaffectedOtherwise()
    {
        // the added member is not covered by the leaf signature, so the verdict denies anyway; the signal is the fresh_at refusal
        Assert.True(Az(Pcactn, null).Allow);
        var r = Az(WithMember(Token(5)), null);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["fresh_at"]);
    }

    // ---- the middleware ----

    static async Task<(DefaultHttpContext Ctx, bool Next)> Run(Func<FreshAtPolicy?> policy, string? header, bool requireHeaderRead = false)
    {
        var ran = false;
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, new PcaOptions
        {
            Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult<JD?>(r == (string)Grant["id"]! ? Grant : null),
            FreshAt = (_, _) => Task.FromResult(policy()),
            Authorize = new PcaAuthorizeOptions { StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Plan = "single-step", Operation = _ => Task.FromResult<Operation?>(Op), ProvenanceFlow = ProvHarness.Options },
        });
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Headers["PCA-Action"] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn)));
        if (header != null) ctx.Request.Headers["pca-fresh-at"] = header;
        ctx.Request.Headers[ArgProvenance.Header] = ProvHarness.Header(Op);
        await mw.InvokeAsync(ctx);
        return (ctx, ran);
    }

    static string TokenJson(long epoch) => Pca.Canonicalize(Token(epoch));

    [Fact] public async Task MiddlewareReadsTheSideCarriedHeader()
    {
        var (_, ok) = await Run(() => Policy(), TokenJson(5));
        Assert.True(ok);
        var (stale, ran) = await Run(() => Policy(), TokenJson(6));
        Assert.False(ran);
        Assert.Equal(403, stale.Response.StatusCode);
    }

    [Fact] public async Task MiddlewareUnparseableHeaderIsABadTokenNotAMissingOne()
    {
        var (ctx, ran) = await Run(() => Policy(), "{not json");
        Assert.False(ran);
        Assert.Equal(403, ctx.Response.StatusCode);
    }

    [Fact] public async Task MiddlewareNoHeaderNoPolicyChangesNothing()
    {
        Assert.True((await Run(() => null, null)).Next);
        Assert.True((await Run(() => Policy(), null)).Next); // policy not required, no token presented
    }
}
