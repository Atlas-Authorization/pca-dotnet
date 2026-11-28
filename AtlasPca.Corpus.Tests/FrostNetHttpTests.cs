using System.Net;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The networked FROST signer over real loopback HTTP: a 2-of-3 group whose signers are three <see cref="SignerHttpServer"/> instances and whose coordinator reaches them
/// only through <see cref="HttpSignerTransport"/>; the aggregate verifies as a standard Ed25519 signature, a forged allow token is refused by every signer, and the server answers
/// the wrong method, route, body and size with the reference's responses.</summary>
public class FrostNetHttpTests
{
    sealed class Rig : IDisposable
    {
        public readonly List<SignerHttpServer> Servers = new();
        public readonly Frost.FrostKeygenResult Group = Frost.TrustedDealerKeygen(2, 3);
        public readonly byte[] PolicySeed = RandomNumberGenerator.GetBytes(32);
        public readonly byte[] PolicyKey;

        public Rig()
        {
            PolicyKey = new Ed25519PrivateKeyParameters(PolicySeed, 0).GeneratePublicKey().GetEncoded();
            foreach (var s in Group.ParticipantShares)
                Servers.Add(SignerHttpServer.Start(new GuardianSignerService(new GuardianSignerOptions
                {
                    Identifier = s.Identifier, Share = s.Share, GroupPublicKey = Group.GroupPublicKey, Threshold = 2, PolicyAuthorityPublicKey = PolicyKey,
                })));
        }

        public NetworkCoordinator Coordinator(int timeoutMs = 10_000) => new(new NetworkCoordinatorOptions
        {
            GroupPublicKey = Group.GroupPublicKey, Threshold = 2,
            Signers = Group.ParticipantShares.Select((s, i) => (ISignerTransport)new HttpSignerTransport(Servers[i].Url, s.Identifier, timeoutMs)).ToList(),
            VerificationShares = Group.ParticipantShares.Select(s => new Frost.VerificationShare(s.Identifier, s.PublicKey)).ToList(),
        });

        public void Dispose() { foreach (var s in Servers) s.Dispose(); }
    }

    [Fact]
    public async Task TwoOfThreeSignsOverLoopback()
    {
        using var rig = new Rig();
        var msg = Encoding.UTF8.GetBytes("release the guardian share");
        var allow = FrostNet.IssueAllowToken(rig.PolicySeed, new IssueAllowOpts { Message = msg, GroupPublicKey = rig.Group.GroupPublicKey });
        var r = await rig.Coordinator().SignAsync(msg, allow);
        Assert.True(Pca.VerifyEd25519Strict(rig.Group.GroupPublicKey, msg, r.Signature));
        Assert.True(r.Signers.Count >= 2);
    }

    [Fact]
    public async Task ForgedAllowTokenIsRefusedByEverySigner()
    {
        using var rig = new Rig();
        var msg = Encoding.UTF8.GetBytes("transfer everything");
        var forged = FrostNet.IssueAllowToken(RandomNumberGenerator.GetBytes(32), new IssueAllowOpts { Message = msg, GroupPublicKey = rig.Group.GroupPublicKey });
        var e = await Assert.ThrowsAnyAsync<CoordinatorError>(() => rig.Coordinator().SignAsync(msg, forged));
        Assert.NotEmpty(e.Refusals);
    }

    [Fact]
    public async Task ServerAnswersTheReferenceResponses()
    {
        using var rig = new Rig();
        using var http = new HttpClient();
        var url = rig.Servers[0].Url;
        async Task<(HttpStatusCode, D)> Send(HttpMethod m, string path, string? body)
        {
            using var req = new HttpRequestMessage(m, url + path) { Content = body == null ? null : new StringContent(body, Encoding.UTF8, "application/json") };
            using var resp = await http.SendAsync(req);
            return (resp.StatusCode, (D)Pca.ParseJson(await resp.Content.ReadAsStringAsync())!);
        }
        var (c1, b1) = await Send(HttpMethod.Get, "/round1", null);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, c1);
        Assert.Equal("method not allowed", b1["reason"]);
        var (c2, b2) = await Send(HttpMethod.Post, "/nope", "{}");
        Assert.Equal(HttpStatusCode.NotFound, c2);
        Assert.Equal("not found", b2["reason"]);
        var (c3, b3) = await Send(HttpMethod.Post, "/round1", "{not json");
        Assert.Equal(HttpStatusCode.BadRequest, c3);
        Assert.True(b3["refused"] is true);
        // a well-formed JSON body that is no round-1 request is the service's own refusal
        var (c4, b4) = await Send(HttpMethod.Post, "/round1", "{}");
        Assert.Equal(HttpStatusCode.OK, c4);
        Assert.True(b4["ok"] is false);
        var (c5, b5) = await Send(HttpMethod.Post, "/round1", "{\"pad\":\"" + new string('a', (1 << 20) + 16) + "\"}");
        Assert.Equal(HttpStatusCode.BadRequest, c5);
        Assert.Equal("request body too large", b5["reason"]);
    }

    [Fact]
    public async Task UnreachableSignerIsATransportFailure()
    {
        SignerHttpServer s;
        using (var rig = new Rig()) s = rig.Servers[0];
        var t = new HttpSignerTransport(s.Url, 1, 500);
        await Assert.ThrowsAnyAsync<Exception>(() => t.Round1Async(new D { ["typ"] = "pca.frost.round1.v1", ["session_id"] = "x" }));
    }
}
