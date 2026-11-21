using System.Net;
using System.Text;
using System.Text.Json;
using AtlasPca;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The step-up client for the principal's device: key handling (RFC 8032 vector 1), list / approve / deny against a stub transport,
// guidance on a principal mismatch, and every fail-closed path. No network: the HTTP handler is a stub.
public class StepUpTests
{
    sealed class Stub : HttpMessageHandler
    {
        public Func<HttpRequestMessage, string, (int Status, string Body)> Respond = (_, _) => (200, "{}");
        public readonly List<(HttpRequestMessage Req, string Body)> Seen = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(ct);
            Seen.Add((request, body));
            var (status, text) = Respond(request, body);
            return new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
        }
    }

    const long NowMs = 1_800_000_000_000;

    static (PrincipalDeviceKey Key, string Pub) NewKey()
    {
        var k = new PrincipalDeviceKey(new MemorySecretStore());
        return (k, k.Generate());
    }

    static bool Verifies(string pubB64, byte[] msg, string sigB64) =>
        Pca.B64uDecode(pubB64, 32) is { } pk && Pca.B64uDecode(sigB64, 64) is { } sig && Ed25519.Verify(sig, 0, pk, 0, msg, 0, msg.Length);

    static StepUpClient Client(Stub stub, PrincipalDeviceKey key) => new(new StepUpClientOptions
    {
        DashboardUrl = "https://dash.example", InstanceUrl = "https://inst.example", AccountId = "acc", InstanceId = "ins", Key = key,
        Token = _ => Task.FromResult("dsk_x"), Http = new HttpClient(stub), Now = () => NowMs,
    });

    static string Iso(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");

    static async Task<StepUpException> Fails(Func<Task> f)
    {
        var e = await Assert.ThrowsAsync<StepUpException>(f);
        return e;
    }

    [Fact]
    public void KeyGenerateExportImportSign()
    {
        var k = new PrincipalDeviceKey(new MemorySecretStore());
        Assert.False(k.Exists());
        var pub = k.Generate();
        Assert.True(k.Exists());
        var k2 = new PrincipalDeviceKey(new MemorySecretStore());
        Assert.Equal(pub, k2.ImportSecret(k.ExportSecret()));
        var msg = Encoding.UTF8.GetBytes("hello");
        Assert.True(Verifies(pub, msg, k2.Sign(msg)), "the signature must verify under the registered public key");
        Assert.Equal(StepUpKind.InvalidSecret, Assert.Throws<StepUpException>(() => k2.ImportSecret("AAAA")).Kind);
        Assert.Equal(StepUpKind.NoDeviceKey, Assert.Throws<StepUpException>(() => new PrincipalDeviceKey(new MemorySecretStore()).Sign(msg)).Kind);
        k.Delete();
        Assert.False(k.Exists());
    }

    // RFC 8032 test vector 1 (empty message): the signature matches the Ed25519 the server verifies with.
    [Fact]
    public void Rfc8032Vector1()
    {
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var k = new PrincipalDeviceKey(new MemorySecretStore());
        var pub = k.ImportSecret(Pca.B64u(seed));
        Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Convert.ToHexString(Pca.B64uDecode(pub, 32)!).ToLowerInvariant());
        Assert.Equal("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            Convert.ToHexString(Pca.B64uDecode(k.Sign(Array.Empty<byte>()), 64)!).ToLowerInvariant());
    }

    [Fact]
    public async Task ListApproveDeny()
    {
        var (key, pub) = NewKey();
        var msg = new byte[] { 1, 2, 3, 250, 251 };
        var stub = new Stub();
        stub.Respond = (req, body) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/cosign")) return (200, "{\"status\":\"approved\",\"allow\":true}");
            if (path.EndsWith("/deny")) return (200, "{}");
            return (200, "{\"stepups\":[{\"id\":\"su_1\",\"grant_ref\":\"g1\",\"action\":{\"verb\":\"pay\",\"resource\":\"order/1\"},\"required_t\":3,\"threshold_message\":\""
                + Pca.B64u(msg) + "\",\"expires_at\":\"" + Iso(NowMs + 600_000) + "\",\"status\":\"pending\"},"
                + "{\"id\":\"old\",\"grant_ref\":\"g\",\"action\":{\"verb\":\"v\",\"resource\":\"r\"},\"required_t\":3,\"threshold_message\":\"AA\",\"expires_at\":\"2001-01-01T00:00:00.000Z\"}]}");
        };
        var c = Client(stub, key);

        var items = await c.PendingAsync();
        var item = Assert.Single(items);
        Assert.Equal(("su_1", "g1", "pay", "order/1", 3, "pay on order/1"), (item.Id, item.GrantRef, item.ActionVerb, item.ActionResource, item.RequiredT, item.Summary));
        var list = stub.Seen[0].Req;
        Assert.Equal("Bearer dsk_x", list.Headers.Authorization!.ToString());
        Assert.Equal("/v1/dashboard/accounts/acc/instances/ins/pca/stepups", list.RequestUri!.AbsolutePath);
        Assert.Equal("?status=pending", list.RequestUri.Query);

        var res = await c.ApproveAsync(item);
        Assert.Equal(("approved", true, 200), (res.Status, res.Anchored, res.HttpStatus));
        var (cosign, cosignBody) = stub.Seen[1];
        Assert.Equal("https://inst.example/v1/pca/stepups/su_1/cosign", cosign.RequestUri!.ToString());
        Assert.Null(cosign.Headers.Authorization);
        using var doc = JsonDocument.Parse(cosignBody);
        var r = doc.RootElement;
        Assert.Equal(("principal", pub), (r.GetProperty("role").GetString(), r.GetProperty("publicKey").GetString()));
        Assert.True(Verifies(pub, msg, r.GetProperty("sig").GetString()!), "the cosign body must carry the device signature over the exact message");

        await c.DenyAsync(item, "no");
        var (deny, denyBody) = stub.Seen[2];
        Assert.EndsWith("/su_1/deny", deny.RequestUri!.AbsolutePath);
        Assert.Equal("{\"reason\":\"no\"}", denyBody);
        await c.DenyAsync(item);
        Assert.Equal("{}", stub.Seen[3].Body);
    }

    [Fact]
    public async Task APrincipalMismatchSurfacesTheServersGuidance()
    {
        var stub = new Stub { Respond = (_, _) => (403, "{\"errors\":[{\"code\":\"forbidden\",\"message\":\"The share is not from this grant's principal key.\"}]}") };
        var (key, _) = NewKey();
        var e = await Fails(() => Client(stub, key).ApproveAsync(new PendingStepUp("s", "g", "v", "r", 1, "AAEC", NowMs)));
        Assert.Equal((StepUpKind.PrincipalMismatch, 403), (e.Kind, e.Status));
        Assert.Contains("principal key", e.Message);
    }

    [Fact]
    public async Task OtherErrorsFailClosed()
    {
        var stub = new Stub { Respond = (_, _) => (409, "not json") };
        var (key, _) = NewKey();
        var c = Client(stub, key);
        var su = new PendingStepUp("s", "g", "v", "r", 1, "AAEC", NowMs);
        var api = await Fails(() => c.ApproveAsync(su));
        Assert.Equal((StepUpKind.Api, "HTTP 409: The request failed."), (api.Kind, api.Message));
        // a threshold message that is not canonical base64url is never signed
        Assert.Equal(StepUpKind.InvalidThresholdMessage, (await Fails(() => c.ApproveAsync(su with { ThresholdMessageB64u = "a" }))).Kind);
        // an id that could rewrite the request path is refused before any request
        var before = stub.Seen.Count;
        Assert.Equal(StepUpKind.InvalidStepUp, (await Fails(() => c.ApproveAsync(su with { Id = "../x" }))).Kind);
        Assert.Equal(StepUpKind.InvalidStepUp, (await Fails(() => c.DenyAsync(su with { Id = "a/b" }))).Kind);
        Assert.Equal(before, stub.Seen.Count);
        // an unreadable list is a transport error, never an empty list
        stub.Respond = (_, _) => (200, "{\"nope\":1}");
        Assert.Equal(StepUpKind.Transport, (await Fails(() => c.PendingAsync())).Kind);
        // no key stored: nothing is sent
        var sent = stub.Seen.Count;
        var none = Client(stub, new PrincipalDeviceKey(new MemorySecretStore()));
        Assert.Equal(StepUpKind.NoDeviceKey, (await Fails(() => none.ApproveAsync(su))).Kind);
        Assert.Equal(sent, stub.Seen.Count);
        // a failing transport is a transport error
        var broken = new Stub { Respond = (_, _) => throw new HttpRequestException("down") };
        Assert.Equal(StepUpKind.Transport, (await Fails(() => Client(broken, key).PendingAsync())).Kind);
    }

    [Fact]
    public void TheOptionsAreValidated()
    {
        var (key, _) = NewKey();
        StepUpClientOptions O(Action<StepUpClientOptions> t) { var o = new StepUpClientOptions { DashboardUrl = "https://d", InstanceUrl = "https://i", AccountId = "a", InstanceId = "b", Key = key, Token = _ => Task.FromResult("t") }; t(o); return o; }
        new StepUpClient(O(_ => { }));
        Assert.Throws<ArgumentException>(() => new StepUpClient(O(o => o.DashboardUrl = "ftp://d")));
        Assert.Throws<ArgumentException>(() => new StepUpClient(O(o => o.InstanceUrl = "not a url")));
        Assert.Throws<ArgumentException>(() => new StepUpClient(O(o => o.AccountId = "a/b")));
        Assert.Throws<ArgumentException>(() => new StepUpClient(O(o => o.Key = null)));
        Assert.Throws<ArgumentException>(() => new StepUpClient(O(o => o.Token = null)));
    }
}
