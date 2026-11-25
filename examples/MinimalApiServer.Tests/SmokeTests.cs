using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using AtlasPca;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace MinimalApiServer.Tests;

public class SmokeTests : IClassFixture<WebApplicationFactory<Program>>
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Op = (JD)Step["operation"]!;
    // the app's own UI records the refund the user asked for (principal-direct) under its pinned mediator key
    static readonly SuiteKey Mediator = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)1, 32).ToArray()));
    static ProvenanceRecorder Recorder() => new("conformance-harness", "k1", Mediator);

    readonly WebApplicationFactory<Program> _factory;
    public SmokeTests(WebApplicationFactory<Program> factory) => _factory = factory;

    HttpClient Client() => _factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton(new ServerSettings
    {
        Audience = (string)Fix["audience"]!,
        Grants = { (JD)Case["grant"]! },
        Clock = () => long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture),
        Mediators = { Recorder().Pin },
        // the fixture proof is for a fixed operation, so the test pins it instead of reading the body
        Operation = _ => Task.FromResult<Operation?>(new Operation((string)Op["verb"]!, (string)Op["resource"]!, Op["params"])),
    }))).CreateClient();

    static HttpRequestMessage Refund()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/refunds") { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        req.Headers.Add("PCA-Action", Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Step["pcactn"]))));
        req.Headers.Add(ArgProvenance.Header, ProvenanceRecorder.HeaderValue(ArgProvenance.PrincipalDirect(Recorder(), (string)Op["verb"]!, (string)Op["resource"]!, Op["params"])));
        return req;
    }

    [Fact]
    public async Task ValidProof_IsAllowed_ThenTheReplayIsRefusedWithDoc()
    {
        var client = Client();
        var ok = await client.SendAsync(Refund());
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var again = await client.SendAsync(Refund());
        Assert.Equal(HttpStatusCode.Forbidden, again.StatusCode);
        var body = JsonDocument.Parse(await again.Content.ReadAsStringAsync()).RootElement;
        Assert.StartsWith("replay:", body.GetProperty("error_description").GetString());
        Assert.EndsWith("/reference/refusals.md#replay", body.GetProperty("doc").GetString());
    }

    [Fact]
    public async Task NoProof_IsRefused()
    {
        var res = await Client().PostAsync("/refunds", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.True(JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.TryGetProperty("doc", out _));
    }
}
