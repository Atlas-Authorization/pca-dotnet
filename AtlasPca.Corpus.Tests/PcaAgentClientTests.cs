using AtlasPca.AgentClient;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class PcaAgentClientTests
{
    static FetchLike Reply(int status, string json, List<string>? seen = null) => (url, init) =>
    {
        seen?.Add(init.Method + " " + url);
        return Task.FromResult(new FetchResponse(status, () => Task.FromResult(Pca.ParseJson(json))));
    };

    static PcaAgentClient Client(FetchLike f)
    {
        var key = SuiteKey.Ed25519(EdKey.FromSeed(new byte[32]));
        var grant = Issue.MintRoot(key, key.Id!, null, new JL());
        return PcaAgent.CreateAgent(new CreateAgentOptions { Grant = grant, Signer = key, RsBaseUrl = "https://rs.example/", Audience = "ins_1", Fetch = f });
    }

    static JD Node => new() { ["id"] = "n1", ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(null) };

    [Fact]
    public void RequiresAudienceAndHttpUrl()
    {
        Assert.Equal("build_failed", Assert.Throws<PcaAgentError>(() => PcaAgent.CreateAgent(new CreateAgentOptions { RsBaseUrl = "https://x" })).Code);
        Assert.Equal("build_failed", Assert.Throws<PcaAgentError>(() => PcaAgent.CreateAgent(new CreateAgentOptions { RsBaseUrl = "ftp://x", Audience = "a" })).Code);
    }

    [Fact]
    public async Task ActWithoutPlanIsAnError()
    {
        var r = await Client(Reply(200, "{}")).ActAsync("n1");
        Assert.Equal("error", r.Status);
        Assert.Equal("no_plan", r.Error!.Code);
    }

    [Fact]
    public async Task PlanRootMustBeEchoed()
    {
        var seen = new List<string>();
        var e = await Assert.ThrowsAsync<PcaAgentError>(() => Client(Reply(200, "{}", seen)).CommitPlanAsync(new[] { Node }));
        Assert.Equal("bad_response", e.Code);
        Assert.Equal("POST https://rs.example/v1/pca/plans", seen[0]);
        var root = Issue.CommitPlan(new[] { Node }).Root;
        var c = Client(Reply(200, "{\"plan_root\":\"" + root + "\"}"));
        Assert.Equal(root, await c.CommitPlanAsync(new[] { Node }));
        Assert.Equal(root, c.PlanRoot);
        var unknown = await c.ActAsync("zz");
        Assert.Equal("unknown_node", unknown.Error!.Code);
    }

    [Fact]
    public async Task StepUpApprovedOnlyOn2xx()
    {
        Assert.Equal("approved", (await Client(Reply(200, "{\"status\":\"approved\"}")).AwaitStepUpAsync("s1", 1, 1000)).Status);
        Assert.Equal("denied", (await Client(Reply(403, "{\"status\":\"approved\"}")).AwaitStepUpAsync("s1", 1, 1000)).Status);
    }
}
