using AtlasPca;
using AtlasPca.Adapters;
using AtlasPca.SemanticKernel;
using Microsoft.SemanticKernel;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.SemanticKernel.Tests;

public class PcaFunctionFilterTests
{
    static AgentHandle NewAgent() => Agent.FromPrincipal(new AgentOptions
    {
        Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
        Permissions = new D { ["stripe"] = new L { "refund" } },
        Limits = new Dictionary<string, string> { ["refund"] = "$500/day" }, Aud = "rs-test", Now = 1_000_000,
    });

    static (string Verb, string Resource)? Map(PcaFunctionCall c) => c.Function == "refund" ? ("stripe.refund", "charge:" + c.Arguments["id"]) : null;

    static Kernel KernelWith(AgentHandle ag, out PcaFunctionFilter filter, PcaFunctionFilterOptions? o = null)
    {
        var k = Kernel.CreateBuilder().Build();
        filter = k.UsePca(ag, Map, o);
        return k;
    }

    [Fact]
    public async Task AMappedCallRunsWithTheProofAndItsResultIsRecordedAsToolOutput()
    {
        var ag = NewAgent();
        var k = KernelWith(ag, out _);
        PcaCall? seen = null;
        var fn = KernelFunctionFactory.CreateFromMethod((Kernel kernel, KernelArguments args, string id, int amount) => { seen = PcaFunctionFilter.CallOf(args); return "refunded " + id; }, "refund");
        // the grant caps the amount ($500/day): a call that states no amount cannot satisfy the cap and is refused, so this call states one
        var r = await k.InvokeAsync(fn, new KernelArguments { ["id"] = "c1", ["amount"] = 100 });
        Assert.Equal("refunded c1", r.GetValue<string>());
        Assert.NotNull(seen);
        Assert.True(seen!.Headers.ContainsKey("PCA-Action"));
        Assert.Equal("tool", ag.Provenance.Receipts()[^1]["origin"]);
    }

    [Fact]
    public async Task AnUnmappedFunctionIsRefusedAndNeverRuns()
    {
        var ag = NewAgent();
        var k = KernelWith(ag, out _);
        var ran = false;
        var fn = KernelFunctionFactory.CreateFromMethod(() => { ran = true; return "x"; }, "wipe");
        var e = await Assert.ThrowsAnyAsync<Exception>(() => k.InvokeAsync(fn));
        // the denial may arrive wrapped by the kernel
        Exception? cur = e;
        while (cur != null && cur is not PcaFunctionDenied) cur = cur.InnerException;
        Assert.NotNull(cur);
        Assert.False(ran);
    }

    [Fact]
    public async Task ALocalDryRunDenyIsRefusedAndCanBeReturnedAsTheResult()
    {
        var ag = NewAgent();
        var k = KernelWith(ag, out _, new PcaFunctionFilterOptions { ThrowOnRefusal = false });
        var ran = false;
        var fn = KernelFunctionFactory.CreateFromMethod((string id, long amount) => { ran = true; return "x"; }, "refund");
        var r = await k.InvokeAsync(fn, new KernelArguments { ["id"] = "c1", ["amount"] = 600L });
        Assert.False(ran);
        Assert.StartsWith("PCA refused kernel function refund", r.GetValue<string>());
    }
}
