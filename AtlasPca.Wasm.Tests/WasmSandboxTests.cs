using AtlasPca.Sandbox;
using AtlasPca.Wasm;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using S = AtlasPca.Sandbox.PcaSandbox;

namespace AtlasPca.Wasm.Tests;

/// <summary>The composed sandbox host (WasmSandbox.CreateSandbox): the table class follows only a verified claim, runs are validated and bounded.</summary>
public class WasmSandboxTests
{
    static AuthorizeResult Bound(string verb, string resource) => new()
    {
        Allow = true, Status = 200,
        Operation = new AuthorizedOperation(verb, resource, Pca.HashCanonical(new D()), "op"),
    };

    static WasmSandboxHost Make(byte[]? result = null) => WasmSandbox.CreateSandbox(new SandboxOptions
    {
        Executors = new Dictionary<string, SandboxExecutor> { ["fs.read"] = (_, _, _) => result ?? new byte[] { 7, 8, 9 } },
    });

    [Fact]
    public void WithoutAVerifiedClaimTheTableIsClassNone()
    {
        var h = Make();
        Assert.Equal("none", h.RuntimeClass);
        var forged = WasmSandbox.CreateSandbox(new SandboxOptions { RuntimeClaim = new SandboxRuntimeClaim(new D { ["class"] = "wasi_no_ambient" }, new D()) });
        Assert.Equal("none", forged.RuntimeClass);
    }

    [Fact]
    public void ARunServesTheHandleAndIsReceipted()
    {
        var h = Make();
        var handle = h.Table.Mint(Bound("fs.read", "/x"), new Operation("fs.read", "/x", new D()));
        var tool = S.BuildTool(new D { ["calls"] = new L { new D { ["handle"] = (long)handle, ["ptr"] = 0L, ["cap"] = 16L } }, ["returns"] = "byte0" });
        var r = h.Run(tool);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal(7, r.Value);
        Assert.NotEmpty(h.Log.Entries);
    }

    [Fact]
    public async Task AnAsyncRunIsStoppedAtTheTimeout()
    {
        var h = Make();
        var spin = S.BuildTool(new D { ["calls"] = new L(), ["spin"] = true });
        var r = await h.RunAsync(spin, "run", 200);
        Assert.False(r.Ok);
        Assert.Equal("timeout", r.Reason);
    }

    [Fact]
    public void AnAmbientImportAndAnOversizeModuleAreRefused()
    {
        var h = Make();
        var bad = S.BuildTool(new D { ["calls"] = new L(), ["extraImports"] = new L { new D { ["module"] = "wasi_snapshot_preview1", ["name"] = "fd_write" } } });
        Assert.Equal("ambient_import:wasi_snapshot_preview1.fd_write", h.Run(bad).Reason);
        var small = WasmSandbox.CreateSandbox(new SandboxOptions { MaxModuleBytes = 4 });
        Assert.Equal("module_size", small.Run(S.BuildProbeTool()).Reason);
    }
}
