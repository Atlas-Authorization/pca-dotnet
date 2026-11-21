using System.Security.Cryptography;
using System.Text;
using AtlasPca.Sandbox;
using AtlasPca.Wasm;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using S = AtlasPca.Sandbox.PcaSandbox;

namespace AtlasPca.Wasm.Tests;

/// <summary>The in-process core-module host (handle use, fuel, wall-clock, memory cap, import allow-list, egress) and the component host (pin logic,
/// JSON-lines protocol against a fake host, and real runs when PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 name a built reference host).</summary>
public class WasmHostTests
{
    static AuthorizeResult Bound(string verb, string resource) => new()
    {
        Allow = true, Status = 200,
        Operation = new AuthorizedOperation(verb, resource, Pca.HashCanonical(new D()), "op"),
    };

    static int Mint(S.HandleTable t, string verb, string resource) => t.Mint(Bound(verb, resource), new Operation(verb, resource, new D()));

    sealed class Fixture
    {
        public S.HandleTable Table = null!;
        public S.ReceiptLog Log = null!;
        public int Fs, NetOk, NetEvil;
    }

    static Fixture MakeFixture(byte[]? fsResult = null)
    {
        var policy = new S.EgressPolicy(() => 0.0);
        policy.Admit(Bound("net.ok", "api.example.com"), new Operation("net.ok", "api.example.com", new D()),
            _ => new D { ["method"] = "GET", ["scheme"] = "https", ["host"] = "api.example.com", ["path"] = "/v1" });
        // the guest has no network; a handle that fetches asks the egress policy, which denies by default
        SandboxExecutor fetch(string url) => (_, _, _) => (bool)policy.Claim("GET", url)["allow"]! ? new byte[] { 1 } : null;
        var ex = new Dictionary<string, SandboxExecutor>
        {
            ["fs.read"] = (_, _, _) => fsResult ?? new byte[] { 7, 8, 9 },
            ["net.ok"] = fetch("https://api.example.com/v1"),
            ["net.evil"] = fetch("https://evil.example/x"),
        };
        var log = new S.ReceiptLog();
        var t = new S.HandleTable("wasi_no_ambient", log, ex);
        return new Fixture { Table = t, Log = log, Fs = Mint(t, "fs.read", "/x"), NetOk = Mint(t, "net.ok", "api.example.com"), NetEvil = Mint(t, "net.evil", "evil.example") };
    }

    static D Call(long h, long ptr, long cap) => new() { ["handle"] = h, ["ptr"] = ptr, ["cap"] = cap };
    static byte[] Tool(D spec) => S.BuildTool(spec);
    static CoreOptions Opts(long fuel = 10_000_000) => new() { Fuel = fuel };
    static void Ok(long v, RunResult r) { Assert.True(r.Ok, r.Reason); Assert.Equal(v, r.Value); }
    static void Fails(string why, RunResult r) { Assert.False(r.Ok); Assert.Equal(why, r.Reason); }

    [Fact]
    public void HandleResultLandsInMemory()
    {
        var f = MakeFixture();
        Ok(7, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.Fs, 0, 16) }, ["returns"] = "byte0" }), Opts()));
        Assert.NotEmpty(f.Log.Entries);
    }

    [Fact]
    public void ProbeSeesCountAndVerb() =>
        Ok(3 * 256 + 'f', WasmHost.RunCoreModule(MakeFixture().Table, S.BuildProbeTool(), Opts()));

    [Fact]
    public void InfiniteLoopHitsFuel() =>
        Fails("fuel_exhausted", WasmHost.RunCoreModule(MakeFixture().Table, Tool(new D { ["calls"] = new L(), ["spin"] = true }), Opts(10_000)));

    [Fact]
    public void InfiniteLoopHitsWallClock()
    {
        var o = Opts(1L << 50); // effectively unbounded fuel (the cap is 2^53-1): only the clock can stop it
        o.TimeoutMs = 200;
        Fails("timeout", WasmHost.RunCoreModule(MakeFixture().Table, Tool(new D { ["calls"] = new L(), ["spin"] = true }), o));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-5L)]
    public void FuelIsRequired(long fuel) =>
        Fails("bad_fuel", WasmHost.RunCoreModule(MakeFixture().Table, Tool(new D { ["calls"] = new L() }), Opts(fuel)));

    [Fact]
    public void MissingFuelIsRefused() =>
        Fails("bad_fuel", WasmHost.RunCoreModule(MakeFixture().Table, Tool(new D { ["calls"] = new L() }), new CoreOptions()));

    [Fact]
    public void MemoryOverCapOrUndeclaredIsRefused()
    {
        var t = MakeFixture().Table;
        foreach (var mem in new[]
        {
            new D { ["min"] = 1L, ["max"] = 257L }, new D { ["min"] = 1L, ["max"] = null }, new D { ["min"] = 257L, ["max"] = 257L },
        })
            Fails("memory_limits", WasmHost.RunCoreModule(t, Tool(new D { ["calls"] = new L(), ["memory"] = mem }), Opts()));
        var m = Tool(new D { ["calls"] = new L(), ["memory"] = new D { ["min"] = 1L, ["max"] = 4L } });
        var o = Opts(); o.MaxMemoryPages = 2;
        Fails("memory_limits", WasmHost.RunCoreModule(t, m, o));
        Ok(0, WasmHost.RunCoreModule(t, m, Opts()));
    }

    [Fact]
    public void SharedMemoryAndMemory64AreRefused()
    {
        // memory section: one memory, flag 3 (shared + max) / flag 4 (memory64)
        static byte[] Mod(params byte[] mem) => new byte[] { 0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 5, (byte)mem.Length }.Concat(mem).ToArray();
        var t = MakeFixture().Table;
        Fails("memory_limits", WasmHost.RunCoreModule(t, Mod(1, 3, 1, 1), Opts()));
        Fails("memory_limits", WasmHost.RunCoreModule(t, Mod(1, 4, 1), Opts()));
    }

    [Theory]
    [InlineData("wasi_snapshot_preview1", "fd_write")]
    [InlineData("env", "x")]
    [InlineData("pca:act", "other")]
    public void ForbiddenImportsAreRefused(string module, string name) =>
        Fails("ambient_import:" + module + "." + name, WasmHost.RunCoreModule(MakeFixture().Table,
            Tool(new D { ["calls"] = new L(), ["extraImports"] = new L { new D { ["module"] = module, ["name"] = name } } }), Opts()));

    [Fact]
    public void MalformedSizeAndEntry()
    {
        var t = MakeFixture().Table;
        Fails("module_size", WasmHost.RunCoreModule(t, Array.Empty<byte>(), Opts()));
        Fails("malformed_module", WasmHost.RunCoreModule(t, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, Opts()));
        var m = Tool(new D { ["calls"] = new L() });
        Fails("no_entry", WasmHost.RunCoreModule(t, m, Opts(), "nope"));
        var o = Opts(); o.MaxModuleBytes = 10;
        Fails("module_size", WasmHost.RunCoreModule(t, m, o));
    }

    [Fact]
    public void BadOutputWindowSpendsNoUse()
    {
        var f = MakeFixture();
        // ptr far past a 1-page memory: -4, and the single use is still there
        Ok(-4, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.Fs, 70000, 16) } }), Opts()));
        Ok(3, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.Fs, 0, 16) } }), Opts()));
    }

    [Fact]
    public void ResultLargerThanCapIsRefused()
    {
        var f = MakeFixture();
        Ok(-3, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.Fs, 0, 2) } }), Opts()));
    }

    [Fact]
    public void EgressInsidePolicyPassesOutsideIsRefused()
    {
        var f = MakeFixture();
        Ok(1, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.NetOk, 0, 16) } }), Opts()));
        // out-of-policy host: the executor errors, the guest sees executor_error (-5) and the receipt says so
        Ok(-5, WasmHost.RunCoreModule(f.Table, Tool(new D { ["calls"] = new L { Call(f.NetEvil, 0, 16) } }), Opts()));
        Assert.Contains(f.Log.Entries, e => Equals(e["outcome"], "error"));
    }

    // ---------------------------------------------------------------------------------------------------- component host

    static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    static S.HandleTable ComponentTable()
    {
        var t = new S.HandleTable("wasi_no_ambient", new S.ReceiptLog(), new Dictionary<string, SandboxExecutor> { ["fs.read"] = (_, _, _) => new byte[] { 5, 6 } });
        Mint(t, "fs.read", "/x");
        return t;
    }

    static ComponentOptions CO(long fuel, int timeout = 10000) => new() { Fuel = fuel, TimeoutMs = timeout };

    static HostBinary Fake(string tag, string body)
    {
        var dir = Directory.CreateTempSubdirectory("pca-comp-test-" + tag + "-").FullName;
        var p = Path.Combine(dir, "host.sh");
        var script = "#!/bin/sh\n" + body + "\n";
        File.WriteAllText(p, script);
        File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return new HostBinary(p, Sha(Encoding.UTF8.GetBytes(script)));
    }

    [Fact]
    public void PinRefusals()
    {
        var t = ComponentTable();
        var x = new byte[] { 1 };
        Fails("host_missing", WasmHost.RunComponent(t, x, new HostBinary("/nonexistent/pca-wasmtime-host", new string('a', 64)), CO(1000)));
        var self = typeof(WasmHostTests).Assembly.Location; // any existing file
        Fails("host_unpinned", WasmHost.RunComponent(t, x, new HostBinary(self, ""), CO(1000)));
        Fails("host_hash_mismatch", WasmHost.RunComponent(t, x, new HostBinary(self, new string('0', 64)), CO(1000)));
        Fails("bad_fuel", WasmHost.RunComponent(t, x, new HostBinary(self, new string('0', 64)), CO(0)));
    }

    [Fact]
    public void ProtocolAgainstFakeHost()
    {
        if (OperatingSystem.IsWindows()) { Console.WriteLine("skipped: fake host is a sh script"); return; }
        var t = ComponentTable();
        // count -> reply, invoke(1) -> reply, then done
        var h = Fake("proto", "printf '{\"op\":\"count\"}\\n'; read a; printf '{\"op\":\"invoke\",\"h\":1}\\n'; read b; case \"$b\" in *\"[5,6]\"*) printf '{\"done\":5,\"fuel_used\":1}\\n';; *) printf '{\"fail\":\"bad_reply\"}\\n';; esac");
        var r = WasmHost.RunComponent(t, new byte[] { 1 }, h, CO(1000));
        Ok(5, r);
        Assert.Equal(1, r.FuelUsed);
        // the use is spent: a second run gets err -2 (spent) and the fake reports bad_reply
        Fails("bad_reply", WasmHost.RunComponent(t, new byte[] { 1 }, h, CO(1000)));
    }

    [Fact]
    public void HungHostIsKilledAndGarbageIsRefused()
    {
        if (OperatingSystem.IsWindows()) { Console.WriteLine("skipped: fake host is a sh script"); return; }
        var t = ComponentTable();
        var x = new byte[] { 1 };
        Fails("timeout", WasmHost.RunComponent(t, x, Fake("hang", "read a"), CO(1000, 200)));
        Fails("host_protocol", WasmHost.RunComponent(t, x, Fake("junk", "echo not-json"), CO(1000)));
        Fails("host_exit", WasmHost.RunComponent(t, x, Fake("quiet", "exit 0"), CO(1000)));
        Fails("fuel_exhausted", WasmHost.RunComponent(t, x, Fake("fail", "echo '{\"fail\":\"fuel_exhausted\"}'"), CO(1000)));
    }

    static HostBinary? Real()
    {
        var p = Environment.GetEnvironmentVariable("PCA_WASMTIME_HOST_BIN");
        var h = Environment.GetEnvironmentVariable("PCA_WASMTIME_HOST_SHA256");
        if ((string.IsNullOrEmpty(p) || string.IsNullOrEmpty(h)) && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")))
            throw new InvalidOperationException("CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256"); // a green CI run never skips the real host
        if (string.IsNullOrEmpty(p) || string.IsNullOrEmpty(h)) { Console.WriteLine("skipped: PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set"); return null; }
        return new HostBinary(p, h);
    }

    [Fact]
    public void RealHostLimits()
    {
        if (Real() is not { } host) return;
        Ok(5, WasmHost.RunComponent(ComponentTable(), S.ReferenceComponentWat(), host, CO(1_000_000)));
        Fails("fuel_exhausted", WasmHost.RunComponent(ComponentTable(), S.ReferenceComponentWat(new D { ["spin"] = true }), host, CO(10_000)));
        Fails("ambient_import:wasi:cli/environment@0.2.0",
            WasmHost.RunComponent(ComponentTable(), S.ReferenceComponentWat(new D { ["extraImport"] = "wasi:cli/environment@0.2.0" }), host, CO(1_000_000)));
    }

    [Fact]
    public void RealHostEgressRefusal()
    {
        if (Real() is not { } host) return;
        // a handle whose executor refuses (an out-of-policy fetch)
        var evil = new S.HandleTable("wasi_no_ambient", new S.ReceiptLog(), new Dictionary<string, SandboxExecutor> { ["net.evil"] = (_, _, _) => null });
        Mint(evil, "net.evil", "evil.example");
        // the executor error is delivered as err -5; the reference component returns that code as its value
        var r = WasmHost.RunComponent(evil, S.ReferenceComponentWat(), host, CO(1_000_000));
        Assert.Equal(-5, r.Value);
    }

    [Fact]
    public void AStagedHostIsOwnerOnly()
    {
        var src = Path.Combine(Directory.CreateTempSubdirectory("pca-stage-src-").FullName, "host.bin");
        var bytes = Encoding.UTF8.GetBytes("not a real host");
        File.WriteAllBytes(src, bytes);
        Assert.Null(WasmHost.Stage(new HostBinary(src, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()), out var dir, out var exe));
        try
        {
            Assert.True(AtlasPca.OwnerOnly.IsOwnerOnly(exe) || !OperatingSystem.IsWindows() && File.GetUnixFileMode(exe) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute));
            if (OperatingSystem.IsWindows()) Assert.True(AtlasPca.OwnerOnly.IsOwnerOnly(dir, true));
        }
        finally { try { Directory.Delete(dir, true); } catch (Exception) { } }
    }
}
