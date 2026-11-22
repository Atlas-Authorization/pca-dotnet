// createSandbox: the sandbox host that composes the pieces (a receipt log, the runtime class a verified claim proves, the capability table) over the
// in-process WebAssembly core-module host. The tool is a core module that imports nothing but pca:act.{invoke,handle_count,handle_verb}: it has no
// filesystem, network, clock, random or environment access. Any other import, a memory with no declared maximum, or a shared / 64-bit memory is refused
// before anything runs. Run is synchronous; RunAsync runs the tool on a worker thread and a tool that never returns is stopped at the timeout (the
// engine's epoch deadline), and both are bounded by work done (fuel) as well as wall-clock time.
using AtlasPca.Sandbox;

namespace AtlasPca.Wasm;

/// <summary>Evidence for the runtime class: the claim and the trust it is verified against (pinnedAttestors, passportDigest, verifiedEvidenceDigests, now).</summary>
public sealed record SandboxRuntimeClaim(object? Claim, object? Trust);

public sealed class SandboxOptions
{
    /// <summary>The executors a handle may run, by verb.</summary>
    public IReadOnlyDictionary<string, SandboxExecutor> Executors { get; set; } = new Dictionary<string, SandboxExecutor>();
    public PcaSandbox.ReceiptLog? Log { get; set; }
    public Func<double>? Now { get; set; }
    /// <summary>Largest tool binary accepted. Default 1 MiB.</summary>
    public int MaxModuleBytes { get; set; } = 1 << 20;
    /// <summary>Largest linear memory a tool may declare (64 KiB pages). Default 256 (16 MiB). A memory without a declared maximum is refused.</summary>
    public int MaxMemoryPages { get; set; } = 256;
    /// <summary>Largest result one handle use may return to the tool. Default 1 MiB.</summary>
    public int MaxResultBytes { get; set; } = 1 << 20;
    /// <summary>The instruction budget of one run (a positive safe integer). Default: the largest the engine accepts (2^53 - 1), so the wall-clock deadline is the bound.</summary>
    public long Fuel { get; set; } = 9007199254740991L;
    /// <summary>Evidence for the runtime class. Without a claim that verifies the table is class none: an operator's say-so does not count.</summary>
    public SandboxRuntimeClaim? RuntimeClaim { get; set; }
}

/// <summary>A sandbox: the capability <see cref="Table"/>, the receipt <see cref="Log"/> and the runners.</summary>
public sealed class WasmSandboxHost
{
    readonly SandboxOptions _o;

    public PcaSandbox.HandleTable Table { get; }
    public PcaSandbox.ReceiptLog Log { get; }
    /// <summary>The runtime class of the table: what the claim proved, capped at what a WASM host can prove (wasi_no_ambient), else none.</summary>
    public string RuntimeClass => Table.RuntimeClass;

    internal WasmSandboxHost(SandboxOptions o)
    {
        _o = o;
        Log = o.Log ?? (o.Now != null ? new PcaSandbox.ReceiptLog(() => o.Now()) : new PcaSandbox.ReceiptLog());
        // a WASM host cannot prove more than wasi_no_ambient, so a stronger claim is capped there
        var proven = o.RuntimeClaim != null ? PcaSandbox.VerifiedRuntimeClass(o.RuntimeClaim.Claim, o.RuntimeClaim.Trust) : "none";
        var cls = proven is "wasi_no_ambient" or "egress_default_deny" or "os_confined" ? proven : "none";
        Table = new PcaSandbox.HandleTable(cls, Log, o.Executors, o.Now);
    }

    /// <summary>Run <paramref name="bytes"/>' <paramref name="entry"/> export against the table (validation, fuel and the wall-clock deadline included).</summary>
    public RunResult Run(byte[] bytes, string entry = "run", int timeoutMs = 5000) =>
        WasmHost.RunCoreModule(Table, bytes, new CoreOptions
        {
            Fuel = _o.Fuel, TimeoutMs = timeoutMs, MaxModuleBytes = _o.MaxModuleBytes, MaxMemoryPages = _o.MaxMemoryPages, MaxResultBytes = _o.MaxResultBytes,
        }, entry);

    /// <summary>Run the tool on a worker thread; one that never returns is stopped at <paramref name="timeoutMs"/> with the reason <c>timeout</c>. Validation is identical to <see cref="Run"/>.</summary>
    public Task<RunResult> RunAsync(byte[] bytes, string entry = "run", int timeoutMs = 5000) => Task.Run(() => Run(bytes, entry, timeoutMs));
}

public static class WasmSandbox
{
    /// <summary>Build a sandbox (the reference createSandbox).</summary>
    public static WasmSandboxHost CreateSandbox(SandboxOptions opts) => new(opts ?? throw new ArgumentException("sandbox options are required"));
}
