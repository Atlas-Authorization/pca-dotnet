// WebAssembly hosts for the sandbox handle table. RunCoreModule runs a core module in-process under Wasmtime with an instruction budget (fuel),
// a wall-clock deadline (epoch interruption), a hard linear-memory cap and no ambient authority: WASI is never configured or linked, the only
// imports are pca:act.{invoke,handle_count,handle_verb}. The guest is served only from a HandleTable; the table decides every use.
using Wasmtime;
using AtlasPca.Sandbox;

namespace AtlasPca.Wasm;

/// <summary>{Ok, Value} or {Ok=false, Reason}.</summary>
public sealed record RunResult(bool Ok, long Value, string? Reason, long? FuelUsed = null)
{
    public static RunResult Success(long v, long? fuelUsed = null) => new(true, v, null, fuelUsed);
    public static RunResult Fail(string reason) => new(false, 0, reason);
}

/// <summary>Options of <see cref="WasmHost.RunCoreModule"/>. <see cref="Fuel"/> is required (a positive safe integer): a budget is a decision.</summary>
public sealed class CoreOptions
{
    public long? Fuel;
    public int TimeoutMs = 5000;
    public int MaxModuleBytes = 1 << 20;
    public int MaxMemoryPages = 256;
    public int MaxResultBytes = 1 << 20;
}

public static partial class WasmHost
{
    const long Safe = 9007199254740991; // 2^53 - 1

    internal static bool BadFuel(long? f) => f == null || f < 1 || f > Safe;

    /// <summary>The first memory of the module: the declaration the engine could not otherwise cap statically.</summary>
    internal sealed record MemInfo(long Count, double Min, double? Max, bool Shared);

    /// <summary>Parse only the memory section. Returns (false, _) when unparseable; (true, null) when there is no memory section. A flag above 3
    /// (memory64 and anything newer) reads as shared, so it is refused.</summary>
    internal static bool MemoryLimits(byte[] b, out MemInfo? info)
    {
        info = null;
        if (b.Length < 8 || b[0] != 0 || b[1] != 0x61 || b[2] != 0x73 || b[3] != 0x6d) return false;
        int o = 8;
        try
        {
            double Leb()
            {
                double r = 0;
                for (int shift = 0; shift < 35; shift += 7)
                {
                    int x = b[o++]; // IndexOutOfRange = eof
                    r += (x & 0x7F) * Math.Pow(2, shift);
                    if ((x & 0x80) == 0) return r;
                }
                throw new FormatException("leb");
            }
            while (o < b.Length)
            {
                int sid = b[o++];
                double size = Leb();
                double end = o + size;
                if (end > b.Length) return false;
                if (sid == 5)
                {
                    long count = (long)Leb();
                    if (count == 0) return true;
                    int flag = b[o++];
                    if (flag > 3) { info = new MemInfo(count, double.PositiveInfinity, null, true); return true; }
                    double mn = Leb();
                    double? mx = (flag & 1) != 0 ? Leb() : null;
                    info = new MemInfo(count, mn, mx, (flag & 2) != 0);
                    return true;
                }
                o = (int)end;
            }
            return true;
        }
        catch (Exception e) when (e is IndexOutOfRangeException or FormatException) { return false; }
    }

    /// <summary>Run <paramref name="wasm"/>'s <paramref name="entry"/> export against <paramref name="table"/>. Refuses to run (fail closed) if the engine
    /// cannot enforce fuel, the wall-clock deadline or the memory cap. Never throws for a guest or engine failure.
    /// A runtime memory.grow past the cap makes the guest see -1 (the store limiter), exactly like the reference; the declared-maximum
    /// check refuses the static cases as memory_limits. A blocking executor cannot be interrupted by the deadline.</summary>
    public static RunResult RunCoreModule(PcaSandbox.HandleTable table, byte[] wasm, CoreOptions opts, string entry = "run")
    {
        if (BadFuel(opts.Fuel)) return RunResult.Fail("bad_fuel");
        if (wasm == null || wasm.Length == 0 || wasm.Length > opts.MaxModuleBytes) return RunResult.Fail("module_size");
        if (!MemoryLimits(wasm, out var mem)) return RunResult.Fail("malformed_module");
        if (mem != null && (mem.Count > 1 || mem.Max == null || mem.Shared || mem.Min > opts.MaxMemoryPages || mem.Max > opts.MaxMemoryPages))
            return RunResult.Fail("memory_limits");

        Engine engine;
        try { engine = new Engine(new Config().WithFuelConsumption(true).WithEpochInterruption(true)); }
        catch (Exception) { return RunResult.Fail("limit_unenforceable:fuel"); }
        using var _engine = engine;

        Module module;
        try { module = Module.FromBytes(engine, "tool", wasm); }
        catch (Exception) { return RunResult.Fail("malformed_module"); }
        using var _module = module;
        foreach (var i in module.Imports)
            if (i is not FunctionImport || i.ModuleName != PcaSandbox.ImportModule || !PcaSandbox.AllowedImports.Contains(i.Name))
                return RunResult.Fail("ambient_import:" + i.ModuleName + "." + i.Name);

        using var store = new Store(engine);
        try { store.SetLimits(memorySize: (long)opts.MaxMemoryPages * 65536); }
        catch (Exception) { return RunResult.Fail("limit_unenforceable:memory"); }
        try { store.Fuel = (ulong)opts.Fuel!.Value; }
        catch (Exception) { return RunResult.Fail("limit_unenforceable:fuel"); }
        try { store.SetEpochDeadline(1); }
        catch (Exception) { return RunResult.Fail("limit_unenforceable:timeout"); }

        // the output window: (ptr as u32) + (len as u32) inside the memory, in unsigned 32-bit math widened so it cannot wrap
        static bool Window(Caller c, int ptr, int len, out Memory? m)
        {
            m = c.GetMemory("memory");
            return m != null && (ulong)(uint)ptr + (uint)len <= (ulong)m.GetLength();
        }
        static void Put(Memory m, int ptr, byte[] data) { if (data.Length > 0) data.CopyTo(m.GetSpan((uint)ptr, data.Length)); }

        using var linker = new Linker(engine); // no DefineWasi: the guest has no ambient authority
        var i32 = ValueKind.Int32;
        linker.DefineFunction(PcaSandbox.ImportModule, "handle_count", (Caller c, ReadOnlySpan<ValueBox> a, Span<ValueBox> r) => r[0] = table.Size,
            Array.Empty<ValueKind>(), new[] { i32 });
        linker.DefineFunction(PcaSandbox.ImportModule, "handle_verb", (Caller c, ReadOnlySpan<ValueBox> a, Span<ValueBox> r) =>
        {
            int h = a[0].AsInt32(), ptr = a[1].AsInt32(), cap = a[2].AsInt32();
            var verb = table.VerbOf(h);
            if (verb == null) { r[0] = (int)PcaSandbox.UseErr["unknown_handle"]; return; }
            var enc = System.Text.Encoding.UTF8.GetBytes(verb);
            if (!Window(c, ptr, cap, out var m)) { r[0] = (int)PcaSandbox.UseErr["bad_memory"]; return; }
            if (enc.Length > (uint)cap) { r[0] = (int)PcaSandbox.UseErr["out_too_small"]; return; }
            Put(m!, ptr, enc);
            r[0] = enc.Length;
        }, new[] { i32, i32, i32 }, new[] { i32 });
        linker.DefineFunction(PcaSandbox.ImportModule, "invoke", (Caller c, ReadOnlySpan<ValueBox> a, Span<ValueBox> r) =>
        {
            int h = a[0].AsInt32(), ptr = a[1].AsInt32(), cap = a[2].AsInt32();
            if (!Window(c, ptr, cap, out var m)) { r[0] = (int)PcaSandbox.UseErr["bad_memory"]; return; } // before a use is spent
            var u = table.Use(h);
            if (!u.Ok) { r[0] = (int)PcaSandbox.UseErr[u.Reason!]; return; }
            var res = u.Result!;
            if (res.Length > opts.MaxResultBytes || (uint)res.Length > (uint)cap) { r[0] = (int)PcaSandbox.UseErr["out_too_small"]; return; }
            Put(m!, ptr, res);
            r[0] = res.Length;
        }, new[] { i32, i32, i32 }, new[] { i32 });

        // the epoch tick is the wall-clock bound: it interrupts a tight loop inside the guest, not just a wait
        using var timer = new System.Threading.Timer(_ => { try { engine.IncrementEpoch(); } catch (Exception) { } }, null, Math.Max(opts.TimeoutMs, 0), System.Threading.Timeout.Infinite);
        try
        {
            Instance instance;
            try { instance = linker.Instantiate(store, module); }
            catch (Exception e) { return Classify(e, true); }
            var fn = instance.GetFunction(entry);
            if (fn == null) return RunResult.Fail("no_entry");
            try
            {
                var v = fn.Invoke();
                return RunResult.Success(v is int n ? n : v is long l ? l : 0);
            }
            catch (Exception e) { return Classify(e, false); }
        }
        finally
        {
            using var done = new System.Threading.ManualResetEvent(false);
            if (timer.Dispose(done)) done.WaitOne(); // a late tick must not hit a disposed engine
        }
    }

    static RunResult Classify(Exception e, bool instantiating)
    {
        if (e is TrapException t)
            return t.Type switch
            {
                TrapCode.OutOfFuel => RunResult.Fail("fuel_exhausted"),
                TrapCode.Interrupt => RunResult.Fail("timeout"),
                _ => RunResult.Fail("trap:RuntimeError"),
            };
        var msg = e.Message.ToLowerInvariant();
        if (msg.Contains("all fuel consumed") || msg.Contains("out of fuel")) return RunResult.Fail("fuel_exhausted");
        if (msg.Contains("interrupt")) return RunResult.Fail("timeout");
        if (msg.Contains("memory") && (msg.Contains("minimum") || msg.Contains("limit") || msg.Contains("exceed"))) return RunResult.Fail("memory_limits");
        return RunResult.Fail(instantiating ? "trap:LinkError" : "trap:RuntimeError");
    }
}
