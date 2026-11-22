// The component host: runs a component (binary or WAT text) in the reference wasmtime host binary as a subprocess, with an instruction budget.
// The binary path comes from configuration (HostBinary.Path, else env PCA_WASMTIME_HOST, else the host the NuGet package carries) and is pinned by SHA-256 (HostBinary.ExpectedSha256,
// else env PCA_WASMTIME_HOST_SHA256), checked on every call; never a PATH search. The verified bytes are copied into a fresh private temp dir and
// THAT copy is executed, so the file cannot change between the hash and the exec. The child gets an empty environment and no shell.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AtlasPca.Sandbox;

namespace AtlasPca.Wasm;

/// <summary>Where the reference host binary is and the SHA-256 (hex) it must have. Null members fall back to the environment.</summary>
public sealed record HostBinary(string? Path = null, string? ExpectedSha256 = null);

public sealed class ComponentOptions
{
    public long? Fuel;
    public int TimeoutMs = 10000;
    public int MaxResultBytes = 1 << 20;
}

public static partial class WasmHost
{
    static bool IsHex64(string? s) => s != null && s.Length == 64 && s.All(Uri.IsHexDigit);

    /// <summary>The reference host the NuGet package carries for this platform (runtimes/&lt;rid&gt;/native, or beside the application after a
    /// rid-specific publish) with its SHA-256 pin from the sidecar file shipped with it; null when this platform has none.</summary>
    public static HostBinary? PackagedHost()
    {
        var rid = (OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux") + "-" + System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        var exe = OperatingSystem.IsWindows() ? "pca-wasmtime-host.exe" : "pca-wasmtime-host";
        foreach (var dir in new[] { Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native"), AppContext.BaseDirectory })
        {
            var path = Path.Combine(dir, exe);
            var sum = Path.Combine(dir, "pca-wasmtime-host.sha256");
            if (!File.Exists(path) || !File.Exists(sum)) continue;
            try { var pin = File.ReadAllText(sum).Trim(); if (IsHex64(pin)) return new HostBinary(path, pin); } catch (IOException) { }
        }
        return null;
    }

    /// <summary>Verify the pin and stage the binary: (null, reason) on refusal, else the private dir and the executable inside it.</summary>
    internal static string? Stage(HostBinary host, out string dir, out string exe)
    {
        dir = ""; exe = "";
        var path = host.Path ?? Environment.GetEnvironmentVariable("PCA_WASMTIME_HOST");
        string? packagedPin = null;
        if (string.IsNullOrEmpty(path)) { var pk = PackagedHost(); path = pk?.Path; packagedPin = pk?.ExpectedSha256; } // no configuration: the host the package carries
        if (string.IsNullOrEmpty(path)) return "host_missing";
        byte[] binary;
        try { binary = File.ReadAllBytes(path); } catch (Exception) { return "host_missing"; }
        var pin = host.ExpectedSha256 ?? Environment.GetEnvironmentVariable("PCA_WASMTIME_HOST_SHA256") ?? packagedPin;
        if (!IsHex64(pin)) return "host_unpinned";
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(binary), Convert.FromHexString(pin!))) return "host_hash_mismatch";
        dir = AtlasPca.OwnerOnly.CreateDirectory(Path.Combine(Path.GetTempPath(), "pca-comp-" + Guid.NewGuid().ToString("N"))).FullName; // owner-only from creation
        exe = Path.Combine(dir, OperatingSystem.IsWindows() ? "host.exe" : "host");
        AtlasPca.OwnerOnly.WriteAllBytes(exe, binary);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return null;
    }

    public static RunResult RunComponent(PcaSandbox.HandleTable table, byte[] component, HostBinary host, ComponentOptions opts)
    {
        if (BadFuel(opts.Fuel)) return RunResult.Fail("bad_fuel");
        var why = Stage(host, out var dir, out var exe);
        if (why != null) return RunResult.Fail(why);
        try
        {
            var file = Path.Combine(dir, "tool.component");
            File.WriteAllBytes(file, component);
            return Converse(table, exe, new[] { file, opts.Fuel!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) }, opts.TimeoutMs, opts.MaxResultBytes);
        }
        finally { try { Directory.Delete(dir, true); } catch (Exception) { } }
    }

    public static RunResult RunComponent(PcaSandbox.HandleTable table, string wat, HostBinary host, ComponentOptions opts) =>
        RunComponent(table, Encoding.UTF8.GetBytes(wat), host, opts);

    /// <summary>The JSON-lines conversation: one request answered at a time until a done/fail line.</summary>
    static RunResult Converse(PcaSandbox.HandleTable table, string exe, string[] args, int timeoutMs, int maxResult)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment.Clear();
        Process? child = null;
        try
        {
            try { child = Process.Start(psi); } catch (Exception) { return RunResult.Fail("host_unavailable"); }
            if (child == null) return RunResult.Fail("host_unavailable");
            child.ErrorDataReceived += (_, _) => { };
            child.BeginErrorReadLine();
            var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(timeoutMs, 0));
            while (true)
            {
                string? line;
                try
                {
                    var t = child.StandardOutput.ReadLineAsync();
                    var left = deadline - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero || !t.Wait(left)) return RunResult.Fail("timeout");
                    line = t.Result;
                }
                catch (Exception) { return RunResult.Fail("host_exit"); }
                if (line == null) return RunResult.Fail("host_exit");
                JsonElement m;
                try
                {
                    m = JsonDocument.Parse(line).RootElement;
                    if (m.ValueKind != JsonValueKind.Object) return RunResult.Fail("host_protocol");
                }
                catch (JsonException) { return RunResult.Fail("host_protocol"); }
                if (m.TryGetProperty("fail", out var f) && f.ValueKind == JsonValueKind.String) return RunResult.Fail(f.GetString()!);
                if (m.TryGetProperty("done", out var d) && d.ValueKind == JsonValueKind.Number)
                {
                    long? used = m.TryGetProperty("fuel_used", out var fu) && fu.TryGetInt64(out var u) ? u : null;
                    return RunResult.Success(d.TryGetInt64(out var v) ? v : (long)d.GetDouble(), used);
                }
                long h = m.TryGetProperty("h", out var hp) && hp.TryGetInt64(out var hv) ? hv : 0;
                string reply;
                switch (m.TryGetProperty("op", out var op) && op.ValueKind == JsonValueKind.String ? op.GetString() : null)
                {
                    case "count": reply = "{\"n\":" + table.Size + "}"; break;
                    case "verb":
                        var verb = table.VerbOf(h);
                        reply = verb == null ? "{\"err\":" + PcaSandbox.UseErr["unknown_handle"] + "}" : "{\"ok\":" + JsonSerializer.Serialize(verb) + "}";
                        break;
                    case "invoke":
                        var r = table.Use(h);
                        reply = !r.Ok ? "{\"err\":" + PcaSandbox.UseErr[r.Reason!] + "}"
                            : r.Result!.Length > maxResult ? "{\"err\":" + PcaSandbox.UseErr["out_too_small"] + "}"
                            : "{\"ok\":[" + string.Join(",", r.Result) + "]}";
                        break;
                    default: return RunResult.Fail("host_protocol");
                }
                try { child.StandardInput.WriteLine(reply); child.StandardInput.Flush(); }
                catch (IOException) { return RunResult.Fail("host_exit"); }
            }
        }
        finally
        {
            if (child != null)
            {
                try { child.Kill(true); } catch (Exception) { }
                try { child.WaitForExit(2000); } catch (Exception) { }
                child.Dispose();
            }
        }
    }
}
