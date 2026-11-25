using Xunit;

namespace AtlasPca.Mpc.Tests;

/// <summary>Shared TLS 1.3 gate. The mesh requires TLS 1.3 (the reference's minVersion) and never falls back. It runs when ATLAS_MPC_TLS13=1 (Linux CI sets it),
/// on Linux outside CI, and is skipped with an explicit reason elsewhere. Linux in CI (CI=true) WITHOUT the opt-in is a failure (<see cref="TlsGateTests"/>), never a silent skip.</summary>
static class TlsGate
{
    public static bool OptIn => Environment.GetEnvironmentVariable("ATLAS_MPC_TLS13") == "1";

    public static bool InCi => string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

    public static string? SkipReason()
    {
        if (OptIn) return null;
        if (OperatingSystem.IsLinux() && !InCi) return null;
        return OperatingSystem.IsLinux()
            ? "SKIPPED: Linux CI did not set ATLAS_MPC_TLS13=1 (TlsGateTests fails this run)."
            : "SKIPPED: the mesh requires TLS 1.3 and SslStream supports it reliably only on Linux (OpenSSL); this runner is not Linux. Set ATLAS_MPC_TLS13=1 to run anyway.";
    }
}

public sealed class TlsFactAttribute : FactAttribute
{
    public TlsFactAttribute() { Skip = TlsGate.SkipReason(); }
}

public class TlsGateTests
{
    [Fact] public void LinuxCiMustOptInToTheTlsTests() =>
        Assert.False(OperatingSystem.IsLinux() && TlsGate.InCi && !TlsGate.OptIn, "Linux CI must set ATLAS_MPC_TLS13=1: the MPC mesh tests would otherwise be skipped silently");
}
