// verifier_from_config: build a vendor attestation verifier from the language-neutral configuration documented in the conformance
// vector file (verifier_config_schema), and the default-verifier seam of Passports.Verify.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Verifies the hardware evidence of one vendor under a fixed configuration. Safe for concurrent use.</summary>
public sealed class VendorVerifier : IVendorVerifier, IAssuranceLabeled
{
    static readonly Dictionary<string, string> ErrorPrefix = new()
    {
        ["amd-sev-snp"] = "amd-snp verification error (fail closed): ",
        ["intel-tdx-dcap"] = "intel-dcap verification error (fail closed): ",
        ["azure-maa"] = "azure-maa verification error (fail closed): ",
        ["gcp-confidential-space"] = "gcp-confidential-space verification error (fail closed): ",
        ["nvidia-gpu-spdm"] = "nvidia-spdm verification error (fail closed): ",
    };

    readonly IVendorImpl impl;
    readonly JD? overrides;

    internal VendorVerifier(string vendor, IVendorImpl impl, JD? overrides) { Vendor = vendor; this.impl = impl; this.overrides = overrides; }

    /// <summary>The vendor this verifier was built for.</summary>
    public string Vendor { get; }

    /// <summary>A vendor verifier is hardware evidence of its vendor (the assurance label comes from this configuration, never from the evidence).</summary>
    public AssuranceLabel Assurance => new("hardware", Vendor);

    public HardwareResult Verify(JD? evidence, AttestationBinding? expected, long nowMs)
    {
        try
        {
            var res = impl.Verify(evidence, expected, nowMs);
            if (res.Ok && res.Measured != null && overrides is { Count: > 0 }) res = res with { Measured = AttestUtil.MergeOverrides(res.Measured, overrides) };
            return res;
        }
        catch (Exception e) { return HardwareResult.Fail(ErrorPrefix[Vendor] + e.Message); }
    }
}

public static class AttestationVerifiers
{
    /// <summary>The vendors <see cref="FromConfig"/> builds a verifier for.</summary>
    public static readonly string[] Vendors = { "amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm" };

    /// <summary>Builds the verifier for (vendor, config). An <see cref="ArgumentException"/> is the constructor's refusal of the configuration (a
    /// missing allowlist, an absent trust anchor, a malformed pin: there is no accept-all). <c>identity_overrides</c>, if present, are merged
    /// over the measured identity of every successful verification.</summary>
    public static IVendorVerifier FromConfig(string vendor, JD? config)
    {
        config ??= new JD();
        IVendorImpl impl = vendor switch
        {
            "amd-sev-snp" => AmdVerifier.Create(config),
            "intel-tdx-dcap" => IntelVerifier.Create(config),
            "azure-maa" => MaaVerifier.Create(config),
            "gcp-confidential-space" => GcpVerifier.Create(config),
            "nvidia-gpu-spdm" => NvidiaVerifier.Create(config),
            _ => throw new ArgumentException($"unknown attestation vendor \"{vendor}\""),
        };
        return new VendorVerifier(vendor, impl, config.GetValueOrDefault("identity_overrides") as JD);
    }
}
