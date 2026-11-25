// Public constants of the satellite packages under the reference names (each is the value of the TypeScript export): the x402 HTTP status map, the escalation maximum,
// the rate periods, the lease shard bounds, the break-glass limits, the Sigstore bundle media types, the grant step-up and need-request domains and message bodies, the
// restricted resource-id character classes and the AMD Milan ARK pin. Where the SDK already uses the same value privately, the tests pin the two together.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class PackageConstants
{
    /// <summary>The HTTP status each x402 settlement outcome maps to.</summary>
    public static IReadOnlyDictionary<string, int> X402HttpStatus { get; } =
        new Dictionary<string, int> { ["payment_required"] = 402, ["malformed"] = 400, ["failed"] = 402, ["internal_error"] = 500, ["settled"] = 200 };

    /// <summary>The highest escalation tier number (auto 0 < confirm 1 < cosign 2 < stepup 3).</summary>
    public const int EscMax = 3;

    /// <summary>The rate-cap periods in milliseconds.</summary>
    public static IReadOnlyDictionary<string, long> RatePeriods { get; } = new Dictionary<string, long> { ["hour"] = 3_600_000, ["day"] = 86_400_000 };

    public const int DefaultLeaseShards = 16;
    public const int MaxLeaseShards = 4096;
    public const int MaxBreakGlassUses = 16;
    public const long MaxBreakGlassWindowMs = 86_400_000;

    /// <summary>The signature suite of a PQ co-signer quorum entry (the hybrid threshold's PQ half).</summary>
    public const string HybridPqAlg = "ml-dsa-65";

    public static IReadOnlyList<string> SigstoreBundleMediaTypes { get; } = new[]
    {
        "application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3", "application/vnd.dev.sigstore.bundle.v0.3+json",
    };

    public const string GrantStepupDomain = "atlas-pca/grant-stepup/v1\0";
    public const string NeedRequestDomain = "atlas-pca/need-request/v1\0";

    /// <summary>The body a principal signs to approve a step-up challenge: <c>{grant, challenge, nonce}</c>.</summary>
    public static JD StepUpMessage(string grantId, string challengeId, string nonce) => new() { ["grant"] = grantId, ["challenge"] = challengeId, ["nonce"] = nonce };

    /// <summary>The body a holder signs to request needs on a grant: <c>{grant, rev, needs}</c>.</summary>
    public static JD NeedRequestMessage(string grantId, long rev, JL needs) => new() { ["grant"] = grantId, ["rev"] = new Num(rev.ToString(System.Globalization.CultureInfo.InvariantCulture)), ["needs"] = needs };

    static IReadOnlySet<string> Chars(string s) => new HashSet<string>(s.Select(c => c.ToString()), StringComparer.Ordinal);
    const string Digits = "0123456789", Lower = "abcdefghijklmnopqrstuvwxyz", Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /// <summary>The character set of each restricted resource-id class (digits, hex, alnum, slug, uuid, any_safe).</summary>
    public static IReadOnlyDictionary<string, IReadOnlySet<string>> IdClassChars { get; } = new Dictionary<string, IReadOnlySet<string>>
    {
        ["digits"] = Chars(Digits), ["hex"] = Chars(Digits + "abcdef"), ["alnum"] = Chars(Digits + Lower + Upper), ["slug"] = Chars(Digits + Lower + "-_"),
        ["uuid"] = Chars(Digits + "abcdef-"), ["any_safe"] = Chars(Digits + Lower + Upper + "._-:/"),
    };

    /// <summary>SHA-384 of the AMD Milan ARK's SPKI (the pinned root of trust of the SEV-SNP certificate chain), hex.</summary>
    public const string AmdMilanArkSpkiSha384 = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e";
}
