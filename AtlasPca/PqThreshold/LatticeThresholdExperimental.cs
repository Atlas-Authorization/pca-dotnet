// EXPERIMENTAL, NOT PRODUCTION. The Raccoon / Ringtail-style lattice-threshold design and a TOY additive secret-sharing sketch (the reference's experimental lattice-threshold
// module): it documents the future, it is not a signature scheme. The sharing is n-of-n over Z_q (every share is needed), the arithmetic is variable-time and the default
// sampler is not a vetted key generator. The shippable post-quantum threshold is the hybrid in the hybrid threshold. Every routine is gated behind an explicit
// opt-in and refuses with the banner without it (fail closed).
using System.Numerics;
using System.Security.Cryptography;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PqThreshold;

/// <summary>Toy lattice parameters: a modulus (a small one for demonstration; the real ML-DSA modulus is 8380417) and the key dimension.</summary>
public sealed record ToyLatticeParams(BigInteger Q, int Dim);

/// <summary>One party's additive share of the toy key: a 1-based index and a coefficient vector mod q.</summary>
public sealed record LatticeKeyShare(int Index, IReadOnlyList<BigInteger> Coeffs);

public static class LatticeThresholdExperimental
{
    public const string ExperimentalBanner =
        "EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign.";

    /// <summary>The default illustrative ML-DSA modulus, used purely so the arithmetic looks familiar.</summary>
    public static readonly ToyLatticeParams ToyDefaultParams = new(8380417, 4);

    static void AssertOptIn(bool iUnderstandThisIsNotProduction)
    {
        if (!iUnderstandThisIsNotProduction) throw new InvalidOperationException(ExperimentalBanner + " Pass iUnderstandThisIsNotProduction: true to proceed.");
    }

    static BigInteger Mod(BigInteger x, BigInteger q)
    {
        var r = x % q;
        return r.Sign < 0 ? r + q : r;
    }

    /// <summary>A random coefficient in [0, q) from the OS random source (an unreadable source is a hard stop, never a fixed coefficient).</summary>
    static BigInteger DefaultSampler(BigInteger q)
    {
        var b = RandomNumberGenerator.GetBytes(8);
        return Mod(new BigInteger(b, isUnsigned: true), q);
    }

    /// <summary>EXPERIMENTAL. Additively secret-share a toy key vector into <paramref name="n"/> shares over Z_q, per coefficient: shares 1..n-1 are random, the last absorbs the
    /// remainder so the shares sum to the key (mod q). n-of-n, not t-of-n and not a signature scheme. <paramref name="sampler"/> (a coefficient in [0, q)) is injectable so tests
    /// are deterministic.</summary>
    public static List<LatticeKeyShare> AdditiveShareLatticeKey(IReadOnlyList<BigInteger> key, int n, bool iUnderstandThisIsNotProduction, ToyLatticeParams? parameters = null, Func<BigInteger, BigInteger>? sampler = null)
    {
        AssertOptIn(iUnderstandThisIsNotProduction);
        var p = parameters ?? ToyDefaultParams;
        if (n < 1 || n > 1024) throw new ArgumentOutOfRangeException(nameof(n), "additiveShareLatticeKey: n must be an integer in [1, 1024]");
        if (key.Count != p.Dim) throw new ArgumentOutOfRangeException(nameof(key), $"additiveShareLatticeKey: key must have {p.Dim} coefficients");
        var s = sampler ?? DefaultSampler;
        var rows = Enumerable.Range(0, n).Select(_ => new BigInteger[p.Dim]).ToArray();
        for (var c = 0; c < p.Dim; c++)
        {
            var target = Mod(key[c], p.Q);
            var running = BigInteger.Zero;
            for (var i = 0; i < n - 1; i++)
            {
                var r = Mod(s(p.Q), p.Q);
                rows[i][c] = r;
                running = Mod(running + r, p.Q);
            }
            rows[n - 1][c] = Mod(target - running, p.Q);
        }
        return rows.Select((coeffs, i) => new LatticeKeyShare(i + 1, coeffs)).ToList();
    }

    /// <summary>EXPERIMENTAL. Reconstruct the toy key by summing ALL shares' coefficient vectors mod q. A repeated share index is refused: it would be counted twice and silently
    /// yield a wrong key.</summary>
    public static List<BigInteger> ReconstructLatticeKey(IReadOnlyList<LatticeKeyShare> shares, bool iUnderstandThisIsNotProduction, ToyLatticeParams? parameters = null)
    {
        AssertOptIn(iUnderstandThisIsNotProduction);
        var p = parameters ?? ToyDefaultParams;
        if (shares.Count == 0) throw new ArgumentOutOfRangeException(nameof(shares), "reconstructLatticeKey: need at least one share");
        if (shares.Select(s => s.Index).Distinct().Count() != shares.Count) throw new ArgumentException("reconstructLatticeKey: duplicate share index", nameof(shares));
        var o = Enumerable.Repeat(BigInteger.Zero, p.Dim).ToList();
        foreach (var share in shares)
        {
            if (share.Coeffs.Count != p.Dim) throw new ArgumentException("reconstructLatticeKey: a share has the wrong dimension", nameof(shares));
            for (var c = 0; c < p.Dim; c++) o[c] = Mod(o[c] + share.Coeffs[c], p.Q);
        }
        return o;
    }

    static L Strs(params string[] xs) => new(xs.Cast<object?>());

    /// <summary>A documented spec of the Raccoon / Ringtail-style lattice-threshold approach: DATA describing the research design, it performs no cryptography.</summary>
    public static D RaccoonDesign() => new()
    {
        ["scheme"] = "Raccoon/Ringtail-style lattice threshold (RESEARCH)",
        ["status"] = "research-prototype",
        ["productionReady"] = false,
        ["banner"] = ExperimentalBanner,
        ["assumption"] = "Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.",
        ["construction"] = Strs(
            "1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.",
            "2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.",
            "3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.",
            "4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.",
            "5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem."),
        ["whyNoLibraryYet"] = Strs(
            "Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.",
            "Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.",
            "No constant-time, side-channel-hardened reference implementation has been published and audited.",
            "The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial."),
        ["shippableAlternative"] =
            "Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.",
        ["parameterSets"] = new L
        {
            new D { ["name"] = "Raccoon-128 (illustrative)", ["nistCategory"] = 1L, ["note"] = "Research parameters only; not implemented here." },
            new D { ["name"] = "Raccoon-192 (illustrative)", ["nistCategory"] = 3L, ["note"] = "Matches ML-DSA-65 category; not implemented here." },
        },
        ["references"] = Strs(
            "Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).",
            "Ringtail: two-round threshold signatures from lattices.",
            "FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror."),
    };
}
