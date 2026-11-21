using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Invariants;

/// <summary>An Ed25519 key pair whose 32-byte secret IS the generator's bytes; <see cref="Pub"/> is the b64u public key (the <c>issuer</c> / <c>holder</c> form).</summary>
public sealed record GenKeyPair(byte[] SecretKey, byte[] PublicKey, string Pub);

/// <summary>One hop of a generated chain: the holder it delegates to and the caveat specs it adds.</summary>
public sealed record HopModel(byte[] HolderSeed, IReadOnlyList<D> AddedSpecs);

/// <summary>The model a legal chain is built from. A caveat spec is <c>{k, ...}</c>: expires / not_before (<c>at</c>), rate (<c>max</c>,
/// <c>per_secs</c>), max_blast_radius (<c>max</c>), reversibility_max (<c>cls</c>), delegation_depth (<c>max</c>), budget_frac (<c>frac</c>).</summary>
public sealed record ChainModel(byte[] PrincipalSeed, byte[] Holder0Seed, IReadOnlyList<D> RootSpecs, IReadOnlyList<HopModel> Hops, object? Predicates);

/// <summary>A generated, signed, legally-attenuating chain with the fixed envelope predicates alongside it.</summary>
public sealed record GeneratedChain(List<D> Caps, object? Predicates, string RootIssuer, List<string> Holders)
{
    public D ToTree() => new()
    {
        ["caps"] = Caps.Cast<object?>().ToList(),
        ["predicates"] = Predicates,
        ["rootIssuer"] = RootIssuer,
        ["holders"] = Holders.Cast<object?>().ToList(),
    };
}

/// <summary>The six risk axes the monotonicity property is stated over (each in [0,1]).</summary>
public sealed record RiskAxes(double SemanticDistance, double BlastRadius, double Taint, double Age, double Reversibility, double Confidence)
{
    public D ToTree() => new()
    {
        ["semanticDistance"] = Num(SemanticDistance), ["blastRadius"] = Num(BlastRadius), ["taint"] = Num(Taint),
        ["age"] = Num(Age), ["reversibility"] = Num(Reversibility), ["confidence"] = Num(Confidence),
    };
    static AtlasPca.Num Num(double d) => new(JsJson.NumberToString(d));
}

/// <summary>Non-negative deltas used to build a pointwise-worse risk input.</summary>
public sealed record RiskDeltas(double DSem, double DBlast, double DTaint, double DAge, double DRev, double DConf);

/// <summary>The deterministic exports of the machine-checked safety invariants: seeded key pairs, the legal-chain builder, the risk "worsen"
/// helper and the registry constants. The property functions and the property-based runner are not part of the native surface (they drive a
/// property-testing library); the native SDK's own suites check the same four universal properties.</summary>
public static class PcaInvariants
{
    public const long DefaultSeed = 20260108;
    public const int DefaultNumRuns = 1000;

    /// <summary>The registry names, in order.</summary>
    public static readonly IReadOnlyList<string> InvariantNames = new[]
    {
        "attenuation-monotonicity", "risk-wellformed-and-monotone", "admission-soundness", "cumulative-budget-bound", "fail-closed:undecidable-leaf",
        "fail-closed:undecidable-groups", "fail-closed:member-of-cycle-safe", "fail-closed:unknown-caveat-type", "fail-closed:forged-chain-rejected",
        "fail-closed:garbage-chain-rejected", "forbid-monotone", "determinism",
    };

    const double BudgetAllocBase = 1_000_000;

    /// <summary>The Ed25519 key pair whose secret is <paramref name="seed"/> (32 bytes; anything else throws).</summary>
    public static GenKeyPair KeyPairFromSeed(byte[] seed)
    {
        using var k = EdKey.FromSeed(seed);
        return new GenKeyPair((byte[])seed.Clone(), (byte[])k.Pub.Clone(), k.Id);
    }

    sealed class Alloc { public double Running = double.PositiveInfinity; }

    /// <summary>Materialise one spec into a concrete caveat, threading the running budget allocation (monotone non-increasing).</summary>
    static D SpecToCaveat(D spec, Alloc alloc)
    {
        object? V(string k) => spec.TryGetValue(k, out var v) ? v : throw new ArgumentException($"caveat spec is missing '{k}'");
        switch (spec.GetValueOrDefault("k") as string)
        {
            case "expires": return new D { ["type"] = "expires", ["at"] = V("at") };
            case "not_before": return new D { ["type"] = "not_before", ["at"] = V("at") };
            case "rate": return new D { ["type"] = "rate", ["max"] = V("max"), ["per_secs"] = V("per_secs") };
            case "max_blast_radius": return new D { ["type"] = "max_blast_radius", ["max"] = V("max") };
            case "reversibility_max": return new D { ["type"] = "reversibility_max", ["class"] = V("cls") };
            case "delegation_depth": return new D { ["type"] = "delegation_depth", ["max"] = V("max") };
            case "budget_frac":
            {
                var bas = double.IsFinite(alloc.Running) ? alloc.Running : BudgetAllocBase;
                // frac in [0,1] and base a non-negative integer: the floor is an integer in [0, base], at most the previous allocation
                var limit = Math.Floor(bas * JsJson.ToJsNumber(V("frac")));
                alloc.Running = limit;
                return new D { ["type"] = "budget_alloc", ["limit"] = new Num(JsJson.NumberToString(limit)) };
            }
            default: throw new ArgumentException("unknown caveat spec");
        }
    }

    /// <summary>Build a signed, legally-attenuating chain from the model: the root is minted by the principal, each hop is signed by the key the
    /// parent is bound to and only appends caveats. Ed25519 signatures are deterministic, so the chain is reproducible from the seeds.</summary>
    public static GeneratedChain BuildChain(ChainModel m)
    {
        var alloc = new Alloc();
        using var principal = EdKey.FromSeed(m.PrincipalSeed);
        var keys = new List<EdKey>();
        try
        {
            var holder0 = EdKey.FromSeed(m.Holder0Seed);
            keys.Add(holder0);
            var rootCaveats = new L(m.RootSpecs.Select(s => (object?)SpecToCaveat(s, alloc)));
            using var principalSuite = SuiteKey.Ed25519(principal);
            var root = Issue.MintRoot(principalSuite, holder0.Id, null, rootCaveats);

            var caps = new List<D> { root };
            var holders = new List<string> { holder0.Id };
            var prev = root;
            var signer = holder0;
            foreach (var hop in m.Hops)
            {
                var to = EdKey.FromSeed(hop.HolderSeed);
                keys.Add(to);
                var added = new L(hop.AddedSpecs.Select(s => (object?)SpecToCaveat(s, alloc)));
                using var signerSuite = SuiteKey.Ed25519(signer);
                var cap = Issue.Delegate(prev, to.Id, added, signerSuite);
                caps.Add(cap);
                holders.Add(to.Id);
                prev = cap;
                signer = to;
            }
            return new GeneratedChain(caps, m.Predicates, principal.Id, holders);
        }
        finally { foreach (var k in keys) k.Dispose(); }
    }

    static double Clamp01(double x) => x < 0 ? 0 : x > 1 ? 1 : x;

    /// <summary>A risk input that is at least <paramref name="b"/> on every risk-increasing axis and at most on every protective axis.</summary>
    public static RiskAxes Worsen(RiskAxes b, RiskDeltas d) => new(
        Clamp01(b.SemanticDistance + d.DSem), Clamp01(b.BlastRadius + d.DBlast), Clamp01(b.Taint + d.DTaint),
        Clamp01(b.Age + d.DAge), Clamp01(b.Reversibility - d.DRev), Clamp01(b.Confidence - d.DConf));
}
