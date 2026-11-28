// Mechanism 2 of the capability ratchet (packages/pca-ratchet accumulator.ts): a homomorphic risk accumulator. Risk is carried as a Pedersen
// commitment on ristretto255, C = risk*G + blinding*H; commitments add homomorphically, and a bit-decomposition range proof (a Fiat-Shamir OR
// proof per bit plus a Schnorr proof that the bit commitments aggregate to the slack commitment) shows the aggregate stays under the budget
// ceiling without revealing the individual risks. A proof is a JSON tree {n, bitCommitments, or, agg}, exactly the wire shape.
using System.Globalization;
using System.Numerics;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;
using G = AtlasPca.Ratchet.RatchetGroup;

namespace AtlasPca.Ratchet;

/// <summary>A refusal of the accumulator; <see cref="Code"/> is one of invalid_value, length_mismatch, invalid_proof_shape.</summary>
public sealed class AccumulatorError(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>A risk commitment (<c>b64u</c> point) and the blinding scalar needed to open it or to build a budget proof.</summary>
public sealed record RiskCommitment(string Commitment, BigInteger Blinding);

public static class RiskAccumulator
{
    /// <summary>Range-proof bit length: the slack (ceiling minus the sum) must lie in [0, 2^32).</summary>
    public const int NBits = 32;

    /// <summary>Largest ceiling the range proof can express.</summary>
    public static readonly BigInteger MaxProvableCeiling = (BigInteger.One << NBits) - 1;

    static readonly byte[] CtxDomain = G.Utf8("atlas-pca-ratchet/budget/ctx/v1");
    static readonly byte[] RiskCtxDomain = G.Utf8("atlas-pca-ratchet/risk-range/ctx/v1");
    static readonly byte[] OrDomain = G.Utf8("atlas-pca-ratchet/budget/bit-or/v1");
    static readonly byte[] AggDomain = G.Utf8("atlas-pca-ratchet/budget/agg/v1");

    /// <summary>A risk or budget amount: a bigint (>= 0) or an integer-valued JavaScript number (>= 0, -0 is 0). Anything else is refused.</summary>
    internal static BigInteger AsUnits(object? x)
    {
        if (x is BigInteger b)
        {
            if (b.Sign < 0) throw new AccumulatorError("invalid_value", "risk/budget must be >= 0");
            return b;
        }
        if (IntentJs.NumOf(x) is double d && double.IsFinite(d) && Math.Floor(d) == d && !(d < 0)) return new BigInteger(d);
        throw new AccumulatorError("invalid_value", "risk/budget must be a non-negative integer");
    }

    /// <summary>Commit to a non-negative integer <paramref name="risk"/> in units, with a given or fresh random blinding.</summary>
    public static RiskCommitment CommitRisk(object? risk, BigInteger? blinding = null)
    {
        var v = AsUnits(risk);
        var b = blinding is null ? G.RandScalar() : G.Mod(blinding.Value);
        var c = G.Add(G.Mul(G.G, v), G.Mul(G.H, b));
        return new RiskCommitment(G.EncodePoint(c), b);
    }

    /// <summary>Homomorphic sum: a commitment to (sum of risks, sum of blindings). The empty list is the identity. Throws on a malformed commitment.</summary>
    public static string AddCommitments(object? commitments)
    {
        var acc = G.Mul(G.G, BigInteger.Zero); // identity
        if (commitments is string s)
        {
            // a string iterates by character; a one-character string is never a 32-byte point
            if (s.Length > 0) G.DecodePoint(s[..1]);
        }
        else if (commitments is IEnumerable<object?> list)
        {
            foreach (var c in list) acc = G.Add(acc, G.DecodePoint(c));
        }
        else throw new InvalidCastException("commitments is not iterable");
        return G.EncodePoint(acc);
    }

    /// <summary>Check that the commitment opens to (risk, blinding). Never throws; malformed input is false.</summary>
    public static bool OpenCommitment(object? commitment, object? risk, object? blinding)
    {
        try
        {
            var v = AsUnits(risk);
            if (blinding is not BigInteger bb) return false;
            var expected = G.Add(G.Mul(G.G, v), G.Mul(G.H, G.Mod(bb)));
            return G.DecodePoint(commitment).Equals(expected);
        }
        catch { return false; }
    }

    // ---- range proof ----

    /// <summary>The ceiling actually proven: one above 2^32 - 1 is clamped to it ("sum &lt;= 2^32 - 1" is stronger than "sum &lt;= bMax", so a verifier
    /// is never weakened and an honest prover whose total fits is never refused).</summary>
    static BigInteger EffectiveCeiling(BigInteger u) => u > MaxProvableCeiling ? MaxProvableCeiling : u;

    static byte[] ContextHash(int n, BigInteger bMaxUnits, RistrettoPoint commitmentSum, IReadOnlyList<RistrettoPoint> bits)
    {
        var parts = new List<byte[]> { CtxDomain, new[] { (byte)(n & 0xff) }, G.NumberToBytesLe(G.Mod(bMaxUnits), 32), commitmentSum.Encode() };
        foreach (var b in bits) parts.Add(b.Encode());
        return G.NumberToBytesLe(G.HashToScalar(parts), 32);
    }

    static byte[] RiskContextHash(int n, RistrettoPoint commitment, IReadOnlyList<RistrettoPoint> bits)
    {
        var parts = new List<byte[]> { RiskCtxDomain, new[] { (byte)(n & 0xff) }, commitment.Encode() };
        foreach (var b in bits) parts.Add(b.Encode());
        return G.NumberToBytesLe(G.HashToScalar(parts), 32);
    }

    static JD ProveBit(byte[] ctx, int index, RistrettoPoint bc, BigInteger b, BigInteger s)
    {
        var p0 = bc;
        var p1 = G.Sub(bc, G.G);
        int real = b.IsOne ? 1 : 0;

        // simulate the false branch with a random challenge/response
        var eFake = G.RandScalar();
        var zFake = G.RandScalar();
        var pFake = real == 1 ? p0 : p1;
        var aFake = G.Sub(G.Mul(G.H, zFake), G.Mul(pFake, eFake));

        // real branch: honest Schnorr commitment on H
        var k = G.RandScalar();
        var aReal = G.Mul(G.H, k);

        var a0 = real == 0 ? aReal : aFake;
        var a1 = real == 1 ? aReal : aFake;
        var e = G.HashToScalar(new List<byte[]> { OrDomain, ctx, new[] { (byte)(index & 0xff) }, a0.Encode(), a1.Encode() });
        var eReal = G.ScalarSub(e, eFake);
        var zReal = G.ScalarAdd(k, G.ScalarMul(eReal, s));

        var e0 = real == 0 ? eReal : eFake;
        var e1 = real == 1 ? eReal : eFake;
        var z0 = real == 0 ? zReal : zFake;
        var z1 = real == 1 ? zReal : zFake;
        return new JD { ["e0"] = G.EncodeScalar(e0), ["e1"] = G.EncodeScalar(e1), ["z0"] = G.EncodeScalar(z0), ["z1"] = G.EncodeScalar(z1) };
    }

    static bool VerifyBit(byte[] ctx, int index, RistrettoPoint bc, object? proof)
    {
        var e0 = G.DecodeScalar(IntentJs.Get(proof, "e0"));
        var e1 = G.DecodeScalar(IntentJs.Get(proof, "e1"));
        var z0 = G.DecodeScalar(IntentJs.Get(proof, "z0"));
        var z1 = G.DecodeScalar(IntentJs.Get(proof, "z1"));
        var p0 = bc;
        var p1 = G.Sub(bc, G.G);
        var a0 = G.Sub(G.Mul(G.H, z0), G.Mul(p0, e0));
        var a1 = G.Sub(G.Mul(G.H, z1), G.Mul(p1, e1));
        var e = G.HashToScalar(new List<byte[]> { OrDomain, ctx, new[] { (byte)(index & 0xff) }, a0.Encode(), a1.Encode() });
        return G.ScalarAdd(e0, e1) == e;
    }

    static JD ProveSchnorr(byte[] ctx, RistrettoPoint d, BigInteger w)
    {
        var k = G.RandScalar();
        var a = G.Mul(G.H, k);
        var e = G.HashToScalar(new List<byte[]> { AggDomain, ctx, d.Encode(), a.Encode() });
        var z = G.ScalarAdd(k, G.ScalarMul(e, w));
        return new JD { ["a"] = G.EncodePoint(a), ["z"] = G.EncodeScalar(z) };
    }

    static bool VerifySchnorr(byte[] ctx, RistrettoPoint d, object? proof)
    {
        var a = G.DecodePoint(IntentJs.Get(proof, "a"));
        var z = G.DecodeScalar(IntentJs.Get(proof, "z"));
        var e = G.HashToScalar(new List<byte[]> { AggDomain, ctx, d.Encode(), a.Encode() });
        return G.Mul(G.H, z).Equals(G.Add(a, G.Mul(d, e)));
    }

    /// <summary>Shared range-proof core: proves that V = value*G + gamma*H commits to a value in [0, 2^32). The value is taken modulo 2^32: an
    /// out-of-range value yields a well-formed proof that the verifier rejects.</summary>
    static JD RangeProve(Func<IReadOnlyList<RistrettoPoint>, byte[]> makeCtx, RistrettoPoint v, BigInteger value, BigInteger gamma)
    {
        var vMasked = value & MaxProvableCeiling; // low 32 bits (the two's-complement low bits even when the value is negative)
        var bitCommitments = new List<RistrettoPoint>();
        var bitBlindings = new List<BigInteger>();
        var bits = new List<BigInteger>();
        for (int i = 0; i < NBits; i++)
        {
            var bit = (vMasked >> i) & BigInteger.One;
            var s = G.RandScalar();
            bits.Add(bit);
            bitBlindings.Add(s);
            bitCommitments.Add(G.Add(G.Mul(G.G, bit), G.Mul(G.H, s)));
        }
        var ctx = makeCtx(bitCommitments);

        var orProofs = new JL();
        for (int i = 0; i < NBits; i++) orProofs.Add(ProveBit(ctx, i, bitCommitments[i], bits[i], bitBlindings[i]));

        // sum 2^i B_i = v' G + sStar H; with v' = value, D = sum - V = (sStar - gamma) H, a pure H-multiple whose dlog the prover knows
        var sStar = BigInteger.Zero;
        var aggPoint = G.Mul(G.G, BigInteger.Zero);
        for (int i = 0; i < NBits; i++)
        {
            var w = BigInteger.One << i;
            sStar = G.ScalarAdd(sStar, G.ScalarMul(w, bitBlindings[i]));
            aggPoint = G.Add(aggPoint, G.Mul(bitCommitments[i], w));
        }
        var d = G.Sub(aggPoint, v);
        var agg = ProveSchnorr(ctx, d, G.ScalarSub(sStar, gamma));
        return new JD
        {
            ["n"] = new Num(NBits.ToString(CultureInfo.InvariantCulture)),
            ["bitCommitments"] = new JL(bitCommitments.Select(p => (object?)G.EncodePoint(p))),
            ["or"] = orProofs,
            ["agg"] = agg,
        };
    }

    static bool RangeVerify(Func<IReadOnlyList<RistrettoPoint>, byte[]> makeCtx, RistrettoPoint v, object? proof)
    {
        if (proof is not JD p) return false;
        if (IntentJs.NumOf(p.GetValueOrDefault("n")) is not double n || n != NBits) return false;
        if (p.GetValueOrDefault("bitCommitments") is not JL bitCommitments || p.GetValueOrDefault("or") is not JL orProofs) return false;
        if (bitCommitments.Count != NBits || orProofs.Count != NBits) return false;
        if (p.GetValueOrDefault("agg") is not JD agg) return false;

        var b = bitCommitments.Select(c => G.DecodePoint(c)).ToList();
        var ctx = makeCtx(b);
        for (int i = 0; i < NBits; i++)
            if (!VerifyBit(ctx, i, b[i], orProofs[i])) return false;
        var aggPoint = G.Mul(G.G, BigInteger.Zero);
        for (int i = 0; i < NBits; i++) aggPoint = G.Add(aggPoint, G.Mul(b[i], BigInteger.One << i));
        return VerifySchnorr(ctx, G.Sub(aggPoint, v), agg);
    }

    static BigInteger Blinding(object? b) => b switch
    {
        null => BigInteger.Zero,
        BigInteger x => x,
        _ => throw new ArgumentException("a blinding must be a bigint"),
    };

    /// <summary>Prove that the committed aggregate satisfies sum(risk) &lt;= bMax in zero knowledge over the individual risks. An over-budget aggregate
    /// (or a slack that does not fit 32 bits) yields a well-formed proof the verifier rejects: soundness lives in verification. The proof is about the
    /// committed VALUE of the sum; pair it with <see cref="ProveRiskRange"/> / <see cref="VerifyBoundedBudget"/> so no addend is a "negative" risk.</summary>
    public static JD ProveBudget(IReadOnlyList<object?> risks, IReadOnlyList<object?> blindings, object? bMax)
    {
        if (risks.Count != blindings.Count) throw new AccumulatorError("length_mismatch", "risks and blindings must have equal length");
        var ceiling = EffectiveCeiling(AsUnits(bMax));
        var sumRisk = BigInteger.Zero;
        var sumBlind = BigInteger.Zero;
        for (int i = 0; i < risks.Count; i++)
        {
            sumRisk += AsUnits(risks[i] ?? BigInteger.Zero);
            sumBlind = G.ScalarAdd(sumBlind, Blinding(blindings[i]));
        }
        var cSum = G.Add(G.Mul(G.G, G.Mod(sumRisk)), G.Mul(G.H, sumBlind));
        var v = G.Sub(G.Mul(G.G, G.Mod(ceiling)), cSum);
        var slack = ceiling - sumRisk; // negative when over budget
        return RangeProve(bits => ContextHash(NBits, ceiling, cSum, bits), v, slack, G.Mod(-sumBlind));
    }

    /// <summary>Verify a budget proof against the commitment sum and ceiling: every bit commitment opens to 0/1 and they aggregate to the slack
    /// commitment ceiling*G - commitmentSum. Never throws; scalars and points must be canonical; ceilings above 2^32 - 1 are clamped.</summary>
    public static bool VerifyBudget(object? commitmentSum, object? bMax, object? proof)
    {
        try
        {
            var ceiling = EffectiveCeiling(AsUnits(bMax));
            var cSum = G.DecodePoint(commitmentSum);
            var v = G.Sub(G.Mul(G.G, G.Mod(ceiling)), cSum);
            return RangeVerify(bits => ContextHash(NBits, ceiling, cSum, bits), v, proof);
        }
        catch { return false; }
    }

    /// <summary>Prove that <c>CommitRisk(risk, blinding)</c> holds a value in [0, 2^32): each action's commitment needs one, because the budget proof
    /// alone only constrains the SUM.</summary>
    public static JD ProveRiskRange(object? risk, object? blinding)
    {
        var v = AsUnits(risk);
        var b = G.Mod(Blinding(blinding ?? throw new ArgumentException("a blinding must be a bigint")));
        var c = G.Add(G.Mul(G.G, G.Mod(v)), G.Mul(G.H, b));
        return RangeProve(bits => RiskContextHash(NBits, c, bits), c, v, b);
    }

    /// <summary>Verify <see cref="ProveRiskRange"/> for the commitment. Never throws; malformed input is false.</summary>
    public static bool VerifyRiskRange(object? commitment, object? proof)
    {
        try
        {
            var c = G.DecodePoint(commitment);
            return RangeVerify(bits => RiskContextHash(NBits, c, bits), c, proof);
        }
        catch { return false; }
    }

    /// <summary>The sound end-to-end check for a budget over per-action commitments: every commitment carries a valid range proof and the budget proof
    /// verifies for their homomorphic sum. Accepting implies the committed risks, as integers, sum to at most min(bMax, 2^32 - 1). Never throws.</summary>
    public static bool VerifyBoundedBudget(object? commitments, object? rangeProofs, object? bMax, object? budgetProof)
    {
        try
        {
            if (commitments is not JL cs || rangeProofs is not JL rps || cs.Count != rps.Count) return false;
            for (int i = 0; i < cs.Count; i++)
                if (!VerifyRiskRange(cs[i], rps[i])) return false;
            return VerifyBudget(AddCommitments(cs), bMax, budgetProof);
        }
        catch { return false; }
    }
}
