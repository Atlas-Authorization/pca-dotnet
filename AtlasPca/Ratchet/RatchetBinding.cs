// Verifier-side bindings the stateless primitives cannot give alone (packages/pca-ratchet binding.ts): (1) a spent-leaf store, so a SECOND
// signature at the same leaf is detected (replay) and a different message at the same leaf is flagged as equivocation, with both digests as
// evidence; (2) risk commitments created by the party that COMPUTES the risk (a risk authority) and signed with the action digest, so a prover
// cannot commit 0 for a 1.0-risk action or move a commitment between actions.
using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ratchet;

/// <summary>The result of an atomic first-claim: <c>First</c> on the first claim, else the record stored earlier.</summary>
public readonly record struct LeafClaim(bool First, string? Record);

/// <summary>Atomic first-claim store keyed by leaf nullifier.</summary>
public interface ISpentLeafStore
{
    Task<LeafClaim> ClaimAsync(string nullifier, string record);
}

/// <summary>In-process <see cref="ISpentLeafStore"/>. Per process: use a shared store for a verifier fleet.</summary>
public sealed class MemorySpentLeafStore : ISpentLeafStore
{
    readonly Dictionary<string, string> _seen = new();

    public Task<LeafClaim> ClaimAsync(string nullifier, string record)
    {
        lock (_seen)
        {
            if (_seen.TryGetValue(nullifier, out var prev)) return Task.FromResult(new LeafClaim(false, prev));
            _seen[nullifier] = record;
            return Task.FromResult(new LeafClaim(true, null));
        }
    }
}

/// <summary>The outcome of a one-time-use leaf verification: ok, or a reason of invalid, replay, equivocation or store-error.</summary>
public sealed record LeafUseResult(bool Ok, string? Reason = null, string? Nullifier = null, string? FirstMessageDigest = null, string? SecondMessageDigest = null)
{
    /// <summary>The reference's JSON shape.</summary>
    public JD ToJson()
    {
        if (Ok) return new JD { ["ok"] = true };
        var o = new JD { ["ok"] = false, ["reason"] = Reason };
        if (Nullifier != null) o["nullifier"] = Nullifier;
        if (FirstMessageDigest != null) { o["firstMessageDigest"] = FirstMessageDigest; o["secondMessageDigest"] = SecondMessageDigest; }
        return o;
    }
}

/// <summary>What a risk authority publishes for one action.</summary>
public sealed record IssuedRiskCommitment(string Commitment, BigInteger Blinding, JD RangeProof, JD Attestation);

public static class RatchetBinding
{
    static readonly byte[] AttestDomain = RatchetGroup.Utf8("atlas-pca-ratchet/risk-attestation/v1\0");

    static string MessageDigest(long leafIndex, byte[] message) => Pca.B64u(Pca.Sha(message)) + "@" + leafIndex.ToString(CultureInfo.InvariantCulture);

    /// <summary>Verify a leaf signature AND enforce one-time use at the verifier: the first valid signature at a leaf is accepted and its message digest
    /// recorded; any later one is refused as <c>replay</c> (same message) or <c>equivocation</c> (a different message: the evidence of a holder that kept
    /// an old state). Fail closed: a store that throws denies.</summary>
    public static async Task<LeafUseResult> VerifyLeafSignatureOnceAsync(string rootCommitment, object? leafIndex, byte[] message, object? signature, ISpentLeafStore store)
    {
        if (!CapabilityRatchet.VerifyLeafSignature(rootCommitment, leafIndex, message, signature)) return new LeafUseResult(false, "invalid");
        var nullifier = CapabilityRatchet.LeafNullifier(rootCommitment, leafIndex);
        var mine = MessageDigest((long)IntentJs.NumOf(leafIndex)!.Value, message);
        try
        {
            var r = await store.ClaimAsync(nullifier, mine).ConfigureAwait(false);
            if (r.First) return new LeafUseResult(true);
            if (r.Record == mine) return new LeafUseResult(false, "replay", nullifier);
            return new LeafUseResult(false, "equivocation", nullifier, r.Record, mine);
        }
        catch { return new LeafUseResult(false, "store-error"); }
    }

    static byte[] AttestMessage(string actionDigest, string commitment)
    {
        var a = RatchetGroup.Utf8(actionDigest);
        var c = RatchetGroup.Utf8(commitment);
        var o = new byte[AttestDomain.Length + 4 + a.Length + 4 + c.Length];
        AttestDomain.CopyTo(o, 0);
        int p = AttestDomain.Length;
        BinaryPrimitives.WriteUInt32BigEndian(o.AsSpan(p), (uint)a.Length);
        a.CopyTo(o, p + 4);
        p += 4 + a.Length;
        BinaryPrimitives.WriteUInt32BigEndian(o.AsSpan(p), (uint)c.Length);
        c.CopyTo(o, p + 4);
        return o;
    }

    /// <summary>RISK AUTHORITY side: commit to the risk it computed for the action, prove the range, and sign (actionDigest, commitment) with its 32-byte
    /// Ed25519 secret key. Hand the blinding privately to the prover (the budget proof needs it); publish the commitment, range proof and attestation.</summary>
    public static IssuedRiskCommitment IssueRiskCommitment(object? risk, string actionDigest, byte[] authoritySecretKey)
    {
        var cr = RiskAccumulator.CommitRisk(risk);
        var rangeProof = RiskAccumulator.ProveRiskRange(risk, cr.Blinding);
        using var key = EdKey.FromSeed(authoritySecretKey);
        var sig = Pca.B64u(key.Sign(AttestMessage(actionDigest, cr.Commitment)));
        return new IssuedRiskCommitment(cr.Commitment, cr.Blinding, rangeProof, new JD { ["actionDigest"] = actionDigest, ["sig"] = sig });
    }

    /// <summary>Verify one attestation against the risk authority's b64u public key. Never throws. A commitment that is not a string is refused (the
    /// reference would sign over its text coercion; no honest authority signs a non-point).</summary>
    public static bool VerifyRiskAttestation(object? commitment, object? attestation, object? authorityPublicKey)
    {
        try
        {
            if (attestation is not JD a) return false;
            if (a.GetValueOrDefault("actionDigest") is not string digest || a.GetValueOrDefault("sig") is not string sig) return false;
            if (commitment is not string c) return false;
            return Pca.VerifyEdInternal(authorityPublicKey, AttestMessage(digest, c), sig);
        }
        catch { return false; }
    }

    /// <summary>Sound end-to-end budget check over ATTESTED commitments. For the verifier's own list of action digests (in order) every item must carry a
    /// valid authority attestation for exactly that digest and commitment, then <see cref="RiskAccumulator.VerifyBoundedBudget"/> must hold. Never throws.</summary>
    public static bool VerifyAttestedBudget(object? items, object? expectedActionDigests, object? authorityPublicKey, object? bMax, object? budgetProof)
    {
        try
        {
            if (items is not JL its || expectedActionDigests is not JL digests || its.Count != digests.Count) return false;
            for (int i = 0; i < its.Count; i++)
            {
                if (its[i] is not JD it) return false;
                var att = IntentJs.Get(it, "attestation");
                if (IntentJs.Get(att, "actionDigest") is not string ad || digests[i] is not string want || ad != want) return false;
                if (!VerifyRiskAttestation(IntentJs.Get(it, "commitment"), att, authorityPublicKey)) return false;
            }
            var cs = new JL(its.Select(x => IntentJs.Get(x, "commitment")));
            var rps = new JL(its.Select(x => IntentJs.Get(x, "rangeProof")));
            return RiskAccumulator.VerifyBoundedBudget(cs, rps, bMax, budgetProof);
        }
        catch { return false; }
    }
}
