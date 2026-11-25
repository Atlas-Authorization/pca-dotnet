// Mechanism 1 of the capability ratchet (packages/pca-ratchet ratchet.ts): puncturable forward-secure capability keys. A holder commits to a
// Merkle root over 2^depth one-time Ed25519 leaf keys (a GGM tree, see Ggm). Signing at leaf i yields an offline-verifiable signature AND a new
// state in which leaf i is PUNCTURED: its key material is dropped and can never be re-derived, so the same leaf can never sign twice.
using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ratchet;

/// <summary>A refusal of the ratchet; <see cref="Code"/> is one of invalid_depth, invalid_seed, leaf_out_of_range, leaf_punctured.</summary>
public sealed class RatchetError(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>The live ratchet. The leaf public keys are public (needed to build Merkle proofs); <see cref="Covering"/> is the SECRET co-path:
/// disjoint GGM seeds whose subtrees are exactly the leaves that can still sign.</summary>
public sealed class RatchetState(int depth, long leafCount, string rootCommitment, IReadOnlyList<string> leafPubKeys, IReadOnlyDictionary<string, CoverNode> covering)
{
    public int Depth { get; } = depth;
    public long LeafCount { get; } = leafCount;
    public string RootCommitment { get; } = rootCommitment;
    public IReadOnlyList<string> LeafPubKeys { get; } = leafPubKeys;
    public IReadOnlyDictionary<string, CoverNode> Covering { get; } = covering;
}

public static class CapabilityRatchet
{
    static readonly byte[] NullifierDomain = RatchetGroup.Utf8("atlas-pca-ratchet/nullifier/v1\0");
    static readonly byte[] SigDomain = RatchetGroup.Utf8("atlas-pca-ratchet/leaf-sig/v1\0");
    static readonly BigInteger Two64 = BigInteger.One << 64;

    // ---- JavaScript BigInt(value) semantics for the leaf index ----
    static BigInteger ToBigInt(object? v)
    {
        switch (v)
        {
            case bool b: return b ? BigInteger.One : BigInteger.Zero;
            case BigInteger bi: return bi;
            case string s: return StringToBigInt(s);
        }
        if (IntentJs.NumOf(v) is double x)
        {
            if (!double.IsFinite(x) || Math.Floor(x) != x) throw new ArgumentOutOfRangeException(nameof(v), $"The number {x.ToString(CultureInfo.InvariantCulture)} cannot be converted to a BigInt because it is not an integer");
            return new BigInteger(x);
        }
        throw new InvalidCastException("Cannot convert the value to a BigInt");
    }

    static BigInteger StringToBigInt(string raw)
    {
        var s = raw.Trim();
        if (s.Length == 0) return BigInteger.Zero;
        if (Regex.IsMatch(s, @"\A[+-]?[0-9]+\z", RegexOptions.CultureInvariant)) return BigInteger.Parse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        var m = Regex.Match(s, @"\A0([xXoObB])([0-9a-fA-F]+)\z", RegexOptions.CultureInvariant);
        if (m.Success)
        {
            int radix = char.ToLowerInvariant(m.Groups[1].Value[0]) switch { 'x' => 16, 'o' => 8, _ => 2 };
            var acc = BigInteger.Zero;
            foreach (var ch in m.Groups[2].Value)
            {
                int dv = Convert.ToInt32(ch.ToString(), 16);
                if (dv >= radix) throw new FormatException("Cannot convert " + raw + " to a BigInt");
                acc = acc * radix + dv;
            }
            return acc;
        }
        throw new FormatException("Cannot convert " + raw + " to a BigInt");
    }

    /// <summary>The per-leaf nullifier a verifier records to detect leaf reuse: <c>b64u(sha256(domain || lp(root) || index))</c>. The index follows
    /// JavaScript BigInt semantics (an integer-valued number, a numeric string or a boolean; anything else throws) and is taken mod 2^64.</summary>
    public static string LeafNullifier(string rootCommitment, object? leafIndex)
    {
        var root = RatchetGroup.Utf8(rootCommitment);
        var idx = ((ToBigInt(leafIndex) % Two64) + Two64) % Two64;
        var o = new byte[NullifierDomain.Length + 4 + root.Length + 8];
        NullifierDomain.CopyTo(o, 0);
        BinaryPrimitives.WriteUInt32BigEndian(o.AsSpan(NullifierDomain.Length), (uint)root.Length);
        root.CopyTo(o, NullifierDomain.Length + 4);
        BinaryPrimitives.WriteUInt64BigEndian(o.AsSpan(NullifierDomain.Length + 4 + root.Length), (ulong)idx);
        return Pca.B64u(Pca.Sha(o));
    }

    public static string LeafNullifier(string rootCommitment, long leafIndex) => LeafNullifier(rootCommitment, (object)new BigInteger(leafIndex));

    /// <summary>The domain-separated signed message: binds the leaf index so a signature cannot be lifted to another leaf.</summary>
    static byte[] LeafSigMessage(long leafIndex, byte[] message)
    {
        var o = new byte[SigDomain.Length + 8 + message.Length];
        SigDomain.CopyTo(o, 0);
        BinaryPrimitives.WriteInt64BigEndian(o.AsSpan(SigDomain.Length), leafIndex);
        message.CopyTo(o, SigDomain.Length + 8);
        return o;
    }

    static bool IsIntegerNumber(object? v, out double x)
    {
        x = 0;
        if (IntentJs.NumOf(v) is double d && double.IsFinite(d) && Math.Floor(d) == d) { x = d; return true; }
        return false;
    }

    /// <summary>Build a ratchet from a root seed (a byte array of at least 32 bytes) and the tree depth (an integer in [1, 20]). Returns the public
    /// root commitment (a Merkle root over all 2^depth leaf public keys) and the live state.</summary>
    public static (string RootCommitment, RatchetState State) DeriveRatchetRoot(object? seed, object? depth)
    {
        if (!IsIntegerNumber(depth, out var dd) || dd < 1 || dd > Ggm.MaxRatchetDepth)
            throw new RatchetError("invalid_depth", $"depth must be an integer in [1, {Ggm.MaxRatchetDepth}]");
        if (seed is not byte[] { Length: >= 32 } sd)
            throw new RatchetError("invalid_seed", "seed must be a Uint8Array of at least 32 bytes");
        int d = (int)dd;
        var root = Ggm.RootSeed(sd);
        var leafPubKeys = Ggm.AllLeafPublicKeys(root, d);
        var rootCommitment = Pca.MerkleRoot(leafPubKeys.Select(k => (object?)k).ToList());
        var covering = new Dictionary<string, CoverNode> { [Ggm.CoverKey(0, 0)] = new CoverNode(0, 0, root) };
        return (rootCommitment, new RatchetState(d, 1L << d, rootCommitment, leafPubKeys, covering));
    }

    /// <summary>The (unique) covering node whose subtree contains the leaf, or null when it is punctured.</summary>
    static CoverNode? FindCovering(RatchetState state, double leafIndex)
    {
        foreach (var node in state.Covering.Values)
            if (Ggm.Covers(node.Level, node.NodeIndex, leafIndex, state.Depth)) return node;
        return null;
    }

    // ---- RFC 6962 inclusion proof over the leaf public keys (JSON proof shape {index, size, path:[{side, hash}]}) ----
    static void Prove(List<byte[]> hs, long idx, JL path)
    {
        if (hs.Count == 1) return;
        int k = (int)Pca.Split(hs.Count);
        if (idx < k)
        {
            Prove(hs.GetRange(0, k), idx, path);
            path.Add(new JD { ["side"] = "R", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(k, hs.Count - k))) });
        }
        else
        {
            Prove(hs.GetRange(k, hs.Count - k), idx - k, path);
            path.Add(new JD { ["side"] = "L", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(0, k))) });
        }
    }

    static JD MerkleProof(IReadOnlyList<string> leaves, long index)
    {
        var path = new JL();
        Prove(leaves.Select(l => Pca.LeafHash(l)).ToList(), index, path);
        return new JD { ["index"] = new Num(index.ToString(CultureInfo.InvariantCulture)), ["size"] = new Num(leaves.Count.ToString(CultureInfo.InvariantCulture)), ["path"] = path };
    }

    /// <summary>Sign <paramref name="message"/> at the leaf, then puncture it. Returns the signature (<c>{edSig, leafPubKey, merklePath, nullifier}</c>) and a
    /// new state with the leaf's key permanently dropped. Throws <see cref="RatchetError"/> when the leaf is out of range or already punctured.</summary>
    public static (JD Signature, RatchetState NewState) SignAtLeaf(RatchetState state, object? leafIndex, byte[] message)
    {
        if (!IsIntegerNumber(leafIndex, out var x) || x < 0 || x >= state.LeafCount)
            throw new RatchetError("leaf_out_of_range", $"leaf {(IntentJs.NumOf(leafIndex) is double v ? v.ToString(CultureInfo.InvariantCulture) : "?")} is out of range [0, {state.LeafCount})");
        var leaf = (long)x;
        var node = FindCovering(state, leaf) ?? throw new RatchetError("leaf_punctured", $"leaf {leaf} is already punctured (spent) and cannot sign");
        var leafSeed = Ggm.DeriveLeafSeed(node, leaf, state.Depth);
        string edSig, leafPubKey;
        using (var key = EdKey.FromSeed(Ggm.LeafSigningSeed(leafSeed)))
        {
            edSig = Pca.B64u(key.Sign(LeafSigMessage(leaf, message)));
            leafPubKey = Pca.B64u(key.Pub);
        }
        var merklePath = MerkleProof(state.LeafPubKeys, leaf);
        if (IntentJs.NumOf(leafIndex) is double lz && IntentJs.IsNegZero(lz)) merklePath["index"] = new Num("-0"); // the proof's index is the leaf as supplied, its sign of zero included

        // Puncture: replace the covering node with its off-path siblings; the on-path (and leaf) seeds vanish.
        var covering = new Dictionary<string, CoverNode>(state.Covering);
        covering.Remove(Ggm.CoverKey(node.Level, node.NodeIndex));
        foreach (var sib in Ggm.PunctureSiblings(node, leaf, state.Depth)) covering[Ggm.CoverKey(sib.Level, sib.NodeIndex)] = sib;

        var sig = new JD { ["edSig"] = edSig, ["leafPubKey"] = leafPubKey, ["merklePath"] = merklePath, ["nullifier"] = LeafNullifier(state.RootCommitment, leaf) };
        return (sig, new RatchetState(state.Depth, state.LeafCount, state.RootCommitment, state.LeafPubKeys, covering));
    }

    /// <summary>Verify a ratchet signature offline against the root commitment, with no shared state: the Ed25519 signature must be valid under the
    /// leaf public key and the Merkle path must prove that key is the leaf at the index under the root. Never throws; malformed input is false.</summary>
    public static bool VerifyLeafSignature(string rootCommitment, object? leafIndex, byte[] message, object? signature)
    {
        try
        {
            if (signature is not JD sig) return false;
            if (sig.GetValueOrDefault("nullifier") is not string nullifier || nullifier != LeafNullifier(rootCommitment, leafIndex)) return false;
            if (sig.GetValueOrDefault("edSig") is not string edSig || sig.GetValueOrDefault("leafPubKey") is not string leafPubKey || sig.GetValueOrDefault("merklePath") is not JD merklePath) return false;
            if (IntentJs.NumOf(merklePath.GetValueOrDefault("index")) is not double a || IntentJs.NumOf(leafIndex) is not double b || a != b) return false;
            if (!(Math.Abs(b) < 9e18)) return false; // no valid proof indexes past a safe integer
            if (!Pca.VerifyEdInternal(leafPubKey, LeafSigMessage((long)b, message), edSig)) return false;
            // a self-describing hash suite other than the default sha256 is refused: the root commitment is a sha256 tree
            if (merklePath.TryGetValue("hash_suite", out var suite) && suite is not "sha256") return false;
            return Pca.VerifyInclusion(rootCommitment, merklePath, leafPubKey);
        }
        catch { return false; }
    }

    /// <summary>Indices of the leaves that can still sign (not yet punctured), ascending.</summary>
    public static List<long> AvailableLeaves(RatchetState state)
    {
        var o = new List<long>();
        foreach (var node in state.Covering.Values)
        {
            long span = 1L << (state.Depth - node.Level);
            long b = node.NodeIndex * span;
            for (long i = 0; i < span; i++) o.Add(b + i);
        }
        o.Sort();
        return o;
    }

    /// <summary>Whether the leaf can still sign. JavaScript number semantics, like the reference: a fractional index counts as its floor.</summary>
    public static bool IsLeafAvailable(RatchetState state, double leafIndex) => FindCovering(state, leafIndex) != null;
}
