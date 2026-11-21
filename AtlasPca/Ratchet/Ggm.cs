// GGM binary-tree puncturable PRF (packages/pca-ratchet ggm.ts): a depth-d complete binary tree whose nodes derive their two children with
// a length-doubling PRG built from HMAC-SHA256. The secret state is a co-path of disjoint covering node seeds; puncturing a leaf expands the
// covering node down to it, keeps every off-path sibling and drops every on-path seed, which the one-way PRG makes irreversible.
using System.Security.Cryptography;

namespace AtlasPca.Ratchet;

/// <summary>A covering node of the live ratchet: its distance from the root, its index within that level and its secret GGM seed.</summary>
public sealed record CoverNode(int Level, long NodeIndex, byte[] Seed);

public static class Ggm
{
    static readonly byte[] PrgDomain = RatchetGroup.Utf8("atlas-pca-ratchet/ggm-prg/v1");
    static readonly byte[] LeafKeyDomain = RatchetGroup.Utf8("atlas-pca-ratchet/ggm-leafkey/v1");
    static readonly byte[] RootDomain = RatchetGroup.Utf8("atlas-pca-ratchet/ggm-root/v1");

    /// <summary>Longest tree accepted. Setup derives all 2^depth leaf public keys, so this bounds that cost.</summary>
    public const int MaxRatchetDepth = 20;

    static byte[] Prg(byte[] seed, byte bit)
    {
        var m = new byte[PrgDomain.Length + 1];
        PrgDomain.CopyTo(m, 0);
        m[PrgDomain.Length] = bit;
        return HMACSHA256.HashData(seed, m);
    }

    static byte[] PrgLeft(byte[] seed) => Prg(seed, 0x00);
    static byte[] PrgRight(byte[] seed) => Prg(seed, 0x01);

    /// <summary>The GGM root seed, normalized and domain-separated from caller-supplied entropy.</summary>
    public static byte[] RootSeed(byte[] seed) => HMACSHA256.HashData(seed, RootDomain);

    /// <summary>The 32-byte Ed25519 signing seed of a leaf, derived from that leaf's GGM seed.</summary>
    public static byte[] LeafSigningSeed(byte[] leafSeed) => HMACSHA256.HashData(leafSeed, LeafKeyDomain);

    /// <summary>The b64u Ed25519 public key of a leaf's GGM seed.</summary>
    public static string LeafPublicKey(byte[] leafSeed)
    {
        using var k = EdKey.FromSeed(LeafSigningSeed(leafSeed));
        return Pca.B64u(k.Pub);
    }

    /// <summary>Does the subtree of node (level, nodeIndex) contain <paramref name="leafIndex"/>? JavaScript number semantics: a fractional index
    /// belongs to the subtree of its floor, a negative one to none.</summary>
    public static bool Covers(int level, long nodeIndex, double leafIndex, int depth) =>
        Math.Floor(leafIndex / Math.Pow(2, depth - level)) == nodeIndex;

    /// <summary>The bit chosen when descending from <paramref name="level"/> towards the leaf (0 = left, 1 = right).</summary>
    static int DescendBit(int level, long leafIndex, int depth) => (int)((leafIndex >> (depth - level - 1)) & 1);

    /// <summary>Derive the leaf GGM seed for <paramref name="leafIndex"/> from a covering node that contains it.</summary>
    public static byte[] DeriveLeafSeed(CoverNode node, long leafIndex, int depth)
    {
        var seed = node.Seed;
        for (int level = node.Level; level < depth; level++)
            seed = DescendBit(level, leafIndex, depth) == 0 ? PrgLeft(seed) : PrgRight(seed);
        return seed;
    }

    /// <summary>Puncture the leaf out of the node's subtree: the off-path sibling covering nodes that together cover every leaf under the node
    /// EXCEPT the leaf. The on-path seeds (and the leaf seed itself) are never returned.</summary>
    public static List<CoverNode> PunctureSiblings(CoverNode node, long leafIndex, int depth)
    {
        var o = new List<CoverNode>();
        var seed = node.Seed;
        long nodeIndex = node.NodeIndex;
        for (int level = node.Level; level < depth; level++)
        {
            int bit = DescendBit(level, leafIndex, depth);
            var left = PrgLeft(seed);
            var right = PrgRight(seed);
            long childBase = nodeIndex * 2;
            o.Add(new CoverNode(level + 1, childBase + (1 - bit), bit == 0 ? right : left));
            seed = bit == 0 ? left : right;
            nodeIndex = childBase + bit;
        }
        return o;
    }

    /// <summary>Derive every leaf's public key from the root seed (used once, at setup, for the commitment).</summary>
    public static string[] AllLeafPublicKeys(byte[] root, int depth)
    {
        var o = new string[1 << depth];
        void Recurse(byte[] seed, int level, int b)
        {
            if (level == depth) { o[b] = LeafPublicKey(seed); return; }
            int half = 1 << (depth - level - 1);
            Recurse(PrgLeft(seed), level + 1, b);
            Recurse(PrgRight(seed), level + 1, b + half);
        }
        Recurse(root, 0, 0);
        return o;
    }

    public static string CoverKey(int level, long nodeIndex) => $"{level}:{nodeIndex}";
}
