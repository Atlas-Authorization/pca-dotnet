// RFC 9162 section 2.1 Merkle tree (SHA-256): tree hash, inclusion paths and consistency proofs, with the verification algorithms of
// sections 2.1.3.2 and 2.1.4.2. Leaf inputs are the raw entry bytes (SHA-256(0x00 || entry)), so any independent RFC 9162 / RFC 6962
// verifier can check a proof given the same entry bytes.
using System.Security.Cryptography;

namespace AtlasPca.Scitt;

public static class Rfc9162
{
    const long MaxSafe = 9007199254740991L;

    static byte[] Sha(byte prefix, params byte[][] parts)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (prefix != 0xff) h.AppendData(new[] { prefix });
        foreach (var p in parts) h.AppendData(p);
        return h.GetHashAndReset();
    }

    /// <summary>Root hash of the empty tree: SHA-256 of the empty string.</summary>
    public static byte[] EmptyRoot() => Sha(0xff);

    /// <summary>SHA-256(0x00 || entry).</summary>
    public static byte[] LeafHash(byte[] entry) => Sha(0x00, entry);

    /// <summary>SHA-256(0x01 || left || right).</summary>
    public static byte[] NodeHash(byte[] left, byte[] right) => Sha(0x01, left, right);

    /// <summary>Largest power of two strictly less than n (n &gt;= 2).</summary>
    public static long SplitPoint(long n)
    {
        long k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    static bool Safe(long n) => n >= -MaxSafe && n <= MaxSafe;

    static bool Equal(byte[] a, byte[] b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>MTH over already-hashed leaves (RFC 9162 section 2.1.1).</summary>
    public static byte[] TreeHash(IReadOnlyList<byte[]> leafHashes) => Mth(leafHashes, 0, leafHashes.Count);

    static byte[] Mth(IReadOnlyList<byte[]> d, int lo, int n)
    {
        if (n == 0) return EmptyRoot();
        if (n == 1) return d[lo];
        int k = (int)SplitPoint(n);
        return NodeHash(Mth(d, lo, k), Mth(d, lo + k, n - k));
    }

    /// <summary>Inclusion path for leaf <paramref name="index"/> (RFC 9162 section 2.1.3.1), bottom-up. Throws <see cref="ArgumentOutOfRangeException"/> out of range.</summary>
    public static List<byte[]> InclusionPath(IReadOnlyList<byte[]> leafHashes, long index)
    {
        if (!Safe(index) || index < 0 || index >= leafHashes.Count) throw new ArgumentOutOfRangeException(nameof(index), "rfc9162: leaf index out of range");
        return Incl(leafHashes, 0, leafHashes.Count, (int)index);
    }

    static List<byte[]> Incl(IReadOnlyList<byte[]> d, int lo, int n, int index)
    {
        if (n == 1) return new();
        int k = (int)SplitPoint(n);
        if (index < k)
        {
            var p = Incl(d, lo, k, index);
            p.Add(Mth(d, lo + k, n - k));
            return p;
        }
        var q = Incl(d, lo + k, n - k, index - k);
        q.Add(Mth(d, lo, k));
        return q;
    }

    /// <summary>Recompute the tree root from a leaf hash and its inclusion path (RFC 9162 section 2.1.3.2); null when (index, size, path) is invalid.</summary>
    public static byte[]? RootFromInclusionPath(byte[] leaf, long index, long size, IReadOnlyList<byte[]> path)
    {
        if (!Safe(index) || !Safe(size) || index < 0 || size < 1 || index >= size) return null;
        if (leaf.Length != 32 || path.Any(p => p.Length != 32)) return null;
        long fn = index, sn = size - 1;
        var r = leaf;
        foreach (var p in path)
        {
            if (sn == 0) return null;
            if ((fn & 1) == 1 || fn == sn)
            {
                r = NodeHash(p, r);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
                }
            }
            else r = NodeHash(r, p);
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 ? r : null;
    }

    /// <summary>Verify an inclusion proof: the recomputed root must equal <paramref name="root"/>.</summary>
    public static bool VerifyInclusionPath(byte[] leaf, long index, long size, IReadOnlyList<byte[]> path, byte[] root)
    {
        var c = RootFromInclusionPath(leaf, index, size, path);
        return c != null && Equal(c, root);
    }

    static List<byte[]> Sub(IReadOnlyList<byte[]> d, int lo, int n, int m, bool complete)
    {
        if (m == n) return complete ? new() : new() { Mth(d, lo, n) };
        int k = (int)SplitPoint(n);
        if (m <= k)
        {
            var p = Sub(d, lo, k, m, complete);
            p.Add(Mth(d, lo + k, n - k));
            return p;
        }
        var q = Sub(d, lo + k, n - k, m - k, false);
        q.Add(Mth(d, lo, k));
        return q;
    }

    /// <summary>Consistency proof between the first <paramref name="m"/> leaves and all of <paramref name="leafHashes"/> (RFC 9162 section 2.1.4.1).</summary>
    public static List<byte[]> ConsistencyPath(IReadOnlyList<byte[]> leafHashes, long m)
    {
        if (!Safe(m) || m < 1 || m > leafHashes.Count) throw new ArgumentOutOfRangeException(nameof(m), "rfc9162: consistency size out of range");
        return Sub(leafHashes, 0, leafHashes.Count, (int)m, true);
    }

    /// <summary>Verify a consistency proof between a tree of <paramref name="first"/> leaves (root <paramref name="firstRoot"/>) and one of
    /// <paramref name="second"/> leaves (RFC 9162 section 2.1.4.2). A proof from an empty tree is rejected.</summary>
    public static bool VerifyConsistencyPath(long first, long second, byte[] firstRoot, byte[] secondRoot, IReadOnlyList<byte[]> path)
    {
        if (!Safe(first) || !Safe(second) || first < 1 || second < first) return false;
        if (firstRoot.Length != 32 || secondRoot.Length != 32 || path.Any(p => p.Length != 32)) return false;
        if (first == second) return path.Count == 0 && Equal(firstRoot, secondRoot);
        if (path.Count == 0) return false;
        var nodes = new List<byte[]>(path);
        // the reference tests "exact power of two" with 32-bit bit operations: reproduce them (a first above 2^32 wraps)
        if ((unchecked((int)first) & unchecked((int)(first - 1))) == 0) nodes.Insert(0, firstRoot);
        long fn = first - 1, sn = second - 1;
        while ((fn & 1) == 1) { fn >>= 1; sn >>= 1; }
        var fr = nodes[0];
        var sr = nodes[0];
        for (int i = 1; i < nodes.Count; i++)
        {
            var c = nodes[i];
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn)
            {
                fr = NodeHash(c, fr);
                sr = NodeHash(c, sr);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
                }
            }
            else sr = NodeHash(sr, c);
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && Equal(fr, firstRoot) && Equal(sr, secondRoot);
    }
}
