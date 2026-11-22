using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>An append-only RFC 9162 Merkle log over opaque commitment strings: head, root at an earlier size, inclusion and consistency
/// proofs, in the wire shapes the verifiers in <see cref="Ledger"/> and <see cref="Mesh"/> read. It holds only commitments (no openings).</summary>
public sealed class MerkleLog
{
    readonly List<string> _commits = new();
    readonly List<byte[]> _hashes = new();

    /// <summary>Rebuild from stored commitments.</summary>
    public static MerkleLog Of(IEnumerable<string> commits)
    {
        var l = new MerkleLog();
        foreach (var c in commits) l.AppendCommitment(c);
        return l;
    }

    public int Size => _commits.Count;

    public List<string> Commits() => new(_commits);

    /// <summary>Append an opaque commitment leaf; refuses an empty one. Returns its index.</summary>
    public int AppendCommitment(string commit)
    {
        if (string.IsNullOrEmpty(commit)) throw new ArgumentException("appendCommitment: commit must be a non-empty string");
        _commits.Add(commit);
        _hashes.Add(Pca.LeafHash(commit));
        return _commits.Count - 1;
    }

    /// <summary>Append a commit read back from storage as it is (no emptiness check: the stored sequence decides the tree).</summary>
    internal void AppendStored(string commit)
    {
        _commits.Add(commit);
        _hashes.Add(Pca.LeafHash(commit));
    }

    static byte[] Mth(List<byte[]> hs) => hs.Count == 0 ? Pca.Sha(Array.Empty<byte>()) : Pca.Build(hs);

    /// <summary>{size, root}.</summary>
    public D Head() => new() { ["size"] = IntentJs.OfLong(Size), ["root"] = Root() };

    public string Root() => Pca.B64u(Mth(_hashes));

    /// <summary>The root the log had when it held only the first <paramref name="size"/> entries.</summary>
    public string RootAt(long size)
    {
        if (size < 0 || size > Size) throw new ArgumentException("rootAt: size out of range");
        return Pca.B64u(Mth(_hashes.GetRange(0, (int)size)));
    }

    /// <summary>{index, size, path: [{side, hash}]}.</summary>
    public D InclusionProof(long index)
    {
        if (index < 0 || index >= Size) throw new ArgumentException("merkleProof: index out of range");
        var path = new L();
        Prove(_hashes, (int)index, path);
        return new D { ["index"] = IntentJs.OfLong(index), ["size"] = IntentJs.OfLong(Size), ["path"] = path };
    }

    internal static void Prove(List<byte[]> hs, int idx, L output)
    {
        if (hs.Count == 1) return;
        int k = (int)Pca.Split(hs.Count);
        var step = new D();
        if (idx < k)
        {
            Prove(hs.GetRange(0, k), idx, output);
            step["side"] = "R";
            step["hash"] = Pca.B64u(Pca.Build(hs.GetRange(k, hs.Count - k)));
        }
        else
        {
            Prove(hs.GetRange(k, hs.Count - k), idx - k, output);
            step["side"] = "L";
            step["hash"] = Pca.B64u(Pca.Build(hs.GetRange(0, k)));
        }
        output.Add(step);
    }

    /// <summary>RFC 9162 SUBPROOF: {oldSize, newSize, path: [b64u]}.</summary>
    public D ConsistencyProof(long oldSize, long newSize)
    {
        if (oldSize < 0 || oldSize > newSize || newSize > Size) throw new ArgumentException("consistencyProof: invalid sizes");
        var output = new L();
        if (oldSize > 0 && oldSize < newSize) Sub((int)oldSize, _hashes.GetRange(0, (int)newSize), true, output);
        return new D { ["oldSize"] = IntentJs.OfLong(oldSize), ["newSize"] = IntentJs.OfLong(newSize), ["path"] = output };
    }

    public D ConsistencyProof(long oldSize) => ConsistencyProof(oldSize, Size);

    static void Sub(int m, List<byte[]> hs, bool b, L output)
    {
        int n = hs.Count;
        if (m == n)
        {
            if (!b) output.Add(Pca.B64u(Mth(hs)));
            return;
        }
        int k = (int)Pca.Split(n);
        if (m <= k)
        {
            Sub(m, hs.GetRange(0, k), b, output);
            output.Add(Pca.B64u(Mth(hs.GetRange(k, n - k))));
        }
        else
        {
            Sub(m - k, hs.GetRange(k, n - k), false, output);
            output.Add(Pca.B64u(Mth(hs.GetRange(0, k))));
        }
    }
}
