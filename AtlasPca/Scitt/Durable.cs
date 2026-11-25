// A durable SCITT Transparency Service. The log keeps the hash of every complete aligned subtree in a store, so an append is O(log n)
// store reads and writes (no recomputation of the tree), the root is O(log n), and an inclusion or consistency proof is O(log^2 n)
// reads. State lives entirely in the IScittLogStore you supply; there is no in-memory default (MemoryScittLogStore is for tests).
using System.Numerics;

namespace AtlasPca.Scitt;

/// <summary>The hash of the complete subtree at <c>Level</c> covering leaves [Index * 2^Level, (Index + 1) * 2^Level).</summary>
public sealed record StoredNode(int Level, long Index, byte[] Hash);

/// <summary>Durable, append-only storage for a transparency log. <c>Append</c> is atomic: it succeeds only when the log still has exactly
/// <c>expectedSize</c> entries (compare-and-set) and stores the entry and the new subtree hashes together, or none of them. Entries and nodes are immutable.</summary>
public interface IScittLogStore
{
    long Size();
    byte[]? GetEntry(long index);
    byte[]? GetNode(int level, long index);
    bool Append(long expectedSize, byte[] entry, IReadOnlyList<StoredNode> nodes);
}

/// <summary>A log failure; <c>Code</c> is one of store_required, store_corrupt, append_contention, out_of_range, bad_statement.</summary>
public sealed class ScittLogException(string code, string message) : ScittException(message, code);

/// <summary>Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs).</summary>
sealed class ScittLogReader(IScittLogStore store)
{
    static long LargestPow2Below(long n)
    {
        long k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    static bool IsPow2(long n) => n > 0 && (n & (n - 1)) == 0;

    byte[] Node(int level, long index)
    {
        var h = store.GetNode(level, index);
        if (h == null || h.Length != 32) throw new ScittLogException("store_corrupt", $"missing or malformed subtree hash ({level}, {index})");
        return h;
    }

    /// <summary>MTH over leaves [lo, lo + n): lo is a multiple of the split points, which every caller guarantees.</summary>
    public byte[] Range(long lo, long n)
    {
        if (n == 1) return Node(0, lo);
        if (IsPow2(n) && lo % n == 0) return Node(BitOperations.Log2((ulong)n), lo / n);
        long k = LargestPow2Below(n);
        return Rfc9162.NodeHash(Range(lo, k), Range(lo + k, n - k));
    }

    public byte[] Root(long size) => size == 0 ? Rfc9162.EmptyRoot() : Range(0, size);

    public List<byte[]> Inclusion(long index, long size) => Walk(0, size, index);

    List<byte[]> Walk(long lo, long n, long idx)
    {
        if (n == 1) return new();
        long k = LargestPow2Below(n);
        if (idx < k)
        {
            var p = Walk(lo, k, idx);
            p.Add(Range(lo + k, n - k));
            return p;
        }
        var q = Walk(lo + k, n - k, idx - k);
        q.Add(Range(lo, k));
        return q;
    }

    public List<byte[]> Consistency(long m, long size) => Sub(0, size, m, true);

    List<byte[]> Sub(long lo, long n, long mm, bool complete)
    {
        if (mm == n) return complete ? new() : new() { Range(lo, n) };
        long k = LargestPow2Below(n);
        if (mm <= k)
        {
            var p = Sub(lo, k, mm, complete);
            p.Add(Range(lo + k, n - k));
            return p;
        }
        var q = Sub(lo + k, n - k, mm - k, false);
        q.Add(Range(lo, k));
        return q;
    }
}

public sealed record DurableRegistration(long Index, byte[] Receipt, string Root);
public sealed record DurableAppend(byte[] Statement, long Index, byte[] Receipt, string Root);

public sealed class DurableTransparencyService
{
    const int MaxAppendAttempts = 16;
    readonly IScittLogStore _store;
    readonly ScittLogReader _reader;
    readonly ReceiptSignerOpts _signer;

    public DurableTransparencyService(IScittLogStore store, string alg, CoseKey key, string? issuer = null)
    {
        _store = store ?? throw new ScittLogException("store_required", "a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default");
        _reader = new ScittLogReader(store);
        _signer = new ReceiptSignerOpts(alg, key, issuer);
    }

    public long Size()
    {
        var n = _store.Size();
        if (n < 0 || n > 9007199254740991L) throw new ScittLogException("store_corrupt", "the store reported an invalid size");
        return n;
    }

    /// <summary>The current tree root (b64u).</summary>
    public string Root() => Pca.B64u(_reader.Root(Size()));

    DurableRegistration ReceiptFor(long index, long size)
    {
        var root = _reader.Root(size);
        var sides = Scitt.SiblingSides(index, size);
        var path = _reader.Inclusion(index, size).Select((h, i) => new ProofStep(sides[i], Pca.B64u(h))).ToList();
        var proof = new InclusionProof(index, size, path);
        return new DurableRegistration(index, Scitt.BuildReceipt(Pca.B64u(root), proof, _signer), Pca.B64u(root));
    }

    /// <summary>Append a Signed Statement (validated structurally first) and return its receipt against the new root.</summary>
    public DurableRegistration Register(byte[] statement)
    {
        try
        {
            var cose = Scitt.DecodeCoseSign1(statement);
            if (cose.Payload == null) throw new ScittException("detached payload");
        }
        catch (Exception e) { throw new ScittLogException("bad_statement", "cannot register: " + e.Message); }
        for (int attempt = 0; attempt < MaxAppendAttempts; attempt++)
        {
            long n = Size();
            var nodes = new List<StoredNode> { new(0, n, Rfc9162.LeafHash(statement)) };
            // completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored
            var hash = nodes[0].Hash;
            for (int level = 1; (n + 1) % (1L << level) == 0; level++)
            {
                long idx = (n + 1) / (1L << level) - 1;
                var left = _store.GetNode(level - 1, 2 * idx);
                if (left == null || left.Length != 32) throw new ScittLogException("store_corrupt", $"missing subtree hash ({level - 1}, {2 * idx})");
                hash = Rfc9162.NodeHash(left, hash);
                nodes.Add(new StoredNode(level, idx, hash));
            }
            if (_store.Append(n, statement, nodes)) return ReceiptFor(n, n + 1);
        }
        throw new ScittLogException("append_contention", "could not append: the log kept changing");
    }

    public DurableAppend AppendAndReceipt(object? payload, SignStatementOpts stmt)
    {
        var statement = Scitt.SignStatement(payload, stmt);
        var r = Register(statement);
        return new DurableAppend(statement, r.Index, r.Receipt, r.Root);
    }

    /// <summary>A receipt for an entry, against the CURRENT root.</summary>
    public DurableRegistration GetReceipt(long index)
    {
        var size = Size();
        if (index < 0 || index >= size) throw new ScittLogException("out_of_range", "getReceipt: index out of range");
        return ReceiptFor(index, size);
    }

    public byte[] GetEntry(long index)
    {
        var size = Size();
        if (index < 0 || index >= size) throw new ScittLogException("out_of_range", "getEntry: index out of range");
        return _store.GetEntry(index) ?? throw new ScittLogException("store_corrupt", $"entry {index} is missing");
    }

    /// <summary>An RFC 9162 consistency proof that the first <paramref name="oldSize"/> entries are a prefix of the current log.</summary>
    public ConsistencyProofResult ConsistencyProof(long oldSize)
    {
        var size = Size();
        if (oldSize < 1 || oldSize > size) throw new ScittLogException("out_of_range", "consistencyProof: size out of range");
        var path = _reader.Consistency(oldSize, size);
        return new ConsistencyProofResult(oldSize, size, Pca.B64u(_reader.Root(oldSize)), Pca.B64u(_reader.Root(size)),
            Cbor.Encode(new List<object?> { oldSize, size, path.Cast<object?>().ToList() }));
    }

    /// <summary>Check a store implementation against the contract the service relies on. Returns the failures (empty = conforms): compare-and-set,
    /// atomic entry-plus-nodes, immutability and a single winner among concurrent appends.</summary>
    public static List<string> CheckScittLogStore(Func<IScittLogStore> makeStore)
    {
        var failures = new List<string>();
        void Fail(string m) => failures.Add(m);
        try
        {
            var s = makeStore();
            if (s.Size() != 0) Fail("a new store is not empty");
            byte[] H(int b) => Enumerable.Repeat((byte)b, 32).ToArray();
            if (!s.Append(0, new byte[] { 1 }, new[] { new StoredNode(0, 0, H(1)) })) Fail("append at the right size was refused");
            if (s.Append(0, new byte[] { 2 }, new[] { new StoredNode(0, 1, H(2)) })) Fail("append at a stale size was accepted (no compare-and-set)");
            if (s.Size() != 1) Fail("a refused append changed the size");
            if (s.GetNode(0, 1) != null) Fail("a refused append left a node behind (not atomic)");
            if (s.GetEntry(1) != null) Fail("a refused append left an entry behind");
            var e0 = s.GetEntry(0);
            if (e0 == null || e0.Length != 1 || e0[0] != 1) Fail("the stored entry does not read back");
            if (e0 != null && e0.Length > 0) e0[0] = 9;
            var again = s.GetEntry(0);
            if (again == null || again[0] != 1) Fail("a returned entry aliases the stored one (mutable)");
            var racers = Enumerable.Range(1, 4).Select(i => Task.Run(() => s.Append(1, new byte[] { (byte)(10 + i) }, new[] { new StoredNode(0, 1, H(10 + i)) }))).ToArray();
            Task.WaitAll(racers);
            if (racers.Count(t => t.Result) != 1) Fail("concurrent appends at the same size did not produce exactly one winner");
            if (s.Size() != 2) Fail("the size after a race is not 2");
        }
        catch (Exception e) { Fail("the store threw: " + e.Message); }
        return failures;
    }
}
