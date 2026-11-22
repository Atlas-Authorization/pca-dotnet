// Test doubles. TransparencyService is an in-memory reference log (it recomputes the Merkle tree on every registration and loses everything
// on restart): use it to produce receipts for tests and demos, never as a production transparency service. The production log is
// DurableTransparencyService over an IScittLogStore you provide; MemoryScittLogStore is the in-memory store for its tests.
namespace AtlasPca.Scitt;

public sealed record RegistrationResult(long Index, byte[] Receipt, string Root);
public sealed record AppendResult(byte[] Statement, long Index, byte[] Receipt, string Root);

public sealed class TransparencyService(string alg, CoseKey key, string? issuer = null)
{
    readonly List<byte[]> _statements = new(); // the registered Signed Statements (the log entries)
    readonly List<byte[]> _leafHashes = new(); // SHA-256(0x00 || statement), RFC 9162 section 2.1.1
    readonly ReceiptSignerOpts _signer = new(alg, key, issuer);

    public long Size => _statements.Count;

    /// <summary>The current Merkle tree root (b64u); the empty-log root for an empty service.</summary>
    public string Root => Pca.B64u(Rfc9162.TreeHash(_leafHashes));

    /// <summary>The statement leaves (b64u of each Signed Statement) currently in the log, in order.</summary>
    public List<string> Snapshot() => _statements.Select(Pca.B64u).ToList();

    RegistrationResult ReceiptFor(long index)
    {
        var root = Rfc9162.TreeHash(_leafHashes);
        var sides = Scitt.SiblingSides(index, _leafHashes.Count);
        var path = Rfc9162.InclusionPath(_leafHashes, index).Select((h, i) => new ProofStep(sides[i], Pca.B64u(h))).ToList();
        var proof = new InclusionProof(index, _leafHashes.Count, path);
        return new RegistrationResult(index, Scitt.BuildReceipt(Pca.B64u(root), proof, _signer), Pca.B64u(root));
    }

    /// <summary>Register an already-signed Signed Statement; append it and return a signed inclusion Receipt.</summary>
    public RegistrationResult Register(byte[] statement)
    {
        var cose = Scitt.DecodeCoseSign1(statement); // structural validation first: fail closed on garbage
        if (cose.Payload == null) throw new ScittException("scitt: cannot register a statement with a detached payload");
        long index = _statements.Count;
        _statements.Add((byte[])statement.Clone());
        _leafHashes.Add(Rfc9162.LeafHash(statement));
        return ReceiptFor(index);
    }

    /// <summary>Sign <paramref name="payload"/> as a Signed Statement, register it, and return the statement plus its Receipt.</summary>
    public AppendResult AppendAndReceipt(object? payload, SignStatementOpts stmt)
    {
        var statement = Scitt.SignStatement(payload, stmt);
        var r = Register(statement);
        return new AppendResult(statement, r.Index, r.Receipt, r.Root);
    }

    /// <summary>Re-issue a Receipt for an already-registered statement, against the CURRENT ledger root.</summary>
    public RegistrationResult GetReceipt(long index)
    {
        if (index < 0 || index >= _statements.Count) throw new ArgumentOutOfRangeException(nameof(index), "getReceipt: index out of range");
        return ReceiptFor(index);
    }

    /// <summary>An RFC 9162 consistency proof that the log at <paramref name="oldSize"/> entries is a prefix of the current log.</summary>
    public ConsistencyProofResult ConsistencyProof(long oldSize)
    {
        if (oldSize < 1 || oldSize > _statements.Count) throw new ArgumentOutOfRangeException(nameof(oldSize), "consistencyProof: size out of range");
        var path = Rfc9162.ConsistencyPath(_leafHashes, oldSize);
        return new ConsistencyProofResult(oldSize, _statements.Count,
            Pca.B64u(Rfc9162.TreeHash(_leafHashes.Take((int)oldSize).ToList())), Root,
            Cbor.Encode(new List<object?> { oldSize, (long)_statements.Count, path.Cast<object?>().ToList() }));
    }

    /// <summary>Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement).</summary>
    public static RegistrationResult RegisterStatement(byte[] statement, TransparencyService service) => service.Register(statement);
}

/// <summary>In-memory log store: single process, forgets everything on restart. For tests only.</summary>
public sealed class MemoryScittLogStore : IScittLogStore
{
    readonly object _gate = new();
    readonly List<byte[]> _entries = new();
    readonly Dictionary<(int, long), byte[]> _nodes = new();

    public long Size() { lock (_gate) return _entries.Count; }

    public byte[]? GetEntry(long index)
    {
        lock (_gate) return index >= 0 && index < _entries.Count ? (byte[])_entries[(int)index].Clone() : null;
    }

    public byte[]? GetNode(int level, long index)
    {
        lock (_gate) return _nodes.TryGetValue((level, index), out var h) ? (byte[])h.Clone() : null;
    }

    public bool Append(long expectedSize, byte[] entry, IReadOnlyList<StoredNode> nodes)
    {
        lock (_gate)
        {
            if (_entries.Count != expectedSize) return false;
            _entries.Add((byte[])entry.Clone());
            foreach (var n in nodes) _nodes[(n.Level, n.Index)] = (byte[])n.Hash.Clone();
            return true;
        }
    }
}
