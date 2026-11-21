using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A transparency log over an <see cref="ILedgerStore"/> (Ed25519 guardian checkpoints). Open it with <see cref="Open"/>; the constructor is private so that
/// no instance exists whose state was not verified against the stored checkpoints.
///
/// On <c>Open</c> the Merkle tree is rebuilt from the stored commits and checked against EVERY stored checkpoint: the guardian signature, the signed <c>prev_root</c>
/// chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each checkpoint root. A store that lost entries after a checkpoint
/// (rollback), edited an entry (tamper) or holds a forged checkpoint FAILS CLOSED with a <see cref="LedgerStoreError"/>. <see cref="Checkpoint"/> refuses to sign a
/// head that is not consistent with the previous one.
///
/// Checkpoints are Ed25519 by default. A post-quantum or hybrid suite (<see cref="Options.Suite"/>) needs the verifier's PQ pin for the guardian (<see cref="Options.Pin"/>);
/// every stored checkpoint is then verified under that pin, so a checkpoint signed by another PQ key is refused.</summary>
public sealed class StoredLedger
{
    /// <summary>Open options. <see cref="Store"/> and <see cref="GuardianKey"/> are required (there is no in-memory default).</summary>
    public sealed class Options
    {
        public ILedgerStore? Store;
        public EdKey? GuardianKey;
        /// <summary>Checkpoint signature suite (null: ed25519). A PQ or hybrid suite needs <see cref="Pin"/>; its Ed25519 key, when it has one, is the guardian key.</summary>
        public SuiteKey? Suite;
        /// <summary>PQ pins for the guardian identity, <c>{ed25519 b64u: pq_pk}</c>; required with a non-ed25519 suite.</summary>
        public IReadOnlyDictionary<string, string>? Pin;
        public string? InstanceId;
        public string? Principal;
        /// <summary>Epoch-ms clock for checkpoint timestamps (default the system clock).</summary>
        public Func<double>? Clock;
    }

    readonly Options _opts;
    readonly ILedgerStore _store;
    readonly string _guardianPublic;
    readonly MerkleLog _log;
    readonly List<D> _cps;
    readonly object _lock = new();

    StoredLedger(Options opts, string guardianPublic, MerkleLog log, List<D> cps)
    {
        _opts = opts;
        _store = opts.Store!;
        _guardianPublic = guardianPublic;
        _log = log;
        _cps = cps;
    }

    static LedgerStoreError Unavailable(Exception e) =>
        e as LedgerStoreError ?? new LedgerStoreError("store_unavailable", string.IsNullOrEmpty(e.Message) ? "store failed" : e.Message, e);

    /// <summary>Load the log and verify it against every stored checkpoint. Throws <see cref="LedgerStoreError"/> with the reference's codes.</summary>
    public static StoredLedger Open(Options opts)
    {
        if (opts?.Store == null) throw new LedgerStoreError("store_missing", "a LedgerStore is required (there is no in-memory default)");
        if (opts.GuardianKey == null || opts.GuardianKey.IsDestroyed) throw new LedgerStoreError("guardian_key_missing", "a guardian secret key is required");
        string gp = opts.GuardianKey.Id;
        if (opts.Suite != null && opts.Suite.Alg != "ed25519" && opts.Pin == null)
            throw new LedgerStoreError("pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)");
        if (opts.Suite?.Ed != null && opts.Suite.Ed.Id != gp) throw new ArgumentException("the suite's Ed25519 key is not the guardian key");
        try
        {
            long size = opts.Store.Size();
            var commits = opts.Store.Read(0, size);
            var cps = new List<D>(opts.Store.Checkpoints(0));
            var self = new StoredLedger(opts, gp, MerkleLog.Of(commits), cps);
            self.VerifyAgainstCheckpoints();
            return self;
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
    }

    /// <summary>verifyCheckpointChain with the failing reason (head / proof_missing / inconsistent); null when the chain verifies.</summary>
    (int At, string Reason)? ChainFailure(List<D> chain)
    {
        D? prev = null;
        for (int i = 0; i < chain.Count; i++)
        {
            var cp = chain[i];
            var sth = SthOf(cp);
            if (!Ledger.VerifyTreeHead(sth, _guardianPublic, null, _opts.Pin)) return (i, "head");
            if (i > 0)
            {
                var proof = cp.GetValueOrDefault("proof");
                if (proof == null || proof is false) return (i, "proof_missing");
                if (!Ledger.VerifyHeadConsistency(prev, sth, proof, _guardianPublic, null, _opts.Pin)) return (i, "inconsistent");
            }
            prev = sth;
        }
        return null;
    }

    static D SthOf(D cp) => (D)cp["sth"]!;

    /// <summary>The checkpoint chain, the log and the stored commits must tell one story.</summary>
    void VerifyAgainstCheckpoints()
    {
        long attested = 0;
        foreach (var cp in _cps)
        {
            var sz = SthOf(cp).GetValueOrDefault("size");
            if (IntentJs.IsInt(sz)) attested = Math.Max(attested, IntentJs.Lng(sz));
        }
        if (_log.Size < attested) throw new LedgerStoreError("rollback", $"the log has {_log.Size} entries but a checkpoint attests {attested}");
        for (int i = 0; i < _cps.Count; i++)
        {
            var sth = SthOf(_cps[i]);
            if (!Equals(sth.GetValueOrDefault("instance_id"), _opts.InstanceId) || !Equals(sth.GetValueOrDefault("principal"), _opts.Principal))
                throw new LedgerStoreError("forged_checkpoint", $"checkpoint {i} belongs to another log");
            var sz = sth.GetValueOrDefault("size");
            if (!IntentJs.IsInt(sz)) throw new ArgumentException("rootAt: size out of range");
            if (!Equals(_log.RootAt(IntentJs.Lng(sz)), sth.GetValueOrDefault("root")))
                throw new LedgerStoreError("tamper", $"the stored entries do not reproduce the root of checkpoint {i} (size {IntentJs.Lng(sz)})");
        }
        if (_cps.Count == 0) return;
        var v = ChainFailure(_cps);
        if (v is { } f) throw new LedgerStoreError(f.Reason == "inconsistent" ? "inconsistent" : "forged_checkpoint", $"checkpoint {f.At}: {f.Reason}");
    }

    public int Size()
    {
        lock (_lock) return _log.Size;
    }

    /// <summary>The guardian public key (b64u) every checkpoint verifies under.</summary>
    public string Guardian => _guardianPublic;

    /// <summary>The latest signed tree head, or null.</summary>
    public D? LatestCheckpoint()
    {
        lock (_lock) return _cps.Count == 0 ? null : SthOf(_cps[^1]);
    }

    public List<D> CheckpointChain()
    {
        lock (_lock) return _cps.Select(c => (D)StoreJs.DeepCopy(c)!).ToList();
    }

    /// <summary>{size, root}.</summary>
    public D Head()
    {
        lock (_lock) return _log.Head();
    }

    public D InclusionProof(long index)
    {
        lock (_lock) return _log.InclusionProof(index);
    }

    /// <summary>RFC 9162 proof from a size the caller already pinned (a checkpoint, or a witness's) to the current log.</summary>
    public D ConsistencyProofFrom(long oldSize)
    {
        lock (_lock) return _log.ConsistencyProof(oldSize, _log.Size);
    }

    public List<string> Commits()
    {
        lock (_lock) return _log.Commits();
    }

    /// <summary>Append an opaque commitment leaf; returns its index. If another writer took the position, reloads and appends at the new tail.</summary>
    public long Append(string commit)
    {
        if (string.IsNullOrEmpty(commit)) throw new LedgerStoreError("invalid_commit", "a commit must be a non-empty string");
        lock (_lock)
        {
            for (int attempt = 0; attempt < 16; attempt++)
            {
                long index = _log.Size;
                LedgerAppendOutcome output;
                try { output = _store.Append(index, new[] { commit }); }
                catch (Exception e) { throw Unavailable(e); }
                if (output.Outcome is "appended" or "replayed")
                {
                    _log.AppendCommitment(commit);
                    return index;
                }
                CatchUpLocked(); // another writer advanced the log: pick up its entries, then try the new tail
            }
            throw new LedgerStoreError("conflict", "the log kept moving; could not append");
        }
    }

    /// <summary>Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints).</summary>
    public void CatchUp()
    {
        lock (_lock) CatchUpLocked();
    }

    void CatchUpLocked()
    {
        try
        {
            long size = _store.Size();
            if (size < _log.Size) throw new LedgerStoreError("rollback", $"the store shrank from {_log.Size} to {size} entries");
            foreach (var c in _store.Read(_log.Size, size)) _log.AppendCommitment(c);
            _cps.AddRange(_store.Checkpoints(_cps.Count));
            VerifyAgainstCheckpoints();
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
    }

    /// <summary>A checkpoint signs what THIS handle holds, so first prove the store still holds exactly that.</summary>
    void AssertStoreMatchesMemory()
    {
        List<string> stored;
        try { stored = _store.Read(0, _log.Size); }
        catch (Exception e) { throw Unavailable(e); }
        if (!stored.SequenceEqual(_log.Commits())) throw new LedgerStoreError("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them");
    }

    /// <summary>Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the previous checkpoint,
    /// so a log that was rewritten under this handle is refused (<c>inconsistent</c>). An unchanged head returns the existing tree head.</summary>
    public D Checkpoint()
    {
        lock (_lock)
        {
            CatchUpLocked();
            AssertStoreMatchesMemory();
            var prev = _cps.Count == 0 ? null : _cps[^1];
            long size = _log.Size;
            string root = _log.Root();
            if (prev != null && IntentJs.IsInt(SthOf(prev).GetValueOrDefault("size")) && IntentJs.Lng(SthOf(prev)["size"]) == size) return SthOf(prev);
            double t = _opts.Clock != null ? _opts.Clock() : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (double.IsNaN(t) || double.IsInfinity(t)) throw new LedgerStoreError("clock_invalid", "the clock returned a non-finite time");
            var body = new D
            {
                ["instance_id"] = _opts.InstanceId,
                ["principal"] = _opts.Principal,
                ["size"] = IntentJs.OfLong(size),
                ["root"] = root,
                ["prev_root"] = prev == null ? "" : SthOf(prev).GetValueOrDefault("root"),
                ["timestamp"] = StoreJs.Number(t),
            };
            var suite = _opts.Suite ?? SuiteKey.Ed25519(_opts.GuardianKey!);
            var bound = IntentJs.BindSuiteFields(body, suite.Alg, true, suite.PqPk, true);
            var msg = Pca.Concat(IntentJs.Utf8(Ledger.SthDomain), IntentJs.CanonBytes(bound));
            var (sig, pqSig) = suite.Sign(msg);
            var sth = new D(bound) { ["guardian"] = _guardianPublic, ["sig"] = sig }; // the bound body carries alg and pq_pk for a non-ed25519 suite
            if (pqSig != null) sth["pq_sig"] = pqSig;
            var cp = new D { ["sth"] = sth };
            if (prev != null) cp["proof"] = _log.ConsistencyProof(IntentJs.Lng(SthOf(prev)["size"]), size);
            var chain = new List<D>(_cps) { cp };
            if (ChainFailure(chain) is { } v)
            {
                if (v.Reason == "head") throw new LedgerStoreError("forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)");
                throw new LedgerStoreError("inconsistent", $"the new head is not consistent with checkpoint {v.At - 1}");
            }
            LedgerCheckpointOutcome output;
            try { output = _store.AppendCheckpoint(_cps.Count, cp); }
            catch (Exception e) { throw Unavailable(e); }
            if (output.Outcome == "conflict") throw new LedgerStoreError("conflict", output.Reason ?? "conflict");
            _cps.Add(cp);
            return sth;
        }
    }
}
