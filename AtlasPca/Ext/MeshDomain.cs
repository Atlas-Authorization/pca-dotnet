using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The issuing side of a mesh domain (an organisation): an append-only delegation log, a revocation set, and head publication against
/// <see cref="MeshWitness"/>es. In production this is the deployed signed-tree-head and revocation-epoch machinery; here it is in memory so the
/// witness protocol can be exercised end to end.</summary>
public sealed class MeshDomain
{
    public string Id { get; }
    public string Name { get; }
    readonly EdKey _key;
    readonly MerkleLog _log = new();
    readonly MeshRevocationSet _rev = new();
    readonly Dictionary<string, Snapshot> _snaps = new(StringComparer.Ordinal);
    readonly object _lock = new();

    sealed record Snapshot(List<string> Log, MeshRevocationSet Rev);

    public MeshDomain(string name, EdKey key)
    {
        Name = name;
        _key = key;
        Id = key.Id;
    }

    /// <summary>Vouch that an agent key belongs to this domain: <c>{agent, domain, role, sig}</c> (for domain policy, not authority).</summary>
    public D Enroll(string agent, string role)
    {
        var body = new D { ["agent"] = agent, ["domain"] = Id, ["role"] = role };
        var m = Pca.Concat(IntentJs.Utf8(Mesh.BindingDomain), IntentJs.CanonBytes(body));
        return new D(body) { ["sig"] = Pca.B64u(_key.Sign(m)) };
    }

    /// <summary>The proof a verifier holding <paramref name="pin"/> (a head of this domain) needs to accept <paramref name="head"/> (a cosigned head this domain
    /// published, larger than the pin): <c>{domain, proof}</c>. Throws if the head is unknown or the pin is not a prefix of that head's log.</summary>
    public D PinProof(D pin, D head)
    {
        lock (_lock)
        {
            if (!_snaps.TryGetValue(Convert.ToString(head.GetValueOrDefault("sig")) ?? "", out var snap)) throw new InvalidOperationException("pinProof: unknown head");
            var inner = (D)head["head"]!;
            // the sizes are integers (a fractional, missing or non-numeric one is refused, never truncated)
            if (!(IntentJs.NumOf(pin.GetValueOrDefault("size")) is double ps && double.IsFinite(ps) && ps == Math.Floor(ps))) throw new ArgumentException("consistencyProof: invalid sizes");
            return new D { ["domain"] = Id, ["proof"] = MerkleLog.Of(snap.Log).ConsistencyProof((long)ps, IntentJs.Lng(inner["size"])) };
        }
    }

    /// <summary>Per-hop evidence against a previously published head: <c>{domain, head, inclusion, binding?, revocation: {cap, issuer_key}}</c>. Throws if the
    /// head is unknown, the capability is not in that head's log, or the capability or its issuer key is revoked as of that head. <paramref name="binding"/> may be null.</summary>
    public D Evidence(D cap, D head, D? binding)
    {
        lock (_lock)
        {
            if (!_snaps.TryGetValue(Convert.ToString(head.GetValueOrDefault("sig")) ?? "", out var snap)) throw new InvalidOperationException("evidence: unknown head");
            int idx = snap.Log.IndexOf(Pca.CapHash(cap));
            if (idx < 0) throw new InvalidOperationException("evidence: capability not in this head");
            var rv = new D
            {
                ["cap"] = snap.Rev.NonMembershipProof((string)cap["id"]!),
                ["issuer_key"] = snap.Rev.NonMembershipProof("key:" + cap["issuer"]),
            };
            var ev = new D { ["domain"] = Id, ["head"] = head, ["inclusion"] = MerkleLog.Of(snap.Log).InclusionProof(idx), ["revocation"] = rv };
            if (binding != null) ev["binding"] = binding;
            return ev;
        }
    }

    /// <summary>Log a delegation hop issued in this domain (identified by its capability hash). Idempotent. Returns its index.</summary>
    public int Record(D cap)
    {
        lock (_lock)
        {
            var h = Pca.CapHash(cap);
            int i = _log.Commits().IndexOf(h);
            return i >= 0 ? i : _log.AppendCommitment(h);
        }
    }

    /// <summary>A copy of the current revocation set (for proofs about it).</summary>
    public MeshRevocationSet RevocationSetCopy()
    {
        lock (_lock) return new MeshRevocationSet(_rev.List());
    }

    /// <summary>Revoke a capability id or an agent key.</summary>
    public void Revoke(string revokedId)
    {
        lock (_lock) _rev.Revoke(revokedId);
    }

    /// <summary>RFC 9162 consistency proof between two sizes of this domain's current log.</summary>
    public D ConsistencyProof(long oldSize, long newSize)
    {
        lock (_lock) return _log.ConsistencyProof(oldSize, newSize);
    }

    /// <summary>The proof from <paramref name="oldSize"/> to the current size of this domain's log.</summary>
    public D ConsistencyProof(long oldSize)
    {
        lock (_lock) return _log.ConsistencyProof(oldSize, _log.Size);
    }

    /// <summary>Publish a head: domain-signed, then cosigned by <paramref name="witnesses"/>, each shown a real consistency proof from ITS last-seen head plus the
    /// revocation list. Throws if a witness refuses (unless <paramref name="threshold"/> tolerates it). Returns <c>{head, sig, cosigs}</c>.</summary>
    public D PublishHead(IReadOnlyList<MeshWitness> witnesses, double timestamp, int? threshold = null)
    {
        lock (_lock)
        {
            long size = _log.Size;
            var head = new D
            {
                ["domain"] = Id,
                ["size"] = IntentJs.OfLong(size),
                ["root"] = size == 0 ? "" : _log.Root(),
                ["rev_root"] = _rev.Root(),
                ["rev_size"] = IntentJs.OfLong(_rev.Size),
                ["timestamp"] = StoreJs.Number(timestamp),
            };
            var m = Pca.Concat(IntentJs.Utf8(Mesh.HeadDomain), IntentJs.CanonBytes(head));
            var cosigs = new L();
            var ch = new D { ["head"] = head, ["sig"] = Pca.B64u(_key.Sign(m)), ["cosigs"] = cosigs };
            var revIds = _rev.List();
            var errors = new List<Exception>();
            foreach (var w in witnesses)
            {
                var prev = w.LastSeen(Id);
                D? consistency = null;
                if (prev != null)
                {
                    long ps = IntentJs.Lng(prev["size"]);
                    if (ps < size) consistency = _log.ConsistencyProof(ps, size);
                    else if (ps > size) // will be refused as rollback
                        consistency = new D { ["oldSize"] = IntentJs.OfLong(ps), ["newSize"] = IntentJs.OfLong(size), ["path"] = new L() };
                }
                var req = new D { ["head"] = ch };
                if (consistency != null) req["consistency"] = consistency;
                req["rev_ids"] = revIds.Cast<object?>().ToList();
                try { cosigs.Add(w.Cosign(req)); }
                catch (Exception e) { errors.Add(e); }
            }
            int need = threshold ?? witnesses.Count;
            if (cosigs.Count < need) throw errors.Count == 0 ? new InvalidOperationException("publishHead: not enough witnesses") : errors[0];
            _snaps[(string)ch["sig"]!] = new Snapshot(_log.Commits(), new MeshRevocationSet(_rev.List()));
            return ch;
        }
    }
}
