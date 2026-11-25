// The issuing side of the transparency ledger: the salted entry commitment and its opening, the root of a commit sequence, the in-memory
// append-only log (inclusion and consistency proofs, crypto-shredding, the witnessed head), guardian-signed tree heads, witness
// cosignatures and the split-view proof for signed tree heads. The verifying side is in Ledger.cs; the durable log is StoredLedger.
using System.Security.Cryptography;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public static partial class Ledger
{
    /// <summary>The salted commitment of a PCActn: the canonical hash of {salt, pcactn_digest}.</summary>
    public static string EntryCommit(string salt, object? pcactn) => Commit(salt, pcactn);

    static string Commit(object? salt, object? pcactn) => Pca.HashCanonical(new D { ["salt"] = salt, ["pcactn_digest"] = Pca.HashCanonical(pcactn) });

    /// <summary>True when the opening {salt, pcactn} reproduces the commit. Never throws: a malformed opening is false.</summary>
    public static bool VerifyOpening(object? commit, object? opening)
    {
        try
        {
            return commit is string c && opening is D o && o.TryGetValue("salt", out var salt) && o.TryGetValue("pcactn", out var pcactn) && Commit(salt, pcactn) == c;
        }
        catch (Exception) { return false; }
    }

    /// <summary>The root of a commit sequence (the empty log is SHA-256 of the empty string), base64url.</summary>
    public static string LedgerRootOf(IEnumerable<string> commits)
    {
        var hs = commits.Select(c => Pca.LeafHash(c)).ToList();
        return Pca.B64u(hs.Count == 0 ? Pca.Sha(Array.Empty<byte>()) : Pca.Build(hs));
    }

    /// <summary>Signs <paramref name="body"/> under <paramref name="domain"/> with the identity's suite (null: ed25519). Returns the body as signed (a
    /// non-ed25519 suite binds alg and pq_pk into it) and the wire fields the artifact carries: sig, plus alg, pq_pk and (hybrid) pq_sig.</summary>
    internal static (D Bound, D Fields) SuiteSign(EdKey identity, SuiteKey? suite, string domain, D body)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (suite?.Ed != null && suite.Ed.Id != identity.Id) throw new ArgumentException("the suite's Ed25519 key is not the signing identity");
        var s = suite ?? SuiteKey.Ed25519(identity);
        var bound = IntentJs.BindSuiteFields(body, s.Alg, true, s.PqPk, true);
        var (sig, pqSig) = s.Sign(IntentJs.Message(domain, bound));
        var fields = new D { ["sig"] = sig };
        if (bound.TryGetValue("alg", out var alg)) fields["alg"] = alg;
        if (bound.TryGetValue("pq_pk", out var pk)) fields["pq_pk"] = pk;
        if (pqSig != null) fields["pq_sig"] = pqSig;
        return (bound, fields);
    }

    /// <summary>The guardian signs the tree head {instance_id, principal, size, root, prev_root, timestamp} (all six are required). The result carries
    /// those members, <c>guardian</c> (the guardian's Ed25519 identity) and the signature fields of the suite (null: ed25519).</summary>
    public static D SignTreeHead(EdKey guardian, D head, SuiteKey? suite = null)
    {
        var body = Pick(head, "instance_id", "principal", "size", "root", "prev_root", "timestamp")
            ?? throw new ArgumentException("signTreeHead: the head needs instance_id, principal, size, root, prev_root and timestamp");
        var (_, fields) = SuiteSign(guardian, suite, SthDomain, body);
        var sth = new D(body) { ["guardian"] = guardian.Id };
        foreach (var e in fields) sth[e.Key] = e.Value;
        return sth;
    }

    /// <summary>A trusted witness cosigns the tree-head statement {instance_id, principal, size, root, prev_root, guardian_epoch (absent or null = 0)} of
    /// <paramref name="sth"/>. Returns {key, sig} plus the suite fields; the cosignature verifies only against a head with the same statement.</summary>
    public static D CosignTreeHead(D sth, EdKey witness, SuiteKey? suite = null)
    {
        var body = Pick(sth, "instance_id", "principal", "size", "root", "prev_root")
            ?? throw new ArgumentException("cosignTreeHead: the head needs instance_id, principal, size, root and prev_root");
        body["guardian_epoch"] = sth.TryGetValue("guardian_epoch", out var e) && e != null ? e : IntentJs.OfLong(0);
        var (_, fields) = SuiteSign(witness, suite, SthWitnessDomain, body);
        var cosig = new D { ["key"] = witness.Id };
        foreach (var f in fields) cosig[f.Key] = f.Value;
        return cosig;
    }

    /// <summary>Split-view proof for signed tree heads: both heads are genuinely signed by the pinned guardian for the same instance, log and size but
    /// carry different roots. Never throws.</summary>
    public static bool DetectTreeHeadEquivocation(object? a, object? b, string guardianPublic, IReadOnlyDictionary<string, string>? pins = null)
    {
        try
        {
            if (a is not D am || b is not D bm || !VerifyTreeHead(a, guardianPublic, null, pins) || !VerifyTreeHead(b, guardianPublic, null, pins)) return false;
            return Same(am.GetValueOrDefault("instance_id"), bm.GetValueOrDefault("instance_id")) && Same(am.GetValueOrDefault("principal"), bm.GetValueOrDefault("principal"))
                && Same(am.GetValueOrDefault("size"), bm.GetValueOrDefault("size")) && !Same(am.GetValueOrDefault("root"), bm.GetValueOrDefault("root"));
        }
        catch (Exception) { return false; }
    }
}

/// <summary>An in-memory append-only transparency log of salted PCActn commitments. Each entry is a commit and, until it is shredded, its opening
/// {salt, pcactn}; the Merkle tree is over the commits only, so shredding an opening changes no leaf, root or proof.</summary>
public sealed class TransparencyLedger
{
    readonly MerkleLog _log = new();
    readonly List<D?> _openings = new();

    public string Principal { get; }

    public TransparencyLedger(string principal = "") { Principal = principal; }

    /// <summary>Rebuild from stored entries ({commit, opening?}), for example after persistence. The openings are taken as stored: check them with <see cref="AuditOpenings"/>.</summary>
    public static TransparencyLedger FromEntries(IEnumerable<D> entries, string principal = "")
    {
        var l = new TransparencyLedger(principal);
        foreach (var e in entries)
        {
            if (e.GetValueOrDefault("commit") is not string c) throw new ArgumentException("fromEntries: every entry needs a string commit");
            l._log.AppendStored(c);
            l._openings.Add(e.GetValueOrDefault("opening") as D);
        }
        return l;
    }

    public int Size => _log.Size;

    /// <summary>Append a PCActn as a salted commitment. Pass <paramref name="salt"/> for deterministic output (default: 16 random bytes, base64url).</summary>
    public (int Index, string Commit) Append(object? pcactn, string? salt = null)
    {
        salt ??= Pca.B64u(RandomNumberGenerator.GetBytes(16));
        var commit = Ledger.EntryCommit(salt, pcactn);
        int index = _log.AppendCommitment(commit);
        _openings.Add(new D { ["salt"] = salt, ["pcactn"] = pcactn });
        return (index, commit);
    }

    /// <summary>Append a precomputed opaque commitment leaf whose opening the caller holds off-log. Refuses an empty commit.</summary>
    public (int Index, string Commit) AppendCommitment(string commit)
    {
        int index = _log.AppendCommitment(commit);
        _openings.Add(null);
        return (index, commit);
    }

    /// <summary>{size, root}.</summary>
    public D Head() => _log.Head();

    /// <summary>The root the log had when it held only the first <paramref name="size"/> entries.</summary>
    public string RootAt(long size) => _log.RootAt(size);

    public List<string> Commits() => _log.Commits();

    /// <summary>{commit, opening?} of one entry.</summary>
    public D Entry(int index)
    {
        if (index < 0 || index >= Size) throw new ArgumentException("entry: index out of range");
        var e = new D { ["commit"] = _log.Commits()[index] };
        if (_openings[index] is { } o) e["opening"] = o;
        return e;
    }

    /// <summary>The indices whose stored opening no longer matches its commit (storage tamper detection).</summary>
    public List<int> AuditOpenings()
    {
        var commits = _log.Commits();
        var bad = new List<int>();
        for (int i = 0; i < commits.Count; i++)
            if (_openings[i] is { } o && !Ledger.VerifyOpening(commits[i], o)) bad.Add(i);
        return bad;
    }

    public D InclusionProof(long index) => _log.InclusionProof(index);

    public bool VerifyInclusion(string root, object? proof, object? commit) => Ledger.VerifyLedgerInclusion(root, proof, commit);

    /// <summary>RFC 9162 consistency proof from <paramref name="oldSize"/> to <paramref name="newSize"/> (null: the current size).</summary>
    public D ConsistencyProof(long oldSize, long? newSize = null) => _log.ConsistencyProof(oldSize, newSize ?? Size);

    public bool VerifyConsistency(object? oldRoot, object? newRoot, object? proof) => Ledger.VerifyLedgerConsistency(oldRoot, newRoot, proof);

    /// <summary>Crypto-shred: destroy the opening (salt and PCActn), keep the commit. Returns whether an opening was removed.</summary>
    public bool Shred(int index)
    {
        if (index < 0 || index >= Size) throw new ArgumentException("shred: index out of range");
        bool had = _openings[index] != null;
        _openings[index] = null;
        return had;
    }

    /// <summary>Sign the current head {principal, size, root} for third-party witnessing; <c>witness</c> is the guardian's Ed25519 identity.</summary>
    public D WitnessHead(EdKey guardian, SuiteKey? suite = null)
    {
        var body = new D { ["principal"] = Principal, ["size"] = IntentJs.OfLong(Size), ["root"] = _log.Root() };
        var (_, fields) = Ledger.SuiteSign(guardian, suite, Ledger.LedgerHeadDomain, body);
        var wh = new D(body) { ["witness"] = guardian.Id };
        foreach (var f in fields) wh[f.Key] = f.Value;
        return wh;
    }
}
