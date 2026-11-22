// Signing and assembling of policy bundles, masking, the append-only decision log with signed heads, inclusion proofs and
// streamed batches, and replay analysis (packages/pca-grants bundle.ts). Verification of bundles, heads, proofs and batches is K3.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

public static class Bundle
{
    const string MaskDomain = "atlas-pca/mask/v1";

    /// <summary>One signer's signature over the bundle body (everything but <c>sigs</c>). Throws when the body is malformed.</summary>
    public static JD SignBundle(object? body, EdKey key)
    {
        var e = K3.BundleShapeError(body);
        if (e != null) throw new ArgumentException("signBundle: " + e);
        return new JD { ["signer"] = key.Id, ["sig"] = Sig.SignBody(K3.BundleDomain, G.Without((JD)body!, "sigs"), key) };
    }

    /// <summary><c>{...body (without sigs), sigs}</c>.</summary>
    public static JD AssembleBundle(JD body, IEnumerable<object?> sigs)
    {
        var o = G.Without(body, "sigs");
        o["sigs"] = sigs.ToList();
        return o;
    }

    static bool Truthy(object? x) => x switch { null => false, bool b => b, string s => s.Length > 0, Num n => double.Parse(n.Raw, System.Globalization.CultureInfo.InvariantCulture) != 0, _ => true };

    /// <summary>Mask by data CLASS: every detail field whose class is in <paramref name="maskClasses"/> becomes a salt-free commitment.</summary>
    public static JD MaskRecord(JD record, IReadOnlyCollection<string> maskClasses)
    {
        var detailRaw = IntentJs.Get(record, "detail");
        var classesRaw = IntentJs.Get(record, "classes");
        if (!Truthy(detailRaw) || !Truthy(classesRaw)) return record;
        if (detailRaw is not JD detail) throw new ArgumentException("maskRecord: detail must be an object");
        var detail2 = new JD();
        foreach (var (k, v) in detail)
        {
            var cls = classesRaw is JD c && c.TryGetValue(k, out var cv) ? cv : null;
            detail2[k] = cls is string cs && maskClasses.Contains(cs)
                ? $"masked:{cs}:{Pca.HashCanonical(new JD { ["d"] = MaskDomain, ["k"] = k, ["v"] = v })}"
                : v;
        }
        var o = new JD(record);
        o["detail"] = detail2;
        return o;
    }

    // ---- Merkle proof (RFC 6962 shape, matching Pca.MerkleRoot / Pca.VerifyInclusion) ----

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

    /// <summary>The inclusion proof of leaf <paramref name="index"/> in a tree over <paramref name="leaves"/> (<c>{index, size, path}</c>).</summary>
    public static JD MerkleProof(IReadOnlyList<object?> leaves, long index)
    {
        if (index < 0 || index >= leaves.Count) throw new ArgumentOutOfRangeException(nameof(index), "merkleProof: index out of range");
        var path = new JL();
        Prove(leaves.Select(Pca.LeafHash).ToList(), index, path);
        return new JD { ["index"] = G.N(index), ["size"] = G.N(leaves.Count), ["path"] = path };
    }

    // ---- the decision log ----

    /// <summary>Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs.</summary>
    public sealed class DecisionLog
    {
        readonly List<JD> recs = new();
        readonly EdKey key;
        readonly IReadOnlyCollection<string> mask;

        public DecisionLog(EdKey key, IReadOnlyCollection<string>? maskClasses = null) { this.key = key; mask = maskClasses ?? Array.Empty<string>(); }

        public int Size => recs.Count;

        static string Commit(JD r) => K3.RecordCommit(r) ?? throw new InvalidOperationException("recordCommit: not canonical");

        /// <summary>Mask, then chain: <c>{v: 1, ...masked, seq, prev}</c> (seq and prev override a caller's).</summary>
        public JD Append(JD record)
        {
            var masked = MaskRecord(record, mask);
            var rec = new JD { ["v"] = new Num("1") };
            foreach (var kv in masked) rec[kv.Key] = kv.Value;
            rec["seq"] = G.N(recs.Count);
            rec["prev"] = recs.Count > 0 ? Commit(recs[^1]) : "";
            recs.Add(rec);
            return rec;
        }

        public JD Head(long now)
        {
            var commits = recs.Select(r => (object?)Commit(r)).ToList();
            var b = new JD
            {
                ["v"] = new Num("1"), ["size"] = G.N(recs.Count), ["root"] = Pca.MerkleRoot(commits),
                ["last_commit"] = recs.Count > 0 ? Commit(recs[^1]) : "", ["issued_at"] = G.N(now), ["signer"] = key.Id,
            };
            var h = new JD(b);
            h["sig"] = Sig.SignBody(K3.LogHeadDomain, b, key);
            return h;
        }

        public JD Proof(long seq) => MerkleProof(recs.Select(r => (object?)Commit(r)).ToList(), seq);

        /// <summary>Records <c>[from, to)</c> (the array slice: out-of-range ends clamp).</summary>
        public List<JD> Slice(long from, long to)
        {
            var f = (int)Math.Clamp(from, 0, recs.Count);
            var t = (int)Math.Clamp(to, 0, recs.Count);
            return t > f ? recs.GetRange(f, t - f) : new List<JD>();
        }
    }

    /// <summary>The next batch of at most <paramref name="max"/> records from the cursor <paramref name="from"/>, with a freshly signed head.</summary>
    public static JD NextBatch(DecisionLog log, long from, long max, long now)
    {
        if (from < 0 || max < 1) throw new ArgumentOutOfRangeException(nameof(from), "nextBatch: bad cursor or size");
        return new JD { ["from"] = G.N(from), ["records"] = log.Slice(from, from + max).Cast<object?>().ToList(), ["head"] = log.Head(now) };
    }

    // ---- replay ----

    static readonly Dictionary<string, int> Rank = new() { ["deny"] = 0, ["escalate"] = 1, ["allow"] = 2 };

    /// <summary>"What would have changed": the cases whose decision differs between two decide functions (an unknown decision is never wider).</summary>
    public static List<JD> SemanticDiff(IEnumerable<(string ActionDigest, object? Input)> cases, Func<object?, string?> oldDecide, Func<object?, string?> newDecide)
    {
        var o = new List<JD>();
        foreach (var (ad, input) in cases)
        {
            var before = oldDecide(input);
            var after = newDecide(input);
            if (before == after) continue;
            var widened = before != null && after != null && Rank.TryGetValue(before, out var rb) && Rank.TryGetValue(after, out var ra) && ra > rb;
            var e = new JD { ["action_digest"] = ad };
            if (before != null) e["before"] = before;
            if (after != null) e["after"] = after;
            e["direction"] = widened ? "widened" : "tightened";
            o.Add(e);
        }
        return o;
    }

    /// <summary>Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift).</summary>
    public static List<JD> AuditReplay(IEnumerable<JD> records, IEnumerable<(string ActionDigest, object? Input)> cases, Func<object?, long, string?> decide)
    {
        var byAction = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (ad, input) in cases) byAction[ad] = input;
        var o = new List<JD>();
        foreach (var r in records)
            if (IntentJs.Get(r, "action_digest") is string ad && byAction.TryGetValue(ad, out var input) && decide(input, G.L(IntentJs.Get(r, "bundle_revision"))) != IntentJs.Get(r, "decision") as string)
                o.Add(r);
        return o;
    }
}
