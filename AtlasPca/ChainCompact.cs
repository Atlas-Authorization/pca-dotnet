// Chain compaction (the reference chain-compact.ts), the cheap pre-authentication chain check and the holder PQ key. A long delegation chain folds
// into one handle: a Merkle root over the ordered hop hashes plus the leaf hop. The verifier that has verified the full chain once remembers it
// under that root; later presentations carry only {depth, hops_root, leaf}. Nothing is trusted from the presentation: a compact chain is accepted
// only when the verifier's OWN memo holds an entry its own full VerifyChain produced for hops_root, the depth equals the memoized depth and the
// presented leaf hashes to the memoized last hop. The caveat language accepts the resulting ChainView in place of the full chain.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>What the caveat language needs to know about a chain: the hop count, the leaf and, per hop, its hash and the length of its (cumulative)
/// caveat list. A full chain gives it directly (<see cref="CaveatLang.ChainViewOf"/>); a compact chain gives it from a verified memo.</summary>
public sealed class ChainView
{
    public int N { get; }
    public object? Leaf { get; }
    readonly Func<int, string> _hash;
    readonly Func<int, int> _count;
    public ChainView(int n, object? leaf, Func<int, string> hash, Func<int, int> count) { N = n; Leaf = leaf; _hash = hash; _count = count; }
    public string Hash(int i) => _hash(i);
    public int Count(int i) => _count(i);
}

/// <summary>The result of <see cref="ChainMemo.Resolve"/>: a view, or a reason.</summary>
public sealed record ChainResolve(bool Ok, ChainView? View = null, string? Reason = null);

public static class ChainCompact
{
    public const string HopDomain = "atlas-pca/chain-hop/v1";
    /// <summary>A memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time).</summary>
    public const long MemoMaxTtlMs = 3_600_000;
    public const int MemoDefaultMaxEntries = 10_000;

    /// <summary>The Merkle leaf of one hop: its content hash under a domain tag.</summary>
    public static JD HopLeaf(object? hop) => new() { ["d"] = HopDomain, ["hop"] = Pca.CapHash(hop) };

    /// <summary>The handle of a chain: the Merkle root over the ordered hop leaves.</summary>
    public static string HopsRoot(IReadOnlyList<object?> chain) => Pca.MerkleRoot(chain.Select(h => (object?)HopLeaf(h)).ToList());

    /// <summary>Fold a chain (root first). Throws on an empty or over-deep chain. Does not verify it (the memo does).</summary>
    public static JD CompactChain(IReadOnlyList<object?> chain)
    {
        if (chain == null || chain.Count == 0 || chain.Count > Pca.MaxChainHops) throw new ArgumentException("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops");
        return new JD
        {
            ["v"] = new Num("1"), ["kind"] = "pca-chain-compact", ["depth"] = new Num(chain.Count.ToString()), ["hops_root"] = HopsRoot(chain), ["leaf"] = chain[^1],
        };
    }

    /// <summary>Null when the compact chain is well formed.</summary>
    public static string? CompactChainShapeError(object? c)
    {
        if (c is not JD d) return "not an object";
        var e = IntentArtifacts.ClosedMembers(d, new[] { "v", "kind", "depth", "hops_root", "leaf" }, Array.Empty<string>(), "compact chain");
        if (e != null) return e;
        if (!(IntentJs.NumOf(d["v"]) == 1.0) || d["kind"] as string != "pca-chain-compact") return "not a pca-chain-compact v1";
        if (!(IntentJs.IsSafeInteger(d["depth"]) && IntentJs.NumOf(d["depth"]) is >= 1 and <= Pca.MaxChainHops)) return $"depth must be 1..{Pca.MaxChainHops}";
        if (d["hops_root"] is not string hr || hr.Length != 43) return "hops_root must be a 43 character digest";
        if (d["leaf"] is not JD) return "leaf must be a capability";
        return null;
    }

    /// <summary>The view of a full chain, for symmetry with <see cref="ChainMemo.Resolve"/> (both feed the caveat language).</summary>
    public static ChainView ViewOfChain(object? grant, object? chain) => CaveatLang.ChainViewOf(grant, chain);
}

/// <summary>The verifier-side memo of verified chains. It remembers a chain only after running the full verifier itself, never evicts a live entry
/// when full (one tenant cannot push another out) and resolves a presented compact chain without its middle hops.</summary>
public sealed class ChainMemo
{
    sealed record Entry(int Depth, string[] Hashes, int[] Counts, long ExpiresAt);

    readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    readonly object _lock = new();
    readonly int _max;
    readonly long _ttl;

    public ChainMemo(int maxEntries = ChainCompact.MemoDefaultMaxEntries, long ttlMs = ChainCompact.MemoMaxTtlMs)
    {
        _max = maxEntries;
        _ttl = Math.Min(ttlMs, ChainCompact.MemoMaxTtlMs);
    }

    public int Size { get { lock (_lock) return _entries.Count; } }

    /// <summary>Verify <paramref name="chain"/> (rooted at <paramref name="expectedRootIssuer"/>) with the full verifier and remember it. Throws when the
    /// chain does not verify or the memo is full of live entries (fail closed). Returns the compact form a holder presents.</summary>
    public JD RememberVerified(JL chain, string expectedRootIssuer, long now, IReadOnlyCollection<string>? allowedSuites = null,
        IReadOnlyDictionary<string, string>? pqPins = null, JD? trustedRoot = null)
    {
        if (Math.Abs(now) > Pca.MaxSafeInt) throw new ArgumentException("rememberVerified: the clock is not a safe integer");
        var (why, ok) = Pca.VerifyChain(chain, expectedRootIssuer, true, allowedSuites, pqPins, trustedRoot);
        if (!ok) throw new ArgumentException($"rememberVerified: the chain does not verify: {(why.Length == 0 ? "invalid" : why)}");
        var compact = ChainCompact.CompactChain(chain);
        var root = (string)compact["hops_root"]!;
        lock (_lock)
        {
            PruneLocked(now);
            if (!_entries.ContainsKey(root) && _entries.Count >= _max) throw new InvalidOperationException("rememberVerified: the memo is full of live entries");
            _entries[root] = new Entry(chain.Count, chain.Select(h => Pca.CapHash(h)).ToArray(),
                chain.Select(h => h is JD hm && hm.GetValueOrDefault("caveats") is JL cs ? cs.Count : 0).ToArray(), now + _ttl);
        }
        return compact;
    }

    /// <summary>Drop entries whose time is up.</summary>
    public void Prune(long now) { lock (_lock) PruneLocked(now); }

    void PruneLocked(long now) { foreach (var k in _entries.Where(kv => kv.Value.ExpiresAt < now).Select(kv => kv.Key).ToList()) _entries.Remove(k); }

    /// <summary>Forget a chain (e.g. when it is revoked).</summary>
    public bool Forget(string hopsRoot) { lock (_lock) return _entries.Remove(hopsRoot); }

    /// <summary>Resolve a presented compact chain against the memo. Total.</summary>
    public ChainResolve Resolve(object? compact, long now)
    {
        try
        {
            if (Math.Abs(now) > Pca.MaxSafeInt) return new(false, Reason: "the verifier clock is not a safe integer (fail closed)");
            var e = ChainCompact.CompactChainShapeError(compact);
            if (e != null) return new(false, Reason: $"malformed compact chain: {e}");
            var c = (JD)compact!;
            Entry? m;
            lock (_lock)
            {
                _entries.TryGetValue((string)c["hops_root"]!, out m);
                if (m != null && m.ExpiresAt < now)
                {
                    _entries.Remove((string)c["hops_root"]!);
                    return new(false, Reason: "the memoized chain has expired (present the full chain)");
                }
            }
            if (m == null) return new(false, Reason: "the chain is not in this verifier memo (present the full chain)");
            if (m.Depth != (int)IntentJs.NumOf(c["depth"])!.Value) return new(false, Reason: "the depth differs from the memoized chain");
            var leaf = (JD)c["leaf"]!;
            if (Pca.CapHash(leaf) != m.Hashes[m.Depth - 1]) return new(false, Reason: "the leaf is not the memoized last hop");
            if (leaf.GetValueOrDefault("caveats") is not JL lc || lc.Count != m.Counts[m.Depth - 1]) return new(false, Reason: "the leaf caveats differ from the memoized chain");
            return new(true, new ChainView(m.Depth, leaf, i => m.Hashes[i], i => m.Counts[i]));
        }
        catch (Exception err) { return new(false, Reason: $"compact chain error (fail closed): {err.Message}"); }
    }
}

public static partial class Pca
{
    /// <summary>The PQ verification key (b64u) for a signature by <paramref name="holder"/> (a chain leaf or threshold share) under suite <paramref name="alg"/>:
    /// the artifact's <c>pq_pk</c> only when it is the key the holder's <c>holder_pq</c> commitment names (the key-resolution choke point). Null for ed25519
    /// and for an unknown suite, and null (so the signature check fails closed) when the artifact's key is not the committed one.</summary>
    public static string? HolderPqKey(object? alg, string holder, object? artifactPqPk, string? holderPq)
    {
        var name = alg ?? "ed25519";
        if (name is not string a || !Pq.RegisteredSuites.Contains(a) || a == "ed25519") return null;
        return PinnedPq.Resolve(holder, artifactPqPk, holderPq)?.Key;
    }

    /// <summary>The CHEAP chain check for a gate that runs BEFORE authentication: only work that is cheap and a NECESSARY condition of
    /// <see cref="VerifyChain"/> (shape, caveat caps, depth, suite allowlist, body digest, parent links, issuer == parent holder, root issuer, and the Ed25519 half of
    /// every hop that has one). No post-quantum verification runs and no PQ key is resolved, so the cost is at most <see cref="MaxChainHops"/> Ed25519 verifications.
    /// A pure-PQ hop has no Ed25519 half and passes on structure alone. <c>Ok</c> is NEVER an authentication; <c>PqHops</c> counts the hops that still need PQ verification.</summary>
    public static (bool Ok, int PqHops, string? Reason) VerifyChainCheap(object? chain, string? expectedRootIssuer = null, IReadOnlyCollection<string>? allowedSuites = null)
    {
        try
        {
            var arr = chain as List<object?> ?? new List<object?>();
            if (arr.Count == 0) return (false, 0, "empty chain");
            if (arr.Count > MaxChainHops) return (false, 0, $"chain too long (max {MaxChainHops} hops)");
            if (CaveatLimitExceeded(arr)) return (false, 0, CaveatLimitReason);
            var pqHops = 0;
            for (var i = 0; i < arr.Count; i++)
            {
                var label = $"hop {i}";
                if (!WellTyped(arr[i])) return (false, 0, $"{label}: malformed capability");
                var c = (JD)arr[i]!;
                var alg = Get(c, "alg");
                var suite = alg ?? "ed25519";
                if (suite is not string name || !Pq.RegisteredSuites.Contains(name)) return (false, 0, $"{label}: unknown signature alg '{alg}'");
                var pol = SuitePolicyError(alg, label, allowedSuites);
                if (pol != null) return (false, 0, pol);
                if (i == 0)
                {
                    if (Has(c, "parent")) return (false, 0, "hop 0: root must not have a parent");
                    if (expectedRootIssuer != null && !StrEq(Get(c, "issuer"), expectedRootIssuer)) return (false, 0, "hop 0: root issuer is not the expected principal");
                }
                else
                {
                    var parent = (JD)arr[i - 1]!;
                    if (!StrEq(Get(c, "parent"), CapHash(parent))) return (false, 0, $"{label}: broken parent link");
                    if (!StrEq(Get(c, "issuer"), Get(parent, "holder"))) return (false, 0, $"{label}: issuer is not the parent's bound holder");
                }
                var needsPq = name != "ed25519";
                var body = new JD { ["issuer"] = Get(c, "issuer"), ["holder"] = Get(c, "holder"), ["caveats"] = Get(c, "caveats"), ["parent"] = Get(c, "parent") };
                if (Get(c, "holder_pq") is string hpq) body["holder_pq"] = hpq;
                if (needsPq)
                {
                    body["alg"] = name;
                    if (Get(c, "pq_pk") is string pk) body["pq_pk"] = pk;
                }
                string digest;
                try { digest = HashCanonical(body); } catch { return (false, 0, $"{label}: malformed body"); }
                var bd = Get(c, "body_digest") as string;
                if (digest != bd || Get(c, "id") as string != bd) return (false, 0, $"{label}: body digest mismatch");
                if (name == "ed25519" || name.StartsWith("hybrid-", StringComparison.Ordinal))
                {
                    var signer = i == 0 ? Get(c, "issuer") : Get((JD)arr[i - 1]!, "holder");
                    var d = B64uDecode(bd, 32);
                    if (d == null || !VerifyB64u(signer, Cat(Encoding.UTF8.GetBytes(CapDomain), d), Get(c, "sig"))) return (false, 0, $"{label}: bad signature (not signed by expected key)");
                }
                if (needsPq) pqHops++;
            }
            return (true, pqHops, null);
        }
        catch (Exception e) { return (false, 0, $"malformed capability chain: {e.GetType().Name}"); }
    }
}
