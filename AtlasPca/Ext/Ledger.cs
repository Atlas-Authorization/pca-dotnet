// Transparency-ledger verification (extension layer): RFC 6962 inclusion of ledger commits, RFC 9162 consistency, guardian-signed
// tree heads, witness cosignatures, head-to-head consistency, checkpoint chains and legacy witnessed heads. Inputs are parsed JSON
// values so a hostile wire object cannot throw out of any function here: every verifier returns false on malformed input.
// Suite-agile like ledger.ts: ed25519 (alg absent) plus every suite IntentJs.VerifyPinnedSuite verifies (PQ / hybrid only under a pinned PQ key); an alg the SDK cannot verify is refused (false).
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The result of <see cref="Ledger.VerifyCheckpointChain"/>: Ok, or At = index of the first checkpoint that fails.</summary>
public readonly record struct CheckpointVerdict(bool Ok, int At);

public static class Ledger
{
    public const string SthDomain = "atlas-pca/sth/v1\0";
    public const string SthWitnessDomain = "atlas-pca/sth-witness/v2\0";
    public const string LedgerHeadDomain = "atlas-pca/ledger-head/v1\0";
    /// <summary>The longest consistency path any tree of fewer than 2^53 leaves can need (2*53+1), plus one of slack as the reference.</summary>
    public const int MaxConsistencyPath = 2 * 53 + 2;

    /// <summary>The root of the empty tree (RFC 9162 2.1.1: SHA-256 of the empty string), base64url.</summary>
    public static readonly string EmptyTreeRoot = Pca.B64u(Pca.Sha256Of(Array.Empty<byte>()));

    static byte[] NodeHash(byte[] l, byte[] r) => Pca.Sha256Of(new byte[] { 0x01 }, l, r);

    static bool SafeInt(object? v, out double f)
    {
        f = IntentJs.NumOf(v) ?? double.NaN;
        return IntentJs.IsSafeInteger(v);
    }


    /// <summary>Suite-agile signature check (TS verifyPinnedSuite): the artifact's own alg (absent = ed25519) is bound into the signed
    /// body, ed25519 verifies under <paramref name="pub"/>, a PQ / hybrid suite only under the PQ key <paramref name="pins"/> pins for
    /// <paramref name="pub"/>. An alg this SDK cannot verify is refused. Never throws.</summary>
    static bool Signed(string pub, string domain, D body, D art, IReadOnlyDictionary<string, string>? pins)
    {
        try
        {
            if (art.GetValueOrDefault("sig") is not string) return false;
            bool ap = art.ContainsKey("alg");
            var msg = IntentJs.Message(domain, IntentJs.BindSuiteFields(body, art.GetValueOrDefault("alg"), ap, art.GetValueOrDefault("pq_pk"), art.ContainsKey("pq_pk")));
            return IntentJs.VerifyPinnedSuite(art.GetValueOrDefault("alg"), ap, pub, art.GetValueOrDefault("pq_pk"), msg, art["sig"], art.GetValueOrDefault("pq_sig"), pins);
        }
        catch (Exception) { return false; }
    }

    /// <summary>The PQ pins a witness policy carries (<c>pqPins</c>: identity b64u to ML-DSA key b64u), or null.</summary>
    static IReadOnlyDictionary<string, string>? PinsOf(D? policy) =>
        policy?.GetValueOrDefault("pqPins") is D p ? p.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>Copies the named members; null when one is absent (the reference throws on undefined).</summary>
    static D? Pick(D m, params string[] keys)
    {
        var o = new D();
        foreach (var k in keys)
        {
            if (!m.TryGetValue(k, out var v)) return null;
            o[k] = v;
        }
        return o;
    }

    /// <summary>JavaScript === on JSON values (compared through their canonical form; both must be canonicalizable).</summary>
    internal static bool Same(object? a, object? b)
    {
        try { return Pca.Canonicalize(a) == Pca.Canonicalize(b); }
        catch (Exception) { return false; }
    }

    /// <summary>Checks a ledger commit (string leaf) against a root with an RFC 6962 inclusion proof.</summary>
    public static bool VerifyLedgerInclusion(string root, object? proof, object? commit)
    {
        try { return proof is D p && Pca.VerifyInclusion(root, p, commit); }
        catch (Exception) { return false; }
    }

    /// <summary>RFC 9162 2.1.4.2 consistency verification. Sizes are JSON safe integers; the index arithmetic is done in ulong so
    /// sizes 3 and 3+2^32 never collide. Size 0 pins oldRoot to the empty-tree root and requires an empty path.</summary>
    public static bool VerifyLedgerConsistency(object? oldRoot, object? newRoot, object? proof)
    {
        try
        {
            if (oldRoot is not string oldR || newRoot is not string nr || proof is not D p) return false;
            if (!SafeInt(p.GetValueOrDefault("oldSize"), out var ff) || !SafeInt(p.GetValueOrDefault("newSize"), out var sf)
                || p.GetValueOrDefault("path") is not L rawPath || ff < 0 || ff > sf || rawPath.Count > MaxConsistencyPath) return false;
            ulong first = (ulong)ff, second = (ulong)sf;
            if (first == 0)
            {
                if (rawPath.Count != 0 || oldR != EmptyTreeRoot) return false;
                return second == 0 ? nr == EmptyTreeRoot : true; // vacuous for a non-empty new tree
            }
            if (first == second) return rawPath.Count == 0 && oldR == nr;
            var path = new List<byte[]>();
            if ((first & (first - 1)) == 0)
            {
                var h = Pca.B64uDecode(oldR);
                if (h == null) return false;
                path.Add(h);
            }
            foreach (var e in rawPath)
            {
                var h = e is string s ? Pca.B64uDecode(s) : null;
                if (h == null) return false;
                path.Add(h);
            }
            if (path.Count == 0) return false;
            ulong fn = first - 1, sn = second - 1;
            while ((fn & 1) == 1) { fn >>= 1; sn >>= 1; }
            byte[] fr = path[0], sr = path[0];
            foreach (var c in path.Skip(1))
            {
                if (sn == 0) return false;
                if ((fn & 1) == 1 || fn == sn)
                {
                    fr = NodeHash(c, fr);
                    sr = NodeHash(c, sr);
                    while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
                }
                else sr = NodeHash(sr, c);
                fn >>= 1; sn >>= 1;
            }
            return sn == 0 && Pca.B64u(fr) == oldR && Pca.B64u(sr) == nr;
        }
        catch (Exception) { return false; }
    }

    /// <summary>Verifies a legacy witnessed head {principal,size,root,witness,sig} against the witness key.</summary>
    public static bool VerifyWitnessedHead(object? wh, string witnessPublic, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (wh is not D m) return false;
        if (m.GetValueOrDefault("witness") as string != witnessPublic) return false;
        var body = Pick(m, "principal", "size", "root");
        return body != null && Signed(witnessPublic, LedgerHeadDomain, body, m, pins);
    }

    /// <summary>True when a and b are both validly witnessed by the witness for the same principal and size but carry different roots.</summary>
    public static bool DetectEquivocation(object? a, object? b, string witnessPublic, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (a is not D am || b is not D bm || !VerifyWitnessedHead(a, witnessPublic, pins) || !VerifyWitnessedHead(b, witnessPublic, pins)) return false;
        var asz = IntentJs.NumOf(am.GetValueOrDefault("size")); var bsz = IntentJs.NumOf(bm.GetValueOrDefault("size"));
        return Same(am.GetValueOrDefault("principal"), bm.GetValueOrDefault("principal")) && asz == bsz && am.GetValueOrDefault("root") as string != bm.GetValueOrDefault("root") as string;
    }

    /// <summary>Verifies one cosignature of a tree head under a trusted witness key, bound to the head's {instance_id, principal,
    /// size, root, prev_root, guardian_epoch (absent or null = 0)}.</summary>
    public static bool VerifyWitnessCosignature(object? sth, object? cosig, string witnessPublic, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (sth is not D sm || cosig is not D cm) return false;
        if (cm.GetValueOrDefault("key") as string != witnessPublic) return false;
        var body = Pick(sm, "instance_id", "principal", "size", "root", "prev_root");
        if (body == null) return false;
        body["guardian_epoch"] = sm.TryGetValue("guardian_epoch", out var e) && e != null ? e : IntentJs.OfLong(0);
        return Signed(witnessPublic, SthWitnessDomain, body, cm, pins);
    }

    /// <summary>The k-of-n check: at least policy.threshold DISTINCT trusted witnesses (policy witnessKeys) carry a valid cosignature over
    /// this exact head. Unknown, duplicate and mis-bound cosignatures do not count; threshold 0 is vacuously met; a non-integer or
    /// negative threshold fails.</summary>
    public static bool VerifyWitnessCosignatures(object? sth, D? policy, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (sth is not D sm || policy == null) return false;
        if (IntentJs.NumOf(policy.GetValueOrDefault("threshold")) is not double tf || tf != Math.Truncate(tf) || tf < 0) return false;
        if (tf == 0) return true;
        pins ??= PinsOf(policy);
        var trusted = (policy.GetValueOrDefault("witnessKeys") as L ?? new L()).OfType<string>().ToHashSet(StringComparer.Ordinal);
        if (trusted.Count == 0) return false;
        if (sm.GetValueOrDefault("witnesses") is not L ws) return false;
        var counted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var w in ws)
        {
            if (w is not D wm || wm.GetValueOrDefault("key") is not string key || wm.GetValueOrDefault("sig") is not string) continue;
            if (!trusted.Contains(key) || counted.Contains(key)) continue;
            if (!VerifyWitnessCosignature(sth, w, key, pins)) continue;
            counted.Add(key);
            if (counted.Count >= tf) return true;
        }
        return counted.Count >= tf;
    }

    /// <summary>Verifies a guardian-signed tree head against the pinned guardian key: the head names that guardian, its size is a
    /// non-negative safe integer, the signature covers {instance_id, principal, size, root, prev_root, timestamp}, and, when
    /// <paramref name="policy"/> is non-null, enough trusted witnesses cosigned it.</summary>
    public static bool VerifyTreeHead(object? sth, string guardianPublic, D? policy, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (sth is not D m) return false;
        if (m.GetValueOrDefault("guardian") as string != guardianPublic) return false;
        if (!SafeInt(m.GetValueOrDefault("size"), out var sz) || sz < 0) return false;
        var body = Pick(m, "instance_id", "principal", "size", "root", "prev_root", "timestamp");
        if (body == null || !Signed(guardianPublic, SthDomain, body, m, pins)) return false;
        return policy == null || VerifyWitnessCosignatures(sth, policy, pins);
    }

    /// <summary>Both heads are genuine for the pinned guardian, belong to the same instance and log, the proof connects exactly their
    /// sizes, the signed prev_root equals older.root when the heads are adjacent, and the RFC 9162 path verifies.</summary>
    public static bool VerifyHeadConsistency(object? older, object? newer, object? proof, string guardianPublic, D? policy, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (!VerifyTreeHead(older, guardianPublic, policy, pins) || !VerifyTreeHead(newer, guardianPublic, policy, pins)) return false;
        var om = (D)older!; var nm = (D)newer!;
        if (proof is not D pm || !Same(om.GetValueOrDefault("instance_id"), nm.GetValueOrDefault("instance_id")) || !Same(om.GetValueOrDefault("principal"), nm.GetValueOrDefault("principal"))) return false;
        var os = IntentJs.NumOf(om.GetValueOrDefault("size")); var ns = IntentJs.NumOf(nm.GetValueOrDefault("size"));
        var ps = IntentJs.NumOf(pm.GetValueOrDefault("oldSize")); var pn = IntentJs.NumOf(pm.GetValueOrDefault("newSize"));
        if (ps == null || pn == null || ps != os || pn != ns) return false;
        if (ns == os + 1 && !Same(nm.GetValueOrDefault("prev_root"), om.GetValueOrDefault("root"))) return false;
        return VerifyLedgerConsistency(om.GetValueOrDefault("root"), nm.GetValueOrDefault("root"), proof);
    }

    /// <summary>Verifies pinned checkpoints end to end: every head is genuine (and witnessed when policy is non-null), the first needs
    /// no proof, every later one carries a consistency proof from the checkpoint before. An empty or non-array chain fails at 0.</summary>
    public static CheckpointVerdict VerifyCheckpointChain(object? chain, string guardianPublic, D? policy, IReadOnlyDictionary<string, string>? pins = null)
    {
        if (chain is not L cs || cs.Count == 0) return new(false, 0);
        object? prev = null;
        for (int i = 0; i < cs.Count; i++)
        {
            if (cs[i] is not D cm || !VerifyTreeHead(cm.GetValueOrDefault("sth"), guardianPublic, policy, pins)) return new(false, i);
            if (i > 0)
            {
                var pr = cm.GetValueOrDefault("proof");
                if (pr == null || pr is false) return new(false, i);
                if (!VerifyHeadConsistency(prev, cm["sth"], pr, guardianPublic, policy, pins)) return new(false, i);
            }
            prev = cm["sth"];
        }
        return new(true, 0);
    }
}
