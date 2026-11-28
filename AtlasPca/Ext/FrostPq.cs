// Post-quantum agility for the FROST guardian-quorum co-sign (interim hybrid) and the ML-DSA-65 co-signer quorum (format version 2).
//
// The FROST aggregate is a plain Ed25519 signature under the group key, so the whole guardian-quorum path rests on the discrete-log hardness of Ed25519. The hybrid keeps that
// aggregate and adds an ML-DSA-65 co-signature by the guardian key over a representative that binds the group key, sha256(message), the signer set and the suite, so a quantum
// adversary must break BOTH. Verification is fail-closed (edOk && pqOk); an artifact that declares hybrid and lacks a valid co-signature is denied (no silent downgrade).
// This is NOT a post-quantum threshold signature: the ML-DSA half is minted by one guardian key. Values are the JSON tree (an absent member is a missing key).
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class FrostPq
{
    public const string Ed25519Alg = "ed25519", HybridAlg = "hybrid-ed25519-ml-dsa-65";
    /// <summary>The suite used when the artifact names none: classical FROST only. Must stay ed25519 for back-compat.</summary>
    public const string DefaultFrostGroupAlg = Ed25519Alg;
    public const int PqQuorumVersion = 2, MaxPqQuorumEntries = 256;
    public const string PqQuorumAlg = "ml-dsa-65";
    const int MlDsa65PublicKeyBytes = 1952;
    const string CosignDomain = "atlas-pca/frost-pq-cosign/v1\0", SignerSetDomain = "atlas-pca/frost-signer-set/v1\0", QuorumDomain = "atlas-pca/pq-quorum/v2\0";

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    static bool IsKnown(object? x) => x is string s && (s == Ed25519Alg || s == HybridAlg);

    /// <summary>The artifact's groupAlg (absent means the default); null for an unknown value (fail-closed).</summary>
    public static string? ResolveFrostGroupAlg(object? groupAlg, bool present = true) => !present ? DefaultFrostGroupAlg : IsKnown(groupAlg) ? (string)groupAlg! : null;

    /// <summary>sha256(DOMAIN || canonical(sorted-distinct ids)): order-insensitive and duplicate-free. An empty set, or an id that is not a positive safe integer, is refused.</summary>
    public static byte[] FrostSignerSetDigest(object? signerSet)
    {
        if (signerSet is not L list || list.Count == 0) throw new ArgumentException("frostSignerSetDigest: empty signer set");
        var ids = new List<double>();
        foreach (var x in list)
        {
            if (x is string || !IntentJs.IsSafeInteger(x) || IntentJs.NumOf(x)!.Value <= 0) throw new ArgumentException("frostSignerSetDigest: participant identifiers must be positive safe integers");
            var d = IntentJs.NumOf(x)!.Value;
            if (!ids.Contains(d)) ids.Add(d);
        }
        ids.Sort();
        return SHA256.HashData(Cat(Utf8(SignerSetDomain), Pca.Canon(ids.Select(d => (object?)(long)d).ToList())));
    }

    /// <summary>The exact bytes the guardian ML-DSA-65 co-signature covers: DOMAIN || groupAlg || 0x00 || groupPublicKey(32) || sha256(message) || signerSetDigest(32).</summary>
    public static byte[] FrostCosignRepresentative(object? groupPublicKeyB64u, byte[] message, object? signerSet, string? groupAlg)
    {
        var gpk = Pca.B64uDecode(groupPublicKeyB64u, 32) ?? throw new ArgumentException("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point");
        ArgumentNullException.ThrowIfNull(message);
        return Cat(Utf8(CosignDomain), Utf8(groupAlg ?? "null"), [0], gpk, SHA256.HashData(message), FrostSignerSetDigest(signerSet));
    }

    /// <summary>The options of <see cref="SignHybridFrostCosign"/>: <c>GroupAlg</c> (null = ed25519), the guardian's ML-DSA-65 key pair (required for hybrid) and an optional quorum threshold.</summary>
    public sealed class HybridCosignOpts
    {
        public string? GroupAlg;
        public PqKeyPair? GuardianMlDsa;
        public int? Threshold;
    }

    /// <summary>Runs the classical FROST round over the quorum (every safety check on) and, for the hybrid suite, adds the guardian's ML-DSA-65 co-signature. Returns {sig} or {sig, groupAlg, pq_sig, pq_pk}.
    /// A hybrid suite without a guardian key throws: a signer never silently emits a weaker artifact than it meant to.</summary>
    public static D SignHybridFrostCosign(byte[] groupPublicKey, List<Frost.FrostParticipantShare> quorum, byte[] message, HybridCosignOpts? opts = null)
    {
        opts ??= new HybridCosignOpts();
        var groupAlg = opts.GroupAlg ?? DefaultFrostGroupAlg;
        if (!IsKnown(groupAlg)) throw new ArgumentException($"signHybridFrostCosign: unknown groupAlg '{groupAlg}'");
        var aggregate = Frost.Cosign(groupPublicKey, quorum, message, opts.Threshold);
        var sig = Pca.B64u(aggregate);
        if (groupAlg == Ed25519Alg) return new D { ["sig"] = sig };
        if (opts.GuardianMlDsa == null) throw new ArgumentException($"signHybridFrostCosign: '{groupAlg}' requires a guardian ML-DSA-65 key pair");
        var rep = FrostCosignRepresentative(Pca.B64u(groupPublicKey), message, quorum.Select(p => (object?)p.Identifier).ToList(), groupAlg);
        return new D { ["sig"] = sig, ["groupAlg"] = groupAlg, ["pq_sig"] = Pca.B64u(PqSuites.MlDsa65Sign(opts.GuardianMlDsa.SecretKey, rep)), ["pq_pk"] = Pca.B64u(opts.GuardianMlDsa.PublicKey) };
    }

    static D Deny(string reason, string? groupAlg = null)
    {
        var d = new D { ["ok"] = false, ["edOk"] = false, ["pqOk"] = false };
        if (groupAlg != null) d["groupAlg"] = groupAlg;
        d["reason"] = reason;
        return d;
    }

    static object? Member(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);

    /// <summary>Verify a hybrid FROST guardian co-sign. Fail-closed: for the hybrid suite BOTH the Ed25519 group signature and the ML-DSA-65 co-signature (under the REGISTERED guardian key, never the artifact's
    /// own pq_pk) must verify. Total: never throws. <paramref name="opts"/> carries guardianPqPublicKey and expectGroupAlg (a pinned suite: a downgrade is denied).</summary>
    public static D VerifyHybridFrostCosign(object? artifact, byte[] message, object? groupPublicKeyB64u, object? signerSet, object? opts = null)
    {
        if (artifact is not D art || art.GetValueOrDefault("sig") is not string) return Deny("malformed artifact");
        if (groupPublicKeyB64u is not string gpkS || Pca.B64uDecode(gpkS, 32) == null) return Deny("malformed group public key");
        var groupAlg = ResolveFrostGroupAlg(art.GetValueOrDefault("groupAlg"), art.ContainsKey("groupAlg"));
        if (groupAlg == null) return Deny($"unknown groupAlg '{JsJson.ToJsString(art["groupAlg"])}'");
        if (Has(opts, "expectGroupAlg"))
        {
            var want = Member(opts, "expectGroupAlg");
            if (!IsKnown(want)) return Deny($"unknown expected groupAlg '{JsJson.ToJsString(want)}'");
            if ((string)want! != groupAlg) return Deny($"groupAlg '{groupAlg}' does not match the required '{want}'", groupAlg);
        }
        bool edOk;
        try { edOk = Pca.VerifyEdInternal(gpkS, message, art["sig"]); } catch (Exception) { edOk = false; }
        if (groupAlg == Ed25519Alg) return edOk ? new D { ["ok"] = true, ["groupAlg"] = groupAlg, ["edOk"] = true, ["pqOk"] = false } : Deny("FROST Ed25519 group signature did not verify", groupAlg);

        var registered = Member(opts, "guardianPqPublicKey");
        if (registered is not string reg || Pca.B64uDecode(reg, MlDsa65PublicKeyBytes) == null) return Deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", groupAlg);
        if (art.ContainsKey("pq_pk") && !(art["pq_pk"] is string pk && pk == reg)) return Deny("artifact pq_pk does not match the registered guardian ML-DSA key", groupAlg);
        if (art.GetValueOrDefault("pq_sig") is not string) return Deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", groupAlg);
        bool pqOk;
        try { pqOk = PqSuites.MlDsa65VerifyB64u(reg, FrostCosignRepresentative(gpkS, message, signerSet, groupAlg), art["pq_sig"]); } catch (Exception) { pqOk = false; }
        if (!edOk || !pqOk) return new D { ["ok"] = false, ["groupAlg"] = groupAlg, ["edOk"] = edOk, ["pqOk"] = pqOk, ["reason"] = !edOk ? "FROST Ed25519 group signature did not verify" : "guardian ML-DSA-65 co-signature did not verify" };
        return new D { ["ok"] = true, ["groupAlg"] = groupAlg, ["edOk"] = true, ["pqOk"] = true };
    }

    // ---- ML-DSA-65 co-signer quorum (pqT-of-m multi-signature), format version 2 ----

    /// <summary>The bytes every quorum co-signature covers: DOMAIN || sha256(message).</summary>
    public static byte[] PqQuorumRepresentative(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Cat(Utf8(QuorumDomain), SHA256.HashData(message));
    }

    /// <summary>One ML-DSA-65 co-signature per key pair over the representative. <paramref name="pqT"/> is informational (the verifier enforces its own); absent it is the signer count.</summary>
    public static D SignPqQuorum(byte[] message, IReadOnlyList<PqKeyPair> keyPairs, int? pqT = null)
    {
        var rep = PqQuorumRepresentative(message);
        var signers = keyPairs.Select(k => (object?)new D { ["pk"] = Pca.B64u(k.PublicKey), ["sig"] = Pca.B64u(PqSuites.MlDsa65Sign(k.SecretKey, rep)) }).ToList();
        return new D { ["v"] = PqQuorumVersion, ["alg"] = PqQuorumAlg, ["pqT"] = pqT ?? signers.Count, ["signers"] = signers };
    }

    /// <summary>The trusted pool as canonical base64url strings, distinct, in first-seen order; entries that are not a well-formed ML-DSA-65 public key are ignored.</summary>
    public static List<string> NormalizePqQuorumPool(IEnumerable<object?> pks)
    {
        var pool = new List<string>();
        foreach (var p in pks)
        {
            var s = p is byte[] b ? Pca.B64u(b) : p as string;
            if (s != null && Pca.B64uDecode(s, MlDsa65PublicKeyBytes) != null && !pool.Contains(s)) pool.Add(s);
        }
        return pool;
    }

    /// <summary>Count DISTINCT trusted keys whose co-signature verifies over the message; ok iff the count reaches <paramref name="pqT"/>. Total: never throws. A block whose version is missing (the pre-0.5
    /// format), 1 or unknown is refused before any verification.</summary>
    public static D VerifyPqQuorum(object? block, byte[] message, IEnumerable<string> trustedPool, object? pqT)
    {
        D No(string reason) => new() { ["ok"] = false, ["count"] = 0, ["need"] = pqT, ["reason"] = reason };
        var tn = IntentJs.NumOf(pqT);
        if (pqT is string || tn is not double need || !double.IsFinite(need) || need != Math.Floor(need) || need < 1) return No("pqT must be a positive integer");
        if (block is not (D or L)) return No("malformed pq block");
        var b = block as D ?? new D();
        if (!b.TryGetValue("v", out var v)) return No("pq quorum version missing (pre-0.5 format is refused)");
        var vn = v is string ? null : IntentJs.NumOf(v);
        if (vn == 1) return No("pq quorum version 1 is no longer accepted (pre-0.5 format)");
        if (vn != PqQuorumVersion) return No("unsupported pq quorum version");
        if (!(b.GetValueOrDefault("alg") is string alg && alg == PqQuorumAlg) || b.GetValueOrDefault("signers") is not L signers) return No("malformed pq block");
        var pool = new HashSet<string>(trustedPool, StringComparer.Ordinal);
        var rep = PqQuorumRepresentative(message);
        var counted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in signers.Take(MaxPqQuorumEntries))
        {
            if (entry is not D s || s.GetValueOrDefault("pk") is not string pk || s.GetValueOrDefault("sig") is not string) continue;
            if (!pool.Contains(pk) || counted.Contains(pk)) continue;
            if (!PqSuites.MlDsa65VerifyB64u(pk, rep, s["sig"])) continue;
            counted.Add(pk);
        }
        var count = counted.Count;
        if (count >= need) return new D { ["ok"] = true, ["count"] = count, ["need"] = pqT };
        return new D { ["ok"] = false, ["count"] = count, ["need"] = pqT, ["reason"] = $"post-quantum quorum short: {count} of {JsJson.ToJsString(pqT)} required ML-DSA co-signatures" };
    }
}
