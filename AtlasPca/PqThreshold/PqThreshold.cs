// Post-quantum threshold step-up (mirrors @atlasauth/pca-pq-threshold): the signed FROST group descriptor, the ML-DSA-65
// pqT-of-m co-signer quorum and the hybrid verifier that needs BOTH the classical FROST aggregate (a plain Ed25519
// signature under the pinned group key) and the quorum. ML-DSA verification is the vetted BouncyCastle implementation
// behind Pq.MlDsa65Verify. Inputs are the JSON tree (Dictionary / List / string / bool / Num / null; byte[] allowed where
// the reference takes a Uint8Array); every verifier fails closed and returns a refusal instead of throwing.
using System.Globalization;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PqThreshold;

public static class PqThreshold
{
    public const int GroupDescriptorVersion = 1;
    public const string GroupSuite = "frost-ed25519";
    public const int MaxGroupSize = 1024;
    public const int HybridArtifactVersion = 2;
    public const string HybridClassicalAlg = "frost-ed25519";
    public const int PqQuorumVersion = 2;
    public const string PqQuorumAlg = "ml-dsa-65";
    public const int MaxPqQuorumEntries = 256;
    /// <summary>The cap on the PQ co-signer entries a quorum may carry (the same bound as <see cref="MaxPqQuorumEntries"/>).</summary>
    public const int MaxPqSignerEntries = MaxPqQuorumEntries;
    const string DescriptorDomain = "atlas-pca-pq-threshold/group-descriptor/v1\0";
    const string SignerSetDomain = "atlas-pca-pq-threshold/signer-set/v1\0";
    const string PqQuorumDomain = "atlas-pca/pq-quorum/v2\0";

    // ---- JS-semantics helpers ----
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    /// <summary>Number.isInteger.</summary>
    static bool IsInteger(object? o) => IntentJs.NumOf(o) is double x && double.IsFinite(x) && x == Math.Round(x);
    /// <summary>A b64u string as the reference's asB64u: bytes encode, anything else passes through.</summary>
    static object? AsB64u(object? k) => k is byte[] b ? Pca.B64u(b) : k;
    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    /// <summary>JavaScript String(v) for the primitives a refusal reason can echo.</summary>
    static string JsStr(object? v, bool present = true) => !present ? "undefined" : v switch
    {
        null => "null",
        string s => s,
        bool b => b ? "true" : "false",
        Num n => IntentJs.NormNum(n.Raw).Raw,
        D => "[object Object]",
        L l => string.Join(",", l.Select(x => x == null ? "" : JsStr(x))),
        _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    // ---- signer set / descriptor ----
    /// <summary>sha256(DOMAIN || canonical(sorted [{id, pk}])): order-insensitive, ids distinct. participants: [{identifier, publicKey}].</summary>
    public static string SignerSetCommitment(object? participants)
    {
        if (participants is not L ps || ps.Count == 0 || ps.Count > MaxGroupSize)
            throw new ArgumentOutOfRangeException(nameof(participants), $"signerSetCommitment: need 1..{MaxGroupSize} participants");
        var rows = new List<(double Id, Num IdNum, string Pk)>();
        foreach (var p in ps)
        {
            if (p == null) throw new ArgumentException("signerSetCommitment: participant is null");
            var pk = AsB64u(G(p, "publicKey"));
            var id = G(p, "identifier");
            if (id is not (Num or int or long or double) || !IntentJs.IsSafeInteger(id) || IntentJs.NumOf(id)!.Value <= 0)
                throw new ArgumentOutOfRangeException(nameof(participants), "signerSetCommitment: participant identifiers must be positive safe integers");
            if (Pca.B64uDecode(pk, 32) == null)
                throw new ArgumentOutOfRangeException(nameof(participants), "signerSetCommitment: verification share is not a canonical b64u(32) value");
            rows.Add((IntentJs.NumOf(id)!.Value, IntentJs.OfLong(IntentJs.Lng(id)), (string)pk!));
        }
        rows.Sort((a, b) => a.Id.CompareTo(b.Id));
        for (int i = 1; i < rows.Count; i++)
            if (rows[i].Id == rows[i - 1].Id) throw new ArgumentException("signerSetCommitment: duplicate participant identifier");
        var body = Pca.Canon(new L(rows.Select(r => (object?)new D { ["id"] = r.IdNum, ["pk"] = r.Pk })));
        return Pca.B64u(Pca.Sha(Pca.Cat(Utf8(SignerSetDomain), body)));
    }

    static byte[] DescriptorBytes(string groupPk, object? t, object? n, string signerSet)
    {
        var body = Pca.Canon(new D
        {
            ["v"] = IntentJs.OfLong(GroupDescriptorVersion),
            ["suite"] = GroupSuite,
            ["group_pk"] = groupPk,
            ["t"] = IntentJs.Normalize(t),
            ["n"] = IntentJs.Normalize(n),
            ["signer_set"] = signerSet,
        });
        return Pca.Cat(Utf8(DescriptorDomain), body);
    }

    /// <summary>Issue a descriptor at DKG time. authoritySecretKey is the setup authority's 32-byte Ed25519 seed. Throws on an impossible group.</summary>
    public static D IssueGroupDescriptor(byte[]? authoritySecretKey, object? groupPublicKey, object? t, object? participants)
    {
        if (participants is not L ps) throw new ArgumentException("issueGroupDescriptor: participants must be an array");
        int n = ps.Count;
        if (!IsInteger(t) || IntentJs.NumOf(t)!.Value < 1 || IntentJs.NumOf(t)!.Value > n)
            throw new ArgumentOutOfRangeException(nameof(t), $"issueGroupDescriptor: need 1 <= t <= n (n={n})");
        var gpk = AsB64u(groupPublicKey);
        if (Pca.B64uDecode(gpk, 32) == null) throw new ArgumentOutOfRangeException(nameof(groupPublicKey), "issueGroupDescriptor: group public key is not canonical b64u(32)");
        if (authoritySecretKey is not { Length: 32 }) throw new ArgumentOutOfRangeException(nameof(authoritySecretKey), "issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key");
        var ssc = SignerSetCommitment(participants);
        var tn = IntentJs.Normalize(t);
        var nn = IntentJs.OfLong(n);
        using var key = EdKey.FromSeed(authoritySecretKey);
        var desc = new D
        {
            ["v"] = IntentJs.OfLong(GroupDescriptorVersion),
            ["suite"] = GroupSuite,
            ["groupPublicKey"] = (string)gpk!,
            ["t"] = tn,
            ["n"] = nn,
            ["signerSetCommitment"] = ssc,
        };
        return new D
        {
            ["descriptor"] = desc,
            ["authority"] = key.Id,
            ["sig"] = Pca.B64u(key.Sign(DescriptorBytes((string)gpk!, tn, nn, ssc))),
        };
    }

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Check a signed descriptor against the verifier's pins (trustedAuthorities, groupKey, t, optional signerSetCommitment). Never throws.</summary>
    public static D VerifyGroupDescriptor(object? s, object? exp)
    {
        try
        {
            if (s is not (D or L)) return Fail("no signed group descriptor: the threshold is unattested");
            var d = G(s, "descriptor");
            var authority = G(s, "authority");
            var sigS = G(s, "sig");
            if (d is not (D or L) || authority is not string || sigS is not string) return Fail("malformed group descriptor");
            if (!(IntentJs.NumOf(G(d, "v")) == GroupDescriptorVersion) || !(G(d, "suite") is string su && su == GroupSuite))
                return Fail("unsupported group descriptor version or suite");
            if (G(d, "groupPublicKey") is not string gpk || G(d, "signerSetCommitment") is not string ssc) return Fail("malformed group descriptor");
            var dt = G(d, "t"); var dn = G(d, "n");
            if (!IsInteger(dt) || !IsInteger(dn) || IntentJs.NumOf(dt)!.Value < 1 || IntentJs.NumOf(dn)!.Value < IntentJs.NumOf(dt)!.Value || IntentJs.NumOf(dn)!.Value > MaxGroupSize)
                return Fail("malformed group descriptor: need 1 <= t <= n");
            // the reference maps the pinned list (a non-array throws -> "could not be verified")
            if (G(exp, "trustedAuthorities") is not L trustedList) return Fail("group descriptor could not be verified (malformed)");
            var trusted = new HashSet<string>(StringComparer.Ordinal);
            foreach (var a in trustedList) if (AsB64u(a) is string a64) trusted.Add(a64);
            if (!trusted.Contains((string)authority)) return Fail("group descriptor authority is not trusted");
            var authorityKey = Pca.B64uDecode(authority, 32);
            var sig = Pca.B64uDecode(sigS, 64);
            if (authorityKey == null || sig == null) return Fail("malformed authority key or signature");
            if (!Pca.VerifyEd25519Strict(authorityKey, DescriptorBytes(gpk, dt, dn, ssc), sig)) return Fail("group descriptor signature does not verify");
            if (AsB64u(G(exp, "groupKey")) is not string want || gpk != want) return Fail("group descriptor is for a different group key");
            var et = G(exp, "t");
            if (!IsInteger(et) || IntentJs.NumOf(et)!.Value < 1) return Fail("required t must be a positive integer");
            if (IntentJs.NumOf(dt) != IntentJs.NumOf(et))
                return Fail($"group was set up as {JsStr(dt)}-of-{JsStr(dn)} but {JsStr(et)} is required: the threshold is not bound to this key");
            if (Has(exp, "signerSetCommitment") && !(G(exp, "signerSetCommitment") is string pin && pin == ssc))
                return Fail("group descriptor is for a different signer set");
            return new D { ["ok"] = true, ["descriptor"] = d };
        }
        catch
        {
            return Fail("group descriptor could not be verified (malformed)");
        }
    }

    // ---- ML-DSA-65 quorum ----
    /// <summary>DOMAIN || sha256(message): the bytes every quorum co-signature covers.</summary>
    public static byte[] PqQuorumRepresentative(byte[] message) => Pca.Cat(Utf8(PqQuorumDomain), Pca.Sha(message));

    /// <summary>The trusted pool as canonical b64u strings; entries that are not a well-formed ML-DSA-65 public key are ignored. A non-array throws.</summary>
    public static HashSet<string> NormalizePqQuorumPool(object? pks)
    {
        if (pks is not L l) throw new ArgumentException("normalizePqQuorumPool: pool is not iterable");
        var pool = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in l)
            if (AsB64u(p) is string s && Pca.B64uDecode(s, Pq.MlDsa65PublicKeyBytes) != null) pool.Add(s);
        return pool;
    }

    /// <summary>Count DISTINCT trusted keys whose co-signature verifies over message; ok iff the count reaches pqT. Total: never throws.</summary>
    public static D VerifyPqQuorum(object? block, byte[] message, HashSet<string> trustedPool, object? pqT) =>
        VerifyPqQuorumCore(block, message, trustedPool, pqT, true);

    static D PqNo(object? pqT, bool present, string reason)
    {
        var r = new D { ["ok"] = false, ["count"] = IntentJs.OfLong(0) };
        if (present) r["need"] = pqT;
        r["reason"] = reason;
        return r;
    }

    static D VerifyPqQuorumCore(object? block, byte[] message, HashSet<string> pool, object? pqT, bool pqTPresent)
    {
        D No(string reason) => PqNo(pqT, pqTPresent, reason);
        if (!IsInteger(pqT) || IntentJs.NumOf(pqT)!.Value < 1) return No("pqT must be a positive integer");
        if (block is not (D or L)) return No("malformed pq block");
        if (!Has(block, "v")) return No("pq quorum version missing (pre-0.5 format is refused)");
        var v = G(block, "v");
        if (IntentJs.NumOf(v) == 1) return No("pq quorum version 1 is no longer accepted (pre-0.5 format)");
        if (IntentJs.NumOf(v) != PqQuorumVersion) return No("unsupported pq quorum version");
        if (!(G(block, "alg") is string alg && alg == PqQuorumAlg) || G(block, "signers") is not L signers) return No("malformed pq block");
        var rep = PqQuorumRepresentative(message);
        var counted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in signers.Take(MaxPqQuorumEntries))
        {
            if (entry is not (D or L)) continue;
            if (G(entry, "pk") is not string pk || G(entry, "sig") is not string sig) continue;
            if (!pool.Contains(pk) || counted.Contains(pk)) continue;
            var pkB = Pca.B64uDecode(pk, Pq.MlDsa65PublicKeyBytes);
            var sgB = Pca.B64uDecode(sig, Pq.MlDsa65SignatureBytes);
            if (pkB == null || sgB == null || !Pq.MlDsa65Verify(pkB, rep, sgB)) continue;
            counted.Add(pk);
        }
        long count = counted.Count;
        var res = new D { ["ok"] = count >= IntentJs.NumOf(pqT)!.Value, ["count"] = IntentJs.OfLong(count), ["need"] = pqT };
        if (count < IntentJs.NumOf(pqT)!.Value) res["reason"] = $"post-quantum quorum short: {count} of {JsStr(pqT)} required ML-DSA co-signatures";
        return res;
    }

    // ---- hybrid ----
    static D HybridRefusal(object? pqT, bool present, string reason, bool zeroNeed = false)
    {
        var pq = zeroNeed ? PqNo(IntentJs.OfLong(0), true, reason) : PqNo(pqT, present, reason);
        return new D { ["ok"] = false, ["frost"] = false, ["pq"] = pq, ["reason"] = reason };
    }

    /// <summary>Verify a standalone hybrid threshold artifact over action. BOTH the classical FROST t-of-n aggregate and the pqT-of-m quorum must hold.
    /// opts: groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?.</summary>
    public static D VerifyHybridThreshold(D action, object? artifact, D opts)
    {
        try { return VerifyHybridInner(action, artifact, opts); }
        catch { return HybridRefusal(null, true, "malformed action or verifier options", zeroNeed: true); }
    }

    static D VerifyHybridInner(D action, object? artifact, D opts)
    {
        var pqTPresent = opts.ContainsKey("pqT");
        var pqT = G(opts, "pqT");
        if (!(artifact is D ad && ad.TryGetValue("v", out var version) && IntentJs.NumOf(version) == HybridArtifactVersion))
        {
            var v = G(artifact, "v");
            var reason = !Has(artifact, "v") ? "artifact version missing (pre-0.5 format is refused)"
                : IntentJs.NumOf(v) == 1 ? "artifact version 1 is no longer accepted (pre-0.5 format)" : "unsupported artifact version";
            return HybridRefusal(pqT, pqTPresent, reason);
        }
        var message = Pca.ThresholdMessage(action);
        var gk = AsB64u(G(opts, "groupKey"));
        var trustedGroupKey = Pca.B64uDecode(gk, 32) == null ? null : (string)gk!;
        var pool = NormalizePqQuorumPool(G(opts, "pqPublicKeys"));

        bool frostOk = false;
        string? frostReason = null;
        var dres = VerifyGroupDescriptor(G(opts, "groupDescriptor"), opts);
        var frost = G(artifact, "frost");
        var ot = G(opts, "t");
        if (!IsInteger(ot) || IntentJs.NumOf(ot)!.Value < 1) frostReason = "t must be a positive integer";
        else if (trustedGroupKey == null) frostReason = "trusted FROST group key is not a canonical b64u(32) point";
        else if (frost is not (D or L) || !(G(frost, "alg") is string fa && fa == HybridClassicalAlg)) frostReason = "malformed or missing FROST part";
        else if (!(dres["ok"] is true)) frostReason = (string)dres["reason"]!;
        else if (!IsInteger(G(frost, "t")) || IntentJs.NumOf(G(frost, "t"))!.Value < IntentJs.NumOf(ot)!.Value)
            frostReason = $"FROST declared threshold {JsStr(G(frost, "t"), Has(frost, "t"))} is below the required t={JsStr(ot)} (downgrade)";
        else if (!(G(frost, "sig") is string fsig && Pca.VerifyEdInternal(trustedGroupKey, message, fsig)))
            frostReason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)";
        else frostOk = true;

        var pq = VerifyPqQuorumCore(G(artifact, "pq"), message, pool, pqT, pqTPresent);
        var ok = frostOk && pq["ok"] is true;
        var res = new D { ["ok"] = ok, ["frost"] = frostOk, ["pq"] = pq };
        if (!ok) res["reason"] = frostOk ? pq.GetValueOrDefault("reason") : frostReason;
        return res;
    }
}
