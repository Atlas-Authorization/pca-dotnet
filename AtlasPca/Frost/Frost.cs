// FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Ed25519, RFC 9591, ciphersuite FROST(Ed25519, SHA-512)
// ("FROST-ED25519-SHA512-v1"). A trusted-dealer split, the two signing rounds, per-share verification and aggregation; the aggregate is an
// ordinary 64-byte Ed25519 signature under the group public key. Group arithmetic is the shared Edwards25519 handle (EdwardsPoint); scalars
// are BigInteger mod L.
//
// Safety checks mirror the reference: strict canonical, prime-order, non-small-order points everywhere; one-shot nonces (a nonce array is
// zeroised after use and its commitment is remembered, so reuse, which would leak the signing share, is refused); every signature share is
// verified before aggregation; the aggregate is verified as strict Ed25519 before it is returned.
// Secret scalar arithmetic (reduction, share-polynomial evaluation, the signature-share sum) runs on the fixed-width CtScalar path, never BigInteger
// multiply or modulo. Honest limit: the point multiplications that take a secret scalar still use the Edwards handle's BigInteger scalar.
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Ratchet;

namespace AtlasPca;

public static class Frost
{
    public static readonly BigInteger L = EdwardsPoint.Order;
    public const string ContextString = "FROST-ED25519-SHA512-v1";
    static readonly byte[] Ctx = Encoding.UTF8.GetBytes(ContextString);
    const long MaxId = 9007199254740991L; // Number.MAX_SAFE_INTEGER
    public const int SpentCommitmentCap = 262_144;

    // ---- records ----
    public sealed record FrostParticipantShare(long Identifier, byte[] Share, byte[] PublicKey);

    public sealed class FrostKeygenOpts
    {
        public byte[]? Secret;
        public List<byte[]>? Coefficients;
        public long[]? Identifiers;
    }

    public sealed record FrostKeygenResult(byte[] GroupPublicKey, List<FrostParticipantShare> ParticipantShares, List<byte[]> GroupCommitment);

    /// <summary>One participant's one-shot secret nonces; the arrays are zeroised by <see cref="Sign"/>.</summary>
    public sealed class FrostNonces(byte[] hiding, byte[] binding)
    {
        public byte[] Hiding = hiding, Binding = binding;
    }

    public sealed record FrostCommitment(long Identifier, byte[] Hiding, byte[] Binding);

    public sealed record FrostCommitResult(byte[] HidingNonce, byte[] BindingNonce, FrostCommitment Commitment)
    {
        public FrostNonces Nonces() => new(HidingNonce, BindingNonce);
    }

    public sealed record FrostSignatureShare(long Identifier, byte[] SigShare);

    /// <summary>A participant's public verification share (share * B).</summary>
    public sealed record VerificationShare(long Identifier, byte[] PublicKey);

    public sealed class FrostSignOpts
    {
        public int? Threshold;
        public byte[]? VerificationShare;
        public List<VerificationShare>? VerificationShares;
    }

    // ---- scalars and hashes ----
    static BigInteger Mod(BigInteger a) { if (a.Sign >= 0 && a < L) return a; var r = a % L; return r.Sign < 0 ? r + L : r; }

    static BigInteger FromLe(byte[] b) => new(b, isUnsigned: true, isBigEndian: false);

    static byte[] Le32(BigInteger n)
    {
        var o = new byte[32];
        var b = n.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Copy(b, o, Math.Min(32, b.Length));
        return o;
    }

    public static byte[] ScalarToBytes(BigInteger s) => Le32(Mod(s));

    /// <summary>Little-endian 0..64 bytes reduced mod L (the wide reduction HashToScalar needs); more than 64 bytes throws, like the reference.</summary>
    public static BigInteger BytesToScalar(byte[] b)
    {
        if (b.Length == 0) return BigInteger.Zero;
        if (b.Length > 64) throw new ArgumentException("ct-scalar: reduce takes 1..64 bytes");
        return FromLe(CtScalar.Reduce(b)); // secret-bearing input (shares, nonces, hash output): fixed-width reduction
    }

    public static bool IsCanonicalScalar(byte[]? b) => b != null && b.Length == 32 && FromLe(b) < L;

    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    static byte[] Sha512(byte[] m) => SHA512.HashData(m);
    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    static BigInteger HashToScalar(byte[] m) => BytesToScalar(Sha512(m));

    public static BigInteger H1(byte[] m) => HashToScalar(Cat(Ctx, Utf8("rho"), m));
    public static BigInteger H2(byte[] m) => HashToScalar(m);
    public static BigInteger H3(byte[] m) => HashToScalar(Cat(Ctx, Utf8("nonce"), m));
    public static byte[] H4(byte[] m) => Sha512(Cat(Ctx, Utf8("msg"), m));
    public static byte[] H5(byte[] m) => Sha512(Cat(Ctx, Utf8("com"), m));

    // ---- points ----
    internal static EdwardsPoint MulBase(BigInteger s) { var v = Mod(s); return v.IsZero ? EdwardsPoint.Zero : EdwardsPoint.Base.Multiply(v); }
    internal static EdwardsPoint MulPoint(EdwardsPoint pt, BigInteger s) { var v = Mod(s); return v.IsZero ? EdwardsPoint.Zero : pt.Multiply(v); }

    /// <summary>Strict decode: canonical encoding, on the curve, not small order, in the prime-order subgroup. Throws otherwise.</summary>
    public static EdwardsPoint DecodeSafePoint(byte[]? b)
    {
        if (b == null || b.Length != 32) throw new ArgumentException("frost: point must be 32 bytes");
        EdwardsPoint pt;
        try { pt = EdwardsPoint.FromBytes(b); } catch (ArgumentException) { throw new ArgumentException("frost: invalid point encoding"); }
        if (pt.IsSmallOrder()) throw new ArgumentException("frost: small-order point rejected");
        if (!pt.IsTorsionFree()) throw new ArgumentException("frost: point is not in the prime-order subgroup");
        if (!pt.ToBytes().AsSpan().SequenceEqual(b)) throw new ArgumentException("frost: non-canonical point encoding");
        return pt;
    }

    static void AssertValidId(long id)
    {
        if (id <= 0 || id > MaxId) throw new ArgumentException("frost: participant identifier must be a positive safe integer");
    }

    static void ValidateCommitments(List<FrostCommitment>? list, int? threshold)
    {
        if (list == null || list.Count == 0) throw new ArgumentException("frost: empty commitment list");
        if (threshold is int t)
        {
            if (t < 1) throw new ArgumentException("frost: invalid threshold");
            if (list.Count < t) throw new ArgumentException($"frost: need at least t={t} commitments (got {list.Count})");
        }
        var seen = new HashSet<long>();
        foreach (var c in list)
        {
            if (c == null) throw new ArgumentException("frost: malformed commitment");
            AssertValidId(c.Identifier);
            if (!seen.Add(c.Identifier)) throw new ArgumentException("frost: duplicate commitment identifier " + c.Identifier);
            DecodeSafePoint(c.Hiding);
            DecodeSafePoint(c.Binding);
        }
    }

    // ---- key generation ----
    static byte[] RandomScalarBytes() => RandomNumberGenerator.GetBytes(32);

    /// <summary>Trusted-dealer Shamir split of a (given or fresh) group secret into n shares with threshold t (RFC 9591 appendix C).</summary>
    public static FrostKeygenResult TrustedDealerKeygen(int t, int n, FrostKeygenOpts? opts = null)
    {
        opts ??= new FrostKeygenOpts();
        if (t < 1 || n < t) throw new ArgumentException($"frostTrustedDealerKeygen: need 1 <= t <= n (got t={t}, n={n})");
        var ids = opts.Identifiers ?? Enumerable.Range(1, n).Select(i => (long)i).ToArray();
        if (ids.Length != n) throw new ArgumentException("frostTrustedDealerKeygen: identifiers.length must equal n");
        if (ids.Distinct().Count() != n) throw new ArgumentException("frostTrustedDealerKeygen: identifiers must be distinct");
        foreach (var x in ids) if (x <= 0 || x > MaxId) throw new ArgumentException("frostTrustedDealerKeygen: identifiers must be positive integers");

        var secret = BytesToScalar(opts.Secret ?? RandomScalarBytes());
        var coeffs = new List<BigInteger> { secret };
        for (var i = 1; i < t; i++)
        {
            var c = opts.Coefficients != null && i - 1 < opts.Coefficients.Count ? opts.Coefficients[i - 1] : null;
            coeffs.Add(BytesToScalar(c ?? RandomScalarBytes()));
        }
        var shares = new List<FrostParticipantShare>();
        foreach (var id in ids)
        {
            var xb = ScalarToBytes(new BigInteger(id)); var acc = new byte[32];
            for (var j = coeffs.Count - 1; j >= 0; j--) acc = CtScalar.Add(CtScalar.Mul(acc, xb), ScalarToBytes(coeffs[j]));
            shares.Add(new FrostParticipantShare(id, acc, MulBase(FromLe(acc)).ToBytes()));
        }
        var commitment = coeffs.Select(a => MulBase(a).ToBytes()).ToList();
        return new FrostKeygenResult(commitment[0], shares, commitment);
    }

    /// <summary>share * B, the participant's public verification share.</summary>
    public static byte[] VerifyingShare(byte[] share) => MulBase(BytesToScalar(share)).ToBytes();

    // ---- round 1 ----
    static BigInteger NonceGenerate(byte[] randomness, byte[] secretShare)
    {
        if (randomness.Length != 32) throw new ArgumentException("frostCommit: nonce randomness must be 32 bytes");
        return H3(Cat(randomness, ScalarToBytes(BytesToScalar(secretShare))));
    }

    /// <summary>Round 1: the one-shot nonce pair and its public commitment. Randomness is drawn fresh unless given (tests / vectors).</summary>
    public static FrostCommitResult Commit(FrostParticipantShare p, byte[]? hidingRandomness = null, byte[]? bindingRandomness = null)
    {
        var h = NonceGenerate(hidingRandomness ?? RandomScalarBytes(), p.Share);
        var b = NonceGenerate(bindingRandomness ?? RandomScalarBytes(), p.Share);
        return new FrostCommitResult(ScalarToBytes(h), ScalarToBytes(b), new FrostCommitment(p.Identifier, MulBase(h).ToBytes(), MulBase(b).ToBytes()));
    }

    // ---- round 2 helpers ----
    static List<FrostCommitment> SortCommitments(List<FrostCommitment> list) => list.OrderBy(c => c.Identifier).ToList();

    static byte[] EncodeCommitmentList(List<FrostCommitment> list) =>
        Cat(list.SelectMany(c => new[] { ScalarToBytes(new BigInteger(c.Identifier)), c.Hiding, c.Binding }).ToArray());

    static Dictionary<long, BigInteger> ComputeBindingFactors(byte[] groupPublicKey, List<FrostCommitment> list, byte[] msg)
    {
        var prefix = Cat(groupPublicKey, H4(msg), H5(EncodeCommitmentList(list)));
        return list.ToDictionary(c => c.Identifier, c => H1(Cat(prefix, ScalarToBytes(new BigInteger(c.Identifier)))));
    }

    static EdwardsPoint ComputeGroupCommitment(List<FrostCommitment> list, Dictionary<long, BigInteger> bindingFactors)
    {
        var r = EdwardsPoint.Zero;
        foreach (var c in list) r = r.Add(DecodeSafePoint(c.Hiding)).Add(MulPoint(DecodeSafePoint(c.Binding), bindingFactors[c.Identifier]));
        return r;
    }

    static BigInteger ComputeChallenge(byte[] r, byte[] groupPublicKey, byte[] msg) => H2(Cat(r, groupPublicKey, msg));

    static BigInteger DeriveInterpolatingValue(List<long> participants, long i)
    {
        if (!participants.Contains(i)) throw new ArgumentException("frost: identifier not in participant list");
        BigInteger num = BigInteger.One, den = BigInteger.One, xi = new(i);
        foreach (var j in participants)
        {
            if (j == i) continue;
            var xj = new BigInteger(j);
            num = Mod(num * xj);
            den = Mod(den * (xj - xi));
        }
        if (den.IsZero) throw new ArgumentException("frost: modular inverse of zero");
        var lam = Mod(num * BigInteger.ModPow(den, L - 2, L));
        if (lam.IsZero) throw new ArgumentException("frost: zero Lagrange coefficient");
        return lam;
    }

    // ---- one-shot nonce registry ----
    static readonly ConditionalWeakTable<byte[], object> SpentNonces = new();
    static readonly Queue<string> SpentOrder = new();
    static readonly HashSet<string> SpentCommitments = new(StringComparer.Ordinal);

    /// <summary>Forget every spent nonce commitment: deterministic replays reuse the same nonces on purpose. Not for production use.</summary>
    internal static void ForgetSpentForReplay() { lock (SpentCommitments) { SpentCommitments.Clear(); SpentOrder.Clear(); } }

    static string CommitmentKey(char kind, byte[] point) => kind + Pca.B64u(point);

    static void ClaimCommitment(string key)
    {
        lock (SpentCommitments)
        {
            if (SpentCommitments.Add(key)) SpentOrder.Enqueue(key);
            if (SpentCommitments.Count > SpentCommitmentCap) SpentCommitments.Remove(SpentOrder.Dequeue());
        }
    }

    static bool CommitmentSpent(string key) { lock (SpentCommitments) return SpentCommitments.Contains(key); }

    static bool IsSpent(byte[] n) => SpentNonces.TryGetValue(n, out _);

    static bool IsZero(byte[] b) { var acc = 0; foreach (var x in b) acc |= x; return acc == 0; }

    // ---- round 2 ----
    /// <summary>Round 2: this participant's signature share. Consumes the nonces (zeroised, and remembered so the same nonce can never be signed with twice).
    /// With VerificationShare(s) in the options the share and the group key are cross-checked before any secret is used.</summary>
    public static FrostSignatureShare Sign(long identifier, byte[] share, byte[] groupPublicKey, FrostNonces? nonces, byte[] message,
        List<FrostCommitment> signingCommitments, FrostSignOpts? opts = null)
    {
        opts ??= new FrostSignOpts();
        AssertValidId(identifier);
        ValidateCommitments(signingCommitments, opts.Threshold);
        DecodeSafePoint(groupPublicKey);
        if (nonces?.Hiding == null || nonces.Binding == null) throw new ArgumentException("frostSign: malformed nonces");
        const string reuse = "frostSign: nonces already used (one-shot; reuse would leak the signing share)";
        if (IsSpent(nonces.Hiding) || IsSpent(nonces.Binding)) throw new ArgumentException(reuse);
        if (IsZero(nonces.Hiding) || IsZero(nonces.Binding)) throw new ArgumentException("frostSign: zero/zeroized nonce");
        if (ReferenceEquals(nonces.Hiding, nonces.Binding)) throw new ArgumentException("frostSign: hiding and binding nonce must differ");

        var list = SortCommitments(signingCommitments);
        var mine = list.FirstOrDefault(c => c.Identifier == identifier) ?? throw new ArgumentException("frostSign: this identifier has no commitment in the set");

        BigInteger hiding = BytesToScalar(nonces.Hiding), binding = BytesToScalar(nonces.Binding), sk = BytesToScalar(share);
        if (!MulBase(hiding).SameAs(DecodeSafePoint(mine.Hiding)) || !MulBase(binding).SameAs(DecodeSafePoint(mine.Binding)))
            throw new ArgumentException("frostSign: own commitment does not match nonces");
        string hKey = CommitmentKey('h', mine.Hiding), bKey = CommitmentKey('b', mine.Binding);
        if (CommitmentSpent(hKey) || CommitmentSpent(bKey)) throw new ArgumentException(reuse);
        if (opts.VerificationShare != null && !MulBase(sk).SameAs(DecodeSafePoint(opts.VerificationShare)))
            throw new ArgumentException("frostSign: share does not match verification share");
        var participants = list.Select(c => c.Identifier).ToList();
        if (opts.VerificationShares != null)
        {
            var acc = EdwardsPoint.Zero;
            foreach (var id in participants)
            {
                var vs = opts.VerificationShares.FirstOrDefault(v => v.Identifier == id) ?? throw new ArgumentException("frostSign: missing verification share for " + id);
                acc = acc.Add(MulPoint(DecodeSafePoint(vs.PublicKey), DeriveInterpolatingValue(participants, id)));
            }
            if (!acc.SameAs(DecodeSafePoint(groupPublicKey))) throw new ArgumentException("frostSign: group public key does not match the verification shares");
        }

        var bindingFactors = ComputeBindingFactors(groupPublicKey, list, message);
        var bf = bindingFactors[identifier];
        var r = ComputeGroupCommitment(list, bindingFactors);
        var lambda = DeriveInterpolatingValue(participants, identifier);
        var c = ComputeChallenge(r.ToBytes(), groupPublicKey, message);
        // z = hiding + binding*bf + (lambda*share)*c on the fixed-width path: nonces and share are secret.
        var z = CtScalar.Add(
            CtScalar.Add(ScalarToBytes(hiding), CtScalar.Mul(ScalarToBytes(binding), ScalarToBytes(bf))),
            CtScalar.Mul(CtScalar.Mul(ScalarToBytes(lambda), ScalarToBytes(sk)), ScalarToBytes(c)));

        SpentNonces.AddOrUpdate(nonces.Hiding, new object());
        SpentNonces.AddOrUpdate(nonces.Binding, new object());
        ClaimCommitment(hKey);
        ClaimCommitment(bKey);
        Array.Clear(nonces.Hiding);
        Array.Clear(nonces.Binding);
        return new FrostSignatureShare(identifier, z);
    }

    /// <summary>RFC 9591 section 5.3: one signature share checked against its verification share. Never throws; any malformed input is false.</summary>
    public static bool VerifySigShare(long identifier, byte[] publicKey, FrostCommitment commitment, FrostSignatureShare sigShare,
        List<FrostCommitment> signingCommitments, byte[] groupPublicKey, byte[] message)
    {
        try
        {
            ValidateCommitments(signingCommitments, null);
            var list = SortCommitments(signingCommitments);
            var bindingFactors = ComputeBindingFactors(groupPublicKey, list, message);
            if (!bindingFactors.TryGetValue(identifier, out var bf)) return false;
            var r = ComputeGroupCommitment(list, bindingFactors);
            var commShare = DecodeSafePoint(commitment.Hiding).Add(MulPoint(DecodeSafePoint(commitment.Binding), bf));
            var c = ComputeChallenge(r.ToBytes(), groupPublicKey, message);
            var lambda = DeriveInterpolatingValue(list.Select(x => x.Identifier).ToList(), identifier);
            if (!IsCanonicalScalar(sigShare.SigShare)) return false; // z and z + L must not both verify
            var lhs = MulBase(BytesToScalar(sigShare.SigShare));
            var rhs = commShare.Add(MulPoint(DecodeSafePoint(publicKey), Mod(c * lambda)));
            return lhs.SameAs(rhs);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Combine the signature shares into the 64-byte Ed25519 signature. Every share is verified against its verification share first, a missing
    /// or extra share is refused, and the result must verify as strict Ed25519 under the group key.</summary>
    public static byte[] Aggregate(byte[] message, List<FrostCommitment> signingCommitments, List<FrostSignatureShare>? sigShares, byte[] groupPublicKey,
        int? threshold, List<VerificationShare>? verificationShares)
    {
        ValidateCommitments(signingCommitments, threshold);
        DecodeSafePoint(groupPublicKey);
        var list = SortCommitments(signingCommitments);
        if (sigShares == null || sigShares.Count != list.Count) throw new ArgumentException("frostAggregate: need exactly one signature share per commitment");
        var shareIds = new HashSet<long>();
        foreach (var s in sigShares)
        {
            if (!list.Any(c => c.Identifier == s.Identifier)) throw new ArgumentException("frostAggregate: share from non-signer");
            if (!shareIds.Add(s.Identifier)) throw new ArgumentException("frostAggregate: duplicate signature share");
        }
        if (verificationShares == null) throw new ArgumentException("frostAggregate: verificationShares are required (every signature share is verified before aggregation)");
        foreach (var s in sigShares)
        {
            var vs = verificationShares.FirstOrDefault(v => v.Identifier == s.Identifier);
            var commitment = list.First(c => c.Identifier == s.Identifier);
            if (vs == null || !VerifySigShare(s.Identifier, vs.PublicKey, commitment, s, list, groupPublicKey, message))
                throw new ArgumentException("frostAggregate: invalid signature share from participant " + s.Identifier);
        }
        var r = ComputeGroupCommitment(list, ComputeBindingFactors(groupPublicKey, list, message));
        var z = new byte[32];
        foreach (var s in sigShares) z = CtScalar.Add(z, ScalarToBytes(BytesToScalar(s.SigShare)));
        var sig = Cat(r.ToBytes(), z);
        if (!Pca.VerifyEd25519Strict(groupPublicKey, message, sig)) throw new ArgumentException("frostAggregate: aggregate signature does not verify (a share is invalid)");
        return sig;
    }

    /// <summary>Run both rounds in-process for a quorum of participant shares (each carries its verification share) and return the aggregate signature.
    /// Fails closed: an empty or sub-threshold quorum, a duplicate participant, or any invalid share throws.</summary>
    public static byte[] Cosign(byte[] groupPublicKey, List<FrostParticipantShare>? quorum, byte[] message, int? threshold = null)
    {
        if (quorum == null || quorum.Count == 0) throw new ArgumentException("frostCosign: empty signing quorum");
        if (threshold is int t && quorum.Count < t) throw new ArgumentException($"frostCosign: quorum of {quorum.Count} is below the threshold t={t}");
        var ids = new HashSet<long>();
        foreach (var p in quorum)
        {
            AssertValidId(p.Identifier);
            if (!ids.Add(p.Identifier)) throw new ArgumentException($"frostCosign: duplicate participant {p.Identifier} in quorum");
        }
        var vss = quorum.Select(p => new VerificationShare(p.Identifier, p.PublicKey)).ToList();
        var commits = quorum.Select(p => Commit(p)).ToList();
        var commitments = commits.Select(c => c.Commitment).ToList();
        var sigShares = new List<FrostSignatureShare>();
        for (var i = 0; i < quorum.Count; i++)
            sigShares.Add(Sign(quorum[i].Identifier, quorum[i].Share, groupPublicKey, commits[i].Nonces(), message, commitments,
                new FrostSignOpts { Threshold = threshold, VerificationShare = quorum[i].PublicKey, VerificationShares = vss }));
        return Aggregate(message, commitments, sigShares, groupPublicKey, threshold, vss);
    }
}
