using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Pairing;
using static supranational.blst;

namespace AtlasPca.Bbs;

/// <summary>
/// BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
/// draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings; validated against the draft's official fixtures).
/// Signatures and generators live in G1 (48 bytes compressed), public keys in G2 (96 bytes), scalars are 32 bytes big-endian.
/// All curve work is blst's; scalar-field arithmetic is BigInteger (see <see cref="Bls12"/>).
/// </summary>
public static class Bbs
{
    /// <summary>Implementation limit on the number of messages in one credential (a verifier derives the count from attacker-supplied lengths).</summary>
    public const int MaxMessages = 1024;
    public static readonly BigInteger R = Bls12.R;
    public const string CiphersuiteId = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    public const string ApiId = CiphersuiteId + "H2G_HM2S_";

    const int ScalarLen = 32;
    const int PointLen = 48;
    const int ExpandLen = 48;
    const string H2sDst = ApiId + "H2S_";
    const string MapDst = ApiId + "MAP_MSG_TO_SCALAR_AS_HASH_";
    const string SeedDst = ApiId + "SIG_GENERATOR_SEED_";
    const string GenDst = ApiId + "SIG_GENERATOR_DST_";
    const string GenSeed = ApiId + "MESSAGE_GENERATOR_SEED";
    const string KeygenDst = ApiId + "KEYGEN_DST_";
    /// <summary>P1: the fixed G1 generator of the ciphersuite (draft 7.2.2).</summary>
    const string P1Hex = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

    static readonly P1 P1Gen = Bls12.DecodeG1(Convert.FromHexString(P1Hex));
    static readonly P2 BP2 = P2.generator();

    // ---- helpers ----

    internal static byte[] Hex(string s) => Convert.FromHexString(s);
    static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
    static byte[] I2osp(BigInteger n, int len) => Bls12.I2osp(n, len);
    static byte[] I2osp(long n, int len) => Bls12.I2osp(new BigInteger(n), len);
    static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    static byte[] Expand(byte[] msg, string dst, int len) => Bls12.ExpandMessageXmd(msg, Ascii(dst), len);

    /// <summary>hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2).</summary>
    public static BigInteger HashToScalar(byte[] msg, string dst) => Bls12.Mod(Bls12.Os2ip(Expand(msg, dst, ExpandLen)));

    /// <summary>MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2).</summary>
    public static BigInteger MapMessageToScalarAsHash(byte[] message) => HashToScalar(message, MapDst);

    public static List<BigInteger> MessagesToScalars(IReadOnlyList<byte[]> messages) => messages.Select(MapMessageToScalarAsHash).ToList();

    static List<P1> Gens(int count)
    {
        if (count < 0) throw new ArgumentException("bbs: generator count must be a non-negative integer");
        if (count > MaxMessages + 1) throw new ArgumentException("bbs: at most " + MaxMessages + " messages are supported");
        var o = new List<P1>();
        var v = Expand(Ascii(GenSeed), SeedDst, ExpandLen);
        for (int i = 1; i <= count; i++)
        {
            v = Expand(Concat(v, I2osp(i, 8)), SeedDst, ExpandLen);
            o.Add(new P1().hash_to(v, GenDst));
        }
        return o;
    }

    /// <summary>create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1).</summary>
    public static List<byte[]> CreateGenerators(int count) => Gens(count).Select(g => g.compress()).ToList();

    // ---- key generation ----

    /// <summary>KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0.</summary>
    public static BigInteger KeyGen(byte[] keyMaterial, byte[]? keyInfo = null)
    {
        keyInfo ??= Array.Empty<byte>();
        if (keyMaterial.Length < 32) throw new ArgumentException("bbs: key material must be at least 32 octets");
        if (keyInfo.Length > 65535) throw new ArgumentException("bbs: key info must be at most 65535 octets");
        var sk = HashToScalar(Concat(keyMaterial, I2osp(keyInfo.Length, 2), keyInfo), KeygenDst);
        if (sk.IsZero) throw new InvalidOperationException("bbs: derived SK is zero (retry with different key material)");
        return sk;
    }

    /// <summary>SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2).</summary>
    public static byte[] SkToPk(BigInteger sk) => Bls12.Mul(BP2, sk).compress();

    public sealed record KeyPair(BigInteger Sk, byte[] Pk);

    /// <summary>A fresh (SK, PK) pair from the system CSPRNG; refuses an all-zero entropy source.</summary>
    public static KeyPair GenerateKeyPair()
    {
        var ikm = RandomNumberGenerator.GetBytes(32);
        if (ikm.All(b => b == 0)) throw new InvalidOperationException("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key");
        var sk = KeyGen(ikm);
        return new KeyPair(sk, SkToPk(sk));
    }

    public static byte[] SkToBytes(BigInteger sk) => I2osp(sk, ScalarLen);

    public static BigInteger SkFromBytes(byte[] bytes)
    {
        if (bytes.Length != ScalarLen) throw new ArgumentException("bbs: SK must be 32 octets");
        var sk = Bls12.Os2ip(bytes);
        if (sk.IsZero || sk >= R) throw new ArgumentException("bbs: SK out of range");
        return sk;
    }

    // ---- serialization (draft 4.2.4) ----

    /// <summary>serialize(): points compressed, scalars 32 octets, integers 8 octets. Elements are P1, P2, BigInteger (scalar) or int (count/index).</summary>
    static byte[] Serialize(List<object> els)
    {
        var o = new List<byte>();
        foreach (var el in els)
        {
            byte[] b = el switch
            {
                P1 p => p.compress(),
                P2 p => p.compress(),
                BigInteger s => I2osp(s, ScalarLen),
                int n => I2osp(n, 8),
                _ => throw new ArgumentException("bbs: unserializable element"),
            };
            o.AddRange(b);
        }
        return o.ToArray();
    }

    // ---- signature octets ----

    sealed record ParsedSignature(P1 A, BigInteger E);

    static byte[] SignatureToOctets(P1 a, BigInteger e) => Concat(a.compress(), I2osp(e, ScalarLen));

    static ParsedSignature OctetsToSignature(byte[] sig)
    {
        if (sig.Length != PointLen + ScalarLen) throw new ArgumentException("bbs: signature must be 80 octets");
        var a = Bls12.DecodeG1(sig[..PointLen]);
        if (a.is_inf()) throw new ArgumentException("bbs: signature point A is the identity");
        var e = Bls12.Os2ip(sig[PointLen..]);
        if (e.Sign <= 0 || e >= R) throw new ArgumentException("bbs: signature scalar e out of range");
        return new ParsedSignature(a, e);
    }

    // ---- domain (draft 4.2.3) ----

    static BigInteger CalculateDomain(byte[] pk, P1 q1, List<P1> h, byte[] header)
    {
        var els = new List<object> { h.Count, q1 };
        els.AddRange(h.Cast<object>());
        var domOcts = Concat(Serialize(els), Ascii(ApiId));
        var domInput = Concat(pk, domOcts, I2osp(header.Length, 8), header);
        return HashToScalar(domInput, H2sDst);
    }

    /// <summary>B = P1 + Q_1*domain + sum H_i*msg_i.</summary>
    static P1 ComputeB(P1 q1, List<P1> h, BigInteger domain, List<BigInteger> msgScalars)
    {
        var b = Bls12.Add(P1Gen, Bls12.Mul(q1, domain));
        for (int i = 0; i < msgScalars.Count; i++) b = Bls12.Add(b, Bls12.Mul(h[i], msgScalars[i]));
        return b;
    }

    // ---- Sign / Verify ----

    /// <summary>Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector.</summary>
    public static byte[] Sign(BigInteger sk, byte[] pk, byte[] header, IReadOnlyList<byte[]> messages)
    {
        var ms = MessagesToScalars(messages);
        var g = Gens(ms.Count + 1);
        var q1 = g[0];
        var h = g.GetRange(1, g.Count - 1);
        var domain = CalculateDomain(pk, q1, h, header);
        var eEls = new List<object> { sk };
        eEls.AddRange(ms.Cast<object>());
        eEls.Add(domain);
        var e = HashToScalar(Serialize(eEls), H2sDst);
        var b = ComputeB(q1, h, domain, ms);
        var a = Bls12.Mul(b, Bls12.Inv(Bls12.Add(sk, e)));
        return SignatureToOctets(a, e);
    }

    /// <summary>Result of a verification: ok, or the stable machine-readable reason.</summary>
    public sealed record Result(bool Ok, string? Reason)
    {
        internal static readonly Result Success = new(true, null);
        internal static Result Fail(string reason) => new(false, reason);
    }

    public const string MalformedSignature = "malformed-signature";
    public const string MalformedPublicKey = "malformed-public-key";
    public const string MalformedProof = "malformed-proof";
    public const string DisclosedLengthMismatch = "disclosed-length-mismatch";
    public const string InvalidDisclosedIndexes = "invalid-disclosed-indexes";
    public const string PairingMismatch = "pairing-mismatch";
    public const string ChallengeMismatch = "challenge-mismatch";

    /// <summary>Decode a public key: strict G2, not the identity; null when malformed.</summary>
    static P2? DecodePk(byte[] pk)
    {
        try
        {
            var w = Bls12.DecodeG2(pk);
            return w.is_inf() ? null : w;
        }
        catch (ArgumentException) { return null; }
    }

    /// <summary>Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input.</summary>
    public static Result VerifyDetailed(byte[] pk, byte[] signature, byte[] header, IReadOnlyList<byte[]> messages)
    {
        ParsedSignature parsed;
        try { parsed = OctetsToSignature(signature); }
        catch (ArgumentException) { return Result.Fail(MalformedSignature); }
        var w = DecodePk(pk);
        if (w == null) return Result.Fail(MalformedPublicKey);
        if (messages.Count > MaxMessages) return Result.Fail(DisclosedLengthMismatch);
        var ms = MessagesToScalars(messages);
        var g = Gens(ms.Count + 1);
        var q1 = g[0];
        var h = g.GetRange(1, g.Count - 1);
        var domain = CalculateDomain(pk, q1, h, header);
        var b = ComputeB(q1, h, domain, ms);
        // e(A, W + BP2*e) == e(B, BP2)
        bool ok = Bls12.PairingEq(parsed.A, Bls12.Add(w.Value, Bls12.Mul(BP2, parsed.E)), b, BP2);
        return ok ? Result.Success : Result.Fail(PairingMismatch);
    }

    public static bool Verify(byte[] pk, byte[] signature, byte[] header, IReadOnlyList<byte[]> messages) => VerifyDetailed(pk, signature, header, messages).Ok;

    // ---- challenge (draft 3.7.4) ----

    static BigInteger CalculateChallenge(P1 abar, P1 bbar, P1 d, P1 t1, P1 t2, List<int> idx, List<BigInteger> msgs, BigInteger domain, byte[] ph)
    {
        var els = new List<object> { idx.Count };
        for (int k = 0; k < idx.Count; k++) { els.Add(idx[k]); els.Add(msgs[k]); }
        els.Add(abar); els.Add(bbar); els.Add(d); els.Add(t1); els.Add(t2); els.Add(domain);
        return HashToScalar(Concat(Serialize(els), I2osp(ph.Length, 8), ph), H2sDst);
    }

    // ---- proof octets ----

    sealed record ParsedProof(P1 Abar, P1 Bbar, P1 D, BigInteger EHat, BigInteger R1Hat, BigInteger R3Hat, List<BigInteger> MHat, BigInteger C);

    static byte[] ProofToOctets(ParsedProof p)
    {
        var parts = new List<byte[]> { p.Abar.compress(), p.Bbar.compress(), p.D.compress(), I2osp(p.EHat, ScalarLen), I2osp(p.R1Hat, ScalarLen), I2osp(p.R3Hat, ScalarLen) };
        foreach (var m in p.MHat) parts.Add(I2osp(m, ScalarLen));
        parts.Add(I2osp(p.C, ScalarLen));
        return Concat(parts.ToArray());
    }

    static BigInteger ReadScalar(byte[] proof, int offset)
    {
        var v = Bls12.Os2ip(proof[offset..(offset + ScalarLen)]);
        if (v >= R) throw new ArgumentException("bbs: proof scalar out of range");
        return v;
    }

    static ParsedProof OctetsToProof(byte[] proof)
    {
        int fixedLen = 3 * PointLen + 4 * ScalarLen;
        if (proof.Length < fixedLen || (proof.Length - fixedLen) % ScalarLen != 0) throw new ArgumentException("bbs: malformed proof length");
        int o = 0;
        var abar = Bls12.DecodeG1(proof[o..(o + PointLen)]); o += PointLen;
        var bbar = Bls12.DecodeG1(proof[o..(o + PointLen)]); o += PointLen;
        var d = Bls12.DecodeG1(proof[o..(o + PointLen)]); o += PointLen;
        var eHat = ReadScalar(proof, o); o += ScalarLen;
        var r1Hat = ReadScalar(proof, o); o += ScalarLen;
        var r3Hat = ReadScalar(proof, o); o += ScalarLen;
        int u = (proof.Length - fixedLen) / ScalarLen;
        var mHat = new List<BigInteger>();
        for (int i = 0; i < u; i++) { mHat.Add(ReadScalar(proof, o)); o += ScalarLen; }
        var c = ReadScalar(proof, o);
        if (abar.is_inf() || bbar.is_inf() || d.is_inf()) throw new ArgumentException("bbs: proof contains the identity point");
        return new ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c);
    }

    // ---- index-set helpers ----

    static void ValidateIndexes(IReadOnlyList<int> indexes, int l)
    {
        var seen = new HashSet<int>();
        foreach (var i in indexes)
        {
            if (i < 0 || i >= l) throw new ArgumentException($"bbs: disclosed index {i} out of range [0, {l})");
            if (!seen.Add(i)) throw new ArgumentException($"bbs: duplicate disclosed index {i}");
        }
    }

    static List<int> UndisclosedAscending(ISet<int> disclosed, int l)
    {
        var o = new List<int>();
        for (int i = 0; i < l; i++) if (!disclosed.Contains(i)) o.Add(i);
        return o;
    }

    // ---- ProofGen ----

    /// <summary>
    /// ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
    /// discloses the messages at the given indexes. <paramref name="fixedRandomScalars"/> (5 + undisclosed count scalars) pins the randomness
    /// for test vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability.
    /// </summary>
    public static byte[] ProofGen(byte[] pk, byte[] signature, byte[] header, byte[] ph, IReadOnlyList<byte[]> messages, IReadOnlyList<int> disclosedIndexes, IReadOnlyList<BigInteger>? fixedRandomScalars = null)
    {
        var sig = OctetsToSignature(signature);
        var a = sig.A;
        var e = sig.E;
        var ms = MessagesToScalars(messages);
        int l = ms.Count;
        ValidateIndexes(disclosedIndexes, l);
        var disclosedSet = new SortedSet<int>(disclosedIndexes);
        var disclosed = disclosedSet.ToList();
        var undisclosed = UndisclosedAscending(disclosedSet, l);
        int u = undisclosed.Count;

        var g = Gens(l + 1);
        var q1 = g[0];
        var h = g.GetRange(1, g.Count - 1);
        var domain = CalculateDomain(pk, q1, h, header);
        var b = ComputeB(q1, h, domain, ms);

        List<BigInteger> rs;
        if (fixedRandomScalars == null)
        {
            rs = new List<BigInteger>();
            for (int i = 0; i < 5 + u; i++) rs.Add(Bls12.Mod(Bls12.Os2ip(RandomNumberGenerator.GetBytes(ExpandLen))));
        }
        else rs = new List<BigInteger>(fixedRandomScalars);
        if (rs.Count != 5 + u) throw new ArgumentException($"bbs: expected {5 + u} random scalars, got {rs.Count}");
        if (rs[0].IsZero || rs[1].IsZero) throw new ArgumentException("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)");
        var r1 = rs[0];
        var r2 = rs[1];
        var eTilde = rs[2];
        var r1Tilde = rs[3];
        var r3Tilde = rs[4];
        var mTilde = rs.GetRange(5, rs.Count - 5);

        var d = Bls12.Mul(b, r2);
        var abar = Bls12.Mul(a, Bls12.Mul(r1, r2));
        var bbar = Bls12.Sub(Bls12.Mul(d, r1), Bls12.Mul(abar, e));
        var t1 = Bls12.Add(Bls12.Mul(abar, eTilde), Bls12.Mul(d, r1Tilde));
        var t2 = Bls12.Mul(d, r3Tilde);
        for (int k = 0; k < u; k++) t2 = Bls12.Add(t2, Bls12.Mul(h[undisclosed[k]], mTilde[k]));

        var disclosedMsgs = disclosed.Select(i => ms[i]).ToList();
        var c = CalculateChallenge(abar, bbar, d, t1, t2, disclosed, disclosedMsgs, domain, ph);

        var r3 = Bls12.Inv(r2);
        var eHat = Bls12.Add(eTilde, Bls12.Mul(e, c));
        var r1Hat = Bls12.Sub(r1Tilde, Bls12.Mul(r1, c));
        var r3Hat = Bls12.Sub(r3Tilde, Bls12.Mul(r3, c));
        var mHat = new List<BigInteger>();
        for (int k = 0; k < u; k++) mHat.Add(Bls12.Add(mTilde[k], Bls12.Mul(ms[undisclosed[k]], c)));
        return ProofToOctets(new ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c));
    }

    // ---- ProofVerify ----

    /// <summary>ProofVerify with a rejection reason. <c>disclosedMessages[k]</c> corresponds to <c>disclosedIndexes[k]</c>.</summary>
    public static Result ProofVerifyDetailed(byte[] pk, byte[] proof, byte[] header, byte[] ph, IReadOnlyList<byte[]> disclosedMessages, IReadOnlyList<int> disclosedIndexes)
    {
        ParsedProof p;
        try { p = OctetsToProof(proof); }
        catch (ArgumentException) { return Result.Fail(MalformedProof); }
        var w = DecodePk(pk);
        if (w == null) return Result.Fail(MalformedPublicKey);
        if (disclosedMessages.Count != disclosedIndexes.Count) return Result.Fail(DisclosedLengthMismatch);
        int u = p.MHat.Count;
        int l = disclosedIndexes.Count + u;
        if (l > MaxMessages) return Result.Fail(MalformedProof);

        List<BigInteger> scalars;
        try
        {
            ValidateIndexes(disclosedIndexes, l);
            scalars = MessagesToScalars(disclosedMessages);
        }
        catch (ArgumentException) { return Result.Fail(InvalidDisclosedIndexes); }
        var order = Enumerable.Range(0, disclosedIndexes.Count).OrderBy(k => disclosedIndexes[k]).ToList(); // positions in the caller's lists, by index
        var disclosedSet = new SortedSet<int>(disclosedIndexes);
        var undisclosed = UndisclosedAscending(disclosedSet, l);

        var g = Gens(l + 1);
        var q1 = g[0];
        var h = g.GetRange(1, g.Count - 1);
        var domain = CalculateDomain(pk, q1, h, header);

        var t1 = Bls12.Add(Bls12.Add(Bls12.Mul(p.Bbar, p.C), Bls12.Mul(p.Abar, p.EHat)), Bls12.Mul(p.D, p.R1Hat));
        var bv = Bls12.Add(P1Gen, Bls12.Mul(q1, domain));
        var sortedIdx = new List<int>();
        var sortedMsgs = new List<BigInteger>();
        foreach (var k in order)
        {
            sortedIdx.Add(disclosedIndexes[k]);
            sortedMsgs.Add(scalars[k]);
            bv = Bls12.Add(bv, Bls12.Mul(h[disclosedIndexes[k]], scalars[k]));
        }
        var t2 = Bls12.Add(Bls12.Mul(bv, p.C), Bls12.Mul(p.D, p.R3Hat));
        for (int k = 0; k < u; k++) t2 = Bls12.Add(t2, Bls12.Mul(h[undisclosed[k]], p.MHat[k]));

        var cv = CalculateChallenge(p.Abar, p.Bbar, p.D, t1, t2, sortedIdx, sortedMsgs, domain, ph);
        if (cv != p.C) return Result.Fail(ChallengeMismatch);
        return Bls12.PairingEq(p.Abar, w.Value, p.Bbar, BP2) ? Result.Success : Result.Fail(PairingMismatch);
    }

    public static bool ProofVerify(byte[] pk, byte[] proof, byte[] header, byte[] ph, IReadOnlyList<byte[]> disclosedMessages, IReadOnlyList<int> disclosedIndexes)
        => ProofVerifyDetailed(pk, proof, header, ph, disclosedMessages, disclosedIndexes).Ok;
}
